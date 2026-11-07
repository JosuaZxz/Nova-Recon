#!/usr/bin/env python3
"""
NOVA v2 - First-Strike Asset Monitor
=====================================
Mesin bug bounty berbasis DETEKSI ASET BARU (bukan scan acak tanpa ingatan).

Alur per program:
  monitor  -> temukan subdomain BARU (crt.sh CT logs + subdomain.center + OTX [+ subfinder]) , diff vs state/
  probe    -> probe hanya host BARU (polite, thread pool, deteksi catchall)
  verify   -> verifikasi 4 kelas temuan ber-impact:
                * exposure (.env / .git / actuator / debug vars)  -> butuh bukti secret di body
                * takeover   (CNAME dangling ke layanan claimable)
                * cors       (ACAO refleksi + credentials)
                * graphql    (introspection aktif)
                * js-secret  (regex secret ber-keyword di file JS / HTML)
  brief    -> ringkasan harian (markdown) + kirim Telegram (opsional)

Compliance:
  - Semua URL dicocokkan ke root domain di targets/<program>.txt (strict scope filter).
  - TIDAK ada scanning IP mentah. TIDAK ada brute force agresif.
  - Rate limit global + per-host. Hanya probe aset BARU.

Usage:
  python scripts/nova.py scope                        # normalisasi & validasi targets/*.txt
  python scripts/nova.py run --programs boozt,bykea   # pipeline lengkap lokal
  python scripts/nova.py monitor --program boozt      # hanya discovery+diff
  python scripts/nova.py verify --program boozt --probe-file data/boozt/probe.jsonl --new-file data/boozt/new.txt
  python scripts/nova.py brief --send-telegram        # rangkum findings hari ini
Deps: requests (satu-satunya dependency eksternal).
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("[!] requests belum terpasang: pip install requests")
    sys.exit(1)

# Windows console safety (cp1252 tidak kenal emoji)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
TARGETS_DIR = ROOT / "targets"
STATE_DIR = ROOT / "state"
DATA_DIR = ROOT / "data"
FINDINGS_DIR = ROOT / "findings"

UA = os.environ.get(
    "NOVA_UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
)

MAX_CONC = int(os.environ.get("NOVA_MAX_CONC", "12"))
REQ_DELAY = float(os.environ.get("NOVA_REQ_DELAY", "0.12"))
HTTP_TIMEOUT = int(os.environ.get("NOVA_TIMEOUT", "9"))
PER_HOST_CAP = int(os.environ.get("NOVA_PER_HOST_CAP", "8"))
MAX_NEW_PROBE = int(os.environ.get("NOVA_MAX_NEW_PROBE", "250"))
MAX_JS_FETCH = int(os.environ.get("NOVA_MAX_JS", "150"))

TG_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TG_GENERAL = os.environ.get("TELEGRAM_GENERAL_ID", "")
TG_DATA = os.environ.get("TELEGRAM_DATA_ID", "")

# ---------------------------------------------------------------- utilities

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def sha(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:16]

def redact(value: str, keep: int = 4) -> str:
    """Redaksi tengah string untuk bukti di briefing (aman utk Telegram)."""
    v = value.strip()
    if len(v) <= keep * 2 + 3:
        return v[:keep] + "***"
    return v[:keep] + "..." + v[-keep:]

def is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("127.")
        or ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("169.254.")
        or ip.startswith("0.")
        or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip)
        or ip in ("::1",)
    )

PRIVATE_HOSTNAMES = ("localhost", ".internal", ".local", ".corp", ".home", ".lan")

INTERESTING_RE = re.compile(
    r"(dev|stg|stag|test|uat|qa|beta|sandbox|api|admin|internal|intra|corp|vpn|"
    r"git|jenkins|jira|conflu|grafana|kibana|elastic|kafka|zipkin|graf|"
    r"panel|portal|cms|app\.|web\.|new|v[0-9]|auth|sso|login|account|pay|"
    r"partner|b2b|backstage|console|manage|dash|report|data|preprod|pre)",
    re.IGNORECASE,
)

def prioritize_hosts(names) -> list:
    """Urutkan: interesting keywords > hostname alfanumerik > numerik murni."""
    names = sorted(set(names))
    interesting, normal, numeric = [], [], []
    for n in names:
        label = n.split(".")[0]
        if re.fullmatch(r"\d+(\.\d+)*", label):
            numeric.append(n)
        elif INTERESTING_RE.search(n):
            interesting.append(n)
        else:
            normal.append(n)
    random.shuffle(interesting)
    random.shuffle(normal)
    return interesting + normal + numeric

def in_scope(host: str, roots) -> bool:
    """True jika host == root atau host berakhir dengan '.' + root."""
    h = host.lower().strip(".")
    for r in roots:
        r = r.lower().strip(".")
        if h == r or h.endswith("." + r):
            return True
    return False

# ------------------------------------------------------------- rate limiter

class RateLimiter:
    def __init__(self):
        self.sem = threading.Semaphore(MAX_CONC)
        self.lock = threading.Lock()
        self.last = 0.0
        self.host_hits = {}
        self.hits_lock = threading.Lock()

    def acquire(self, host: str):
        self.sem.acquire()
        with self.lock:
            wait = REQ_DELAY - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            self.last = time.time()
        with self.hits_lock:
            self.host_hits[host] = self.host_hits.get(host, 0) + 1

    def release(self):
        self.sem.release()

    def host_exhausted(self, host: str) -> bool:
        with self.hits_lock:
            return self.host_hits.get(host, 0) >= PER_HOST_CAP

LIMITER = RateLimiter()

def http_get(url, allow_redirects=False, extra_headers=None, max_bytes=400_000, method="GET", body=None):
    """GET/POST polisi-traffic: rate limit + timeout + batas byte. Return (resp|None, err)."""
    host = urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
    if LIMITER.host_exhausted(host):
        return None, "host-cap"
    LIMITER.acquire(host)
    try:
        headers = {"User-Agent": UA, "Accept": "*/*"}
        if extra_headers:
            headers.update(extra_headers)
        r = requests.request(
            method, url, headers=headers, timeout=HTTP_TIMEOUT,
            allow_redirects=allow_redirects, stream=True, data=body,
        )
        chunk = b""
        for part in r.iter_content(chunk_size=65536):
            chunk += part
            if len(chunk) >= max_bytes:
                break
        r._nova_body = chunk
        return r, None
    except requests.exceptions.SSLError:
        return None, "ssl"
    except requests.exceptions.ConnectTimeout:
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        return None, "conn"
    except Exception as e:  # noqa: BLE001
        return None, f"err:{type(e).__name__}"
    finally:
        LIMITER.release()

# ------------------------------------------------------------------- DNS

def resolve_a(host: str):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []

def resolve_cname(host: str):
    """CNAME via nslookup (Windows & Linux). Return (cname|None, nxdomain: bool)."""
    try:
        out = subprocess.run(
            ["nslookup", "-type=CNAME", host],
            capture_output=True, text=True, timeout=8,
        ).stdout
    except Exception:
        return None, False
    out_l = out.lower()
    if "nxdomain" in out_l or "can't find" in out_l or "no servers could be reached" in out_l:
        return None, True
    m = re.search(r"canonical name\s*=\s*([A-Za-z0-9._-]+)", out)
    if not m:
        m = re.search(r"aliase\s*=\s*([A-Za-z0-9._-]+)", out)
    return (m.group(1).rstrip(".").lower() if m else None), False

# ------------------------------------------------------ passive discovery

def src_crt_sh(domain: str, out: set):
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    for attempt in range(4):
        try:
            r = requests.get(url, timeout=45, headers={"User-Agent": UA})
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    for name in str(entry.get("name_value", "")).split("\n"):
                        name = name.strip().lstrip("*.").lower().strip(".")
                        if name and " " not in name and "/" not in name:
                            out.add(name)
                return True
            time.sleep(2 + attempt * 3)
        except Exception:
            time.sleep(2 + attempt * 3)
    return False

def src_subdomain_center(domain: str, out: set):
    try:
        r = requests.get("https://api.subdomain.center/?domain=" + domain, timeout=25,
                         headers={"User-Agent": UA})
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for n in data:
                    n = str(n).strip().lstrip("*.").lower()
                    if n and "/" not in n:
                        out.add(n)
            return True
    except Exception:
        pass
    return False

def src_otx(domain: str, out: set):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=25, headers={"User-Agent": UA},
        )
        if r.status_code == 200:
            for rec in r.json().get("passive_dns", []):
                n = str(rec.get("hostname", "")).strip().lstrip("*.").lower()
                if n:
                    out.add(n)
            return True
    except Exception:
        pass
    return False

PASSIVE_SOURCES = [src_crt_sh, src_subdomain_center, src_otx]

# ------------------------------------------------------------- program I/O

def program_file(program: str) -> Path:
    return TARGETS_DIR / f"{program}.txt"

def program_roots(program: str):
    f = program_file(program)
    roots = []
    if f.exists():
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                roots.append(line)
    return roots

def list_programs():
    return sorted(p.stem for p in TARGETS_DIR.glob("*.txt") if p.stem != "test_target")

def load_state(program: str) -> set:
    f = STATE_DIR / f"{program}.subs.txt"
    if f.exists():
        return {l.strip().lower() for l in f.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()}
    return set()

def save_state(program: str, subs: set):
    STATE_DIR.mkdir(exist_ok=True)
    f = STATE_DIR / f"{program}.subs.txt"
    f.write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")

def load_findings_index(program: str) -> set:
    f = STATE_DIR / f"{program}.findings.txt"
    if f.exists():
        return {l.strip() for l in f.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()}
    return set()

def append_finding_index(program: str, h: str):
    STATE_DIR.mkdir(exist_ok=True)
    with open(STATE_DIR / f"{program}.findings.txt", "a", encoding="utf-8") as f:
        f.write(h + "\n")

# ------------------------------------------------------------------ monitor

def cmd_monitor(args):
    program = args.program
    roots = program_roots(program)
    if not roots:
        print(f"[!] targets/{program}.txt kosong/tidak ada. Lewati.")
        return
    known = load_state(program)
    discovered = set()

    print(f"[*] {program}: passive discovery untuk {len(roots)} root domain...")
    for root in roots:
        found = set()
        ok_sources = 0
        for src in PASSIVE_SOURCES:
            try:
                if src(root, found):
                    ok_sources += 1
            except Exception as e:  # noqa: BLE001
                print(f"    [!] source error {src.__name__}: {e}")
        print(f"    {root}: {len(found)} nama dari {ok_sources}/3 sumber")
        for name in found:
            if in_scope(name, roots):
                discovered.add(name)

    # merge hasil subfinder eksternal (jika workflow memberikan)
    if args.merge_file and Path(args.merge_file).exists():
        for line in Path(args.merge_file).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lstrip("*.").lower()
            if line and in_scope(line, roots):
                discovered.add(line)
        print(f"    + digabung dari {args.merge_file}")

    new = discovered - known
    print(f"[=] {program}: total {len(discovered)} | known {len(known)} | BARU {len(new)}")

    # state update (commit-able)
    save_state(program, known | discovered)

    # pilih sampel baru utk probe: PRIORITAS host "menarik" (dev/stg/api/admin/dll),
    # buang host numerik murni ke urutan terakhir (noise CT log), lalu acak sisanya.
    new_list = prioritize_hosts(new)
    if len(new_list) > MAX_NEW_PROBE:
        new_list = new_list[:MAX_NEW_PROBE]

    out_dir = DATA_DIR / program
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "new.txt").write_text("\n".join(sorted(new)) + "\n", encoding="utf-8")
    (out_dir / "probe_batch.txt").write_text("\n".join(new_list) + "\n", encoding="utf-8")
    print(f"[+] new.txt: {len(new)} | probe_batch.txt: {len(new_list)} -> {out_dir}")

# ------------------------------------------------------------------- probe

def probe_host(host: str, roots):
    """Probe satu host. Return dict hasil atau None."""
    if not in_scope(host, roots):
        return None
    if any(host.endswith(s) or s in host for s in PRIVATE_HOSTNAMES):
        return None

    ips = resolve_a(host)
    if not ips:
        return {"host": host, "status": "dead-dns", "url": None, "ips": []}
    if all(is_private_ip(ip) for ip in ips):
        return None

    result = {"host": host, "ips": ips, "status": None, "url": None,
              "http_status": None, "title": None, "server": None, "tech": [],
              "scripts": [], "catchall": False, "body": ""}

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        r, err = http_get(url)
        if r is not None:
            body = getattr(r, "_nova_body", b"")[:20_000].decode("utf-8", "ignore")
            result["url"] = url
            result["http_status"] = r.status_code
            result["server"] = r.headers.get("Server", "")
            result["body"] = body
            if r.headers.get("Content-Type", "").startswith("text/html"):
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m:
                    result["title"] = m.group(1).strip()[:120]
                for sm in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE):
                    result["scripts"].append(urljoin(url, sm.group(1)))
                # deteksi catch-all (SPA/404 personalizado utk SEMUA path)
                rr, _ = http_get(f"{scheme}://{host}/nova-random-probe-{random.randint(1000,9999)}")
                if rr is not None and rr.status_code == 200:
                    b2 = getattr(rr, "_nova_body", b"")[:2000].decode("utf-8", "ignore")
                    if abs(len(b2) - len(body[:2000])) < 80:
                        result["catchall"] = True
            # redirect -> catat tujuan
            if r.status_code in (301, 302, 307, 308):
                result["redirect"] = r.headers.get("Location", "")[:200]
            return result
        if err in ("timeout", "ssl", "conn", "host-cap"):
            continue
        break
    result["status"] = "no-http"
    return result

def cmd_probe(args):
    program = args.program
    roots = program_roots(program)
    if not roots:
        print(f"[!] targets/{program}.txt kosong. Lewati.")
        return
    batch_file = Path(args.batch_file) if args.batch_file else DATA_DIR / program / "probe_batch.txt"
    if not batch_file.exists():
        print(f"[!] {batch_file} tidak ada. Jalankan monitor dulu.")
        return
    hosts = [l.strip() for l in batch_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    if not hosts:
        print(f"[=] {program}: tidak ada host baru utk diprobe.")
        (DATA_DIR / program / "probe.jsonl").write_text("", encoding="utf-8")
        return

    print(f"[*] {program}: probing {len(hosts)} host baru (max {MAX_CONC} thread)...")
    out_dir = DATA_DIR / program
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    live = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONC) as ex:
        futures = {ex.submit(probe_host, h, roots): h for h in hosts}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                res = fut.result()
            except Exception:
                continue
            if res:
                results.append(res)
                if res.get("http_status"):
                    live += 1
            if done % 50 == 0:
                print(f"    ... {done}/{len(hosts)} (live: {live})")

    with open(out_dir / "probe.jsonl", "w", encoding="utf-8") as f:
        for res in results:
            f.write(json.dumps(res, ensure_ascii=False) + "\n")
    with open(out_dir / "live.txt", "w", encoding="utf-8") as f:
        for res in results:
            if res.get("url"):
                f.write(res["url"] + "\n")
    print(f"[=] {program}: probe selesai. live={live}/{len(hosts)} -> {out_dir/'probe.jsonl'}")

# ------------------------------------------------------------------ verify

EXPOSURE_CHECKS = [
    # (path, verdict_fn) - verdict_fn(body, headers) -> (bool, evidence_str)
    ("/.env", lambda b, h: (_env_secret(b), None)),
    ("/.env.local", lambda b, h: (_env_secret(b), None)),
    ("/.env.production", lambda b, h: (_env_secret(b), None)),
    ("/.env.backup", lambda b, h: (_env_secret(b), None)),
    ("/.git/config", lambda b, h: ("[core]" in b or '[remote "origin"]' in b, "git config present")),
    ("/.git/HEAD", lambda b, h: (b.strip().startswith("ref: refs/"), "git HEAD: " + b.strip()[:40])),
    ("/actuator/env", lambda b, h: ("propertySources" in b, "Spring actuator env JSON")),
    ("/actuator/heapdump", lambda b, h: (
        h.get("Content-Type", "").startswith("application/octet-stream"),
        "heapdump binary served")),
    ("/debug/vars", lambda b, h: ("memstats" in b.lower() or "cmdline" in b.lower(), "Go expvar exposed")),
]

ENV_KEY_RE = re.compile(
    r"^\s*([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASS|AWS|SMTP|MAIL|DB|DATABASE|API|CRED)[A-Z0-9_]*)\s*[=:]\s*(.{8,})\s*$",
    re.IGNORECASE | re.MULTILINE,
)
ENV_PLACEHOLDERS = {"", "changeme", "change-me", "password", "your-password", "your_password_here",
                    "null", "none", "true", "false", "0", "1", "xxx", "test", "example", "secret",
                    "${var}", "%s", "********", "xxx-xxx-xxx"}

def _env_secret(body: str):
    """Return (bool, evidence) - butuh >=1 nilai yang BUKAN placeholder."""
    if body.lstrip()[:1] == "<":  # halaman HTML catchall
        return False, None
    hits = []
    for m in ENV_KEY_RE.finditer(body):
        key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
        if val.lower() in ENV_PLACEHOLDERS or val.startswith("${") or set(val) <= set("x*."):
            continue
        hits.append(f"{key}={redact(val, 3)}")
        if len(hits) >= 3:
            break
    if hits:
        return True, "; ".join(hits)
    return False, None

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,50}|github_pat_[A-Za-z0-9_]{20,}")),
    ("Stripe live key", re.compile(r"[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Twilio key", re.compile(r"SK[a-f0-9]{32}")),
    ("Mailgun key", re.compile(r"key-[a-f0-9]{32}")),
]

TAKEOVER_SUFFIXES = (
    "s3.amazonaws.com", "s3-website", "s3-accelerate", "amazonaws.com",
    "azurewebsites.net", "cloudapp.azure.com", "azureedge.net", "blob.core.windows.net",
    "cloudfront.net", "herokuapp.com", "herokussl.com", "github.io", "gitlab.io",
    "bitbucket.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "surge.sh", "firebaseapp.com", "web.app", "myshopify.com",
    "readthedocs.io", "tumblr.com", "zendesk.com", "helpjuice.com",
    "helpscout.net", "readme.io", "canny.io", "teamwork.com", "pantheon.io",
)

TAKEOVER_BODY_SIGS = [
    ("NoSuchBucket", "high", "S3 bucket hilang"),
    ("There isn't a GitHub Pages site here", "high", "GitHub Pages belum diklaim"),
    ("fastly error: unknown domain", "high", "Fastly domain belum terdaftar"),
    ("The specified bucket does not exist", "high", "S3 bucket hilang"),
    ("Repository not found", "medium", "Vercel/Netlify project hilang"),
    ("no longer available", "medium", "layanan deprecated"),
]

def check_takeover(host, roots):
    """CNAME dangling ke layanan claimable. Return finding dict atau None."""
    if not in_scope(host, roots):
        return None
    cname, host_nx = resolve_cname(host)
    if not cname:
        # host sendiri NXDOMAIN tanpa CNAME -> cuma catat kalau ada petunjuk
        return None
    if not any(cname.endswith(sfx) or sfx in cname for sfx in TAKEOVER_SUFFIXES):
        return None
    target_ips = resolve_a(cname)
    if not target_ips:
        return {
            "type": "takeover", "url": f"https://{host}", "host": host,
            "severity_hint": "high", "confidence": "strong",
            "evidence": f"CNAME -> {cname} (NXDOMAIN). Layanan claimable, subdomain menggantung.",
            "next": "Daftar/klaim di provider layanan tsb, lalu buktikan kontrol. Verifikasi manual wajib.",
        }
    # target resolve: cek body signature 404 khas
    r, _ = http_get(f"https://{host}/")
    if r is not None and r.status_code == 404:
        body = getattr(r, "_nova_body", b"")[:4000].decode("utf-8", "ignore")
        for sig, sev, desc in TAKEOVER_BODY_SIGS:
            if sig.lower() in body.lower():
                return {
                    "type": "takeover", "url": f"https://{host}", "host": host,
                    "severity_hint": sev, "confidence": "medium",
                    "evidence": f"CNAME -> {cname}; body 404: '{sig}'",
                    "next": "Klaim di provider, verifikasi manual wajib.",
                }
    return None

def check_cors(url):
    r, _ = http_get(url, extra_headers={"Origin": "https://nova-cors-canary.example.com"})
    if r is None:
        return None
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "https://nova-cors-canary.example.com":
        if acac.lower() == "true":
            return {
                "type": "cors", "url": url, "severity_hint": "high", "confidence": "medium",
                "evidence": f"ACAO refleksi origin arbitrer + Access-Control-Allow-Credentials: true",
                "next": "Uji fetch() dengan credentials dari origin terkontrol; cari endpoint berisi data user.",
            }
        return {
            "type": "cors", "url": url, "severity_hint": "low", "confidence": "low",
            "evidence": "ACAO refleksi origin arbitrer (tanpa credentials)",
            "next": "Cek apakah ada endpoint sensitif + header custom (Authorization) yg terekspos.",
        }
    return None

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/api/v1/graphql")

def check_graphql(base_url):
    for p in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + p
        r, _ = http_get(url, method="POST",
                        body=json.dumps({"query": "{ __schema { queryType { name } } }"}),
                        extra_headers={"Content-Type": "application/json"})
        if r is None:
            continue
        if r.status_code == 200:
            body = getattr(r, "_nova_body", b"")[:8000].decode("utf-8", "ignore")
            if "__schema" in body:
                return {
                    "type": "graphql", "url": url, "severity_hint": "medium", "confidence": "medium",
                    "evidence": "Introspection aktif (__schema diterima)",
                    "next": "Dump schema, cari tipe/mutation sensitif (admin, PII, billing).",
                }
    return None

def check_exposures(base_url, catchall):
    findings = []
    for path, verdict in EXPOSURE_CHECKS:
        url = base_url.rstrip("/") + path
        r, err = http_get(url)
        if r is None:
            continue
        if r.status_code != 200:
            continue
        body = getattr(r, "_nova_body", b"")[:60_000].decode("utf-8", "ignore")
        ct = r.headers.get("Content-Type", "")
        if ct.startswith("text/html") and path not in ("/.env",):
            continue
        ok, evidence = verdict(body, r.headers)
        if ok:
            findings.append({
                "type": "exposure", "url": url, "severity_hint": "critical",
                "confidence": "strong", "evidence": evidence or path,
                "next": "Buka di browser incognito, screenshot, identifikasi secret, cek validitas kredensial.",
            })
            break  # satu cukup per host, jangan nafsu
    return findings

def check_js_secrets(scripts, roots):
    """Fetch JS + regex secret high-confidence. Return findings."""
    findings = []
    seen_url = set()
    fetched = 0
    for js_url in scripts:
        if fetched >= MAX_JS_FETCH:
            break
        js_url = js_url.strip()
        if not js_url or js_url in seen_url:
            continue
        seen_url.add(js_url)
        host = urlparse(js_url).netloc
        if not in_scope(host, roots):
            continue
        fetched += 1
        r, _ = http_get(js_url, max_bytes=500_000)
        if r is None or r.status_code != 200:
            continue
        body = getattr(r, "_nova_body", b"").decode("utf-8", "ignore")
        for name, rx in SECRET_PATTERNS:
            m = rx.search(body)
            if m:
                token = m.group(0)
                findings.append({
                    "type": "js-secret", "url": js_url, "severity_hint": "critical",
                    "confidence": "medium",  # perlu verifikasi validitas token
                    "evidence": f"{name}: {redact(token)}",
                    "next": "Cek validitas token (jangan aktiv-attack), laporkan sebagai leaked credential.",
                })
                break  # satu secret per file cukup utk lead
    return findings

def cmd_verify(args):
    program = args.program
    roots = program_roots(program)
    if not roots:
        print(f"[!] targets/{program}.txt kosong. Lewati.")
        return
    out_dir = DATA_DIR / program
    probe_file = Path(args.probe_file) if args.probe_file else out_dir / "probe.jsonl"
    new_file = Path(args.new_file) if args.new_file else out_dir / "new.txt"
    if not probe_file.exists():
        print(f"[!] {probe_file} tidak ada. Jalankan probe dulu.")
        return

    probe_results = []
    for line in probe_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line:
            try:
                probe_results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    index = load_findings_index(program)
    findings = []

    # 1) exposures + cors + graphql + js-secrets (dari hasil probe)
    for res in probe_results:
        url = res.get("url")
        if not url or res.get("http_status") not in (200, 401, 403):
            continue
        base = url.rstrip("/")
        # exposures
        findings.extend(check_exposures(base, res.get("catchall", False)))
        # cors & graphql hanya di host non-catchall, status 200
        if res.get("http_status") == 200 and not res.get("catchall"):
            f = check_cors(base)
            if f:
                findings.append(f)
            f = check_graphql(base)
            if f:
                findings.append(f)
        # js secrets
        scripts = res.get("scripts", [])
        if scripts:
            findings.extend(check_js_secrets(scripts, roots))

    # 2) takeover: cek SEMUA host baru (termasuk yang DNS-nya mati)
    new_hosts = []
    if new_file.exists():
        new_hosts = [l.strip() for l in new_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    print(f"[*] {program}: takeover check pada {len(new_hosts)} host baru...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for f in ex.map(lambda h: check_takeover(h, roots), new_hosts):
            if f:
                findings.append(f)

    # dedupe vs index (url+type) & simpan
    saved = 0
    day_dir = FINDINGS_DIR / today_str() / program
    day_dir.mkdir(parents=True, exist_ok=True)
    for f in findings:
        h = sha(f["type"] + "|" + f["url"])
        if h in index:
            continue
        append_finding_index(program, h)
        f["program"] = program
        f["first_seen"] = now_utc()
        fhash = h
        with open(day_dir / f"{f['type']}-{fhash}.json", "w", encoding="utf-8") as fh:
            json.dump(f, fh, ensure_ascii=False, indent=2)
        saved += 1
        print(f"  [LEAD] [{f['severity_hint']}] {f['type']}: {f['url']}  -> {f['evidence'][:80]}")

    print(f"[=] {program}: {len(findings)} kandidat, {saved} BARU disimpan di {day_dir}")

# ------------------------------------------------------------------- brief

def collect_findings(date=None):
    day_dir = FINDINGS_DIR / (date or today_str())
    out = []
    if not day_dir.exists():
        return out
    for f in sorted(day_dir.rglob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda x: sev_rank.get(x.get("severity_hint", "low"), 9))
    return out

def build_briefing(date=None) -> str:
    findings = collect_findings(date)
    lines = []
    lines.append(f"NOVA BRIEFING - {date or today_str()}")
    lines.append("=" * 44)
    if not findings:
        lines.append("Tidak ada lead terverifikasi hari ini. Mesin tetap jalan; aset baru terpantau.")
        return "\n".join(lines)
    by_prog = {}
    for f in findings:
        by_prog.setdefault(f.get("program", "?"), []).append(f)
    lines.append(f"Programs: {len(by_prog)} | Leads: {len(findings)}")
    lines.append("")
    for prog, fl in by_prog.items():
        lines.append(f"### {prog} ({len(fl)} leads)")
        for f in fl[:10]:
            lines.append(f"[{f.get('severity_hint','?').upper()}] {f.get('type')} | {f.get('url','')}")
            lines.append(f"    Bukti : {f.get('evidence','')[:160]}")
            lines.append(f"    Next  : {f.get('next','')[:160]}")
        if len(fl) > 10:
            lines.append(f"    ... +{len(fl)-10} leads lagi di findings/")
        lines.append("")
    lines.append("Catatan: VERIFIKASI MANUAL dulu sebelum submit (browser incognito + screenshot).")
    return "\n".join(lines)

def tg_send_text(text):
    if not (TG_TOKEN and TG_GENERAL):
        print("[!] Telegram belum diset (TELEGRAM_TOKEN / TELEGRAM_GENERAL_ID). Briefing hanya file.")
        return False
    for i in range(0, len(text), 3800):
        try:
            requests.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={"chat_id": TG_GENERAL, "text": text[i:i + 3800]},
                timeout=20,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[!] Telegram gagal: {e}")
            return False
    return True

def cmd_brief(args):
    findings = collect_findings(args.date)
    if not findings and args.send_telegram and not args.force:
        print("[=] Tidak ada lead hari ini -> Telegram tidak dikirim (anti-spam).")
    text = build_briefing(args.date)
    day = args.date or today_str()
    FINDINGS_DIR.mkdir(exist_ok=True)
    out = FINDINGS_DIR / f"BRIEFING-{day}.md"
    out.write_text(text, encoding="utf-8")
    print(f"[+] Briefing: {out}")
    print(text)
    if args.send_telegram and (findings or args.force):
        tg_send_text(text)
    # zip findings -> Telegram data channel (seperti kebiasaan lama, tapi kini berisi LEADS)
    if args.send_telegram and TG_TOKEN and TG_DATA:
        import zipfile
        day_dir = FINDINGS_DIR / day
        if day_dir.exists():
            zpath = DATA_DIR / f"NOVA_LEADS_{day}.zip"
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
                for p in day_dir.rglob("*"):
                    if p.is_file():
                        z.write(p, p.relative_to(FINDINGS_DIR))
            try:
                with open(zpath, "rb") as fh:
                    requests.post(
                        f"https://api.telegram.org/bot{TG_TOKEN}/sendDocument",
                        data={"chat_id": TG_DATA, "caption": f"NOVA leads {day}"},
                        files={"document": fh}, timeout=60,
                    )
                print(f"[+] Leads zip terkirim ke Telegram data channel: {zpath.name}")
            except Exception as e:  # noqa: BLE001
                print(f"[!] Kirim zip gagal: {e}")

# ------------------------------------------------------------------- scope

PUBLIC_SUFFIX_2ND = {"com", "net", "org", "edu", "gov", "co", "or", "id", "uk", "au", "br", "mx", "jp"}

def registered_domain(host: str) -> str:
    labels = host.strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in PUBLIC_SUFFIX_2ND:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

def cmd_scope(args):
    """Normalisasi targets/*.txt: root domain saja, dedupe, turunkan subdomain ke root implisit."""
    STATE_DIR.mkdir(exist_ok=True)
    todo_lines = []
    print("=== NOVA SCOPE AUDIT ===")
    for f in sorted(TARGETS_DIR.glob("*.txt")):
        if f.stem == "test_target":
            continue
        raw = [l.strip().lower() for l in f.read_text(encoding="utf-8", errors="ignore").splitlines()]
        raw = [l for l in raw if l and not l.startswith("#")]
        valid, invalid = [], []
        for line in raw:
            if DOMAIN_RE.match(line):
                valid.append(line)
            elif line:
                invalid.append(line)
        valid_set = set(valid)
        roots = set()
        derived = []
        for d in valid:
            rd = registered_domain(d)
            roots.add(rd)
        kept = []
        for d in sorted(roots):
            kept.append(d)
        dropped_subs = [d for d in valid if d not in roots]
        # subdomain dgn root TIDAK ada di file -> root implisit ditambahkan (flag verifikasi)
        for d in dropped_subs:
            rd = registered_domain(d)
            if rd not in valid_set:
                derived.append(rd)
        # files yang sebelumnya hanya berisi subdomain
        if derived:
            todo_lines.append(
                f"- {f.stem}.txt: root implisit ditambahkan {sorted(set(derived))} "
                f"(dari {dropped_subs}) - VERIFIKASI ke halaman policy program!"
            )
        new_content = "\n".join(sorted(kept)) + "\n"
        old_content = f.read_text(encoding="utf-8", errors="ignore")
        f.write_text(new_content, encoding="utf-8")
        status = "OK" if old_content == new_content else "FIXED"
        print(f"  [{status}] {f.name}: {len(kept)} root ({len(dropped_subs)} sub di-drop, {len(derived)} root implisit)")
        if invalid:
            print(f"      invalid dilepas: {invalid}")
    if todo_lines:
        todo_path = ROOT / "SCOPE_TODO.md"
        content = "# Scope yang perlu diverifikasi manual\n\nRoot domain berikut diturunkan otomatis dari subdomain yang kamu daftarkan.\nBuka halaman policy program (HackerOne/Bugcrowd) dan pastikan root ini benar-benar in-scope.\n\n" + "\n".join(todo_lines) + "\n"
        todo_path.write_text(content, encoding="utf-8")
        print(f"[!] {todo_path} ditulis - cek daftarnya!")
    print("[=] Scope audit selesai.")

# -------------------------------------------------------------------- run

def cmd_run(args):
    programs = args.programs.split(",") if args.programs else list_programs()
    programs = [p.strip() for p in programs if p.strip()]
    print(f"=== NOVA RUN {now_utc()} ===")
    print(f"Programs ({len(programs)}): {', '.join(programs)}")
    for prog in programs:
        print(f"\n---- {prog} ----")
        ns = argparse.Namespace(program=prog, merge_file=args.merge_file)
        cmd_monitor(ns)
        if args.skip_probe:
            continue
        cmd_probe(argparse.Namespace(program=prog, batch_file=None))
        cmd_verify(argparse.Namespace(program=prog, probe_file=None, new_file=None))
    print(f"\n=== SELESAI {now_utc()} ===")
    cmd_brief(argparse.Namespace(date=None, send_telegram=args.send_telegram, force=False))

# -------------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description="NOVA v2 - First-Strike Asset Monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scope", help="normalisasi & audit targets/*.txt")
    s.set_defaults(func=cmd_scope)

    s = sub.add_parser("monitor", help="discovery pasif + diff state")
    s.add_argument("--program", required=True)
    s.add_argument("--merge-file", default=None, help="file subfinder tambahan utk digabung")
    s.set_defaults(func=cmd_monitor)

    s = sub.add_parser("probe", help="probe host baru")
    s.add_argument("--program", required=True)
    s.add_argument("--batch-file", default=None)
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("verify", help="verifikasi temuan (exposure/takeover/cors/graphql/js)")
    s.add_argument("--program", required=True)
    s.add_argument("--probe-file", default=None)
    s.add_argument("--new-file", default=None)
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("brief", help="briefing harian + telegram")
    s.add_argument("--date", default=None)
    s.add_argument("--send-telegram", action="store_true")
    s.add_argument("--force", action="store_true", help="kirim ke Telegram meski kosong")
    s.set_defaults(func=cmd_brief)

    s = sub.add_parser("run", help="pipeline lengkap utk beberapa program")
    s.add_argument("--programs", default=None, help="koma-separated; default semua")
    s.add_argument("--merge-file", default=None)
    s.add_argument("--skip-probe", action="store_true")
    s.add_argument("--send-telegram", action="store_true")
    s.set_defaults(func=cmd_run)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
