#!/usr/bin/env python3
"""
NOVA v2.2 - Intelligent Recon, AI Validation Gate & Report Generator
====================================================================
Alur otomatis per program:
  monitor  -> discovery pasif (crt.sh + subdomain.center + OTX [+ subfinder]),
              filter scope & !exclude, antrean lossless (state/<program>.queue.txt)
  probe    -> probe host + smart same-host redirect follower (hingga 3 hop),
              ekstrak bundle JS (<script src> & modulepreload), simpan state/<program>.hosts.json
  verify   -> cek non-destruktif berbukti lengkap (double-tap exposure, dual-DoH claimable takeover,
              CORS+credentials, GraphQL schema/mutation extractor, JS secret high-entropy)
              + AI Validation Gate (GROQ_API_KEY) -> drop FP, generate REPORT-*.md siap kirim
  diff     -> pantau perubahan host lama (403/404->200) & diff JS bundle (API/GraphQL baru)
              + AI Validation Gate -> generate REPORT-*.md siap kirim
  brief    -> kirim ringkasan + lampiran dokumen REPORT-*.md langsung ke Telegram

Deps: requests (satu-satunya dependency eksternal).
"""

from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urljoin, urlparse

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from ai_brief import (  # noqa: E402
    render_markdown_report,
    summarize_findings,
    validate_and_draft_report,
)
from js_intel import (  # noqa: E402
    canonical_js_key,
    diff_js_bundle,
    is_vendor_js,
    load_js_state,
    redact,
    save_js_state,
    scan_js_secrets,
)
from scope_guard import (  # noqa: E402
    ProgramPolicy,
    audit_target_file,
    load_focus_programs,
    load_program_policy,
)

try:
    import requests
except ImportError:
    print("[!] requests belum terpasang: pip install requests")
    sys.exit(1)

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = SCRIPTS_DIR.parent
TARGETS_DIR = ROOT / "targets"
STATE_DIR = ROOT / "state"
DATA_DIR = ROOT / "data"
FINDINGS_DIR = ROOT / "findings"

UA = os.environ.get(
    "NOVA_UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
)
try:
    EXTRA_HEADERS = json.loads(os.environ.get("NOVA_EXTRA_HEADERS", "{}"))
    if not isinstance(EXTRA_HEADERS, dict):
        EXTRA_HEADERS = {}
except Exception:
    EXTRA_HEADERS = {}

MAX_CONC = int(os.environ.get("NOVA_MAX_CONC", "12"))
REQ_DELAY = float(os.environ.get("NOVA_REQ_DELAY", "0.12"))
HTTP_TIMEOUT = int(os.environ.get("NOVA_TIMEOUT", "9"))
PER_HOST_CAP = int(os.environ.get("NOVA_PER_HOST_CAP", "10"))
MAX_NEW_PROBE = int(os.environ.get("NOVA_MAX_NEW_PROBE", "250"))
MAX_JS_FETCH = int(os.environ.get("NOVA_MAX_JS", "120"))
DIFF_BUDGET = int(os.environ.get("NOVA_DIFF_BUDGET", "60"))
MAX_TRACKED_HOSTS = int(os.environ.get("NOVA_MAX_TRACKED_HOSTS", "1200"))
SEED_CAP = int(os.environ.get("NOVA_SEED_CAP", "1000"))

TG_TOKEN = os.environ.get("TELEGRAM_TOKEN", "").strip()
TG_GENERAL = os.environ.get("TELEGRAM_GENERAL_ID", "").strip()
TG_DATA = os.environ.get("TELEGRAM_DATA_ID", "").strip()


# ---------------------------------------------------------------- utilities

def now_utc() -> str:
    """Return current UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def today_str() -> str:
    """Return current UTC date string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def sha(text: str) -> str:
    """Return short 16-char SHA-1 identifier."""
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:16]


def is_private_ip(ip: str) -> bool:
    """Return True if IP is loopback, link-local, or RFC1918 private space."""
    return (
        ip.startswith("127.")
        or ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("169.254.")
        or ip.startswith("0.")
        or bool(re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip))
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

LOGIN_PATH_RE = re.compile(
    r"(/login|/signin|/auth/login|/sso|oauth2?/authorize|oktapreview|auth0\.com|wp-login)",
    re.IGNORECASE,
)

SCRIPT_TAG_RE = re.compile(
    r'(?:src|href)=["\']([^"\']+\.m?js(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)


def _subdomain_prefix(host: str, policy: ProgramPolicy | None = None) -> str:
    """Return only the subdomain prefix before the matched root domain."""
    h = host.lower().strip(".")
    if policy:
        for rule in policy.includes:
            base = rule[2:] if rule.startswith("*.") else rule
            if h.endswith("." + base):
                return h[: -(len(base) + 1)]
            if h == base:
                return ""
    parts = h.split(".")
    return ".".join(parts[:-2]) if len(parts) > 2 else h


def is_interesting_host(host: str, policy: ProgramPolicy | None = None) -> bool:
    """Return True when subdomain prefix matches high-value environment/app keywords."""
    prefix = _subdomain_prefix(host, policy)
    return bool(prefix and INTERESTING_RE.search(prefix))


def prioritize_hosts(names, policy: ProgramPolicy | None = None) -> list[str]:
    """Order hosts: interesting keywords > normal alphanumeric > numeric."""
    unique = sorted(set(names))
    interesting, normal, numeric = [], [], []
    for n in unique:
        label = n.split(".")[0]
        if re.fullmatch(r"\d+(\.\d+)*", label):
            numeric.append(n)
        elif is_interesting_host(n, policy):
            interesting.append(n)
        else:
            normal.append(n)
    random.shuffle(interesting)
    random.shuffle(normal)
    return interesting + normal + numeric


def _format_resp_evidence(resp, body_excerpt: str, max_headers: int = 8) -> str:
    """Format HTTP status, key headers, and body excerpt for report evidence."""
    hdr_lines = [f"HTTP/1.1 {resp.status_code}"]
    important = (
        "content-type",
        "server",
        "location",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "x-powered-by",
        "content-length",
    )
    count = 0
    for k, v in resp.headers.items():
        if k.lower() in important or count < max_headers:
            hdr_lines.append(f"{k}: {v[:160]}")
            count += 1
    excerpt = body_excerpt.strip()[:900]
    return "\n".join(hdr_lines) + ("\n\n" + excerpt if excerpt else "")


# ------------------------------------------------------------- rate limiter

class RateLimiter:
    """Global concurrency, inter-request delay, and per-host request cap."""

    def __init__(self):
        self.sem = threading.Semaphore(MAX_CONC)
        self.lock = threading.Lock()
        self.last = 0.0
        self.host_hits: dict[str, int] = {}
        self.hits_lock = threading.Lock()

    def acquire(self, host: str) -> None:
        self.sem.acquire()
        with self.lock:
            wait = REQ_DELAY - (time.time() - self.last)
            if wait > 0:
                time.sleep(wait)
            self.last = time.time()
        with self.hits_lock:
            self.host_hits[host] = self.host_hits.get(host, 0) + 1

    def release(self) -> None:
        self.sem.release()

    def host_exhausted(self, host: str) -> bool:
        with self.hits_lock:
            return self.host_hits.get(host, 0) >= PER_HOST_CAP


LIMITER = RateLimiter()


def http_get(
    url: str,
    allow_redirects: bool = False,
    extra_headers: dict | None = None,
    max_bytes: int = 400_000,
    method: str = "GET",
    body: str | None = None,
):
    """Execute rate-limited HTTP request and read up to max_bytes."""
    host = urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
    if LIMITER.host_exhausted(host):
        return None, "host-cap"
    LIMITER.acquire(host)
    try:
        headers = {"User-Agent": UA, "Accept": "*/*"}
        if EXTRA_HEADERS:
            headers.update(EXTRA_HEADERS)
        if extra_headers:
            headers.update(extra_headers)
        r = requests.request(
            method,
            url,
            headers=headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=allow_redirects,
            stream=True,
            data=body,
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
    except Exception as e:
        return None, f"err:{type(e).__name__}"
    finally:
        LIMITER.release()


# ------------------------------------------------------------------- DNS

DOH_ENDPOINTS = (
    ("Cloudflare", "https://1.1.1.1/dns-query"),
    ("Google", "https://dns.google/resolve"),
)


def dns_lookup(host: str, resolver_url: str = "https://1.1.1.1/dns-query") -> tuple[list[str], list[str]]:
    """Resolve (cnames, ips) via DoH with local nslookup/socket fallback."""
    try:
        r = requests.get(
            resolver_url,
            params={"name": host, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=8,
        )
        ans = r.json().get("Answer") or []
        cns = [a["data"].rstrip(".").lower() for a in ans if a.get("type") == 5]
        ips = [a["data"] for a in ans if a.get("type") == 1]
        return cns, ips
    except Exception:
        pass
    cname, _ = resolve_cname(host)
    ips = resolve_a(host)
    return ([cname] if cname else []), ips


def resolve_a(host: str) -> list[str]:
    """Resolve IPv4 addresses via socket.getaddrinfo."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def resolve_cname(host: str) -> tuple[str | None, bool]:
    """Resolve CNAME via nslookup fallback."""
    try:
        out = subprocess.run(
            ["nslookup", "-type=CNAME", host],
            capture_output=True,
            text=True,
            timeout=8,
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

def src_crt_sh(domain: str, out: set[str]) -> bool:
    """Query crt.sh Certificate Transparency logs."""
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    for attempt in range(4):
        try:
            r = requests.get(url, timeout=45, headers={"User-Agent": UA})
            if r.status_code == 200:
                for entry in r.json():
                    for name in str(entry.get("name_value", "")).split("\n"):
                        name = name.strip().lstrip("*.").lower().strip(".")
                        if name and " " not in name and "/" not in name:
                            out.add(name)
                return True
            time.sleep(2 + attempt * 3)
        except Exception:
            time.sleep(2 + attempt * 3)
    return False


def src_subdomain_center(domain: str, out: set[str]) -> bool:
    """Query subdomain.center passive API."""
    try:
        r = requests.get(
            "https://api.subdomain.center/?domain=" + domain,
            timeout=25,
            headers={"User-Agent": UA},
        )
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


def src_otx(domain: str, out: set[str]) -> bool:
    """Query AlienVault OTX passive DNS."""
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=25,
            headers={"User-Agent": UA},
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

def list_programs() -> list[str]:
    """Return all configured program stems excluding test and underscore-prefixed meta files."""
    return sorted(
        p.stem
        for p in TARGETS_DIR.glob("*.txt")
        if p.stem != "test_target" and not p.stem.startswith("_")
    )


def _read_lines_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    }


def _write_sorted_lines(path: Path, items: set[str] | list[str]) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    clean = sorted({x.strip().lower() for x in items if x.strip()})
    path.write_text(("\n".join(clean) + "\n") if clean else "", encoding="utf-8")


def load_state(program: str) -> set[str]:
    return _read_lines_set(STATE_DIR / f"{program}.subs.txt")


def save_state(program: str, subs: set[str]) -> None:
    _write_sorted_lines(STATE_DIR / f"{program}.subs.txt", subs)


def load_queue(program: str) -> set[str]:
    return _read_lines_set(STATE_DIR / f"{program}.queue.txt")


def save_queue(program: str, pending: list[str] | set[str]) -> None:
    _write_sorted_lines(STATE_DIR / f"{program}.queue.txt", pending)


def load_hosts_state(program: str) -> dict:
    """Load tracked live host snapshots."""
    path = STATE_DIR / f"{program}.hosts.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_hosts_state(program: str, hosts: dict) -> None:
    """Persist bounded tracked host snapshots while preserving meta keys."""
    STATE_DIR.mkdir(exist_ok=True)
    meta = {k: v for k, v in hosts.items() if k.startswith("_")}
    host_items = [
        (k, v)
        for k, v in hosts.items()
        if not k.startswith("_") and isinstance(v, dict)
    ]
    if len(host_items) > MAX_TRACKED_HOSTS:
        host_items = sorted(
            host_items,
            key=lambda kv: (
                0 if kv[1].get("interesting") else 1,
                0 if kv[1].get("http_status") == 200 else 1,
                kv[1].get("last_checked", ""),
            ),
        )[:MAX_TRACKED_HOSTS]
    merged = {**meta, **dict(host_items)}
    path = STATE_DIR / f"{program}.hosts.json"
    path.write_text(json.dumps(merged, ensure_ascii=False, indent=1), encoding="utf-8")


def load_findings_index(program: str) -> set[str]:
    f = STATE_DIR / f"{program}.findings.txt"
    if f.exists():
        return {
            line.strip()
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        }
    return set()


def append_finding_index(program: str, h: str) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    with open(STATE_DIR / f"{program}.findings.txt", "a", encoding="utf-8") as f:
        f.write(h + "\n")


def _finding_dedupe_key(f: dict) -> str:
    ftype = f.get("type", "")
    url = f.get("url", "")
    if ftype == "js-diff":
        delta = ",".join(f.get("added_routes", [])[:5] + f.get("added_ops", [])[:5])
        return sha(f"{ftype}|{f.get('canonical_key', url)}|{delta}")
    if ftype == "host-change":
        return sha(f"{ftype}|{url}|{f.get('transition', '')}")
    return sha(f"{ftype}|{url}")


def _persist_findings(program: str, findings: list[dict], rebuild: bool = False) -> int:
    """
    Run each candidate through the AI Validation Gate, drop false positives,
    and persist both JSON metadata and ready-to-submit REPORT-*.md files.
    """
    index = load_findings_index(program)
    saved = 0
    rejected = 0
    day_dir = FINDINGS_DIR / today_str() / program
    day_dir.mkdir(parents=True, exist_ok=True)

    for f in findings:
        if f.get("type") == "dangling-cname":
            continue
        h = _finding_dedupe_key(f)
        if not rebuild and h in index:
            continue

        f["program"] = program
        f["first_seen"] = now_utc()

        draft = validate_and_draft_report(f)
        if h not in index:
            append_finding_index(program, h)
            index.add(h)

        if draft is None:
            rejected += 1
            reason = f.get("_rejection_reason", "false positive")
            print(f"  [AI-REJECT] {h} {f.get('type')} dropped ({reason[:80]})")
            continue

        f["report_title"] = draft.get("title", "")
        f["severity_hint"] = draft.get("severity", f.get("severity_hint", "medium"))
        f["ai_score"] = draft.get("confidence_score", 80)
        report_name = f"REPORT-{program}-{f['type']}-{h}.md"
        f["report_file"] = report_name

        report_md = render_markdown_report(f, draft)
        (day_dir / report_name).write_text(report_md, encoding="utf-8")
        with open(day_dir / f"{f['type']}-{h}.json", "w", encoding="utf-8") as fh:
            json.dump(f, fh, ensure_ascii=False, indent=2)
        saved += 1
        print(
            f"  [VALIDATED-LEAD] {h} {f['type']} "
            f"[{f['severity_hint'].upper()} | AI:{f['ai_score']}/100] -> {report_name}"
        )
    if rejected:
        print(f"    (AI Gatekeeper membuang {rejected} false positive)")
    return saved


# ------------------------------------------------------------------ monitor

def _query_root_roots(policy: ProgramPolicy) -> list[str]:
    return [r.lstrip("*.") for r in policy.includes]


def cmd_monitor(args) -> None:
    """Passive discovery + scope/exclusion filtering + lossless probe queue."""
    program = args.program
    policy = load_program_policy(program, TARGETS_DIR)
    roots = _query_root_roots(policy)
    if not roots:
        print(f"[!] targets/{program}.txt kosong/tidak ada. Lewati.")
        return

    known = load_state(program)
    old_queue = {h for h in load_queue(program) if policy.in_scope(h)}
    discovered: set[str] = set()

    budget = int(os.environ.get("NOVA_MONITOR_BUDGET", "240"))
    start = time.monotonic()
    tasks = [(root, src) for root in roots for src in PASSIVE_SOURCES]
    holders = []
    skipped = 0

    print(
        f"[*] {program}: passive discovery {len(roots)} root x {len(PASSIVE_SOURCES)} sumber (budget {budget}s)..."
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {}
        for root, src in tasks:
            if time.monotonic() - start > budget:
                skipped = len(tasks) - len(futs)
                break
            holder: set[str] = set()
            holders.append((root, src.__name__, holder))
            futs[ex.submit(src, root, holder)] = None
        for fut in concurrent.futures.as_completed(futs):
            fut.result()

    if skipped:
        print(f"    [!] budget habis: {skipped} kombinasi root-sumber dilewati")

    for _, _, holder in holders:
        good = {n for n in holder if policy.in_scope(n)}
        discovered |= good

    if args.merge_file and Path(args.merge_file).exists():
        for line in Path(args.merge_file).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lstrip("*.").lower()
            if line and policy.in_scope(line):
                discovered.add(line)
        print(f"    + digabung dari {args.merge_file}")

    new = {h for h in (discovered - known) if policy.in_scope(h)}
    all_known = known | new
    save_state(program, all_known)

    # Backlog Seeder: bangunkan subdomain lama di subs.txt yang belum pernah diprobe v2.2
    hosts_state = load_hosts_state(program)
    if not old_queue and not hosts_state.get("_seeded") and all_known:
        probed_hosts = {k for k in hosts_state if not k.startswith("_")}
        unprobed = {h for h in all_known if policy.in_scope(h) and h not in probed_hosts}
        hosts_state["_seeded"] = True
        save_hosts_state(program, hosts_state)
        if unprobed:
            seeded = set(prioritize_hosts(unprobed, policy=policy)[:SEED_CAP])
            old_queue |= seeded
            print(
                f"    [+] Backlog seeder: membangunkan {len(seeded)}/{len(unprobed)} "
                f"subdomain prioritas dari state lama"
            )

    pending = prioritize_hosts(old_queue | new, policy=policy)
    batch = pending[:MAX_NEW_PROBE]
    remaining = pending[MAX_NEW_PROBE:]
    save_queue(program, remaining)

    out_dir = DATA_DIR / program
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "new.txt").write_text(("\n".join(sorted(new)) + "\n") if new else "", encoding="utf-8")
    (out_dir / "probe_batch.txt").write_text(
        ("\n".join(batch) + "\n") if batch else "", encoding="utf-8"
    )
    print(
        f"[=] {program}: total {len(discovered)} | known {len(known)} | BARU {len(new)} | "
        f"batch {len(batch)} | antrean sisa {len(remaining)}"
    )


# ------------------------------------------------------------------- probe

def _same_logical_host(host_a: str, host_b: str) -> bool:
    """Return True if two hostnames are identical or differ only by www."""
    a = host_a.lower().strip(".").removeprefix("www.")
    b = host_b.lower().strip(".").removeprefix("www.")
    return a == b


def probe_host(host: str, policy: ProgramPolicy) -> dict | None:
    """
    Probe single host safely with smart same-host redirect following (up to 3 hops)
    so 301/302/308 redirects reach the actual HTML and JS bundles.
    """
    if not policy.in_scope(host):
        return None
    if any(host.endswith(s) or s in host for s in PRIVATE_HOSTNAMES):
        return None

    ips = resolve_a(host)
    if not ips:
        return {"host": host, "status": "dead-dns", "url": None, "ips": []}
    if all(is_private_ip(ip) for ip in ips):
        return None

    result = {
        "host": host,
        "ips": ips,
        "status": None,
        "url": None,
        "http_status": None,
        "title": None,
        "server": None,
        "scripts": [],
        "catchall": False,
        "body": "",
    }

    for scheme in ("https", "http"):
        curr_url = f"{scheme}://{host}/"
        r = None
        err = None
        redirect_target = ""

        for _hop in range(4):
            r, err = http_get(curr_url)
            if r is None:
                break
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "").strip()
                if not loc:
                    break
                next_url = urljoin(curr_url, loc)
                redirect_target = next_url[:200]
                next_host = urlparse(next_url).netloc.split("@")[-1].split(":")[0].lower()
                # Follow only same-host redirects that are not login walls
                if _same_logical_host(host, next_host) and not LOGIN_PATH_RE.search(next_url):
                    curr_url = next_url
                    continue
            break

        if r is not None:
            body = getattr(r, "_nova_body", b"")[:25_000].decode("utf-8", "ignore")
            result["url"] = curr_url
            result["http_status"] = r.status_code
            result["server"] = r.headers.get("Server", "")
            result["body"] = body
            if redirect_target:
                result["redirect"] = redirect_target
            ct = r.headers.get("Content-Type", "")
            if "html" in ct.lower() or body.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m:
                    result["title"] = m.group(1).strip()[:120]
                for sm in SCRIPT_TAG_RE.finditer(body):
                    js_u = urljoin(curr_url, sm.group(1))
                    if policy.in_scope(js_u) and not is_vendor_js(js_u):
                        result["scripts"].append(js_u)
                if r.status_code == 200:
                    rr, _ = http_get(
                        f"{scheme}://{host}/nova-random-probe-{random.randint(1000,9999)}"
                    )
                    if rr is not None and rr.status_code == 200:
                        b2 = getattr(rr, "_nova_body", b"")[:2000].decode("utf-8", "ignore")
                        if abs(len(b2) - len(body[:2000])) < 80:
                            result["catchall"] = True
            return result
        if err in ("timeout", "ssl", "conn", "host-cap"):
            continue
        break

    result["status"] = "no-http"
    return result


def _merge_hosts_snapshot(
    hosts_state: dict, results: list[dict], policy: ProgramPolicy | None = None
) -> None:
    """Update persistent host snapshot with latest HTTP state."""
    stamp = now_utc()
    for res in results:
        if not res.get("url") or not res.get("http_status"):
            continue
        host = res["host"]
        hosts_state[host] = {
            "url": res["url"],
            "http_status": res["http_status"],
            "title": res.get("title") or "",
            "redirect": res.get("redirect") or "",
            "scripts": sorted(set(res.get("scripts", [])))[:30],
            "catchall": bool(res.get("catchall", False)),
            "interesting": is_interesting_host(host, policy),
            "last_checked": stamp,
        }


def cmd_probe(args) -> None:
    """Probe hosts in probe_batch.txt and record live snapshots."""
    program = args.program
    policy = load_program_policy(program, TARGETS_DIR)
    if not policy.includes:
        print(f"[!] targets/{program}.txt kosong. Lewati.")
        return

    batch_file = Path(args.batch_file) if args.batch_file else DATA_DIR / program / "probe_batch.txt"
    if not batch_file.exists():
        print(f"[!] {batch_file} tidak ada. Jalankan monitor dulu.")
        return

    hosts = [
        line.strip()
        for line in batch_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and policy.in_scope(line.strip())
    ]
    out_dir = DATA_DIR / program
    out_dir.mkdir(parents=True, exist_ok=True)
    if not hosts:
        print(f"[=] {program}: tidak ada host di batch utk diprobe.")
        (out_dir / "probe.jsonl").write_text("", encoding="utf-8")
        return

    print(f"[*] {program}: probing {len(hosts)} host (max {MAX_CONC} thread)...")
    results = []
    live = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONC) as ex:
        futures = {ex.submit(probe_host, h, policy): h for h in hosts}
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

    hosts_state = load_hosts_state(program)
    _merge_hosts_snapshot(hosts_state, results, policy=policy)
    save_hosts_state(program, hosts_state)
    print(f"[=] {program}: probe selesai. live={live}/{len(hosts)} | tracked={len(hosts_state)}")


# ------------------------------------------------------------------ verify

ENV_KEY_RE = re.compile(
    r"^\s*([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASS|AWS|SMTP|MAIL|DB|DATABASE|API|CRED)[A-Z0-9_]*)\s*[=:]\s*(.{8,})\s*$",
    re.IGNORECASE | re.MULTILINE,
)
ENV_PLACEHOLDERS = {
    "", "changeme", "change-me", "password", "your-password", "your_password_here",
    "null", "none", "true", "false", "0", "1", "xxx", "test", "example", "secret",
    "${var}", "%s", "********", "xxx-xxx-xxx",
}


def _env_secret(body: str):
    """Return (bool, evidence) requiring >=1 non-placeholder secret value."""
    if body.lstrip()[:1] == "<":
        return False, None
    hits = []
    for m in ENV_KEY_RE.finditer(body):
        key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
        if val.lower() in ENV_PLACEHOLDERS or val.startswith("${") or set(val) <= set("x*."):
            continue
        hits.append(f"{key}={redact(val, 3)}")
        if len(hits) >= 3:
            break
    return (True, "; ".join(hits)) if hits else (False, None)


EXPOSURE_CHECKS = [
    ("/.env", lambda b, h: _env_secret(b)),
    ("/.env.local", lambda b, h: _env_secret(b)),
    ("/.env.production", lambda b, h: _env_secret(b)),
    ("/.env.backup", lambda b, h: _env_secret(b)),
    ("/.git/config", lambda b, h: ("[core]" in b or '[remote "origin"]' in b, "git config present")),
    ("/.git/HEAD", lambda b, h: (b.strip().startswith("ref: refs/"), "git HEAD: " + b.strip()[:40])),
    ("/actuator/env", lambda b, h: ("propertySources" in b, "Spring actuator env JSON")),
    (
        "/actuator/heapdump",
        lambda b, h: (
            h.get("Content-Type", "").startswith("application/octet-stream")
            and int(h.get("Content-Length") or 0) > 500_000,
            "heapdump binary served (>500KB)",
        ),
    ),
    ("/debug/vars", lambda b, h: ("memstats" in b.lower() or "cmdline" in b.lower(), "Go expvar exposed")),
    (
        "/server-status",
        lambda b, h: ("apache server status for" in b.lower() and "scoreboard" in b.lower(), "Apache server-status exposed"),
    ),
]

HIGH_CLAIMABLE_SUFFIXES = (
    "s3.amazonaws.com", "s3-website", "s3-accelerate",
    "azurewebsites.net", "cloudapp.azure.com", "blob.core.windows.net",
    "herokuapp.com", "herokussl.com", "github.io", "gitlab.io", "bitbucket.io",
    "netlify.app", "vercel.app", "pages.dev", "surge.sh",
    "firebaseapp.com", "web.app", "readthedocs.io", "tumblr.com",
    "zendesk.com", "helpjuice.com", "helpscout.net", "readme.io",
    "canny.io", "teamwork.com", "pantheon.io",
)
SERVICE_APEXES = (
    "azurewebsites.net", "cloudapp.azure.com", "herokuapp.com", "github.io",
    "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "surge.sh", "readthedocs.io",
)
TAKEOVER_BODY_SIGS = [
    ("NoSuchBucket", "high"),
    ("There isn't a GitHub Pages site here", "high"),
    ("fastly error: unknown domain", "high"),
    ("The specified bucket does not exist", "high"),
    ("Repository not found", "medium"),
    ("no longer available", "medium"),
]


def check_takeover(host: str, policy: ProgramPolicy) -> dict | None:
    """
    Verify claimable subdomain takeovers across dual independent DoH resolvers
    (Cloudflare 1.1.1.1 + Google 8.8.8.8). Non-claimable CDN/ELB records are ignored.
    """
    if not policy.in_scope(host):
        return None
    cns_cf, _ = dns_lookup(host, DOH_ENDPOINTS[0][1])
    if not cns_cf:
        return None
    cname = cns_cf[-1]
    claimable = any(cname.endswith(sfx) or sfx in cname for sfx in HIGH_CLAIMABLE_SUFFIXES)
    if not claimable or cname in SERVICE_APEXES:
        return None

    _, ips_cf = dns_lookup(cname, DOH_ENDPOINTS[0][1])
    if not ips_cf:
        # Second-resolver confirmation via Google DoH
        cns_gg, _ = dns_lookup(host, DOH_ENDPOINTS[1][1])
        _, ips_gg = dns_lookup(cname, DOH_ENDPOINTS[1][1])
        if not ips_gg and (not cns_gg or cns_gg[-1] == cname):
            return {
                "type": "takeover",
                "url": f"https://{host}",
                "host": host,
                "severity_hint": "high",
                "confidence": "strong",
                "evidence": f"Dual-DoH verified dangling CNAME: {host} -> {cname} (NXDOMAIN on Cloudflare & Google DNS)",
                "request_evidence": f"$ dig {host} CNAME +short\n$ dig {cname} A +short",
                "response_evidence": (
                    f"Cloudflare DoH (1.1.1.1): {host} CNAME -> {' -> '.join(cns_cf)} | A = NXDOMAIN\n"
                    f"Google DoH (8.8.8.8):     {host} CNAME -> {' -> '.join(cns_gg or cns_cf)} | A = NXDOMAIN"
                ),
                "next": "Pastikan subdomain masuk scope policy; klaim resource di provider bila diizinkan aturan program untuk PoC.",
            }
        return None

    r, _ = http_get(f"https://{host}/")
    if r is not None and r.status_code == 404:
        body = getattr(r, "_nova_body", b"")[:4000].decode("utf-8", "ignore")
        for sig, sev in TAKEOVER_BODY_SIGS:
            if sig.lower() in body.lower():
                return {
                    "type": "takeover",
                    "url": f"https://{host}",
                    "host": host,
                    "severity_hint": sev,
                    "confidence": "strong",
                    "evidence": f"CNAME -> {cname}; HTTP 404 provider signature: '{sig}'",
                    "request_evidence": f"GET / HTTP/1.1\nHost: {host}",
                    "response_evidence": _format_resp_evidence(r, body[:600]),
                    "next": "Verifikasi manual ketersediaan resource di provider & cek policy program.",
                }
    return None


def check_cors(url: str) -> dict | None:
    """Check arbitrary Origin reflection WITH Access-Control-Allow-Credentials: true."""
    canary = "https://nova-cors-canary.example.com"
    r, _ = http_get(url, extra_headers={"Origin": canary})
    if r is None:
        return None
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == canary and acac.lower() == "true":
        parsed = urlparse(url)
        body = getattr(r, "_nova_body", b"")[:500].decode("utf-8", "ignore")
        return {
            "type": "cors",
            "url": url,
            "host": parsed.netloc.lower(),
            "severity_hint": "high",
            "confidence": "strong",
            "evidence": "ACAO reflects arbitrary Origin + Access-Control-Allow-Credentials: true",
            "request_evidence": f"GET {parsed.path or '/'} HTTP/1.1\nHost: {parsed.netloc}\nOrigin: {canary}",
            "response_evidence": _format_resp_evidence(r, body),
            "next": "Uji pada endpoint terautentikasi untuk memastikan respons membawa data sensitif user.",
        }
    return None


GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/api/v1/graphql")


def check_graphql(base_url: str, program: str = "") -> dict | None:
    """Check GraphQL introspection and extract custom queries/mutations as evidence."""
    if program.lower() == "shopify":
        return None
    query_payload = json.dumps(
        {
            "query": (
                "{ __schema { queryType { name } "
                "mutationType { name fields { name } } "
                "types { name kind } } }"
            )
        }
    )
    for p in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + p
        r, _ = http_get(
            url,
            method="POST",
            body=query_payload,
            extra_headers={"Content-Type": "application/json"},
        )
        if r is None or r.status_code != 200:
            continue
        body = getattr(r, "_nova_body", b"")[:25_000].decode("utf-8", "ignore")
        if "__schema" not in body:
            continue
        mutations = []
        custom_types = []
        try:
            data = json.loads(body).get("data", {}).get("__schema", {})
            m_fields = (data.get("mutationType") or {}).get("fields") or []
            mutations = [f.get("name") for f in m_fields if f.get("name")][:20]
            types = data.get("types") or []
            custom_types = [
                t.get("name")
                for t in types
                if t.get("name") and not str(t.get("name")).startswith("__")
                and t.get("name") not in ("String", "Int", "Float", "Boolean", "ID")
            ][:25]
        except Exception:
            pass
        if not mutations and len(custom_types) < 3:
            continue
        parsed = urlparse(url)
        ev_summary = (
            f"Introspection enabled | Mutations ({len(mutations)}): {', '.join(mutations[:8]) or 'none'} | "
            f"Types: {', '.join(custom_types[:8])}"
        )
        return {
            "type": "graphql",
            "url": url,
            "host": parsed.netloc.lower(),
            "severity_hint": "medium",
            "confidence": "strong" if mutations else "medium",
            "evidence": ev_summary[:220],
            "request_evidence": (
                f"POST {parsed.path} HTTP/1.1\nHost: {parsed.netloc}\n"
                f"Content-Type: application/json\n\n{query_payload}"
            ),
            "response_evidence": _format_resp_evidence(r, body[:800]),
            "next": "Audit daftar mutation & tipe sensitif di atas untuk menguji otorisasi/IDOR sesuai scope.",
        }
    return None


def _redact_body_secrets(body: str) -> str:
    """Redact raw secret values inside an exposure excerpt while preserving key names."""
    def _repl(m):
        return f"{m.group(1)}={redact(m.group(2).strip(), 3)}"
    return ENV_KEY_RE.sub(_repl, body[:1200])


def check_exposures(base_url: str, catchall: bool) -> list[dict]:
    """
    Check sensitive configuration exposure paths with a double-tap canary check
    to guarantee the host is not serving a catch-all 200 OK response.
    """
    if catchall:
        return []
    findings = []
    parsed_base = urlparse(base_url)

    for path, verdict in EXPOSURE_CHECKS:
        url = base_url.rstrip("/") + path
        r, _ = http_get(url)
        if r is None or r.status_code != 200:
            continue
        body = getattr(r, "_nova_body", b"")[:60_000].decode("utf-8", "ignore")
        ct = r.headers.get("Content-Type", "")
        if ct.startswith("text/html") or body.lstrip()[:1] == "<":
            continue
        ok, evidence = verdict(body, r.headers)
        if not ok:
            continue

        # Double-tap canary verification on the same host/directory
        parent = path.rsplit("/", 1)[0]
        canary_path = f"{parent}/nova-canary-{random.randint(10000, 99999)}"
        rc, _ = http_get(base_url.rstrip("/") + canary_path)
        if rc is not None and rc.status_code == 200:
            c_body = getattr(rc, "_nova_body", b"")[:60_000].decode("utf-8", "ignore")
            c_ok, _ = verdict(c_body, rc.headers)
            if c_ok or abs(len(c_body) - len(body)) < 60:
                continue

        safe_excerpt = (
            "[Binary heapdump stream > 500KB]"
            if path == "/actuator/heapdump"
            else _redact_body_secrets(body)
        )
        findings.append(
            {
                "type": "exposure",
                "url": url,
                "host": parsed_base.netloc.lower(),
                "severity_hint": "critical",
                "confidence": "strong",
                "evidence": evidence or path,
                "request_evidence": f"GET {path} HTTP/1.1\nHost: {parsed_base.netloc}",
                "response_evidence": _format_resp_evidence(r, safe_excerpt),
                "next": "Verifikasi manual di browser incognito, screenshot bukti, lalu kirim laporan.",
            }
        )
        break
    return findings


def _fetch_and_analyze_js(
    js_targets: list[tuple[str, bool]],
    policy: ProgramPolicy,
    js_state: dict,
    run_diff: bool = True,
) -> list[dict]:
    """Fetch unique in-scope non-vendor JS bundles and run secret + diff analysis."""
    findings = []
    seen_urls: set[str] = set()
    fetched = 0

    for js_url, is_interesting in js_targets:
        if fetched >= MAX_JS_FETCH:
            break
        js_url = js_url.strip()
        if not js_url or js_url in seen_urls:
            continue
        seen_urls.add(js_url)
        if not policy.in_scope(js_url) or is_vendor_js(js_url):
            continue

        fetched += 1
        r, _ = http_get(js_url, max_bytes=600_000)
        if r is None or r.status_code != 200:
            continue
        body = getattr(r, "_nova_body", b"").decode("utf-8", "ignore")
        if len(body) < 40:
            continue

        findings.extend(scan_js_secrets(body, js_url))

        if run_diff:
            entry, diff_finding = diff_js_bundle(js_url, body, js_state, is_interesting)
            if entry is not None:
                js_state[canonical_js_key(js_url)] = entry
            if diff_finding is not None:
                findings.append(diff_finding)
                sm_url = diff_finding.get("sourcemap_url")
                if sm_url and policy.in_scope(sm_url):
                    sm_resp, _ = http_get(sm_url, max_bytes=4096)
                    if sm_resp is not None and sm_resp.status_code == 200:
                        sm_head = getattr(sm_resp, "_nova_body", b"").decode("utf-8", "ignore")
                        if '"mappings"' in sm_head or '"sources"' in sm_head:
                            parsed_sm = urlparse(sm_url)
                            findings.append(
                                {
                                    "type": "sourcemap",
                                    "url": sm_url,
                                    "host": parsed_sm.netloc.lower(),
                                    "severity_hint": "low",
                                    "confidence": "strong",
                                    "evidence": f"SourceMap publik terbuka ({sm_url})",
                                    "request_evidence": f"GET {parsed_sm.path} HTTP/1.1\nHost: {parsed_sm.netloc}",
                                    "response_evidence": _format_resp_evidence(sm_resp, sm_head[:500]),
                                    "next": "Unduh sourcemap untuk audit source code frontend & logika API internal.",
                                }
                            )
    return findings


def cmd_verify(args) -> None:
    """Verify exposures, CORS, GraphQL, JS secrets, and takeover on newly probed hosts."""
    program = args.program
    policy = load_program_policy(program, TARGETS_DIR)
    if not policy.includes:
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

    findings: list[dict] = []
    js_targets: list[tuple[str, bool]] = []

    for res in probe_results:
        host = res.get("host", "")
        url = res.get("url")
        if not url or not policy.in_scope(host):
            continue
        if res.get("http_status") not in (200, 401, 403):
            continue
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        findings.extend(check_exposures(base, res.get("catchall", False)))
        if res.get("http_status") == 200 and not res.get("catchall"):
            f = check_cors(base)
            if f:
                findings.append(f)
            f = check_graphql(base, program=program)
            if f:
                findings.append(f)
        interesting = is_interesting_host(host, policy)
        for js_url in res.get("scripts", []):
            js_targets.append((js_url, interesting))

    if js_targets:
        js_state = load_js_state(STATE_DIR, program)
        findings.extend(_fetch_and_analyze_js(js_targets, policy, js_state, run_diff=True))
        save_js_state(STATE_DIR, program, js_state)

    takeover_pool: set[str] = set()
    if new_file.exists():
        takeover_pool |= {
            line.strip()
            for line in new_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and policy.in_scope(line.strip())
        }
    batch_file = out_dir / "probe_batch.txt"
    if batch_file.exists():
        takeover_pool |= {
            line.strip()
            for line in batch_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and policy.in_scope(line.strip())
        }
    cap = int(os.environ.get("NOVA_TAKEOVER_CAP", "2000"))
    sweep = prioritize_hosts(takeover_pool, policy=policy)[:cap] if takeover_pool else []
    print(f"[*] {program}: takeover check (dual-DoH claimable) pada {len(sweep)} host...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        for f in ex.map(lambda h: check_takeover(h, policy), sweep):
            if f:
                findings.append(f)

    saved = _persist_findings(program, findings, rebuild=getattr(args, "rebuild", False))
    print(f"[=] {program}: verify selesai ({len(findings)} kandidat, {saved} VALIDATED)")


# ------------------------------------------------------------------- diff

def detect_host_transition(host: str, prev: dict, curr: dict) -> dict | None:
    """Detect meaningful HTTP state changes on previously tracked hosts."""
    old_status = prev.get("http_status")
    new_status = curr.get("http_status")
    if not old_status or not new_status:
        return None

    if old_status in (401, 403, 404, 502, 503) and new_status == 200 and not curr.get("catchall"):
        transition = f"{old_status}->200"
        return {
            "type": "host-change",
            "url": curr["url"],
            "host": host,
            "transition": transition,
            "severity_hint": "medium",
            "confidence": "strong",
            "evidence": f"Status berubah {transition} (title: {curr.get('title') or '-'})",
            "request_evidence": f"GET / HTTP/1.1\nHost: {host}",
            "response_evidence": (
                f"Previous State: HTTP {old_status} (title: {prev.get('title') or '-'})\n"
                f"Current State:  HTTP 200 OK (title: {curr.get('title') or '-'})\n\n"
                f"{(curr.get('body') or '')[:500]}"
            ),
            "next": "Aset yang sebelumnya terbatas/mati kini menjawab 200 OK; cek fitur & kontrol akses manual.",
        }

    old_redir = (prev.get("redirect") or "").lower()
    if (
        old_status in (301, 302, 307, 308)
        and any(tok in old_redir for tok in ("/login", "/signin", "/auth", "/sso"))
        and new_status == 200
        and not curr.get("catchall")
    ):
        transition = f"auth-redirect({old_status})->200"
        return {
            "type": "host-change",
            "url": curr["url"],
            "host": host,
            "transition": transition,
            "severity_hint": "medium",
            "confidence": "strong",
            "evidence": f"Redirect login hilang -> langsung 200 OK (title: {curr.get('title') or '-'})",
            "request_evidence": f"GET / HTTP/1.1\nHost: {host}",
            "response_evidence": (
                f"Previous State: HTTP {old_status} Location: {prev.get('redirect')}\n"
                f"Current State:  HTTP 200 OK (title: {curr.get('title') or '-'})"
            ),
            "next": "Verifikasi di browser incognito apakah halaman internal terekspos tanpa auth.",
        }

    return None


def cmd_diff(args) -> None:
    """Watch tracked hosts for HTTP transitions and JS bundle route/API updates."""
    program = args.program
    policy = load_program_policy(program, TARGETS_DIR)
    hosts_state = load_hosts_state(program)
    if not hosts_state:
        print(f"[=] {program}: belum ada tracked hosts untuk diff.")
        return

    budget = int(getattr(args, "budget", None) or DIFF_BUDGET)
    candidates = [
        (host, info)
        for host, info in hosts_state.items()
        if not host.startswith("_") and isinstance(info, dict) and policy.in_scope(host)
    ]
    candidates.sort(
        key=lambda item: (
            0 if item[1].get("interesting") else 1,
            0 if item[1].get("http_status") in (200, 401, 403) else 2,
            item[1].get("last_checked", ""),
        )
    )
    selected = [h for h, _ in candidates[:budget]]
    if not selected:
        return

    print(f"[*] {program}: diff monitor pada {len(selected)}/{len(hosts_state)} tracked host...")
    refreshed: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONC) as ex:
        for res in ex.map(lambda h: probe_host(h, policy), selected):
            if res:
                refreshed.append(res)

    findings: list[dict] = []
    js_targets: list[tuple[str, bool]] = []
    stamp = now_utc()

    for res in refreshed:
        host = res["host"]
        prev = hosts_state.get(host, {})
        if res.get("url") and res.get("http_status"):
            transition = detect_host_transition(host, prev, res)
            if transition:
                findings.append(transition)
            hosts_state[host] = {
                "url": res["url"],
                "http_status": res["http_status"],
                "title": res.get("title") or "",
                "redirect": res.get("redirect") or "",
                "scripts": sorted(set(res.get("scripts", [])))[:30],
                "catchall": bool(res.get("catchall", False)),
                "interesting": is_interesting_host(host, policy),
                "last_checked": stamp,
            }
            for js_url in res.get("scripts", []):
                js_targets.append((js_url, is_interesting_host(host, policy)))
        elif host in hosts_state:
            hosts_state[host]["last_checked"] = stamp

    if js_targets:
        js_state = load_js_state(STATE_DIR, program)
        findings.extend(_fetch_and_analyze_js(js_targets, policy, js_state, run_diff=True))
        save_js_state(STATE_DIR, program, js_state)

    save_hosts_state(program, hosts_state)
    saved = _persist_findings(program, findings)
    print(f"[=] {program}: diff selesai ({len(findings)} sinyal, {saved} VALIDATED)")


# ------------------------------------------------------------------- brief

def collect_findings(date: str | None = None) -> list[dict]:
    """Collect and severity-sort all validated findings for a given UTC date."""
    day_dir = FINDINGS_DIR / (date or today_str())
    out = []
    if not day_dir.exists():
        return out
    for f in sorted(day_dir.rglob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda x: sev_rank.get(x.get("severity_hint", "low"), 9))
    return out


def build_briefing(date: str | None = None, include_ai: bool = True) -> str:
    """Build daily Markdown briefing of AI-validated findings."""
    findings = collect_findings(date)
    lines = [
        f"NOVA v2.2 VALIDATED BRIEFING - {date or today_str()}",
        "=" * 48,
    ]
    if not findings:
        lines.append("Tidak ada temuan valid baru pada run ini. Mesin tetap memantau aset & JS.")
        return "\n".join(lines)

    if include_ai:
        ai_notes = summarize_findings(findings)
        if ai_notes:
            lines.append("## Ringkasan Laporan Tervalidasi AI (Siap Kirim)")
            lines.append(ai_notes)
            lines.append("")

    by_prog: dict[str, list[dict]] = {}
    for f in findings:
        by_prog.setdefault(f.get("program", "?"), []).append(f)

    lines.append(f"Programs: {len(by_prog)} | Validated Reports: {len(findings)}")
    lines.append("")
    for prog, fl in by_prog.items():
        lines.append(f"### {prog} ({len(fl)} laporan siap kirim)")
        for f in fl[:10]:
            score = f.get("ai_score", "-")
            rep_file = f.get("report_file", "-")
            lines.append(
                f"[{f.get('severity_hint', '?').upper()} | AI:{score}/100] {f.get('type')} | {f.get('url', '')}"
            )
            lines.append(f"    Judul : {f.get('report_title', '-')[:160]}")
            lines.append(f"    Bukti : {f.get('evidence', '')[:180]}")
            lines.append(f"    File  : {rep_file}")
        if len(fl) > 10:
            lines.append(f"    ... +{len(fl) - 10} laporan lagi di findings/")
        lines.append("")
    lines.append("File REPORT-*.md lengkap dengan bukti HTTP/DNS & langkah reproduksi dikirim sebagai dokumen lampiran.")
    return "\n".join(lines)


def tg_send_text(text: str, chat_id: str = "") -> bool:
    """Send briefing message in Telegram-safe chunks."""
    target_chat = chat_id or TG_GENERAL or TG_DATA
    if not (TG_TOKEN and target_chat):
        print("[!] Telegram belum diset (TELEGRAM_TOKEN / TELEGRAM_GENERAL_ID). Briefing hanya file.")
        return False
    ok = True
    for i in range(0, len(text), 3800):
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={"chat_id": target_chat, "text": text[i : i + 3800]},
                timeout=20,
            )
            if r.status_code != 200:
                print(f"[!] Telegram sendMessage HTTP {r.status_code}")
                ok = False
        except Exception as e:
            print(f"[!] Telegram gagal: {type(e).__name__}")
            ok = False
    return ok


def tg_send_report_documents(day_dir: Path) -> int:
    """Send each individual REPORT-*.md file directly to Telegram as a ready-to-submit document."""
    target_chat = TG_GENERAL or TG_DATA
    if not (TG_TOKEN and target_chat and day_dir.exists()):
        return 0
    sent = 0
    for rpt in sorted(day_dir.rglob("REPORT-*.md"))[:15]:
        title_line = rpt.stem
        try:
            first_line = rpt.read_text(encoding="utf-8", errors="ignore").splitlines()[0]
            if first_line.startswith("# "):
                title_line = first_line[2:].strip()[:120]
        except Exception:
            pass
        caption = f"🚨 [LAPORAN SIAP KIRIM] {rpt.parent.name}: {title_line}"
        try:
            with open(rpt, "rb") as fh:
                r = requests.post(
                    f"https://api.telegram.org/bot{TG_TOKEN}/sendDocument",
                    data={"chat_id": target_chat, "caption": caption[:1000]},
                    files={"document": fh},
                    timeout=35,
                )
                if r.status_code == 200:
                    sent += 1
                else:
                    print(f"[!] Gagal kirim dokumen report HTTP {r.status_code}")
        except Exception as e:
            print(f"[!] Error kirim dokumen report: {type(e).__name__}")
    return sent


def cmd_brief(args) -> None:
    """Generate daily briefing Markdown and dispatch briefing + REPORT-*.md files via Telegram."""
    findings = collect_findings(args.date)
    day = args.date or today_str()
    day_dir = FINDINGS_DIR / day

    tok_state = "SET" if TG_TOKEN else "MISSING"
    gen_state = "SET" if TG_GENERAL else "MISSING"
    dat_state = "SET" if TG_DATA else "MISSING"
    ai_state = "SET" if os.environ.get("GROQ_API_KEY", "").strip() else "MISSING"
    print(
        f"[*] Config status: TELEGRAM_TOKEN={tok_state} | GENERAL_ID={gen_state} | "
        f"DATA_ID={dat_state} | GROQ_API_KEY={ai_state}"
    )

    if not findings and args.send_telegram and not args.force:
        print("[=] 0 laporan valid baru pada run ini -> Telegram tidak dikirim (anti-spam).")

    text = build_briefing(args.date, include_ai=not getattr(args, "no_ai", False))
    FINDINGS_DIR.mkdir(exist_ok=True)
    out = FINDINGS_DIR / f"BRIEFING-{day}.md"
    out.write_text(text, encoding="utf-8")

    msg_ok = False
    docs_sent = 0
    if args.send_telegram and (findings or args.force):
        msg_ok = tg_send_text(text)
        docs_sent = tg_send_report_documents(day_dir)

    archive_chat = TG_DATA or TG_GENERAL
    if args.send_telegram and TG_TOKEN and archive_chat and findings and day_dir.exists():
        import zipfile

        DATA_DIR.mkdir(exist_ok=True)
        zpath = DATA_DIR / f"NOVA_VALIDATED_REPORTS_{day}.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for p in day_dir.rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(FINDINGS_DIR))
        try:
            with open(zpath, "rb") as fh:
                requests.post(
                    f"https://api.telegram.org/bot{TG_TOKEN}/sendDocument",
                    data={"chat_id": archive_chat, "caption": f"📦 NOVA Validated Reports & Evidence ({day})"},
                    files={"document": fh},
                    timeout=60,
                )
        except Exception as e:
            print(f"[!] Kirim zip gagal: {type(e).__name__}")

    print(
        f"[+] Briefing: {out.name} | validated_reports: {len(findings)} | "
        f"tg_msg_sent: {msg_ok} | tg_docs_sent: {docs_sent}"
    )

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, "a", encoding="utf-8") as sf:
                sf.write(
                    f"\n### Status Validasi & Telegram\n"
                    f"- Secrets: `TELEGRAM_TOKEN={tok_state}`, `GENERAL_ID={gen_state}`, `DATA_ID={dat_state}`, `GROQ_API_KEY={ai_state}`\n"
                    f"- Laporan Valid (Lolos AI Gate): **{len(findings)}**\n"
                    f"- Terkirim ke Telegram: pesan=`{msg_ok}`, dokumen laporan=`{docs_sent}`\n"
                )
        except Exception:
            pass


# ------------------------------------------------------------------- scope

def cmd_scope(args) -> None:
    """Audit & normalize targets/*.txt preserving explicit subdomains and `!` excludes."""
    STATE_DIR.mkdir(exist_ok=True)
    print("=== NOVA SCOPE AUDIT (v2.2) ===")
    for f in sorted(TARGETS_DIR.glob("*.txt")):
        if f.stem == "test_target" or f.stem.startswith("_"):
            continue
        status, inc_count, exc_count, invalid = audit_target_file(f)
        print(f"  [{status}] {f.name}: {inc_count} include, {exc_count} exclude")
        if invalid:
            print(f"      invalid dilepas/diabaikan: {invalid}")
    print("[=] Scope audit selesai.")


# -------------------------------------------------------------------- run

def cmd_run(args) -> None:
    """Run full monitor -> probe -> verify -> diff -> brief pipeline."""
    if args.programs:
        programs = [p.strip() for p in args.programs.split(",") if p.strip()]
    elif not getattr(args, "all", False):
        focus = load_focus_programs(TARGETS_DIR)
        programs = focus if focus else list_programs()
    else:
        programs = list_programs()

    print(f"=== NOVA v2.2 RUN {now_utc()} ===")
    print(f"Programs ({len(programs)}): {', '.join(programs)}")
    for prog in programs:
        print(f"\n---- {prog} ----")
        cmd_monitor(argparse.Namespace(program=prog, merge_file=args.merge_file))
        if args.skip_probe:
            continue
        cmd_probe(argparse.Namespace(program=prog, batch_file=None))
        cmd_verify(argparse.Namespace(program=prog, probe_file=None, new_file=None, rebuild=False))
        cmd_diff(argparse.Namespace(program=prog, budget=getattr(args, "diff_budget", None)))
    print(f"\n=== SELESAI {now_utc()} ===")
    cmd_brief(
        argparse.Namespace(
            date=None,
            send_telegram=args.send_telegram,
            force=False,
            no_ai=getattr(args, "no_ai", False),
        )
    )


# -------------------------------------------------------------------- CLI

def main() -> None:
    ap = argparse.ArgumentParser(
        description="NOVA v2.2 - Intelligent Recon, AI Validation Gate & Report Generator"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scope", help="normalisasi & audit targets/*.txt (aman utk subdomain & !exclude)")
    s.set_defaults(func=cmd_scope)

    s = sub.add_parser("monitor", help="discovery pasif + diff state + antrean probe")
    s.add_argument("--program", required=True)
    s.add_argument("--merge-file", default=None, help="file subfinder tambahan utk digabung")
    s.set_defaults(func=cmd_monitor)

    s = sub.add_parser("probe", help="probe host (follow same-host redirect) & update snapshot hosts")
    s.add_argument("--program", required=True)
    s.add_argument("--batch-file", default=None)
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("verify", help="verifikasi + AI Validation Gate + generate REPORT-*.md")
    s.add_argument("--program", required=True)
    s.add_argument("--probe-file", default=None)
    s.add_argument("--new-file", default=None)
    s.add_argument("--rebuild", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("diff", help="pantau perubahan host & diff JS bundle + AI Validation Gate")
    s.add_argument("--program", required=True)
    s.add_argument("--budget", type=int, default=None)
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("brief", help="kirim briefing + dokumen REPORT-*.md siap kirim ke Telegram")
    s.add_argument("--date", default=None)
    s.add_argument("--send-telegram", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--no-ai", action="store_true")
    s.set_defaults(func=cmd_brief)

    s = sub.add_parser("run", help="pipeline lengkap utk target pilihan / semua")
    s.add_argument("--programs", default=None, help="koma-separated; default _focus.txt atau semua")
    s.add_argument("--all", action="store_true", help="abaikan targets/_focus.txt")
    s.add_argument("--merge-file", default=None)
    s.add_argument("--skip-probe", action="store_true")
    s.add_argument("--diff-budget", type=int, default=None)
    s.add_argument("--send-telegram", action="store_true")
    s.add_argument("--no-ai", action="store_true")
    s.set_defaults(func=cmd_run)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
