"""JavaScript bundle change diffing, route extraction, cloud asset discovery, and secret filtering."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse


VENDOR_JS_RE = re.compile(
    r"(jquery|bootstrap|gtag|googletagmanager|google-analytics|analytics\.js|"
    r"recaptcha|hcaptcha|turnstile|cloudflare|polyfill|lodash|moment\.min|"
    r"axios\.min|swiper|chart\.min|jsrsasign|validator\.min|react-dom|"
    r"vue\.runtime|sentry|datadog|intercom|zendesk|onetrust|cookiebot|"
    r"hotjar|clarity\.ms|facebook\.net|fbevents|tiktok\.com|snapchat)",
    re.IGNORECASE,
)

# Normalize content-hashed filenames such as main.a1b2c3d4.js or app-1234abcd.js.
HASH_CHUNK_RE = re.compile(
    r"([.\-_])[a-f0-9]{6,32}(?=(?:\.min)?\.m?js$)",
    re.IGNORECASE,
)

ENDPOINT_RE = re.compile(
    r"""['"`]((?:/api/|/v[1-9][0-9]?/|/graphql(?:/[a-z0-9_\-]+)?|/internal/|/admin/|/management/|/private/|/auth/|/oauth2?/|/webhook[s]?/|/billing/|/export|/users/|/debug/|/actuator/)[a-zA-Z0-9_\-./:{}]{1,90})['"`]"""
)

IGNORE_ROUTE_PARTS = (
    "/api/v1/widget",
    "/api/v2/widget",
    "/api/v1/analytics",
    "/api/v1/events",
    "/api/v1/track",
    "/api/v1/metrics",
    "/api/v1/telemetry",
    "/api/v1/ping",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/locales",
    "/api/v1/translations",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".css",
    ".woff",
    ".ico",
)

HIGH_SIGNAL_ROUTE_KW = (
    "/admin",
    "/internal",
    "/private",
    "/graphql",
    "/auth",
    "/oauth",
    "/billing",
    "/export",
    "/webhook",
    "/users",
    "/management",
    "/debug",
    "/actuator",
    "/secret",
    "/token",
    "/tenant",
)

GRAPHQL_OP_RE = re.compile(
    r"\b(?:query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]{2,50})\b"
)

SENSITIVE_KEY_RE = re.compile(
    r"\b(impersonate|isAdmin|isSuperAdmin|adminRole|internalToken|"
    r"bypassAuth|debugMode|featureFlags?|redirect_?uri|callback_?url)\b",
    re.IGNORECASE,
)

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"<>]+)")

S3_URL_RE = re.compile(
    r"https?://(?:([a-z0-9][a-z0-9.\-_]{2,61})\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|"
    r"s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-_]{2,61}))",
    re.IGNORECASE,
)

FIREBASE_URL_RE = re.compile(
    r"https://([a-z0-9][a-z0-9\-]{2,60}(?:\.[a-z0-9\-]+)?\.(?:firebaseio\.com|firebasedatabase\.app))",
    re.IGNORECASE,
)

GCS_URL_RE = re.compile(
    r"https?://(?:storage\.googleapis\.com/([a-z0-9][a-z0-9.\-_]{2,61})(?=[/?'\"\s])|"
    r"([a-z0-9][a-z0-9.\-_]{2,61})\.storage\.googleapis\.com)",
    re.IGNORECASE,
)

AZURE_BLOB_RE = re.compile(
    r"https://([a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9][a-z0-9\-]{2,62})",
    re.IGNORECASE,
)

SECRET_PATTERNS = (
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    (
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,60}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("GitLab token", re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,50})\b")),
    ("Stripe live key", re.compile(r"\b([sr]k_live_[A-Za-z0-9]{20,})\b")),
    ("Slack token", re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[A-Za-z0-9\-]{10,})\b")),
    (
        "Slack webhook",
        re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"
        ),
    ),
    ("SendGrid key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b")),
    ("Resend API key", re.compile(r"\b(re_[A-Za-z0-9_]{28,50})\b")),
    ("Brevo API key", re.compile(r"\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b")),
    ("Mailgun key", re.compile(r"\b(key-[a-f0-9]{32})\b")),
    ("OpenAI project key", re.compile(r"\b(sk-proj-[A-Za-z0-9_\-]{40,180})\b")),
    ("Anthropic API key", re.compile(r"\b(sk-ant-api03-[A-Za-z0-9_\-]{50,140})\b")),
    ("Groq API key", re.compile(r"\b(gsk_[A-Za-z0-9]{40,80})\b")),
    ("HuggingFace token", re.compile(r"\b(hf_[A-Za-z0-9]{34,60})\b")),
    ("Shopify private token", re.compile(r"\b(shp(?:at|ca|ss|pa)_[a-fA-F0-9]{32})\b")),
    ("Telegram Bot token", re.compile(r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b")),
    ("NPM access token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("Doppler service token", re.compile(r"\b(dp\.(?:pt|st|ct)\.[A-Za-z0-9_]{36,60})\b")),
    ("Linear API key", re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b")),
    ("Mapbox secret token", re.compile(r"\b(sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,})\b")),
    (
        "Database credentials URI",
        re.compile(
            r"((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|rediss?|amqp)://"
            r"[^/\s'\":<>]{2,64}:[^@\s'\"<>]{8,128}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})"
        ),
    ),
    (
        "Google Service Account",
        re.compile(r'"type"\s*:\s*"service_account"[\s\S]{1,250}?"private_key"\s*:'),
    ),
    (
        "Private key block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[A-Za-z0-9+/=\r\n\\n]{220,}-----END [A-Z ]*?PRIVATE KEY-----"
        ),
    ),
    (
        "Hardcoded Bearer JWT",
        re.compile(
            r"Bearer\s+(eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})"
        ),
    ),
    (
        "Hardcoded Basic Auth header",
        re.compile(
            r"""['"]Authorization['"]\s*:\s*['"]Basic\s+([A-Za-z0-9+/]{24,}={0,2})['"]"""
        ),
    ),
)

FP_CONTEXT_HINTS = (
    "example",
    "sample",
    "dummy",
    "placeholder",
    "your_key",
    "your-api-key",
    "test_key",
    "jsrsasign",
    "node-forge",
    "pkcs8",
    "mock",
    "redact",
    "localhost",
    "127.0.0.1",
    "user:pass",
    "username:password",
)

MAX_ROUTES_PER_BUNDLE = 250
MAX_OPS_PER_BUNDLE = 100
MAX_BUNDLES_PER_PROGRAM = 300


def redact(value: str, keep: int = 4) -> str:
    """Redact the middle of a sensitive token for safe reporting."""
    v = value.strip()
    if len(v) <= keep * 2 + 3:
        return v[:keep] + "***"
    return v[:keep] + "..." + v[-keep:]


def canonical_js_key(js_url: str) -> str:
    """Normalize a versioned JS URL so deploy hashes map to the same logical bundle."""
    parsed = urlparse(js_url.strip())
    path = HASH_CHUNK_RE.sub(r"\1HASH", parsed.path)
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path}"


def is_vendor_js(js_url: str, body_head: str = "") -> bool:
    """Return True for third-party/vendor JS libraries unlikely to contain target routes."""
    if VENDOR_JS_RE.search(js_url):
        return True
    head = body_head[:400].lower()
    return any(
        marker in head
        for marker in ("jquery foundation", "jsrsasign", "/*! bootstrap", "react-dom")
    )


JS_LINE_COMMENT_RE = re.compile(r"(?m)^\s*//.*$")
JS_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]{0,4000}?\*/")


def extract_cloud_urls(js_text: str) -> dict[str, list[str]]:
    """Extract unique AWS S3, Firebase Realtime DB, GCS, and Azure Blob URLs outside JS comments."""
    active_code = JS_BLOCK_COMMENT_RE.sub(" ", JS_LINE_COMMENT_RE.sub(" ", js_text))
    s3_buckets = set()
    for m in S3_URL_RE.finditer(active_code):
        bucket = (m.group(1) or m.group(2) or "").lower().strip(".")
        if bucket and not any(
            ig in bucket for ig in ("example", "test-bucket", "your-bucket", "amazonaws", "esp-link")
        ):
            s3_buckets.add(f"https://{bucket}.s3.amazonaws.com")

    firebase_dbs = set()
    for m in FIREBASE_URL_RE.finditer(active_code):
        host = m.group(1).lower()
        if not any(ig in host for ig in ("example", "your-project", "dummy")):
            firebase_dbs.add(f"https://{host}")

    gcs_buckets = set()
    for m in GCS_URL_RE.finditer(active_code):
        bucket = (m.group(1) or m.group(2) or "").lower().strip(".")
        if bucket and not any(ig in bucket for ig in ("example", "your-bucket", "googleapis", "gstatic")):
            gcs_buckets.add(f"https://storage.googleapis.com/{bucket}")

    azure_blobs = set()
    for m in AZURE_BLOB_RE.finditer(active_code):
        blob_path = m.group(1).lower().strip("/")
        if blob_path and not any(ig in blob_path for ig in ("example", "contoso", "youraccount")):
            azure_blobs.add(f"https://{blob_path}?restype=container&comp=list")

    return {
        "s3_urls": sorted(s3_buckets)[:25],
        "firebase_urls": sorted(firebase_dbs)[:15],
        "gcs_urls": sorted(gcs_buckets)[:15],
        "azure_urls": sorted(azure_blobs)[:15],
    }


def extract_js_intel(js_text: str, js_url: str) -> dict:
    """Extract API routes, GraphQL operations, sensitive keywords, and sourcemap URL."""
    routes = set()
    for match in ENDPOINT_RE.findall(js_text):
        route = match.strip()
        lower = route.lower()
        if len(route) < 4 or any(part in lower for part in IGNORE_ROUTE_PARTS):
            continue
        routes.add(route)

    gql_ops = set(GRAPHQL_OP_RE.findall(js_text))
    keywords = {m.lower() for m in SENSITIVE_KEY_RE.findall(js_text)}

    sourcemap_url = None
    sm = SOURCEMAP_RE.search(js_text[-2500:] if len(js_text) > 2500 else js_text)
    if sm:
        raw_map = sm.group(1).strip()
        if raw_map and not raw_map.startswith("data:"):
            sourcemap_url = urljoin(js_url, raw_map)

    return {
        "sha256": hashlib.sha256(js_text.encode("utf-8", "ignore")).hexdigest()[:20],
        "routes": sorted(routes)[:MAX_ROUTES_PER_BUNDLE],
        "graphql_ops": sorted(gql_ops)[:MAX_OPS_PER_BUNDLE],
        "keywords": sorted(keywords)[:30],
        "sourcemap_url": sourcemap_url,
    }


def _has_real_entropy(token: str) -> bool:
    """Reject low-entropy or repeated dummy strings."""
    core = re.sub(
        r"^(AKIA|gh[pousr]_|github_pat_|glpat-|[sr]k_live_|xox[baprs]-|SG\.|re_|xkeysib-|"
        r"key-|sk-proj-|sk-ant-api03-|gsk_|hf_|shp(?:at|ca|ss|pa)_|npm_|dp\.[a-z]{2}\.|lin_api_|sk\.|eyJ)",
        "",
        token,
    )
    if len(set(core)) < 7:
        return False
    if any(seq in core.lower() for seq in ("12345678", "abcdefgh", "00000000", "xxxxxxxx", "${")):
        return False
    return True


def scan_js_secrets(js_text: str, js_url: str) -> list[dict]:
    """Scan JS or HTML text for high-confidence leaked secrets while suppressing known FPs."""
    if is_vendor_js(js_url, js_text):
        return []

    parsed = urlparse(js_url)
    findings = []
    for name, rx in SECRET_PATTERNS:
        m = rx.search(js_text)
        if not m:
            continue
        start = max(0, m.start() - 120)
        end = min(len(js_text), m.end() + 120)
        raw_ctx = js_text[start:end]
        ctx = raw_ctx.lower()
        if any(hint in ctx for hint in FP_CONTEXT_HINTS):
            continue
        token = m.group(1) if m.groups() else m.group(0)
        if name != "Google Service Account" and not _has_real_entropy(token):
            continue
        redacted_token = redact(token, 5)
        safe_snippet = raw_ctx.replace(token, redacted_token).replace("\n", " ").strip()[:300]
        findings.append(
            {
                "type": "js-secret",
                "url": js_url,
                "host": parsed.netloc.lower(),
                "severity_hint": "critical",
                "confidence": "strong",
                "evidence": f"{name}: {redacted_token}",
                "request_evidence": f"GET {parsed.path or '/'} HTTP/1.1\nHost: {parsed.netloc}",
                "response_evidence": (
                    f"HTTP/1.1 200 OK\nContent-Type: application/javascript\n\n"
                    f"... {safe_snippet} ..."
                ),
                "next": "Verifikasi validitas token secara pasif (jangan eksekusi write/destruct), cek scope program sebelum report.",
            }
        )
        break
    return findings


def load_js_state(state_dir: Path, program: str) -> dict:
    """Load persisted JS bundle snapshots for a program."""
    path = state_dir / f"{program}.js.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_js_state(state_dir: Path, program: str, state: dict) -> None:
    """Persist bounded JS bundle snapshots without transient underscore fields."""
    state_dir.mkdir(exist_ok=True)
    cleaned = {
        k: {ek: ev for ek, ev in v.items() if not ek.startswith("_")}
        for k, v in state.items()
        if isinstance(v, dict)
    }
    if len(cleaned) > MAX_BUNDLES_PER_PROGRAM:
        ordered = sorted(
            cleaned.items(),
            key=lambda kv: kv[1].get("updated", ""),
            reverse=True,
        )[:MAX_BUNDLES_PER_PROGRAM]
        cleaned = dict(ordered)
    path = state_dir / f"{program}.js.json"
    path.write_text(json.dumps(cleaned, ensure_ascii=False, indent=1), encoding="utf-8")


def diff_js_bundle(
    js_url: str,
    js_text: str,
    js_state: dict,
    is_interesting_host: bool = False,
) -> tuple[dict | None, dict | None]:
    """Compare a JS bundle against its previous snapshot and attach newly seen routes/maps."""
    if is_vendor_js(js_url, js_text):
        return None, None

    key = canonical_js_key(js_url)
    intel = extract_js_intel(js_text, js_url)
    prev = js_state.get(key)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Skip duplicate bundles whose sha256 was already analyzed on a sibling subdomain.
    seen_hashes = {
        v.get("sha256")
        for v in js_state.values()
        if isinstance(v, dict) and v.get("sha256")
    }
    if intel["sha256"] in seen_hashes:
        if prev:
            prev["last_url"] = js_url
            prev["updated"] = now
            return prev, None
        return {
            "last_url": js_url,
            "sha256": intel["sha256"],
            "routes": intel["routes"][:MAX_ROUTES_PER_BUNDLE],
            "graphql_ops": intel["graphql_ops"][:MAX_OPS_PER_BUNDLE],
            "updated": now,
        }, None

    if prev and prev.get("sha256") == intel["sha256"]:
        prev["last_url"] = js_url
        prev["updated"] = now
        return prev, None

    prev_routes = set(prev.get("routes", [])) if prev else set()
    prev_ops = set(prev.get("graphql_ops", [])) if prev else set()

    added_routes = sorted(set(intel["routes"]) - prev_routes)
    added_ops = sorted(set(intel["graphql_ops"]) - prev_ops)
    is_update = prev is not None

    high_signal_routes = [
        r for r in added_routes if any(kw in r.lower() for kw in HIGH_SIGNAL_ROUTE_KW)
    ]

    # Attach transient fields so nova.py always tests new routes and sourcemaps even on non-keyword hosts.
    entry = {
        "last_url": js_url,
        "sha256": intel["sha256"],
        "routes": sorted(prev_routes | set(intel["routes"]))[:MAX_ROUTES_PER_BUNDLE],
        "graphql_ops": sorted(prev_ops | set(intel["graphql_ops"]))[:MAX_OPS_PER_BUNDLE],
        "updated": now,
        "_unseen_hash": True,
        "_added_routes": (added_routes if is_update else (high_signal_routes or added_routes[:10])),
        "_sourcemap_url": intel["sourcemap_url"],
    }

    should_report = (
        (is_update and (len(added_routes) > 0 or len(added_ops) > 0))
        or (not is_update and is_interesting_host and (len(high_signal_routes) > 0 or len(added_ops) > 0))
    )

    if not should_report:
        return entry, None

    routes_preview = (added_routes if is_update else high_signal_routes)[:12]
    ops_preview = added_ops[:10]
    parts = []
    if routes_preview:
        parts.append("routes baru: " + ", ".join(routes_preview))
    if ops_preview:
        parts.append("GraphQL ops baru: " + ", ".join(ops_preview))
    if intel["keywords"]:
        parts.append("flags: " + ", ".join(intel["keywords"][:6]))

    parsed = urlparse(js_url)
    prev_sha = prev.get("sha256", "none") if prev else "none"
    finding = {
        "type": "js-diff",
        "url": js_url,
        "host": parsed.netloc.lower(),
        "canonical_key": key,
        "is_update": is_update,
        "severity_hint": "medium" if is_update else "low",
        "confidence": "strong" if is_update else "medium",
        "added_routes": added_routes[:30],
        "added_ops": added_ops[:20],
        "sourcemap_url": intel["sourcemap_url"],
        "evidence": (
            ("Deploy JS berubah -> " if is_update else "JS host prioritas -> ")
            + " | ".join(parts)
        ),
        "request_evidence": f"GET {parsed.path or '/'} HTTP/1.1\nHost: {parsed.netloc}",
        "response_evidence": (
            f"Bundle Key: {key}\nPrevious SHA256: {prev_sha}\nNew SHA256: {intel['sha256']}\n"
            f"Added Routes ({len(added_routes)}): {', '.join(routes_preview)}\n"
            f"Added GraphQL Ops ({len(added_ops)}): {', '.join(ops_preview)}"
        ),
        "next": "Review manual di browser/proxy: uji kontrol akses (IDOR/authz) pada endpoint atau operasi baru sesuai scope.",
    }
    return entry, finding


_PARAM_VAR_RE = re.compile(r"(?:\$\{[^}]+\}|\{[^}]+\}|:[a-zA-Z0-9_]+)")
_FULL_URL_RE = re.compile(r"""https?://([a-z0-9.\-_]{3,120})(/[a-zA-Z0-9_\-./:?=&]{4,100})?""", re.IGNORECASE)
_SNIPPET_MARKERS = (
    "fetch(",
    "axios.",
    ".get(",
    "Authorization",
    "Bearer ",
    "apiKey",
    "client_secret",
    "internal",
    "admin",
    "graphql",
    "swagger",
    "openapi",
    "process.env",
    "NEXT_PUBLIC_",
    "window.__",
)


def normalize_parameterized_routes(routes: list[str]) -> list[str]:
    """Convert parameterized paths/URLs into safe, concrete GET verification candidates."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in routes:
        r = str(raw or "").strip()
        if not r or not (r.startswith("/") or r.startswith(("http://", "https://"))):
            continue
        if _PARAM_VAR_RE.search(r):
            for sample in ("1", "me"):
                cand = _PARAM_VAR_RE.sub(sample, r)
                if cand not in seen and " " not in cand and "'" not in cand and '"' not in cand:
                    seen.add(cand)
                    out.append(cand)
        else:
            if r not in seen and " " not in r and "'" not in r and '"' not in r:
                seen.add(r)
                out.append(r)
    return out


def extract_in_scope_hosts_and_urls(js_text: str, scope_roots: list[str]) -> tuple[list[str], list[str]]:
    """Extract deterministic in-scope subdomains and full API URLs from active JS code."""
    active_code = JS_BLOCK_COMMENT_RE.sub(" ", JS_LINE_COMMENT_RE.sub(" ", js_text))
    roots = [r.lower().lstrip("*.").strip(".") for r in (scope_roots or []) if r]
    subs: set[str] = set()
    api_urls: set[str] = set()
    if not roots:
        return [], []
    for m in _FULL_URL_RE.finditer(active_code):
        host = m.group(1).lower().strip(".")
        path = m.group(2) or ""
        if not any(host == root or host.endswith("." + root) for root in roots):
            continue
        subs.add(host)
        lower_p = path.lower()
        if path and any(kw in lower_p for kw in ("/api/", "/v1/", "/v2/", "/v3/", "/internal/", "/admin/", "/graphql", "/export", "/users", "/swagger", "/openapi")):
            if not any(part in lower_p for part in IGNORE_ROUTE_PARTS):
                api_urls.add(f"https://{host}{path}")
    return sorted(subs)[:40], sorted(api_urls)[:25]


def extract_high_signal_snippets(js_text: str, max_chars: int = 3500) -> str:
    """Extract deduplicated +-140 char windows around high-signal markers in active JS code."""
    active_code = JS_BLOCK_COMMENT_RE.sub(" ", JS_LINE_COMMENT_RE.sub(" ", js_text))
    if not active_code:
        return ""
    windows: list[str] = []
    seen_ranges: list[tuple[int, int]] = []
    lower = active_code.lower()
    for marker in _SNIPPET_MARKERS:
        m_low = marker.lower()
        idx = 0
        hits = 0
        while hits < 3:
            pos = lower.find(m_low, idx)
            if pos == -1:
                break
            idx = pos + len(marker)
            start = max(0, pos - 140)
            end = min(len(active_code), pos + len(marker) + 140)
            if any(not (end <= s or start >= e) for s, e in seen_ranges):
                continue
            seen_ranges.append((start, end))
            snippet = active_code[start:end].replace("\n", " ").strip()
            if snippet:
                windows.append(snippet)
            hits += 1
    combined = "\n---\n".join(windows)
    return combined[:max_chars]
