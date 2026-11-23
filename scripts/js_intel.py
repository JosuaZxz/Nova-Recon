"""JavaScript bundle change diffing, route extraction, and secret FP filtering."""

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

# Normalize content-hashed filenames: main.a1b2c3d4.js or app-1234abcd.js
HASH_CHUNK_RE = re.compile(
    r"([.\-_])[a-f0-9]{6,32}(?=(?:\.min)?\.m?js$)",
    re.IGNORECASE,
)

ENDPOINT_RE = re.compile(
    r"""['"`]((?:/api/|/v[1-9][0-9]?/|/graphql(?:/[a-z0-9_\-]+)?|/internal/|/admin/|/management/|/private/|/auth/|/oauth2?/|/webhook[s]?/|/billing/|/export|/users/)[a-zA-Z0-9_\-./:{}]{1,90})['"`]"""
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
    r"https://([a-z0-9][a-z0-9\-]{2,60}(?:\.[a-z0-9\-]+)?\.firebaseio\.com)",
    re.IGNORECASE,
)

SECRET_PATTERNS = (
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    (
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,60}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("Stripe live key", re.compile(r"\b([sr]k_live_[A-Za-z0-9]{20,})\b")),
    ("Slack token", re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[A-Za-z0-9\-]{10,})\b")),
    (
        "Slack webhook",
        re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"
        ),
    ),
    ("SendGrid key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b")),
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
    ("Mailgun key", re.compile(r"\b(key-[a-f0-9]{32})\b")),
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
)

MAX_ROUTES_PER_BUNDLE = 250
MAX_OPS_PER_BUNDLE = 100
MAX_BUNDLES_PER_PROGRAM = 250


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


def extract_cloud_urls(js_text: str) -> dict[str, list[str]]:
    """Extract unique AWS S3 buckets and Firebase Realtime DB URLs referenced in JS."""
    s3_buckets = set()
    for m in S3_URL_RE.finditer(js_text):
        bucket = (m.group(1) or m.group(2) or "").lower().strip(".")
        if bucket and not any(ig in bucket for ig in ("example", "test-bucket", "your-bucket", "amazonaws")):
            s3_buckets.add(f"https://{bucket}.s3.amazonaws.com")

    firebase_dbs = set()
    for m in FIREBASE_URL_RE.finditer(js_text):
        host = m.group(1).lower()
        if not any(ig in host for ig in ("example", "demo", "your-project", "firebaseio.com")):
            pass
        if not any(ig in host for ig in ("example", "your-project", "dummy")):
            firebase_dbs.add(f"https://{host}")

    return {
        "s3_urls": sorted(s3_buckets)[:25],
        "firebase_urls": sorted(firebase_dbs)[:15],
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
    sm = SOURCEMAP_RE.search(js_text[-2000:] if len(js_text) > 2000 else js_text)
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
    """Reject low-entropy / repeated dummy strings (e.g. AAAA..., 123456...)."""
    core = re.sub(r"^(AKIA|gh[pousr]_|github_pat_|[sr]k_live_|xox[baprs]-|SG\.|key-)", "", token)
    if len(set(core)) < 7:
        return False
    if any(seq in core.lower() for seq in ("12345678", "abcdefgh", "00000000", "xxxxxxxx")):
        return False
    return True


def scan_js_secrets(js_text: str, js_url: str) -> list[dict]:
    """Scan JS text for high-confidence leaked secrets while suppressing known FPs."""
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
    """Persist bounded JS bundle snapshots to keep git state lightweight."""
    state_dir.mkdir(exist_ok=True)
    if len(state) > MAX_BUNDLES_PER_PROGRAM:
        ordered = sorted(
            state.items(),
            key=lambda kv: kv[1].get("updated", ""),
            reverse=True,
        )[:MAX_BUNDLES_PER_PROGRAM]
        state = dict(ordered)
    path = state_dir / f"{program}.js.json"
    path.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")


def diff_js_bundle(
    js_url: str,
    js_text: str,
    js_state: dict,
    is_interesting_host: bool = False,
) -> tuple[dict | None, dict | None]:
    """Compare a JS bundle against its previous snapshot and emit a diff finding if warranted."""
    if is_vendor_js(js_url, js_text):
        return None, None

    key = canonical_js_key(js_url)
    intel = extract_js_intel(js_text, js_url)
    prev = js_state.get(key)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Skip duplicate bundles with identical sha256 already analyzed on sibling subdomains
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

    entry = {
        "last_url": js_url,
        "sha256": intel["sha256"],
        "routes": sorted(prev_routes | set(intel["routes"]))[:MAX_ROUTES_PER_BUNDLE],
        "graphql_ops": sorted(prev_ops | set(intel["graphql_ops"]))[:MAX_OPS_PER_BUNDLE],
        "updated": now,
    }

    # Alert on real deploy diffs (routes/ops added) or high-signal new interesting hosts
    high_signal_routes = [
        r
        for r in added_routes
        if any(
            kw in r.lower()
            for kw in (
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
            )
        )
    ]

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
