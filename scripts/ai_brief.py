"""AI validation gate and ready-to-submit bug report generator for NOVA v2.2."""

from __future__ import annotations

import json
import os
import re
import requests


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_NVIDIA_MODELS = (
    "nvidia/nemotron-3-ultra-550b-a55b",
    "nvidia/nemotron-3.5-lightning-30b-a3b",
)

WAF_OR_LOGIN_NOISE = (
    "attention required! | cloudflare",
    "request was blocked by our security service",
    "pardon our interruption",
    "access denied",
    "just a moment...",
    "cf-mitigated",
    "vercel security checkpoint",
    "firewall triggered",
    "ddos-guard",
    "incapsula incident id",
    "sucuri website firewall",
)

DIRECT_IMPACT_TYPES = (
    "exposure",
    "takeover",
    "js-secret",
    "cors",
    "unauth-api",
    "cloud-takeover",
    "cloud-exposure",
)


def deterministic_fp_check(finding: dict) -> tuple[bool, str]:
    """Fast deterministic pre-filter before calling the LLM validator."""
    ftype = finding.get("type", "")
    if ftype == "dangling-cname":
        return True, "Non-claimable CDN/ELB dangling CNAME (informative only)"

    # Bare js-diff (route strings in JS without proven unauthenticated 200 OK leak) is recon intel, NOT a reportable bug
    if ftype == "js-diff":
        return True, "JS route list alone is recon intel, not a reportable vulnerability without proven unauth data leak"

    if ftype == "host-change":
        return True, "Host status transition alone is recon intel, not a standalone vulnerability without proven exposure"

    if ftype == "sourcemap":
        return True, "Bare sourcemap without proven secret or unauthenticated API leak is Informative"

    if ftype == "graphql":
        return True, "GraphQL introspection alone without proven unauthenticated sensitive data leak is Informative (P5)"

    if ftype == "cors" and finding.get("severity_hint") != "high":
        return True, "CORS reflection without Access-Control-Allow-Credentials: true"

    res_ev = (finding.get("response_evidence") or "").lower()
    ev_txt = (finding.get("evidence") or "").lower()
    if any(marker in res_ev or marker in ev_txt for marker in WAF_OR_LOGIN_NOISE):
        return True, "WAF block or challenge page detected in response evidence"

    if ftype == "exposure":
        body_part = res_ev.split("\n\n", 1)[-1].lstrip() if "\n\n" in res_ev else res_ev.lstrip()
        if body_part.startswith("<!doctype html") or body_part.startswith("<html"):
            return True, "HTML catch-all page returned for configuration exposure check"

    return False, ""


def _fallback_draft(finding: dict) -> dict:
    """Build a structured report draft deterministically when Groq API is unavailable."""
    ftype = finding.get("type", "finding")
    prog = finding.get("program", "target")
    url = finding.get("url", "")
    sev = finding.get("severity_hint", "medium").lower()
    evidence = finding.get("evidence", "")

    titles = {
        "exposure": f"Sensitive Configuration / State Exposure on {url}",
        "takeover": f"Subdomain Takeover via Dangling Claimable CNAME on {finding.get('host', url)}",
        "js-secret": f"Hardcoded Credential / Secret Exposed in JavaScript Bundle on {prog}",
        "cors": f"Misconfigured CORS Allowing Arbitrary Origin with Credentials on {url}",
        "graphql": f"Exposed GraphQL Introspection and Schema Operations on {url}",
        "sourcemap": f"Exposed Production JavaScript SourceMap on {url}",
        "host-change": f"Previously Restricted Endpoint Transitioned to Public 200 OK on {url}",
        "unauth-api": f"Unauthenticated Sensitive API Data Exposure on {url}",
        "cloud-takeover": f"Unclaimed S3 Cloud Bucket Referenced in Active JavaScript Bundle ({url})",
        "cloud-exposure": f"Publicly Accessible Cloud Storage / Firebase Database Referenced in JS ({url})",
    }
    impacts = {
        "exposure": (
            "Unauthenticated access to configuration or runtime state files can expose "
            "environment secrets, internal endpoints, and service credentials."
        ),
        "takeover": (
            "An external actor can register the abandoned upstream cloud resource and "
            "serve arbitrary content under the legitimate subdomain, enabling phishing and cookie-scope abuse."
        ),
        "js-secret": (
            "Credentials embedded in client-side JavaScript bundles are accessible to any user "
            "and can be used to access third-party APIs or internal backend services."
        ),
        "cors": (
            "Reflecting arbitrary origins with Access-Control-Allow-Credentials: true allows "
            "cross-origin websites to read authenticated responses from victim sessions."
        ),
        "graphql": (
            "Publicly enabled GraphQL introspection reveals internal queries, mutations, and object fields "
            "that expand the attack surface for authorization testing."
        ),
        "sourcemap": (
            "Exposed source maps allow full reconstruction of unminified frontend source code, "
            "internal comments, and private API contract logic."
        ),
        "host-change": (
            "An endpoint that previously enforced access restrictions (401/403/404 or auth redirect) "
            "now responds with 200 OK and should be verified for broken access control."
        ),
        "unauth-api": (
            "An internal or private API route discovered via JavaScript bundle analysis responds with "
            "200 OK and returns sensitive JSON data without requiring authentication."
        ),
        "cloud-takeover": (
            "An active JavaScript bundle loads or references an AWS S3 bucket that returns NoSuchBucket. "
            "An external actor can claim the bucket name in AWS and serve attacker-controlled assets or scripts to application users."
        ),
        "cloud-exposure": (
            "A cloud storage bucket or Firebase Realtime Database referenced by the frontend bundle allows "
            "unauthenticated directory listing or JSON data read access."
        ),
    }
    remediations = {
        "exposure": "Block public access to dotfiles, `.git`, `/actuator`, and debug endpoints at the reverse proxy / web server layer and rotate any exposed credentials.",
        "takeover": "Remove the dangling CNAME record from DNS immediately or reclaim the upstream cloud resource name.",
        "js-secret": "Revoke and rotate the exposed credential immediately, remove it from frontend bundles, and route sensitive requests through a backend proxy.",
        "cors": "Replace dynamic Origin reflection with a strict allowlist of trusted origins when `Access-Control-Allow-Credentials: true` is enabled.",
        "graphql": "Disable GraphQL introspection in production environments unless explicitly required for public APIs, and enforce field-level authorization.",
        "sourcemap": "Disable `.js.map` generation or restrict access to source map files in production deployments.",
        "host-change": "Verify that authentication and role-based access controls are properly enforced on the newly accessible host.",
        "unauth-api": "Enforce authentication and role-based authorization checks on the exposed API endpoint before returning any internal or user data.",
        "cloud-takeover": "Remove references to the decommissioned S3 bucket from the frontend bundle or re-create and lock down the bucket in AWS.",
        "cloud-exposure": "Restrict S3 bucket ACLs / bucket policies to disable public ListBucket access, or configure Firebase Security Rules to require authentication.",
    }

    return {
        "verdict": "VALID",
        "confidence_score": 80 if finding.get("confidence") == "strong" else 70,
        "title": titles.get(ftype, f"Security Finding ({ftype}) on {url}"),
        "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
        "summary": (
            f"During automated non-destructive reconnaissance on `{prog}`, NOVA detected a `{ftype}` "
            f"issue affecting `{url}`. Verification evidence: {evidence}"
        ),
        "technical_analysis": (
            f"The endpoint `{url}` returned verifiable evidence matching `{ftype}` criteria "
            f"while passing anti-catch-all and false-positive checks.\n\nDetails: {evidence}"
        ),
        "steps_to_reproduce": [
            f"1. Confirm `{url}` is listed as in-scope on the `{prog}` program policy page.",
            f"2. Open `{url}` in a clean Private/Incognito browser session or send a standard non-destructive HTTP/DNS request as shown in the Evidence section below.",
            f"3. Observe the verified behavior: {evidence}",
            f"4. Recommended manual step: {finding.get('next', 'Verify impact manually before submitting.')}",
        ],
        "impact": impacts.get(ftype, "Potential unauthorized information disclosure or access control weakness."),
        "remediation": remediations.get(ftype, "Restrict access to the affected resource and review configuration."),
    }


def _eligible_for_fallback(finding: dict) -> bool:
    """Only allow deterministic fallback reports for strong direct-impact bug categories."""
    return (
        finding.get("confidence") == "strong"
        and finding.get("type") in DIRECT_IMPACT_TYPES
    )


def _parse_llm_response(resp_json: dict, required_key: str | None = "verdict") -> dict | None:
    """Extract and parse a JSON object from an OpenAI-compatible chat response."""
    try:
        choices = resp_json.get("choices") or []
        if not choices:
            return None
        content = (choices[0].get("message") or {}).get("content")
        if not content:
            return None
        text = str(content).strip()
        match = re.search(r"\{.*\}", text, re.DOTALL)
        parsed = json.loads(match.group(0) if match else text)
        if not isinstance(parsed, dict):
            return None
        if required_key and required_key not in parsed:
            return None
        return parsed
    except Exception:
        return None


def _query_llm_providers(
    prompt: str,
    max_tokens: int = 1500,
    fast: bool = False,
    required_key: str | None = "verdict",
) -> dict | None:
    """Query Groq first, then fail over automatically to NVIDIA NIM models."""
    req_timeout = 20 if fast else 35
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    if groq_key:
        groq_model = os.environ.get("NOVA_AI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
        try:
            resp = requests.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": groq_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": min(max_tokens, 1100) if fast else max_tokens,
                    "response_format": {"type": "json_object"},
                },
                timeout=req_timeout,
            )
            if resp.status_code == 200:
                parsed = _parse_llm_response(resp.json(), required_key=required_key)
                if parsed is not None:
                    return parsed
        except Exception:
            pass

    nvidia_key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if nvidia_key:
        override_model = os.environ.get("NOVA_NVIDIA_MODEL", "").strip()
        base_models = (
            ("nvidia/nemotron-3.5-lightning-30b-a3b", "nvidia/nemotron-3-ultra-550b-a55b")
            if fast
            else DEFAULT_NVIDIA_MODELS
        )
        candidates = []
        if override_model:
            candidates.append(override_model)
        for m in base_models:
            if m not in candidates:
                candidates.append(m)

        for nv_model in candidates:
            try:
                resp = requests.post(
                    NVIDIA_API_URL,
                    headers={
                        "Authorization": f"Bearer {nvidia_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": nv_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": max_tokens,
                        "chat_template_kwargs": {"enable_thinking": False},
                    },
                    timeout=req_timeout,
                )
                if resp.status_code == 200:
                    parsed = _parse_llm_response(resp.json(), required_key=required_key)
                    if parsed is not None:
                        return parsed
            except Exception:
                continue

    return None


_UNSAFE_ACTION_KW = ("delete", "remove", "reset", "logout", "drop", "destroy", "revoke")


def _has_ai_credentials() -> bool:
    return bool(
        os.environ.get("GROQ_API_KEY", "").strip()
        or os.environ.get("NVIDIA_API_KEY", "").strip()
    )


def _sanitize_endpoint(ep: str) -> str | None:
    if not isinstance(ep, str):
        return None
    s = ep.strip()
    if not s or len(s) > 160 or any(c in s for c in (" ", "'", '"', "<", ">", "\n", "\r")):
        return None
    if not (s.startswith("/") or s.startswith(("http://", "https://"))):
        return None
    low = s.lower()
    if any(kw in low for kw in _UNSAFE_ACTION_KW):
        return None
    return s


def ai_hunt_js_bundle(
    js_url: str,
    snippet_text: str,
    program: str = "",
    scope_roots: list[str] | None = None,
) -> dict:
    """Ask AI to actively reconstruct GET endpoints, in-scope subdomains, and real secrets from JS snippets."""
    empty = {"endpoints": [], "subdomains": [], "secrets": []}
    if not snippet_text or not snippet_text.strip() or not _has_ai_credentials():
        return empty

    roots = [r.lower().lstrip("*.").strip(".") for r in (scope_roots or []) if r]
    prompt = (
        "You are an automated Read-Only Bug Bounty JS Hunter.\n"
        f"Program: {program or 'target'} | In-scope root domains: {', '.join(roots[:8]) or 'same origin'}\n"
        f"Source JS URL: {js_url}\n\n"
        "Analyze the JavaScript code snippets below and extract ONLY concrete, non-destructive targets:\n"
        "1. 'endpoints': up to 10 read-only GET API routes or full URLs reconstructed from variables/concatenation/template literals (replace path parameters like :id or {id} with 1 or me; never include destructive delete/reset/logout actions).\n"
        "2. 'subdomains': up to 10 in-scope subdomains referenced anywhere in the snippets.\n"
        "3. 'secrets': up to 3 genuine leaked backend/service credentials or high-privilege tokens (skip public publishable keys, test keys, or placeholders) as {\"name\": \"...\", \"value\": \"...\"}.\n\n"
        "Return ONLY raw JSON: {\"endpoints\": [...], \"subdomains\": [...], \"secrets\": [...]}\n\n"
        f"SNIPPETS:\n{snippet_text[:3500]}"
    )
    parsed = _query_llm_providers(prompt, max_tokens=700, fast=True, required_key=None)
    if not parsed:
        return empty

    endpoints: list[str] = []
    for raw in (parsed.get("endpoints") or [])[:12]:
        clean = _sanitize_endpoint(raw)
        if clean and clean not in endpoints:
            endpoints.append(clean)
        if len(endpoints) >= 10:
            break

    subdomains: list[str] = []
    for raw in (parsed.get("subdomains") or [])[:15]:
        if not isinstance(raw, str):
            continue
        h = raw.strip().lower().rstrip(".")
        if not h or " " in h or "/" in h:
            continue
        if roots and not any(h == r or h.endswith("." + r) for r in roots):
            continue
        if h not in subdomains:
            subdomains.append(h)
        if len(subdomains) >= 10:
            break

    secrets: list[dict] = []
    for item in (parsed.get("secrets") or [])[:5]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "AI-detected secret").strip()[:60]
        val = str(item.get("value") or "").strip()
        if len(val) >= 16:
            secrets.append({"name": name, "value": val})
        if len(secrets) >= 3:
            break

    return {"endpoints": endpoints, "subdomains": subdomains, "secrets": secrets}


def ai_suggest_host_paths(program: str, hosts_meta: list[dict]) -> dict[str, list[str]]:
    """Fingerprint up to 4 live hosts in one batch and predict read-only GET API/config paths."""
    if not hosts_meta or not _has_ai_credentials():
        return {}

    compact = []
    for item in hosts_meta[:4]:
        compact.append(
            {
                "host": str(item.get("host", "")),
                "http_status": item.get("http_status"),
                "title": str(item.get("title") or "")[:80],
                "server": str(item.get("server") or "")[:60],
                "body_head": str(item.get("body_head") or "")[:240],
            }
        )
    prompt = (
        "You are an automated Read-Only Bug Bounty Recon Strategist.\n"
        f"Program: {program}\n"
        "Fingerprint each host below from its status, title, Server header, and body snippet, and predict up to 4 high-value, strictly read-only GET paths to check for unauthenticated API/config/schema leaks (e.g., /api/v1/users, /api/v1/config, /v2/keys, /realms/master/.well-known/openid-configuration, /api/swagger.json). Never suggest destructive paths.\n"
        "Return ONLY raw JSON mapping hostname -> array of path strings starting with '/'.\n\n"
        f"HOSTS:\n{json.dumps(compact, ensure_ascii=False)}"
    )
    parsed = _query_llm_providers(prompt, max_tokens=600, fast=True, required_key=None)
    if not parsed:
        return {}

    out: dict[str, list[str]] = {}
    valid_hosts = {c["host"] for c in compact if c["host"]}
    for host, paths in parsed.items():
        if host not in valid_hosts or not isinstance(paths, list):
            continue
        cleaned: list[str] = []
        for p in paths[:6]:
            s = _sanitize_endpoint(p)
            if s and s.startswith("/") and len(s) <= 120 and s not in cleaned:
                cleaned.append(s)
            if len(cleaned) >= 4:
                break
        if cleaned:
            out[host] = cleaned
    return out


def ai_classify_json_response(url: str, body_excerpt: str) -> tuple[bool, str]:
    """Use AI to classify whether an unauthenticated 200 OK JSON body leaks sensitive data."""
    if not _has_ai_credentials() or len((body_excerpt or "").strip()) < 40:
        return False, ""

    prompt = (
        "You are a Security Triage Analyst classifying an unauthenticated HTTP 200 JSON response.\n"
        f"URL: {url}\n"
        "Decide if this response leaks sensitive private/internal/user data (PII, emails, credentials, tokens, internal config, tenant/user records, permission dumps) vs harmless public metadata (translations, locales, public UI flags, public marketing catalog).\n"
        'Return ONLY JSON: {"is_sensitive": true/false, "confidence_score": 0 to 100, "evidence_summary": "short summary"}\n\n'
        f"JSON EXCERPT:\n{body_excerpt[:800]}"
    )
    parsed = _query_llm_providers(prompt, max_tokens=250, fast=True, required_key=None)
    if not parsed:
        return False, ""
    try:
        is_sens = bool(parsed.get("is_sensitive") is True)
        score = int(parsed.get("confidence_score") or 0)
        summary = str(parsed.get("evidence_summary") or "").strip()[:180]
        if is_sens and score >= 80:
            return True, summary or "AI classified response as leaking sensitive unauthenticated data"
    except Exception:
        pass
    return False, ""


def validate_and_draft_report(finding: dict) -> dict | None:
    """
    Validate a candidate finding via deterministic rules + Groq / NVIDIA AI (if configured).
    Returns a report draft dict if VALID, or None if rejected as a FALSE_POSITIVE.
    """
    is_fp, reason = deterministic_fp_check(finding)
    if is_fp:
        finding["_rejection_reason"] = reason
        return None

    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    nvidia_key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not groq_key and not nvidia_key:
        if _eligible_for_fallback(finding):
            return _fallback_draft(finding)
        finding["_rejection_reason"] = "Fallback rejected non-direct or medium-confidence finding"
        return None

    payload_ctx = {
        "program": finding.get("program", ""),
        "type": finding.get("type", ""),
        "url": finding.get("url", ""),
        "host": finding.get("host", ""),
        "severity_hint": finding.get("severity_hint", ""),
        "confidence": finding.get("confidence", ""),
        "evidence": finding.get("evidence", ""),
        "request_evidence": (finding.get("request_evidence") or "")[:900],
        "response_evidence": (finding.get("response_evidence") or "")[:1500],
        "added_routes": finding.get("added_routes", [])[:15],
        "added_ops": finding.get("added_ops", [])[:15],
    }

    prompt = (
        "You are a Principal Bug Bounty Triage Auditor.\n"
        "Evaluate the following candidate security finding and its raw HTTP/DNS evidence.\n\n"
        "STRICT VALIDATION RULES:\n"
        "1. REJECT AS FALSE_POSITIVE if:\n"
        "   - The response is a generic HTML page, SPA catch-all, login redirect, or 403/401 WAF block.\n"
        "   - A secret/key is a public client-side placeholder, dummy/example key, or third-party UI library artifact.\n"
        "   - A subdomain takeover points to a non-claimable CDN/ELB or apex domain without a claimable resource name.\n"
        "   - The finding has no plausible security impact or verifiable evidence.\n"
        "2. MARK AS VALID if the evidence shows genuine leaked secrets/configs, a multi-resolver claimable dangling CNAME, "
        "unclaimed S3 bucket (NoSuchBucket) or open cloud storage/Firebase DB referenced in JS, unauthenticated 200 OK JSON leaking sensitive user/internal fields, "
        "CORS reflection with credentials=true, GraphQL introspection exposing state-changing mutations, "
        "or a 403/404->200 host transition exposing an internal interface.\n"
        "3. Never invent CVEs or fabricate evidence not present in the input.\n"
        "4. If VALID, write a clear, professional, ready-to-submit Bug Bounty Report (in English for platform submission, with concise Indonesian notes in steps if helpful).\n\n"
        "Return ONLY valid JSON matching this schema:\n"
        "{\n"
        '  "verdict": "VALID" or "FALSE_POSITIVE",\n'
        '  "confidence_score": 0 to 100,\n'
        '  "rejection_reason": "reason if FALSE_POSITIVE else empty string",\n'
        '  "title": "Concise professional bug report title",\n'
        '  "severity": "critical|high|medium|low",\n'
        '  "summary": "Executive summary of the vulnerability",\n'
        '  "technical_analysis": "Detailed explanation referencing the exact evidence",\n'
        '  "steps_to_reproduce": ["1. Step one...", "2. Step two..."],\n'
        '  "impact": "Concrete security and business impact",\n'
        '  "remediation": "Actionable fix for the engineering team"\n'
        "}\n\n"
        f"CANDIDATE DATA:\n{json.dumps(payload_ctx, ensure_ascii=False)}"
    )

    parsed = _query_llm_providers(prompt)
    if parsed is None:
        if _eligible_for_fallback(finding):
            return _fallback_draft(finding)
        finding["_rejection_reason"] = "Fallback rejected non-direct or medium-confidence finding"
        return None

    try:
        verdict = str(parsed.get("verdict", "")).upper()
        score = int(parsed.get("confidence_score") or 0)
    except Exception:
        if _eligible_for_fallback(finding):
            return _fallback_draft(finding)
        finding["_rejection_reason"] = "Fallback rejected malformed AI verdict"
        return None

    if verdict == "FALSE_POSITIVE" or score < 65:
        finding["_rejection_reason"] = parsed.get("rejection_reason") or f"AI score {score} < 65"
        return None

    fallback = _fallback_draft(finding)
    return {
        "verdict": "VALID",
        "confidence_score": score,
        "title": parsed.get("title") or fallback["title"],
        "severity": (parsed.get("severity") or fallback["severity"]).lower(),
        "summary": parsed.get("summary") or fallback["summary"],
        "technical_analysis": parsed.get("technical_analysis") or fallback["technical_analysis"],
        "steps_to_reproduce": parsed.get("steps_to_reproduce") or fallback["steps_to_reproduce"],
        "impact": parsed.get("impact") or fallback["impact"],
        "remediation": parsed.get("remediation") or fallback["remediation"],
    }


def render_markdown_report(finding: dict, draft: dict) -> str:
    """Render a complete, ready-to-submit Markdown bug bounty report with raw evidence."""
    prog = finding.get("program", "unknown")
    url = finding.get("url", "")
    ftype = finding.get("type", "")
    sev = draft.get("severity", finding.get("severity_hint", "medium")).upper()
    score = draft.get("confidence_score", 80)
    req_ev = (finding.get("request_evidence") or "").strip()
    res_ev = (finding.get("response_evidence") or "").strip()

    steps = draft.get("steps_to_reproduce") or []
    if isinstance(steps, list):
        steps_text = "\n".join(str(s) for s in steps)
    else:
        steps_text = str(steps)

    lines = [
        f"# {draft.get('title', 'Security Vulnerability Report')}",
        "",
        "## Metadata",
        f"- **Program:** `{prog}`",
        f"- **Category:** `{ftype}`",
        f"- **Severity:** **{sev}**",
        f"- **AI Validation Score:** `{score}/100 (VALIDATED)`",
        f"- **Affected Asset / URL:** `{url}`",
        f"- **Timestamp (UTC):** `{finding.get('first_seen', '')}`",
        "",
        "## Executive Summary",
        draft.get("summary", ""),
        "",
        "## Technical Analysis",
        draft.get("technical_analysis", ""),
        "",
        "## Steps to Reproduce",
        steps_text,
        "",
        "## Proof of Concept / Non-Destructive Evidence",
        f"- **Verification Summary:** `{finding.get('evidence', '')}`",
    ]

    if req_ev:
        lines.extend(
            [
                "",
                "### Request / Lookup",
                "```http",
                req_ev,
                "```",
            ]
        )
    if res_ev:
        lines.extend(
            [
                "",
                "### Response / Output Excerpt",
                "```http",
                res_ev,
                "```",
            ]
        )

    if finding.get("added_routes"):
        lines.extend(
            [
                "",
                "### Newly Added API Routes (JS Diff)",
                "```text",
                "\n".join(finding["added_routes"][:25]),
                "```",
            ]
        )
    if finding.get("added_ops"):
        lines.extend(
            [
                "",
                "### Newly Added GraphQL Operations (JS Diff)",
                "```text",
                "\n".join(finding["added_ops"][:20]),
                "```",
            ]
        )

    lines.extend(
        [
            "",
            "## Impact",
            draft.get("impact", ""),
            "",
            "## Remediation",
            draft.get("remediation", ""),
            "",
            "---",
            "*Checklist sebelum klik Submit di platform:*",
            "1. Pastikan URL di atas masuk tabel In-Scope terbaru pada halaman policy program.",
            "2. Buka URL di browser Incognito / terminal untuk mengambil screenshot tambahan bila diminta triager.",
        ]
    )
    return "\n".join(lines) + "\n"


def summarize_findings(findings: list[dict]) -> str | None:
    """Build a concise overview of validated findings for the top of the daily briefing."""
    if not findings:
        return None
    lines = []
    for idx, f in enumerate(findings[:8], start=1):
        title = f.get("report_title") or f.get("evidence", "")[:90]
        score = f.get("ai_score", "-")
        lines.append(
            f"{idx}. [{f.get('severity_hint', '?').upper()} | AI:{score}/100] "
            f"{f.get('program', '?')} ({f.get('type', '?')}): {title}\n"
            f"   URL: {f.get('url', '')}"
        )
    return "\n".join(lines)
