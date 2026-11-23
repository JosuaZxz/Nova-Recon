"""AI validation gate and ready-to-submit bug report generator for NOVA v2.2."""

from __future__ import annotations

import json
import os
import re
import requests


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"

WAF_OR_LOGIN_NOISE = (
    "attention required! | cloudflare",
    "request was blocked by our security service",
    "pardon our interruption",
    "access denied",
    "just a moment...",
    "cf-mitigated",
)


def deterministic_fp_check(finding: dict) -> tuple[bool, str]:
    """Fast deterministic pre-filter before calling the LLM validator."""
    ftype = finding.get("type", "")
    if ftype == "dangling-cname":
        return True, "Non-claimable CDN/ELB dangling CNAME (informative only)"

    # Bare js-diff (route strings in JS without proven unauthenticated 200 OK leak) is recon intel, NOT a reportable bug
    if ftype == "js-diff":
        return True, "JS route list alone is recon intel, not a reportable vulnerability without proven unauth data leak"

    if ftype == "cors" and finding.get("severity_hint") != "high":
        return True, "CORS reflection without Access-Control-Allow-Credentials: true"

    res_ev = (finding.get("response_evidence") or "").lower()
    if any(marker in res_ev for marker in WAF_OR_LOGIN_NOISE):
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


def validate_and_draft_report(finding: dict) -> dict | None:
    """
    Validate a candidate finding via deterministic rules + Groq AI (if configured).
    Returns a report draft dict if VALID, or None if rejected as a FALSE_POSITIVE.
    """
    is_fp, reason = deterministic_fp_check(finding)
    if is_fp:
        finding["_rejection_reason"] = reason
        return None

    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        if finding.get("confidence") == "strong" and finding.get("type") in (
            "exposure",
            "takeover",
            "js-secret",
            "cors",
            "unauth-api",
        ):
            return _fallback_draft(finding)
        finding["_rejection_reason"] = "No GROQ_API_KEY and finding is not strong-confidence direct proof"
        return None

    model = os.environ.get("NOVA_AI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
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
        "CORS reflection with credentials=true, GraphQL introspection exposing sensitive mutations/types, an exposed production sourcemap, "
        "a 403/404->200 host transition, or newly deployed sensitive internal/admin/auth/billing API routes.\n"
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

    try:
        resp = requests.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1100,
                "response_format": {"type": "json_object"},
            },
            timeout=40,
        )
        if resp.status_code != 200:
            return _fallback_draft(finding)

        content = resp.json()["choices"][0]["message"]["content"].strip()
        match = re.search(r"\{.*\}", content, re.DOTALL)
        parsed = json.loads(match.group(0) if match else content)

        verdict = str(parsed.get("verdict", "")).upper()
        score = int(parsed.get("confidence_score") or 0)
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
    except Exception:
        return _fallback_draft(finding)


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
