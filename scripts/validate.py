import os
import json
import requests
import subprocess
import re
import time
import hashlib
from datetime import datetime

# --- [ CONFIGURATION ] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"
GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-70b-versatile",
    "llama-3.1-8b-instant",
]


def _as_text(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        return value.get("raw") or value.get("body") or json.dumps(value)
    return str(value)


def extract_http_pair(data):
    req = _as_text(data.get("request") or data.get("request-raw"))
    res = _as_text(data.get("response") or data.get("response-raw"))
    return req[:600], (res[:1200] if len(res) > 1200 else res)


def get_verification_context(data):
    info = data.get("info", {}) or {}
    matcher = data.get("matcher-name", "Behavioral Match")
    extracted = data.get("extracted-results", [])
    req, res = extract_http_pair(data)
    tid = data.get("template-id", "Unknown")

    status_match = re.search(r"^HTTP/\d\.\d\s+(400|401|403|404|405|406|429|502|503)", res)
    if status_match:
        return None

    if re.search(r"^HTTP/\d\.\d\s+(301|302|307|308)", res):
        if re.search(r"Location:.*(/login|/signin|/auth|/sso|oauth|redirect_uri|wp-login)", res, re.IGNORECASE):
            return None

    noise_keywords = [
        "phs.getpostman.com",
        "schema.getpostman.com",
        "the nlb has been offline",
        "request was blocked by our security service",
        "attention required! | cloudflare",
        "pardon our interruption",
    ]
    res_lower = res.lower()

    secret_regex = re.compile(
        r"("
        r"AKIA[0-9A-Z]{16}|"
        r"ghp_[a-zA-Z0-9]{36}|"
        r"AIza[0-9A-Za-z-_]{35}|"
        r"[rs]k_live_[a-zA-Z0-9]{24}|"
        r"xox[baprs]-[0-9]{12}-[0-9]{12}|"
        r"sq0csp-[0-9A-Za-z\-_]{43}|"
        r"BEGIN (RSA|OPENSSH) PRIVATE KEY"
        r")"
    )

    if any(noise in res_lower for noise in noise_keywords):
        if not secret_regex.search(res):
            return None

    if "token" in tid.lower() or "key" in tid.lower() or "credential" in tid.lower():
        if res and not secret_regex.search(res) and not re.search(r'("email"\s*:\s*"[^"]+@[^"]+\.[^"]+")', res_lower):
            return None

    return {
        "template_id": tid,
        "template_name": info.get("name", "Unknown Bug Type"),
        "matcher_logic": matcher,
        "extracted_data": extracted,
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "request_evidence": req or "(empty — Nuclei did not include request body)",
        "response_evidence": res or "(empty — Nuclei did not include response body)",
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def create_h1_draft(title, description, impact, severity, url):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                return "ALREADY_REPORTED"

    if PROGRAM_NAME in ["00_test", "test_target"]:
        return "TEST-DRAFT-ID-2026"

    if not H1_USER or not H1_API_KEY:
        return None

    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"

    payload = {
        "data": {
            "type": "report-intent",
            "attributes": {
                "team_handle": target_handle,
                "title": title,
                "description": description,
                "impact": impact,
                "severity_rating": h1_sev,
            },
        }
    }

    try:
        time.sleep(2)
        res = requests.post(
            "https://api.hackerone.com/v1/hackers/report_intents",
            auth=auth,
            headers={"Accept": "application/json"},
            json=payload,
            timeout=30,
        )
        print(f"[H1] report_intent HTTP {res.status_code} handle={target_handle}")
        if res.status_code == 201:
            with open(SEEN_DB, "a") as f:
                f.write(f"{url_hash}\n")
            return res.json()["data"]["id"]
    except Exception as e:
        print(f"[H1] draft failed: {e}")
    return None


def already_seen(tid):
    url_hash = hashlib.md5(f"{PROGRAM_NAME}_{tid}".encode()).hexdigest()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as db_read:
            if url_hash in db_read.read():
                return True, url_hash
    return False, url_hash


def mark_seen(url_hash):
    with open(SEEN_DB, "a") as db_append:
        db_append.write(f"{url_hash}\n")


def write_alert(sev_folder, tid, header, body):
    os.makedirs(f"data/{PROGRAM_NAME}/alerts/{sev_folder}", exist_ok=True)
    report_path = f"data/{PROGRAM_NAME}/alerts/{sev_folder}/{tid}.md"
    with open(report_path, "w", encoding="utf-8") as f_report:
        f_report.write(header)
        f_report.write(body)
    print(f"[+] Saved alert: {report_path}")
    return report_path


def raw_markdown(tid, findings, urls_list, runner_ip):
    first = findings[0]
    return f"""# [MANUAL REVIEW] {first['template_name']} in {PROGRAM_NAME}

## Vulnerability Details
- **Template:** `{tid}`
- **Severity (scanner):** {first['severity']}
- **Matcher:** {first.get('matcher_logic')}
- **Scanner IP:** {runner_ip}
- **Time:** {first.get('time')}

## Affected Assets
{urls_list}

## Evidence (from Nuclei)
### Request
```http
{first.get('request_evidence')}
```

### Response
```http
{first.get('response_evidence')}
```

Extracted: `{first.get('extracted_data')}`

This file was written by the scanner gate, not by AI. Confirm in-scope and reproduce manually before submitting.
"""


def parse_ai_json(ai_data):
    match = re.search(r"\{.*\}", ai_data, re.DOTALL)
    if not match:
        return None
    raw_json = match.group(0)
    try:
        return json.loads(raw_json, strict=False)
    except json.JSONDecodeError:
        try:
            return json.loads(raw_json.replace("\n", "\\n"), strict=False)
        except json.JSONDecodeError as e:
            print(f"[-] AI JSON parse failed: {e}")
            return None


def ask_groq(prompt):
    if not AI_KEY:
        print("[-] GROQ_API_KEY missing, skip AI polish")
        return None

    headers = {"Authorization": f"Bearer {AI_KEY}"}
    url = "https://api.groq.com/openai/v1/chat/completions"
    last_err = None
    for model in GROQ_MODELS:
        try:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            }
            res = requests.post(url, headers=headers, json=payload, timeout=120)
            print(f"[Groq] model={model} HTTP {res.status_code}")
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"].strip()
            last_err = res.text[:300]
        except Exception as e:
            last_err = str(e)
            print(f"[Groq] {model} error: {e}")
    print(f"[-] Groq failed: {last_err}")
    return None


def write_summary(raw_lines, parsed_ok, dropped_noise, grouped_findings):
    os.makedirs(f"data/{PROGRAM_NAME}/alerts", exist_ok=True)
    lines = [
        f"SCAN SUMMARY — {PROGRAM_NAME}",
        f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Nuclei JSON lines: {raw_lines}",
        f"Parsed OK: {parsed_ok}",
        f"Dropped as noise/low: {dropped_noise}",
        f"Templates that passed filter: {len(grouped_findings)}",
        "",
    ]
    if grouped_findings:
        lines.append("Passed templates:")
        for tid, findings in grouped_findings.items():
            urls = ", ".join(f["matched_url"] for f in findings[:5])
            lines.append(f"- {tid} x{len(findings)} | {urls}")
    else:
        lines.append("No findings passed the technical filter.")
        if raw_lines == 0:
            lines.append("Cause: Nuclei returned 0 hits (scanner, templates, or WAF).")
        else:
            lines.append("Cause: hits existed but were filtered (401/403/WAF/info).")

    text = "\n".join(lines) + "\n"
    path = f"data/{PROGRAM_NAME}/alerts/summary.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(text)
    return path


def validate_findings():
    print(f"Starting Intelligence Triage for: {PROGRAM_NAME}")
    path = f"data/{PROGRAM_NAME}/nuclei_results.json"
    raw_lines = 0
    parsed_ok = 0
    dropped_noise = 0
    grouped_findings = {}

    if os.path.exists(path) and os.stat(path).st_size > 0:
        trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw_lines += 1
                try:
                    d = json.loads(line)
                    if isinstance(d, list):
                        d = d[0]
                    parsed_ok += 1
                    tid = d.get("template-id", "Unknown")
                    sev = (d.get("info", {}) or {}).get("severity", "info").lower()

                    if sev not in ["medium", "high", "critical"] or any(t in tid for t in trash):
                        dropped_noise += 1
                        continue

                    ctx = get_verification_context(d)
                    if not ctx:
                        dropped_noise += 1
                        continue
                    grouped_findings.setdefault(tid, []).append(ctx)
                except Exception:
                    continue

    write_summary(raw_lines, parsed_ok, dropped_noise, grouped_findings)
    if not grouped_findings:
        return

    runner_ip = subprocess.getoutput("curl -s --max-time 10 ifconfig.me")
    if not runner_ip or len(runner_ip) > 20:
        runner_ip = "GitHub_Runner_Scanner"

    luxury_template = """
.# {title} in {program}

.## Vulnerability Details
- **Severity:** {severity}
- **Affected Assets:**
{urls_list}
- **Scanner IP:** {ip}

.## Quick Verification Link
- **Primary Test URL:** {verify_url}
- **Instructions:** Open the link in a private window and confirm the same response without authentication if this is an exposure finding.

.## Executive Summary
{summary}

.## Technical Analysis
{technical_explanation}

.## Reproduction notes
1. **Target List:** {urls_list}
2. **Detection:** {attack_vector}
3. **Template:** `{payload}`

.## Evidence
.```http
{request_evidence}
.```
.```http
{response_evidence}
.```

.## Impact Analysis
- **Technical Impact:** {technical_impact}
- **Business Impact:** {business_impact}

.## Remediation
{remediation}
"""

    for tid, findings in grouped_findings.items():
        if not findings:
            continue
        urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
        is_seen, url_hash = already_seen(tid)
        if is_seen:
            print(f"[-] Skip (Already Processed): {tid}")
            continue

        nuclei_sev = (findings[0].get("severity") or "medium").lower()
        sev_folder = "high" if nuclei_sev in ["critical", "high"] else "low"
        write_alert(
            sev_folder,
            tid,
            "Draft ID: `PENDING_MANUAL_REVIEW`\n\n",
            raw_markdown(tid, findings, urls_list, runner_ip),
        )
        mark_seen(url_hash)

        prompt = f"""Role: Senior Security Auditor.
Program: {PROGRAM_NAME}
Vulnerability Type: {tid}
Context Data: {json.dumps(findings[:3])}

TASK: Write an honest professional review of this scanner hit.

RULES:
1. Do not invent CVE IDs. Use only provided data.
2. Public blog/help/article pages are FALSE_POSITIVE unless private data is visible.
3. Version-only matches (Next.js/React version strings) without a concrete exposure are FALSE_POSITIVE.
4. Login redirects, 401/403, and WAF block pages are FALSE_POSITIVE.
5. Unauthenticated access to an admin/debug/internal tool, config, or data that the matcher expected IS valid even if there is no password dump or PII.
6. Keep placeholders literal: '{{ip}}', '{{verify_url}}', '{{urls_list}}', '{{program}}', '{{severity}}', '{{payload}}', '{{request_evidence}}', '{{response_evidence}}'.
7. Fill '{{title}}', '{{summary}}', '{{technical_explanation}}', '{{attack_vector}}', '{{technical_impact}}', '{{business_impact}}', '{{remediation}}'.

If FALSE POSITIVE return ONLY:
{{"title": "FALSE_POSITIVE"}}

If valid, return ONLY:
{{"title": "Valid Vulnerability Title", "severity": "critical/high/medium", "full_markdown": "..."}}

Markdown structure if valid:
{luxury_template}
"""
        try:
            print(f"[*] Analyzing Group: {tid}...")
            ai_data = ask_groq(prompt)
            if not ai_data:
                continue
            rep = parse_ai_json(ai_data)
            if not rep:
                continue
            if rep.get("title") == "FALSE_POSITIVE":
                print(f"[-] AI marked FP (raw alert kept): {tid}")
                continue

            primary_url = findings[0]["matched_url"]
            req_ev = findings[0].get("request_evidence", "No request data captured.")
            res_ev = findings[0].get("response_evidence", "No response data captured.")
            clean_md_raw = (
                rep["full_markdown"]
                .replace(".#", "#")
                .replace(".##", "##")
                .replace(".###", "###")
                .replace(".```", "```")
            )
            final_clean_report = (
                clean_md_raw.replace("{ip}", runner_ip)
                .replace("{urls_list}", urls_list)
                .replace("{program}", PROGRAM_NAME)
                .replace("{verify_url}", primary_url)
                .replace("{severity}", rep.get("severity", "Medium"))
                .replace("{request_evidence}", req_ev)
                .replace("{response_evidence}", res_ev)
                .replace("{payload}", tid)
            )

            final_d_id = create_h1_draft(
                rep["title"],
                final_clean_report,
                "Automated exposure/misconfiguration detection. Confirm manually before filing.",
                rep.get("severity", nuclei_sev),
                primary_url,
            )
            if not final_d_id:
                final_d_id = "MANUAL_SUBMIT_REQUIRED"

            ai_folder = "high" if any(x in str(rep.get("severity", "")).upper() for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
            write_alert(ai_folder, tid, f"Draft ID: `{final_d_id}`\n\n", final_clean_report)
            print(f"[+] AI polished report saved: {tid}")
        except Exception as e:
            print(f"Error in {tid}: {e}")


if __name__ == "__main__":
    validate_findings()
