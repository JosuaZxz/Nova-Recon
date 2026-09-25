import os
import sys
import json
import subprocess
import re
import time
import hashlib
from datetime import datetime

# Ensure stdout and stderr handle utf-8 safely across all environments
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Fallback for requests using standard library if not installed
try:
    import requests
except ImportError:
    import urllib.request
    import urllib.error
    import base64

    class SimpleRequestsResponse:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text
        def json(self):
            return json.loads(self.text)

    class SimpleRequests:
        @staticmethod
        def post(url, headers=None, json=None, data=None, auth=None, timeout=60):
            req_headers = headers.copy() if headers else {}
            body_bytes = None
            if json is not None:
                import json as _json
                body_bytes = _json.dumps(json).encode('utf-8')
                req_headers['Content-Type'] = 'application/json'
            elif data is not None:
                body_bytes = data.encode('utf-8') if isinstance(data, str) else data

            if auth:
                cred = f"{auth[0]}:{auth[1]}".encode('utf-8')
                req_headers['Authorization'] = f"Basic {base64.b64encode(cred).decode('utf-8')}"

            req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method='POST')
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read().decode('utf-8', errors='ignore')
                    return SimpleRequestsResponse(resp.getcode(), raw)
            except urllib.error.HTTPError as e:
                err_text = e.read().decode('utf-8', errors='ignore')
                return SimpleRequestsResponse(e.code, err_text)
            except Exception as e:
                return SimpleRequestsResponse(500, str(e))

    requests = SimpleRequests()

# --- [ CONFIGURATION ] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"

def get_verification_context(data):
    info = data.get("info", {})
    matcher = data.get("matcher-name", "Behavioral Match")
    extracted = data.get("extracted-results", [])
    
    req = data.get("request", "")
    res = data.get("response", "")
    tid = data.get("template-id", "Unknown")
    
    # --- [ THE ANNIHILATION FILTER (ZERO TOLERANCE) ] ---
    # Only filter out HTTP error codes if there are no extracted results from nuclei
    if not extracted and res:
        status_match = re.search(r'^HTTP/[\d.]+\s+(400|401|403|404|405|406|429|502|503)', res)
        if status_match:
            return None 
            
        if re.search(r'^HTTP/[\d.]+\s+(301|302|307|308)', res):
            if re.search(r'Location:.*(/login|/signin|/auth|/sso|oauth|redirect_uri|wp-login)', res, re.IGNORECASE):
                return None 
                
    # Noise keywords filter (WAF & common generic error pages)
    noise_keywords = [
        "phs.getpostman.com", "schema.getpostman.com", "swagger-ui",
        "api-docs", "\"state\":\"SUCCESS\"", "salesforce.com/aura",
        "the nlb has been offline", 
        "request was blocked by our security service", 
        "attention required! | cloudflare",
        "pardon our interruption"
    ]
    res_lower = res.lower() if res else ""
    
    secret_regex = re.compile(r'('
        r'AKIA[0-9A-Z]{16}|'
        r'ghp_[a-zA-Z0-9]{36}|'
        r'AIza[0-9A-Za-z-_]{35}|'
        r'[rs]k_live_[a-zA-Z0-9]{24}|'
        r'xox[baprs]-[0-9]{12}-[0-9]{12}|'
        r'sq0csp-[0-9A-Za-z\-_]{43}|'
        r'BEGIN (RSA|OPENSSH) PRIVATE KEY'
    r')')

    if any(noise in res_lower for noise in noise_keywords):
        if not secret_regex.search(res) and not extracted:
            return None 
            
    if "token" in tid.lower() or "key" in tid.lower() or "credential" in tid.lower():
        if not extracted and not secret_regex.search(res) and not re.search(r'("email"\s*:\s*"[^"]+@[^"]+\.[^"]+")', res_lower):
            return None 

    # --- [ PRECISION SANITY FILTERS (ANTI-FALSE-POSITIVE SHIELD) ] ---
    # 1. Empty body / 0-byte backup or dump check
    if any(k in tid.lower() for k in ["backup", "archive", "dump", "heapdump", "zip", "tar"]):
        if "content-length: 0" in res_lower:
            return None
        body_split = res.split("\r\n\r\n", 1) if "\r\n\r\n" in res else res.split("\n\n", 1)
        if len(body_split) > 1 and len(body_split[1].strip()) < 50:
            return None

    # 2. GraphQL Introspection disabled error / Shopify public storefront
    if "graphql" in tid.lower():
        if any(d in res_lower for d in ["has been disabled", "is not allowed", "introspection is disabled", "introspectionquery is disabled"]):
            return None
        if any(s in res_lower for s in ["powered-by: shopify", "shopify-complexity-score", "storefront/query"]):
            return None
        if '"__schema"' not in res_lower and '\"__schema\"' not in res_lower:
            return None

    # 3. Jenkins Script Console false positive (e.g. Jenkins Arena, Next.js sites)
    if "jenkins" in tid.lower():
        if any(ign in res_lower for ign in ["jenkins arena", "next.js", "_next/static", "cloudfront"]):
            if not any(v in res_lower for v in ["manage jenkins", "groovy script", "x-jenkins", "_class\":\"hudson", "_class\":\"jenkins"]):
                return None

    # 4. WordPress CVE on non-WordPress site (e.g. X/Twitter, React/Next.js)
    if "wp-" in tid.lower() or "wordpress" in tid.lower():
        host_str = str(data.get("host", "")).lower()
        if "x.com" in host_str or "twitter.com" in host_str:
            return None
        if not any(wp in res_lower for wp in ["wp-content", "wp-includes", "wordpress", "wp-json"]):
            return None

    # 5. CyberPanel CVE on non-CyberPanel site
    if "cve-2024-51567" in tid.lower() or "cyberpanel" in tid.lower():
        if not any(cp in res_lower for cp in ["cyberpanel", "databases/upgrademysqlstatus"]):
            return None

    clean_res = res[:2000] if len(res) > 2000 else res
    
    return {
        "template_id": tid,
        "template_name": info.get("name", "Unknown Bug Type"),
        "matcher_logic": matcher,
        "extracted_data": extracted,
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "request_evidence": req[:800] if req else "No raw request data.",
        "response_evidence": clean_res if clean_res else "Pattern match verified by Nuclei engine.",
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def is_seen(url_hash):
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            for line in f:
                if line.strip() == url_hash:
                    return True
    return False

def mark_seen(url_hash):
    with open(SEEN_DB, "a") as f:
        f.write(f"{url_hash}\n")

def create_h1_draft(title, description, impact, severity, url):
    if not H1_USER or not H1_API_KEY:
        return "MANUAL_SUBMIT_REQUIRED"

    if PROGRAM_NAME in ["00_test", "test_target"]: 
        return "TEST-DRAFT-ID-2026"

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
                "severity_rating": h1_sev
            }
        }
    }
    
    try:
        time.sleep(2)
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload, timeout=30)
        if res.status_code == 201:
            return res.json()['data']['id']
    except Exception as e:
        print(f"[-] HackerOne draft creation error: {e}")
    return "MANUAL_SUBMIT_REQUIRED"

def generate_fallback_report(tid, findings, runner_ip):
    f0 = findings[0]
    title = f"{f0.get('template_name', tid)} Vulnerability"
    sev = f0.get('severity', 'Medium').capitalize()
    urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
    primary_url = f0['matched_url']
    req_ev = f0.get('request_evidence', 'No request data captured.')
    res_ev = f0.get('response_evidence', 'Pattern match verified.')
    extracted = f0.get('extracted_data', [])
    extracted_md = f"\n- **Extracted Secrets/Tokens:** `{json.dumps(extracted)}`" if extracted else ""
    
    report = f"""# {title} in {PROGRAM_NAME}

## 📊 Vulnerability Details
- **Severity:** {sev}
- **Template ID:** `{tid}`
- **Affected Assets:** 
{urls_list}
- **Scanner IP:** {runner_ip}{extracted_md}

## 🔗 Quick Verification Link
- **Primary Test URL:** {primary_url}
- **Instructions:** Test the URL above to verify the exposed sensitive pattern or vulnerability.

## 📝 Executive Summary
Nuclei detection engine triggered a {sev}-severity security finding on target `{PROGRAM_NAME}` for template `{tid}`.

## 🔍 Technical Analysis
The endpoint responded matching the signature for `{f0.get('template_name', tid)}`. Matcher logic: `{f0.get('matcher_logic', 'Rule matched')}`.

## 🚀 Steps To Reproduce (PoC)
1. **Target:** `{primary_url}`
2. **Payload / Signature:** `{tid}`

## 🛡️ Proof of Concept (Evidence)
```http
{req_ev}
```
```http
{res_ev}
```

## ⚠️ Impact Analysis
- **Technical Impact:** Potential unauthorized data exposure, misconfiguration, or remote command execution.
- **Business Impact:** High security risk to sensitive organization assets and infrastructure.

## ✅ Remediation
Review server configuration, restrict public endpoint access, rotate exposed secrets if any, and apply security patches.
"""
    return {"title": title, "severity": sev, "full_markdown": report}

def validate_findings():
    print(f"[*] Starting Intelligence Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        print(f"[-] No results file or empty at: {path}")
        return

    runner_ip = subprocess.getoutput("curl -s ifconfig.me")
    if not runner_ip or len(runner_ip) > 20: 
        runner_ip = "GitHub_Runner_Scanner"

    grouped_findings = {}
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]

    total_lines = 0
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if isinstance(d, list): 
                    d = d[0]
                tid = d.get("template-id", "Unknown")
                sev = d.get("info", {}).get("severity", "info").lower()
                
                if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
                    ctx = get_verification_context(d)
                    if ctx:
                        if tid not in grouped_findings: 
                            grouped_findings[tid] = []
                        grouped_findings[tid].append(ctx)
            except Exception as e:
                continue

    print(f"[*] Processed {total_lines} findings lines. Valid grouped templates: {len(grouped_findings)}")

    if not grouped_findings: 
        print("[-] No actionable Medium/High/Critical findings after noise filter.")
        return

    luxury_template = """
.# {title} in {program}

.## 📊 Vulnerability Details
- **Severity:** {severity}
- **Affected Assets:** 
{urls_list}
- **Scanner IP:** {ip}

.## 🔗 Quick Verification Link
- **Primary Test URL:** {verify_url}
- **Instructions:** Open the link above to inspect the finding.

.## 📝 Executive Summary
{summary}

.## 🔍 Technical Analysis
{technical_explanation}

.## 🚀 Steps To Reproduce (PoC)
1. **Target List:** {urls_list}
2. **Attack Vector:** {attack_vector}
3. **Payload used:** `{payload}`

.## 🛡️ Proof of Concept (Evidence)
.```http
{request_evidence}
.```
.```http
{response_evidence}
.```

.## ⚠️ Impact Analysis
- **Technical Impact:** {technical_impact}
- **Business Impact:** {business_impact}

.## ✅ Remediation
{remediation}
"""

    for tid, findings in grouped_findings.items():
        if not findings: 
            continue
            
        primary_url = findings[0]['matched_url']
        url_hash = hashlib.md5(f"{PROGRAM_NAME}_{tid}_{primary_url}".encode()).hexdigest()
        
        if is_seen(url_hash):
            print(f"[-] Skip (Already Processed): {tid} ({primary_url})")
            continue 

        urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
        req_ev = findings[0].get('request_evidence', 'No request data captured.')
        res_ev = findings[0].get('response_evidence', 'No response data captured.')
        
        rep = None
        
        # If Groq AI is available, use it for deep triage
        if AI_KEY:
            prompt = f"""Role: Senior Security Auditor.
Program: {PROGRAM_NAME}
Vulnerability Type: {tid}
Context Data: {json.dumps(findings[:3])}

TASK: Write a SURGICAL, HONEST, and PROFESSIONAL Bug Report.

CRITICAL LOGIC & TECHNICAL RULES:
1. NO HALLUCINATION: DO NOT invent CVE IDs. Use only provided data.
2. PUBLIC URL SKEPTICISM: If the URL contains '/article/', '/blog/', '/help/', or '/announcements/' and only shows public content without sensitive data, return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
3. BOILERPLATE TRAP: If the response body only shows generic landing page HTML/CSS without actual leaked sensitive data, credentials, internal debug info, or command execution output, return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
4. CONFIRM EVIDENCE: Check if the finding has real evidence (e.g. database credentials, cloud metadata, API tokens, actuator env dumps, or known CVE trigger).
5. MANDATORY PLACEHOLDERS: You MUST include these exact strings LITERALLY: '{{ip}}', '{{verify_url}}', '{{urls_list}}', '{{program}}', '{{severity}}', '{{payload}}', '{{request_evidence}}', and '{{response_evidence}}'.
6. DESCRIPTIONS: Provide professional content for '{{title}}', '{{summary}}', '{{technical_explanation}}', '{{attack_vector}}', '{{technical_impact}}', '{{business_impact}}', and '{{remediation}}'.

IF THE FINDING IS A FALSE POSITIVE:
Return EXACTLY: {{"title": "FALSE_POSITIVE"}}

IF THE FINDING IS VALID:
Return ONLY the JSON format below:
{{"title": "Valid Vulnerability Title", "severity": "critical/high/medium", "full_markdown": "{luxury_template}"}}
"""
            try:
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {"Authorization": f"Bearer {AI_KEY}"}
                payload = {
                    "model": "llama-3.3-70b-versatile",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                }
                
                print(f"[*] AI Analyzing Group: {tid}...")
                res = requests.post(url, headers=headers, json=payload, timeout=60)
                if res.status_code == 200:
                    ai_data = res.json()['choices'][0]['message']['content'].strip()
                    match = re.search(r'\{.*\}', ai_data, re.DOTALL)
                    if match:
                        raw_json = match.group(0)
                        cleaned_json = raw_json.replace('\\', '\\\\').replace('\\\\"', '\\"')
                        try:
                            rep = json.loads(cleaned_json, strict=False)
                        except Exception:
                            rep = json.loads(raw_json, strict=False)
                else:
                    print(f"[!] Groq API returned status {res.status_code}: {res.text[:200]}")
            except Exception as e:
                print(f"[!] AI Triage Exception for {tid}: {e}")

        # If AI was not used, failed, or timed out, generate resilient fallback report
        if not rep or not isinstance(rep, dict):
            print(f"[+] Generating heuristic fallback report for: {tid}")
            rep = generate_fallback_report(tid, findings, runner_ip)

        if rep.get("title") == "FALSE_POSITIVE":
            print(f"[-] Dropping False Positive: {tid}")
            continue

        clean_md_raw = rep.get('full_markdown', '')
        clean_md_raw = clean_md_raw.replace(".#", "#").replace(".##", "##").replace(".###", "###").replace(".```", "```")
        
        final_clean_report = clean_md_raw.replace("{ip}", runner_ip) \
                                         .replace("{urls_list}", urls_list) \
                                         .replace("{program}", PROGRAM_NAME) \
                                         .replace("{verify_url}", primary_url) \
                                         .replace("{severity}", rep.get('severity', 'Medium')) \
                                         .replace("{request_evidence}", req_ev) \
                                         .replace("{response_evidence}", res_ev) \
                                         .replace("{payload}", tid)

        final_d_id = create_h1_draft(rep['title'], final_clean_report, "Automated vulnerability detection.", rep.get('severity', 'medium'), primary_url)

        sev_folder = "high" if any(x in str(rep.get('severity', '')).upper() for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
        os.makedirs(f"data/{PROGRAM_NAME}/alerts/{sev_folder}", exist_ok=True)
        report_path = f"data/{PROGRAM_NAME}/alerts/{sev_folder}/{tid}.md"
    
        with open(report_path, 'w', encoding='utf-8') as f_report:
            f_report.write(f"🆔 **Draft ID:** `{final_d_id}`\n\n")
            f_report.write(final_clean_report)

        mark_seen(url_hash)
        print(f"[+] Alert Successfully Saved: {report_path}")

if __name__ == "__main__":
    validate_findings()
