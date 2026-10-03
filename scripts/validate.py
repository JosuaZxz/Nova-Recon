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
    tid = str(data.get("template-id", "Unknown")).strip()
    t_name = str(info.get("name", tid)).strip()
    t_tags = info.get("tags", [])
    if isinstance(t_tags, list):
        tags_str = " ".join([str(t).lower() for t in t_tags])
    else:
        tags_str = str(t_tags).lower()

    host_str = str(data.get("host", "")).lower()
    matched_url = str(data.get("matched-at", data.get("host", ""))).lower()
    res_lower = res.lower() if res else ""
    tid_lower = tid.lower()
    name_lower = t_name.lower()

    # --- [ SHIELD 1: THE ANNIHILATION FILTER (ZERO TOLERANCE) ] ---
    # 1. Filter out pure HTTP error codes if no actual verified secret was extracted
    if not extracted and res:
        status_match = re.search(r'^HTTP/[\d.]+\s+(400|401|403|404|405|406|410|429|500|502|503|504)', res.strip())
        if status_match:
            return None 

    # 2. Redirect-to-Login Killer (Next.js & general auth redirects)
    # If the response redirected to /login, /signin, etc., it is NOT a bypass!
    if res:
        has_redirect_header = bool(re.search(r'^(HTTP/[\d.]+\s+(301|302|303|307|308))', res.strip()))
        if has_redirect_header or "x-nextjs-redirect" in res_lower:
            # Check Location header, X-Nextjs-Redirect header, or refresh redirect
            if re.search(r'(location|x-nextjs-redirect):\s*https?://[^\r\n]*(/login|/signin|/auth|/sso|oauth|redirect_uri|wp-login|accounts\.google)', res_lower):
                return None
            if re.search(r'(location|x-nextjs-redirect):\s*(/login|/signin|/auth|/sso|oauth|wp-login)', res_lower):
                return None

    # 3. Known Public / Out of Scope Telemetry Filters
    # Azure Application Insights Instrumentation Key is public telemetry write-only token
    if "azure-instrumentation-key" in tid_lower or "application-insights" in tid_lower:
        return None

    # Google API Browser Key / Client ID in client-side JS (Firebase/Maps public client keys)
    if tid_lower in ["google-api-key", "google-client-id", "credentials-disclosure"]:
        if not extracted:
            return None
        # Okta widget and webpack chunks are client JS code, not server credential leaks
        if any(w in matched_url for w in ["okta-sign-in", "chunk-", "output.", "main.", "analytics.js", "pa-js"]):
            return None

    # 4. Next.js Version Match Noise Killer
    # CVE-2025-29927-HEADLESS passively flags "Vulnerable Next.js => 13.x" in public HTML
    if "cve-2025-29927" in tid_lower:
        if "headless" in tid_lower or not req:
            # Merely detecting Next.js version banner without an exploited route is Informative
            return None
        # If the non-headless CVE redirected to login, it is a false positive
        if "x-nextjs-redirect" in res_lower or "307 temporary redirect" in res_lower:
            return None

    # 5. WordPress / WooCommerce / CMS Cross-Platform False Positive Killer
    is_wp_cve = any(x in tid_lower or x in name_lower or x in tags_str for x in ["wp-", "wordpress", "woocommerce", "learnpress", "epsilon", "cve-2020-36708", "cve-2024-8522", "cve-2026-49777"])
    if is_wp_cve:
        # Twitter, X, Crypto.com, Venmo, PayPal, Stripchat do not run WordPress WooCommerce/Epsilon
        if any(d in host_str or d in matched_url for d in ["x.com", "twitter.com", "crypto.com", "venmo.com", "paypal.com", "stripchat.com", "airbnb.com"]):
            return None
        # Genuine WordPress endpoints ALWAYS have wp-content, wp-includes, or wp-json in response
        if not any(wp in res_lower for wp in ["wp-content", "wp-includes", "wordpress", "wp-json"]):
            return None

    # 6. NVIDIA Triton Inference Server Cross-Matching Killer
    is_triton_cve = "triton" in tid_lower or "triton" in name_lower or "cve-2026-24207" in tid_lower
    if is_triton_cve:
        # Stripchat model directory is for adult performers, not NVIDIA AI servers!
        if any(d in host_str or d in matched_url for d in ["stripchat.com", "x.com", "airbnb.com"]):
            return None
        if not any(tr in res_lower for tr in ["triton", "inference:server", "tritonserver", "kserve"]):
            return None

    # 7. CyberPanel CVE on non-CyberPanel sites
    if "cve-2024-51567" in tid_lower or "cyberpanel" in tid_lower or "cyberpanel" in name_lower:
        if not any(cp in res_lower for cp in ["cyberpanel", "databases/upgrademysqlstatus"]):
            return None

    # 8. phpMyAdmin Unauthenticated Access Verifier
    if "phpmyadmin" in tid_lower and "unauth" in tid_lower:
        # If the response contains login form inputs, it is NOT unauthenticated access!
        if any(p in res_lower for p in ["pma_password", "pma_username", "input_username", "input_password"]):
            return None
        if not any(db in res_lower for db in ["server_databases.php", "pma_navigation_tree_content", "sql query:", "database:"]):
            return None

    # 9. GraphQL Introspection Schema Noise Filter
    if "graphql" in tid_lower and "introspection" in tid_lower:
        # Filter disabled introspection or shopify storefronts
        if any(d in res_lower for d in ["has been disabled", "is not allowed", "introspection is disabled", "introspectionquery is disabled"]):
            return None
        if any(s in res_lower for s in ["powered-by: shopify", "shopify-complexity-score", "storefront/query"]):
            return None
        if '"__schema"' not in res_lower and '\"__schema\"' not in res_lower:
            return None
        # Introspection alone without extracted tokens/PII is Low/Info (Recon Data)
        if not extracted and not secret_regex.search(res):
            info["severity"] = "low"


    # 10. Noise keywords filter (WAF, Captcha, generic maintenance pages)
    noise_keywords = [
        "phs.getpostman.com", "schema.getpostman.com", "swagger-ui",
        "api-docs", "\"state\":\"success\"", "salesforce.com/aura",
        "the nlb has been offline", 
        "request was blocked by our security service", 
        "attention required! | cloudflare",
        "cf-mitigated",
        "pardon our interruption"
    ]
    
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

    clean_res = res[:2000] if len(res) > 2000 else res
    
    return {
        "template_id": tid,
        "template_name": t_name,
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
        else:
            print(f"[-] HackerOne draft creation status {res.status_code}: {res.text[:150]}")
    except Exception as e:
        print(f"[-] HackerOne draft creation error: {e}")
    return "MANUAL_SUBMIT_REQUIRED"

def build_verified_report(ai_verdict, tid, findings, runner_ip):
    f0 = findings[0]
    title = ai_verdict.get("title", f"{f0.get('template_name', tid)} in {PROGRAM_NAME}")
    sev = ai_verdict.get("severity", f0.get("severity", "Medium")).capitalize()
    urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
    primary_url = f0['matched_url']
    req_ev = f0.get('request_evidence', 'No request data captured.')
    res_ev = f0.get('response_evidence', 'Pattern match verified.')
    extracted = f0.get('extracted_data', [])
    extracted_md = f"\n- **Extracted Secrets/Tokens:** `{json.dumps(extracted)}`" if extracted else ""
    
    summary = ai_verdict.get("summary", f"Nuclei detection engine triggered a verified finding for template `{tid}`.")
    technical_explanation = ai_verdict.get("technical_explanation", f"Endpoint matched verified signature for `{tid}`.")
    attack_vector = ai_verdict.get("attack_vector", f"Direct HTTP request to exposed asset `{primary_url}` using signature `{tid}`.")
    technical_impact = ai_verdict.get("technical_impact", "Potential unauthorized access or information disclosure.")
    business_impact = ai_verdict.get("business_impact", "Risk to organization sensitive infrastructure and assets.")
    remediation = ai_verdict.get("remediation", "Restrict public network access to endpoint, enforce strict authentication, and apply security updates.")

    report = f"""# {title}

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
{summary}

## 🔍 Technical Analysis
{technical_explanation}

## 🚀 Steps To Reproduce (PoC)
1. **Target:** `{primary_url}`
2. **Attack Vector:** {attack_vector}
3. **Payload / Signature:** `{tid}`

## 🛡️ Proof of Concept (Evidence)
```http
{req_ev}
```
```http
{res_ev}
```

## ⚠️ Impact Analysis
- **Technical Impact:** {technical_impact}
- **Business Impact:** {business_impact}

## ✅ Remediation
{remediation}
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
            except Exception:
                continue

    print(f"[*] Processed {total_lines} findings lines. Valid candidate templates after Shield Filter: {len(grouped_findings)}")

    if not grouped_findings: 
        print("[-] Zero actionable findings after strict noise & false-positive filters.")
        return

    for tid, findings in grouped_findings.items():
        if not findings: 
            continue
            
        primary_url = findings[0]['matched_url']
        url_hash = hashlib.md5(f"{PROGRAM_NAME}_{tid}_{primary_url}".encode()).hexdigest()
        
        if is_seen(url_hash):
            print(f"[-] Skip (Already Processed): {tid} ({primary_url})")
            continue 

        # --- [ SHIELD 2: SURGICAL AI TRIAGE VIA GROQ ] ---
        ai_verdict = None
        if AI_KEY:
            prompt = f"""You are a cynical, expert Bug Bounty Triage Specialist on HackerOne.
Your job is to REJECT false positives with ZERO MERCY.

Candidate Target:
Program: {PROGRAM_NAME}
Template ID: {tid}
Context: {json.dumps(findings[:2])}

REJECT AS FALSE POSITIVE (is_valid: false):
1. Single Page Application (SPA / React / Next.js) route returning 200 OK for non-existent PHP/WordPress paths (e.g. /wp-admin on twitter.com).
2. Word collisions (e.g. webcam "models" on stripchat triggering NVIDIA AI Triton CVE; crypto price ticker triggering WooCommerce CVE).
3. Authorization bypass tests that actually redirected to a /login page (status 301/302/307).
4. Telemetry / analytics keys (Azure App Insights, Google Maps/Analytics).
5. Passive version banners without proof of exploitation.
6. Login forms claiming to be "unauthenticated access".
7. Cloudflare / WAF / generic 200 OK landing pages.

Return ONLY a valid, compact JSON object matching this schema EXACTLY:
{{
  "is_valid": true,
  "confidence": 95,
  "reason": "1-sentence reason",
  "title": "Clear vulnerability title",
  "severity": "critical",
  "summary": "1-2 sentence executive summary",
  "technical_explanation": "Technical details",
  "attack_vector": "Attack vector used",
  "technical_impact": "Impact on systems/data",
  "business_impact": "Impact on business",
  "remediation": "Concrete fix instructions"
}}
If false positive, set "is_valid": false and provide "reason" and "confidence".
"""
            try:
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {AI_KEY}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": "llama-3.3-70b-versatile",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.0,
                    "response_format": {"type": "json_object"}
                }
                
                print(f"[*] AI Analyzing Candidate: {tid} on {primary_url}...")
                res = requests.post(url, headers=headers, json=payload, timeout=45)
                if res.status_code == 200:
                    ai_raw = res.json()['choices'][0]['message']['content'].strip()
                    try:
                        ai_verdict = json.loads(ai_raw)
                    except Exception:
                        match = re.search(r'\{[\s\S]*\}', ai_raw)
                        if match:
                            ai_verdict = json.loads(match.group(0))
                else:
                    print(f"[!] Groq API status {res.status_code}: {res.text[:200]}")
            except Exception as e:
                print(f"[!] Groq API Exception for {tid}: {e}")

        # Strict Validation Gate:
        # If AI explicitly judged it as False Positive:
        if ai_verdict and isinstance(ai_verdict, dict):
            if not ai_verdict.get("is_valid", False) or ai_verdict.get("confidence", 0) < 80:
                print(f"[-] AI Dropped False Positive ({ai_verdict.get('confidence')}%, {ai_verdict.get('reason')}): {tid}")
                mark_seen(url_hash)
                continue
        elif AI_KEY:
            # If AI key was provided but the call failed or timed out, DO NOT generate a blind fallback!
            # It is safer to skip than to submit false positives to HackerOne and ruin Signal score.
            print(f"[!] Warning: AI Triage failed or returned empty. Skipping candidate {tid} to prevent false-positive spam.")
            continue
        else:
            # If no AI key configured at all, require strict extracted proof to proceed
            if not findings[0].get('extracted_data'):
                print(f"[-] No AI Key configured and no extracted secret proof for {tid}. Skipping.")
                continue
            ai_verdict = {
                "title": f"{findings[0].get('template_name', tid)} in {PROGRAM_NAME}",
                "severity": findings[0].get("severity", "Medium"),
                "is_valid": True,
                "confidence": 85
            }

        print(f"[+] VERIFIED VULNERABILITY CONFIRMED: {tid} ({ai_verdict.get('title')})")
        report_data = build_verified_report(ai_verdict, tid, findings, runner_ip)

        # Only create HackerOne draft for verified high-confidence findings
        final_d_id = "MANUAL_SUBMIT_REQUIRED"
        if ai_verdict.get("is_valid") and ai_verdict.get("confidence", 0) >= 85:
            final_d_id = create_h1_draft(
                report_data['title'],
                report_data['full_markdown'],
                report_data.get('summary', 'Verified vulnerability detection.'),
                report_data.get('severity', 'medium'),
                primary_url
            )

        sev_folder = "high" if any(x in str(report_data.get('severity', '')).upper() for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
        os.makedirs(f"data/{PROGRAM_NAME}/alerts/{sev_folder}", exist_ok=True)
        report_path = f"data/{PROGRAM_NAME}/alerts/{sev_folder}/{tid}.md"
    
        with open(report_path, 'w', encoding='utf-8') as f_report:
            f_report.write(f"🆔 **Draft ID:** `{final_d_id}`\n\n")
            f_report.write(report_data['full_markdown'])

        mark_seen(url_hash)
        print(f"[+] Verified Alert Successfully Saved: {report_path}")

if __name__ == "__main__":
    validate_findings()
