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

def get_verification_context(data):
    info = data.get("info", {})
    matcher = data.get("matcher-name", "Behavioral Match")
    extracted = data.get("extracted-results",[])
    
    req = data.get("request", "")
    res = data.get("response", "")

    # [+] INJEKSI SURGICAL FIX: Definisikan tid agar filter tidak NameError
    tid = data.get("template-id", "Unknown")
    
    # ---[ THE ANNIHILATION FILTER (ZERO TOLERANCE) ] ---
    # 1. BUNUH: WAF, Not Found, Unauthorized, Method Not Allowed, Bad Gateway
    status_match = re.search(r'^HTTP/\d\.\d\s+(400|401|403|404|405|406|429|502|503)', res)
    if status_match:
        return None 
        
    # 2. BUNUH: Redirect (301/302) yang menuju halaman Login/SSO/Auth
    if re.search(r'^HTTP/\d\.\d\s+(301|302|307|308)', res):
        if re.search(r'Location:.*(/login|/signin|/auth|/sso|oauth|redirect_uri|wp-login)', res, re.IGNORECASE):
            return None 
            
    # 3. BUNUH: Halaman Dokumentasi (Postman/Swagger) & Salesforce Aura Kosong
    noise_keywords =[
        "phs.getpostman.com", "schema.getpostman.com", "swagger-ui",
        "api-docs", "\"state\":\"SUCCESS\"", "salesforce.com/aura"
    ]
    res_lower = res.lower()
    
    # KAMUS REGEX API KEY (High-Fidelity)
    # Ini memastikan AI hanya bereaksi jika menemukan format rahasia yang matematis akurat
    secret_regex = re.compile(r'('
        r'AKIA[0-9A-Z]{16}|'                              # AWS Access Key
        r'ghp_[a-zA-Z0-9]{36}|'                           # GitHub Personal Access Token
        r'AIza[0-9A-Za-z-_]{35}|'                         # Google API Key
        r'[rs]k_live_[a-zA-Z0-9]{24}|'                    # Stripe Live Key
        r'xox[baprs]-[0-9]{12}-[0-9]{12}|'                # Slack Token
        r'sq0csp-[0-9A-Za-z\-_]{43}|'                     # Square Access Token
        r'BEGIN (RSA|OPENSSH) PRIVATE KEY'                # Private Certificates
    r')')

    if any(noise in res_lower for noise in noise_keywords):
        # Jika ada noise dokumentasi, TETAP LAPORKAN JIKA ADA API KEY YANG BENTUKNYA VALID
        if not secret_regex.search(res):
            return None 
            
    # Jika tidak ada noise, pastikan jika ini dari template 'token/keys', formatnya harus logis
    if "token" in tid.lower() or "key" in tid.lower() or "credential" in tid.lower():
        if not secret_regex.search(res) and not re.search(r'("email"\s*:\s*"[^"]+@[^"]+\.[^"]+")', res_lower):
             return None # Buang jika temuan token tidak masuk akal secara format
    # ----------------------------------------------------

    # Ambil 1200 char saja untuk bukti AI
    clean_res = res[:1200] if len(res) > 1200 else res
    
    return {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": info.get("name", "Unknown Bug Type"),
        "matcher_logic": matcher,
        "extracted_data": extracted,
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "request_evidence": req[:600],
        "response_evidence": clean_res,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    
def create_h1_draft(title, description, impact, severity, url):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                return "ALREADY_REPORTED"

    # MODE TESTING (Biarkan tanpa memory dulu biar puas testingnya)
    if PROGRAM_NAME in ["00_test", "test_target"]: 
        return "TEST-DRAFT-ID-2026"

    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": target_handle, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    
    try:
        time.sleep(2)
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload)
        if res.status_code == 201:
            with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")
            return res.json()['data']['id']
    except: pass
    return None

def validate_findings():
    print(f"🔍 Starting Intelligence Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    # --- GANTI BAGIAN INI (IP FETCHING) ---
    runner_ip = subprocess.getoutput("curl -s ifconfig.me")
    if not runner_ip or len(runner_ip) > 20: runner_ip = "GitHub_Runner_Scanner"

    # --- LOGIC GROUPING PER TEMPLATE ID (ANTI-POINT FARMING) ---
    grouped_findings = {}
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]

    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                tid = d.get("template-id", "Unknown")
                sev = d.get("info", {}).get("severity", "info").lower()
                
                if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
                    if tid not in grouped_findings: grouped_findings[tid] = []
                    grouped_findings[tid].append(get_verification_context(d))
            except: continue

    if not grouped_findings: return

    # --- TEMPLATE KERAS DENGAN QUICK VERIFY (STEALTH MODE) ---
    luxury_template = """
.# {title} in {program}

.## 📊 Vulnerability Details
- **Severity:** {severity}
- **Affected Assets:** 
{urls_list}
- **Scanner IP:** {ip}

.## 🔗 Quick Verification Link
- **Primary Test URL:** {verify_url}
- **Instructions:** Open the link above in a **Private/Incognito** browser window. If you can see dashboard content or internal data without logging in, the bug is confirmed.

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
        # Gabungkan semua URL yang terkena bug yang sama
        urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
        
        # --- PROMPT SUPER-AUDITOR (ANTI-HALLUCINATION + QUICK VERIFY + JSON INTEGRITY) ---
        prompt = f"""Role: Senior Security Auditor.
Program: {PROGRAM_NAME}
Vulnerability Type: {tid}
Context Data: {json.dumps(findings[:3])}

TASK: Write a SURGICAL, HONEST, and PROFESSIONAL Bug Report.

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

def get_verification_context(data):
    info = data.get("info", {})
    matcher = data.get("matcher-name", "Behavioral Match")
    extracted = data.get("extracted-results",[])
    
    req = data.get("request", "")
    res = data.get("response", "")

    # [+] INJEKSI SURGICAL FIX: Definisikan tid agar filter tidak NameError
    tid = data.get("template-id", "Unknown")
    
    # ---[ THE ANNIHILATION FILTER (ZERO TOLERANCE) ] ---
    # 1. BUNUH: WAF, Not Found, Unauthorized, Method Not Allowed, Bad Gateway
    status_match = re.search(r'^HTTP/\d\.\d\s+(400|401|403|404|405|406|429|502|503)', res)
    if status_match:
        return None 
        
    # 2. BUNUH: Redirect (301/302) yang menuju halaman Login/SSO/Auth
    if re.search(r'^HTTP/\d\.\d\s+(301|302|307|308)', res):
        if re.search(r'Location:.*(/login|/signin|/auth|/sso|oauth|redirect_uri|wp-login)', res, re.IGNORECASE):
            return None 
            
    # 3. BUNUH: Halaman Dokumentasi (Postman/Swagger) & Salesforce Aura Kosong
    noise_keywords =[
        "phs.getpostman.com", "schema.getpostman.com", "swagger-ui",
        "api-docs", "\"state\":\"SUCCESS\"", "salesforce.com/aura"
    ]
    res_lower = res.lower()
    
    # KAMUS REGEX API KEY (High-Fidelity)
    # Ini memastikan AI hanya bereaksi jika menemukan format rahasia yang matematis akurat
    secret_regex = re.compile(r'('
        r'AKIA[0-9A-Z]{16}|'                              # AWS Access Key
        r'ghp_[a-zA-Z0-9]{36}|'                           # GitHub Personal Access Token
        r'AIza[0-9A-Za-z-_]{35}|'                         # Google API Key
        r'[rs]k_live_[a-zA-Z0-9]{24}|'                    # Stripe Live Key
        r'xox[baprs]-[0-9]{12}-[0-9]{12}|'                # Slack Token
        r'sq0csp-[0-9A-Za-z\-_]{43}|'                     # Square Access Token
        r'BEGIN (RSA|OPENSSH) PRIVATE KEY'                # Private Certificates
    r')')

    if any(noise in res_lower for noise in noise_keywords):
        # Jika ada noise dokumentasi, TETAP LAPORKAN JIKA ADA API KEY YANG BENTUKNYA VALID
        if not secret_regex.search(res):
            return None 
            
    # Jika tidak ada noise, pastikan jika ini dari template 'token/keys', formatnya harus logis
    if "token" in tid.lower() or "key" in tid.lower() or "credential" in tid.lower():
        if not secret_regex.search(res) and not re.search(r'("email"\s*:\s*"[^"]+@[^"]+\.[^"]+")', res_lower):
             return None # Buang jika temuan token tidak masuk akal secara format
    # ----------------------------------------------------

    # Ambil 1200 char saja untuk bukti AI
    clean_res = res[:1200] if len(res) > 1200 else res
    
    return {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": info.get("name", "Unknown Bug Type"),
        "matcher_logic": matcher,
        "extracted_data": extracted,
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "request_evidence": req[:600],
        "response_evidence": clean_res,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    
def create_h1_draft(title, description, impact, severity, url):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                return "ALREADY_REPORTED"

    # MODE TESTING (Biarkan tanpa memory dulu biar puas testingnya)
    if PROGRAM_NAME in ["00_test", "test_target"]: 
        return "TEST-DRAFT-ID-2026"

    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": target_handle, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    
    try:
        time.sleep(2)
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload)
        if res.status_code == 201:
            with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")
            return res.json()['data']['id']
    except: pass
    return None

def validate_findings():
    print(f"🔍 Starting Intelligence Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    # --- GANTI BAGIAN INI (IP FETCHING) ---
    runner_ip = subprocess.getoutput("curl -s ifconfig.me")
    if not runner_ip or len(runner_ip) > 20: runner_ip = "GitHub_Runner_Scanner"

    # --- LOGIC GROUPING PER TEMPLATE ID (ANTI-POINT FARMING) ---
    grouped_findings = {}
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]

    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                tid = d.get("template-id", "Unknown")
                sev = d.get("info", {}).get("severity", "info").lower()
                
                if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
                    if tid not in grouped_findings: grouped_findings[tid] = []
                    grouped_findings[tid].append(get_verification_context(d))
            except: continue

    if not grouped_findings: return

    # --- TEMPLATE KERAS DENGAN QUICK VERIFY (STEALTH MODE) ---
    luxury_template = """
.# {title} in {program}

.## 📊 Vulnerability Details
- **Severity:** {severity}
- **Affected Assets:** 
{urls_list}
- **Scanner IP:** {ip}

.## 🔗 Quick Verification Link
- **Primary Test URL:** {verify_url}
- **Instructions:** Open the link above in a **Private/Incognito** browser window. If you can see dashboard content or internal data without logging in, the bug is confirmed.

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
        # Gabungkan semua URL yang terkena bug yang sama
        urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
        
        # --- PROMPT SUPER-AUDITOR (ANTI-HALLUCINATION + QUICK VERIFY + JSON INTEGRITY) ---
        prompt = f"""Role: Senior Security Auditor.
Program: {PROGRAM_NAME}
Vulnerability Type: {tid}
Context Data: {json.dumps(findings[:3])}

TASK: Write a SURGICAL, HONEST, and PROFESSIONAL Bug Report.

CRITICAL LOGIC & TECHNICAL RULES:
1. NO HALLUCINATION: DO NOT invent CVE IDs. Use only provided data.
2. PUBLIC URL SKEPTICISM: If the URL contains '/article/', '/blog/', '/help/', or '/announcements/', it is likely a PUBLIC page. DO NOT claim it as a "Dashboard Bypass" unless you see private user data. Return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
3. BOILERPLATE TRAP & CSS NOISE: If the response body only shows generic Next.js, React, CSS classes (like 'anticon', 'loadingCircle'), or generic HTML without actual leaked sensitive data (PII, credentials), this is NOT a vulnerability. Return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
4. SEVERITY CHECK: If the bug is only a "version match" (like Next.js or React) without proof of stolen data, DO NOT report it. Return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
5. SMOKING GUN: In 'Technical Analysis', point out exactly why 'response_evidence' proves the bug (e.g., "The presence of compromised polyfill.io link in source code").
6. NO 'NONE' POLICY: Explain behavioral detection if request is empty. NEVER write 'None' or 'Not Applicable'.
7. ONE-CLICK PROOF: In 'Quick Verification Link', provide the exact direct URL that proves the bug.
8. MANDATORY PLACEHOLDERS: You MUST include these exact strings LITERALLY: '{{ip}}', '{{verify_url}}', '{{urls_list}}', '{{program}}', '{{severity}}', '{{payload}}', '{{request_evidence}}', and '{{response_evidence}}'.
9. DESCRIPTIONS: You MUST write professional paragraphs for '{{title}}', '{{summary}}', '{{technical_explanation}}', '{{attack_vector}}', '{{technical_impact}}', '{{business_impact}}', and '{{remediation}}'. Do not leave ini empty.
10. REDIRECT SKEPTICISM (NEW): If the response evidence shows a '301/302 Found' or '401/403' that redirects to a '/login', '/signin', or SSO page, this is a FALSE POSITIVE. In this case, return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
11. DATA VERIFICATION (NEW): If the response body only shows generic HTML/JS code without actual sensitive user data (PII like emails, cleartext passwords, or internal IDs), return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
12. WAF & FORBIDDEN SKEPTICISM (NEW): If the response status is '403 Forbidden', '401 Unauthorized', or contains WAF headers like 'Cf-Mitigated', 'Cloudflare', or 'Akamai', it means the payload was BLOCKED. Return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.
13. TECHNOLOGY MISMATCH (NEW): If the bug implies a specific CMS or framework (e.g., PrestaShop, WordPress, Magento) but the target is clearly a different proprietary platform (e.g., Shopify), this is a FALSE POSITIVE. Return ONLY JSON: {{"title": "FALSE_POSITIVE"}}.

Structure:
{luxury_template}

Return ONLY a JSON OBJECT: {{"title": "...", "severity": "...", "full_markdown": "..."}}
"""
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {"Authorization": f"Bearer {AI_KEY}"}
            payload = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
            
            print(f"[*] Analyzing Group: {tid}...")
            res = requests.post(url, headers=headers, json=payload, timeout=120)
            if res.status_code != 200: continue
            
            ai_data = res.json()['choices'][0]['message']['content'].strip()
            match = re.search(r'\{.*\}', ai_data, re.DOTALL)
            if match:
                # --- [ JSON SANITIZER: ANTI-BACKSLASH CRASH ] ---
                # Membersihkan karakter backslash yang merusak format JSON dari AI
                raw_json = match.group(0)
                # Fix common escape errors for TikTok/large HTML
                cleaned_json = raw_json.replace('\\', '\\\\').replace('\\\\"', '\\"')
                
                try:
                    rep = json.loads(cleaned_json, strict=False)
                except Exception as e:
                    print(f"[-] Sanitizer retry needed for {tid}: {e}")
                    # Fallback ke raw jika cleaned gagal
                    rep = json.loads(raw_json, strict=False)

                # JIKA AI MENDETEKSI FALSE POSITIVE, JANGAN LANJUTKAN
                if rep.get("title") == "FALSE_POSITIVE":
                    print(f"[-] Dropping False Positive: {tid}")
                    continue
                
                # Gunakan hash unik gabungan Program + Template ID
                url_hash = hashlib.md5(f"{PROGRAM_NAME}_{tid}".encode()).hexdigest()
                
                # --- LOGIKA MEMORI & FILTER DUPLIKAT ---
                is_seen = False
                if os.path.exists(SEEN_DB):
                    with open(SEEN_DB, "r") as db_read:
                        if url_hash in db_read.read(): 
                            is_seen = True

                # JIKA SUDAH PERNAH DILAPORKAN, LEWATI TOTAL (ANTI-SPAM)
                if is_seen:
                    print(f"[-] Skip (Already Processed): {tid}")
                    continue 

                # 1. SIAPKAN DATA TEKNIS (SUNTIKAN BUKTI ASLI)
                primary_url = findings[0]['matched_url']
                req_ev = findings[0].get('request_evidence', 'No request data captured.')
                res_ev = findings[0].get('response_evidence', 'No response data captured.')
                
                clean_md_raw = rep['full_markdown'].replace(".#", "#").replace(".##", "##").replace(".###", "###").replace(".```", "```")
                
                # 2. REPLACING PLACEHOLDERS (PEMBERSIHAN TOTAL)
                final_clean_report = clean_md_raw.replace("{ip}", runner_ip) \
                                                 .replace("{urls_list}", urls_list) \
                                                 .replace("{program}", PROGRAM_NAME) \
                                                 .replace("{verify_url}", primary_url) \
                                                 .replace("{severity}", rep.get('severity', 'Medium')) \
                                                 .replace("{request_evidence}", req_ev) \
                                                 .replace("{response_evidence}", res_ev) \
                                                 .replace("{payload}", tid) # TID adalah ID Nuclei yang asli

                # 2. BUAT DRAFT H1 PAKE LAPORAN YANG SUDAH BERSIH (HANYA SEKALI PANGGIL)
                final_d_id = create_h1_draft(rep['title'], final_clean_report, "Automated supply chain/bypass vulnerability detection.", rep['severity'], primary_url)
                if not final_d_id: final_d_id = "MANUAL_SUBMIT_REQUIRED"

                # 3. SIMPAN LAPORAN MD UNTUK NOTIF TELEGRAM
                sev_folder = "high" if any(x in rep['severity'].upper() for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
                os.makedirs(f"data/{PROGRAM_NAME}/alerts/{sev_folder}", exist_ok=True)
                report_path = f"data/{PROGRAM_NAME}/alerts/{sev_folder}/{tid}.md"
            
                with open(report_path, 'w') as f_report:
                    f_report.write(f"🆔 **Draft ID:** `{final_d_id}`\n\n")
                    f_report.write(final_clean_report)

                # 4. DATABASE SAFETY: Catat ke memori HANYA jika semua proses di atas sukses
                with open(SEEN_DB, "a") as db_append:
                    db_append.write(f"{url_hash}\n")
            
                print(f"[+] Success Reported & Saved: {tid}")

        except Exception as e: print(f"Error in {tid}: {e}")

if __name__ == "__main__":
    validate_findings()


Structure:
{luxury_template}

Return ONLY a JSON OBJECT: {{"title": "...", "severity": "...", "full_markdown": "..."}}
"""
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {"Authorization": f"Bearer {AI_KEY}"}
            payload = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
            
            print(f"[*] Analyzing Group: {tid}...")
            res = requests.post(url, headers=headers, json=payload, timeout=120)
            if res.status_code != 200: continue
            
            ai_data = res.json()['choices'][0]['message']['content'].strip()
            match = re.search(r'\{.*\}', ai_data, re.DOTALL)
            if match:
                # --- [ JSON SANITIZER: ANTI-BACKSLASH CRASH ] ---
                # Membersihkan karakter backslash yang merusak format JSON dari AI
                raw_json = match.group(0)
                # Fix common escape errors for TikTok/large HTML
                cleaned_json = raw_json.replace('\\', '\\\\').replace('\\\\"', '\\"')
                
                try:
                    rep = json.loads(cleaned_json, strict=False)
                except Exception as e:
                    print(f"[-] Sanitizer retry needed for {tid}: {e}")
                    # Fallback ke raw jika cleaned gagal
                    rep = json.loads(raw_json, strict=False)

                # JIKA AI MENDETEKSI FALSE POSITIVE, JANGAN LANJUTKAN
                if rep.get("title") == "FALSE_POSITIVE":
                    print(f"[-] Dropping False Positive: {tid}")
                    continue
                
                # Gunakan hash unik gabungan Program + Template ID
                url_hash = hashlib.md5(f"{PROGRAM_NAME}_{tid}".encode()).hexdigest()
                
                # --- LOGIKA MEMORI & FILTER DUPLIKAT ---
                is_seen = False
                if os.path.exists(SEEN_DB):
                    with open(SEEN_DB, "r") as db_read:
                        if url_hash in db_read.read(): 
                            is_seen = True

                # JIKA SUDAH PERNAH DILAPORKAN, LEWATI TOTAL (ANTI-SPAM)
                if is_seen:
                    print(f"[-] Skip (Already Processed): {tid}")
                    continue 

                # 1. SIAPKAN DATA TEKNIS (SUNTIKAN BUKTI ASLI)
                primary_url = findings[0]['matched_url']
                req_ev = findings[0].get('request_evidence', 'No request data captured.')
                res_ev = findings[0].get('response_evidence', 'No response data captured.')
                
                clean_md_raw = rep['full_markdown'].replace(".#", "#").replace(".##", "##").replace(".###", "###").replace(".```", "```")
                
                # 2. REPLACING PLACEHOLDERS (PEMBERSIHAN TOTAL)
                final_clean_report = clean_md_raw.replace("{ip}", runner_ip) \
                                                 .replace("{urls_list}", urls_list) \
                                                 .replace("{program}", PROGRAM_NAME) \
                                                 .replace("{verify_url}", primary_url) \
                                                 .replace("{severity}", rep.get('severity', 'Medium')) \
                                                 .replace("{request_evidence}", req_ev) \
                                                 .replace("{response_evidence}", res_ev) \
                                                 .replace("{payload}", tid) # TID adalah ID Nuclei yang asli

                # 2. BUAT DRAFT H1 PAKE LAPORAN YANG SUDAH BERSIH (HANYA SEKALI PANGGIL)
                final_d_id = create_h1_draft(rep['title'], final_clean_report, "Automated supply chain/bypass vulnerability detection.", rep['severity'], primary_url)
                if not final_d_id: final_d_id = "MANUAL_SUBMIT_REQUIRED"

                # 3. SIMPAN LAPORAN MD UNTUK NOTIF TELEGRAM
                sev_folder = "high" if any(x in rep['severity'].upper() for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
                os.makedirs(f"data/{PROGRAM_NAME}/alerts/{sev_folder}", exist_ok=True)
                report_path = f"data/{PROGRAM_NAME}/alerts/{sev_folder}/{tid}.md"
            
                with open(report_path, 'w') as f_report:
                    f_report.write(f"🆔 **Draft ID:** `{final_d_id}`\n\n")
                    f_report.write(final_clean_report)

                # 4. DATABASE SAFETY: Catat ke memori HANYA jika semua proses di atas sukses
                with open(SEEN_DB, "a") as db_append:
                    db_append.write(f"{url_hash}\n")
            
                print(f"[+] Success Reported & Saved: {tid}")

        except Exception as e: print(f"Error in {tid}: {e}")

if __name__ == "__main__":
    validate_findings()
