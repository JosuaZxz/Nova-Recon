import os
import json
import requests
import subprocess
import re
import time
import hashlib
from datetime import datetime

# --- [ 1. CONFIGURATION ] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"

def get_verification_context(data):
    info = data.get("info", {})
    return {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": info.get("name", "Unknown Bug Type"), # Tambahkan ini!
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "ip": data.get("ip", "Unknown IP"),
        "request_evidence": data.get("request", "")[:1500],
        "response_evidence": data.get("response", "")[:1000],
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def create_h1_draft(title, description, impact, severity, url):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                return "ALREADY_REPORTED"

    # Bypass H1 API jika program testing
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
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    all_findings = []
    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                all_findings.append(d)
            except: continue

    # 1. Priority Ranking
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("info",{}).get("severity","info").lower(), 0), reverse=True)

    findings_list = []
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]
    for d in all_findings:
        sev = d.get("info", {}).get("severity", "info").lower()
        tid = d.get("template-id", "").lower()
        if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
            findings_list.append(get_verification_context(d))
        if len(findings_list) >= 15: break

    if not findings_list: return

    # 2. Luxury Template (Sultan Edition - Spacing Updated)
    luxury_template = """
.# {title}

.## 📊 Vulnerability Details
- **Severity:** {severity}
- **Affected Asset:** `{url}`
- **Scanner IP:** {ip}
- **User-Agent:** NovaRecon/2026

.## 📝 Executive Summary
{summary}

.## 🔍 Technical Analysis
{technical_explanation}

.## 🚀 Steps To Reproduce (PoC)
1. **Target Navigation:** Navigate to {url}
2. **Attack Vector:** Inject payload `{payload_used}` into the parameter.
3. **Reproduction URL:** {reproduction_url}
4. **Observation:** {step_3}

.## 🛡️ Proof of Concept (Evidence)

.### HTTP Request:
.```http
{request_evidence}
.```

.### HTTP Response (Vulnerable Response):
.```http
{response_evidence}
.```

.## ⚠️ Impact Analysis

.### 🏢 Business Impact:
{business_impact}

.### 💻 Technical Impact:
{technical_impact}

.## ✅ Remediation
{remediation_plan}
"""

    # 3. Prompt AI dengan Instruksi REPRODUCTION URL (Tinggal Klik)
    prompt = f"""Role: Elite Cyber Security Analyst.
Data Findings: {json.dumps(findings_list)}.

Task: Write a Professional Bug Bounty Report.
STRICT RULES:
1. BUG TYPE: You MUST identify the bug type BASED ON 'template_name' and 'template_id'. 
   - If template is 'Cross Site Scripting', the title and analysis MUST be about XSS.
   - If template is 'SQL Injection', the title MUST be about SQLi.
   - DO NOT be fooled by database errors if the payload used is a <script> tag.
2. PAYLOAD: Identify the exact payload used from the 'request_evidence'. 
3. REPRODUCTION: Provide a 'reproduction_url' that is the 'matched_url' from the data.
4. CVE: Only mention a CVE if it is explicitly listed in the 'template_id'.
5. VERBOSE: Make the 'Technical Analysis' and 'Impact' sections long, technical, and accurate.

Template:
{luxury_template}

Output ONLY a JSON ARRAY of objects: ["title", "severity", "url", "full_markdown"]."""
    try:
        # 4. AI Execution
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}"}
        payload = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        
        print(f"[*] Sending to AI...")
        res = requests.post(url, headers=headers, json=payload, timeout=120)
        if res.status_code != 200: return
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        # 5. Parsing & Penulisan Laporan (Loop yang kamu tanyakan)
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

            for idx, rep in enumerate(reports):
                # Buat draf di HackerOne
                d_id = create_h1_draft(rep['title'], rep['full_markdown'], "See detail.", rep['severity'], rep.get('url', ''))
                if d_id in [None, "ALREADY_REPORTED"]: continue
                
                sev = rep.get('severity', 'Medium').upper()
                folder = "high" if any(x in sev for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
                
                safe_title = re.sub(r'\W+', '_', rep['title'])[:50]
                report_path = f"data/{PROGRAM_NAME}/alerts/{folder}/{safe_title}_{idx}.md"
                
                with open(report_path, 'w') as f:
                    # JUDUL DI BARIS PERTAMA (PENTING UNTUK NOTIF TELEGRAM)
                    f.write(f"# {rep['title']} in {PROGRAM_NAME}\n\n")
                    f.write(f"🆔 **Draft ID:** `{d_id}`\n\n")
                    
                    # Bersihkan titik penanda secara otomatis
                    final_report = rep['full_markdown'].replace(".#", "#").replace(".##", "##").replace(".###", "###").replace(".```", "```")
                    f.write(final_report)
                
                print(f"[+] Success: {rep['title']} for {PROGRAM_NAME}")

    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
