import os
import json
import requests
import subprocess
import re
import time
import hashlib
from datetime import datetime

# --- [1. CONFIGURATION] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"

def get_verification_context(data):
    host = data.get("host", "")
    info = data.get("info", {})
    raw_req = data.get("request", "")
    raw_res = data.get("response", "")
    short_req = (raw_req[:1500] + '..[truncated]') if len(raw_req) > 1500 else raw_req
    short_res = (raw_res[:800] + '..[truncated]') if len(raw_res) > 800 else raw_res

    return {
        "template_id": data.get("template-id", "Unknown"),
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", host),
        "ip": data.get("ip", "Unknown IP"),
        "request_evidence": short_req,
        "response_evidence": short_res,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def create_h1_draft(title, description, impact, severity, url):
    """Kirim laporan ke H1 dengan sistem Hashing URL (Stealth)"""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                print(f"[-] Duplicate skipped (Hashed): {url_hash}")
                return "ALREADY_REPORTED"

    # --- [BAGIAN INI YANG WAJIB DIEDIT] ---
    # Kita paksa return ID palsu kalau targetnya cuma testing
    # Agar script TIDAK mencoba connect ke API HackerOne
    if PROGRAM_NAME in ["00_test", "test_target"]: 
        print("[+] Test Mode: Skipping H1 Upload. Generating Telegram Alert...")
        return "TEST-DRAFT-ID-2026"
    # --------------------------------------

    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": target_handle, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    
    try:
        time.sleep(2) # Anti-Spam Delay
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload)
        if res.status_code == 201:
            with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")
            return res.json()['data']['id']
    except: pass
    return None

def validate_findings():
    print(f"🔍 Starting Professional Triage: {PROGRAM_NAME}")
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

    # Sort: Critical top
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("info",{}).get("severity","info").lower(), 0), reverse=True)

    findings_list = []
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec"]
    
    for d in all_findings:
        sev = d.get("info", {}).get("severity", "info").lower()
        tid = d.get("template-id", "").lower()
        if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
            findings_list.append(get_verification_context(d))
        if len(findings_list) >= 10: break

    if not findings_list: return

    # --- [REPORT TEMPLATE] ---
    report_template = """## Vulnerability Details
**Title:** {title}
**Severity:** {severity}
**Affected Asset:** {url}
## Summary
{summary}
## Technical Evidence (Request):
```http
{request_evidence}
```
## Impact
### Business Impact:
{business_impact}
### Technical Impact:
{technical_impact}
## Technical Details
{technical_explanation}
## Steps To Reproduce
1. Navigate to {url}
2. {step_2}
3. {step_3}
## Environment
- IP: {ip} | User-Agent: NovaRecon/2026
## Remediation
{remediation_plan}"""

    # --- [ PROMPT ULTIMATE & PROFESIONAL ] ---
    prompt = f"""Role: Senior Security Researcher & Lead Triage.
Data Findings: {json.dumps(findings_list)}.

Task: Create a highly professional, detailed, and technical vulnerability report for each bug found in the provided Data. 
These reports are for a professional Triage Team, so they must be clear, actionable, and include all technical evidence.

Instructions:
1. Fill the provided 'report_template' below for each valid vulnerability.
2. Use the 'request_evidence' and 'response_evidence' to write a realistic 'Steps to Reproduce' section.
3. In the 'Environment' section, you MUST map the 'ip' and 'time' from the Data findings.
4. Ensure the Technical Explanation explains WHY this is a vulnerability.

--- REPORT TEMPLATE TO FILL ---
{report_template}
------------------------------

Output MUST be ONLY a JSON ARRAY of objects with these exact keys:
[
  {{
    "title": "Concise Technical Title",
    "severity": "CRITICAL/HIGH/MEDIUM",
    "url": "The Affected URL",
    "full_markdown": "PASTE THE ENTIRE FILLED MARKDOWN REPORT HERE (From Details to Remediation)"
  }}
]

If no valid security bugs are found, output: NO_VALID_BUG"""

    try:
        # --- [ AI EXECUTION WITH SEQUENTIAL RETRY ] ---
        ai_out = None
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}"}
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }

        print(f"[*] Sending findings to AI for {PROGRAM_NAME}...")

        for attempt in range(3): # Coba sampai 3 kali jika gagal
            try:
                # Timeout 90 detik karena laporan kita sekarang sangat detil
                res = requests.post(url, headers=headers, json=payload, timeout=90)
                
                if res.status_code == 200:
                    ai_out = res.json()['choices'][0]['message']['content'].strip()
                    break # Sukses! Keluar dari loop
                
                elif res.status_code == 429: # Rate Limit
                    print(f" [!] AI busy (Rate Limit). Waiting 15s... (Attempt {attempt+1}/3)")
                    time.sleep(15)
                
                else:
                    print(f" [!] AI Server Error ({res.status_code}). Retrying... (Attempt {attempt+1}/3)")
                    time.sleep(5)
                    
            except Exception as e:
                print(f" [!] Connection Error: {e}. Retrying... (Attempt {attempt+1}/3)")
                time.sleep(5)

        # --- [ POST-PROCESSING ] ---
        if not ai_out or "NO_VALID_BUG" in ai_out:
            print(f"[-] No valid bugs found by AI for {PROGRAM_NAME}.")
            return

        # Mencari JSON di dalam output AI
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

            for idx, rep in enumerate(reports):
                # --- FIX 1: Kirim 'full_markdown' ke HackerOne ---
                d_id = create_h1_draft(rep['title'], rep['full_markdown'], "Detail impact ada di laporan.", rep['severity'], rep.get('url', ''))
                
                if d_id in [None, "ALREADY_REPORTED"]: 
                    continue
                
                # Labeling Severity
                sev = rep.get('severity', 'Medium').upper()
                p_label = "P1-P2" if any(x in sev for x in ["CRITICAL", "HIGH", "P1", "P2"]) else "P3-P4"
                folder = "high" if p_label == "P1-P2" else "low"
                
                # Simpan Report ke file .md
                safe_title = re.sub(r'\W+', '_', rep['title'])[:50]
                report_path = f"data/{PROGRAM_NAME}/alerts/{folder}/{p_label}_{safe_title}_{idx}.md"
                
                # --- FIX 2: Tulis 'full_markdown' ke File Telegram ---
                with open(report_path, 'w') as f:
                    f.write(f"🆔 **Draft ID:** `{d_id}`\n\n")
                    f.write(rep['full_markdown']) # <--- Ini yang bikin laporan panjang & pro
                
                print(f"[+] SUCCESS: Professional Report for {rep['title']}")

    except Exception as e: 
        print(f"Error in AI/Drafting process: {e}")

if __name__ == "__main__":
    validate_findings()
