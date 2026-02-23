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
    """Mengumpulkan bukti teknis IP, DNS, dan Deskripsi Template"""
    host = data.get("host", "")
    info = data.get("info", {})
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    return {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": info.get("name", "Unknown"),
        "template_desc": info.get("description", "No description"),
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", host),
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time
    }

def create_h1_draft(title, description, impact, severity, url):
    """Kirim laporan ke H1 dengan sistem Hashing URL (Stealth)"""
    # Use MD5 Hash to make the URL list in the Public repo unreadable to humans
    url_hash = hashlib.md5(url.encode()).hexdigest()
    
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                print(f"[-] Duplicate skipped (Hashed): {url_hash}")
                return "ALREADY_REPORTED"

    if PROGRAM_NAME == "00_test": return "TEST-DRAFT-ID-2026"

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
    print(f"🔍 Starting Grandmaster Triage: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings_list = []
    # Quality filter: Only Medium and above & discard the noisy ones
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers"]
    
    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                sev = d.get("info", {}).get("severity", "info").lower()
                tid = d.get("template-id", "").lower()
                
                if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
                    findings_list.append(get_verification_context(d))
                if len(findings_list) >= 15: break
            except: continue

    if not findings_list: return

    # --- [REPORT TEMPLATE] ---
    report_template = """## Vulnerability Details
**Title:** {title}
**Severity:** {severity}
**Affected Asset:** {url}
## Summary
{summary}
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
- IP: {ip} | User-Agent: SniperRecon/2026
## Remediation
{remediation_plan}"""

    prompt = f"Role: Senior Triage Lead. Data: {json.dumps(findings_list)}. Write technical reports using template: {report_template}. Output ONLY a JSON ARRAY: [{{title, description, impact, severity, url}}]. If nothing valid: NO_VALID_BUG"

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        res = requests.post(url, headers={"Authorization": f"Bearer {AI_KEY}"}, json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1})
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

            for idx, rep in enumerate(reports):
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'], rep.get('url', ''))
                if d_id in [None, "ALREADY_REPORTED"]: continue
                
                sev = rep.get('severity', 'Medium').upper()
                p_label = "P1-P2" if any(x in sev for x in ["CRITICAL", "HIGH", "P1", "P2"]) else "P3-P4"
                folder = "high" if p_label == "P1-P2" else "low"
                
                safe_title = re.sub(r'\W+', '_', rep['title'])[:50]
                with open(f"data/{PROGRAM_NAME}/alerts/{folder}/{p_label}_{safe_title}_{idx}.md", 'w') as f:
                    f.write(f"# {rep['title']}\n\nDraft ID: `{d_id}`\n\n{rep['description']}\n\n## Impact\n{rep['impact']}")
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
