import os
import json
import requests
import subprocess
import re
from datetime import datetime

# --- KONFIGURASI ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """Ambil bukti teknis + Waktu Testing"""
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    context = {
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time,
        "template": data.get("template-id", "Unknown")
    }
    
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["cname"] = cname if cname else "No CNAME"
        except: context["dns_error"] = "Lookup failed"
    return context

def create_h1_draft(title, description, impact, severity):
    """Kirim Draf ke HackerOne"""
    if PROGRAM_NAME == "00_test": return "TEST-ID-123"

    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    h1_sev = "low"
    if severity.lower() in ["critical", "high"]: h1_sev = "high"
    elif severity.lower() == "medium": h1_sev = "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": PROGRAM_NAME, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    
    try:
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    # --- [LOGIKA KHUSUS TES: DENGAN LABEL SEVERITY] ---
    if PROGRAM_NAME == "00_test":
        msg = "🚨 **[CRITICAL BUG FOUND]**\n🎯 Target: 00_TEST\n🆔 ID: `DRAFT-PRO-123`\n📝 Status: Jalur Notifikasi High Aktif!"
        with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f: f.write(msg)
        return

    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 20: 
                d = json.loads(line)
                d["context"] = get_verification_context(d)
                findings.append(d)

    # --- TEMPLATE LAPORAN PRO (PAYPAL STYLE) ---
    report_template = """
## Vulnerability Details
**Title:** {{Suggested Title}}
**Severity:** {{Severity}}
**Category:** {{Vulnerability Type}}
**Affected Asset:** {{Vulnerable URL}}

## Summary
{{Brief summary of the vulnerability}}

## Technical Details
{{Detailed technical explanation, showing how the bug works}}

## Steps To Reproduce
1. Open a terminal or browser.
2. Access the following URL: {{Vulnerable URL}}
3. Observe the response: {{Evidence from data}}

## Proof of Concept
The vulnerability was detected using an automated scanner (Nuclei) with template: {{Template ID}}.

## Remediation
**Recommendation:** Secure the affected endpoint immediately.

## Testing Environment
- **IP Address(es):** {{Target IP Address}}
- **User Agent:** Mozilla/5.0 (Automated Scanner)
- **Testing Timezone:** UTC
- **Testing Period:** {{Scan Time}}
    """

    prompt = f"""
    ROLE: Senior Triage. PROGRAM: {PROGRAM_NAME}. DATA: {json.dumps(findings)}
    TASK: 
    1. Filter noise. 
    2. Write separate reports using the template below.
    3. Categorize as 'Critical', 'High', 'Medium', or 'Low' under key 'severity'.
    
    TEMPLATE:
    {report_template}

    FORMAT: Return ONLY a raw JSON ARRAY:
    [ {{"title": "...", "description": "...", "impact": "...", "severity": "..."}} ]
    If no valid bug: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        
        res = requests.post(url, headers=headers, json=data)
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return
        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            final_high = ""
            final_low = ""
            for rep in reports:
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
                if d_id:
                    # --- [UPDATE: PENAMBAHAN LABEL SEVERITY DI NOTIFIKASI] ---
                    sev = rep.get('severity', 'Medium').upper()
                    emoji = "🚨" if sev in ["CRITICAL", "HIGH"] else "⚠️"
                    msg_line = f"{emoji} **[{sev} BUG FOUND]**\n🎯 {PROGRAM_NAME.upper()}\n🆔 Draft ID: `{d_id}`\n📝 Title: {rep['title']}\n\n"
                    
                    if sev in ["CRITICAL", "HIGH"]: final_high += msg_line
                    else: final_low += msg_line

            if final_high:
                with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f: f.write(final_high)
            if final_low:
                with open(f'data/{PROGRAM_NAME}/low_findings.txt', 'w') as f: f.write(final_low)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
