import os
import json
import requests
import subprocess
import re
from datetime import datetime

# --- [1. KONFIGURASI] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """Ambil bukti teknis (IP & DNS)"""
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
            context["cname"] = cname if cname else "No CNAME found"
        except: context["dns_error"] = "Lookup failed"
    return context

def create_h1_draft(title, description, impact, severity):
    """Kirim Draf ke HackerOne (Auto-Switch Handle untuk Tes)"""
    # Jika program 'hackerone', maka API H1 akan menerima request kita
    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    h1_sev = "low"
    if severity.lower() in ["critical", "high"]: h1_sev = "high"
    elif severity.lower() == "medium": h1_sev = "medium"
    
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
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                d = json.loads(line)
                # --- FIX ERROR: 'list' object has no attribute 'get' ---
                if isinstance(d, list): d = d[0]
                
                d["context"] = get_verification_context(d)
                findings.append(d)

    # --- TEMPLATE LAPORAN PRO PAYPAL ---
    report_template = """
## Vulnerability Details
**Title:** {title}
**Severity:** {severity}
**Affected Asset:** {url}

## Summary
{summary}

## Technical Details
{tech_details}

## Steps To Reproduce
1. Access {url}
2. Observe match for template {template}
3. IP Address identified: {ip}

## Testing Environment
- **IP:** {ip}
- **Testing Period:** {time}
    """

    prompt = f"""
    ROLE: Senior Triage Lead. PROGRAM: {PROGRAM_NAME}. DATA: {json.dumps(findings)}
    TASK: 1. Filter false positives. 2. Write SEPARATE reports for EACH bug using the template below.
    3. Categorize as 'Critical', 'High', 'Medium', or 'Low' under key 'severity'.
    
    TEMPLATE TO FILL:
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
            if isinstance(reports, dict): reports = [reports]
            
            final_high = ""
            final_low = ""
            for rep in reports:
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
                if d_id:
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
