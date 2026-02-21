import os
import json
import requests
import subprocess
import re

# --- KONFIGURASI ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    context = {
        "ip_address": data.get("ip", "Unknown"),
        "status_code": data.get("info", {}).get("status-code", "Unknown"),
        "template_id": data.get("template-id", "Unknown")
    }
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME"
        except: context["dns_cname"] = "DNS Error"
    return context

def create_h1_draft(title, description, impact, severity):
    """Kirim draf ke HackerOne"""
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    # Mapping severity AI ke standar HackerOne
    h1_severity = "low"
    if severity.lower() in ["critical", "high"]: h1_severity = "high"
    elif severity.lower() == "medium": h1_severity = "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": PROGRAM_NAME, "title": title, "description": description, "impact": impact, "severity_rating": h1_severity}}}
    
    try:
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25:
                d = json.loads(line)
                d["context"] = get_verification_context(d)
                findings.append(d)

    # PROMPT: Minta AI tentukan SEVERITY (Critical/High/Medium/Low)
    prompt = f"""
    ROLE: Senior Security Triage Lead.
    PROGRAM: {PROGRAM_NAME}
    DATA: {json.dumps(findings)}

    TASK:
    1. Filter out false positives/noise.
    2. Consolidate same bugs into one report.
    3. DETERMINE SEVERITY: Must be 'Critical', 'High', 'Medium', or 'Low'.
    4. WRITE REPORT: Technical steps, URL, IP, Impact.
    
    FORMAT JSON: {{"title": "...", "description": "...", "impact": "...", "severity": "..."}}
    If no valid bug: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        
        res = requests.post(url, headers=headers, json=data)
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return

        match = re.search(r'\{.*\}', ai_out, re.DOTALL)
        if match:
            rep = json.loads(match.group(0), strict=False)
            d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
            
            # --- LOGIKA PEMISAH PESAN ---
            sev = rep['severity'].upper()
            msg = f"{'🚨' if sev in ['CRITICAL', 'HIGH'] else '⚠️'} **{sev} BUG FOUND!**\n\n🎯 {PROGRAM_NAME.upper()}\n🆔 H1 Draft: `{d_id}`\n📝 {rep['title']}"
            
            # Pisahkan file berdasarkan tingkat bahaya
            if sev in ["CRITICAL", "HIGH"]:
                with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f: f.write(msg)
            else:
                with open(f'data/{PROGRAM_NAME}/low_findings.txt', 'w') as f: f.write(msg)

    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
