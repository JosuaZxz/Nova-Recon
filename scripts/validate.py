import os
import json
import requests
import subprocess
import re
from datetime import datetime

# --- [1. KONFIGURASI RAHASIA] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    context = {
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time,
        "template": data.get("template-id", "Unknown"),
        "url": data.get("matched-at", host)
    }
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME found"
        except: context["dns_error"] = "Lookup failed"
    return context

def create_h1_draft(title, description, impact, severity):
    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": target_handle, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    try:
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    print(f"🔍 Starting Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                d["context"] = get_verification_context(d)
                findings.append(d)

    # Folder untuk menyimpan file laporan individu
    os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
    os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

    report_template = """
## Vulnerability Details
**Severity:** {severity_label}
**Affected Asset:** {url}

## Summary
{summary}

## Impact
{impact_details}

## Technical Details
{tech_details}

## Steps To Reproduce
1. {step_1}
2. {step_2}
3. {step_3}

## Environment
- **IP:** {ip}
- **Scan Time:** {time}
"""

    prompt = f"Role: Senior Triage Specialist. Program: {PROGRAM_NAME}. Data: {json.dumps(findings)}. Task: Write separate technical reports using template: {report_template}. Format: JSON ARRAY of objects [{{title, description, impact, severity}}]. No talk, just JSON."

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        response = requests.post(url, headers=headers, json=data)
        ai_out = response.json()['choices'][0]['message']['content'].strip()

        match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            for idx, rep in enumerate(reports):
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
                
                # Tentukan Kategori P-Level
                sev = rep.get('severity', 'Medium').upper()
                p_label = "P1-P2" if sev in ["CRITICAL", "HIGH"] else "P3-P4"
                
                # Buat Nama File yang Aman (Title dibersihkan)
                safe_title = re.sub(r'[^\w\s-]', '', rep['title']).strip().replace(' ', '_')
                file_path = f"data/{PROGRAM_NAME}/alerts/{'high' if p_label == 'P1-P2' else 'low'}/{p_label}_{safe_title}_{idx}.md"

                # Susun isi file Markdown
                content = f"# {rep['title']}\n\n"
                content += f"**Draft ID:** `{d_id or 'Manual_Review'}`\n"
                content += f"**Program:** {PROGRAM_NAME.upper()}\n"
                content += f"**Severity:** {sev}\n\n"
                content += f"{rep['description']}\n\n"
                content += f"## Impact\n{rep['impact']}\n"

                with open(file_path, 'w') as f:
                    f.write(content)
                    
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
