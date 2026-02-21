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
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time,
        "template": data.get("template-id", "Unknown")
    }

def create_h1_draft(title, description, impact, severity):
    """Kirim Draf ke HackerOne dengan Error Logging Detail"""
    # Gunakan handle 'hackerone' jika sedang mengetes
    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    # Konversi severity ke format yang diterima HackerOne (high, medium, low)
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
        response = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        if response.status_code == 201:
            print(f"✅ Draft Created Successfully: {title}")
            return response.json()['data']['id']
        else:
            # TAMPILKAN ERROR ASLI DARI HACKERONE DISINI
            print(f"❌ H1 API REJECTED: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"❌ H1 Connection Fatal: {e}")
        return None

def validate_findings():
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        return

    findings = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                d["context"] = get_verification_context(d)
                findings.append(d)

    report_template = "## Vulnerability Details\n**Title:** {title}\n**Severity:** {severity}\n**Affected Asset:** {url}\n\n## Summary\n{summary}\n\n## Technical Details\n{tech_details}\n\n## Steps To Reproduce\n1. Access {url}\n2. Observe result\n\n## Testing Environment\n- **IP:** {ip}\n- **Period:** {time}"

    prompt = f"""
    ROLE: Senior Triage Lead at HackerOne. PROGRAM: {PROGRAM_NAME}.
    TASK: Write professional technical reports for these findings: {json.dumps(findings)}
    INSTRUCTION: Use this template: {report_template}. Categorize as 'Critical', 'High', 'Medium', or 'Low'.
    FORMAT: Return ONLY a raw JSON ARRAY of objects with keys: title, description, impact, severity.
    """

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
            
            final_high = ""
            final_low = ""
            for rep in reports:
                # KIRIM KE HACKERONE
                d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
                
                # JIKA BERHASIL (ATAU MESKIPUN GAGAL KE H1, TETAP LAPOR KE TELEGRAM BIAR BOS TAU)
                sev = rep.get('severity', 'Medium').upper()
                emoji = "🚨" if sev in ["CRITICAL", "HIGH"] else "⚠️"
                status_h1 = f"`{d_id}`" if d_id else "FAILED_TO_DRAFT"
                msg_line = f"{emoji} **[{sev} BUG FOUND]**\n🎯 {PROGRAM_NAME.upper()}\n🆔 H1 ID: {status_h1}\n📝 {rep['title']}\n\n"
                
                if sev in ["CRITICAL", "HIGH"]: final_high += msg_line
                else: final_low += msg_line

            if final_high:
                with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f: f.write(final_high)
            if final_low:
                with open(f'data/{PROGRAM_NAME}/low_findings.txt', 'w') as f: f.write(final_low)
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
