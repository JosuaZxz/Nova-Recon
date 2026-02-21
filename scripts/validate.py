import os
import json
import requests
import subprocess
import google.generativeai as genai

# --- [BAGIAN 1: KONFIGURASI GITHUB SECRETS] ---
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

# --- [BAGIAN 2: SETUP AI GEMINI 2.0 FLASH] ---
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash')

def get_verification_context(data):
    """Mengecek bukti teknis (IP & DNS) secara real-time"""
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    
    context = {
        "ip_address": data.get("ip", "Unknown"),
        "status_code": data.get("info", {}).get("status-code", "Unknown"),
        "template_id": data.get("template-id", "Unknown"),
        "matched_at": data.get("matched-at", "Unknown")
    }
    
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME found"
        except:
            context["dns_cname"] = "DNS lookup failed"
    return context

def create_h1_draft(title, description, impact):
    """Mengirim laporan valid langsung ke Draft HackerOne"""
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    payload = {
        "data": {
            "type": "report-intent",
            "attributes": {
                "team_handle": PROGRAM_NAME,
                "title": title,
                "description": description,
                "impact": impact
            }
        }
    }
    
    try:
        response = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return response.json()['data']['id'] if response.status_code == 201 else None
    except:
        return None

def validate_findings():
    """Proses Triage, Konsolidasi Bug, dan Pelaporan"""
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings_list = [] # Variabel ini sekarang singkron dengan prompt
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                raw_data = json.loads(line)
                raw_data["verification_context"] = get_verification_context(raw_data)
                findings_list.append(raw_data)

    # --- [BAGIAN 3: PROMPT AI GRANDMASTER] ---
    prompt = f"""
    ROLE: Senior Security Researcher & Triage Lead at HackerOne.
    PROGRAM: {PROGRAM_NAME}
    DATA: {json.dumps(findings_list)}

    TASK:
    1. ANALYZE: Filter out false positives. Ignore 403/401 on sensitive files or informational noise.
    2. CONSOLIDATE (ANTI-SPAM): If multiple subdomains have the SAME bug, combine them into ONE single report.
    3. LABEL: If the bug is High/Critical (SQLi, RCE, Takeover, Secret Leak), start the title with [URGENT].
    4. POC: Provide clear technical steps (1, 2, 3) to reproduce.
    5. INFO: Include Resolved IP and DNS CNAME in the description.

    FORMAT: Return ONLY a raw JSON with keys: "title", "description", "impact". 
    If nothing is truly valid/vulnerable, return: NO_VALID_BUG
    """

    try:
        response = model.generate_content(prompt)
        ai_output = response.text.strip()

        if "NO_VALID_BUG" in ai_output:
            print(f"[{PROGRAM_NAME}] AI Analysis: Safe. No valid bugs.")
            return

        clean_json = ai_output.replace('```json', '').replace('```', '').strip()
        report_data = json.loads(clean_json)
        
        draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
        
        if draft_id:
            status = f"🎯 **BUG DISCOVERED!**\n\nDraft ID: `{draft_id}`\nTitle: {report_data['title']}"
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                f.write(status)
                
    except Exception as e:
        print(f"AI/Process Error: {e}")

if __name__ == "__main__":
    validate_findings()
