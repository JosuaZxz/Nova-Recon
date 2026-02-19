import os
import json
import requests
import google.generativeai as genai

# Ambil rahasia dari GitHub Secrets
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

# Inisialisasi Gemini AI
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

def create_h1_draft(title, description, impact):
    """Kirim draft ke HackerOne Report Intents"""
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    headers = {"Accept": "application/json"}
    
    data = {
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
        response = requests.post(url, auth=auth, headers=headers, json=data)
        if response.status_code == 201:
            return response.json()['data']['id']
        else:
            print(f"H1 Error: {response.text}")
    except Exception as e:
        print(f"H1 Connection Error: {e}")
    return None

def validate_findings():
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 15: # Ambil 15 temuan teratas
                findings.append(json.loads(line))

    # PROMPT PROFESIONAL DENGAN IP ADDRESS
    prompt = f"""
    ROLE: Senior Bug Bounty Hunter and Security Engineer.
    TASK: Create a professional HackerOne report for program '{PROGRAM_NAME}'.
    DATA: {json.dumps(findings)}

    INSTRUCTIONS:
    1. Output MUST be ONLY a VALID JSON with: "title", "description", "impact".
    2. In "description", include:
       - Vulnerable URL
       - Resolved IP Address (get from 'ip' field in data)
       - Nuclei Template ID
       - Detailed Steps to Reproduce (1, 2, 3...)
    3. Use technical and formal English.
    """

    try:
        response = model.generate_content(prompt)
        # Bersihkan JSON dari tanda markdown
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        report_data = json.loads(clean_json)
        
        # Kirim ke HackerOne
        draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
        
        if draft_id:
            msg = f"✅ **DRAFT CREATED ON HACKERONE**\n\n🎯 Target: {PROGRAM_NAME}\n🆔 ID: `{draft_id}`\n📝 Title: {report_data['title']}"
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                f.write(msg)
                
    except Exception as e:
        print(f"AI Process Error: {e}")

if __name__ == "__main__":
    validate_findings()
