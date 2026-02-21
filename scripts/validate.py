import os
import json
import requests
import subprocess
import re

# --- [1. KONFIGURASI] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """Mengecek bukti teknis secara real-time"""
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
        except: context["dns_cname"] = "Failed"
    return context

def create_h1_draft(title, description, impact):
    """Kirim draf laporan ke HackerOne"""
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
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    """Proses Triage AI menggunakan GROQ (Anti-Error Version)"""
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        return

    findings_list = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25:
                data = json.loads(line)
                data["verification_context"] = get_verification_context(data)
                findings_list.append(data)

    # PROMPT DENGAN INSTRUKSI FORMAT KETAT
    prompt = f"Role: Senior H1 Triage. Program: {PROGRAM_NAME}. Data: {json.dumps(findings_list)}. " \
             "Task: 1. Filter false positives. 2. Consolidate same bugs. 3. Title with [URGENT] if Critical. " \
             "4. Write pro report in English. Output ONLY a valid JSON object with keys: title, description, impact. " \
             "No conversational text. If no valid bug, return ONLY: NO_VALID_BUG"

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1 # Suhu rendah agar AI lebih patuh format
        }
        
        response = requests.post(url, headers=headers, json=data)
        ai_output = response.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_output:
            print(f"[{PROGRAM_NAME}] Safe target.")
            return

        # --- [PROSES PEMBERSIHAN JSON SUPER KUAT] ---
        # 1. Ambil teks di antara kurung kurawal { ... }
        json_match = re.search(r'\{.*\}', ai_output, re.DOTALL)
        if json_match:
            clean_json = json_match.group(0)
            # 2. Gunakan strict=False untuk mengabaikan karakter kontrol (Enter/Tab) yang rusak
            report_data = json.loads(clean_json, strict=False)
            
            draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
            
            if draft_id:
                msg = f"💎 **BUG FOUND (GROQ)!**\n🎯 Target: {PROGRAM_NAME.upper()}\n🆔 Draft ID: `{draft_id}`\n📝 Title: {report_data['title']}"
                with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                    f.write(msg)
        else:
            print("AI didn't return valid JSON format.")
                
    except Exception as e:
        print(f"AI/Process Error: {e}")

if __name__ == "__main__":
    validate_findings()
