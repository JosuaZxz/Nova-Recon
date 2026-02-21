import os
import json
import requests
import subprocess
import re

# --- [BAGIAN 1: KONFIGURASI RAHASIA] ---
# Mengambil kunci dari GitHub Secrets
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """
    Fungsi cerdas untuk mengecek bukti teknis (IP & DNS) secara real-time.
    Ini fitur yang bikin laporan kamu terlihat sangat niat.
    """
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    
    context = {
        "ip_address": data.get("ip", "Unknown"),
        "status_code": data.get("info", {}).get("status-code", "Unknown"),
        "template_id": data.get("template-id", "Unknown"),
        "matched_at": data.get("matched-at", "Unknown")
    }
    
    # Verifikasi CNAME jika ada indikasi Subdomain Takeover
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME record found"
        except:
            context["dns_cname"] = "DNS lookup failed"
    return context

def create_h1_draft(title, description, impact):
    """
    Mengirim laporan valid langsung ke Draft HackerOne.
    Ditambahkan fitur Bypass untuk mode testing.
    """
    # JIKA MODE TES: Kita buat ID palsu agar Telegram tetap bunyi
    if PROGRAM_NAME == "00_test":
        print("DEBUG: Test Mode detected. Bypassing H1 API.")
        return "DRAFT-TEST-12345"

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
        if response.status_code == 201:
            return response.json()['data']['id']
        else:
            print(f"H1 Error: {response.text}")
    except Exception as e:
        print(f"H1 Connection Error: {e}")
    return None

def validate_findings():
    """Proses utama: Analisa Bug, Triage AI, dan Pelaporan Otomatis"""
    print(f"🔍 Starting Professional Triage for: {PROGRAM_NAME}")
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        print("❌ No results found to analyze.")
        return

    findings_list = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 25: 
                raw_data = json.loads(line)
                # Tambahkan bukti teknis DNS/IP
                raw_data["verification_context"] = get_verification_context(raw_data)
                findings_list.append(raw_data)

    # PROMPT AI STANDAR HACKERONE (LLAMA 3.3 70B)
    prompt = f"""
    ROLE: Senior Security Researcher at HackerOne (Triage Specialist).
    PROGRAM: {PROGRAM_NAME}
    DATA: {json.dumps(findings_list)}

    TASK:
    1. ANALYZE: Identify real security vulnerabilities.
    2. CONSOLIDATE: Merge same bugs into ONE report.
    3. LABEL: Use [URGENT] for Critical bugs.
    4. POC: Provide clear technical steps (1, 2, 3) to reproduce.
    5. FORMAT: Return ONLY a raw JSON with keys: "title", "description", "impact".
    
    If nothing is valid, reply only: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        
        response = requests.post(url, headers=headers, json=data)
        ai_output = response.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_output:
            print("✅ AI Analysis: Target is safe.")
            return

        # Parsing JSON dengan aman menggunakan Regex
        json_match = re.search(r'\{.*\}', ai_output, re.DOTALL)
        if json_match:
            report_data = json.loads(json_match.group(0), strict=False)
            
            # Kirim ke HackerOne (atau Bypass jika Tes)
            draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
            
            if draft_id:
                # Siapkan pesan untuk Telegram
                msg = f"💎 **VALID BUG DISCOVERED!**\n\n🎯 Target: {PROGRAM_NAME.upper()}\n🆔 Draft ID: `{draft_id}`\n📝 Title: {report_data['title']}"
                with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                    f.write(msg)
                print("🚀 Success! Data saved for notification.")
                
    except Exception as e:
        print(f"❌ AI Processing Error: {e}")

# --- [BAGIAN 4: RUN SCRIPT] ---
if __name__ == "__main__":
    validate_findings()
