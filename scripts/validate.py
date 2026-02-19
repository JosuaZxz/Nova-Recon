import os
import json
import requests
import google.generativeai as genai

# --- [BAGIAN 1: KONFIGURASI] ---
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

# --- [BAGIAN 2: SETUP AI TERBARU] ---
genai.configure(api_key=GEMINI_API_KEY)
# Menggunakan Gemini 2.0 Flash (Paling Cerdas & Cepat per Feb 2026)
model = genai.GenerativeModel('gemini-2.0-flash')

def create_h1_draft(title, description, impact):
    """Mengirim data ke HackerOne via API (Draft Intents)"""
    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    headers = {"Accept": "application/json"}
    
    # Menyiapkan payload untuk dikirim ke HackerOne
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
        # Status 201 artinya draf sukses dibuat di dashboard kamu
        if response.status_code == 201:
            return response.json()['data']['id']
        else:
            print(f"H1 API Error: {response.text}")
    except Exception as e:
        print(f"H1 Connection Error: {e}")
    return None

def validate_findings():
    """Membaca hasil Nuclei dan memanggil AI untuk validasi"""
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    
    # Jika file scan kosong, robot langsung berhenti (Irit kuota)
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            # Analisis 20 temuan teratas (Keunggulan Gemini 2.0)
            if i < 20: 
                findings.append(json.loads(line))

    # --- [BAGIAN 3: PROMPT AI TEKNIS] ---
    prompt = f"""
    ROLE: Elite Cyber Security Analyst.
    PROGRAM: {PROGRAM_NAME}
    DATA: {json.dumps(findings)}

    INSTRUCTIONS:
    1. Filter: Identify valid security vulnerabilities (P1 to P3). 
    2. Ignore: Low-impact headers, 403/404 errors, or false positives.
    3. Output: Provide ONLY a raw JSON with keys: "title", "description", "impact".
    4. Technical Detail: In "description", include URL, Resolved IP, and clear Steps to Reproduce.
    
    Tone: Professional Technical English.
    """

    try:
        # Proses berpikir AI
        response = model.generate_content(prompt)
        
        # Membersihkan format JSON dari respon AI
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        report_data = json.loads(clean_json)
        
        # Eksekusi kirim ke HackerOne
        draft_id = create_h1_draft(report_data['title'], report_data['description'], report_data['impact'])
        
        # Jika sukses ke H1, siapkan notifikasi Telegram
        if draft_id:
            msg = f"🚀 **NEW H1 DRAFT CREATED!**\n\n🎯 Target: {PROGRAM_NAME}\n🆔 ID: `{draft_id}`\n📝 Title: {report_data['title']}"
            
            # Disimpan di memori sementara server GitHub (Bukan di web)
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                f.write(msg)
                
    except Exception as e:
        # Log error untuk debugging manual di tab Actions
        print(f"AI Process Error: {e}")

# --- [BAGIAN 4: EKSEKUSI] ---
if __name__ == "__main__":
    validate_findings()
