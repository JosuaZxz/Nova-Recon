import os
import json
import requests
import subprocess
import google.generativeai as genai

# --- [BAGIAN 1: IDENTITAS & KUNCI RAHASIA] ---
# Mengambil rahasia yang kamu simpan di GitHub Secrets
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

# --- [BAGIAN 2: SETUP OTAK AI GEMINI 2.0] ---
genai.configure(api_key=GEMINI_API_KEY)
# Menggunakan model 2.0 Flash untuk kecepatan nalar tingkat tinggi
model = genai.GenerativeModel('gemini-2.0-flash')

def get_verification_context(data):
    """
    Fungsi cerdas untuk mengecek kondisi asli di lapangan (Terminal).
    Membantu AI membedakan mana bug asli dan mana yang palsu.
    """
    domain = data.get("host", "").replace("https://", "").replace("http://", "").split(":")[0]
    # Mengambil IP dan info tambahan jika ada
    context = {
        "ip_address": data.get("ip", "Unknown"),
        "template_id": data.get("template-id", "Unknown"),
        "status_code": data.get("info", {}).get("status-code", "Unknown")
    }
    
    # Khusus untuk Takeover, kita cek CNAME-nya pakai perintah 'dig'
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["dns_cname"] = cname if cname else "No CNAME Record Found"
        except:
            context["dns_cname"] = "DNS Query Failed"
            
    return context

def create_h1_draft(title, description, impact):
    """Mengirim laporan yang sudah divalidasi AI langsung ke HackerOne"""
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
    """Proses utama: Membaca hasil Nuclei, Verifikasi, dan Panggil AI"""
    results_path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings_to_analyze = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            # Analisa hingga 20 temuan agar AI punya pandangan luas
            if i < 20:
                raw_data = json.loads(line)
                # Tambahkan konteks verifikasi (DNS/IP/Status Code) ke data AI
                raw_data["verification_context"] = get_verification_context(raw_data)
                findings_to_analyze.append(raw_data)

    # --- [BAGIAN 3: INSTRUKSI AI (TRIAGE LEAD ROLE)] ---
    # Ini adalah "perintah rahasia" yang bikin AI kamu jadi pinter
    prompt = f"""
    ROLE: You are the Senior Triage Lead at HackerOne.
    TASK: Critically analyze these scan results for the program: {PROGRAM_NAME}.
    
    DATA TO REVIEW:
    {json.dumps(findings_to_analyze)}

    INSTRUCTIONS:
    1. VALIDATE STATUS CODES: 
       - If a sensitive file (.env, .git, etc.) shows status 403 or 401, it is PROTECTED. Discard it.
       - If it shows 200 OK, it is a VALID VULNERABILITY.
    2. CHECK TAKEOVERS: Use the 'dns_cname' in the context. Only report if it's pointing to a vulnerable 3rd party.
    3. FILTER NOISE: Discard 'Informational' or 'Low' severity findings that have no security impact.
    4. REPORT: If you find a valid bug, write a professional report in English.
    5. FORMAT: Return ONLY a raw JSON with keys: "title", "description", "impact".
    6. IF NOTHING IS VALID: Simply return the word: NO_VALID_BUG
    """

    try:
        response = model.generate_content(prompt)
        ai_text = response.text.strip()

        if "NO_VALID_BUG" in ai_text:
            print(f"[{PROGRAM_NAME}] AI Analysis: No valid security threats found.")
            return

        # Membersihkan dan parsing JSON dari AI
        clean_json = ai_text.replace('```json', '').replace('```', '').strip()
        report = json.loads(clean_json)
        
        # Kirim draf ke HackerOne
        draft_id = create_h1_draft(report['title'], report['description'], report['impact'])
        
        if draft_id:
            # Notifikasi untuk Telegram kamu
            status = f"🎯 **VALID BUG DISCOVERED!**\n\nTarget: {PROGRAM_NAME.upper()}\nDraft ID: `{draft_id}`\nTitle: {report['title']}"
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
                f.write(status)
                
    except Exception as e:
        print(f"DEBUG: AI Processing Error -> {e}")

# --- [BAGIAN 4: EKSEKUSI] ---
if __name__ == "__main__":
    validate_findings()
