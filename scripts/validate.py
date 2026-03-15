import os
import json
import requests
import subprocess
import re
import time
import hashlib
from datetime import datetime

# --- [ CONFIGURATION ] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"

def get_verification_context(data):
    info = data.get("info", {})
    req = data.get("request", "")
    res = data.get("response", "")
    
    # Ambil 800 char awal dan 400 char akhir saja agar AI tidak overload
    clean_req = (req[:800] + "\n[...]\n" + req[-400:]) if len(req) > 1200 else req
    clean_res = (res[:800] + "\n[...]\n" + res[-400:]) if len(res) > 1200 else res

    return {
        "template_id": data.get("template-id", "Unknown"),
        "template_name": info.get("name", "Unknown Bug Type"),
        "severity": info.get("severity", "unknown"),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "request_evidence": clean_req,
        "response_evidence": clean_res,
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

def create_h1_draft(title, description, impact, severity, url):
    url_hash = hashlib.md5(url.encode()).hexdigest()
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read():
                return "ALREADY_REPORTED"

    # MODE TESTING (Biarkan tanpa memory dulu biar puas testingnya)
    if PROGRAM_NAME in ["00_test", "test_target"]: 
        return "TEST-DRAFT-ID-2026"

    target_handle = "hackerone" if PROGRAM_NAME == "hackerone" else PROGRAM_NAME
    auth = (H1_USER, H1_API_KEY)
    h1_sev = "high" if severity.lower() in ["critical", "high"] else "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": target_handle, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    
    try:
        time.sleep(2)
        res = requests.post("https://api.hackerone.com/v1/hackers/report_intents", auth=auth, headers={"Accept": "application/json"}, json=payload)
        if res.status_code == 201:
            with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")
            return res.json()['data']['id']
    except: pass
    return None

def validate_findings():
    print(f"🔍 Starting Intelligence Triage for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    # --- AMBIL IP RUNNER UNTUK LAPORAN ---
    try: runner_ip = requests.get('https://ifconfig.me', timeout=5).text.strip()
    except: runner_ip = "Unknown IP"

    # --- LOGIC GROUPING PER TEMPLATE ID (ANTI-POINT FARMING) ---
    grouped_findings = {}
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]

    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                tid = d.get("template-id", "Unknown")
                sev = d.get("info", {}).get("severity", "info").lower()
                
                if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
                    if tid not in grouped_findings: grouped_findings[tid] = []
                    grouped_findings[tid].append(get_verification_context(d))
            except: continue

    if not grouped_findings: return

    # --- TEMPLATE KERAS DENGAN TITIK (.) UNTUK FORMATTING ---
    luxury_template = """
.# {title} in {program}

.## 📊 Vulnerability Details
- **Severity:** {severity}
- **Affected Assets:** 
{urls_list}
- **Scanner IP:** {ip}
- **User-Agent:** NovaRecon/2026

.## 📝 Executive Summary
{summary}

.## 🔍 Technical Analysis
{technical_explanation}

.## 🚀 Steps To Reproduce (PoC)
1. **Target List:** {urls_list}
2. **Attack Vector:** {attack_vector}
3. **Payload used:** `{payload}`

.## 🛡️ Proof of Concept (Evidence)
.```http
{request_evidence}
.```
.```http
{response_evidence}
.```

.## ⚠️ Impact Analysis
- **Technical Impact:** {technical_impact}
- **Business Impact:** {business_impact}

.## ✅ Remediation
{remediation}
"""

    for tid, findings in grouped_findings.items():
        # Gabungkan semua URL yang terkena bug yang sama
        urls_list = "\n".join([f"- `{f['matched_url']}`" for f in findings])
        
        prompt = f"""Role: Elite Security Researcher.
Program: {PROGRAM_NAME}
Vulnerability ID: {tid}
Findings Data: {json.dumps(findings[:5])}

Task: Write ONE professional bug report for ALL affected assets.
MANDATORY: Use this EXACT structure (include the dots at start of lines):
{luxury_template}

Return ONLY a JSON OBJECT: {{"title": "...", "severity": "...", "full_markdown": "..."}}
"""

        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {"Authorization": f"Bearer {AI_KEY}"}
            payload = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
            
            print(f"[*] Analyzing Group: {tid}...")
            res = requests.post(url, headers=headers, json=payload, timeout=120)
            if res.status_code != 200: continue
            
            ai_data = res.json()['choices'][0]['message']['content'].strip()
            match = re.search(r'\{.*\}', ai_data, re.DOTALL)
            if match:
                rep = json.loads(match.group(0), strict=False)
                
                # Gunakan hash unik gabungan Program + Template ID
                url_hash = hashlib.md5(f"{PROGRAM_NAME}_{tid}".encode()).hexdigest()
                
                # Cek Database Memory
                is_seen = False
                if os.path.exists(SEEN_DB):
                    with open(SEEN_DB, "r") as f:
                        if url_hash in f.read(): is_seen = True

                # Draft H1 hanya dibuat jika belum pernah dilaporkan
                final_d_id = "ALREADY_REPORTED" if is_seen else create_h1_draft(rep['title'], rep['full_markdown'], "Multiple endpoints affected.", rep['severity'], findings[0]['matched_url'])
                
                if not is_seen:
                    with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")

                # Tentukan Folder Severity
                sev_folder = "high" if any(x in rep['severity'].upper() for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
                os.makedirs(f"data/{PROGRAM_NAME}/alerts/{sev_folder}", exist_ok=True)
                
                # Simpan MD dan bersihkan tanda titik (.)
                report_path = f"data/{PROGRAM_NAME}/alerts/{sev_folder}/{tid}.md"
                with open(report_path, 'w') as f:
                    f.write(f"🆔 **Draft ID:** `{final_d_id}`\n\n")
                    # Membersihkan titik agar Markdown jadi valid
                    clean_md = rep['full_markdown'].replace(".#", "#").replace(".##", "##").replace(".###", "###").replace(".```", "```")
                    # Isi placeholder yang tersisa
                    final_md = clean_md.replace("{ip}", runner_ip).replace("{urls_list}", urls_list).replace("{program}", PROGRAM_NAME)
                    f.write(final_md)
                
                print(f"[+] Grouped Report Saved: {tid}")
        except Exception as e: print(f"Error in {tid}: {e}")

if __name__ == "__main__":
    validate_findings()
