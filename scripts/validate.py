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

    all_findings = []
    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                all_findings.append(d)
            except: continue

    # --- [ PRIORITASKAN CRITICAL & HIGH ] ---
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("info",{}).get("severity","info").lower(), 0), reverse=True)

    findings_list = []
    # Buang sampah headers tapi jangan buang daging
    trash = ["ssl-issuer", "tech-detect", "tls-version", "http-missing-security-headers", "dns-sec", "robots-txt"]
    
    for d in all_findings:
        sev = d.get("info", {}).get("severity", "info").lower()
        tid = d.get("template-id", "").lower()
        if sev in ["medium", "high", "critical"] and not any(t in tid for t in trash):
            # Batasi bukti agar AI Groq tidak meledak (Limit 1000 char saja)
            context = get_verification_context(d)
            context["request_evidence"] = context["request_evidence"][:1000]
            context["response_evidence"] = context["response_evidence"][:1000]
            findings_list.append(context)
        
        # Ambil maksimal 10 temuan terbaik saja agar tidak kena Rate Limit AI
        if len(findings_list) >= 10: break

    if not findings_list: return
        
    # --- TEMPLATE ---
    luxury_template = """
.# {title}

.## 📊 Vulnerability Details
- **Severity:** {severity}
- **Affected Asset:** `{url}`
- **Scanner IP:** {ip}
- **User-Agent:** NovaRecon/2026

.## 📝 Executive Summary
{summary}

.## 🔍 Technical Analysis
{technical_explanation}

.## 🚀 Steps To Reproduce (PoC)
1. **Target:** {url}
2. **Attack Vector:** {step_2}
3. **Payload:** `{payload_used}`
4. **Reproduction Link:** {reproduction_url}

.## 🛡️ Proof of Concept (Evidence)
.```http
{request_evidence}
.```
.```http
{response_evidence}
.```

.## ⚠️ Impact Analysis
- **Business:** {business_impact}
- **Technical:** {technical_impact}

.## ✅ Remediation
{remediation_plan}

"""

    # --- PROMPT DIPERKETAT (ANTI-CRASH) ---
    prompt = f"""Role: Elite Security Researcher.
Analyze these security findings: {json.dumps(findings_list)}.

Task: Write a Professional Bug Report.
Return ONLY a JSON ARRAY of OBJECTS. 
FORMAT: [ {{"title": "...", "severity": "...", "url": "...", "full_markdown": "..."}} ]

CRITICAL RULES:
1. Return valid JSON only.
2. If response contains SQL errors, report as SQL Injection.
3. Clean the matched_url from junk paths.
"""

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}"}
        payload = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        
        print(f"[*] Analyzing with AI...")
        res = requests.post(url, headers=headers, json=payload, timeout=120)
        if res.status_code != 200: return
        ai_out = res.json()['choices'][0]['message']['content'].strip()
        
        # Ekstraksi JSON yang aman
        match = re.search(r'\[\s*\{.*\}\s*\]', ai_out, re.DOTALL)
        if not match: match = re.search(r'\[.*\]', ai_out, re.DOTALL)

        if match:
            reports = json.loads(match.group(0), strict=False)
            if isinstance(reports, dict): reports = [reports]
            
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/high", exist_ok=True)
            os.makedirs(f"data/{PROGRAM_NAME}/alerts/low", exist_ok=True)

            for idx, rep in enumerate(reports):
                # PELINDUNG: Pastikan 'rep' adalah Dictionary, bukan String
                if not isinstance(rep, dict):
                    print("[-] AI returned string instead of object, skipping this item.")
                    continue

                target_url = rep.get('url', '')
                if not target_url: continue

                url_hash = hashlib.md5(target_url.encode()).hexdigest()
                
                # Simpan ke Database (Lakukan sebelum simpan file agar aman)
                with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")

                # Tentukan Folder & Simpan Markdown
                sev = rep.get('severity', 'Medium').upper()
                folder = "high" if any(x in sev for x in ["CRIT", "HIGH", "P1", "P2"]) else "low"
                
                safe_title = re.sub(r'\W+', '_', rep.get('title', 'bug'))[:50]
                report_path = f"data/{PROGRAM_NAME}/alerts/{folder}/{safe_title}_{idx}.md"
                
                # Buat Draft H1
                d_id = create_h1_draft(rep.get('title', 'Security Finding'), rep.get('full_markdown', ''), "Automated detection", rep.get('severity', 'high'), target_url)
                final_d_id = d_id if d_id else "MANUAL_SUBMIT_REQUIRED"

                with open(report_path, 'w') as f:
                    f.write(f"🆔 **Draft ID:** `{final_d_id}`\n\n")
                    f.write(rep.get('full_markdown', '').replace(".#", "#").replace(".##", "##").replace(".###", "###").replace(".```", "```"))
                
                print(f"[+] Success Saved: {rep.get('title')}")
                
    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
