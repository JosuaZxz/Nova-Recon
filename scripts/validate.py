import os
import json
import requests
import re
import time
import hashlib
from datetime import datetime

# --- [ 1. CONFIGURATION ] ---
AI_KEY = os.environ.get("GROQ_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")
SEEN_DB = ".seen_urls"

def extract_ua(request_data):
    """Mengambil User-Agent asli dari request mentah Nuclei"""
    match = re.search(r"User-Agent: (.*)", request_data, re.IGNORECASE)
    return match.group(1).strip() if match else "Mozilla/5.0 (Randomized Stealth)"

def get_contextual_snippet(res_raw, data):
    """
    LOGIKA SNIPER ELIT: Mencari pusat bukti berdasarkan matcher Nuclei, 
    bukan sekadar potong 1000 karakter awal.
    """
    if not res_raw: return "No Response Data"
    
    # Kumpulkan kata kunci pencarian dari data Nuclei
    keywords = []
    if "matcher-name" in data: keywords.append(data["matcher-name"])
    if "extracted-results" in data: keywords.extend(data["extracted-results"])
    
    # Kata kunci umum jika tidak ada matcher spesifik
    common_triggers = ["sql syntax", "mysql", "root:x:", "alert(", "<script", "lsass", "metadata"]
    keywords.extend(common_triggers)

    target_index = -1
    for kw in keywords:
        idx = res_raw.lower().find(str(kw).lower())
        if idx != -1:
            target_index = idx
            break
    
    # Jika tidak ketemu titik luka, ambil 1000 karakter pertama sebagai fallback
    if target_index == -1:
        return res_raw[:1000] + "\n[...Trimmed...]"

    # Ambil 500 karakter sebelum dan 500 setelah titik luka (Window 1000)
    start = max(0, target_index - 500)
    end = min(len(res_raw), target_index + 500)
    
    snippet = res_raw[start:end]
    return f"[...Snipped Context...]\n{snippet}\n[...Snipped Context...]"

def get_verification_context(data):
    """Mengumpulkan bukti lengkap untuk disuapkan ke AI"""
    req_raw = data.get("request", "")
    res_raw = data.get("response", "")
    
    # Cek bukti OAST (Interactsh) untuk SSRF/Blind Bugs
    interaction_info = "NONE"
    if "interaction" in data:
        interaction_info = json.dumps(data["interaction"], indent=2)

    return {
        "template_name": data.get("info", {}).get("name", "Unknown Vulnerability"),
        "severity": data.get("info", {}).get("severity", "medium").upper(),
        "matched_url": data.get("matched-at", data.get("host", "")),
        "ip": data.get("ip", "Unknown"),
        "real_ua": extract_ua(req_raw),
        "request_evidence": req_raw[:1500],
        "response_evidence": get_contextual_snippet(res_raw, data), # SNIPER SHOT!
        "interaction_evidence": interaction_info
    }

def create_h1_draft(title, url_hash):
    """Mencegah spam dengan database .seen_urls"""
    if os.path.exists(SEEN_DB):
        with open(SEEN_DB, "r") as f:
            if url_hash in f.read(): return "ALREADY_REPORTED"

    # MODE TESTING (Selalu catat agar tidak lapor ulang)
    with open(SEEN_DB, "a") as f: f.write(f"{url_hash}\n")
    
    if PROGRAM_NAME in ["00_test", "test_target"]: 
        return "TEST-DRAFT-ID-2026"
    
    return "PRO-HUNTER-DRAFT"

def validate_findings():
    print(f"🔍 [OPERASI SNIPER] Processing findings for: {PROGRAM_NAME}")
    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: 
        print("[!] No findings in Nuclei results.")
        return

    all_findings = []
    with open(path, 'r') as f:
        for line in f:
            try:
                d = json.loads(line)
                if isinstance(d, list): d = d[0]
                all_findings.append(d)
            except: continue

    # Urutkan: Critical & High duluan!
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    all_findings.sort(key=lambda x: sev_rank.get(x.get("info",{}).get("severity","").upper(), 0), reverse=True)

    processed_count = 0
    for d in all_findings:
        if processed_count >= 15: break # Maksimal 15 bug per target biar ga spam
        
        ctx = get_verification_context(d)
        if ctx['severity'] not in ["MEDIUM", "HIGH", "CRITICAL"]: continue

        print(f"[*] Analyzing with AI: {ctx['template_name']} on {ctx['matched_url']}")

        # --- [ PROMPT SULTAN TRIAGE ] ---
        prompt = f"""Role: Bug Bounty Elite Triage. 
Finding Data: {json.dumps(ctx)}

TASK: Write a professional Bug Bounty Report.

STRICT REPUTATION RULES:
1. UA SYNC: Vulnerability Details MUST show 'User-Agent: {ctx['real_ua']}'.
2. SNIPER POC: The 'reproduction_url' MUST be EXACTLY '{ctx['matched_url']}'. Do not change anything.
3. BLIND BUGS: If 'interaction_evidence' is not 'NONE', prioritize it as the main proof of SSRF/XSS.
4. VALIDATION: If 'response_evidence' does not show the payload or error, output ONLY: {{"title": "Inconclusive", "status": "skip"}}
5. QUALITY: Use clear Markdown with technical impact analysis.

Template:
.# {{title}}

.## 📊 Vulnerability Details
- **Severity:** {{severity}}
- **Affected Asset:** `{{url}}`
- **Scanner IP:** {ctx['ip']}
- **User-Agent:** {ctx['real_ua']}

.## 📝 Executive Summary
{{summary}}

.## 🚀 Steps To Reproduce (PoC)
1. Navigate to {{url}}
2. Verify the payload behavior.
3. Reproduction Link: {{url}}

.## 🛡️ Proof of Concept (Evidence)
.### HTTP Request:
.```http
{ctx['request_evidence']}
.```
.### HTTP Response/Proof:
.```http
{ctx['response_evidence'] if ctx['interaction_evidence'] == 'NONE' else ctx['interaction_evidence']}
.```

.## ⚠️ Impact Analysis
- **Technical Impact:** {{tech}}
- **Business Impact:** {{biz}}

.## ✅ Remediation
{{plan}}
"""

        try:
            time.sleep(3) # Anti-429 for Groq
            res = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {AI_KEY}"},
                json={"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
            )
            
            if res.status_code != 200: continue
            ai_out = res.json()['choices'][0]['message']['content'].strip()
            
            if "Inconclusive" in ai_out:
                print(f"[!] Evidence inconclusive for {ctx['matched_url']}. Skipping...")
                continue

            match = re.search(r'\[.*\]|\{.*\}', ai_out, re.DOTALL)
            if match:
                rep = json.loads(match.group(0), strict=False)
                if isinstance(rep, list): rep = rep[0]

                url_hash = hashlib.md5(ctx['matched_url'].encode()).hexdigest()
                d_id = create_h1_draft(rep['title'], url_hash)
                if d_id == "ALREADY_REPORTED": continue
                
                folder = "high" if any(x in ctx['severity'] for x in ["CRIT", "HIGH"]) else "low"
                safe_title = re.sub(r'\W+', '_', rep['title'])[:50]
                report_path = f"data/{PROGRAM_NAME}/alerts/{folder}/{safe_title}.md"
                
                os.makedirs(os.path.dirname(report_path), exist_ok=True)
                with open(report_path, 'w') as f:
                    f.write(f"# {rep['title']} in {PROGRAM_NAME}\n\n🆔 **Draft ID:** `{d_id}`\n\n")
                    # Clean custom dots for markdown
                    f.write(rep['full_markdown'].replace(".#", "#").replace(".##", "##").replace(".```", "```"))
                
                print(f"[+] Report Created: {rep['title']}")
                processed_count += 1

        except Exception as e: print(f"Error Triaging: {e}")

if __name__ == "__main__":
    validate_findings()
