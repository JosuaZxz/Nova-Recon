import os
import json
import requests
import subprocess
import re
from datetime import datetime

# --- KONFIGURASI ---
AI_KEY = os.environ.get("GROQ_API_KEY")
H1_USER = os.environ.get("H1_USERNAME")
H1_API_KEY = os.environ.get("H1_API_KEY")
PROGRAM_NAME = os.environ.get("PROGRAM_NAME", "Unknown")

def get_verification_context(data):
    """Ambil bukti teknis + Waktu Testing"""
    host = data.get("host", "")
    domain = host.replace("https://", "").replace("http://", "").split(":")[0]
    
    # Kita ambil waktu sekarang untuk 'Testing Period'
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    context = {
        "ip": data.get("ip", "Unknown IP"),
        "status": data.get("info", {}).get("status-code", "Unknown"),
        "time": current_time,
        "template": data.get("template-id", "Unknown")
    }
    
    if "takeover" in data.get("template-id", "").lower():
        try:
            cname = subprocess.check_output(['dig', 'CNAME', '+short', domain], timeout=5).decode('utf-8').strip()
            context["cname"] = cname if cname else "No CNAME"
        except: context["cname"] = "DNS Error"
    return context

def create_h1_draft(title, description, impact, severity):
    if PROGRAM_NAME == "00_test": return "TEST-ID-123"

    url = "https://api.hackerone.com/v1/hackers/report_intents"
    auth = (H1_USER, H1_API_KEY)
    
    # Mapping severity untuk API HackerOne
    h1_sev = "low"
    if severity.lower() in ["critical", "high"]: h1_sev = "high"
    elif severity.lower() == "medium": h1_sev = "medium"
    
    payload = {"data": {"type": "report-intent", "attributes": {"team_handle": PROGRAM_NAME, "title": title, "description": description, "impact": impact, "severity_rating": h1_sev}}}
    
    try:
        res = requests.post(url, auth=auth, headers={"Accept": "application/json"}, json=payload)
        return res.json()['data']['id'] if res.status_code == 201 else None
    except: return None

def validate_findings():
    # BYPASS MODE TEST
    if PROGRAM_NAME == "00_test":
        with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f:
            f.write("🚨 **TEST SUCCESS (TEMPLATE V2)**\nID: `DRAFT-PRO-123`")
        return

    path = f'data/{PROGRAM_NAME}/nuclei_results.json'
    if not os.path.exists(path) or os.stat(path).st_size == 0: return

    findings = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if i < 20: 
                d = json.loads(line)
                d["context"] = get_verification_context(d)
                findings.append(d)

    # --- TEMPLATE LAPORAN PRO (PAYPAL STYLE) ---
    report_template = """
## Vulnerability Details
**Title:** {{Suggested Title}}
**Severity:** {{Severity}}
**Category:** {{Vulnerability Type}}
**Affected Asset:** {{Vulnerable URL}}

## Summary
{{Brief summary of the vulnerability}}

## Technical Details
{{Detailed technical explanation, showing how the bug works based on the Nuclei match}}

## Steps To Reproduce
1. Open a terminal or browser.
2. Access the following URL: {{Vulnerable URL}}
3. Observe the response: {{Evidence from data}}
4. {{Step 4 if needed}}

## Proof of Concept
The vulnerability was detected using an automated scanner (Nuclei) with template: {{Template ID}}.
The server responded with status code: {{Status Code}}.

## Remediation
**Recommendation:** {{Specific fix instructions}}
**Fix References:** {{Links to documentation if any}}

## Discovery Process
Automated discovery using ProjectDiscovery Nuclei during authorized security testing.

## Testing Environment
- **IP Address(es):** {{Target IP Address}}
- **User Agent:** Mozilla/5.0 (Automated Scanner)
- **Testing Timezone:** UTC
- **Testing Period:** {{Scan Time}}
    """

    # --- PROMPT AI ---
    prompt = f"""
    ROLE: Senior Triage. PROGRAM: {PROGRAM_NAME}. DATA: {json.dumps(findings)}

    TASK:
    1. Filter out false positives.
    2. TREAT EACH VALID URL AS A SEPARATE REPORT (Do NOT consolidate).
    3. If 3 valid bugs found, output JSON List with 3 objects.
    
    FORMATTING INSTRUCTIONS:
    For the 'description' field in the JSON, you MUST use the provided markdown template exactly.
    Fill in the placeholders ({{...}}) with real data from the scan.
    
    TEMPLATE TO USE:
    {report_template}

    OUTPUT FORMAT: Return ONLY a raw JSON ARRAY:
    [
      {{"title": "...", "description": "MARKDOWN_STRING_HERE", "impact": "...", "severity": "..."}},
      ...
    ]
    If no valid bug: NO_VALID_BUG
    """

    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {AI_KEY}", "Content-Type": "application/json"}
        data = {"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        
        res = requests.post(url, headers=headers, json=data)
        ai_out = res.json()['choices'][0]['message']['content'].strip()

        if "NO_VALID_BUG" in ai_out: return

        # Bersihkan JSON Array
        clean_json = ai_out.replace('```json', '').replace('```', '').strip()
        if clean_json.startswith("{"): clean_json = "[" + clean_json + "]"
        
        reports = json.loads(clean_json, strict=False)
        
        final_msg_high = ""
        final_msg_low = ""
        
        for rep in reports:
            d_id = create_h1_draft(rep['title'], rep['description'], rep['impact'], rep['severity'])
            if d_id:
                sev = rep['severity'].upper()
                emoji = "🚨" if sev in ["CRITICAL", "HIGH"] else "⚠️"
                msg_line = f"{emoji} **{sev} BUG:** `{d_id}` | {rep['title']}\n"
                
                if sev in ["CRITICAL", "HIGH"]: final_msg_high += msg_line
                else: final_msg_low += msg_line

        if final_msg_high:
            with open(f'data/{PROGRAM_NAME}/high_findings.txt', 'w') as f: f.write(f"🎯 **{PROGRAM_NAME.upper()} HITS:**\n\n{final_msg_high}")
        
        if final_msg_low:
            with open(f'data/{PROGRAM_NAME}/low_findings.txt', 'w') as f: f.write(f"🎯 **{PROGRAM_NAME.upper()} LOW HITS:**\n\n{final_msg_low}")

    except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    validate_findings()
