import os
import json
import google.generativeai as genai

# Ambil nama program dan API Key
program_name = os.environ.get("PROGRAM_NAME", "Unknown")
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

def validate_findings():
    results_path = f'data/{program_name}/nuclei_results.json'
    
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 15: # Ambil 15 temuan pertama untuk dianalisa AI
                findings.append(json.loads(line))

    prompt = f"""
    You are a professional Bug Bounty Triage Specialist.
    Analyze these Nuclei findings for the program: {program_name}
    
    Findings Data:
    {json.dumps(findings)}

    Tugas:
    1. Filter out False Positives.
    2. Categorize valid bugs into TWO groups:
       - HIGH: Only for P1 and P2 (Critical/High severity).
       - LOW: For P3 and P4 (Medium/Low severity).
    
    Format the output exactly like this:
    ===HIGH===
    (Report for P1/P2 in English. Mention Vuln Name, URL, and Impact. If none, write: No High findings)
    ===LOW===
    (Report for P3/P4 in English. Mention Vuln Name, URL, and Impact. If none, write: No Low findings)
    """

    try:
        response = model.generate_content(prompt).text
        
        high_content = ""
        low_content = ""

        if "===HIGH===" in response and "===LOW===" in response:
            parts = response.split("===LOW===")
            high_content = parts[0].replace("===HIGH===", "").strip()
            low_content = parts[1].strip()

            # Simpan file High jika valid
            if high_content and "No High findings" not in high_content:
                with open(f'data/{program_name}/high_findings.txt', 'w') as f:
                    f.write(high_content)

            # Simpan file Low jika valid
            if low_content and "No Low findings" not in low_content:
                with open(f'data/{program_name}/low_findings.txt', 'w') as f:
                    f.write(low_content)
    except Exception as e:
        print(f"AI Error: {e}")

if __name__ == "__main__":
    validate_findings()
