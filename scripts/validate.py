import os
import json
import google.generativeai as genai

program_name = os.environ.get("PROGRAM_NAME", "Unknown Program")
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

def validate_findings():
    results_path = f'data/{program_name}/nuclei_results.json'
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        for i, line in enumerate(f):
            if i < 15: findings.append(json.loads(line))

    # PROMPT: Minta AI memisahkan dengan delimiter khusus
    prompt = f"""
    Analyze these Nuclei findings for {program_name}:
    {json.dumps(findings)}

    Instructions:
    1. Categorize into two groups: 
       - HIGH: P1 and P2 (Critical/High)
       - LOW: P3 and P4 (Medium/Low/Info)
    2. Format the output exactly like this:
    ===HIGH===
    (Your report for P1/P2 here)
    ===LOW===
    (Your report for P3/P4 here)
    """

    try:
        response = model.generate_content(prompt).text
        
        # Pisahkan output berdasarkan delimiter
        high_part = ""
        low_part = ""
        
        if "===HIGH===" in response and "===LOW===" in response:
            parts = response.split("===LOW===")
            high_part = parts[0].replace("===HIGH===", "").strip()
            low_part = parts[1].strip()
        
        # Simpan ke file terpisah jika ada isinya
        if high_part and "No significant" not in high_part:
            with open(f'data/{program_name}/high_findings.txt', 'w') as f:
                f.write(high_part)
        
        if low_part and "No significant" not in low_part:
            with open(f'data/{program_name}/low_findings.txt', 'w') as f:
                f.write(low_part)
                
    except Exception as e:
        print(f"Error AI: {e}")

if __name__ == "__main__":
    validate_findings()
