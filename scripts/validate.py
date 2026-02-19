import os
import json
import google.generativeai as genai

# Ambil nama program dari environment variable
program_name = os.environ.get("PROGRAM_NAME", "Unknown Program")
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-1.5-flash')

def validate_findings():
    results_path = f'data/{program_name}/nuclei_results.json'
    
    if not os.path.exists(results_path) or os.stat(results_path).st_size == 0:
        return

    findings = []
    with open(results_path, 'r') as f:
        # Kita ambil 10 temuan teratas agar tidak melebihi limit token AI
        for i, line in enumerate(f):
            if i < 15: 
                findings.append(json.loads(line))

    # PROMPT DALAM BAHASA INGGRIS
    prompt = f"""
    Role: Senior Cyber Security Researcher and Triage Specialist.
    Program: {program_name}
    
    Task: Analyze the following Nuclei scan output data:
    {json.dumps(findings)}

    Instructions:
    1. Filter out False Positives and low-impact noise (e.g., generic info headers).
    2. For valid vulnerabilities, generate a PROFESSIONAL BUG BOUNTY REPORT in ENGLISH.
    3. Format the output for each finding as follows:
       
       ### [PROGRAM]: {program_name}
       - **Vulnerability**: [Vulnerability Name]
       - **Severity**: [P1/P2/P3/P4]
       - **Endpoint**: [Target URL]
       - **Description**: [Provide a clear and concise technical description of the bug]
       - **Impact**: [Explain the potential business or security impact]
       - **Remediation**: [Provide a brief fix recommendation]

    Ensure the tone is technical and professional. If no critical vulnerabilities are found, just say "No significant findings."
    """

    try:
        response = model.generate_content(prompt)
        output_file = f'data/{program_name}/ai_findings.txt'
        with open(output_file, 'w') as f:
            f.write(response.text)
    except Exception as e:
        print(f"Error AI on {program_name}: {e}")

if __name__ == "__main__":
    validate_findings()
