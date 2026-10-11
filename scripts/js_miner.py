import os
import sys
import re
import json
import urllib.request
import urllib.error
import concurrent.futures
from urllib.parse import urlparse, urljoin

# Ensure UTF-8 output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# High-Confidence Secret Signatures
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'(AKIA[0-9A-Z]{16})'),
    "Slack Token": re.compile(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})'),
    "Slack Webhook": re.compile(r'(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)'),
    "Stripe Secret Key": re.compile(r'([rs]k_live_[0-9a-zA-Z]{24})'),
    "GitHub Personal Token": re.compile(r'(gh[pous]_[a-zA-Z0-9]{36,255})'),
    "SendGrid API Key": re.compile(r'(SG\.[a-zA-Z0-9_\-\.]{66})'),
    "Google Private Key": re.compile(r'("type":\s*"service_account"[\s\S]{1,200}?"private_key":)'),
    "RSA/EC Private Key": re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'),
}

# Sensitive Route Extraction Patterns
ENDPOINT_REGEX = re.compile(r'[\'\"`]((?:/api/|/v[1-9]/|/internal/|/admin/|/management/|/private/|/debug/|/actuator/)[a-zA-Z0-9_\-\./]{2,60})[\'\"`]')

# Noise routes to ignore
IGNORE_ROUTES = [
    "/api/v1/widget", "/api/v2/widget", "/api/v1/analytics", "/api/v1/events",
    "/api/v1/track", "/api/v1/metrics", "/api/v1/telemetry", "/api/v1/ping",
    "/api/v1/health", "/api/v1/status", "/api/v1/locales", "/api/v1/translations"
]

def fetch_url(url, timeout=8):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                content = resp.read().decode('utf-8', errors='ignore')
                return content
    except Exception:
        pass
    return None

def analyze_js_file(js_url):
    findings = []
    content = fetch_url(js_url)
    if not content or len(content) < 50:
        return findings, []

    # 1. Search Secrets
    for secret_name, pattern in SECRET_PATTERNS.items():
        match = pattern.search(content)
        if match:
            found_token = match.group(1)[:100]
            # Context snippet around the secret
            start = max(0, match.start() - 60)
            end = min(len(content), match.end() + 60)
            snippet = content[start:end].replace("\n", " ").strip()
            
            nuclei_item = {
                "template-id": "ghost-js-secret-leak",
                "info": {
                    "name": f"Exposed {secret_name} in JavaScript",
                    "severity": "critical" if "Key" in secret_name or "Token" in secret_name else "high",
                    "tags": ["exposure", "token", "credentials", "javascript"]
                },
                "matcher-name": secret_name,
                "matched-at": js_url,
                "extracted-results": [found_token],
                "request": f"GET {urlparse(js_url).path} HTTP/1.1\nHost: {urlparse(js_url).netloc}\n\n",
                "response": f"HTTP/1.1 200 OK\nContent-Type: application/javascript\n\n... {snippet} ..."
            }
            findings.append(nuclei_item)

    # 2. Extract Interesting Endpoints
    extracted_routes = set()
    raw_matches = ENDPOINT_REGEX.findall(content)
    for route in raw_matches:
        route = route.strip()
        if not any(ign in route.lower() for ign in IGNORE_ROUTES):
            extracted_routes.add(route)

    return findings, list(extracted_routes)

def probe_route(base_url, route):
    target = urljoin(base_url, route)
    req = urllib.request.Request(
        target,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read(4096).decode('utf-8', errors='ignore')
            
            # Check for high-impact unauthenticated responses (JSON with data, users, admin)
            if status == 200 and ("application/json" in content_type or raw.strip().startswith("{") or raw.strip().startswith("[")):
                # Must not be a generic error or empty json
                if len(raw.strip()) > 30 and not any(err in raw.lower() for err in ["not found", "unauthorized", "login required", "\"error\":"]):
                    if any(kw in raw.lower() for kw in ["\"data\":", "\"user\":", "\"users\":", "\"config\":", "\"admin\":", "\"items\":", "\"token\":", "\"secret\":"]):
                        return {
                            "template-id": "ghost-unauth-internal-api",
                            "info": {
                                "name": "Unauthenticated Sensitive Internal API Access",
                                "severity": "high",
                                "tags": ["api", "unauth", "idor", "information-disclosure"]
                            },
                            "matcher-name": "Sensitive JSON Endpoint",
                            "matched-at": target,
                            "request": f"GET {route} HTTP/1.1\nHost: {urlparse(target).netloc}\n\n",
                            "response": f"HTTP/1.1 200 OK\nContent-Type: {content_type}\n\n{raw[:1500]}"
                        }
    except Exception:
        pass
    return None

def run_miner(js_urls_file, output_dir):
    if not os.path.exists(js_urls_file):
        print(f"[-] JS list file not found: {js_urls_file}")
        return

    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "nuclei_js.json")

    js_urls = []
    with open(js_urls_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u.startswith("http") and u.endswith(".js"):
                js_urls.append(u)

    # De-duplicate and take top 100 most promising JS files
    js_urls = list(set(js_urls))[:100]
    print(f"[*] JS Miner: Inspecting {len(js_urls)} unique JavaScript targets...")

    all_findings = []
    all_routes = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(analyze_js_file, url): url for url in js_urls}
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                findings, routes = future.result()
                if findings:
                    all_findings.extend(findings)
                base = future_to_url[future]
                for r in routes:
                    all_routes.add((base, r))
            except Exception:
                pass

    print(f"[+] JS Miner: Found {len(all_findings)} hardcoded secret leads, extracted {len(all_routes)} internal API routes.")

    # Probe up to 40 unique extracted internal API routes
    if all_routes:
        print("[*] Probing extracted internal routes for unauthenticated data leakage...")
        sample_routes = list(all_routes)[:40]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(probe_route, base, r) for base, r in sample_routes]
            for f in concurrent.futures.as_completed(futures):
                try:
                    res = f.result()
                    if res:
                        all_findings.append(res)
                        print(f"[🔥] DISCOVERY: Unauthenticated endpoint exposure: {res['matched-at']}")
                except Exception:
                    pass

    # Save to nuclei_js.json
    if all_findings:
        with open(out_file, "a", encoding="utf-8") as f:
            for item in all_findings:
                f.write(json.dumps(item) + "\n")
        print(f"[✅] JS Miner successfully logged {len(all_findings)} actionable items to {out_file}")
    else:
        print("[-] JS Miner: No exposed secrets or unauthenticated routes detected.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python js_miner.py <js_urls_file> <output_dir>")
        sys.exit(1)
    run_miner(sys.argv[1], sys.argv[2])
