<h1><b>🎯 NovaRecon: Powerfull Recon Edition (2026)</b></h1>

**NovaRecon** is an autonomous, high-speed Bug Bounty reconnaissance and vulnerability scanning engine powered by **GitHub Actions** and **Llama 3.3 70B AI**. Designed for the modern bug hunter, it operates in "Sniper Mode"—randomly selecting and neutralizing targets from your list every 10 minutes, 24/7.

**Current Build**: v2.0 (Powerfull Edition)
**User-Agent**: NovaRecon/2026

🚀 **Key Features**

* ⚡ **24/7 Autonomous Sniper**: Runs on GitHub Actions with a 10-minute cron interval. Zero infrastructure cost, maximum uptime.
* 🛡️ **Double-Power Discovery**: Concurrent subdomain gathering using `Subfinder` (all sources) and `Assetfinder`.
* 🔍 **Advanced URL Mining**: Deep historical URL extraction via `Waybackurls` and `GAU` to uncover hidden endpoints and sensitive parameters.
* 🔫 **Ranked Severity Scanning**: Nuclei engine optimized for "Gold Hunting"—prioritizing **Critical, High, and Medium** vulnerabilities first.
* 🏎️ **Ultra-Fast Performance**: Running at **200 RPS** (Requests Per Second) with optimized concurrency to beat other hunters to the report.
* 🧠 **AI Triage Lead (Llama 3.3)**: Every finding is analyzed by AI. It validates technical evidence (Raw Request/Response) and writes professional reports.
* 📝 **Automated HackerOne Drafting**: Directly creates report intents on HackerOne with full standard templates (Summary, Impact, Steps to Reproduce, Remediation).
* 📟 **Stealth Memory (Anti-Spam)**: Uses **MD5 Hashing** for `.seen_urls` database to ensure you never report the same bug twice.
* 📲 **Modular Telegram Alerts**: Smart notifications split into dedicated channels: `Critical (P1-P2)`, `General (P3-P4)`, and `Database Backups`.

🏗️ **Architecture & Workflow**

1. **Selection**: Randomly picks a target file from the `targets/` directory.
2. **Reconnaissance**: Horizontal & Vertical subdomain enumeration + `httpx` live host filtering.
3. **Mining**: Historical URL gathering to find exposed tokens, API keys, and secret endpoints.
4. **Phase 1 (The Killshot)**: Immediate scan for high-impact vulnerabilities (RCE, SQLi, LFI, SSRF).
5. **Phase 2 (The Sweep)**: Secondary scan for lower-severity bugs and information disclosure.
6. **AI Analysis**: The `validate.py` script sends technical data to Groq AI for professional triage.
7. **Fulfillment**: Creates HackerOne drafts and pings Telegram with the full report.

🛠️ Installation & Setup

**1. Fork the Repo**
Click the Fork button to create your own instance of the Sniper.

**2. Configure Secrets**
Navigate to `Settings > Secrets and Variables > Actions` and add the following keys:


| Secret Name | Description |
| :--- | :--- |
| `GROQ_API_KEY` | API Key for Llama 3.3 70B (from Groq) |
| `H1_USERNAME` | Your HackerOne Username |
| `H1_API_KEY` | Your HackerOne API Identifier/Token |
| `TELEGRAM_TOKEN` | Your Telegram Bot Token (@BotFather) |
| `TELEGRAM_CRITICAL_ID` | Chat ID for P1-P2 Alerts |
| `TELEGRAM_GENERAL_ID` | Chat ID for P3-P4 Alerts |
| `TELEGRAM_DATA_ID` | Chat ID for Database ZIP storage |

**3. Add Your Targets**
Create `.txt` files in the `targets/` folder.
Example: `airbnb.txt` containing:
'''bash
airbnb.com
airbnb.co.uk
