<h1>🎯 NovaRecon: Powerfull Recon Edition (2026)</h1>

**NovaRecon** is an autonomous, high-speed Bug Bounty reconnaissance and vulnerability scanning engine powered by **GitHub Actions** and **Llama 3.3 70B AI**. Designed for the modern bug hunter, it operates in "Sniper Mode"—randomly selecting and neutralizing targets from your list every 10 minutes, 24/7.

**Current Build**: v2.0 (Powerfull Edition)
**User-Agent**: NovaRecon/2026

<h2>🚀 Key Features</h2>

* **⚡ 24/7 Autonomous Sniper**: Runs on GitHub Actions with a 10-minute cron interval. Zero infrastructure cost, maximum uptime.
* **🛡️ Double-Power Discovery**: Concurrent subdomain gathering using `Subfinder` (all sources) and `Assetfinder`.
* **🔍 Advanced URL Mining**: Deep historical URL extraction via `Waybackurls` and `GAU` to uncover hidden endpoints and sensitive parameters.
* **🔫 Ranked Severity Scanning**: Nuclei engine optimized for "Gold Hunting"—prioritizing **Critical, High, and Medium** vulnerabilities first.
* **🏎️ Ultra-Fast Performance**: Running at **200 RPS** (Requests Per Second) with optimized concurrency to beat other hunters to the report.
* **🧠 AI Triage Lead (Llama 3.3)**: Every finding is analyzed by AI. It validates technical evidence (Raw Request/Response) and writes professional reports.
* **📝 Automated HackerOne Drafting**: Directly creates report intents on HackerOne with full standard templates (Summary, Impact, Steps to Reproduce, Remediation).
* **📟 Stealth Memory (Anti-Spam)**: Uses **MD5 Hashing** for `.seen_urls` database to ensure you never report the same bug twice.
* **📲 Modular Telegram Alerts**: Smart notifications split into dedicated channels: `Critical (P1-P2)`, `General (P3-P4)`, and `Database Backups`.

<h2>🏗️ Architecture & Workflow</h2>

1. **Selection**: Randomly picks a target file from the `targets/` directory.
2. **Reconnaissance**: Horizontal & Vertical subdomain enumeration + `httpx` live host filtering.
3. **Mining**: Historical URL gathering to find exposed tokens, API keys, and secret endpoints.
4. **Phase 1 (The Killshot)**: Immediate scan for high-impact vulnerabilities (RCE, SQLi, LFI, SSRF).
5. **Phase 2 (The Sweep)**: Secondary scan for lower-severity bugs and information disclosure.
6. **AI Analysis**: The `validate.py` script sends technical data to Groq AI for professional triage.
7. **Fulfillment**: Creates HackerOne drafts and pings Telegram with the full report.

<h2>🛠️ Installation & Setup</h2>

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
```bash
airbnb.com
airbnb.co.uk
```
**4. Deploy**

The machine will start automatically based on the cron schedule. <br>
To test immediately, go to **Actions > Automation Recon > Run Workflow**.

<h2>📂 Repository Structure</h2>

```bash
├── .github/workflows/
│   └── recon.yml       # The Automation Engine (CI/CD)
├── scripts/
│   └── validate.py    # The AI Brain (Triage & Reporting)
├── targets/           # Your Target Lists (.txt)
├── .seen_urls         # Stealth Memory DB (Auto-sync)
└── README.md          # Documentation
```

<h1>⚠️ Disclaimer</h1>

``This tool is for educational and authorized security testing purposes only. <br>
Usage of NovaRecon for attacking targets without prior consent is illegal. <br>
The developers assume no liability and are not responsible for any misuse or damage caused by this program.``

**Developed by**: JosuaZxz <br>
**Status**: Operational 🟢 | Powerfull Mode Active
