# Nova-Recon v2 — First-Strike Asset Monitor

Mesin bug bounty otomatis berbasis **deteksi aset baru** (Certificate Transparency logs + sumber pasif), bukan scan acak.

- Mesin: `scripts/nova.py` (Python + requests)
- Otomasi 24/7: `.github/workflows/nova.yml` (GitHub Actions, tiap jam)
- Panduan lengkap & kepatuhan scope: **[HANDBOOK.md](HANDBOOK.md)**

Alur: `monitor` (aset baru via crt.sh/subfinder) → `probe` (hanya host baru, sopan) → `verify` (exposed secrets / takeover / CORS / GraphQL, semua diverifikasi otomatis) → `brief` (Telegram, hanya saat ada lead).

> ⚠️ Hanya untuk target yang terdaftar di program bug bounty resmi dengan izin. Scope ditentukan `targets/<program>.txt`.
