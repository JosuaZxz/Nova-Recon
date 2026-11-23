# NOVA v2.2 - Intelligent Recon, AI Validation Gate & Report Generator

Mesin recon & pemantau perubahan aset untuk bug bounty berbasis **delta subdomain + smart redirect follower + JS bundle diffing + AI Validation Gate**.

## Alur Otomatis NOVA v2.2
1. **Monitor & Lossless Queue (`state/<program>.queue.txt`):** Mencari subdomain baru dari CT logs (`crt.sh`, `subdomain.center`, `otx`, `subfinder`), menyaring dengan `scope_guard.py` (termasuk aturan `!exclude`), dan menyimpan antrean probe agar tidak ada subdomain yang terlewat batas 250 per run.
2. **Smart Same-Host Redirect Follower (`probe_host`):** Mengikuti redirect `301/302/303/307/308` pada host yang sama hingga 3 hop (selama bukan halaman login) supaya halaman HTML utama serta bundle `<script src>` dan `<link rel="modulepreload" href="...js">` tetap tertangkap.
3. **Double-Tap & Dual-DoH Verification (`verify` & `diff`):**
   - **Double-Tap Canary Check:** Memastikan temuan `/.env`, `/.git`, `/actuator`, `/debug/vars`, `/server-status` bukan halaman catch-all dengan menguji path canary acak di direktori yang sama.
   - **Dual-Resolver DoH Takeover Check:** Memverifikasi CNAME *claimable* di dua resolver independen (Cloudflare `1.1.1.1` & Google `8.8.8.8`) dan otomatis membuang `dangling-cname` level `info` (CloudFront/ELB non-claimable).
   - **High-Entropy JS Secret & JS Route Diffing:** Menyaring token ber-entropi rendah/dummy serta library vendor, dan mendeteksi penambahan route API / operasi GraphQL baru saat bundle JS berubah.
4. **AI Validation Gate & Laporan Siap Kirim (`ai_brief.py`):**
   - Setiap kandidat divalidasi berdasarkan bukti HTTP Request/Response atau rantai DNS menggunakan `GROQ_API_KEY` (`validate_and_draft_report`).
   - Kandidat **False Positive** langsung dibuang dan tidak dikirim ke Telegram.
   - Kandidat **VALID** langsung dibuatkan dokumen laporan lengkap `REPORT-<program>-<type>-<hash>.md` (Title, Severity, Summary, Technical Analysis, Steps to Reproduce, Proof of Concept / Evidence, Impact, Remediation) dan dikirim sebagai lampiran dokumen ke Telegram.

## Menjalankan Unit Tests
```bash
python -m unittest discover -s tests -v
```
