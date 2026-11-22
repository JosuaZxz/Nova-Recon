# NOVA v2.1 - Continuous Asset & JS Change Monitor

Mesin recon & pemantau perubahan aset untuk bug bounty berbasis **delta subdomain + JS bundle diffing + scope guard**.

## Apa yang Diperbaiki & Di-upgrade di v2.1
1. **Lossless Probe Queue (`state/<program>.queue.txt`):** Subdomain baru di atas batas `NOVA_MAX_NEW_PROBE` (default 250) tidak lagi hilang dianggap "sudah known", melainkan tetap mengantre untuk run berikutnya.
2. **Scope & Exclusion Guard (`scripts/scope_guard.py`):** Mendukung wildcard dan aturan pengecualian (`!host.example.com`, `!*.dev.example.com`, `!regex:...`) di `targets/<program>.txt`. Perintah `nova.py scope` tidak lagi memaksa subdomain menjadi apex root domain.
3. **Host & JS Bundle Change Diffing (`scripts/js_intel.py` + `nova.py diff`):**
   - Memantau perubahan status HTTP host lama (mis. `403/404 -> 200` atau redirect login hilang).
   - Menormalisasi nama bundle JS ber-hash (`main.a1b2c3.js` -> `main.HASH.js`) sehingga saat developer rilis update, mesin mendeteksi **hanya route API / operasi GraphQL baru** yang ditambahkan dan mengecek `.js.map` yang terbuka.
   - Menyaring false positive library JS pihak ketiga (`jquery`, `jsrsasign`, `validator.min`, placeholder/test key).
4. **AI Triage & Panduan Cek Manual (`scripts/ai_brief.py`):** Jika `GROQ_API_KEY` diset, merangkum lead dan diff teratas ke briefing harian Telegram untuk mempercepat audit manual (tanpa auto-exploit).
5. **Mode Fokus (`targets/_focus.txt`):** Hapus tanda `#` pada nama program pilihanmu di `targets/_focus.txt` agar run tiap jam fokus pada target yang benar-benar kamu ikuti.

## Cara Pakai Lokal
```bash
pip install requests
python scripts/nova.py scope
python scripts/nova.py run --programs boozt,bykea --no-ai
```

## Menjalankan Unit Tests
```bash
python -m unittest discover -s tests -v
```
