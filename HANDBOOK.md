# NOVA v2 — HANDBOOK Serah Terima

> Mesin bug bounty berbasis **deteksi aset baru**, bukan scan acak.
> Dibangun ulang 2026-11-07 setelah 4 bulan pipeline lama menghasilkan **nol temuan** (2.900+ run, semua `nuclei_*.json` 0 byte).

---

## 1. Kenapa mesin lama gagal (jangan diulang)

| Masalah lama | Akibat |
|---|---|
| `targets/adobe.txt` isinya subdomain (`lightroom.adobe.com`), bukan root | subfinder, alterx, dan scope filter bekerja pada ruang aset yang salah |
| 40 program = raksasa tier-1 (PayPal, Netflix, TikTok, Coinbase, X) | di-scan 24/7 oleh ribuan hunter + semua bot; nuclei template publik = peluang nol |
| Rotasi acak 2.000 subdomain/jam, tanpa memori | tidak ada deteksi perubahan; aset baru (misconfig deploy) lolos tak terpantau |
| Nuclei massal + AI triage report | menghasilkan noise, bukan laporan valid; bulan-bulan 0 byte |

**Prinsip v2:** emas ada di **aset yang BARU muncul** (subdomain dev/staging baru, API baru, panel baru). Deploy baru sering salah konfigurasi — itu jendela waktu kita. Mesin v2 memantau CT logs (crt.sh) tiap jam, mencatat semua aset ke `state/`, dan **hanya memproses yang baru**.

## 2. Arsitektur v2 (1 file + 1 workflow)

```
scripts/nova.py          # seluruh mesin (Python + requests saja)
.github/workflows/nova.yml  # jalan tiap jam di GitHub Actions (gratis, repo public)
targets/<program>.txt    # root domain, SATU root per baris
state/<program>.subs.txt # memori aset (di-commit, inilah "ingatan" mesin)
findings/<tanggal>/      # lead terverifikasi (TIDAK di-commit, dikirim ke Telegram)
SCOPE_TODO.md            # root yang WAJIB kamu verifikasi ke halaman policy program
```

Subcommands `nova.py`:
- `scope`   — normalisasi & audit `targets/*.txt` (jalan sekali, sudah dijalankan)
- `monitor` — discovery pasif (crt.sh + subdomain.center + OTX + subfinder) + diff vs state
- `probe`   — probe hanya host baru (polite: rate limit, cap per-host, prioritas dev/stg/api/admin)
- `verify`  — verifikasi: `.env`/`.git`/actuator (butuh secret nyata di body), dangling CNAME takeover, CORS refleksi+credentials, GraphQL introspection, secret di file JS
- `brief`   — briefing harian + Telegram (hanya terkirim jika ADA lead — anti-spam)
- `run`     — semua di atas sekaligus

## 3. Cara pakai harian (10–15 menit saja)

1. Telegram-mu menerima **briefing hanya saat ada lead terverifikasi**.
2. Buka lead → verifikasi manual di browser incognito (selalu, tanpa kecuali).
3. Screenshot bukti → tulis report → submit ke platform program.
4. Tandai lead sudah diproses (hapus file JSON-nya atau pindah ke `findings/done/`).

Jalankan manual kapan saja:
```bash
python scripts/nova.py run --programs boozt,bykea --send-telegram   # lokal
# atau di GitHub: Actions → NOVA v2 → Run workflow → isi nama program
```

## 4. Yang WAJIB kamu lakukan minggu ini

1. **Buka `SCOPE_TODO.md`** — verifikasi tiap root ke halaman policy programnya (10 menit). Kalau root tidak in-scope, hapus barisnya dari `targets/<program>.txt`. Mesin hanya mengikuti daftar ini.
2. **Kurangi raksasa, tambah program menengah.** Adobe/PayPal/Netflix boleh dipertahankan untuk *asset monitoring* pasif (aset baru tetap muncul), tapi peluang realistis ada di program menengah: scope lebar, kompetitor lebih sedikit, respon triage cepat. Tambahkan program yang KAMU DAFTARKAN — cukup buat `targets/<nama>.txt` berisi root domainnya.
3. **Cek Actions secrets** masih ada: `TELEGRAM_TOKEN`, `TELEGRAM_GENERAL_ID`, `TELEGRAM_DATA_ID`. (Workflow lama memakai `GROQ_API_KEY`, `H1_USERNAME`, `H1_API_KEY` — masih tersimpan, dipakai bila fitur auto-draft diaktifkan lagi.)

## 5. Kejujuran tentang ekspektasi

- Mesin ini **meningkatkan peluang**, bukan menjamin bounty. Tidak ada mesin yang bisa.
- Yang berubah vs 4 bulan lalu: dulu kamu scanning acak tanpa ingatan di target paling keras di dunia. Sekarang: aset baru terdeteksi dalam hitungan jam, tiap lead **sudah terverifikasi otomatis** sebelum sampai ke kamu, dan kamu hanya mengerjakan bagian yang tidak bisa diotomasi: verifikasi final + report berkualitas.
- Kualitas report menentukan penerimaan. Jangan pernah submit tanpa bukti sendiri.
- Target yang masih di daftar tapi di luar program yang kamu ikuti = hapus. Testing di luar program = risiko banned + ilegal.

## 6. Aturan kepatuhan yang sudah tertanam di kode

- Strict scope filter: setiap URL dicocokkan ke `targets/<program>.txt` sebelum disentuh.
- Tidak ada scanning IP mentah (fitur "origin IP" mesin lama dihapus).
- Rate limit global + cap per-host; hanya aset BARU yang di-probe.
- Briefing hanya file lokal + Telegram privat; **tidak ada temuan yang di-commit ke repo public** (hindari kebocoran ke hunter lain).

## 7. Troubleshooting

| Gejala | Solusi |
|---|---|
| crt.sh 502 | normal, otomatis retry 4x + fallback 2 sumber lain |
| WAF block semua probe (mis. bykea) | normal dari IP runner; mesin tetap catat aset, coba verifikasi manual dari browser |
| Briefing tak masuk Telegram | cek secrets `TELEGRAM_TOKEN` & `TELEGRAM_GENERAL_ID`; ingat: hanya terkirim saat ada lead |
| Push tabrakan di commit state | sudah ada retry 5x; kalau gagal terus, jalankan ulang workflow |
| crt.sh lambat di domain raksasa | timeout 45s per source; subfinder menutupi sisanya |

## 8. Angka pembanding (uji 2026-11-07)

- bykea.net: **222 subdomain dalam 16 detik** pasif (pipeline lama: 10 menit subfinder untuk hasil serupa/kurang)
- Uji probe 30 host prioritas: 4 live (WAF bykea memblok sisanya — sesuai desain, tetap tercatat)
- State diff: run kedua → BARU 0 (tidak ada kerja ulang, tidak ada biaya boros)
