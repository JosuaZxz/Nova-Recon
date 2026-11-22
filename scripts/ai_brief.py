"""Optional Groq AI triage summarizer for NOVA daily manual-audit briefings."""

from __future__ import annotations

import json
import os
import requests


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"


def _compact_finding(item: dict) -> dict:
    """Keep only high-signal fields within a compact token budget."""
    return {
        "program": item.get("program", ""),
        "type": item.get("type", ""),
        "severity": item.get("severity_hint", ""),
        "url": item.get("url", ""),
        "evidence": (item.get("evidence", "") or "")[:280],
        "added_routes": item.get("added_routes", [])[:10],
        "added_ops": item.get("added_ops", [])[:8],
    }


def summarize_findings(findings: list[dict]) -> str | None:
    """Generate a prioritized manual-review summary via Groq, or None if unavailable."""
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key or not findings:
        return None

    actionable = [f for f in findings if f.get("type") != "dangling-cname"]
    if not actionable:
        return None

    model = os.environ.get("NOVA_AI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    compact = [_compact_finding(f) for f in actionable[:20]]

    prompt = (
        "Kamu adalah asisten triage keamanan defensif & bug bounty (manual review).\n"
        "Tugasmu HANYA merangkum daftar lead hasil recon/diff berikut untuk membantu researcher manusia memilih mana yang layak dicek manual hari ini.\n"
        "ATURAN KETAT:\n"
        "1. Jangan membuat payload eksploitasi atau skrip serangan.\n"
        "2. Jangan mengarang temuan di luar JSON input.\n"
        "3. Pilih maksimal 5 lead paling berpotensi (utamakan js-secret terverifikasi, takeover claimable, exposure nyata, host-change 403/404->200, dan js-diff dengan route admin/internal/auth/billing/graphql baru).\n"
        "4. Untuk setiap lead prioritas, tulis ringkas dalam Bahasa Indonesia: URL/program, kenapa menarik, dan langkah verifikasi manual aman (cek policy scope + uji kontrol akses/IDOR dengan akun uji sendiri di browser/proxy).\n"
        "5. Jika ada yang kelihatan seperti noise/false positive, tandai singkat agar tidak buang waktu.\n\n"
        f"DATA LEADS:\n{json.dumps(compact, ensure_ascii=False)}"
    )

    try:
        resp = requests.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.15,
                "max_tokens": 900,
            },
            timeout=35,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()
        return content or None
    except Exception:
        return None
