#!/usr/bin/env python3
"""Sync paid wildcard bug bounty scopes and official exclusions from bounty-targets-data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlparse

import requests

from scope_guard import DOMAIN_RE, WILDCARD_RE, audit_target_file

FEEDS = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
}

# Never allow multi-tenant cloud or hosting suffixes as wildcard includes.
SHARED_HOSTING_SUFFIXES = (
    "amazonaws.com",
    "cloudfront.net",
    "herokuapp.com",
    "herokussl.com",
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "bitbucket.io",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "blob.core.windows.net",
    "firebaseapp.com",
    "firebaseio.com",
    "web.app",
    "appspot.com",
    "googleusercontent.com",
    "run.app",
    "cloudfunctions.net",
    "myshopify.com",
    "shopify.com",
    "zendesk.com",
    "freshdesk.com",
    "atlassian.net",
    "jira.com",
    "salesforce.com",
    "force.com",
    "site.com",
    "wpengine.com",
    "wordpress.com",
    "webflow.io",
    "ghost.io",
    "surge.sh",
    "fly.dev",
    "onrender.com",
    "railway.app",
    "ngrok.io",
)

# Skip saturated tier-1 mega-corporations and strict Zero-Trust defense targets.
OVERSATURATED_HANDLES = {
    "adobe",
    "airbnb",
    "alibaba",
    "amazon",
    "amazonwebservices",
    "anduril_industries",
    "apple",
    "att",
    "binance",
    "bookingcom",
    "bytedance",
    "cisco",
    "cloudflare",
    "coinbase",
    "dell",
    "deptofdefense",
    "discord",
    "dropbox",
    "ebay",
    "epicgames",
    "facebook",
    "fastly",
    "GeneralMotors",
    "github",
    "gitlab",
    "goldmansachs",
    "google",
    "grab",
    "hilton",
    "ibm",
    "indeed",
    "intel",
    "kong",
    "linkedin",
    "marriott",
    "mercadolibre",
    "meta",
    "microsoft",
    "netflix",
    "nintendo",
    "nvidia",
    "openai",
    "oracle",
    "paypal",
    "pinterest",
    "playstation",
    "reddit",
    "riot",
    "robinhood",
    "robinhood_markets",
    "salesforce",
    "samsung",
    "shopify",
    "slack",
    "snapchat",
    "sony",
    "spotify",
    "starbucks",
    "stripchat",
    "stripe",
    "t-mobile",
    "tesla",
    "tiktok",
    "trip_com",
    "twitch",
    "twitter",
    "uber",
    "valve",
    "verily_life_sciences",
    "verizon",
    "visa",
    "walmart",
    "wellsfargo",
    "wellsfargo-bbp",
    "wordpress",
    "x",
    "yahoo",
    "zoom",
}

SLUG_CLEAN_RE = re.compile(r"[^a-z0-9_-]+")
HOST_TOKEN_RE = re.compile(r"(\*\.[a-z0-9][a-z0-9.-]+\.[a-z]{2,63}|[a-z0-9][a-z0-9.-]+\.[a-z]{2,63})", re.IGNORECASE)


def _slugify(raw: str) -> str:
    slug = SLUG_CLEAN_RE.sub("_", raw.lower().strip()).strip("_-")
    return slug[:42]


def _is_shared_suffix(domain: str) -> bool:
    base = domain[2:] if domain.startswith("*.") else domain
    return any(base == sfx or base.endswith("." + sfx) for sfx in SHARED_HOSTING_SUFFIXES)


def _extract_clean_host(raw: str, allow_wildcard: bool = True) -> str | None:
    """Extract a clean domain or `*.domain` wildcard, rejecting placeholders and paths."""
    if not raw or any(ch in raw for ch in ("<", ">", "{", "}", " ", "*.") if ch in ("<", ">", "{", "}")):
        return None
    s = raw.strip().lower()
    s = s.split("(", 1)[0].split(",", 1)[0].strip()
    if "://" in s:
        parsed = urlparse(s)
        host = parsed.netloc
        path = parsed.path.strip("/")
        # If an out-of-scope URL specifies a sub-path (e.g. domain.com/blog), do not exclude the whole host.
        if path and not allow_wildcard:
            return None
    else:
        parts = s.split("/", 1)
        host = parts[0]
        if len(parts) > 1 and parts[1].strip() and not allow_wildcard:
            return None

    host = host.split("@")[-1].split(":")[0].strip(".")
    if host.startswith("http"):
        return None
    if allow_wildcard and WILDCARD_RE.match(host):
        return None if _is_shared_suffix(host) else host
    if DOMAIN_RE.match(host):
        return None if _is_shared_suffix(host) else host
    return None


def _parse_hackerone(data: list[dict]) -> list[dict]:
    programs = []
    for p in data:
        if p.get("submission_state") != "open" or not p.get("offers_bounties"):
            continue
        handle = _slugify(p.get("handle") or p.get("name") or "")
        if not handle or handle in OVERSATURATED_HANDLES:
            continue
        targets = p.get("targets") or {}
        wildcards = set()
        excludes = set()

        for item in targets.get("in_scope") or []:
            ident = str(item.get("asset_identifier") or "")
            atype = str(item.get("asset_type") or "").upper()
            if not item.get("eligible_for_submission", True):
                ex = _extract_clean_host(ident, allow_wildcard=True)
                if ex:
                    excludes.add(ex)
                continue
            if not item.get("eligible_for_bounty"):
                continue
            sev = str(item.get("max_severity") or "").lower()
            if sev not in ("critical", "high"):
                continue
            instr = str(item.get("instruction") or "").lower()
            if "vpn required" in instr or "only accessible via vpn" in instr:
                continue
            if atype == "WILDCARD" or ident.startswith("*."):
                clean = _extract_clean_host(ident, allow_wildcard=True)
                if clean and clean.startswith("*."):
                    wildcards.add(clean)

        for item in targets.get("out_of_scope") or []:
            ident = str(item.get("asset_identifier") or "")
            for tok in HOST_TOKEN_RE.findall(ident):
                ex = _extract_clean_host(tok, allow_wildcard=True)
                if ex:
                    excludes.add(ex)

        if 1 <= len(wildcards) <= 8:
            eff = int(p.get("response_efficiency_percentage") or 80)
            programs.append(
                {
                    "slug": handle,
                    "platform": "hackerone",
                    "url": p.get("url", ""),
                    "wildcards": sorted(wildcards),
                    "excludes": sorted(excludes - wildcards),
                    "score": eff + (15 if p.get("allows_bounty_splitting") else 0) + len(wildcards) * 4,
                }
            )
    return programs


def _parse_bugcrowd(data: list[dict]) -> list[dict]:
    programs = []
    for p in data:
        max_pay = p.get("max_payout") or 0
        if not isinstance(max_pay, (int, float)) or max_pay < 500:
            continue
        url = str(p.get("url") or "")
        raw_slug = url.rstrip("/").rsplit("/", 1)[-1] or str(p.get("name") or "")
        slug = _slugify(raw_slug)
        if not slug or slug in OVERSATURATED_HANDLES:
            continue

        targets = p.get("targets") or {}
        wildcards = set()
        excludes = set()

        for item in targets.get("in_scope") or []:
            for field in ("target", "uri", "name"):
                val = str(item.get(field) or "").strip()
                if val.startswith("*.") or "://*." in val:
                    clean = _extract_clean_host(val, allow_wildcard=True)
                    if clean and clean.startswith("*."):
                        wildcards.add(clean)

        for item in targets.get("out_of_scope") or []:
            for field in ("target", "uri", "name"):
                val = str(item.get(field) or "").strip()
                ex = _extract_clean_host(val, allow_wildcard=True)
                if ex:
                    excludes.add(ex)

        if 1 <= len(wildcards) <= 8:
            safe = 20 if str(p.get("safe_harbor") or "").lower() == "full" else 5
            pay_bonus = min(int(max_pay // 500), 25)
            programs.append(
                {
                    "slug": f"bc_{slug}" if len(slug) < 4 else slug,
                    "platform": "bugcrowd",
                    "url": url,
                    "wildcards": sorted(wildcards),
                    "excludes": sorted(excludes - wildcards),
                    "score": 70 + safe + pay_bonus + len(wildcards) * 3,
                }
            )
    return programs


def _parse_yeswehack(data: list[dict]) -> list[dict]:
    programs = []
    for p in data:
        if not p.get("public") or p.get("disabled"):
            continue
        max_pay = p.get("max_bounty") or 0
        if not isinstance(max_pay, (int, float)) or max_pay < 500:
            continue
        raw_id = str(p.get("id") or p.get("name") or "")
        slug = _slugify(raw_id.replace("-bug-bounty-program", "").replace("-public", ""))
        if not slug or slug in OVERSATURATED_HANDLES:
            continue

        targets = p.get("targets") or {}
        wildcards = set()
        excludes = set()

        for item in targets.get("in_scope") or []:
            val = str(item.get("target") or "").strip()
            if val.startswith("*.") or "://*." in val:
                clean = _extract_clean_host(val, allow_wildcard=True)
                if clean and clean.startswith("*."):
                    wildcards.add(clean)

        for item in targets.get("out_of_scope") or []:
            val = str(item.get("target") or "").strip()
            ex = _extract_clean_host(val, allow_wildcard=True)
            if ex:
                excludes.add(ex)

        if 1 <= len(wildcards) <= 8:
            programs.append(
                {
                    "slug": slug,
                    "platform": "yeswehack",
                    "url": f"https://yeswehack.com/programs/{p.get('id', '')}",
                    "wildcards": sorted(wildcards),
                    "excludes": sorted(excludes - wildcards),
                    "score": 80 + min(int(max_pay // 500), 20) + len(wildcards) * 3,
                }
            )
    return programs


def _parse_intigriti(data: list[dict]) -> list[dict]:
    programs = []
    for p in data:
        if p.get("status") != "open" or p.get("confidentiality_level") != "public":
            continue
        if p.get("tacRequired") or p.get("twoFactorRequired"):
            continue
        max_b = (p.get("max_bounty") or {}).get("value") or 0
        if not isinstance(max_b, (int, float)) or max_b < 500:
            continue
        slug = _slugify(str(p.get("company_handle") or p.get("handle") or ""))
        if not slug or slug in OVERSATURATED_HANDLES:
            continue

        targets = p.get("targets") or {}
        wildcards = set()
        excludes = set()
        for item in targets.get("in_scope") or []:
            if str(item.get("impact") or "").lower() == "no bounty":
                continue
            val = str(item.get("endpoint") or "").strip()
            if val.startswith("*."):
                clean = _extract_clean_host(val, allow_wildcard=True)
                if clean and clean.startswith("*."):
                    wildcards.add(clean)

        for item in targets.get("out_of_scope") or []:
            val = str(item.get("endpoint") or "").strip()
            ex = _extract_clean_host(val, allow_wildcard=True)
            if ex:
                excludes.add(ex)

        if 1 <= len(wildcards) <= 8:
            programs.append(
                {
                    "slug": slug,
                    "platform": "intigriti",
                    "url": str(p.get("url") or ""),
                    "wildcards": sorted(wildcards),
                    "excludes": sorted(excludes - wildcards),
                    "score": 78 + min(int(max_b // 500), 20),
                }
            )
    return programs


def sync_paid_scopes(
    targets_dir: Path,
    limit: int = 90,
    include_intigriti: bool = False,
    preserve_focus: list[str] | None = None,
) -> list[str]:
    """Fetch public paid wildcard programs, write targets/<slug>.txt, and update _focus.txt."""
    targets_dir.mkdir(parents=True, exist_ok=True)
    candidates: list[dict] = []

    parsers = [
        ("hackerone", _parse_hackerone),
        ("bugcrowd", _parse_bugcrowd),
        ("yeswehack", _parse_yeswehack),
    ]
    if include_intigriti:
        parsers.append(("intigriti", _parse_intigriti))

    for name, fn in parsers:
        try:
            resp = requests.get(FEEDS[name], timeout=35)
            if resp.status_code == 200:
                parsed = fn(resp.json())
                print(f"[+] {name}: {len(parsed)} paid mid-tier wildcard programs matched")
                candidates.extend(parsed)
        except Exception as e:
            print(f"[!] {name} feed failed: {type(e).__name__}")

    # Deduplicate by root wildcard set and slug, keeping highest score.
    candidates.sort(key=lambda x: x["score"], reverse=True)
    seen_slugs: set[str] = set()
    seen_roots: set[str] = set()
    selected: list[dict] = []

    for c in candidates:
        slug = c["slug"]
        if slug in seen_slugs or slug in OVERSATURATED_HANDLES:
            continue
        roots_sig = ",".join(c["wildcards"])
        if roots_sig in seen_roots:
            continue
        seen_slugs.add(slug)
        seen_roots.add(roots_sig)
        selected.append(c)
        if len(selected) >= limit:
            break

    written_slugs: list[str] = []
    for c in selected:
        slug = c["slug"]
        target_path = targets_dir / f"{slug}.txt"
        lines = [
            f"# Auto-synced paid bounty scope ({c['platform']}): {c['url']}",
            *c["wildcards"],
            *[f"!{ex}" for ex in c["excludes"]],
        ]
        target_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        audit_target_file(target_path)
        written_slugs.append(slug)

    focus_list: list[str] = []
    for p in preserve_focus or []:
        if p not in OVERSATURATED_HANDLES and (targets_dir / f"{p}.txt").exists() and p not in focus_list:
            focus_list.append(p)
    for slug in written_slugs:
        if slug not in focus_list:
            focus_list.append(slug)

    focus_lines = [
        "# Active Paid Mid-Tier Wildcard Bug Bounty Focus List (NOVA v2.4)",
        "# Filtered strictly for offers_bounties=true, wildcard scopes, and official !exclude rules.",
        "",
        *focus_list[:limit],
    ]
    (targets_dir / "_focus.txt").write_text("\n".join(focus_lines) + "\n", encoding="utf-8")
    return focus_list[:limit]


def main() -> None:
    ap = argparse.ArgumentParser(description="Sync paid wildcard bug bounty scopes into targets/")
    ap.add_argument("--limit", type=int, default=90, help="Target count for _focus.txt (default: 90)")
    ap.add_argument("--include-intigriti", action="store_true", help="Include public Intigriti programs without TAC")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    keep = [
        "bybit_fintech",
        "unico_idtech",
        "remitly",
        "toolsforhumanity",
        "crypto",
        "varonis",
        "dynatrace",
        "khealth",
        "boozt",
        "bykea",
        "dyson",
        "banco_plata",
        "hypr-corp",
        "superhuman",
    ]
    active = sync_paid_scopes(
        root / "targets",
        limit=args.limit,
        include_intigriti=args.include_intigriti,
        preserve_focus=keep,
    )
    print(f"[=] Synced {len(active)} active paid wildcard programs into targets/_focus.txt")


if __name__ == "__main__":
    main()
