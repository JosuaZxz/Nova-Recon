#!/usr/bin/env python3
"""
Optional local Playwright-CLI / headless browser dynamic JS chunk harvester for NOVA.
Captures lazy-loaded SPA JavaScript bundle URLs via playwright-cli and feeds them into NOVA.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


JS_URL_RE = re.compile(r"https?://[^\s\"'<>]+\.m?js(?:\?[^\s\"'<>]*)?", re.IGNORECASE)


def harvest_js_with_playwright_cli(target_url: str) -> list[str]:
    """Use playwright-cli to open a SPA page, evaluate performance resource entries, and close."""
    js_urls: set[str] = set()
    try:
        subprocess.run(
            ["playwright-cli", "open", target_url],
            capture_output=True,
            text=True,
            timeout=25,
        )
        res = subprocess.run(
            [
                "playwright-cli",
                "--raw",
                "eval",
                "JSON.stringify(performance.getEntriesByType('resource').map(r => r.name))",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for u in JS_URL_RE.findall(res.stdout or ""):
            js_urls.add(u)
    except Exception:
        pass
    finally:
        try:
            subprocess.run(["playwright-cli", "close"], capture_output=True, timeout=10)
        except Exception:
            pass
    return sorted(js_urls)


def main() -> None:
    ap = argparse.ArgumentParser(description="Harvest lazy-loaded SPA JS bundles via playwright-cli")
    ap.add_argument("--url", required=True, help="Target SPA URL")
    ap.add_argument("--out", required=True, help="Output JSON or text file")
    args = ap.parse_args()

    urls = harvest_js_with_playwright_cli(args.url)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.suffix == ".json":
        out_path.write_text(json.dumps(urls, indent=2), encoding="utf-8")
    else:
        out_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    print(f"[+] Harvested {len(urls)} JS URLs from {args.url} -> {out_path}")


if __name__ == "__main__":
    main()
