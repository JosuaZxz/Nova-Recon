"""Unit tests for NOVA v2.1 scope guard, lossless queue, JS diffing, and AI briefing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import ai_brief  # noqa: E402
import js_intel  # noqa: E402
import nova  # noqa: E402
import scope_guard  # noqa: E402


class TestScopeGuard(unittest.TestCase):
    def test_explicit_subdomains_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            (tdir / "adobe.txt").write_text(
                "\n".join(
                    [
                        "# Adobe Intigriti scope",
                        "acrobat.adobe.com",
                        "*.example.org",
                        "!staging.acrobat.adobe.com",
                        "!*.blog.example.org",
                        "!regex:^sandbox-[0-9]+\\.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            policy = scope_guard.load_program_policy("adobe", tdir)

            self.assertTrue(policy.in_scope("acrobat.adobe.com"))
            self.assertTrue(policy.in_scope("https://api.acrobat.adobe.com/v1/docs"))
            self.assertFalse(policy.in_scope("captivateprimeazdev.adobe.com"))
            self.assertFalse(policy.in_scope("staging.acrobat.adobe.com"))
            self.assertTrue(policy.in_scope("app.example.org"))
            self.assertFalse(policy.in_scope("news.blog.example.org"))
            self.assertFalse(policy.in_scope("sandbox-12.example.org"))

    def test_audit_preserves_subdomains_and_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "adobe.txt"
            p.write_text(
                "# Adobe\nacrobat.adobe.com\n!dev.acrobat.adobe.com\nbad line!\n",
                encoding="utf-8",
            )
            status, inc_cnt, exc_cnt, invalid = scope_guard.audit_target_file(p)
            self.assertEqual(status, "FIXED")
            self.assertEqual(inc_cnt, 1)
            self.assertEqual(exc_cnt, 1)
            self.assertEqual(invalid, ["bad line!"])
            content = p.read_text(encoding="utf-8")
            self.assertIn("acrobat.adobe.com", content)
            self.assertIn("!dev.acrobat.adobe.com", content)

    def test_focus_programs_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            (tdir / "boozt.txt").write_text("boozt.com\n", encoding="utf-8")
            (tdir / "bykea.txt").write_text("bykea.net\n", encoding="utf-8")
            (tdir / "_focus.txt").write_text("# comment\nboozt\nmissing\nbykea\n", encoding="utf-8")
            self.assertEqual(scope_guard.load_focus_programs(tdir), ["boozt", "bykea"])


class TestJsIntel(unittest.TestCase):
    def test_canonical_js_key_and_vendor_filter(self):
        k1 = js_intel.canonical_js_key("https://app.target.com/assets/main.a1b2c3d4.js?v=1")
        k2 = js_intel.canonical_js_key("https://app.target.com/assets/main.99887766.js?v=2")
        self.assertEqual(k1, k2)
        self.assertTrue(js_intel.is_vendor_js("https://cdn.target.com/js/jquery-3.7.1.min.js"))
        self.assertTrue(
            js_intel.is_vendor_js("https://form.target.com/assets/js/bank-account-validator.min.js")
        )

    def test_diff_js_bundle_detects_new_routes_across_deploy_hashes(self):
        state: dict = {}
        js_v1 = 'const a = "/api/v1/public/status";'
        entry1, diff1 = js_intel.diff_js_bundle(
            "https://app.target.com/assets/app.1111aaaa.js", js_v1, state, is_interesting_host=True
        )
        self.assertIsNotNone(entry1)
        self.assertIsNone(diff1)  # baseline only has low-value public status route
        state[js_intel.canonical_js_key("https://app.target.com/assets/app.1111aaaa.js")] = entry1

        js_v2 = (
            'const a = "/api/v1/public/status"; '
            'const b = "/api/internal/v2/exportUsers"; '
            'const m = "mutation ImpersonateTenant"; '
            '//# sourceMappingURL=app.2222bbbb.js.map'
        )
        entry2, diff2 = js_intel.diff_js_bundle(
            "https://app.target.com/assets/app.2222bbbb.js", js_v2, state, is_interesting_host=True
        )
        self.assertIsNotNone(entry2)
        self.assertIsNotNone(diff2)
        self.assertTrue(diff2["is_update"])
        self.assertIn("/api/internal/v2/exportUsers", diff2["added_routes"])
        self.assertIn("ImpersonateTenant", diff2["added_ops"])
        self.assertEqual(
            diff2["sourcemap_url"], "https://app.target.com/assets/app.2222bbbb.js.map"
        )

    def test_secret_scanner_suppresses_fp_and_catches_real_token(self):
        fp_js = '/* example placeholder */ const k = "ghp_1234567890abcdef1234567890abcdef1234";'
        self.assertEqual(js_intel.scan_js_secrets(fp_js, "https://app.target.com/app.js"), [])

        real_js = 'window.__CFG__ = { token: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890" };'
        hits = js_intel.scan_js_secrets(real_js, "https://app.target.com/app.js")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["type"], "js-secret")
        self.assertNotIn("aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", hits[0]["evidence"])


class TestNovaPipeline(unittest.TestCase):
    def test_monitor_queue_preserves_overflow_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tdir, sdir, ddir, fdir = root / "targets", root / "state", root / "data", root / "findings"
            tdir.mkdir()
            (tdir / "demo.txt").write_text("demo.test\n", encoding="utf-8")
            merge_file = root / "subfinder.txt"
            merge_file.write_text(
                "\n".join(
                    [
                        "a.demo.test",
                        "b.demo.test",
                        "dev-api.demo.test",
                        "c.demo.test",
                        "admin.demo.test",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with (
                patch.object(nova, "TARGETS_DIR", tdir),
                patch.object(nova, "STATE_DIR", sdir),
                patch.object(nova, "DATA_DIR", ddir),
                patch.object(nova, "FINDINGS_DIR", fdir),
                patch.object(nova, "PASSIVE_SOURCES", []),
                patch.object(nova, "MAX_NEW_PROBE", 2),
            ):
                nova.cmd_monitor(argparse.Namespace(program="demo", merge_file=str(merge_file)))
                batch1 = (ddir / "demo" / "probe_batch.txt").read_text(encoding="utf-8").splitlines()
                rem1 = (sdir / "demo.queue.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(batch1), 2)
                self.assertEqual(len(rem1), 3)
                # Interesting hosts should be prioritized into batch 1
                self.assertEqual(sorted(batch1), ["admin.demo.test", "dev-api.demo.test"])

                # Second monitor run with 0 new discoveries must drain queued hosts
                nova.cmd_monitor(argparse.Namespace(program="demo", merge_file=None))
                batch2 = (ddir / "demo" / "probe_batch.txt").read_text(encoding="utf-8").splitlines()
                rem2 = (sdir / "demo.queue.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(batch2), 2)
                self.assertEqual(len(rem2), 1)

    def test_host_transition_and_cmd_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tdir, sdir, ddir, fdir = root / "targets", root / "state", root / "data", root / "findings"
            tdir.mkdir()
            sdir.mkdir()
            (tdir / "demo.txt").write_text("demo.test\n", encoding="utf-8")

            fake_probe = {
                "host": "portal.demo.test",
                "url": "https://portal.demo.test/",
                "http_status": 200,
                "title": "Admin Portal",
                "redirect": "",
                "scripts": ["https://portal.demo.test/assets/app.222222.js"],
                "catchall": False,
            }

            def fake_http_get(url, **kwargs):
                resp = MagicMock()
                resp.status_code = 200
                if url.endswith("app.222222.js"):
                    resp._nova_body = (
                        b'fetch("/api/admin/audit-logs"); //# sourceMappingURL=app.222222.js.map'
                    )
                    return resp, None
                if url.endswith("app.222222.js.map"):
                    resp._nova_body = b'{"version":3,"sources":["index.ts"],"mappings":"AAAA"}'
                    return resp, None
                return None, "not-mocked"

            with (
                patch.object(nova, "TARGETS_DIR", tdir),
                patch.object(nova, "STATE_DIR", sdir),
                patch.object(nova, "DATA_DIR", ddir),
                patch.object(nova, "FINDINGS_DIR", fdir),
                patch.object(nova, "probe_host", return_value=fake_probe),
                patch.object(nova, "http_get", side_effect=fake_http_get),
            ):
                nova.save_hosts_state(
                    "demo",
                    {
                        "portal.demo.test": {
                            "url": "https://portal.demo.test/",
                            "http_status": 403,
                            "title": "Forbidden",
                            "redirect": "",
                            "scripts": ["https://portal.demo.test/assets/app.111111.js"],
                            "catchall": False,
                            "interesting": True,
                            "last_checked": "2026-11-01 00:00:00 UTC",
                        }
                    },
                )
                js_intel.save_js_state(
                    sdir,
                    "demo",
                    {
                        "https://portal.demo.test/assets/app.HASH.js": {
                            "last_url": "https://portal.demo.test/assets/app.111111.js",
                            "sha256": "oldhash",
                            "routes": ["/api/v1/health"],
                            "graphql_ops": [],
                            "updated": "2026-11-01 00:00:00 UTC",
                        }
                    },
                )
                nova.cmd_diff(argparse.Namespace(program="demo", budget=10))
                day_dir = fdir / nova.today_str() / "demo"
                files = list(day_dir.glob("*.json"))
                types = sorted(json.loads(p.read_text(encoding="utf-8"))["type"] for p in files)
                self.assertEqual(types, ["host-change", "js-diff", "sourcemap"])

                # Re-running diff with identical state must emit 0 duplicate files
                nova.cmd_diff(argparse.Namespace(program="demo", budget=10))
                files_after = list(day_dir.glob("*.json"))
                self.assertEqual(len(files_after), 3)

    def test_ai_brief_fallback_and_mocked_summary(self):
        sample = [
            {
                "program": "demo",
                "type": "js-diff",
                "severity_hint": "medium",
                "url": "https://portal.demo.test/app.js",
                "evidence": "routes baru: /api/admin/users",
                "added_routes": ["/api/admin/users"],
                "added_ops": [],
            }
        ]
        with patch.dict("os.environ", {"GROQ_API_KEY": ""}):
            self.assertIsNone(ai_brief.summarize_findings(sample))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "1. Cek portal.demo.test secara manual."}}]
        }
        with (
            patch.dict("os.environ", {"GROQ_API_KEY": "test-key"}),
            patch("ai_brief.requests.post", return_value=mock_resp),
        ):
            out = ai_brief.summarize_findings(sample)
            self.assertIn("portal.demo.test", out)


if __name__ == "__main__":
    unittest.main()
