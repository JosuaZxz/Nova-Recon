"""Unit tests for NOVA v2.2 scope guard, redirect follower, double-tap verify, JS diff, and AI report gate."""

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
        self.assertIsNone(diff1)
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
        self.assertIn("Previous SHA256:", diff2["response_evidence"])

    def test_secret_scanner_suppresses_fp_and_low_entropy(self):
        tok_prefix = "gh" + "p_"
        fp_js = f'/* example placeholder */ const k = "{tok_prefix}1234567890abcdef1234567890abcdef1234";'
        self.assertEqual(js_intel.scan_js_secrets(fp_js, "https://app.target.com/app.js"), [])

        ones = "1" * 36
        low_ent = f'window.__CFG__ = {{ token: "{tok_prefix}{ones}" }};'
        self.assertEqual(js_intel.scan_js_secrets(low_ent, "https://app.target.com/app.js"), [])

        real_tok = tok_prefix + "a9K3mP7xQ2vL8nR4tY6wZ1bC5dF0gH2jK9mN"
        real_js = f'window.__CFG__ = {{ token: "{real_tok}" }};'
        hits = js_intel.scan_js_secrets(real_js, "https://app.target.com/app.js")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["type"], "js-secret")
        self.assertIn("GET /app.js HTTP/1.1", hits[0]["request_evidence"])


class TestNovaV22(unittest.TestCase):
    def test_probe_host_follows_same_host_redirect_and_extracts_modulepreload_js(self):
        policy = scope_guard.ProgramPolicy(program="demo", includes=["demo.org"])

        def fake_http_get(url, **kwargs):
            resp = MagicMock()
            if url == "https://app.demo.org/":
                resp.status_code = 302
                resp.headers = {"Location": "/dashboard", "Content-Type": "text/plain"}
                resp._nova_body = b""
                return resp, None
            if url == "https://app.demo.org/dashboard":
                resp.status_code = 200
                resp.headers = {"Content-Type": "text/html; charset=utf-8", "Server": "nginx"}
                resp._nova_body = (
                    b'<html><head><title>App Dashboard</title>'
                    b'<link rel="modulepreload" href="/assets/index.a1b2c3.mjs">'
                    b'</head><body>Welcome</body></html>'
                )
                return resp, None
            if "nova-random-probe-" in url:
                resp.status_code = 404
                resp.headers = {"Content-Type": "text/html"}
                resp._nova_body = b"Not found"
                return resp, None
            return None, "unexpected"

        with (
            patch.object(nova, "resolve_a", return_value=["93.184.216.34"]),
            patch.object(nova, "http_get", side_effect=fake_http_get),
        ):
            res = nova.probe_host("app.demo.org", policy)
            self.assertIsNotNone(res)
            self.assertEqual(res["http_status"], 200)
            self.assertEqual(res["title"], "App Dashboard")
            self.assertEqual(res["scripts"], ["https://app.demo.org/assets/index.a1b2c3.mjs"])

    def test_double_tap_exposure_rejects_catchall_and_accepts_real_env(self):
        def fake_catchall_http(url, **kwargs):
            r = MagicMock()
            r.status_code = 200
            r.headers = {"Content-Type": "text/plain"}
            r._nova_body = b"DB_PASSWORD=super_secret_prod_db_99182\n"
            return r, None

        with patch.object(nova, "http_get", side_effect=fake_catchall_http):
            # Canary returns identical body -> must be rejected as catch-all
            self.assertEqual(nova.check_exposures("https://api.demo.org", False), [])

        def fake_real_env_http(url, **kwargs):
            r = MagicMock()
            if url.endswith("/.env"):
                r.status_code = 200
                r.headers = {"Content-Type": "text/plain"}
                r._nova_body = b"INTERNAL_DB_PASS=99a88b77c66d55e44f33g22h11j00k\n"
                return r, None
            r.status_code = 404
            r.headers = {"Content-Type": "text/plain"}
            r._nova_body = b"404 Not Found"
            return r, None

        with patch.object(nova, "http_get", side_effect=fake_real_env_http):
            hits = nova.check_exposures("https://api.demo.org", False)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["type"], "exposure")
            self.assertIn("GET /.env HTTP/1.1", hits[0]["request_evidence"])

    def test_dual_doh_takeover_ignores_elb_and_verifies_claimable(self):
        policy = scope_guard.ProgramPolicy(program="demo", includes=["demo.org"])

        # Non-claimable ELB should return None (never clutter findings)
        with patch.object(
            nova, "dns_lookup", return_value=(["internal-123.us-east-1.elb.amazonaws.com"], [])
        ):
            self.assertIsNone(nova.check_takeover("old.demo.org", policy))

        # Claimable Azure service verified on both Cloudflare and Google DoH
        def fake_dual_dns(host, resolver_url=""):
            if host == "dev.demo.org":
                return (["abandoned-app.azurewebsites.net"], [])
            return ([], [])

        with patch.object(nova, "dns_lookup", side_effect=fake_dual_dns):
            hit = nova.check_takeover("dev.demo.org", policy)
            self.assertIsNotNone(hit)
            self.assertEqual(hit["type"], "takeover")
            self.assertIn("Cloudflare DoH", hit["response_evidence"])
            self.assertIn("Google DoH", hit["response_evidence"])

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
                self.assertEqual(sorted(batch1), ["admin.demo.test", "dev-api.demo.test"])

                nova.cmd_monitor(argparse.Namespace(program="demo", merge_file=None))
                batch2 = (ddir / "demo" / "probe_batch.txt").read_text(encoding="utf-8").splitlines()
                rem2 = (sdir / "demo.queue.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(batch2), 2)
                self.assertEqual(len(rem2), 1)

    def test_backlog_seeder_wakes_legacy_subs_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tdir, sdir, ddir, fdir = root / "targets", root / "state", root / "data", root / "findings"
            tdir.mkdir()
            sdir.mkdir()
            (tdir / "legacy.txt").write_text("legacy.org\n", encoding="utf-8")
            # Simulate legacy v2.0 state: subs.txt populated, but hosts.json and queue.txt empty
            (sdir / "legacy.subs.txt").write_text(
                "dev-api.legacy.org\nadmin.legacy.org\nstatic.legacy.org\n",
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
                nova.cmd_monitor(argparse.Namespace(program="legacy", merge_file=None))
                batch1 = (ddir / "legacy" / "probe_batch.txt").read_text(encoding="utf-8").splitlines()
                rem1 = (sdir / "legacy.queue.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(sorted(batch1), ["admin.legacy.org", "dev-api.legacy.org"])
                self.assertEqual(rem1, ["static.legacy.org"])

                # Drain remaining 1 queued host
                nova.cmd_monitor(argparse.Namespace(program="legacy", merge_file=None))
                batch2 = (ddir / "legacy" / "probe_batch.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(batch2, ["static.legacy.org"])

                # Third run: queue is now empty and _seeded=True, so it must NOT re-seed dead hosts
                nova.cmd_monitor(argparse.Namespace(program="legacy", merge_file=None))
                batch3 = (ddir / "legacy" / "probe_batch.txt").read_text(encoding="utf-8").splitlines()
                self.assertEqual(batch3, [])

    def test_verify_extracted_routes_drops_403_and_reports_unauth_200_json(self):
        policy = scope_guard.ProgramPolicy(program="demo", includes=["demo.org"])

        def fake_http(url, **kwargs):
            r = MagicMock()
            if url == "https://portal.demo.org/api/internal/users":
                r.status_code = 200
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = (
                    b'{"users":[{"id":1,"email":"admin@demo.org","role":"superadmin"}]}'
                )
                return r, None
            if url == "https://portal.demo.org/api/internal/locked":
                r.status_code = 403
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = b'{"error":{"message":"missing session cookie"}}'
                return r, None
            r.status_code = 404
            r.headers = {"Content-Type": "application/json"}
            r._nova_body = b'{"error":"not found"}'
            return r, None

        with patch.object(nova, "http_get", side_effect=fake_http):
            # 403 route must return 0 findings
            self.assertEqual(
                nova.verify_extracted_routes(
                    "https://portal.demo.org/app.js", ["/api/internal/locked"], policy
                ),
                [],
            )
            # 200 OK JSON with sensitive fields + 404 canary must emit unauth-api
            hits = nova.verify_extracted_routes(
                "https://portal.demo.org/app.js", ["/api/internal/users"], policy
            )
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["type"], "unauth-api")
            self.assertIn("admin@demo.org", hits[0]["response_evidence"])

    def test_verify_cloud_assets_detects_unclaimed_s3_and_open_firebase(self):
        js_code = (
            'const assets = "https://legacy-assets-prod-99.s3.amazonaws.com/logo.png"; '
            'const fbOpen = "https://corp-staging-rtdb.firebaseio.com"; '
            'const fbLocked = "https://corp-locked-rtdb.firebaseio.com";'
        )
        extracted = js_intel.extract_cloud_urls(js_code)
        self.assertEqual(extracted["s3_urls"], ["https://legacy-assets-prod-99.s3.amazonaws.com"])
        self.assertEqual(len(extracted["firebase_urls"]), 2)

        def fake_cloud_http(url, **kwargs):
            r = MagicMock()
            if "legacy-assets-prod-99.s3.amazonaws.com" in url:
                r.status_code = 404
                r.headers = {"Content-Type": "application/xml"}
                r._nova_body = b"<Error><Code>NoSuchBucket</Code></Error>"
                return r, None
            if "corp-staging-rtdb.firebaseio.com" in url:
                r.status_code = 200
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = b'{"users":true,"admin_config":true}'
                return r, None
            if "corp-locked-rtdb.firebaseio.com" in url:
                r.status_code = 401
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = b'{"error":"Permission denied"}'
                return r, None
            return None, "unexpected"

        with patch.object(nova, "http_get", side_effect=fake_cloud_http):
            hits = nova.verify_cloud_assets("https://app.demo.org/main.js", js_code)
            types = [h["type"] for h in hits]
            self.assertEqual(types, ["cloud-takeover", "cloud-exposure"])

    def test_ai_gatekeeper_rejects_fp_and_generates_ready_report_for_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdir, fdir = root / "state", root / "findings"
            sdir.mkdir()
            fdir.mkdir()

            fp_candidate = {
                "type": "exposure",
                "url": "https://www.demo.org/.env",
                "host": "www.demo.org",
                "severity_hint": "critical",
                "confidence": "strong",
                "evidence": "KEY=val",
                "request_evidence": "GET /.env HTTP/1.1",
                "response_evidence": "HTTP/1.1 200 OK\n\n<!DOCTYPE html><html>Attention Required! | Cloudflare</html>",
            }
            valid_candidate = {
                "type": "takeover",
                "url": "https://stage.demo.org",
                "host": "stage.demo.org",
                "severity_hint": "high",
                "confidence": "strong",
                "evidence": "Dual-DoH verified dangling CNAME: stage.demo.org -> stage-demo.azurewebsites.net",
                "request_evidence": "$ dig stage.demo.org CNAME +short",
                "response_evidence": "Cloudflare DoH: NXDOMAIN\nGoogle DoH: NXDOMAIN",
            }

            mock_groq_resp = MagicMock()
            mock_groq_resp.status_code = 200
            mock_groq_resp.json.return_value = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "verdict": "VALID",
                                    "confidence_score": 94,
                                    "rejection_reason": "",
                                    "title": "Subdomain Takeover on stage.demo.org via Dangling Azure CNAME",
                                    "severity": "high",
                                    "summary": "The subdomain stage.demo.org points to an unclaimed Azure App Service.",
                                    "technical_analysis": "Both Cloudflare and Google DoH confirm NXDOMAIN.",
                                    "steps_to_reproduce": [
                                        "1. Query CNAME for stage.demo.org",
                                        "2. Confirm NXDOMAIN on stage-demo.azurewebsites.net",
                                    ],
                                    "impact": "Arbitrary content hosting under stage.demo.org.",
                                    "remediation": "Remove the dangling CNAME record.",
                                }
                            )
                        }
                    }
                ]
            }

            with (
                patch.object(nova, "STATE_DIR", sdir),
                patch.object(nova, "FINDINGS_DIR", fdir),
                patch.dict("os.environ", {"GROQ_API_KEY": "test-groq-key"}),
                patch("ai_brief.requests.post", return_value=mock_groq_resp),
            ):
                saved = nova._persist_findings("demo", [fp_candidate, valid_candidate])
                self.assertEqual(saved, 1)
                day_dir = fdir / nova.today_str() / "demo"
                reports = list(day_dir.glob("REPORT-*.md"))
                self.assertEqual(len(reports), 1)
                report_text = reports[0].read_text(encoding="utf-8")
                self.assertIn("# Subdomain Takeover on stage.demo.org", report_text)
                self.assertIn("94/100 (VALIDATED)", report_text)
                self.assertIn("Cloudflare DoH: NXDOMAIN", report_text)

    def test_per_host_cap_allows_full_verify_and_same_host_js(self):
        self.assertGreaterEqual(nova.PER_HOST_CAP, 40)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tdir, sdir, ddir, fdir = root / "targets", root / "state", root / "data", root / "findings"
            tdir.mkdir()
            sdir.mkdir()
            (ddir / "demo").mkdir(parents=True)
            fdir.mkdir()
            (tdir / "demo.txt").write_text("demo.org\n", encoding="utf-8")
            probe_rec = {
                "host": "app.demo.org",
                "url": "https://app.demo.org/",
                "http_status": 200,
                "catchall": False,
                "scripts": ["https://app.demo.org/assets/main.js"],
                "body": "<html></html>",
            }
            (ddir / "demo" / "probe.jsonl").write_text(json.dumps(probe_rec) + "\n", encoding="utf-8")
            (ddir / "demo" / "new.txt").write_text("", encoding="utf-8")

            gl_prefix = "gl" + "pat-"
            tok = gl_prefix + "a9K3mP7xQ2vL8nR4tY6wZ1bC"
            seen_urls = []

            def fake_requests_req(method, url, **kwargs):
                seen_urls.append(url)
                resp = MagicMock()
                resp.headers = {"Content-Type": "text/plain"}
                if url == "https://app.demo.org/assets/main.js":
                    resp.status_code = 200
                    resp.headers = {"Content-Type": "application/javascript"}
                    resp.iter_content.return_value = [f'const cfg = "{tok}";'.encode("utf-8")]
                    return resp
                resp.status_code = 404
                resp.iter_content.return_value = [b"404"]
                return resp

            with (
                patch.object(nova, "TARGETS_DIR", tdir),
                patch.object(nova, "STATE_DIR", sdir),
                patch.object(nova, "DATA_DIR", ddir),
                patch.object(nova, "FINDINGS_DIR", fdir),
                patch.object(nova, "REQ_DELAY", 0.0),
                patch("nova.requests.request", side_effect=fake_requests_req),
                patch.dict("os.environ", {"GROQ_API_KEY": ""}),
            ):
                nova.cmd_verify(
                    argparse.Namespace(program="demo", probe_file=None, new_file=None, rebuild=False)
                )
                self.assertIn("https://app.demo.org/assets/main.js", seen_urls)
                js_saved = json.loads((sdir / "demo.js.json").read_text(encoding="utf-8"))
                self.assertEqual(len(js_saved), 1)
                reports = list((fdir / nova.today_str() / "demo").glob("REPORT-demo-js-secret-*.md"))
                self.assertEqual(len(reports), 1)

    def test_verify_scans_404_api_hosts_and_openapi_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tdir, sdir, ddir, fdir = root / "targets", root / "state", root / "data", root / "findings"
            tdir.mkdir()
            sdir.mkdir()
            (ddir / "demo").mkdir(parents=True)
            fdir.mkdir()
            (tdir / "demo.txt").write_text("demo.org\n", encoding="utf-8")
            probe_rec = {
                "host": "api-stg.demo.org",
                "url": "https://api-stg.demo.org/",
                "http_status": 404,
                "catchall": False,
                "scripts": [],
                "body": '{"status":404,"error":"Not Found"}',
            }
            (ddir / "demo" / "probe.jsonl").write_text(json.dumps(probe_rec) + "\n", encoding="utf-8")
            (ddir / "demo" / "new.txt").write_text("", encoding="utf-8")

            def fake_http(url, **kwargs):
                r = MagicMock()
                if url == "https://api-stg.demo.org/openapi.json":
                    r.status_code = 200
                    r.headers = {"Content-Type": "application/json"}
                    r._nova_body = json.dumps(
                        {"openapi": "3.0.1", "paths": {"/api/v1/users/export": {"get": {}}}}
                    ).encode("utf-8")
                    return r, None
                if url == "https://api-stg.demo.org/api/v1/users/export":
                    r.status_code = 200
                    r.headers = {"Content-Type": "application/json"}
                    r._nova_body = b'{"users":[{"email":"ops@demo.org","phone":"+15550199"}]}'
                    return r, None
                r.status_code = 404
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = b'{"error":"not found"}'
                return r, None

            with (
                patch.object(nova, "TARGETS_DIR", tdir),
                patch.object(nova, "STATE_DIR", sdir),
                patch.object(nova, "DATA_DIR", ddir),
                patch.object(nova, "FINDINGS_DIR", fdir),
                patch.object(nova, "http_get", side_effect=fake_http),
                patch.dict("os.environ", {"GROQ_API_KEY": ""}),
            ):
                nova.cmd_verify(
                    argparse.Namespace(program="demo", probe_file=None, new_file=None, rebuild=False)
                )
                reports = list((fdir / nova.today_str() / "demo").glob("REPORT-demo-unauth-api-*.md"))
                self.assertEqual(len(reports), 1)

    def test_hidden_sourcemap_and_non_keyword_host_routes_are_verified(self):
        policy = scope_guard.ProgramPolicy(program="demo", includes=["demo.org"])
        js_state: dict = {}
        shp_prefix = "shp" + "at_"
        secret_tok = shp_prefix + "a1b2c3d4e5f60718293a4b5c6d7e8f90"

        def fake_http(url, **kwargs):
            r = MagicMock()
            if url == "https://merchant.demo.org/static/main.js":
                r.status_code = 200
                r.headers = {"Content-Type": "application/javascript"}
                r._nova_body = b'const api = "/api/v1/public/ping"; console.log(api);'
                return r, None
            if url == "https://merchant.demo.org/static/main.js.map":
                r.status_code = 200
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = (
                    f'{{"version":3,"sources":["env.ts"],"sourcesContent":["const k = \\"{secret_tok}\\";"]}}'
                ).encode("utf-8")
                return r, None
            r.status_code = 404
            r.headers = {"Content-Type": "text/plain"}
            r._nova_body = b"404"
            return r, None

        with patch.object(nova, "http_get", side_effect=fake_http):
            hits = nova._fetch_and_analyze_js(
                [("https://merchant.demo.org/static/main.js", False)],
                policy,
                js_state,
                run_diff=True,
            )
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["type"], "js-secret")
            self.assertEqual(hits[0]["url"], "https://merchant.demo.org/static/main.js.map")

    def test_ai_gate_blocks_bare_sourcemap_and_mutationless_graphql(self):
        is_fp_sm, _ = ai_brief.deterministic_fp_check({"type": "sourcemap", "url": "https://a.com/a.js.map"})
        self.assertTrue(is_fp_sm)
        is_fp_hc, _ = ai_brief.deterministic_fp_check(
            {
                "type": "host-change",
                "url": "https://dev.loom.com/",
                "response_evidence": "Previous State: HTTP 403 (title: Vercel Security Checkpoint)",
            }
        )
        self.assertTrue(is_fp_hc)
        is_fp_gql_med, _ = ai_brief.deterministic_fp_check(
            {"type": "graphql", "confidence": "medium", "url": "https://a.com/graphql"}
        )
        self.assertTrue(is_fp_gql_med)
        is_fp_gql_strong, _ = ai_brief.deterministic_fp_check(
            {
                "type": "graphql",
                "confidence": "strong",
                "url": "https://wildcard.website.bokundemo.com/api/graphql",
            }
        )
        self.assertTrue(is_fp_gql_strong)

    def test_cloud_exposure_filters_third_party_static_banners_and_public_pricingfeed(self):
        kayak_js = 'const img = "https://storage.googleapis.com/crowdriff-static/banner.png";'
        deriv_js = 'const fb = "https://deriv-static-pricingfeedv2.firebaseio.com";'
        corp_js = 'const rtdb = "https://corp-staging-rtdb.firebaseio.com";'

        def fake_cloud_http(url, **kwargs):
            r = MagicMock()
            if "crowdriff-static" in url:
                r.status_code = 200
                r.headers = {"Content-Type": "application/xml"}
                r._nova_body = (
                    b"<ListBucketResult><Name>crowdriff-static</Name>"
                    b"<Contents><Key>/console/v4/collector/10269/banner_08a35ff8.png</Key></Contents>"
                    b"<Contents><Key>/console/v4/collector/10269/banner_6f4f0160.jpg</Key></Contents>"
                    b"</ListBucketResult>"
                )
                return r, None
            if "deriv-static-pricingfeedv2.firebaseio.com" in url:
                r.status_code = 200
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = b'{"eu":true,"n8n":true,"row":true}'
                return r, None
            if "corp-staging-rtdb.firebaseio.com" in url:
                r.status_code = 200
                r.headers = {"Content-Type": "application/json"}
                r._nova_body = b'{"users":true,"admin_config":true}'
                return r, None
            return None, "unexpected"

        with patch.object(nova, "http_get", side_effect=fake_cloud_http):
            self.assertEqual(
                nova.verify_cloud_assets("http://rights.kayak.com/app.js", kayak_js, program="kayak"),
                [],
            )
            self.assertEqual(
                nova.verify_cloud_assets("https://staging.deriv.com/app.js", deriv_js, program="deriv"),
                [],
            )
            hits = nova.verify_cloud_assets("https://app.demo.org/app.js", corp_js, program="demo")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["type"], "cloud-exposure")

    def test_scope_sync_filters_paid_wildcards_and_shared_hosting(self):
        import scope_sync

        self.assertIsNone(scope_sync._extract_clean_host("*.myshopify.com"))
        self.assertIsNone(scope_sync._extract_clean_host("*.s3.amazonaws.com"))
        self.assertEqual(scope_sync._extract_clean_host("*.acorns.com"), "*.acorns.com")

        h1_sample = [
            {
                "handle": "midtier_saas",
                "submission_state": "open",
                "offers_bounties": True,
                "url": "https://hackerone.com/midtier_saas",
                "targets": {
                    "in_scope": [
                        {
                            "asset_identifier": "*.midtiersaas.io",
                            "asset_type": "WILDCARD",
                            "eligible_for_bounty": True,
                            "eligible_for_submission": True,
                            "max_severity": "critical",
                        },
                        {
                            "asset_identifier": "*.vdp-only.io",
                            "asset_type": "WILDCARD",
                            "eligible_for_bounty": False,
                            "eligible_for_submission": True,
                            "max_severity": "high",
                        },
                    ],
                    "out_of_scope": [{"asset_identifier": "status.midtiersaas.io"}],
                },
            }
        ]
        parsed = scope_sync._parse_hackerone(h1_sample)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["wildcards"], ["*.midtiersaas.io"])
        self.assertEqual(parsed[0]["excludes"], ["status.midtiersaas.io"])

    def test_check_cors_rejects_empty_dsn_ping_and_accepts_stateful_leak(self):
        def fake_empty_cors(url, **kwargs):
            r = MagicMock()
            r.status_code = 200
            r.headers = {
                "Access-Control-Allow-Origin": "https://nova-cors-canary.example.com",
                "Access-Control-Allow-Credentials": "true",
                "Content-Length": "0",
            }
            r._nova_body = b""
            return r, None

        with patch.object(nova, "http_get", side_effect=fake_empty_cors):
            self.assertIsNone(nova.check_cors("https://2vwv4gxx2x-dsn.algolia.net/"))

        def fake_real_cors(url, **kwargs):
            r = MagicMock()
            r.status_code = 200
            r.headers = {
                "Access-Control-Allow-Origin": "https://nova-cors-canary.example.com",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin, Cookie",
            }
            r._nova_body = b'{"email":"ceo@demo.org","token":"sess_live_991"}'
            return r, None

        with patch.object(nova, "http_get", side_effect=fake_real_cors):
            hit = nova.check_cors("https://api.demo.org/v1/me")
            self.assertIsNotNone(hit)
            self.assertEqual(hit["type"], "cors")

    def test_ai_gatekeeper_falls_back_to_nvidia_when_groq_fails(self):
        candidate = {
            "program": "etoro-mbb-og",
            "type": "takeover",
            "url": "https://candle-src.etoro.com",
            "host": "candle-src.etoro.com",
            "severity_hint": "high",
            "confidence": "strong",
            "evidence": "Dual-DoH NXDOMAIN on prod-candle.trafficmanager.net",
            "request_evidence": "dig candle-src.etoro.com CNAME +short",
            "response_evidence": "Cloudflare DoH: NXDOMAIN\nGoogle DoH: NXDOMAIN",
        }
        seen_urls = []

        def fake_post(url, **kwargs):
            seen_urls.append(url)
            resp = MagicMock()
            if url == ai_brief.GROQ_API_URL:
                resp.status_code = 429
                return resp
            if url == ai_brief.NVIDIA_API_URL:
                resp.status_code = 200
                resp.json.return_value = {
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "verdict": "VALID",
                                        "confidence_score": 91,
                                        "rejection_reason": "",
                                        "title": "Subdomain Takeover via Dangling Azure Traffic Manager on candle-src.etoro.com",
                                        "severity": "high",
                                        "summary": "Verified dangling CNAME to prod-candle.trafficmanager.net.",
                                        "technical_analysis": "Dual-DoH resolvers return NXDOMAIN.",
                                        "steps_to_reproduce": ["1. Query CNAME record"],
                                        "impact": "Subdomain takeover risk under etoro.com.",
                                        "remediation": "Remove dangling CNAME record.",
                                    }
                                )
                            }
                        }
                    ]
                }
                return resp
            resp.status_code = 500
            return resp

        with (
            patch.dict(
                "os.environ",
                {"GROQ_API_KEY": "broken-groq-key", "NVIDIA_API_KEY": "test-nvidia-key"},
            ),
            patch("ai_brief.requests.post", side_effect=fake_post),
        ):
            draft = ai_brief.validate_and_draft_report(candidate)
            self.assertIsNotNone(draft)
            self.assertEqual(draft["confidence_score"], 91)
            self.assertEqual(
                draft["title"],
                "Subdomain Takeover via Dangling Azure Traffic Manager on candle-src.etoro.com",
            )
            self.assertEqual(seen_urls, [ai_brief.GROQ_API_URL, ai_brief.NVIDIA_API_URL])


if __name__ == "__main__":
    unittest.main()
