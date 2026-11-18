import contextlib
import importlib.util
import io
import json
from email.message import Message
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("dependency_audit", Path(__file__).resolve().parents[1] / "scripts/audit-dependencies.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class DependencyAuditTests(unittest.TestCase):
    def test_inventory_requires_pins_and_hashes_for_both_release_locks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good = "demo==1.2.3 ; sys_platform == 'darwin' \\\n    --hash=sha256:" + "a" * 64 + "\n"
            for name in ("runtime.lock", "build.lock"):
                (root / name).write_text(good)
            self.assertEqual(audit.inventory(root), [{"name": "demo", "version": "1.2.3"}])
            for bad in ("demo>=1.2\n", "demo==1.2\n", "--extra-index-url https://example.invalid\n", ""):
                (root / "runtime.lock").write_text(bad)
                with self.assertRaises(ValueError):
                    audit.inventory(root)

    def test_incomplete_or_malformed_api_result_never_becomes_a_clean_result(self):
        packages = [{"name": "demo", "version": "1"}]
        for payload in (None, {}, {"results": []}, {"results": [None]}, {"results": [{"error": "failed"}]},
                        {"results": [{"next_page_token": "more"}]}, {"results": [{"vulns": "wrong"}]},
                        {"results": [{"unexpected": "unavailable"}]}, {"results": [{"next_page_token": False}]},
                        {"results": [{}], "error": "incomplete"},
                        {"results": [{"vulns": [{"id": "https://example.invalid"}]}]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                audit.findings(packages, payload)

    def test_known_advisories_remain_visible_and_are_not_dismissed(self):
        package = {"name": "demo", "version": "1"}
        self.assertEqual(audit.findings([package], {"results": [{"vulns": [{"id": "GHSA-test-test-test"}]}]}),
                         [{**package, "advisories": ["GHSA-test-test-test"]}])
        self.assertEqual(audit.findings([package], {"results": [{}]}), [])

    def test_default_inventory_does_not_contact_a_service(self):
        output = io.StringIO()
        with patch.object(audit, "fetch", side_effect=AssertionError("No network expected")), contextlib.redirect_stdout(output):
            self.assertEqual(audit.main([]), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "inventory_only")

    def test_online_errors_and_advisories_have_distinct_nonzero_status(self):
        for response, expected in (({"results": [{"vulns": [{"id": "GHSA-test-test-test"}]}]}, 1), ({}, 2)):
            output = io.StringIO()
            with patch.object(audit, "inventory", return_value=[{"name": "demo", "version": "1"}]), patch.object(
                audit, "fetch", return_value=response
            ), contextlib.redirect_stdout(output):
                self.assertEqual(audit.main(["--online"]), expected)
            self.assertNotEqual(json.loads(output.getvalue())["status"], "no_known_matches")

    def test_media_type_and_early_eof_are_not_accepted_as_complete(self):
        raw = b'{"results":[{}]}'
        class Reply(io.BytesIO):
            status = 200
        for mime, length in (("text/plain", len(raw)), ("application/json", len(raw) + 9),
                             ("application/json", -1), ("application/json", 3 * 1024 * 1024)):
            reply = Reply(raw)
            reply.headers = Message()
            reply.headers["Content-Type"] = mime
            reply.headers["Content-Length"] = str(length)
            opener = type("Opener", (), {"open": lambda *_args, **_options: reply})()
            with self.subTest(mime=mime, length=length), patch.object(audit.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    audit.fetch([{"name": "demo", "version": "1"}])

    def test_duplicate_response_fields_are_not_reinterpreted_as_clean(self):
        class Reply(io.BytesIO):
            status = 200
        raw = b'{"results":[{"vulns":[{"id":"GHSA-test-test-test"}]}],"results":[{}]}'
        reply = Reply(raw)
        reply.headers = Message()
        reply.headers["Content-Type"] = "application/json"
        reply.headers["Content-Length"] = str(len(raw))
        opener = type("Opener", (), {"open": lambda *_args, **_options: reply})()
        with patch.object(audit.urllib.request, "build_opener", return_value=opener), self.assertRaises(ValueError):
            audit.fetch([{"name": "demo", "version": "1"}])


if __name__ == "__main__":
    unittest.main()
