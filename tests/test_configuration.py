import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from egress_guard.cli import main
from egress_guard.config import initialize, load_config
from egress_guard.dashboard_app import Application
from egress_guard.feeds import CachedFeed
from egress_guard.paths import data_dir


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name)
        self.environment = patch.dict(os.environ, {"EGRESS_GUARD_DATA": str(self.state),
                                                   "EGRESS_GUARD_CONFIG": str(self.state / "config.toml")})
        self.environment.start()
        initialize()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def test_initialization_is_private_and_does_not_create_transport_or_tokens(self):
        self.assertEqual(data_dir(), self.state)
        self.assertEqual((self.state / "config.toml").stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(path.name for path in self.state.iterdir()), {"config.toml"})

    def test_new_config_disables_history_without_overriding_explicit_existing_choices(self):
        self.assertEqual(load_config()["logging"]["history"], "none")
        for mode in ("full", "aggregate"):
            (self.state / "config.toml").write_text('[logging]\nhistory = "' + mode + '"\n')
            initialize()
            self.assertEqual(load_config()["logging"]["history"], mode)

    def test_invalid_ports_unknown_settings_and_domain_urls_fail(self):
        for value in ('[proxy]\nport=22', '[proxy]\nbind="0.0.0.0"', '[block]\nhosts=["https://example.com/path"]'):
            (self.state / "config.toml").write_text(value)
            with self.assertRaises(ValueError):
                load_config()

    def test_empty_cache_cannot_start_transport(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(main(["run"]), 1)
        self.assertIn("refresh", errors.getvalue())
        self.assertFalse((self.state / "transport").exists())

    def test_dashboard_mutations_are_scoped_and_timed(self):
        application = Application(self.state, self.state / "config.toml")
        application.action({"action": "block", "host": "tracking.example"})
        self.assertEqual(application.domain("tracking.example")["decision"], "blocked")
        self.assertFalse(application.domain("tracking.example")["can_block"])
        with self.assertRaises(PermissionError):
            application.action({"action": "allow", "host": "tracking.example", "minutes": 5})
        # No analytics host is exempted by default, so it can be blocked manually.
        application.action({"action": "block", "host": "analytics.google.com"})
        self.assertEqual(application.domain("analytics.google.com")["source"], "local-block")
        application.action({"action": "unblock", "host": "analytics.google.com"})
        (self.state / "config.toml").write_text('[block]\nexemption_presets = ["analytics-dashboards"]\n')
        with self.assertRaises(ValueError):
            application.action({"action": "block", "host": "analytics.google.com"})
        with self.assertRaises(ValueError):
            application.action({"action": "pause", "minutes": 99999})
        application.action({"action": "pause", "minutes": 5})
        self.assertGreater(json.loads((self.state / "filter-controls.json").read_text())["tracker_pause_until"], 0)
        application.action({"action": "unblock", "host": "tracking.example"})
        self.assertEqual(application.domain("tracking.example")["decision"], "indeterminate")

    def test_dashboard_sees_same_size_replacement_with_preserved_mtime(self):
        application = Application(self.state, self.state / "config.toml")
        path = self.state / "block.txt"
        path.write_text("first.example\n")
        before = path.stat()
        self.assertEqual(application.domain("first.example")["source"], "local-block")
        replacement = self.state / "block.next"
        replacement.write_text("other.example\n")
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(replacement, path)
        after = path.stat()
        self.assertEqual((after.st_size, after.st_mtime_ns), (before.st_size, before.st_mtime_ns))
        self.assertEqual(application.domain("first.example")["source"], "no-match")
        self.assertEqual(application.domain("other.example")["source"], "local-block")

    def test_dashboard_reports_applied_only_for_the_proxy_reported_revision(self):
        verified = CachedFeed({"one.example", "two.example"}, "digest", 1_700_000_000, None)
        loader = patch("egress_guard.policy.load_cached_feed", return_value=verified)
        loader.start()
        self.addCleanup(loader.stop)
        application = Application(self.state, self.state / "config.toml")
        saved = application.policy().revision
        for reported, applied, state in (
            (None, False, "unknown"),
            ({"revision": "0" * 64, "pending": False, "degraded": False}, False, "degraded"),
            ({"revision": saved, "pending": True, "degraded": False}, False, "degraded"),
            ({"revision": saved, "pending": False, "degraded": False}, True, "active"),
        ):
            with self.subTest(reported=reported), patch(
                "egress_guard.dashboard_app.proxy_health", return_value={"ready": True, "policy": reported}
            ):
                data = application.status()
            self.assertEqual(data["policy"]["saved_revision"], saved)
            self.assertIs(data["policy"]["applied"], applied)
            self.assertEqual(data["proxies"][1]["state"], state)
            if not applied:
                self.assertNotIn("applied by the proxy", data["proxies"][1]["detail"])
        self.assertEqual(data["filters"][0]["published_at"], "2023-11-14T22:13:20+00:00")

    def test_check_is_indeterminate_without_complete_feed_coverage(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["check", "unlisted.example"]), 2)
        result = json.loads(output.getvalue())
        self.assertEqual((result["decision"], result["source"]), ("indeterminate", "no-match"))
        self.assertFalse(result["policy_ready"])
        self.assertEqual(set(result["coverage"].values()), {"missing"})
        self.assertRegex(result["revision"], "^[0-9a-f]{64}$")

    def test_dashboard_lookup_does_not_claim_allow_with_missing_feeds(self):
        application = Application(self.state, self.state / "config.toml")
        result = application.domain("unlisted.example")
        self.assertEqual(result["decision"], "indeterminate")
        self.assertFalse(result["policy_ready"])
        application.action({"action": "block", "host": "blocked.example"})
        self.assertEqual(application.domain("blocked.example")["decision"], "blocked")

    def test_read_only_dashboard_does_not_expose_registration_secrets(self):
        application = Application(self.state, self.state / "config.toml")
        with patch("egress_guard.dashboard_app.proxy_health", return_value={"ready": False}):
            data = application.status()
        self.assertEqual(data["protection"]["state"], "degraded")
        self.assertEqual(data["canaries"][0]["state"], "disabled")
        self.assertNotIn("auth_token", json.dumps(data))
        self.assertFalse((self.state / "canaries.json").exists())

    def test_dashboard_surfaces_canary_history_overflow(self):
        application = Application(self.state, self.state / "config.toml")
        with patch("egress_guard.dashboard_app.proxy_health", return_value={"ready": False}), patch.object(
            application.canaries, "status", return_value=[{"label": "Test placement", "last_success": 1,
                                                         "history_truncated": True}]
        ):
            data = application.status()
        self.assertEqual(data["canaries"][0]["state"], "degraded")
        self.assertIn("1,024", data["canaries"][0]["detail"])

    def test_oversized_prospective_manual_edit_preserves_existing_rules(self):
        application = Application(self.state, self.state / "config.toml")
        path = self.state / "block.txt"
        before = "kept.example\n#" + "x" * (65536 - len("kept.example\n#"))
        path.write_text(before)
        with self.assertRaises(ValueError):
            application.action({"action": "block", "host": "new.example"})
        self.assertEqual(path.read_text(), before)
        self.assertEqual(application.domain("kept.example")["decision"], "blocked")


if __name__ == "__main__":
    unittest.main()
