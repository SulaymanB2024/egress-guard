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
        with self.assertRaises(ValueError):
            application.action({"action": "block", "host": "analytics.google.com"})
        with self.assertRaises(ValueError):
            application.action({"action": "pause", "minutes": 99999})
        application.action({"action": "pause", "minutes": 5})
        self.assertGreater(json.loads((self.state / "filter-controls.json").read_text())["tracker_pause_until"], 0)
        application.action({"action": "unblock", "host": "tracking.example"})
        self.assertEqual(application.domain("tracking.example")["decision"], "allowed")

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
