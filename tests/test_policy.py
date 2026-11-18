import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard.policy import MAX_CONTROL_BYTES, Policy, normalize_host


class PolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.config = {
            "block": {
                "hosts": ["manual.example", "invalid/url"],
                "allow": ["tracker.example", "danger.example", "manual.example"],
                "dashboard_hosts": ["dashboard.example", "dashboard.danger.example"],
            }
        }
        snapshots = {
            "threat": {"danger.example"},
            "tracker": {"tracker.example", "dashboard.example", "analytics.example"},
            "cname": {"masked.example", "dashboard.danger.example", "manual.example"},
        }
        with patch("egress_guard.policy.read_cached_feed", side_effect=lambda _, feed: snapshots[feed.category]):
            self.policy = Policy(self.config, self.state)

    def test_priorities_and_match_boundaries(self):
        self.assertEqual(self.policy.decision("A.Danger.Example."), {
            "decision": "blocked", "source": "threat-intel",
            "matched_domain": "danger.example", "can_allow": False,
        })
        self.assertEqual(self.policy.decision("dashboard.danger.example")["source"], "threat-intel")
        self.assertEqual(self.policy.decision("manual.example")["source"], "local-block")
        self.assertEqual(self.policy.decision("a.tracker.example")["source"], "local-allow")
        self.assertEqual(self.policy.decision("dashboard.example")["source"], "dashboard-exception")
        self.assertEqual(self.policy.decision("a.dashboard.example")["source"], "tracker-feed")
        self.assertEqual(self.policy.decision("notdanger.example")["source"], "no-match")
        self.assertEqual(self.policy.decision("danger.example.other")["source"], "no-match")
        self.assertEqual(self.policy.decision("masked.example")["source"], "cname-feed")
        self.assertEqual(self.policy.decision("a.masked.example")["source"], "no-match")

    def test_temporary_exception_is_exact_and_bounded(self):
        (self.state / "tracker-exceptions.json").write_text(json.dumps({
            "analytics.example": 1001,
            "danger.example": 1001,
            "masked.example": 1000 + 86_401,
        }))
        self.policy.reload_controls()
        with patch("egress_guard.policy.time.time", return_value=1000):
            self.assertEqual(self.policy.decision("analytics.example")["source"], "temporary-exception")
            self.assertTrue(self.policy.decision("sub.analytics.example")["can_allow"])
            self.assertTrue(self.policy.decision("masked.example")["can_allow"])
            self.assertFalse(self.policy.decision("danger.example")["can_allow"])
        with patch("egress_guard.policy.time.time", return_value=1001):
            self.assertEqual(self.policy.decision("analytics.example")["source"], "tracker-feed")

    def test_pause_cannot_bypass_threats_or_manual_blocks(self):
        (self.state / "filter-controls.json").write_text(json.dumps({
            "tracker_pause_until": time.time() + 120,
        }))
        self.policy.reload_controls()
        self.assertEqual(self.policy.decision("analytics.example")["source"], "tracker-paused")
        self.assertEqual(self.policy.decision("masked.example")["source"], "tracker-paused")
        self.assertEqual(self.policy.decision("danger.example")["source"], "threat-intel")
        self.assertEqual(self.policy.decision("manual.example")["source"], "local-block")
        (self.state / "filter-controls.json").write_text("{" + " " * 65_537 + "}")
        self.policy.reload_controls()
        self.assertEqual(self.policy.decision("masked.example")["source"], "cname-feed")

    def test_rule_file_distinguishes_missing_empty_and_invalid(self):
        path = self.state / "block.txt"
        with patch("egress_guard.policy.read_cached_feed", return_value=set()):
            self.assertEqual(Policy({}, self.state).decision("local.example")["source"], "no-match")
            path.write_bytes(b"")
            self.assertEqual(Policy({}, self.state).decision("local.example")["source"], "no-match")
            path.write_text("# custom block\nlocal.example # exact domain and descendants\n")
            self.assertEqual(Policy({}, self.state).decision("a.local.example")["source"], "local-block")
            for data, message in (
                (b"#" * (MAX_CONTROL_BYTES + 1), "64 KiB"),
                (b"local.example\n\xff", "UTF-8"),
                (b"local.example\ninvalid/url\n", "invalid domain on line 2"),
            ):
                with self.subTest(message=message):
                    path.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, message):
                        Policy({}, self.state)
            with patch.object(Path, "open", side_effect=PermissionError):
                with self.assertRaisesRegex(ValueError, "block.txt could not be read"):
                    Policy({}, self.state)

    def test_malformed_request_targets_and_ip_literals(self):
        for value in ("abc../", "*.example", "example..", "https://danger.example", "a" * 254, "日本.example"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_host(value))
                self.assertEqual(self.policy.decision(value)["source"], "invalid-host")
        self.assertEqual(normalize_host("[2001:DB8::1]"), "2001:db8::1")
        self.assertEqual(self.policy.decision("1.2.3.4")["source"], "no-match")
        self.assertEqual(normalize_host("xn--wgv71a.example."), "xn--wgv71a.example")


if __name__ == "__main__":
    unittest.main()
