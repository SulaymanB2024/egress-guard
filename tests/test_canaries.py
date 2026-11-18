from email.message import Message
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Event
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from egress_guard import canaries


TOKEN = "z" * 24 + "5"
AUTH = "b" * 32
LABEL = """Desk copy ' " ; $(ignore-me)"""
PLACEMENT = {"label": LABEL, "token": TOKEN, "auth_token": AUTH, "kind": "web"}
OLD = {"time_of_hit": 100, "src_ip": "192.0.2.44", "useragent": "Allowlisted string"}
NEW = {"time_of_hit": 101, "src_ip": "2001:db8::1", "useragent": "https://example.invalid/test"}


@unittest.skipUnless(canaries.fcntl is not None and hasattr(os, "O_NOFOLLOW"), "requires POSIX file locks")
class CanaryMonitorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name)
        self.monitor = canaries.CanaryMonitor(self.state)
        self.now = 1000
        patches = [
            patch.object(canaries, "supports_native_notifications", return_value=True),
            patch.object(canaries.http.client, "HTTPSConnection"),
            patch.object(canaries.subprocess, "run"),
            patch.object(canaries.time, "time", side_effect=lambda: self.now),
        ]
        self.platform, self.connection_type, self.notification, _ = [p.start() for p in patches]
        for patcher in patches:
            self.addCleanup(patcher.stop)
        self.connection = self.connection_type.return_value
        deadline = patch.object(canaries, "ResponseDeadline")
        deadline.start()
        self.addCleanup(deadline.stop)
        self.when_history()

    def when_history(self, *hits, status=200, kind="web", content_type="application/json", raw=None):
        response = MagicMock()
        response.status = status
        response.headers = Message()
        response.headers["Content-Type"] = content_type
        response.read.return_value = raw if raw is not None else json.dumps({
            "history": {"token_type": kind, "hits": hits},
            "canarydrop": {"auth": AUTH, "generated_url": "https://example.invalid/omit"},
        }).encode()
        self.connection.getresponse.return_value.__enter__.return_value = response
        return response

    def test_optional_empty_state_does_no_work(self):
        self.assertEqual(self.monitor.status(), [])
        self.assertEqual(self.monitor.poll_once(), [])
        self.assertEqual(list(self.state.iterdir()), [])
        self.connection_type.assert_not_called()
        self.notification.assert_not_called()
        stop_event = Event()
        stop_event.set()
        self.monitor.run(stop_event)

    def test_import_uses_authenticated_get_and_persists_baseline_privately(self):
        response = self.when_history(OLD)
        status = self.monitor.import_token(PLACEMENT)
        self.assertEqual(status["kind"], "web")
        self.assertEqual(status["last_success"], 1000)
        self.assertEqual(status["next_attempt"], 1060)
        self.assertTrue(status["native_notifications"])
        self.assertEqual(status["events"], 0)
        self.assertNotIn(TOKEN, repr(status))
        self.assertNotIn(AUTH, repr(status))
        self.assertNotIn(OLD["src_ip"], self.monitor.path.read_text())
        self.assertNotIn("https://example.invalid", self.monitor.path.read_text())
        self.assertEqual(self.monitor.path.stat().st_mode & 0o777, 0o600)

        method, endpoint = self.connection.request.call_args.args
        parsed = urlsplit(endpoint)
        self.assertEqual(method, "GET")
        self.assertEqual(parsed.path, canaries.HISTORY_PATH)
        self.assertEqual(parse_qs(parsed.query), {"token": [TOKEN], "auth": [AUTH]})
        self.assertEqual(self.connection_type.call_args.args, (canaries.HOST,))
        self.assertEqual(self.connection_type.call_args.kwargs["timeout"], 15)
        self.assertEqual(self.connection_type.call_args.kwargs["context"].verify_mode.name, "CERT_REQUIRED")
        response.read.assert_called_once_with(8 * 1024 * 1024 + 1)
        self.notification.assert_not_called()

        self.now = 1059
        self.monitor.poll_once()
        self.connection.request.assert_called_once()
        self.now = 1060
        self.monitor.poll_once()
        self.assertEqual(self.connection.request.call_count, 2)
        self.notification.assert_not_called()

    def test_import_rejects_bad_provider_payload_redirect_and_large_response(self):
        cases = (
            {"status": 302},
            {"status": 404},
            {"hits": (dict(OLD, time_of_hit=True),)},
            {"hits": (dict(OLD, src_ip=["wrong type"]),)},
            {"kind": "dns"},
            {"raw": b"[]"},
            {"content_type": "text/html"},
            {"raw": b"x" * (8 * 1024 * 1024 + 1)},
        )
        for case in cases:
            with self.subTest(case=tuple(case)):
                values = dict(case)
                self.when_history(*values.pop("hits", ()), **values)
                with self.assertRaises(canaries.CanaryError) as failure:
                    self.monitor.import_token(PLACEMENT)
                self.assertNotIn(TOKEN, str(failure.exception))
                self.assertNotIn(AUTH, str(failure.exception))
                self.assertFalse(self.monitor.path.exists())
        self.assertEqual(self.connection.request.call_count, len(cases))
        self.notification.assert_not_called()

    def test_new_events_are_batched_and_deduplicated_after_reopen(self):
        self.when_history(OLD)
        self.monitor.import_token(PLACEMENT)
        self.now = 1060
        self.when_history(OLD, NEW, NEW, dict(NEW, time_of_hit=102))
        batch = self.monitor.poll_once()[0]
        self.assertEqual(batch["events"], 2)
        self.assertEqual(batch["notifications"], 1)
        args = self.notification.call_args.args[0]
        self.assertEqual(args[:2], ["/usr/bin/osascript", "-e"])
        self.assertNotIn(LABEL, args[2])
        self.assertEqual(args[3:], ["--", f"Canary triggered: {LABEL} (2 events)", "Egress Guard canary alert"])
        self.assertNotIn(NEW["src_ip"], repr(batch))
        self.assertNotIn(NEW["useragent"], repr(batch))

        self.now = 1120
        reopened = canaries.CanaryMonitor(self.state)
        self.assertEqual(reopened.poll_once()[0]["events"], 2)
        self.notification.assert_called_once()

    def test_failed_delivery_retries_pending_hits_even_if_provider_drops_them(self):
        self.monitor.import_token(PLACEMENT)
        self.now = 1060
        self.when_history(NEW)
        self.notification.side_effect = subprocess.TimeoutExpired("osascript", 15)
        failed = self.monitor.poll_once()[0]
        self.assertEqual(failed["events"], 0)
        self.assertEqual(failed["error"], canaries.NOTIFICATION_ERROR)
        persisted = json.loads(self.monitor.path.read_text())["placements"][0]
        self.assertEqual(len(persisted["pending"]), 1)
        self.assertEqual(persisted["seen"], [])

        self.now = failed["next_attempt"]
        self.notification.side_effect = None
        self.when_history(status=500)
        retried = canaries.CanaryMonitor(self.state).poll_once()[0]
        self.assertEqual(retried["events"], 1)
        self.assertEqual(retried["error"], canaries.PROVIDER_ERROR)
        self.assertEqual(self.notification.call_count, 2)

    def test_duplicate_recent_rows_leave_room_for_an_older_distinct_event(self):
        self.monitor.import_token(PLACEMENT)
        self.now = 1060
        recent = {"time_of_hit": 200}
        older = {"time_of_hit": 100}
        self.when_history(*([recent] * 1024), older)
        report = self.monitor.poll_once()[0]
        self.assertEqual(report["events"], 2)
        self.assertFalse(report["history_truncated"])
        self.assertEqual(report["notifications"], 1)

    def test_large_history_reports_truncation_and_selects_latest_distinct_events(self):
        events = [{"time_of_hit": timestamp} for timestamp in range(1, 1026)]
        self.when_history(events[-1], *reversed(events))
        report = self.monitor.import_token(PLACEMENT)
        self.assertTrue(report["history_truncated"])
        self.assertEqual(report["events"], 0)
        seen = json.loads(self.monitor.path.read_text())["placements"][0]["seen"]
        self.assertEqual(len(seen), 1024)
        self.assertEqual(seen[-1], canaries._validated_event(events[-1], "web")[1])
        self.assertNotIn(canaries._validated_event(events[0], "web")[1], seen)

        self.now = report["next_attempt"]
        self.when_history(*events, events[-1])
        report = self.monitor.poll_once()[0]
        self.assertTrue(report["history_truncated"])
        self.assertEqual(report["events"], 0)
        self.notification.assert_not_called()

        self.now = report["next_attempt"]
        self.when_history(*events[1:], {"time_of_hit": 1026})
        report = self.monitor.poll_once()[0]
        self.assertTrue(report["history_truncated"])
        self.assertEqual(report["events"], 1)
        self.notification.assert_called_once()

    def test_large_history_rejects_malformed_fields_even_outside_recent_window(self):
        events = [{"time_of_hit": timestamp} for timestamp in range(2, 1026)]
        self.when_history(*events, {"time_of_hit": 1, "src_ip": ["invalid field"]})
        with self.assertRaisesRegex(canaries.CanaryError, "invalid data"):
            self.monitor.import_token(PLACEMENT)
        self.assertFalse(self.monitor.path.exists())
        self.notification.assert_not_called()

    def test_truncated_history_keeps_pending_event_through_eviction_and_reappearance(self):
        events = [{"time_of_hit": timestamp} for timestamp in range(1, 1026)]
        self.when_history(*events)
        report = self.monitor.import_token(PLACEMENT)
        new_event = {"time_of_hit": 1026}
        self.now = report["next_attempt"]
        self.when_history(*events, new_event)
        self.notification.side_effect = subprocess.TimeoutExpired("osascript", 15)
        report = self.monitor.poll_once()[0]
        self.assertEqual(report["events"], 0)

        self.now = report["next_attempt"]
        self.when_history(*events)
        self.notification.side_effect = None
        report = self.monitor.poll_once()[0]
        self.assertEqual(report["events"], 1)
        self.assertTrue(report["history_truncated"])

        self.now = report["next_attempt"]
        self.when_history(*events, new_event)
        report = canaries.CanaryMonitor(self.state).poll_once()[0]
        self.assertEqual(report["events"], 1)
        self.assertEqual(self.notification.call_count, 2)

    def test_backoff_and_one_health_alert_until_provider_recovers(self):
        self.monitor.import_token(PLACEMENT)
        self.when_history(status=503)
        self.now = 1060
        for failures, delay in enumerate((120, 240, 480, 900), start=1):
            report = self.monitor.poll_once()[0]
            self.assertEqual(report["failures"], failures)
            self.assertEqual(report["next_attempt"] - self.now, delay)
            self.assertEqual(report["last_poll"], self.now)
            self.assertEqual(report["last_success"], 1000)
            self.assertEqual(self.notification.call_count, int(failures >= 3))
            self.now = report["next_attempt"]
        self.when_history()
        success = self.monitor.poll_once()[0]
        self.assertEqual(success["failures"], 0)
        self.assertIsNone(success["error"])
        self.assertEqual(success["last_success"], success["last_poll"])

    def test_refuses_unsafe_labels_duplicate_placement_and_unsupported_platform(self):
        for label in (TOKEN, AUTH, "https://example.invalid/a", "Host 192.0.2.4",
                      "Host [2001:db8::1]", "a" * 81, "\nInjected"):
            with self.subTest(label=label):
                with self.assertRaises(canaries.CanaryError):
                    self.monitor.import_token(dict(PLACEMENT, label=label))
        self.connection_type.assert_not_called()
        self.monitor.import_token(PLACEMENT)
        with self.assertRaisesRegex(canaries.CanaryError, "already configured"):
            self.monitor.import_token(dict(PLACEMENT, label="Other"))
        with self.assertRaisesRegex(canaries.CanaryError, "already configured"):
            self.monitor.import_token(dict(PLACEMENT, token="q" * 25))
        self.platform.return_value = False
        self.assertFalse(self.monitor.status()[0]["native_notifications"])
        with self.assertRaisesRegex(canaries.CanaryError, "require macOS"):
            self.monitor.poll_once()
        self.connection.request.assert_called_once()

    def test_rejects_placement_above_limit_before_fetching_it(self):
        self.monitor.import_token(PLACEMENT)
        with patch.object(canaries, "MAX_PLACEMENTS", 1):
            with self.assertRaisesRegex(canaries.CanaryError, "up to 32"):
                self.monitor.import_token(dict(PLACEMENT, label="Another desk", token="q" * 25))
        self.connection.request.assert_called_once()
        self.assertEqual(len(self.monitor.status()), 1)

    def test_refuses_linked_state_and_provider_errors_never_leak_url_or_credentials(self):
        target = self.state / "unrelated"
        target.write_text("Leave this intact.")
        self.monitor.path.symlink_to(target)
        with self.assertRaisesRegex(canaries.CanaryError, "private canary state"):
            self.monitor.import_token(PLACEMENT)
        self.assertEqual(target.read_text(), "Leave this intact.")
        self.connection_type.assert_not_called()

        self.monitor.path.unlink()
        self.connection.request.side_effect = OSError(f"https://example.invalid/{TOKEN}?auth={AUTH}")
        with self.assertRaises(canaries.CanaryError) as failure:
            self.monitor.import_token(PLACEMENT)
        self.assertEqual(str(failure.exception), canaries.PROVIDER_ERROR)
        self.assertTrue(failure.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
