from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard.ledger import Ledger


def wait_for(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class LedgerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "events.sqlite3"

    def ledger(self, **kwargs):
        ledger = Ledger(self.path, **kwargs)
        self.addCleanup(ledger.close)
        return ledger

    def test_readiness_and_safe_schema(self):
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        self.assertFalse(ledger.record("https://example.test?q=secret", "blocked", "tracker-feed", "connect"))
        self.assertFalse(ledger.record("example.test", "blocked", "untrusted content", "http"))
        self.assertFalse(ledger.record("example.test", "blocked", "tracker-feed", "path"))
        self.assertTrue(ledger.record("EXAMPLE.test.", "blocked", "tracker-feed", "connect"))
        ledger.close()
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute("SELECT host, decision, source, transport FROM events").fetchall()
        self.assertEqual(rows, [("example.test", "blocked", "tracker-feed", "connect")])

    def test_recovers_from_path_failure_and_preserves_accepted_rows(self):
        self.path.mkdir()
        ledger = self.ledger(max_queue=2)
        self.assertTrue(ledger.record("one.test", "allowed", "no-match", "http"))
        self.assertTrue(ledger.record("two.test", "allowed", "no-match", "http"))
        self.assertFalse(ledger.record("three.test", "allowed", "no-match", "http"))
        self.assertFalse(ledger.ready())
        self.path.rmdir()
        self.assertTrue(wait_for(ledger.ready))
        ledger.close()
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute("SELECT host FROM events ORDER BY id").fetchall()
        self.assertEqual(rows, [("one.test",), ("two.test",)])

    def test_enforces_row_and_time_limits(self):
        ledger = self.ledger(retention_days=1)
        self.assertTrue(wait_for(ledger.ready))
        ledger.close()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT INTO events(ts, host, decision, source, transport) VALUES (?, ?, ?, ?, ?)",
                (int(time.time()) - 100_000, "expired.test", "allowed", "no-match", "http"),
            )
        with patch("egress_guard.ledger.MAX_EVENTS", 2):
            ledger = self.ledger(retention_days=1)
            self.assertTrue(wait_for(ledger.ready))
            for host in ("one.test", "two.test", "three.test"):
                self.assertTrue(ledger.record(host, "allowed", "no-match", "connect"))
            ledger.close()
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute("SELECT host FROM events ORDER BY id").fetchall()
        self.assertEqual(rows, [("two.test",), ("three.test",)])


if __name__ == "__main__":
    unittest.main()
