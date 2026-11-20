from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard.ledger import Ledger, read_activity


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


    def rows(self, sql):
        with sqlite3.connect(self.path) as connection:
            return connection.execute(sql).fetchall()

    def test_aggregate_keeps_counts_and_blocked_hosts_only(self):
        ledger = self.ledger(history="aggregate")
        self.assertTrue(wait_for(ledger.ready))
        for host, decision in (("a.test", "allowed"), ("b.test", "allowed"), ("t.test", "blocked"), ("t.test", "blocked")):
            self.assertTrue(ledger.record(host, decision, "no-match" if decision == "allowed" else "tracker-feed", "connect"))
        ledger.close()
        daily = self.rows("SELECT host, decision, source, count FROM daily ORDER BY decision")
        self.assertEqual(daily, [("", "allowed", "no-match", 2), ("t.test", "blocked", "tracker-feed", 2)])
        self.assertEqual(self.rows("SELECT name FROM sqlite_master WHERE name='events'"), [])
        columns = [row[1] for row in self.rows("PRAGMA table_info(daily)")]
        self.assertNotIn("ts", columns)
        dump = repr(self.rows("SELECT * FROM daily"))
        self.assertNotIn("a.test", dump)
        activity = read_activity(self.path)
        self.assertEqual(activity["history"], "aggregate")
        self.assertTrue(all(event["day_only"] for event in activity["events"]))
        self.assertEqual(sorted(event["count"] for event in activity["events"]), [2, 2])

    def test_none_writes_no_traffic_rows(self):
        ledger = self.ledger(history="none")
        self.assertTrue(wait_for(ledger.ready))
        self.assertTrue(ledger.record("secret-id.test", "blocked", "tracker-feed", "connect"))
        self.assertEqual(ledger.status()["decisions"], 1)
        ledger.close()
        tables = [row[0] for row in self.rows("SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertNotIn("events", tables)
        self.assertNotIn("daily", tables)
        self.assertNotIn("secret-id", repr(self.rows("SELECT * FROM meta")))
        activity = read_activity(self.path)
        self.assertEqual((activity["history"], activity["events"]), ("none", []))

    def test_full_mode_is_unchanged_and_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            Ledger(self.path, history="verbose")
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        ledger.record("one.test", "allowed", "no-match", "http")
        ledger.close()
        self.assertEqual(self.rows("SELECT host FROM events"), [("one.test",)])
        self.assertEqual(read_activity(self.path)["events"][0]["host"], "one.test")

    def test_dropped_events_are_counted_not_stored(self):
        self.path.mkdir()  # the writer cannot open the database, so the queue fills
        ledger = self.ledger(max_queue=2)
        self.assertTrue(ledger.record("one.test", "allowed", "no-match", "http"))
        self.assertTrue(ledger.record("two.test", "allowed", "no-match", "http"))
        self.assertFalse(ledger.record("lost.test", "allowed", "no-match", "http"))
        self.assertFalse(ledger.record("lost2.test", "allowed", "no-match", "http"))
        self.assertFalse(ledger.record("not a host", "allowed", "no-match", "http"))  # invalid, not a drop
        self.assertEqual(ledger.status()["dropped"], 2)
        self.path.rmdir()
        self.assertTrue(wait_for(ledger.ready))
        self.assertTrue(wait_for(lambda: self.path.is_file() and read_activity(self.path)["dropped"] == 2))
        ledger.close()
        self.assertEqual(self.rows("SELECT host FROM events ORDER BY id"), [("one.test",), ("two.test",)])
        self.assertNotIn("lost", repr(self.rows("SELECT * FROM meta")))

    def test_existing_full_database_opens_under_other_modes_and_is_left_alone(self):
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        ledger.record("old.test", "allowed", "no-match", "http")
        ledger.close()
        for mode in ("aggregate", "none"):
            other = Ledger(self.path, history=mode)
            self.assertTrue(wait_for(other.ready))
            other.record("new.test", "blocked", "tracker-feed", "connect")
            other.close()
            self.assertEqual(self.rows("SELECT host FROM events"), [("old.test",)])
            self.assertEqual(read_activity(self.path)["history"], mode)
        self.assertEqual([e["host"] for e in read_activity(self.path)["events"]], [])
        back = self.ledger()
        self.assertTrue(wait_for(back.ready))
        back.close()
        self.assertEqual(read_activity(self.path)["events"][0]["host"], "old.test")


if __name__ == "__main__":
    unittest.main()
