from pathlib import Path
import sqlite3
import tempfile
import threading
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

    def test_live_none_discards_queued_and_already_dequeued_rows_before_receipt(self):
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        ledger.record("committed.test", "allowed", "no-match", "http")
        self.assertTrue(wait_for(lambda: self.rows("SELECT host FROM events") == [("committed.test",)]))
        entered, dequeued, release = threading.Event(), threading.Event(), threading.Event()
        original = ledger._take_batch

        def held_batch():
            entered.set()
            batch = original()
            if batch and not dequeued.is_set():
                dequeued.set()
                release.wait(3)
            return batch

        with patch.object(ledger, "_take_batch", side_effect=held_batch):
            self.assertTrue(entered.wait(2))
            ledger.record("dequeued-secret.test", "allowed", "no-match", "http")
            self.assertTrue(dequeued.wait(2))
            try:
                ledger.record("queued-secret.test", "blocked", "tracker-feed", "connect")
                self.assertFalse(ledger.reconfigure(history="none", timeout=0))
                self.assertFalse(ledger.status()["applied"])
                self.assertTrue(ledger.record("during-transition.test", "allowed", "no-match", "http"))
            finally:
                release.set()
            self.assertTrue(ledger.reconfigure(history="none"))
        self.assertTrue(ledger.status()["applied"])
        self.assertEqual(ledger.status()["history"], "none")
        ledger.record("after-receipt.test", "blocked", "tracker-feed", "connect")
        ledger.close()
        self.assertEqual(self.rows("SELECT host FROM events"), [("committed.test",)])
        self.assertEqual(self.meta()["history"], "none")

    def test_live_aggregate_then_full_applies_retention_and_queue_bounds(self):
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        self.assertTrue(ledger.reconfigure(history="aggregate", retention_days=2, max_queue=100))
        ledger.record("private-allowed.test", "allowed", "no-match", "http")
        ledger.record("blocked.test", "blocked", "tracker-feed", "connect")
        self.assertTrue(wait_for(lambda: len(self.rows("SELECT * FROM daily")) == 2))
        self.assertEqual(self.rows("SELECT host FROM daily ORDER BY host"), [("",), ("blocked.test",)])
        self.assertEqual(self.meta()["retention_days"], "2")
        self.assertEqual(ledger.status()["max_queue"], 100)
        self.assertTrue(ledger.reconfigure(history="full"))
        ledger.record("new-full.test", "allowed", "no-match", "http")
        ledger.close()
        self.assertEqual(self.rows("SELECT host FROM events"), [("new-full.test",)])

    def test_failed_mode_commit_never_acknowledges_or_resumes_history(self):
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        with patch.object(ledger, "_configure", side_effect=sqlite3.OperationalError("fixture")):
            self.assertFalse(ledger.reconfigure(history="none", timeout=0.2))
            self.assertFalse(ledger.status()["applied"])
            ledger.record("must-not-persist.test", "allowed", "no-match", "http")
        self.assertTrue(ledger.reconfigure(history="none"))
        ledger.close()
        self.assertEqual(self.rows("SELECT host FROM events"), [])

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


    def meta(self):
        return dict(self.rows("SELECT key, value FROM meta"))

    def test_creation_time_is_written_once(self):
        before = int(time.time())
        ledger = self.ledger(retention_days=3)
        self.assertTrue(wait_for(ledger.ready))
        ledger.close()
        created = int(self.meta()["created"])
        self.assertGreaterEqual(created, before)
        self.assertEqual(self.meta()["retention_days"], "3")
        with sqlite3.connect(self.path) as connection:
            connection.execute("UPDATE meta SET value = '123' WHERE key = 'created'")
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        ledger.close()
        self.assertEqual(self.meta()["created"], "123")

    def test_existing_ledger_without_creation_time_keeps_its_oldest_row(self):
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        ledger.close()
        old = int(time.time()) - 3 * 86400
        with sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM meta WHERE key = 'created'")
            connection.execute("INSERT INTO events(ts, host, decision, source, transport) VALUES (?, 'x.test', 'allowed', 'no-match', 'http')", (old,))
        ledger = self.ledger()
        self.assertTrue(wait_for(ledger.ready))
        ledger.close()
        self.assertEqual(self.meta()["created"], str(old))

    def test_capped_aggregate_trim_is_deterministic_and_marks_the_day(self):
        day = int(time.time()) // 86400 * 86400
        with patch("egress_guard.ledger.MAX_EVENTS", 3):
            ledger = self.ledger(history="aggregate")
            self.assertTrue(wait_for(ledger.ready))
            ledger.close()
            with sqlite3.connect(self.path) as connection:
                connection.executemany(
                    "INSERT INTO daily VALUES (?, ?, 'blocked', 'tracker-feed', ?)",
                    [(day - 86400, "old1.test", 5), (day - 86400, "old2.test", 1), (day, "a.test", 1), (day, "b.test", 2)])
            ledger = self.ledger(history="aggregate")
            self.assertTrue(wait_for(ledger.ready))
            self.assertTrue(ledger.record("c.test", "blocked", "tracker-feed", "connect"))
            ledger.close()
        rows = self.rows("SELECT day, host FROM daily ORDER BY day, host")
        self.assertEqual(rows, [(day, "a.test"), (day, "b.test"), (day, "c.test")])
        self.assertEqual(int(self.meta()["trimmed_through"]), day - 86400)


if __name__ == "__main__":
    unittest.main()
