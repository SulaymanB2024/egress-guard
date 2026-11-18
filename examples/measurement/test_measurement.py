import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dashboard_insights import HealthCache, Insights, histogram
from domain_rollups import DomainRollups, SCHEMA, store_window
from performance_metrics import DomainFilterMetrics
from tracker_attribution import AttributionIndex


def fixture_attribution():
    return AttributionIndex(
        [("tracker.example", "Fixture owner", "Analytics", "fixture tracker entry"),
         ("content.example", "Fixture owner", "Content", "fixture content entry")],
        lambda host: "example" if host.endswith(".example") else None,
        {"provider": "Fixture", "state": "fresh"},
    )


class InsightsTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.state = Path(self.folder.name)
        self.now = 100000.0
        self.current = {"version": 1, "pid": 2, "started_at_unix_s": 99000,
                        "connections": {"proxy_connect_requests": 40}, "ledger": {"queue_depth": 2},
                        "domain_filter": {"sample_every": 16, "by_hook": {}}}
        self.view = Insights(self.state, lambda host: None if host == "hidden.example" else host,
                             lambda: {"ready": True, "performance": self.current},
                             fixture_attribution(), clock=lambda: self.now)
        self.db = sqlite3.connect(self.state / "ledger.sqlite3")

    def tearDown(self):
        self.db.close()
        self.folder.cleanup()

    def domain_tables(self):
        self.db.executescript("""
            CREATE TABLE domain_windows(id INTEGER PRIMARY KEY,started_at REAL,ended_at REAL,recorded INTEGER,overflow INTEGER);
            CREATE TABLE domain_counts(window_id INTEGER,host TEXT,event TEXT,decision TEXT,count INTEGER);
        """)

    def test_ownership_does_not_turn_content_into_a_tracker_and_partial_windows_are_excluded(self):
        self.domain_tables()
        self.db.execute("INSERT INTO domain_windows VALUES(1,?,?,33,2)", (self.now-60, self.now))
        rows = [(1, "tracker.example", "tls_handshake", "blocked", 3),
                (1, "tracker.example", "tls_handshake", "passed", 2),
                (1, "tracker.example", "http_request", "passed", 4),
                (1, "content.example", "tls_handshake", "passed", 7),
                (1, "unknown.example", "tls_handshake", "passed", 8),
                (1, "hidden.example", "tls_handshake", "passed", 9)]
        self.db.executemany("INSERT INTO domain_counts VALUES(?,?,?,?,?)", rows)
        self.db.execute("INSERT INTO domain_windows VALUES(2,?,?,999,0)", (self.now-3601, self.now-3541))
        self.db.execute("INSERT INTO domain_counts VALUES(2,'tracker.example','tls_handshake','blocked',999)")
        self.db.commit()
        result = self.view.intelligence(1)
        self.assertEqual(result["totals"], {"events": 24, "matched": 9, "blocked": 3, "allowed": 6,
                                           "observed": 0, "unmatched": 8, "owner_known": 16, "other": 15})
        self.assertEqual(result["coverage"]["events_recorded"], 33)
        self.assertEqual(result["coverage"]["overflow_events"], 2)
        self.assertEqual(result["coverage"]["hidden_domains"], 1)
        self.assertEqual(len(result["owners"]), 1)
        self.assertEqual(result["owners"][0]["domains"][0]["tls_handshakes"], 5)
        self.assertEqual(result["window"]["from"], self.now-60)
        self.assertEqual(result["origin_app"], "unknown")

    def test_missing_history_is_collecting_and_read_failure_is_unavailable(self):
        self.assertEqual(self.view.intelligence()["state"], "collecting")
        with patch.object(self.view, "_database", side_effect=sqlite3.OperationalError("busy")):
            self.assertEqual(self.view.intelligence(1)["state"], "unavailable")
        self.assertEqual(self.view.performance()["state"], "available")
        self.assertEqual(self.view.performance()["points"], [])
        with self.assertRaises(ValueError):
            self.view.intelligence(0)

    def test_summary_queries_are_cached_without_reopening_the_database(self):
        with patch.object(self.view, "_database", wraps=self.view._database) as opened:
            self.view.intelligence()
            self.view.intelligence()
            self.assertEqual(opened.call_count, 1)
            self.now += 16
            self.view.intelligence()
            self.assertEqual(opened.call_count, 2)

    def test_rates_break_on_restarts_missing_intervals_and_counter_rollback(self):
        self.db.execute("CREATE TABLE performance_samples(id INTEGER PRIMARY KEY,captured_at REAL,snapshot TEXT)")
        samples = [(-600, 1, 0), (-540, 1, 30), (-480, 2, 2), (-420, 2, 12),
                   (-120, 2, 32), (-60, 2, 30), (0, 2, 40)]
        for index, (offset, pid, count) in enumerate(samples):
            value = {"pid": pid, "started_at_unix_s": 99000 if pid == 2 else 98000,
                     "connections": {"proxy_connect_requests": count}}
            self.db.execute("INSERT INTO performance_samples VALUES(?,?,?)", (index, self.now+offset, json.dumps(value)))
        self.db.commit()
        result = self.view.performance()
        self.assertEqual([row["proxy_connect_per_minute"] for row in result["points"]],
                         [None, 30, None, 10, None, None, 10])
        self.assertEqual(result["timing_period"]["kind"], "since_restart")

    def test_bucket_quantiles_use_sample_counts_and_overflow_maximum(self):
        self.assertEqual(histogram({"upper_bounds": [1, 10], "counts": [7, 2, 1], "max": 25}),
                         {"samples": 10, "p50_upper_ns": 1, "p95_upper_ns": 25, "max_ns": 25})
        self.assertEqual(histogram({"upper_bounds": [10, 1], "counts": [7, 2, 1]})["samples"], 0)

    def test_authenticated_health_is_shared_between_views_for_five_seconds(self):
        now, calls = [0], []
        cache = HealthCache(lambda port: calls.append(port) or {"ready": True}, ports=(9001,), clock=lambda: now[0])
        cache.read(9001)
        cache.read(9001)
        self.assertEqual(calls, [9001])
        now[0] = 5
        cache.read(9001)
        self.assertEqual(calls, [9001, 9001])
        self.assertFalse(cache.read(123)["ready"])


class CollectionTest(unittest.TestCase):
    def test_rollup_bounds_and_overflow_preserve_known_keys(self):
        rollup = DomainRollups()
        self.assertIsNone(rollup.finish_window(1, 2, 1))
        with patch("domain_rollups.MAX_KEYS_PER_WINDOW", 1):
            rollup.record("printer.local", "tls_handshake", False)
            rollup.record("tracker.example", "tls_handshake", True)
            rollup.record("other.example", "http_request", False)
            rollup.record("tracker.example", "tls_handshake", True)
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript(SCHEMA)
        store_window(db, rollup.finish_window(61, 2, 1), max_windows=1)
        self.assertEqual(db.execute("SELECT recorded,overflow FROM domain_windows").fetchone(), (2, 1))
        self.assertEqual(db.execute("SELECT host,count FROM domain_counts").fetchone(), ("tracker.example", 2))
        store_window(db, rollup.finish_window(121, 2, 1), max_windows=1)
        self.assertEqual(db.execute("SELECT count(*) FROM domain_counts").fetchone(), (0,))

    def test_timing_samples_one_in_sixteen_filter_checks(self):
        counters = DomainFilterMetrics()
        with patch("performance_metrics.monotonic_ns", side_effect=[10, 15, 20, 31]):
            for _ in range(17):
                counters.evaluate(lambda host, process: True, "tracker.example", None)
        results = counters.snapshot()
        self.assertEqual((results["decisions"], results["blocked"]), (17, 17))
        self.assertEqual(sum(results["elapsed_ns"]["counts"]), 2)
        self.assertEqual(results["elapsed_ns"]["max"], 11)

    def test_attribution_does_not_cross_shared_or_private_suffix_boundaries(self):
        index = AttributionIndex(
            [("tracker.example", "Fixture owner", "Analytics", "fixture"),
             ("shared.example", "Hosting owner", None, "fixture"),
             ("edge.example", "Hosting owner", None, "fixture"),
             ("ambiguous.example", "First owner", "Analytics", "fixture"),
             ("ambiguous.example", "Second owner", "Advertising", "fixture")],
            lambda host: "shared.example" if host.endswith(".shared.example") else "example",
            {"provider": "Fixture"},
            shared_boundaries=("edge.example",),
        )
        self.assertEqual(index.lookup("sub.tracker.example")["match"], "suffix")
        self.assertEqual(index.lookup("tenant.shared.example")["classification"], "unknown")
        self.assertEqual(index.lookup("tenant.edge.example")["classification"], "unknown")
        self.assertEqual(index.lookup("ambiguous.example")["reason"], "ambiguous_owner")


if __name__ == "__main__":
    unittest.main()
