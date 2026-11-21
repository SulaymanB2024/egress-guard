"""Outcome summaries are exact counts of ledger rows in every history mode."""
from datetime import datetime, timedelta
import http.client
import json
from pathlib import Path
import sqlite3
import os
import tempfile
import threading
import time
import unittest

from egress_guard.dashboard_http import ProtectionServer
from egress_guard.insights import CATEGORIES, category, read_insights

NOW = datetime(2026, 11, 20, 15, 30).astimezone().timestamp()
TODAY = datetime(2026, 11, 20).astimezone().timestamp()


def ledger(path, history, rows=(), created=0, retention=None, extra=()):
    connection = sqlite3.connect(path)
    with connection:
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO meta VALUES ('history', ?)", (history,))
        connection.execute("INSERT INTO meta VALUES ('dropped', '3')")
        if created is not None:  # None imitates a ledger made before the creation time was recorded.
            connection.execute("INSERT INTO meta VALUES ('created', ?)", (str(created),))
        if retention is not None:
            connection.execute("INSERT INTO meta VALUES ('retention_days', ?)", (str(retention),))
        connection.executemany("INSERT INTO meta VALUES (?, ?)", extra)
        if history == "full":
            connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, host TEXT NOT NULL,"
                               " decision TEXT NOT NULL, source TEXT NOT NULL, transport TEXT NOT NULL)")
            connection.executemany("INSERT INTO events(ts,host,decision,source,transport) VALUES (?,?,?,?,'connect')", rows)
        elif history == "aggregate":
            connection.execute("CREATE TABLE daily (day INTEGER NOT NULL, host TEXT NOT NULL, decision TEXT NOT NULL,"
                               " source TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (day, host, decision, source))")
            connection.executemany("INSERT INTO daily VALUES (?,?,?,?,?)", rows)
    connection.close()


class InsightsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "events.sqlite3"

    def tearDown(self):
        self.temporary.cleanup()

    def test_missing_ledger_is_an_empty_full_history(self):
        result = read_insights(self.path, NOW)
        self.assertEqual(result["history"], "full")
        self.assertEqual(result["today"]["blocked"], 0)
        self.assertEqual(len(result["hourly"]), 24)
        self.assertEqual(len(result["daily"]), 7)
        self.assertEqual(result["top_blocked"], {"today": [], "week": []})
        self.assertFalse(self.path.exists())

    def test_full_history_counts_today_yesterday_and_categories(self):
        hour = 3600
        rows = [
            (TODAY + 1 * hour, "tracker.example", "blocked", "tracker-feed"),
            (TODAY + 2 * hour, "tracker.example", "blocked", "tracker-feed"),
            (TODAY + 3 * hour, "bad.example", "blocked", "phishing"),
            (TODAY + 4 * hour, "cloak.example", "blocked", "cname-feed"),
            (TODAY + 5 * hour, "mine.example", "blocked", "local-block"),
            (TODAY + 6 * hour, "odd.example", "blocked", "some-future-source"),
            (TODAY + 7 * hour, "ok.example", "allowed", "no-match"),
            (TODAY + 8 * hour, "ok.example", "allowed", "no-match"),
            # Yesterday: one before this time of day, one after it.
            (TODAY - 86400 + 2 * hour, "tracker.example", "blocked", "tracker-feed"),
            (TODAY - 86400 + 20 * hour, "tracker.example", "blocked", "tracker-feed"),
            (TODAY - 3 * 86400, "malware.example", "blocked", "threat-intel"),
        ]
        ledger(self.path, "full", rows)
        result = read_insights(self.path, NOW)
        self.assertEqual(result["dropped"], 3)
        self.assertEqual(result["today"]["blocked"], 6)
        self.assertEqual(result["today"]["allowed"], 2)
        self.assertEqual(result["yesterday"]["blocked"], 2)
        self.assertEqual(result["same_time_yesterday"]["blocked"], 1)
        today = {item["id"]: item["blocked"] for item in result["categories"]["today"]}
        self.assertEqual(today, {"threats": 1, "ads": 2, "cname": 1, "doh": 0, "manual": 1, "other": 1})
        self.assertEqual(result["threats"]["today"], 1)
        self.assertEqual(result["threats"]["week"], 2)
        self.assertEqual([item["host"] for item in result["threats"]["recent"]], ["bad.example", "malware.example"])
        self.assertEqual(result["top_blocked"]["today"][0], {**result["top_blocked"]["today"][0],
                                                             "host": "tracker.example", "count": 2, "category": "ads"})
        self.assertEqual(sum(day["blocked"] for day in result["daily"]), 9)
        self.assertEqual(sum(hour["blocked"] + hour["allowed"] for hour in result["hourly"]), 8 + 1)
        self.assertFalse(result["coverage"]["capped"])

    def test_aggregate_history_uses_utc_days_without_hours(self):
        day = int(NOW) // 86400 * 86400
        ledger(self.path, "aggregate", [(day, "tracker.example", "blocked", "tracker-feed", 5),
                                        (day, "", "allowed", "no-match", 40),
                                        (day - 86400, "tracker.example", "blocked", "tracker-feed", 2)])
        result = read_insights(self.path, NOW)
        self.assertEqual(result["day_basis"], "utc")
        self.assertIsNone(result["hourly"])
        self.assertEqual(result["today"], {**result["today"], "blocked": 5, "allowed": 40})
        self.assertEqual(result["yesterday"]["blocked"], 2)
        self.assertEqual(result["top_blocked"]["week"][0]["count"], 7)
        self.assertTrue(all(item["host"] for item in result["top_blocked"]["week"]))

    def test_no_history_reports_nothing(self):
        ledger(self.path, "none")
        result = read_insights(self.path, NOW)
        self.assertEqual(result["history"], "none")
        self.assertIsNone(result["today"])
        self.assertIsNone(result["daily"])

    def test_reader_never_writes(self):
        ledger(self.path, "full", [(TODAY, "a.example", "blocked", "tracker-feed")])
        self.path.chmod(0o400)
        read_insights(self.path, NOW)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o400)

    def test_unknown_sources_fall_back_to_other(self):
        self.assertEqual(category("malware"), "threats")
        self.assertEqual(category("doh"), "other")
        self.assertEqual(category(None), "other")
        self.assertIn("other", CATEGORIES)


class TimeZoneCase(unittest.TestCase):
    zone = "America/New_York"

    def setUp(self):
        self.old_zone = os.environ.get("TZ")
        os.environ["TZ"] = self.zone
        time.tzset()
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "events.sqlite3"

    def tearDown(self):
        self.temporary.cleanup()
        if self.old_zone is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self.old_zone
        time.tzset()

    @staticmethod
    def at(*parts):
        return datetime(*parts).astimezone().timestamp()


class DaylightSavingTest(TimeZoneCase):
    def test_fall_back_days_hours_and_same_time_yesterday(self):
        now = self.at(2026, 11, 2, 12)
        rows = [(self.at(2026, 11, 1, 0, 30), "a.test", "blocked", "tracker-feed"),
                (self.at(2026, 10, 27, 0, 30), "b.test", "blocked", "tracker-feed"),
                (self.at(2026, 11, 1, 11, 59), "c.test", "blocked", "tracker-feed"),
                (self.at(2026, 11, 1, 12, 1), "d.test", "blocked", "tracker-feed"),
                (self.at(2026, 11, 2, 1, 0), "e.test", "blocked", "tracker-feed")]
        ledger(self.path, "full", rows, created=self.at(2026, 10, 1), retention=30)
        result = read_insights(self.path, now)
        days = {item["day"]: item for item in result["daily"]}
        self.assertEqual(days["2026-10-27"]["blocked"], 1)
        self.assertEqual(days["2026-10-31"]["blocked"], 0)
        self.assertEqual(days["2026-11-01"]["blocked"], 3)
        self.assertEqual(result["yesterday"]["blocked"], 3)
        # Same wall-clock time yesterday (12:00), which is 25 hours earlier, so the 12:01 event is out.
        self.assertEqual(result["same_time_yesterday"]["blocked"], 2)
        self.assertEqual(result["today"]["blocked"], 1)
        self.assertEqual(sum(item["blocked"] for item in result["daily"]), 5)
        self.assertTrue(all(item["complete"] for item in result["daily"]))

    def test_fall_back_day_has_no_double_counted_hour(self):
        # 2026-11-01 has 25 hours; the 01:00 hour happens twice.
        first, second = self.at(2026, 11, 1, 1, 30), self.at(2026, 11, 1, 1, 30) + 3600
        rows = [(first, "a.test", "blocked", "tracker-feed"), (second, "b.test", "blocked", "tracker-feed")]
        ledger(self.path, "full", rows, created=self.at(2026, 10, 1), retention=30)
        result = read_insights(self.path, self.at(2026, 11, 1, 23, 30))
        self.assertEqual(sum(item["blocked"] for item in result["hourly"]), 2)
        self.assertEqual(result["today"]["blocked"], 2)
        self.assertEqual(result["daily"][-1]["blocked"], 2)

    def test_spring_forward_day_is_23_hours(self):
        # 2026-03-08: 02:00 does not exist.
        now = self.at(2026, 3, 9, 12)
        rows = [(self.at(2026, 3, 8, 0, 30), "a.test", "blocked", "tracker-feed"),
                (self.at(2026, 3, 8, 3, 30), "b.test", "blocked", "tracker-feed"),
                (self.at(2026, 3, 8, 23, 30), "c.test", "blocked", "tracker-feed"),
                (self.at(2026, 3, 9, 0, 30), "d.test", "blocked", "tracker-feed"),
                (self.at(2026, 3, 3, 0, 30), "e.test", "blocked", "tracker-feed")]
        ledger(self.path, "full", rows, created=self.at(2026, 2, 1), retention=30)
        result = read_insights(self.path, now)
        days = {item["day"]: item["blocked"] for item in result["daily"]}
        self.assertEqual(days["2026-03-08"], 3)
        self.assertEqual(days["2026-03-09"], 1)
        self.assertEqual(days["2026-03-03"], 1)
        self.assertEqual(result["yesterday"]["blocked"], 3)
        self.assertEqual(result["same_time_yesterday"]["blocked"], 2)
        # The last 24 hours start at 13:00 on the 8th, so both late events count once.
        self.assertEqual(sum(item["blocked"] for item in result["hourly"]), 2)

    def test_spring_forward_hourly_buckets_across_the_gap(self):
        now = self.at(2026, 3, 8, 6)
        rows = [(self.at(2026, 3, 8, 1, 30), "a.test", "blocked", "tracker-feed"),
                (self.at(2026, 3, 8, 3, 30), "b.test", "blocked", "tracker-feed")]
        ledger(self.path, "full", rows, created=self.at(2026, 2, 1), retention=30)
        result = read_insights(self.path, now)
        self.assertEqual(sum(item["blocked"] for item in result["hourly"]), 2)
        self.assertEqual(len(result["hourly"]), 24)
        self.assertEqual(result["today"]["blocked"], 2)


class SourceCategoryTest(unittest.TestCase):
    def test_every_policy_source_has_a_known_dashboard_category(self):
        from egress_guard.policy import CATEGORIES as POLICY
        for source in POLICY:
            self.assertIn(category(source), CATEGORIES)

    def test_new_sources_map_as_designed(self):
        for source in ("threat-intel", "malware-feed", "phishing-feed", "lookalike-domain"):
            self.assertEqual(category(source), "threats", source)
        self.assertEqual(category("doh-feed"), "doh")
        self.assertEqual(category("tracker-feed"), "ads")
        self.assertEqual(category("cname-feed"), "cname")
        self.assertEqual(category("local-block"), "manual")
        for source in ("safety-list", "ip-literal", "nonstandard-port", "no-match", "brand-new-source", None, 7):
            self.assertEqual(category(source), "other", source)

    def test_new_sources_are_counted_and_listed_as_threats(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            rows = [(TODAY + 3600, "m.test", "blocked", "malware-feed"), (TODAY + 7200, "p.test", "blocked", "phishing-feed"),
                    (TODAY + 10800, "l.test", "blocked", "lookalike-domain"), (TODAY + 14400, "d.test", "blocked", "doh-feed"),
                    (TODAY + 18000, "s.test", "allowed", "safety-list")]
            ledger(path, "full", rows, created=TODAY - 86400, retention=7)
            result = read_insights(path, NOW)
        today = {item["id"]: item["blocked"] for item in result["categories"]["today"]}
        self.assertEqual(today["threats"], 3)
        self.assertEqual(today["doh"], 1)
        self.assertEqual(result["threats"]["today"], 3)
        self.assertEqual({item["source"] for item in result["threats"]["recent"]},
                         {"malware-feed", "phishing-feed", "lookalike-domain"})
        self.assertEqual(result["source_categories"]["lookalike-domain"], "threats")
        self.assertEqual(result["source_categories"]["doh-feed"], "doh")
        self.assertIn({"id": "doh", "label": "Encrypted DNS servers"}, result["categories_list"])


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "events.sqlite3"
        self.addCleanup(self.temporary.cleanup)

    def flags(self, result):
        return [item["complete"] for item in result["daily"]]

    def test_retention_of_one_day_marks_older_days_incomplete(self):
        rows = [(TODAY + 3600, "a.test", "blocked", "tracker-feed")]
        ledger(self.path, "full", rows, created=TODAY - 30 * 86400, retention=1)
        result = read_insights(self.path, NOW)
        self.assertEqual(self.flags(result), [False] * 6 + [True])
        self.assertFalse(result["yesterday"]["complete"])
        self.assertFalse(result["same_time_yesterday"]["complete"])
        self.assertTrue(result["hourly"][-1]["complete"])

    def test_fresh_ledger_does_not_claim_earlier_days(self):
        created = TODAY + 2 * 3600
        ledger(self.path, "full", [(created + 60, "a.test", "blocked", "tracker-feed")], created=created, retention=7)
        result = read_insights(self.path, NOW)
        self.assertEqual(self.flags(result), [False] * 7)
        self.assertFalse(result["yesterday"]["complete"])
        self.assertEqual(result["today"]["blocked"], 1)
        self.assertTrue(result["hourly"][-1]["complete"])
        # The next day is fully covered.
        later = read_insights(self.path, NOW + 86400)
        self.assertEqual(self.flags(later)[-2:], [False, True])

    def test_covered_ledger_is_complete(self):
        ledger(self.path, "full", [(TODAY - 86400 + 3600, "a.test", "blocked", "tracker-feed")],
               created=TODAY - 10 * 86400, retention=7)
        result = read_insights(self.path, NOW)
        self.assertEqual(self.flags(result), [True] * 7)
        self.assertTrue(result["same_time_yesterday"]["complete"])

    def test_legacy_ledger_uses_oldest_row(self):
        rows = [(TODAY - 3 * 86400 + 3600, "a.test", "blocked", "tracker-feed")]
        ledger(self.path, "full", rows, created=None)
        result = read_insights(self.path, NOW)
        self.assertEqual(self.flags(result), [False, False, False, False, True, True, True])

    def test_legacy_ledger_without_rows_is_unknown(self):
        ledger(self.path, "full", [], created=None)
        result = read_insights(self.path, NOW)
        self.assertEqual(self.flags(result), [False] * 7)
        self.assertFalse(result["yesterday"]["complete"])

    def test_capped_aggregate_marks_trimmed_days_incomplete(self):
        day = int(TODAY) // 86400 * 86400
        rows = [(day - 86400, "a.test", "blocked", "tracker-feed", 2), (day, "b.test", "blocked", "tracker-feed", 1)]
        ledger(self.path, "aggregate", rows, created=day - 20 * 86400, retention=30,
               extra=[("trimmed_through", str(day - 86400))])
        result = read_insights(self.path, day + 3600)
        self.assertEqual(self.flags(result)[-2:], [False, True])
        self.assertFalse(result["yesterday"]["complete"])
        self.assertEqual(result["today"]["blocked"], 1)

    def test_aggregate_without_creation_time_falls_back_to_oldest_row(self):
        day = int(TODAY) // 86400 * 86400
        ledger(self.path, "aggregate", [(day - 2 * 86400, "a.test", "blocked", "tracker-feed", 1)], created=None)
        result = read_insights(self.path, day + 3600)
        self.assertEqual(self.flags(result), [False, False, False, False, True, True, True])

    def test_aggregate_retention_one(self):
        day = int(TODAY) // 86400 * 86400
        ledger(self.path, "aggregate", [(day, "a.test", "blocked", "tracker-feed", 1)],
               created=day - 20 * 86400, retention=1)
        result = read_insights(self.path, day + 3600)
        self.assertEqual(self.flags(result), [False] * 6 + [True])


class InsightsEndpointTest(unittest.TestCase):
    class Application:
        def insights(self):
            return {"history": "full", "today": {"blocked": 1, "allowed": 2}}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        (Path(self.temporary.name) / "index.html").write_text("<!doctype html>")
        self.server = ProtectionServer(self.Application(), "x" * 43, port=0, static=Path(self.temporary.name))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def get(self, headers):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request("GET", "/api/insights", headers={"Origin": self.server.origin, **headers})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def test_requires_a_session_and_same_origin(self):
        self.assertEqual(self.get({})[0], 401)
        self.assertEqual(self.get({"Origin": "http://evil.example"})[0], 403)
        session = self.server.new_session()
        status, body = self.get({"Authorization": "Bearer " + session})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["today"]["blocked"], 1)
        self.assertEqual(self.get({"Authorization": "Bearer " + session, "Sec-Fetch-Site": "cross-site"})[0], 403)


if __name__ == "__main__":
    unittest.main()
