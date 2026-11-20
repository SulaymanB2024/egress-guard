"""Outcome summaries are exact counts of ledger rows in every history mode."""
from datetime import datetime, timedelta
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from egress_guard.dashboard_http import ProtectionServer
from egress_guard.insights import CATEGORIES, category, read_insights

NOW = datetime(2026, 11, 20, 15, 30).astimezone().timestamp()
TODAY = datetime(2026, 11, 20).astimezone().timestamp()


def ledger(path, history, rows=()):
    connection = sqlite3.connect(path)
    with connection:
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO meta VALUES ('history', ?)", (history,))
        connection.execute("INSERT INTO meta VALUES ('dropped', '3')")
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
        self.assertEqual(today, {"threats": 1, "ads": 2, "cname": 1, "manual": 1, "other": 1})
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
