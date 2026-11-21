from dataclasses import replace
import datetime as dt
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

from egress_guard import feeds
from egress_guard.config import load_config
from egress_guard.policy import Policy

_real_selected_feeds = feeds.selected_feeds


def fixture_feeds():
    return tuple(replace(feed, minimum=2) for feed in feeds.selected_feeds({}))


class FeedTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.sources = fixture_feeds()
        patched = patch("egress_guard.feeds.selected_feeds", return_value=self.sources)
        patched.start()
        self.addCleanup(patched.stop)

    def test_exact_source_discards_wildcards_and_rejects_non_domain_payloads(self):
        records = b"""# Example fixture
*.wildcard.test
bad-label-.test
https://invalid.test/path
UPPERCASE.TEST.
valid.test
"""
        exact = next(feed for feed in self.sources if feed.exact)
        names, published = feeds._parse_feed(records, exact)
        self.assertEqual(names, {"uppercase.test", "valid.test"})
        self.assertIsNone(published)
        for body in (b"<html>service unavailable</html>\n", b"one.test\ntwo.test", b"\xffbad.test\n"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                feeds._parse_feed(body, self.sources[0])

    def test_preserves_previous_good_cache_independently_of_other_feeds(self):
        initial = b"# Last modified: 16 Nov 2026 01:00 UTC\none.test\ntwo.test\n"
        with patch("egress_guard.feeds._download", return_value=initial):
            first = feeds.update_feeds(self.state, {})
        path = self.sources[0].path(self.state)
        snapshot = path.read_bytes()
        self.assertTrue(first["ok"])
        self.assertEqual(first["feeds"][0]["entries"], 2)

        def download(feed):
            if feed == self.sources[0]:
                return b"<html>503</html>\n"
            return b"three.test\nfour.test\n"

        with patch("egress_guard.feeds._download", side_effect=download):
            result = feeds.update_feeds(self.state, {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["feeds"][0]["status"], "using-previous")
        self.assertEqual(path.read_bytes(), snapshot)
        self.assertEqual(feeds.read_cached_feed(self.state, self.sources[0]), {"one.test", "two.test"})
        # A previously dated feed cannot silently roll back or drop its source clock.
        self.assertEqual(result["feeds"][1]["status"], "using-previous")

    def test_oversized_feed_and_corrupt_cache_are_unusable(self):
        with patch("egress_guard.feeds.MAX_FEED_BYTES", 15), self.assertRaises(ValueError):
            feeds._parse_feed(b"hello.test\nworld.test\n", self.sources[0])
        with patch("egress_guard.feeds._download", return_value=b"one.test\ntwo.test\n"):
            feeds.update_feeds(self.state, {})
        threat = self.sources[1].path(self.state)
        threat.write_bytes(threat.read_bytes().replace(b"one.test", b"abc.test"))
        self.assertFalse(feeds.read_cached_feed(self.state, self.sources[1]))
        with patch("egress_guard.policy.selected_feeds", return_value=self.sources):
            self.assertFalse(Policy({}, self.state).ready())

    def test_future_publication_keeps_the_previous_snapshot(self):
        now = dt.datetime.now(dt.timezone.utc)
        current = f"# TimeUpdated: {now.isoformat()}\none.test\ntwo.test\n".encode("ascii")
        later = now + dt.timedelta(days=2)
        future = f"# TimeUpdated: {later.isoformat()}\nthree.test\nfour.test\n".encode("ascii")
        with patch("egress_guard.feeds._download", return_value=current):
            self.assertTrue(feeds.update_feeds(self.state, {})["ok"])
        with patch("egress_guard.feeds._download", return_value=future):
            report = feeds.update_feeds(self.state, {})
        self.assertFalse(report["ok"])
        for feed, row in zip(self.sources, report["feeds"], strict=True):
            self.assertEqual(row["status"], "using-previous")
            self.assertIn("publication timestamp", row["error"])
            self.assertEqual(feeds.read_cached_feed(self.state, feed), {"one.test", "two.test"})

    def test_future_snapshot_is_reported_invalid_and_does_not_set_rollback_floor(self):
        (self.state / "blocklists").mkdir(mode=0o700)
        poisoned = self.sources[0].path(self.state)
        poisoned.write_bytes(feeds._snapshot({f"bad{number}.test" for number in range(8)},
                                             time.time() + 7 * 86400))
        invalid = feeds.feed_status(self.state)[0]
        self.assertEqual(invalid["status"], "invalid")
        self.assertIsNone(invalid["published_at"])
        published = dt.datetime.now(dt.timezone.utc).isoformat()
        current = f"# TimeUpdated: {published}\none.test\ntwo.test\n".encode("ascii")
        with patch("egress_guard.feeds._download", return_value=current):
            report = feeds.update_feeds(self.state, {})
        self.assertTrue(report["ok"])
        self.assertEqual(report["feeds"][0]["status"], "current")
        self.assertEqual(feeds.read_cached_feed(self.state, self.sources[0]), {"one.test", "two.test"})

    def test_refresh_does_not_overlap_another_writer(self):
        with patch("egress_guard.feeds._download", return_value=b"one.test\ntwo.test\n"):
            feeds.update_feeds(self.state, {})
        with sqlite3.connect(self.state / "blocklists/.refresh.sqlite3") as connection:
            connection.execute("BEGIN IMMEDIATE")
            with patch("egress_guard.feeds._download") as download:
                result = feeds.update_feeds(self.state, {})
            download.assert_not_called()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "feed refresh lock unavailable")

    def test_selection_tiers_and_toggles(self):
        select = _real_selected_feeds  # setUp patches feeds.selected_feeds
        self.assertEqual([feed.id for feed in select({})], [
            "hagezi-pro.plus", "urlhaus-filter", "phishing-army", "hagezi-threat-intel-full", "hagezi-doh",
            "adguard-cname-ads", "adguard-cname-trackers"])
        lean = select({"block": {"threat_tier": "medium", "block_encrypted_dns": False, "cname_protection": False}})
        self.assertEqual([feed.id for feed in lean],
                         ["hagezi-pro.plus", "urlhaus-filter", "phishing-army", "hagezi-threat-intel"])
        with self.assertRaisesRegex(ValueError, "threat tier"):
            select({"block": {"threat_tier": "huge"}})
        for feed in feeds.ALL_FEEDS:
            self.assertTrue(feed.url.startswith("https://") and feed.source and feed.kind)
        config = self.state / "config.toml"
        config.write_text('[block]\nthreat_tier = "mini"\n')
        with self.assertRaisesRegex(ValueError, "threat_tier"):
            load_config(config)
        config.write_text('[block]\nblock_encrypted_dns = "yes"\n')
        with self.assertRaisesRegex(ValueError, "block_encrypted_dns"):
            load_config(config)

    def test_ip_entries_only_in_ip_feeds_and_new_date_headers(self):
        body = (b"# Title: Malicious Domains Blocklist\n# Updated: 2026-11-20T12:10:15Z\n"
                b"bad.example\n198.51.100.7\n2001:DB8::7\n198.51.100.7.example\n")
        names, published = feeds._parse_feed(body, replace(feeds.MALWARE, minimum=2))
        self.assertEqual(names, {"bad.example", "198.51.100.7", "2001:db8::7", "198.51.100.7.example"})
        self.assertEqual(published, dt.datetime(2026, 11, 20, 12, 10, 15, tzinfo=dt.timezone.utc).timestamp())
        names, _ = feeds._parse_feed(b"one.example\ntwo.example\n198.51.100.7\n", replace(feeds.PHISHING, minimum=2))
        self.assertEqual(names, {"one.example", "two.example"})
        generated = b"# Generated: 2026-11-20T23:00:25Z\none.example\ntwo.example\n"
        self.assertIsNotNone(feeds._parse_feed(generated, replace(feeds.PHISHING, minimum=2))[1])

    def test_host_set_is_compact_membership_only(self):
        names = {f"host{number}.example" for number in range(1000)}
        compact = feeds.HostSet(names)
        self.assertEqual(len(compact), 1000)
        self.assertTrue(all(name in compact for name in names))
        self.assertFalse(any(f"other{number}.example" in compact for number in range(1000)))
        self.assertNotIn(None, compact)
        self.assertLess(compact._hashes.itemsize * len(compact), 8 * 1001)
        compact.clear()
        self.assertFalse(compact)
        # A loaded snapshot uses the compact set; the text view stays available for measurement.
        with patch("egress_guard.feeds._download", return_value=b"one.test\ntwo.test\n"):
            feeds.update_feeds(self.state, {})
        snapshot = feeds.load_cached_feed(self.state, self.sources[0])
        self.assertIsInstance(snapshot.names, feeds.HostSet)
        self.assertIn("one.test", snapshot.names)
        self.assertEqual(feeds.read_cached_feed(self.state, self.sources[0]), {"one.test", "two.test"})

    def test_no_following_redirects_from_feed_hosts(self):
        redirect = urllib.error.HTTPError(self.sources[0].url, 302, "redirect", {}, None)
        with patch("urllib.request.OpenerDirector.open", side_effect=redirect):
            with self.assertRaisesRegex(ValueError, "HTTP 302"):
                feeds._download(self.sources[0])
        self.assertIsNone(feeds._NoRedirect().redirect_request(None, None, 302, "", {}, "http://127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
