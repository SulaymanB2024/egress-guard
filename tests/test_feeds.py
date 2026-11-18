from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from egress_guard import feeds
from egress_guard.policy import Policy


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
        names, published = feeds._parse_feed(records, self.sources[2])
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

    def test_no_following_redirects_from_feed_hosts(self):
        redirect = urllib.error.HTTPError(self.sources[0].url, 302, "redirect", {}, None)
        with patch("urllib.request.OpenerDirector.open", side_effect=redirect):
            with self.assertRaisesRegex(ValueError, "HTTP 302"):
                feeds._download(self.sources[0])
        self.assertIsNone(feeds._NoRedirect().redirect_request(None, None, 302, "", {}, "http://127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
