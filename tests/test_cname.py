from pathlib import Path
import time
import unittest
from unittest.mock import patch

from egress_guard.cname import MAX_HOPS, MAX_RECORDS, inspect_answers, normalize_cname_host
from egress_guard.feeds import CachedFeed
from egress_guard.policy import Policy


def alias(owner, target, interface=0):
    return {"owner": owner, "target": target, "ttl": 90, "interface_index": interface}


def answer(query_type, aliases=(), terminals=(), status="answered", **metadata):
    return {"query_type": query_type, "status": status, "aliases": list(aliases),
            "terminal_names": list(terminals), **metadata}


class CNAMEInspectionTests(unittest.TestCase):
    def setUp(self):
        feeds = {
            "threat": {"malware.example"}, "tracker": {"metrics.example"}, "cname": {"static.example"},
        }
        cached = lambda _, feed: CachedFeed(feeds[feed.category], feed.id, None, None)
        with patch("egress_guard.policy.load_cached_feed", side_effect=cached):
            self.policy = Policy({"block": {"hosts": ["manual.example"], "allow": ["static.example"]}},
                                 Path(__file__).parent / "unused-cname-state")

    def inspect(self, aliases, terminal, host="new.example"):
        rows = [answer(family, aliases, [terminal]) for family in ("A", "AAAA")]
        return inspect_answers(host, rows, self.policy)

    def test_reports_new_reachable_alias_and_ignores_unrelated_records(self):
        result = self.inspect([
            alias("New.Example.", "hop.example"), alias("hop.example", "a.metrics.example"),
            alias("unrelated.example", "malware.example"),
        ], "A.Metrics.Example.")
        self.assertTrue(result["complete"])
        self.assertFalse(result["indeterminate"])
        self.assertTrue(result["live_policy_unchanged"])
        self.assertEqual(result["original_policy"]["source"], "no-match")
        for family in result["families"]:
            self.assertEqual(family["terminal"], "a.metrics.example")
            self.assertEqual([hop["target"] for hop in family["chain"]], ["hop.example", "a.metrics.example"])
            self.assertEqual(family["chain"][-1]["policy"]["source"], "tracker-feed")

    def test_keeps_original_exception_and_each_hops_policy_independent(self):
        result = self.inspect([
            alias("static.example", "manual.example"), alias("manual.example", "malware.example"),
        ], "malware.example", "static.example")
        self.assertEqual(result["original_policy"]["source"], "local-allow")
        self.assertNotIn("effective_decision", result)
        self.assertEqual([hop["policy"]["source"] for hop in result["families"][0]["chain"]],
                         ["local-block", "threat-intel"])
        self.policy.controls["tracker_pause_until"] = time.time() + 120
        result = self.inspect([alias("new.example", "metrics.example")], "metrics.example")
        self.assertEqual(result["families"][0]["chain"][0]["policy"]["source"], "tracker-paused")
        self.policy.controls.clear()
        self.policy.exceptions["metrics.example"] = time.time() + 120
        result = self.inspect([alias("new.example", "metrics.example")], "metrics.example")
        self.assertEqual(result["families"][0]["chain"][0]["policy"]["source"], "temporary-exception")

    def test_benign_cdn_matches_names_only(self):
        result = self.inspect([alias("new.example", "shared-cdn.example")], "shared-cdn.example")
        self.assertEqual(result["families"][0]["chain"][0]["policy"]["source"], "no-match")

    def test_normalizes_idna_case_and_trailing_dot_and_rejects_non_names(self):
        self.assertEqual(normalize_cname_host("BÜCHER.Example."), "xn--bcher-kva.example")
        self.assertEqual(normalize_cname_host("XN--BCHER-KVA.EXAMPLE."), "xn--bcher-kva.example")
        for host in ("https://example.com", "1.2.3.4", "::1", "single", "faß.example", "a" * 255):
            with self.subTest(host=host), self.assertRaises(ValueError):
                inspect_answers(host, [], self.policy)

    def test_distinguishes_negative_timeout_and_unavailable_policy(self):
        negative = answer("A", status="negative")
        result = inspect_answers("new.example", [negative, answer("AAAA", status="timeout")], self.policy)
        self.assertTrue(result["families"][0]["complete"])
        self.assertEqual(result["families"][0]["status"], "negative")
        self.assertIsNone(result["families"][0]["terminal"])
        self.assertFalse(result["complete"])
        self.assertTrue(result["indeterminate"])
        both_negative = inspect_answers("new.example", [negative, answer("AAAA", status="negative")], self.policy)
        self.assertTrue(both_negative["complete"])
        self.assertTrue(both_negative["indeterminate"])
        self.policy.threats.clear()
        self.assertTrue(self.inspect([], "new.example")["indeterminate"])

    def test_limits_cycles_forks_and_mixed_interfaces(self):
        deep = [alias("new.example", "node0.example")]
        deep.extend(alias(f"node{n}.example", f"node{n + 1}.example") for n in range(MAX_HOPS))
        for records, issue in (
            ([alias("new.example", "new.example")], "cycle"),
            ([alias("new.example", "a.example"), alias("new.example", "b.example")], "fork"),
            ([alias("new.example", "a.example", 1), alias("a.example", "b.example", 2)], "mixed-interface"),
            (deep, "hop-limit"),
            ([alias("new.example", "a.example")] * MAX_RECORDS, "record-limit"),
        ):
            with self.subTest(issue=issue):
                observed = self.inspect(records, "a-terminal.example")
                self.assertTrue(observed["indeterminate"])
                self.assertEqual(observed["families"][0]["issue"], issue)

    def test_family_divergence_missing_terminal_and_interface_disagreement(self):
        rows = [
            answer("A", [alias("new.example", "a.example")], ["a.example"]),
            answer("AAAA", [alias("new.example", "b.example")], ["b.example"]),
        ]
        self.assertIn("divergent-families", inspect_answers("new.example", rows, self.policy)["ambiguity"])
        rows[1] = answer("AAAA", terminals=["unrelated.example"])
        self.assertEqual(inspect_answers("new.example", rows, self.policy)["families"][1]["issue"],
                         "missing-terminal")
        rows = [answer("A", terminals=["new.example"], interface_index=1),
                answer("AAAA", terminals=["new.example"], interface_index=2)]
        self.assertIn("mixed-interface", inspect_answers("new.example", rows, self.policy)["ambiguity"])

    def test_detects_conflicting_negative_path_without_treating_empty_negative_as_divergent(self):
        alias_path = [alias("new.example", "alias.example")]
        first = answer("A", terminals=["new.example"])
        negative_with_alias = answer("AAAA", alias_path, status="negative")
        result = inspect_answers("new.example", [first, negative_with_alias], self.policy)
        self.assertTrue(result["indeterminate"])
        self.assertIn("divergent-families", result["ambiguity"])
        first = answer("A", alias_path, ["alias.example"])
        result = inspect_answers("new.example", [first, answer("AAAA", status="negative")], self.policy)
        self.assertFalse(result["indeterminate"])

    def test_malformed_worker_reply_leaves_diagnostic_indeterminate(self):
        rows = [answer("A", terminals=["new.example"]), {"query_type": "AAAA", "status": "negative"}]
        result = inspect_answers("new.example", rows, self.policy)
        self.assertTrue(result["indeterminate"])
        self.assertEqual(result["families"][1]["issue"], "invalid-observation")
