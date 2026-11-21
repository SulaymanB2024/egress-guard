import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard.config import load_config
from egress_guard.feeds import CachedFeed
from egress_guard.ledger import SOURCES
from egress_guard.policy import CATEGORIES, MAX_CONTROL_BYTES, Policy, PolicyRuntime, normalize_host, policy_stamp


def cached(names, published=None):
    return CachedFeed(set(names), "digest-" + "-".join(sorted(names)), published, None)


def pick(snapshots, feed):
    """Specific threat feeds have fixtures under their ledger source; others under their group."""
    return snapshots[feed.source] if feed.source in snapshots else snapshots[feed.category]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.config = {
            "block": {
                "hosts": ["manual.example", "invalid/url"],
                "allow": ["tracker.example", "danger.example", "manual.example"],
                "dashboard_hosts": ["dashboard.example", "dashboard.danger.example"],
            }
        }
        snapshots = {
            "threat": {"danger.example"},
            "tracker": {"tracker.example", "dashboard.example", "analytics.example"},
            "cname": {"masked.example", "dashboard.danger.example", "manual.example"},
            "doh": {"dns.example"},
            "malware-feed": {"payload.example", "203.0.113.9"},
            "phishing-feed": {"phish.example", "both.danger.example", "accounts.google.com"},
        }
        self.snapshots = snapshots
        with patch("egress_guard.policy.load_cached_feed", side_effect=lambda _, feed: cached(pick(snapshots, feed))):
            self.policy = Policy(self.config, self.state)

    def test_priorities_and_match_boundaries(self):
        self.assertEqual(self.policy.decision("A.Danger.Example."), {
            "decision": "blocked", "source": "threat-intel", "category": "threat",
            "matched_domain": "danger.example", "can_allow": False,
        })
        self.assertEqual(self.policy.decision("dashboard.danger.example")["source"], "threat-intel")
        self.assertEqual(self.policy.decision("manual.example")["source"], "local-block")
        self.assertEqual(self.policy.decision("a.tracker.example")["source"], "local-allow")
        self.assertEqual(self.policy.decision("dashboard.example")["source"], "dashboard-exception")
        self.assertEqual(self.policy.decision("a.dashboard.example")["source"], "tracker-feed")
        self.assertEqual(self.policy.decision("notdanger.example")["source"], "no-match")
        self.assertEqual(self.policy.decision("danger.example.other")["source"], "no-match")
        self.assertEqual(self.policy.decision("masked.example")["source"], "cname-feed")
        self.assertEqual(self.policy.decision("a.masked.example")["source"], "no-match")

    def test_specific_threat_sources_and_categories(self):
        decide = self.policy.decision
        # The most specific threat feed names the source, even when HaGeZi also lists a parent.
        self.assertEqual((decide("both.danger.example")["source"], decide("both.danger.example")["category"]),
                         ("phishing-feed", "phishing"))
        self.assertEqual(decide("x.payload.example")["category"], "malware")
        self.assertEqual(decide("phish.example")["can_allow"], False)
        # Allow rules, exemptions, pauses and timed exceptions never override threat feeds.
        config = {"block": {"allow": ["phish.example", "payload.example"], "dashboard_hosts": ["phish.example"]}}
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": time.time() + 60}))
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"phish.example": time.time() + 60}))
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            relaxed = Policy(config, self.state)
        self.assertEqual(relaxed.decision("phish.example")["source"], "phishing-feed")
        self.assertEqual(relaxed.decision("payload.example")["source"], "malware-feed")
        for source, category in CATEGORIES.items():
            self.assertIn(source, SOURCES)
            self.assertTrue(category)
        self.assertLessEqual(set(SOURCES), set(CATEGORIES))

    def test_ip_literal_targets(self):
        decide = self.policy.decision
        self.assertEqual(decide("203.0.113.9"), {"decision": "blocked", "source": "malware-feed",
                                                 "category": "malware", "matched_domain": "203.0.113.9",
                                                 "can_allow": False})
        self.assertEqual(decide("1.1.1.1")["source"], "doh-feed")
        self.assertEqual(decide("[2606:4700:4700::1111]")["source"], "doh-feed")
        self.assertEqual(decide("93.184.215.14"), {"decision": "allowed", "source": "ip-literal",
                                                   "category": "unfiltered", "matched_domain": "93.184.215.14",
                                                   "can_allow": False})
        for private in ("10.0.0.1", "127.0.0.1", "::1", "fe80::1"):
            self.assertEqual(decide(private)["source"], "no-match")
        # A listed IP is matched exactly, never as a DNS suffix.
        self.assertEqual(decide("203.0.113.10")["source"], "no-match")

    def test_equivalent_ips_cannot_evade_ip_threat_or_resolver_rules(self):
        for host in ("::ffff:203.0.113.9", "[::ffff:cb00:7109]"):
            self.assertEqual(self.policy.decision(host), self.policy.decision("203.0.113.9"))
        for host in ("::ffff:8.8.8.8", "[::ffff:808:808]"):
            self.assertEqual(self.policy.decision(host), self.policy.decision("8.8.8.8"))
        for host in ("0x08080808", "0x8.0x8.0x8.0x8", "134744072", "010.010.010.010", "8.8.2056"):
            self.assertEqual(self.policy.decision(host)["source"], "invalid-host")
        self.assertEqual(normalize_host("[::ffff:127.0.0.1]"), "127.0.0.1")
        self.assertEqual(normalize_host("0x8.example"), "0x8.example")
        self.assertFalse(self.policy.decision("8.8.8.8")["can_allow"])
        self.snapshots["malware-feed"] = {"::ffff:cb00:7109"}
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            old_cache = Policy(self.config, self.state)
        self.assertEqual(old_cache.decision("203.0.113.9")["source"], "malware-feed")

    def test_actual_addresses_have_independent_ip_only_decisions(self):
        self.assertEqual(self.policy.decision("accounts.google.com")["source"], "safety-list")
        self.assertEqual(self.policy.address_decision("::ffff:203.0.113.9")["source"], "malware-feed")
        self.assertEqual(self.policy.address_decision("::ffff:8.8.8.8")["source"], "doh-feed")
        self.assertEqual(self.policy.address_decision("accounts.google.com")["source"], "invalid-host")
        config = {"block": {"block_encrypted_dns": False},
                  "transport": {"profile": "hardened", "address_guard": True}}
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            changed = Policy(config, self.state)
        # The literal CONNECT floor must not deny every hostname's numeric sockaddr.
        self.assertEqual(changed.address_decision("8.8.8.8")["decision"], "allowed")
        self.assertEqual(changed.address_decision("203.0.113.9")["decision"], "blocked")
        self.assertFalse(changed.address_decision("203.0.113.9")["can_allow"])

    def test_grants_and_pause_are_immutable_until_a_new_revision_is_applied(self):
        config_path = self.state / "config.toml"
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            runtime = PolicyRuntime(lambda old: Policy(self.config, self.state, old),
                                    lambda: policy_stamp(config_path, self.state))
            self.assertTrue(runtime.poll())
            before = runtime.policy
            (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": time.time() + 60}))
            desired = Policy(self.config, self.state)
            self.assertNotEqual(desired.revision, before.revision)
            self.assertEqual(before.decision("analytics.example")["source"], "tracker-feed")
            self.assertEqual(desired.decision("analytics.example")["source"], "tracker-paused")
            self.assertTrue(runtime.poll())
            self.assertEqual(runtime.status()["revision"], desired.revision)
            (self.state / "filter-controls.json").write_text("{}")
            (self.state / "tracker-exceptions.json").write_text(json.dumps({"analytics.example": time.time() + 60}))
            self.assertTrue(runtime.poll())
            self.assertNotEqual(runtime.status()["revision"], desired.revision)
            self.assertEqual(runtime.policy.decision("analytics.example")["source"], "temporary-exception")

    def test_invalid_control_timestamps_cannot_crash_the_runtime(self):
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": 10 ** 1000}))
        (self.state / "tracker-exceptions.json").write_text('{"analytics.example": NaN}')
        self.policy.reload_controls()
        self.assertEqual(self.policy.decision("analytics.example")["source"], "tracker-feed")

    def test_runtime_receipt_waits_for_runtime_settings_apply(self):
        revision = [0]
        refused = [False]

        def apply(_candidate):
            if refused[0]:
                raise ValueError("writer has not acknowledged")

        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            runtime = PolicyRuntime(lambda old: Policy(self.config, self.state, old), lambda: (revision[0],),
                                    apply=apply, clock=lambda: 0.0)
            self.assertTrue(runtime.poll())
            original = runtime.policy
            refused[0] = True
            revision[0] += 1
            self.assertFalse(runtime.poll())
            self.assertIs(runtime.policy, original)
            self.assertTrue(runtime.status()["pending"])
            self.assertTrue(runtime.status()["degraded"])
            refused[0] = False
            revision[0] += 1
            self.assertTrue(runtime.poll())
            self.assertFalse(runtime.status()["pending"])

    def test_encrypted_dns_servers(self):
        decide = self.policy.decision
        self.assertEqual((decide("a.dns.example")["source"], decide("dns.example")["category"]), ("doh-feed", "doh"))
        self.assertTrue(decide("dns.example")["can_allow"])
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": time.time() + 60}))
        self.policy.reload_controls()
        self.assertEqual(decide("dns.example")["source"], "doh-feed")  # pausing ads does not unblock DoH
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"dns.example": time.time() + 60}))
        self.policy.reload_controls()
        self.assertEqual(decide("dns.example")["source"], "temporary-exception")
        config = {"block": {"block_encrypted_dns": False}}
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            off = Policy(config, self.state)
        self.assertNotIn("hagezi-doh", off.coverage)
        self.assertEqual(off.decision("dns.example")["source"], "no-match")
        self.assertEqual(off.decision("1.1.1.1")["source"], "ip-literal")

    def test_safety_list_outranks_feeds_but_not_manual_blocks(self):
        self.assertEqual(self.policy.decision("accounts.google.com"),
                         {"decision": "allowed", "source": "safety-list", "category": "safety",
                          "matched_domain": "accounts.google.com", "can_allow": False})
        # Exact only: a listed subdomain of a safety host is still blocked.
        self.assertEqual(self.policy.decision("x.accounts.google.com")["source"], "phishing-feed")
        (self.state / "block.txt").write_text("accounts.google.com\n")
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            manual = Policy(self.config, self.state)
        # The user's block removes the protection; feed matches then apply in their usual order.
        self.assertEqual(manual.decision("accounts.google.com")["decision"], "blocked")
        self.assertEqual(manual.decision("appleid.apple.com")["source"], "safety-list")
        (self.state / "block.txt").write_text("appleid.apple.com\n")
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            manual = Policy(self.config, self.state)
        self.assertEqual(manual.decision("appleid.apple.com")["source"], "local-block")

    def test_lookalike_domains(self):
        decide = self.policy.decision
        for host, matched in (("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),  # аррӏе.com, all Cyrillic
                              ("login.xn--pple-43d.com", "xn--pple-43d.com"),  # аpple.com
                              ("xn--pypal-4ve.example", "xn--pypal-4ve.example"),  # pаypal
                              ("xn--secure-pypal-49j.example", "xn--secure-pypal-49j.example")):
            with self.subTest(host=host):
                self.assertEqual(decide(host), {"decision": "blocked", "source": "lookalike-domain",
                                                "category": "lookalike", "matched_domain": matched,
                                                "can_allow": False})
        for host in ("xn--bcher-kva.ch", "xn--mnchen-3ya.de", "xn--fiqs8s.xn--fiqs8s", "apple.com",
                     "xn--bcher-apple-thb.example", "xn--zz-.example", "xn--a.example"):
            with self.subTest(host=host):
                self.assertNotEqual(decide(host)["source"], "lookalike-domain")
        with patch("egress_guard.policy.load_cached_feed",
                   side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
            allowed = Policy({"block": {"allow": ["xn--pple-43d.com"]}}, self.state)
        self.assertEqual(allowed.decision("xn--pple-43d.com")["source"], "no-match")

    def test_nonstandard_ports_are_labelled_not_blocked(self):
        decide = self.policy.decision
        self.assertEqual(decide("plain.example", 443)["source"], "no-match")
        self.assertEqual(decide("plain.example", 80)["source"], "no-match")
        self.assertEqual(decide("plain.example")["source"], "no-match")
        self.assertEqual(decide("plain.example", 8443),
                         {"decision": "allowed", "source": "nonstandard-port", "category": "unfiltered",
                          "matched_domain": None, "can_allow": False})
        self.assertEqual(decide("analytics.example", 8443)["source"], "tracker-feed")

    def test_full_threat_tier_substitutes_the_verified_medium_cache(self):
        def only_medium(_, feed):
            if feed.id == "hagezi-threat-intel-full":
                return None
            return cached(pick(self.snapshots, feed))

        with patch("egress_guard.policy.load_cached_feed", side_effect=only_medium):
            policy = Policy({}, self.state)
        self.assertEqual(policy.coverage["hagezi-threat-intel-full"], "substitute")
        self.assertEqual(policy.decision("danger.example")["source"], "threat-intel")
        self.assertTrue(policy.ready() and policy.degraded())

    def test_temporary_exception_is_exact_and_bounded(self):
        (self.state / "tracker-exceptions.json").write_text(json.dumps({
            "analytics.example": 1001,
            "danger.example": 1001,
            "masked.example": 1000 + 86_401,
        }))
        self.policy.reload_controls()
        with patch("egress_guard.policy.time.time", return_value=1000):
            self.assertEqual(self.policy.decision("analytics.example")["source"], "temporary-exception")
            self.assertTrue(self.policy.decision("sub.analytics.example")["can_allow"])
            self.assertTrue(self.policy.decision("masked.example")["can_allow"])
            self.assertFalse(self.policy.decision("danger.example")["can_allow"])
        with patch("egress_guard.policy.time.time", return_value=1001):
            self.assertEqual(self.policy.decision("analytics.example")["source"], "tracker-feed")

    def test_pause_cannot_bypass_threats_or_manual_blocks(self):
        (self.state / "filter-controls.json").write_text(json.dumps({
            "tracker_pause_until": time.time() + 120,
        }))
        self.policy.reload_controls()
        self.assertEqual(self.policy.decision("analytics.example")["source"], "tracker-paused")
        self.assertEqual(self.policy.decision("masked.example")["source"], "tracker-paused")
        self.assertEqual(self.policy.decision("danger.example")["source"], "threat-intel")
        self.assertEqual(self.policy.decision("manual.example")["source"], "local-block")
        (self.state / "filter-controls.json").write_text("{" + " " * 65_537 + "}")
        self.policy.reload_controls()
        self.assertEqual(self.policy.decision("masked.example")["source"], "cname-feed")

    def test_rule_file_distinguishes_missing_empty_and_invalid(self):
        path = self.state / "block.txt"
        with patch("egress_guard.policy.load_cached_feed", return_value=None):
            self.assertEqual(Policy({}, self.state).decision("local.example")["source"], "no-match")
            path.write_bytes(b"")
            self.assertEqual(Policy({}, self.state).decision("local.example")["source"], "no-match")
            path.write_text("# custom block\nlocal.example # exact domain and descendants\n")
            self.assertEqual(Policy({}, self.state).decision("a.local.example")["source"], "local-block")
            for data, message in (
                (b"#" * (MAX_CONTROL_BYTES + 1), "64 KiB"),
                (b"local.example\n\xff", "UTF-8"),
                (b"local.example\ninvalid/url\n", "invalid domain on line 2"),
            ):
                with self.subTest(message=message):
                    path.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, message):
                        Policy({}, self.state)
            with patch.object(Path, "open", side_effect=PermissionError):
                with self.assertRaisesRegex(ValueError, "block.txt could not be read"):
                    Policy({}, self.state)

    def test_corrupt_enabled_cname_cache_keeps_last_good_block_and_is_not_fully_ready(self):
        self.assertEqual(self.policy.decision("masked.example")["source"], "cname-feed")
        self.assertTrue(self.policy.ready())
        self.assertFalse(self.policy.degraded())

        def corrupt_cname(_, feed):
            return None if feed.category == "cname" else cached(pick(self.snapshots, feed))

        with patch("egress_guard.policy.load_cached_feed", side_effect=corrupt_cname):
            replacement = Policy(self.config, self.state, self.policy)
            fresh = Policy(self.config, self.state)
        # The running replacement keeps the verified CNAME component, and says so.
        self.assertEqual(replacement.decision("masked.example"),
                         {"decision": "blocked", "source": "cname-feed", "category": "cname-cloak",
                          "matched_domain": "masked.example", "can_allow": True})
        self.assertTrue(replacement.degraded())
        self.assertIn("last-good", replacement.coverage.values())
        # Without a previous policy, an enabled feed with no data is never full readiness.
        self.assertFalse(fresh.ready())
        self.assertTrue(fresh.enforceable())
        self.assertEqual(fresh.explain("masked.example")["decision"], "indeterminate")
        self.assertNotEqual(fresh.revision, self.policy.revision)

    def test_strict_default_exempts_nothing_and_preset_is_explicit(self):
        trackers = {"analytics.google.com", "us.posthog.com", "tracker.example"}
        load = lambda _, feed: cached(trackers if feed.category == "tracker" else {"danger.example"})
        config = load_config(self.state / "missing.toml")
        self.assertEqual((config["block"]["dashboard_hosts"], config["block"]["exemption_presets"]), ([], []))
        with patch("egress_guard.policy.load_cached_feed", side_effect=load):
            strict = Policy(config, self.state)
            config["block"]["exemption_presets"] = ["analytics-dashboards"]
            compatible = Policy(config, self.state)
            (self.state / "block.txt").write_text("us.posthog.com\n")
            manual = Policy(config, self.state)
        self.assertEqual(strict.decision("analytics.google.com")["source"], "tracker-feed")
        self.assertEqual(compatible.decision("analytics.google.com")["source"], "dashboard-exception")
        self.assertEqual(manual.decision("us.posthog.com")["source"], "local-block")
        (self.state / "config.toml").write_text('[block]\nexemption_presets = ["everything"]\n')
        with self.assertRaisesRegex(ValueError, "exemption_presets"):
            load_config(self.state / "config.toml")

    def test_runtime_recovers_from_one_time_read_error_without_another_edit(self):
        clock = [100.0]
        failures = [0]
        block = self.state / "block.txt"

        def load(previous):
            if failures[0]:
                failures[0] -= 1
                raise ValueError("block.txt could not be read as UTF-8")
            with patch("egress_guard.policy.load_cached_feed",
                       side_effect=lambda _, feed: cached(pick(self.snapshots, feed))):
                return Policy(self.config, self.state, previous)

        observe = lambda: (block.stat().st_mtime_ns, block.stat().st_size) if block.exists() else None
        runtime = PolicyRuntime(load, observe, clock=lambda: clock[0])
        self.assertTrue(runtime.poll())
        first = runtime.policy
        self.assertFalse(runtime.status()["pending"])

        block.write_text("late.example\n")
        failures[0] = 1
        self.assertFalse(runtime.poll())
        status = runtime.status()
        self.assertIs(runtime.policy, first)
        self.assertTrue(status["pending"] and status["degraded"])
        self.assertEqual(status["revision"], first.revision)
        self.assertEqual(runtime.policy.decision("late.example")["source"], "no-match")
        # Bounded backoff: no reload before the retry is due, then the same files apply.
        with patch.object(runtime, "_load", side_effect=AssertionError("retried early")):
            runtime.poll()
        clock[0] += 1
        self.assertTrue(runtime.poll())
        status = runtime.status()
        self.assertEqual(runtime.policy.decision("late.example")["source"], "local-block")
        self.assertFalse(status["pending"] or status["degraded"])
        self.assertNotEqual(status["revision"], first.revision)

    def test_runtime_keeps_enforceable_policy_over_unenforceable_replacement(self):
        stamp = [1]
        empty = [False]

        def load(previous):
            source = (lambda *_: None) if empty[0] else (lambda _, feed: cached(pick(self.snapshots, feed)))
            with patch("egress_guard.policy.load_cached_feed", side_effect=source):
                return Policy(self.config, self.state)  # no carry-forward, to force an empty candidate

        runtime = PolicyRuntime(load, lambda: stamp[0], clock=lambda: 0.0)
        runtime.poll()
        running = runtime.policy
        empty[0], stamp[0] = True, 2
        self.assertFalse(runtime.poll())
        self.assertIs(runtime.policy, running)
        self.assertTrue(runtime.status()["pending"])
        self.assertIn("threat or tracker", runtime.status()["error"])

    def test_malformed_request_targets_and_ip_literals(self):
        for value in ("abc../", "*.example", "example..", "https://danger.example", "a" * 254, "日本.example"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_host(value))
                self.assertEqual(self.policy.decision(value)["source"], "invalid-host")
        self.assertEqual(normalize_host("[2001:DB8::1]"), "2001:db8::1")
        self.assertEqual(self.policy.decision("1.2.3.4")["source"], "ip-literal")
        self.assertEqual(self.policy.decision("192.168.1.10")["source"], "no-match")
        self.assertEqual(normalize_host("xn--wgv71a.example."), "xn--wgv71a.example")


if __name__ == "__main__":
    unittest.main()
