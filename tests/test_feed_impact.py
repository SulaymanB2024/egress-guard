"""Candidate impact uses real precedence without reading traffic or publishing policy."""
from dataclasses import replace
from hashlib import sha256
from contextlib import contextmanager
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard import feed_review, feeds
from egress_guard.config import load_config
from egress_guard.feed_impact import (CORPUS_SHA256, ComponentCache, DESCENDANT_LABEL, ImpactContext,
                                    MAX_CONFIGURED_HOSTS, MAX_PROBES, load_corpus)
from egress_guard.heuristics import SAFETY_HOSTS
from egress_guard.policy import MAX_EXCEPTION_SECONDS, Policy


class FeedImpactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        (self.state / "blocklists").mkdir(mode=0o700)
        self.tracker = replace(feeds.TRACKERS["pro.plus"], minimum=1)
        self.threat = replace(feeds.MALWARE, minimum=1)
        self.cname = replace(feeds.CNAME_FEEDS[0], minimum=1)
        self.selected = (self.tracker, self.threat, self.cname)
        for target in ("egress_guard.feeds.selected_feeds", "egress_guard.policy.selected_feeds"):
            mocked = patch(target, side_effect=lambda _config: self.selected)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.install(self.tracker, {"google-analytics.com", "tracker.example"})
        self.install(self.threat, {"malware.example"})
        self.install(self.cname, {"alias.example"})

    def install(self, feed, names):
        raw = feeds._snapshot(set(names), None)
        feed.path(self.state).write_bytes(raw)
        feed.path(self.state).chmod(0o600)
        return raw

    def candidate(self, feed, names):
        return feeds._reviewed_snapshot(feeds._snapshot(set(names), None), feed)

    def compare(self, feed, names, *, config=None, roots=()):
        context = ImpactContext(self.state, config or {})
        candidate = self.candidate(feed, names)
        digest = feed_review.digest(feed.path(self.state).read_bytes())
        return context.compare(feed, candidate, base_sha256=digest, changed_roots=roots)

    def stage(self, feed, names):
        candidate = self.candidate(feed, names)
        current = feed_review.digest(feed.path(self.state).read_bytes()) if feed.path(self.state).exists() else None
        return feed_review.write(self.state, feed, "candidate", candidate.raw, current,
                                 cause="refresh", limit=feeds.MAX_FEED_BYTES)

    def probe(self, result, host):
        self.assertEqual(result["status"], "compared")
        return next(row for row in result["probes"] if row["host"] == host)

    def refresh(self, changed_feed, names, *, config=None):
        def download(feed):
            entries = names if feed == changed_feed else feeds.read_cached_feed(self.state, feed)
            return ("\n".join(sorted(entries)) + "\n").encode("ascii")
        with patch("egress_guard.feeds._download", side_effect=download):
            return feeds.update_feeds(self.state, config or {})

    def refresh_check(self, report, feed):
        return next(row for row in report["policy_impact"]["checks"] if row["id"] == feed.id)

    def configuration_file(self, *, custom=False):
        parent = self.state
        if custom:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            parent = Path(temporary.name)
        path = parent / ("custom.toml" if custom else "config.toml")
        path.write_text('[block]\nallow = ["api.github.com"]\n')
        return path, load_config(path)

    @contextmanager
    def during_active_fsync(self, action):
        atomic, fsync = feeds.atomic_private, os.fsync
        active_write = False
        triggered = []

        def guarded_write(path, content, **kwargs):
            nonlocal active_write
            if path != self.tracker.path(self.state):
                return atomic(path, content, **kwargs)
            active_write = True
            try:
                return atomic(path, content, **kwargs)
            finally:
                active_write = False

        def change_after_fsync(descriptor):
            result = fsync(descriptor)
            if active_write and not triggered:
                triggered.append(True)
                action()
            return result

        with patch("egress_guard.feeds.atomic_private", side_effect=guarded_write), \
                patch("egress_guard.paths.os.fsync", side_effect=change_after_fsync):
            yield triggered

    def test_other_feed_masks_component_removal_without_inventing_a_new_allow(self):
        self.install(self.threat, {"malware.example", "google-analytics.com"})
        result = self.compare(self.tracker, {"tracker.example"})
        row = self.probe(result, "google-analytics.com")
        self.assertEqual(row["before"], row["after"])
        self.assertEqual(row["after"]["source"], "malware-feed")
        self.assertEqual(result["review_signals"]["new_public_canary_allows"], [])
        # Component loss remains separately visible and still quarantined.
        assessment = feed_review.assess(self.tracker, {"google-analytics.com"}, {"tracker.example"})
        self.assertIn("tracker-coverage-removed", assessment["reasons"])

    def test_category_and_exception_authority_change_while_the_host_stays_blocked(self):
        self.install(self.threat, {"google-analytics.com", "malware.example"})
        result = self.compare(self.threat, {"malware.example"})
        row = self.probe(result, "google-analytics.com")
        self.assertEqual((row["before"]["decision"], row["after"]["decision"]), ("blocked", "blocked"))
        self.assertEqual((row["before"]["source"], row["after"]["source"]), ("malware-feed", "tracker-feed"))
        self.assertEqual((row["before"]["can_allow"], row["after"]["can_allow"]), (False, True))
        self.assertIn("category", row["changed"])
        self.assertIn("can_allow", row["changed"])
        self.assertNotIn("google-analytics.com", result["newly_allowed"])

    def test_manual_and_exact_safety_precedence_remain_the_real_policy(self):
        (self.state / "block.txt").write_text("github.com\n")
        result = self.compare(self.tracker, {"google-analytics.com", "tracker.example", "github.com", "googleapis.com"})
        manual = self.probe(result, "github.com")
        self.assertEqual(manual["before"]["source"], "local-block")
        self.assertEqual(manual["after"]["source"], "local-block")
        safety = self.probe(result, "oauth2.googleapis.com")
        self.assertEqual(safety["before"]["source"], "safety-list")
        self.assertEqual(safety["after"]["source"], "safety-list")
        self.assertNotIn("github.com", result["review_signals"]["new_critical_denies"])
        self.assertNotIn("oauth2.googleapis.com", result["review_signals"]["new_critical_denies"])
        self.assertIn("googleapis.com", result["review_signals"]["new_critical_denies"])

    def test_configured_allow_deltas_are_advisory_and_never_override_threats(self):
        self.install(self.tracker, {"private-project.example", "dashboard.example"})
        config = {"block": {"allow": ["private-project.example"], "dashboard_hosts": ["dashboard.example"]}}
        result = self.compare(self.threat, {"malware.example", "private-project.example", "dashboard.example"}, config=config)
        for host, expected_source in (("private-project.example", "local-allow"), ("dashboard.example", "dashboard-exception")):
            row = self.probe(result, host)
            self.assertEqual(row["before"]["source"], expected_source)
            self.assertEqual(row["after"]["source"], "malware-feed")
            self.assertFalse(row["after"]["can_allow"])
            self.assertIn(host, result["review_signals"]["new_configured_allow_denies"])
        child = self.probe(result, DESCENDANT_LABEL + "dashboard.example")
        self.assertEqual(child["before"]["source"], "tracker-feed")
        self.assertEqual(result["review_signals"]["new_critical_denies"], [])
        self.assertEqual(result["automatic_hold_reasons"], [])
        self.assertFalse((self.state / "allow.txt").exists())

    def test_suffix_and_exact_cname_candidates_have_different_descendant_effects(self):
        for feed in (self.tracker, self.cname):
            with self.subTest(feed=feed.id):
                result = self.compare(feed, {"google-analytics.com", "tracker.example", "alias.example", "github.com"})
                parent = self.probe(result, "github.com")
                child = self.probe(result, DESCENDANT_LABEL + "github.com")
                self.assertEqual(parent["after"]["decision"], "blocked")
                self.assertEqual(child["after"]["decision"], "allowed" if feed.exact else "blocked")

    def test_preview_has_the_same_revision_and_decisions_as_real_publication(self):
        config = {"block": {"allow": ["allowed.example"]}}
        names = {"google-analytics.com", "github.com", "allowed.example"}
        candidate = self.candidate(self.tracker, names)
        context = ImpactContext(self.state, config)
        result = context.compare(self.tracker, candidate,
                                 base_sha256=feed_review.digest(self.tracker.path(self.state).read_bytes()))
        original_revision = context.policy.revision
        self.tracker.path(self.state).write_bytes(candidate.raw)
        actual = Policy(config, self.state)
        self.assertEqual(actual.revision, result["after"]["revision"])
        self.assertEqual(context.policy.revision, original_revision)
        for row in result["probes"]:
            self.assertEqual(actual.decision(row["host"], row["port"], at=result["evaluated_at"]), row["after"])

    def test_timed_grants_use_one_instant_and_preview_does_not_reload_controls(self):
        instant = time.time()
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"google-analytics.com": instant + 1}))
        context = ImpactContext(self.state, {}, evaluated_at=instant)
        candidate = self.candidate(self.tracker, {"google-analytics.com", "tracker.example", "more.example"})
        with patch("egress_guard.policy.time.time", return_value=instant + 20), \
                patch("egress_guard.policy._read_controls", side_effect=AssertionError("reread controls")):
            result = context.compare(self.tracker, candidate,
                                     base_sha256=feed_review.digest(self.tracker.path(self.state).read_bytes()))
        row = self.probe(result, "google-analytics.com")
        self.assertEqual(row["before"]["source"], "temporary-exception")
        self.assertEqual(row["after"]["source"], "temporary-exception")
        self.assertEqual(context.policy.decision("google-analytics.com", at=instant + 20)["source"], "tracker-feed")

    def test_missing_or_corrupt_other_feed_cannot_produce_a_complete_comparison(self):
        candidate = self.candidate(self.tracker, {"github.com", "tracker.example"})
        base = feed_review.digest(self.tracker.path(self.state).read_bytes())
        original = self.cname.path(self.state).read_bytes()
        for raw in (None, b"broken\n"):
            with self.subTest(raw=raw):
                if raw is None:
                    self.cname.path(self.state).unlink(missing_ok=True)
                else:
                    self.cname.path(self.state).write_bytes(raw)
                result = ImpactContext(self.state, {}).compare(self.tracker, candidate, base_sha256=base)
                self.assertEqual(result["status"], "not-covered")
                self.assertEqual(result["probes"], [])
        # Even a self-consistent digest cannot qualify unsorted feed records.
        body = b"z.example\na.example\n"
        metadata = {"entries": 2, "sha256": sha256(body).hexdigest(), "published_at": None, "updated_at": time.time()}
        self.cname.path(self.state).write_bytes(b"# " + json.dumps(metadata).encode() + b"\n" + body)
        result = ImpactContext(self.state, {}).compare(self.tracker, candidate, base_sha256=base)
        self.assertEqual(result["reason"], "invalid-feed-input")
        self.cname.path(self.state).write_bytes(original)

    def test_changed_inputs_and_wrong_base_refuse_instead_of_reporting_a_delta(self):
        context = ImpactContext(self.state, {})
        candidate = self.candidate(self.tracker, {"tracker.example", "github.com"})
        result = context.compare(self.tracker, candidate, base_sha256="0" * 64)
        self.assertEqual(result["reason"], "base-does-not-match-captured-policy")
        (self.state / "allow.txt").write_text("github.com\n")
        result = context.compare(self.tracker, candidate,
                                 base_sha256=feed_review.digest(self.tracker.path(self.state).read_bytes()))
        self.assertEqual(result["reason"], "policy-inputs-changed")
        self.assertEqual(result["probes"], [])

    def test_malformed_controls_are_not_silently_qualified_as_empty_controls(self):
        (self.state / "filter-controls.json").write_text('{"tracker_pause_until":')
        result = self.compare(self.tracker, {"tracker.example", "github.com"})
        self.assertEqual(result["reason"], "invalid-policy-input")
        self.assertEqual(result["probes"], [])

    def test_bounded_explicit_config_probes_report_omissions(self):
        config = {"block": {"allow": [f"allow-{number:04}.example" for number in range(2000)]}}
        result = self.compare(self.tracker, {"google-analytics.com", "tracker.example"}, config=config)
        self.assertLessEqual(result["probes_evaluated"], MAX_PROBES)
        self.assertEqual(result["limits"]["configured_hosts_sampled"], MAX_CONFIGURED_HOSTS)
        self.assertEqual(result["limits"]["configured_hosts_omitted"], 2000 - MAX_CONFIGURED_HOSTS)
        self.assertIn("allow-0000.example", {row["host"] for row in result["probes"]})
        self.assertNotIn("allow-1999.example", {row["host"] for row in result["probes"]})

    def test_review_rejects_stale_candidate_and_invalid_transition_before_dry_run(self):
        self.stage(self.tracker, {"tracker.example", "github.com"})
        self.install(self.tracker, {"google-analytics.com", "tracker.example", "another.example"})
        row = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]
        self.assertEqual(row["candidate"]["policy_impact"]["reason"], "stale-candidate-base")
        self.stage(self.tracker, {"github.com"})
        row = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]
        self.assertEqual(row["candidate"]["policy_impact"]["reason"], "invalid-transition")

    def test_bootstrap_is_explicitly_uncovered_and_exact_approval_can_still_repair(self):
        self.tracker.path(self.state).unlink()
        self.stage(self.tracker, {"tracker.example", "github.com"})
        row = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]
        candidate = row["candidate"]
        self.assertEqual(candidate["policy_impact"]["reason"], "incomplete-feed-coverage")
        result = feeds.approve_feed(self.state, {}, self.tracker.id,
                                   candidate_sha256=candidate["candidate_sha256"], base_sha256=None)
        self.assertTrue(result["ok"])
        self.assertFalse(result["runtime_acknowledged"])
        self.assertTrue(Policy({}, self.state).ready())
        self.assertEqual(Policy({}, self.state).decision("github.com")["decision"], "blocked")

    def test_change_after_one_comparison_invalidates_that_row_before_return(self):
        self.stage(self.tracker, {"tracker.example", "github.com"})
        compare = ImpactContext.compare

        def change_after(context, *args, **kwargs):
            result = compare(context, *args, **kwargs)
            (self.state / "block.txt").write_text("github.com\n")
            return result

        with patch.object(ImpactContext, "compare", change_after):
            row = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]
        self.assertEqual(row["candidate"]["policy_impact"]["reason"], "policy-inputs-changed")

    def test_specific_shared_hierarchy_roots_hold_without_protecting_individual_tenants(self):
        for root in ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net"):
            with self.subTest(root=root):
                assessment = feed_review.assess(self.tracker, set(), {root})
                self.assertIn("critical-infrastructure-added", assessment["reasons"])
                tenant = "malicious-tenant." + root
                self.assertEqual(feed_review.assess(self.tracker, set(), {tenant})["reasons"], [])
                result = self.compare(self.tracker, {"google-analytics.com", "tracker.example", tenant}, roots=(tenant,))
                self.assertEqual(self.probe(result, tenant)["after"]["decision"], "blocked")
                self.assertEqual(self.probe(result, root)["after"]["decision"], "allowed")

    def test_equal_count_new_service_deny_is_automatically_held_by_real_decision_delta(self):
        old = {"tracker.example", "other.example"}
        new = {"tracker.example", "api.github.com"}
        original = self.install(self.tracker, old)
        self.assertEqual(feed_review.assess(self.tracker, old, new)["reasons"], [])
        report = self.refresh(self.tracker, new)
        self.assertFalse(report["ok"])
        self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
        check = self.refresh_check(report, self.tracker)
        self.assertEqual(check["status"], "compared")
        self.assertEqual(check["automatic_hold_reasons"], ["policy-critical-deny"])
        self.assertEqual(check["new_critical_deny_count"], 1)
        candidate = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]["candidate"]
        self.assertEqual(candidate["state"], "held")
        self.assertEqual(candidate["reasons"], ["policy-critical-deny"])
        self.assertEqual(self.probe(candidate["policy_impact"], "api.github.com")["after"]["decision"], "blocked")

    def test_equal_count_threat_removal_that_allows_public_canary_is_automatically_held(self):
        self.install(self.tracker, {"tracker.example", "other.example"})
        old = {"google-analytics.com", "malware.example"}
        new = {"malware.example", "new-malware.example"}
        original = self.install(self.threat, old)
        self.assertEqual(feed_review.assess(self.threat, old, new)["reasons"], [])
        report = self.refresh(self.threat, new)
        self.assertFalse(report["ok"])
        self.assertEqual(self.threat.path(self.state).read_bytes(), original)
        check = self.refresh_check(report, self.threat)
        self.assertEqual(check["automatic_hold_reasons"], ["policy-canary-allow"])
        self.assertGreater(check["new_public_canary_allow_count"], 0)
        self.assertEqual(Policy({}, self.state).decision("google-analytics.com")["source"], "malware-feed")

    def test_automatic_refresh_can_legitimately_override_only_a_configured_allow_with_threat(self):
        config = {"block": {"allow": ["private-project.example"]}}
        self.install(self.tracker, {"tracker.example", "private-project.example"})
        report = self.refresh(self.threat, {"malware.example", "private-project.example"}, config=config)
        self.assertTrue(report["ok"])
        self.assertEqual(self.refresh_check(report, self.threat)["automatic_hold_reasons"], [])
        decision = Policy(config, self.state).decision("private-project.example")
        self.assertEqual((decision["decision"], decision["category"], decision["can_allow"]), ("blocked", "malware", False))
        self.assertFalse((self.state / "allow.txt").exists())
        self.assertFalse(feed_review.path(self.state, self.threat, "candidate").exists())
        # Attempt receipts stay small and never persist configured domain probes.
        attempt = feeds._attempt_path(self.threat.path(self.state)).read_bytes()
        self.assertLess(len(attempt), 4096)
        self.assertNotIn(b"private-project.example", attempt)

    def test_refresh_rechecks_controls_after_journal_preparation_before_active_rename(self):
        original = self.tracker.path(self.state).read_bytes()
        write = feed_review.write
        injected = False

        def race(state, feed, slot, *args, **kwargs):
            nonlocal injected
            result = write(state, feed, slot, *args, **kwargs)
            if feed == self.tracker and slot == "transition" and not injected:
                injected = True
                (self.state / "allow.txt").write_text("api.github.com\n")
            return result

        with patch("egress_guard.feeds.feed_review.write", side_effect=race):
            report = self.refresh(self.tracker, {"google-analytics.com", "tracker.example", "new.example"})
        self.assertTrue(injected)
        self.assertFalse(report["ok"])
        self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
        self.assertEqual(self.refresh_check(report, self.tracker)["reason"], "policy-inputs-changed")

    def test_refresh_keeps_a_concurrent_active_generation_instead_of_overwriting_it(self):
        concurrent = feeds._snapshot({"concurrent.example", "other.example"}, None)
        write = feed_review.write
        injected = False

        def race(state, feed, slot, *args, **kwargs):
            nonlocal injected
            result = write(state, feed, slot, *args, **kwargs)
            if feed == self.tracker and slot == "transition" and not injected:
                injected = True
                self.tracker.path(self.state).write_bytes(concurrent)
            return result

        with patch("egress_guard.feeds.feed_review.write", side_effect=race):
            report = self.refresh(self.tracker, {"google-analytics.com", "tracker.example", "new.example"})
        self.assertTrue(injected)
        self.assertFalse(report["ok"])
        self.assertEqual(self.tracker.path(self.state).read_bytes(), concurrent)
        self.assertEqual(self.refresh_check(report, self.tracker)["reason"], "policy-inputs-changed")

    def test_control_change_during_active_temp_fsync_refuses_and_keeps_prior_rollback(self):
        original = self.tracker.path(self.state).read_bytes()
        stable = {"google-analytics.com", "tracker.example", "stable.example"}
        self.assertTrue(self.refresh(self.tracker, stable)["ok"])
        current = self.tracker.path(self.state).read_bytes()
        rollback_path = feed_review.path(self.state, self.tracker, "rollback")
        rollback = rollback_path.read_bytes()
        allow = self.state / "allow.txt"
        allow.write_text("api.github.com\n")
        with self.during_active_fsync(allow.unlink) as triggered:
            report = self.refresh(self.tracker, stable | {"api.github.com"})
        self.assertEqual(triggered, [True])
        self.assertFalse(report["ok"])
        self.assertEqual(self.tracker.path(self.state).read_bytes(), current)
        self.assertEqual(rollback_path.read_bytes(), rollback)
        previous = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]["rollback"]
        self.assertEqual(previous["previous_sha256"], feed_review.digest(original))
        self.assertFalse(previous["recovery_pending"])
        self.assertEqual(self.refresh_check(report, self.tracker)["reason"], "policy-inputs-changed")
        self.assertEqual({path.name for path in (self.state / "blocklists").iterdir() if path.name.startswith(".")},
                         {".refresh.sqlite3"})

    def test_explicit_approval_and_rollback_recheck_exact_base_after_temp_fsync(self):
        original = self.tracker.path(self.state).read_bytes()
        self.assertTrue(self.refresh(self.tracker, {"google-analytics.com", "tracker.example", "stable.example"})["ok"])
        current = self.tracker.path(self.state).read_bytes()
        rollback_path = feed_review.path(self.state, self.tracker, "rollback")
        previous_record = rollback_path.read_bytes()
        for action in ("approve", "rollback"):
            with self.subTest(action=action):
                self.tracker.path(self.state).write_bytes(current)
                record = self.stage(self.tracker, {"tracker.example", "api.github.com"})
                concurrent = feeds._snapshot({"concurrent.example", "other.example"}, None)
                mutate = lambda: self.tracker.path(self.state).write_bytes(concurrent)
                with self.during_active_fsync(mutate) as triggered, self.assertRaisesRegex(ValueError, "installed feed changed"):
                    if action == "approve":
                        feeds.approve_feed(self.state, {}, self.tracker.id, candidate_sha256=record.sha256,
                                           base_sha256=feed_review.digest(current))
                    else:
                        feeds.rollback_feed(self.state, {}, self.tracker.id, current_sha256=feed_review.digest(current),
                                            previous_sha256=feed_review.digest(original))
                self.assertEqual(triggered, [True])
                self.assertEqual(self.tracker.path(self.state).read_bytes(), concurrent)
                self.assertEqual(rollback_path.read_bytes(), previous_record)

    def test_candidate_replacement_invalidates_review_and_old_approval_digest(self):
        old_record = self.stage(self.tracker, {"tracker.example", "api.github.com"})
        active = self.tracker.path(self.state).read_bytes()
        compare = ImpactContext.compare

        def replace_candidate(context, *args, **kwargs):
            result = compare(context, *args, **kwargs)
            self.stage(self.tracker, {"tracker.example", "raw.githubusercontent.com"})
            return result

        with patch.object(ImpactContext, "compare", replace_candidate):
            row = feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]
        self.assertEqual(row["candidate"]["policy_impact"]["reason"], "candidate-input-changed")
        with self.assertRaisesRegex(ValueError, "candidate changed"):
            feeds.approve_feed(self.state, {}, self.tracker.id, candidate_sha256=old_record.sha256,
                               base_sha256=feed_review.digest(active))
        self.assertEqual(self.tracker.path(self.state).read_bytes(), active)

    def test_initial_refresh_marks_every_missing_baseline_uncovered_and_still_bootstraps(self):
        for feed in self.selected:
            feed.path(self.state).unlink()
        with patch("egress_guard.feeds._download", return_value=b"one.example\ntwo.example\n"):
            report = feeds.update_feeds(self.state, {})
        self.assertTrue(report["ok"])
        self.assertTrue(Policy({}, self.state).ready())
        for check in report["policy_impact"]["checks"]:
            self.assertEqual(check["status"], "not-covered")
            self.assertEqual(check["reason"], "incomplete-feed-coverage")
            self.assertEqual(check["automatic_hold_reasons"], [])

    def test_pauses_and_timed_exceptions_cannot_mask_automatic_public_service_holds(self):
        for mode in ("pause", "exception"):
            with self.subTest(mode=mode):
                for name in ("filter-controls.json", "tracker-exceptions.json"):
                    (self.state / name).unlink(missing_ok=True)
                if mode == "pause":
                    (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": time.time() + 300}))
                else:
                    (self.state / "tracker-exceptions.json").write_text(json.dumps({"api.github.com": time.time() + 300}))
                original = self.tracker.path(self.state).read_bytes()
                names = {"google-analytics.com", "tracker.example", "api.github.com"}
                result = self.compare(self.tracker, names)
                self.assertEqual(result["review_signals"]["new_critical_denies"], [])
                self.assertIn("api.github.com", result["grant_expiry_counterfactual"]["new_critical_denies"])
                self.assertIn("policy-critical-deny", result["automatic_hold_reasons"])
                report = self.refresh(self.tracker, names)
                self.assertFalse(report["ok"])
                self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
                check = self.refresh_check(report, self.tracker)
                self.assertEqual(check["new_critical_deny_count"], 0)
                self.assertEqual(check["without_temporary_grants"]["new_critical_deny_count"], 1)

    def test_permanent_allow_still_wins_in_both_views_and_expiry_does_not_activate_invalid_grants(self):
        instant = time.time()
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": instant + 300}))
        names = {"google-analytics.com", "tracker.example", "api.github.com"}
        config = {"block": {"allow": ["api.github.com"]}}
        result = self.compare(self.tracker, names, config=config)
        row = self.probe(result, "api.github.com")
        self.assertEqual(row["after"]["source"], "local-allow")
        self.assertEqual(row["without_temporary_grants"]["after"]["source"], "local-allow")
        self.assertEqual(result["automatic_hold_reasons"], [])
        self.assertTrue(self.refresh(self.tracker, names, config=config)["ok"])
        (self.state / "filter-controls.json").unlink()
        self.install(self.tracker, {"google-analytics.com", "tracker.example"})
        far_future = instant + 2 * MAX_EXCEPTION_SECONDS
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"api.github.com": far_future}))
        result = self.compare(self.tracker, names)
        self.assertGreater(result["grant_expiry_counterfactual"]["evaluated_at"], far_future)
        self.assertEqual(self.probe(result, "api.github.com")["without_temporary_grants"]["after"]["source"], "tracker-feed")

    def test_component_cache_reuses_only_unchanged_verified_file_observations(self):
        cache = ComponentCache()
        with patch("egress_guard.feed_impact._installed", wraps=feeds._installed) as installed:
            first = ImpactContext(self.state, {}, component_cache=cache)
            self.assertIsNone(first.reason)
            count = installed.call_count
            self.assertEqual(count, len(self.selected))
            self.assertIsNone(ImpactContext(self.state, {}, component_cache=cache).reason)
            self.assertEqual(installed.call_count, count)
            target = self.tracker.path(self.state)
            original = target.stat()
            replacement = target.with_suffix(".new")
            replacement.write_bytes(target.read_bytes())
            os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
            replacement.replace(target)
            self.assertIsNone(ImpactContext(self.state, {}, component_cache=cache).reason)
            self.assertEqual(installed.call_count, count + 1)

    def test_packaged_corpus_has_exact_reviewable_roles_hash_and_port_context(self):
        public, corpus = load_corpus()
        self.assertEqual(corpus["sha256"], CORPUS_SHA256)
        self.assertEqual((corpus["public_hosts"], corpus["public_contexts"], corpus["synthetic_contexts"]), (64, 95, 31))
        self.assertEqual(corpus["port"], 443)
        self.assertFalse(corpus["network_requests"])
        by_role = {role: {host for host, origin, _ in public if origin == role}
                   for role in {origin for _, origin, _ in public}}
        self.assertEqual(by_role["public-tracker"], set(feed_review.TRACKER_ANCHORS))
        self.assertEqual(by_role["public-shared-service"], set(feed_review.CRITICAL_HOSTS))
        self.assertEqual(by_role["public-safety"], set(SAFETY_HOSTS))
        self.assertEqual(len(by_role["public-service-endpoint"]), 4)
        self.assertIn("dns.google", by_role["public-doh"])
        result = self.compare(self.tracker, {"google-analytics.com", "tracker.example"})
        self.assertEqual(result["corpus"], corpus)
        self.assertEqual({row["port"] for row in result["probes"]}, {443})

    def test_doh_canary_removal_holds_only_a_previously_blocked_decision(self):
        doh = replace(feeds.DOH, minimum=1)
        self.selected = (*self.selected, doh)
        original = self.install(doh, {"dns.google", "old-resolver.example"})
        names = {"other-resolver.example", "new-resolver.example"}
        result = self.compare(doh, names)
        row = self.probe(result, "dns.google")
        self.assertEqual((row["before"]["category"], row["before"]["can_allow"]), ("doh", True))
        self.assertEqual(row["after"]["decision"], "allowed")
        self.assertIn("policy-canary-allow", result["automatic_hold_reasons"])
        report = self.refresh(doh, names)
        self.assertFalse(report["ok"])
        self.assertEqual(doh.path(self.state).read_bytes(), original)
        self.assertEqual(self.refresh_check(report, doh)["automatic_hold_reasons"], ["policy-canary-allow"])
        self.selected = tuple(feed for feed in self.selected if feed != doh)
        disabled = self.compare(self.tracker, {"google-analytics.com", "tracker.example", "new.example"},
                                config={"block": {"block_encrypted_dns": False}})
        self.assertEqual(self.probe(disabled, "dns.google")["before"]["decision"], "allowed")
        self.assertEqual(disabled["automatic_hold_reasons"], [])

    def test_limit_counts_actual_configured_hosts_and_never_silently_omits_public_context(self):
        _, corpus = load_corpus()
        config = {"block": {"allow": [f"allow-{number:04}.example" for number in range(200)]}}
        with patch("egress_guard.feed_impact.MAX_PROBES", corpus["public_contexts"] + 1):
            result = self.compare(self.tracker, {"google-analytics.com", "tracker.example"}, config=config)
        self.assertEqual(result["status"], "compared")
        self.assertEqual(result["limits"]["configured_hosts_attempted"], MAX_CONFIGURED_HOSTS)
        self.assertEqual(result["limits"]["configured_hosts_sampled"], 1)
        self.assertEqual(result["limits"]["configured_hosts_omitted"], 199)
        self.assertEqual(result["limits"]["public_contexts_omitted"], 0)
        with patch("egress_guard.feed_impact.MAX_PROBES", corpus["public_contexts"] - 1):
            result = self.compare(self.tracker, {"google-analytics.com", "tracker.example"})
        self.assertEqual(result["reason"], "public-probe-limit")

    def test_invalid_pinned_corpus_refuses_refresh_without_replacing_installed_cache(self):
        original = self.tracker.path(self.state).read_bytes()
        with patch("egress_guard.feed_impact.CORPUS_SHA256", "0" * 64):
            report = self.refresh(self.tracker, {"google-analytics.com", "tracker.example", "new.example"})
        self.assertFalse(report["ok"])
        self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
        check = self.refresh_check(report, self.tracker)
        self.assertEqual(check["status"], "not-covered")
        self.assertEqual(check["reason"], "invalid-probe-corpus")
        self.assertIsNone(check["corpus"])

    def test_config_mismatch_or_change_during_initial_binding_refuses_before_download(self):
        path, config = self.configuration_file()
        original = self.tracker.path(self.state).read_bytes()
        path.write_text('[block]\nallow = []\n')
        with patch("egress_guard.feeds._download", side_effect=AssertionError("downloaded before binding")):
            result = feeds.update_feeds(self.state, config, config_file=path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["policy_impact"]["reason"], "configuration-binding-failed")
        config = load_config(path)
        read_config = load_config

        def change_after_read(source):
            loaded = read_config(source)
            # Same normalized values still require a stable file observation.
            source.write_text('[block]\nallow = []\n# changed during binding\n')
            return loaded

        with patch("egress_guard.config.load_config", side_effect=change_after_read), \
                patch("egress_guard.feeds._download", side_effect=AssertionError("downloaded before binding")):
            result = feeds.update_feeds(self.state, config, config_file=path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["policy_impact"]["reason"], "configuration-binding-failed")
        self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
        self.assertFalse((self.state / "blocklists" / ".refresh.sqlite3").exists())

    def test_default_and_custom_config_change_during_download_refuses_old_settings(self):
        for custom in (False, True):
            with self.subTest(custom=custom):
                path, config = self.configuration_file(custom=custom)
                original = self.tracker.path(self.state).read_bytes()
                changed = []

                def download(feed):
                    if not changed:
                        changed.append(True)
                        path.write_text('[block]\nallow = []\n')
                    entries = ({"google-analytics.com", "tracker.example", "api.github.com"}
                               if feed == self.tracker else feeds.read_cached_feed(self.state, feed))
                    return ("\n".join(sorted(entries)) + "\n").encode("ascii")

                with patch("egress_guard.feeds._download", side_effect=download):
                    result = feeds.update_feeds(self.state, config, config_file=path)
                self.assertFalse(result["ok"])
                self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
                self.assertEqual(self.refresh_check(result, self.tracker)["reason"], "configuration-input-changed")
                self.assertEqual(Policy(load_config(path), self.state).decision("api.github.com")["decision"], "allowed")

    def test_default_and_custom_config_changes_after_temp_fsync_refuse_publication(self):
        for custom in (False, True):
            with self.subTest(custom=custom):
                path, config = self.configuration_file(custom=custom)
                original = self.tracker.path(self.state).read_bytes()

                def download(feed):
                    entries = ({"google-analytics.com", "tracker.example", "api.github.com"}
                               if feed == self.tracker else feeds.read_cached_feed(self.state, feed))
                    return ("\n".join(sorted(entries)) + "\n").encode("ascii")

                with self.during_active_fsync(lambda: path.write_text('[block]\nallow = []\n')) as triggered, \
                        patch("egress_guard.feeds._download", side_effect=download):
                    result = feeds.update_feeds(self.state, config, config_file=path)
                self.assertEqual(triggered, [True])
                self.assertFalse(result["ok"])
                self.assertEqual(self.tracker.path(self.state).read_bytes(), original)
                self.assertEqual(self.refresh_check(result, self.tracker)["reason"], "configuration-input-changed")

    def test_missing_bound_config_becoming_present_is_a_change_even_with_identical_defaults(self):
        path = self.state / "initially-missing.toml"
        config = load_config(path)
        original = self.tracker.path(self.state).read_bytes()

        def download(feed):
            if not path.exists():
                path.write_text('[logging]\nhistory = "none"\n')
            entries = feeds.read_cached_feed(self.state, feed)
            return ("\n".join(sorted(entries)) + "\n").encode("ascii")

        with patch("egress_guard.feeds._download", side_effect=download):
            result = feeds.update_feeds(self.state, config, config_file=path)
        self.assertFalse(result["ok"])
        self.assertEqual(load_config(path), config)
        self.assertEqual(self.refresh_check(result, self.tracker)["reason"], "configuration-input-changed")
        self.assertEqual(self.tracker.path(self.state).read_bytes(), original)

    def test_bound_review_detects_config_change_but_no_path_api_uses_only_supplied_settings(self):
        path, config = self.configuration_file(custom=True)
        self.stage(self.tracker, {"google-analytics.com", "tracker.example", "api.github.com"})
        original = self.tracker.path(self.state).read_bytes()
        compare = ImpactContext.compare

        def change_after(context, *args, **kwargs):
            result = compare(context, *args, **kwargs)
            path.write_text('[block]\nallow = []\n')
            return result

        with patch.object(ImpactContext, "compare", change_after):
            report = feeds.review_feeds(self.state, config, self.tracker.id, config_file=path)
        self.assertEqual(report["configuration_status"], "changed")
        self.assertEqual(report["feeds"][0]["candidate"]["policy_impact"]["reason"], "configuration-input-changed")
        with patch("egress_guard.config.load_config", side_effect=AssertionError("guessed a config file")):
            report = feeds.review_feeds(self.state, config, self.tracker.id)
        impact = report["feeds"][0]["candidate"]["policy_impact"]
        self.assertEqual(report["configuration_status"], "supplied-settings")
        self.assertFalse(impact["configuration_bound"])
        self.assertEqual(self.probe(impact, "api.github.com")["after"]["source"], "local-allow")
        self.assertEqual(self.tracker.path(self.state).read_bytes(), original)

    def test_cli_and_dashboard_forward_the_actual_custom_config_path(self):
        from egress_guard.cli import main
        from egress_guard.dashboard_app import Application

        path, config = self.configuration_file(custom=True)
        environment = {"EGRESS_GUARD_DATA": str(self.state), "EGRESS_GUARD_CONFIG": str(path)}
        previous_umask = os.umask(0o077)
        try:
            with patch.dict(os.environ, environment), redirect_stdout(io.StringIO()), \
                    patch("egress_guard.cli.update_feeds", return_value={"ok": True}) as update:
                self.assertEqual(main(["refresh"]), 0)
                self.assertEqual(update.call_args.args, (self.state, config))
                self.assertEqual(update.call_args.kwargs, {"config_file": path})
            with patch.dict(os.environ, environment), redirect_stdout(io.StringIO()), \
                    patch("egress_guard.cli.review_feeds", return_value={"feeds": []}) as review:
                self.assertEqual(main(["feed-review", self.tracker.id]), 0)
                self.assertEqual(review.call_args.args, (self.state, config, self.tracker.id))
                self.assertEqual(review.call_args.kwargs, {"config_file": path})
        finally:
            os.umask(previous_umask)
        application = Application(self.state, path)
        with patch("egress_guard.dashboard_app.update_feeds", return_value={"ok": True}) as update, \
                patch("egress_guard.dashboard_app.threading.Thread") as worker:
            worker.return_value.start.side_effect = lambda: worker.call_args.kwargs["target"]()
            application.action({"action": "refresh_filters"})
            self.assertEqual(update.call_args.args, (self.state, config))
            self.assertEqual(update.call_args.kwargs, {"config_file": path})
            self.assertFalse(application.refreshing)

    def test_real_review_cannot_write_read_history_or_attempt_network(self):
        self.stage(self.tracker, {"tracker.example", "github.com"})
        (self.state / "activity.sqlite3").write_bytes(b"SYNTHETIC HISTORY MUST NOT BE OPENED")

        def snapshot():
            return {str(path.relative_to(self.state)): (sha256(path.read_bytes()).hexdigest(),
                    path.stat().st_mode, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
                    for path in self.state.rglob("*") if path.is_file()}

        before = snapshot()
        code = r'''
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch
from egress_guard import feeds
from egress_guard.feed_impact import ImpactContext
state = Path(sys.argv[1]).resolve()
selected = (replace(feeds.TRACKERS["pro.plus"], minimum=1),
            replace(feeds.MALWARE, minimum=1), replace(feeds.CNAME_FEEDS[0], minimum=1))
allowed = {"block.txt", "allow.txt", "filter-controls.json", "tracker-exceptions.json"}
for feed in selected:
    allowed.add(feed.path(state).name)
    allowed.update(feed.id + "." + slot for slot in ("candidate", "rollback", "transition"))
reads = 0
def audit(event, args):
    global reads
    if event == "open":
        path, mode, flags = args
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError("review attempted a write")
        if isinstance(path, (str, bytes)):
            target = Path(os.fsdecode(path)).absolute()
            if state in target.parents:
                reads += 1
                if target.name not in allowed:
                    raise AssertionError("review opened non-policy state")
    if event.startswith("socket.") or event in {"sqlite3.connect", "subprocess.Popen", "os.mkdir", "os.remove",
                                               "os.rename", "os.rmdir", "os.chmod", "os.link", "os.symlink"}:
        raise AssertionError("review attempted a forbidden side effect")
sys.addaudithook(audit)
with patch("egress_guard.feeds.selected_feeds", return_value=selected), \
     patch("egress_guard.policy.selected_feeds", return_value=selected):
    result = feeds.review_feeds(state, {}, selected[0].id)
print(json.dumps({"status": result["feeds"][0]["candidate"]["policy_impact"]["status"], "policy_reads": reads}))
'''
        child = subprocess.run([sys.executable, "-B", "-c", code, str(self.state)],
                               text=True, capture_output=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result["status"], "compared")
        self.assertGreater(result["policy_reads"], 0)
        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()
