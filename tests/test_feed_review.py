"""Feed-change authority, quarantine, exact approvals and interrupted publication."""
import contextlib
from dataclasses import replace
import datetime as dt
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from egress_guard import feed_review, feeds
from egress_guard.cli import main
from egress_guard.policy import Policy


SOURCE = Path(__file__).resolve().parents[1] / "src"
INITIAL = {"google-analytics.com", "one.test", "two.test", "three.test"}
POISONED = {"github.com", "one.test", "two.test", "three.test"}
OTHER = {"threat.test", "other-threat.test"}


class FeedReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.tracker = replace(feeds.TRACKERS["pro.plus"], minimum=2)
        self.threat = replace(feeds.MALWARE, minimum=2)
        self.selected = (self.tracker, self.threat)
        for target in ("egress_guard.feeds.selected_feeds", "egress_guard.policy.selected_feeds"):
            patched = patch(target, return_value=self.selected)
            patched.start()
            self.addCleanup(patched.stop)

    def refresh(self, names, *, published=None):
        def download(feed):
            entries = names if feed == self.tracker else OTHER
            header = f"# TimeUpdated: {published}\n" if published else ""
            return (header + "\n".join(sorted(entries)) + "\n").encode("ascii")
        with patch("egress_guard.feeds._download", side_effect=download):
            return feeds.update_feeds(self.state, {})

    def row(self):
        return feeds.review_feeds(self.state, {}, self.tracker.id)["feeds"][0]

    def active(self):
        return self.tracker.path(self.state).read_bytes()

    def stage(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        self.assertFalse(self.refresh(POISONED)["ok"])
        return self.row()["candidate"]

    def approve(self, candidate=None):
        candidate = candidate or self.row()["candidate"]
        return feeds.approve_feed(self.state, {}, self.tracker.id,
                                  candidate_sha256=candidate["candidate_sha256"],
                                  base_sha256=candidate["base_sha256"])

    def rollback(self):
        previous = self.row()["rollback"]
        return feeds.rollback_feed(self.state, {}, self.tracker.id,
                                   current_sha256=previous["current_sha256"],
                                   previous_sha256=previous["previous_sha256"])

    def test_same_size_poisoning_is_held_without_changing_ready_policy_or_active_bytes(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        original = self.active()
        before = Policy({}, self.state)
        report = self.refresh(POISONED)
        after = Policy({}, self.state)
        self.assertFalse(report["ok"])
        self.assertEqual(report["feeds"][0]["status"], "using-previous")
        self.assertIn("quarantined", report["feeds"][0]["error"])
        self.assertEqual(self.active(), original)
        self.assertTrue(before.ready() and after.ready())
        self.assertEqual(before.revision, after.revision)
        self.assertEqual(after.decision("google-analytics.com")["decision"], "blocked")
        self.assertEqual(after.decision("github.com")["decision"], "allowed")
        candidate = self.row()["candidate"]
        self.assertEqual(candidate["state"], "held")
        self.assertEqual(candidate["reasons"], ["tracker-coverage-removed", "critical-infrastructure-added"])
        self.assertEqual((candidate["delta"]["entries_added"], candidate["delta"]["entries_removed"]), (1, 1))
        self.assertEqual(candidate["base_sha256"], feed_review.digest(original))

    def test_initial_critical_parent_is_held_but_absent_canaries_are_not_required(self):
        self.assertFalse(self.refresh(POISONED)["ok"])
        row = self.row()
        self.assertEqual(row["active"]["state"], "missing")
        self.assertIsNone(row["candidate"]["base_sha256"])
        self.assertFalse(Policy({}, self.state).ready())
        self.assertEqual(row["candidate"]["reasons"], ["critical-infrastructure-added"])
        self.approve(row["candidate"])
        self.assertTrue(Policy({}, self.state).ready())
        self.assertEqual(Policy({}, self.state).decision("github.com")["decision"], "blocked")
        self.assertIsNone(self.row()["rollback"])

    def test_canary_requirement_is_relative_and_critical_tenants_are_not_hard_allowed(self):
        ordinary = {"one.test", "two.test", "bad-tenant.github.io"}
        self.assertTrue(self.refresh(ordinary)["ok"])
        self.assertIsNone(self.row()["candidate"])
        policy = Policy({}, self.state)
        self.assertEqual(policy.decision("bad-tenant.github.io")["decision"], "blocked")
        self.assertEqual(policy.decision("other-tenant.github.io")["decision"], "allowed")
        (self.state / "block.txt").write_text("github.com\n")
        self.assertEqual(Policy({}, self.state).decision("github.com")["source"], "local-block")

    def test_coverage_uses_exact_cname_and_suffix_tracker_semantics(self):
        exact = replace(feeds.CNAME_FEEDS[0], minimum=2)
        previous, following = {"www.google-analytics.com"}, {"google-analytics.com"}
        self.assertFalse(feed_review.assess(self.tracker, previous, following)["reasons"])
        self.assertEqual(feed_review.assess(exact, previous, following)["reasons"], ["tracker-coverage-removed"])
        # A new parent covers the critical host, even when the spelling differs.
        self.assertIn("critical-infrastructure-added",
                      feed_review.assess(self.tracker, set(), {"googleapis.com"})["reasons"])
        self.assertFalse(feed_review.assess(self.tracker, set(), {"bad.googleapis.com"})["reasons"])

    def test_approval_binds_exact_candidate_and_base_and_never_creates_allow_rules(self):
        candidate = self.stage()
        original = self.active()
        result = self.approve(candidate)
        self.assertTrue(result["ok"])
        self.assertFalse(result["runtime_acknowledged"])
        self.assertEqual(feeds.read_cached_feed(self.state, self.tracker), POISONED)
        self.assertEqual(result["installed_sha256"], feed_review.digest(self.active()))
        self.assertEqual(self.row()["rollback"]["previous_sha256"], feed_review.digest(original))
        self.assertIsNone(self.row()["candidate"])
        self.assertFalse((self.state / "allow.txt").exists())
        for path in feed_review.directory(self.state).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(feed_review.directory(self.state).stat().st_mode & 0o777, 0o700)

    def test_wrong_digest_or_changed_base_cannot_publish(self):
        candidate = self.stage()
        original = self.active()
        with self.assertRaisesRegex(ValueError, "candidate changed"):
            feeds.approve_feed(self.state, {}, self.tracker.id, candidate_sha256="0" * 64,
                               base_sha256=candidate["base_sha256"])
        self.assertEqual(self.active(), original)
        replacement = feeds._snapshot(INITIAL, None)  # Same names, different exact installed generation.
        self.tracker.path(self.state).write_bytes(replacement)
        self.assertEqual(self.row()["candidate"]["state"], "stale-base")
        with self.assertRaisesRegex(ValueError, "installed feed changed"):
            self.approve(candidate)
        self.assertEqual(self.active(), replacement)

    def test_identical_held_download_keeps_candidate_identity_and_original_timestamps(self):
        candidate = self.stage()
        with patch("egress_guard.feeds.time.time", return_value=time.time() + 60):
            self.assertFalse(self.refresh(POISONED)["ok"])
        again = self.row()["candidate"]
        self.assertEqual(again["candidate_sha256"], candidate["candidate_sha256"])
        self.assertEqual(again["snapshot"], candidate["snapshot"])

    def test_upstream_recovery_can_install_safe_data_and_discard_obsolete_candidate(self):
        self.stage()
        safe = INITIAL | {"new-tracker.test"}
        self.assertTrue(self.refresh(safe)["ok"])
        self.assertEqual(feeds.read_cached_feed(self.state, self.tracker), safe)
        self.assertIsNone(self.row()["candidate"])

    def test_corrupt_candidate_is_visible_and_can_be_discarded_only_by_its_exact_hash(self):
        self.stage()
        original = self.active()
        path = feed_review.path(self.state, self.tracker, "candidate")
        path.write_bytes(path.read_bytes()[:-1] + b"X")
        candidate = self.row()["candidate"]
        self.assertEqual(candidate["state"], "invalid")
        with self.assertRaises(ValueError):
            feeds.approve_feed(self.state, {}, self.tracker.id, candidate_sha256=candidate["candidate_sha256"],
                               base_sha256=feed_review.digest(original))
        with self.assertRaisesRegex(ValueError, "candidate changed"):
            feeds.discard_feed(self.state, {}, self.tracker.id, candidate_sha256="0" * 64)
        feeds.discard_feed(self.state, {}, self.tracker.id, candidate_sha256=candidate["candidate_sha256"])
        self.assertEqual(self.active(), original)
        self.assertIsNone(self.row()["candidate"])

    def test_record_identity_cannot_be_transferred_to_another_feed(self):
        self.stage()
        copied = feed_review.path(self.state, self.threat, "candidate")
        copied.write_bytes(feed_review.path(self.state, self.tracker, "candidate").read_bytes())
        row = feeds.review_feeds(self.state, {}, self.threat.id)["feeds"][0]
        self.assertEqual(row["candidate"]["state"], "invalid")
        with self.assertRaisesRegex(ValueError, "metadata"):
            feeds.approve_feed(self.state, {}, self.threat.id,
                               candidate_sha256=row["candidate"]["candidate_sha256"],
                               base_sha256=row["active"]["snapshot_sha256"])

    def test_malformed_review_metadata_cannot_be_approved(self):
        self.stage()
        original = self.active()
        path = feed_review.path(self.state, self.tracker, "candidate")
        header, payload = path.read_bytes().split(b"\n", 1)
        metadata = json.loads(header[len(feed_review.PREFIX):])
        mutations = (
            {"schema": True}, {"cause": []}, {"base_sha256": "A" * 64},
            {"payload_sha256": "x" * 64}, {"source_url": "https://other.invalid/feed"},
            {"created_at": time.time() + 2 * 86400}, {"unexpected": "field"},
        )
        malformed = [feed_review.PREFIX + json.dumps({**metadata, **change}).encode() + b"\n" + payload
                     for change in mutations]
        malformed.extend((
            feed_review.PREFIX + b'{"schema":1,"schema":1}\n' + payload,
            feed_review.PREFIX + b" " * feed_review.MAX_HEADER_BYTES + b"\n" + payload,
        ))
        for index, raw in enumerate(malformed):
            with self.subTest(index=index):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    feeds.approve_feed(self.state, {}, self.tracker.id,
                                       candidate_sha256=feed_review.digest(raw),
                                       base_sha256=feed_review.digest(original))
                self.assertEqual(self.active(), original)

    def test_approval_does_not_override_size_loss_publication_or_record_validation(self):
        published = time.time() - 60
        stamp = dt.datetime.fromtimestamp(published, dt.timezone.utc).isoformat()
        initial = {"google-analytics.com"} | {f"host{i}.test" for i in range(9)}
        self.assertTrue(self.refresh(initial, published=stamp)["ok"])
        original = self.active()
        base = feed_review.digest(original)
        candidates = (
            (feeds._snapshot({"one.test", "two.test"}, published), "more than half"),
            (feeds._snapshot(initial, published - 1), "older"),
            (feeds._snapshot(initial, None), "older"),
            (feeds._snapshot(initial, time.time() + 2 * 86400), "metadata"),
            (feeds._snapshot(initial | {"invalid record.test"}, published), "invalid record"),
        )
        for raw, error in candidates:
            with self.subTest(error=error):
                record = feed_review.write(self.state, self.tracker, "candidate", raw, base,
                                           cause="refresh", limit=feeds.MAX_FEED_BYTES)
                with self.assertRaisesRegex(ValueError, error):
                    feeds.approve_feed(self.state, {}, self.tracker.id,
                                       candidate_sha256=record.sha256, base_sha256=base)
                self.assertEqual(self.active(), original)

    def test_known_old_rollback_preserves_bytes_and_age_and_holds_future_refreshes(self):
        old = time.time() - 3 * 86400
        old_stamp = dt.datetime.fromtimestamp(old, dt.timezone.utc).isoformat()
        new_stamp = dt.datetime.now(dt.timezone.utc).isoformat()
        self.assertTrue(self.refresh(INITIAL, published=old_stamp)["ok"])
        original = self.active()
        self.assertTrue(self.refresh(INITIAL | {"new.test"}, published=new_stamp)["ok"])
        result = self.rollback()
        self.assertTrue(result["refresh_held_until_approval"])
        self.assertEqual(self.active(), original)
        row = self.row()
        self.assertTrue(row["active"]["snapshot"]["stale"])
        self.assertEqual(feeds.feed_status(self.state)[0]["status"], "stale")
        self.assertTrue(row["rollback"]["refresh_held"])
        self.assertFalse(self.refresh(INITIAL | {"new.test"}, published=new_stamp)["ok"])
        self.assertEqual(self.active(), original)
        self.assertIn("explicit-rollback-hold", self.row()["candidate"]["reasons"])
        self.approve()
        self.assertFalse(self.row()["rollback"]["refresh_held"])

    def test_rollback_requires_current_and_immediately_previous_exact_generations(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        self.assertTrue(self.refresh(INITIAL | {"new.test"})["ok"])
        original, rollback = self.active(), self.row()["rollback"]
        for current, previous in (("0" * 64, rollback["previous_sha256"]),
                                  (rollback["current_sha256"], "0" * 64)):
            with self.subTest(current=current), self.assertRaises(ValueError):
                feeds.rollback_feed(self.state, {}, self.tracker.id,
                                    current_sha256=current, previous_sha256=previous)
            self.assertEqual(self.active(), original)

    def test_unchanged_refresh_keeps_the_last_distinct_generation_available(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        original = self.active()
        changed = INITIAL | {"new.test"}
        self.assertTrue(self.refresh(changed)["ok"])
        for _ in range(2):
            self.assertTrue(self.refresh(changed)["ok"])
        self.assertEqual(self.row()["rollback"]["previous_sha256"], feed_review.digest(original))
        self.rollback()
        self.assertEqual(self.active(), original)

    def test_active_write_failure_preserves_current_and_existing_rollback(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        original = self.active()
        self.assertTrue(self.refresh(INITIAL | {"second.test"})["ok"])
        current = self.active()
        atomic = feeds.atomic_private

        def fail_active(path, content):
            if path == self.tracker.path(self.state):
                raise OSError("injected active rename failure")
            return atomic(path, content)

        with patch("egress_guard.feeds.atomic_private", side_effect=fail_active):
            self.assertFalse(self.refresh(INITIAL | {"third.test"})["ok"])
        self.assertEqual(self.active(), current)
        self.assertEqual(self.row()["rollback"]["previous_sha256"], feed_review.digest(original))

    def test_failed_journal_finalize_still_has_truthful_installed_state_and_recoverable_rollback(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        original = self.active()
        rename = os.replace

        def fail_finalize(source, target):
            if Path(target) == feed_review.path(self.state, self.tracker, "rollback"):
                raise OSError("injected journal finalization failure")
            return rename(source, target)

        changed = INITIAL | {"second.test"}
        with patch("egress_guard.feeds.os.replace", side_effect=fail_finalize):
            self.assertTrue(self.refresh(changed)["ok"])
            current = self.active()
            self.assertEqual(feeds.read_cached_feed(self.state, self.tracker), changed)
            self.assertTrue(self.row()["rollback"]["recovery_pending"])
            # A later write cannot destroy an unfinalized, applicable rollback.
            self.assertFalse(self.refresh(INITIAL | {"third.test"})["ok"])
            self.assertEqual(self.active(), current)
        self.assertEqual(self.row()["rollback"]["previous_sha256"], feed_review.digest(original))
        self.rollback()
        self.assertEqual(self.active(), original)

    def test_failed_candidate_write_preserves_the_prior_verified_candidate(self):
        candidate = self.stage()
        original = self.active()
        atomic = feed_review.atomic_private

        def fail_candidate(path, content):
            if path == feed_review.path(self.state, self.tracker, "candidate"):
                raise OSError("injected candidate write failure")
            return atomic(path, content)

        with patch("egress_guard.feed_review.atomic_private", side_effect=fail_candidate):
            self.assertFalse(self.refresh(POISONED | {"new.test"})["ok"])
        self.assertEqual(self.active(), original)
        self.assertEqual(self.row()["candidate"]["candidate_sha256"], candidate["candidate_sha256"])

    def test_approval_cleanup_or_status_write_failure_cannot_hide_successful_publication(self):
        candidate = self.stage()
        with patch("egress_guard.feeds._discard_candidate_file", return_value=False), \
             patch("egress_guard.feeds._record_attempt", side_effect=OSError("status write failed")):
            result = self.approve(candidate)
        self.assertTrue(result["ok"])
        self.assertTrue(result["candidate_cleanup_pending"])
        self.assertFalse(result["attempt_recorded"])
        self.assertEqual(result["installed_sha256"], feed_review.digest(self.active()))
        self.assertEqual(self.row()["candidate"]["state"], "already-current")
        original = self.active()
        retried = self.approve(candidate)
        self.assertTrue(retried["already_current"])
        self.assertEqual(self.active(), original)
        self.assertIsNone(self.row()["candidate"])

    def test_unreadable_rollback_state_blocks_publication_without_destroying_history(self):
        self.assertTrue(self.refresh(INITIAL)["ok"])
        self.assertTrue(self.refresh(INITIAL | {"second.test"})["ok"])
        original = self.active()
        path = feed_review.path(self.state, self.tracker, "rollback")
        rollback_bytes = path.read_bytes()
        read = feed_review.read

        def failed(state, feed, slot, limit):
            if feed == self.tracker and slot == "rollback":
                raise OSError("temporary read failure")
            return read(state, feed, slot, limit)

        with patch("egress_guard.feed_review.read", side_effect=failed):
            self.assertFalse(self.refresh(INITIAL | {"third.test"})["ok"])
            self.assertEqual(self.row()["rollback"]["state"], "invalid")
        self.assertEqual(self.active(), original)
        self.assertEqual(path.read_bytes(), rollback_bytes)
        self.assertTrue(self.row()["rollback"]["available"])

    def test_conflicting_active_generation_during_preparation_is_not_overwritten(self):
        candidate = self.stage()
        conflicting = feeds._snapshot(INITIAL | {"independent-change.test"}, None)
        write = feed_review.write

        def changed(state, feed, slot, payload, base, **kwargs):
            result = write(state, feed, slot, payload, base, **kwargs)
            if feed == self.tracker and slot == "transition":
                self.tracker.path(self.state).write_bytes(conflicting)
            return result

        with patch("egress_guard.feed_review.write", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "installed feed changed"):
                self.approve(candidate)
        self.assertEqual(self.active(), conflicting)

    def test_review_is_read_only_and_mutations_share_the_refresh_lock(self):
        missing = self.state / "not-created"
        self.assertEqual(feeds.review_feeds(missing, {})["feeds"][0]["active"]["state"], "missing")
        self.assertFalse(missing.exists())
        candidate = self.stage()
        with sqlite3.connect(self.state / "blocklists/.refresh.sqlite3") as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(feeds.RefreshBusy, "lock unavailable"):
                self.approve(candidate)
            with self.assertRaises(feeds.RefreshBusy):
                feeds.discard_feed(self.state, {}, self.tracker.id, candidate_sha256=candidate["candidate_sha256"])
        self.approve(candidate)
        with sqlite3.connect(self.state / "blocklists/.refresh.sqlite3") as connection:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(feeds.RefreshBusy):
                self.rollback()

    def test_fixed_id_enabled_scope_and_bounded_non_link_records(self):
        for name in ("../escape", "unknown", "", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                feeds.approve_feed(self.state, {}, name, candidate_sha256="0" * 64, base_sha256=None)
        with self.assertRaisesRegex(ValueError, "enabled"):
            feeds.approve_feed(self.state, {}, feeds.TRACKERS["pro"].id,
                               candidate_sha256="0" * 64, base_sha256=None)
        path = self.state / "too-large"
        path.write_bytes(b"x" * 33)
        with self.assertRaisesRegex(ValueError, "bounded"):
            feed_review.read_regular(path, 32)
        link = self.state / "link"
        link.symlink_to(path)
        with self.assertRaises((OSError, ValueError)):
            feed_review.read_regular(link, 64)
        if hasattr(os, "mkfifo"):
            fifo = self.state / "pipe"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular"):
                feed_review.read_regular(fifo, 64)

    def test_real_process_interruption_before_and_after_active_rename_recovers_correct_generation(self):
        child = r'''
from dataclasses import replace
from pathlib import Path
import os, sys
from egress_guard import feeds
state, point = Path(sys.argv[1]), sys.argv[2]
tracker = replace(feeds.TRACKERS["pro.plus"], minimum=2)
threat = replace(feeds.MALWARE, minimum=2)
feeds.selected_feeds = lambda config: (tracker, threat)
feeds._download = lambda feed: (b"google-analytics.com\nthird.test\n" if feed == tracker
                               else b"other-threat.test\nthreat.test\n")
atomic = feeds.atomic_private
def interrupt(path, content):
    if path == tracker.path(state):
        if point == "before": os._exit(91)
        atomic(path, content)
        os._exit(92)
    return atomic(path, content)
feeds.atomic_private = interrupt
feeds.update_feeds(state, {})
raise AssertionError("interruption point was not reached")
'''
        parent_state = self.state
        for point, code in (("before", 91), ("after", 92)):
            with self.subTest(point=point):
                self.state = parent_state / point
                self.assertTrue(self.refresh({"google-analytics.com", "first.test"})["ok"])
                first = self.active()
                self.assertTrue(self.refresh({"google-analytics.com", "second.test"})["ok"])
                second = self.active()
                process = subprocess.run([sys.executable, "-B", "-c", child, str(self.state), point],
                                         cwd=parent_state, env={**os.environ, "PYTHONPATH": str(SOURCE),
                                                                "PYTHONDONTWRITEBYTECODE": "1"},
                                         capture_output=True, timeout=10)
                self.assertEqual(process.returncode, code, process.stderr.decode())
                row = self.row()
                previous = first if point == "before" else second
                self.assertEqual(row["rollback"]["previous_sha256"], feed_review.digest(previous))
                self.assertEqual(row["rollback"]["recovery_pending"], point == "after")
                current = self.active()
                self.assertTrue(self.refresh({"google-analytics.com", "fourth.test"})["ok"])
                self.assertEqual(self.row()["rollback"]["previous_sha256"], feed_review.digest(current))
                self.assertFalse(self.row()["rollback"]["recovery_pending"])
        self.state = parent_state

    def test_cli_review_approve_rollback_and_discard_require_concrete_digests(self):
        environment = {"EGRESS_GUARD_DATA": str(self.state), "EGRESS_GUARD_CONFIG": str(self.state / "config.toml")}
        candidate = self.stage()

        def command(arguments):
            out, error = io.StringIO(), io.StringIO()
            previous_umask = os.umask(0o077)
            try:
                with patch.dict(os.environ, environment), contextlib.redirect_stdout(out), contextlib.redirect_stderr(error):
                    code = main(arguments)
            finally:
                os.umask(previous_umask)
            return code, json.loads(out.getvalue()) if out.getvalue() else None, error.getvalue()

        code, review, error = command(["feed-review", self.tracker.id])
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(review["feeds"][0]["candidate"], candidate)
        code, result, error = command(["feed-approve", self.tracker.id, "--candidate", candidate["candidate_sha256"],
                                       "--base", candidate["base_sha256"]])
        self.assertEqual((code, error), (0, ""))
        self.assertTrue(result["ok"])
        self.assertFalse(result["runtime_acknowledged"])
        rollback = self.row()["rollback"]
        code, result, error = command(["feed-rollback", self.tracker.id, "--current", rollback["current_sha256"],
                                       "--previous", rollback["previous_sha256"]])
        self.assertEqual((code, error), (0, ""))
        self.assertTrue(result["refresh_held_until_approval"])
        self.assertFalse(self.refresh(POISONED)["ok"])
        candidate = self.row()["candidate"]
        code, result, error = command(["feed-discard", self.tracker.id, "--candidate", candidate["candidate_sha256"]])
        self.assertEqual((code, error), (0, ""))
        self.assertTrue(result["active_unchanged"])
        code, _, error = command(["feed-approve", self.tracker.id, "--candidate", "wrong", "--base", "none"])
        self.assertEqual(code, 1)
        self.assertIn("exact candidate and base digests", error)


if __name__ == "__main__":
    unittest.main()
