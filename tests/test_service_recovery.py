"""Launchd recovery uses a temporary home and a fully mocked native boundary."""
import contextlib
import io
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from egress_guard import services


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires POSIX service-file and locking semantics")
class ServiceRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.directory = self.home / "Library/LaunchAgents"
        self.directory.mkdir(parents=True)
        self.state = self.home / "state"
        self.state.mkdir(mode=0o700)
        self.configuration = self.state / "config.toml"
        self.jobs = [("org.egressguard.test." + name, action) for name, action in
                     (("proxy", "run"), ("dashboard", "dashboard"), ("feeds", "refresh"))]
        for item in (patch.object(services, "_macos"), patch.object(services, "initialize"),
                     patch.object(services, "load_config", return_value={"proxy": {"port": 8080}}),
                     patch.object(services, "data_dir", return_value=self.state),
                     patch.object(services, "config_path", return_value=self.configuration),
                     patch.object(services, "jobs", return_value=self.jobs),
                     patch.object(services.Path, "home", return_value=self.home)):
            item.start()
            self.addCleanup(item.stop)
        policy = patch.object(services, "Policy")
        policy.start().return_value.ready.return_value = True
        self.addCleanup(policy.stop)
        native = patch.object(services.subprocess, "run", side_effect=self.native)
        self.native_call = native.start()
        self.addCleanup(native.stop)
        self.health = patch.object(services, "proxy_health", return_value={"ready": True})
        self.health_call = self.health.start()
        self.addCleanup(self.health.stop)
        for name, value in (("READY_TIMEOUT_SECONDS", 0.05), ("READY_POLL_SECONDS", 0.01)):
            item = patch.object(services, name, value)
            item.start()
            self.addCleanup(item.stop)
        self.loaded = set()
        self.fail_bootstrap = None
        self.fail_bootout = None
        self.bootstrap_loaded_before_failure = False
        self.replace_definition_on_failure = None
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def target(self, index):
        return self.directory / (self.jobs[index][0] + ".plist")

    def definition(self, index):
        label, action = self.jobs[index]
        value = {"Label": label, "ProgramArguments": [sys.executable, "-I", "-B", "-m", "egress_guard", action],
                 "EnvironmentVariables": {"EGRESS_GUARD_DATA": str(self.state), "EGRESS_GUARD_CONFIG": str(self.configuration)},
                 "ProcessType": "Background", "LowPriorityIO": True, "Umask": 0o077,
                 "StandardOutPath": "/dev/null",
                 "StandardErrorPath": str(self.state / "logs/services.err.log")}
        if action == "refresh":
            value["StartCalendarInterval"] = {"Hour": 7, "Minute": 0}
        else:
            value.update(RunAtLoad=True, KeepAlive=True, ThrottleInterval=30)
        return plistlib.dumps(value)

    def native(self, arguments, **options):
        self.assertEqual(arguments[0], "/bin/launchctl")
        operation = arguments[1]
        label = Path(arguments[-1]).stem if operation == "bootstrap" else arguments[-1].rsplit("/", 1)[-1]
        if operation == "print":
            return subprocess.CompletedProcess(arguments, 0 if label in self.loaded else 1)
        if (operation == "bootstrap" and label == self.fail_bootstrap
                or operation == "bootout" and label == self.fail_bootout):
            if operation == "bootstrap" and self.bootstrap_loaded_before_failure:
                self.loaded.add(label)
                raise subprocess.TimeoutExpired(arguments, 10)
            if self.replace_definition_on_failure is not None:
                self.replace_definition_on_failure.write_bytes(plistlib.dumps({"Label": "replacement-job"}))
            raise subprocess.CalledProcessError(5, arguments)
        if operation == "bootstrap":
            self.loaded.add(label)
        elif operation == "bootout":
            self.loaded.discard(label)
        else:
            self.fail("Unexpected native operation")
        return subprocess.CompletedProcess(arguments, 0)

    def test_later_foreign_definition_is_detected_before_any_job_or_file_changes(self):
        foreign = plistlib.dumps({"Label": "foreign-job"})
        self.target(1).write_bytes(foreign)
        with self.assertRaises(ValueError):
            services.start()
        self.native_call.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [self.target(1)])
        self.assertEqual(self.target(1).read_bytes(), foreign)

    def test_failed_bootstrap_rolls_back_only_jobs_and_definitions_it_created(self):
        self.fail_bootstrap = self.jobs[1][0]
        with self.assertRaises((RuntimeError, subprocess.SubprocessError)):
            services.start()
        self.assertEqual(self.loaded, set(), "An earlier KeepAlive job survived the failed start")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_rollback_preserves_preexisting_running_job_and_definition(self):
        before = self.definition(0)
        self.target(0).write_bytes(before)
        self.loaded.add(self.jobs[0][0])
        self.fail_bootstrap = self.jobs[2][0]
        with self.assertRaises((RuntimeError, subprocess.SubprocessError)):
            services.start()
        self.assertEqual(self.loaded, {self.jobs[0][0]})
        self.assertEqual(self.target(0).read_bytes(), before)
        self.assertEqual(list(self.directory.iterdir()), [self.target(0)])

    def test_failed_rollback_retains_definition_for_the_job_that_could_not_stop(self):
        self.fail_bootstrap = self.jobs[1][0]
        self.fail_bootout = self.jobs[0][0]
        with self.assertRaisesRegex(RuntimeError, "roll.*back|recover"):
            services.start()
        self.assertEqual(self.loaded, {self.jobs[0][0]})
        self.assertEqual(list(self.directory.iterdir()), [self.target(0)])

    def test_timed_out_bootstrap_is_reinspected_and_rolled_back_even_if_it_loaded(self):
        self.fail_bootstrap = self.jobs[1][0]
        self.bootstrap_loaded_before_failure = True
        with self.assertRaises(subprocess.TimeoutExpired):
            services.start()
        self.assertEqual(self.loaded, set())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_rollback_preserves_an_initially_unloaded_definition_it_did_not_create(self):
        before = self.definition(0)
        self.target(0).write_bytes(before)
        self.fail_bootstrap = self.jobs[1][0]
        with self.assertRaises(subprocess.CalledProcessError):
            services.start()
        self.assertEqual(self.loaded, set())
        self.assertEqual(self.target(0).read_bytes(), before)
        self.assertEqual(list(self.directory.iterdir()), [self.target(0)])

    def test_replaced_definition_is_preserved_and_not_used_to_claim_a_job(self):
        self.fail_bootstrap = self.jobs[1][0]
        self.replace_definition_on_failure = self.target(0)
        with self.assertRaisesRegex(RuntimeError, "roll.*back|recover"):
            services.start()
        self.assertEqual(self.loaded, {self.jobs[0][0]})
        self.assertEqual(plistlib.loads(self.target(0).read_bytes()), {"Label": "replacement-job"})
        self.assertEqual(list(self.directory.iterdir()), [self.target(0)])

    def test_definition_created_after_preflight_is_never_overwritten_or_deleted(self):
        publish = services._publish_definition
        foreign = plistlib.dumps({"Label": "replacement-job"})
        def concurrent_file(target, definition):
            if target == self.target(1):
                target.write_bytes(foreign)
            return publish(target, definition)

        with patch.object(services, "_publish_definition", side_effect=concurrent_file):
            with self.assertRaises(FileExistsError):
                services.start()
        self.assertEqual(self.loaded, set())
        self.assertEqual(self.target(1).read_bytes(), foreign)
        self.assertEqual(list(self.directory.iterdir()), [self.target(1)])

    def test_start_and_stop_share_one_nonblocking_lifecycle_lock(self):
        with services._service_lock():
            for operation in (services.start, services.stop):
                with self.subTest(operation=operation.__name__), self.assertRaisesRegex(ValueError, "already running"):
                    operation()
        self.native_call.assert_not_called()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_stop_preserves_jobs_when_receipt_restoration_fails(self):
        for index in range(3):
            self.target(index).write_bytes(self.definition(index))
        self.loaded = {label for label, _ in self.jobs}
        (self.state / "proxy-receipt.json").write_text("{}")
        with patch("egress_guard.macos.restore_proxy", side_effect=ValueError("Synthetic restoration declined")):
            with self.assertRaises(ValueError):
                services.stop()
        self.assertEqual(self.loaded, {label for label, _ in self.jobs})
        self.assertEqual(len(list(self.directory.iterdir())), 3)
        self.native_call.assert_not_called()

    def test_repeated_start_keeps_preexisting_jobs_and_definitions(self):
        for index in range(3):
            self.target(index).write_bytes(self.definition(index))
        self.loaded = {label for label, _ in self.jobs}
        before = {path: path.read_bytes() for path in self.directory.iterdir()}
        services.start()
        self.assertEqual(self.loaded, {label for label, _ in self.jobs})
        self.assertEqual({path: path.read_bytes() for path in self.directory.iterdir()}, before)
        self.assertTrue(all(call.args[0][1] == "print" for call in self.native_call.call_args_list))

    def test_start_with_worker_that_never_becomes_ready_fails_and_rolls_back(self):
        self.health_call.return_value = {"ready": False}
        with self.assertRaisesRegex(RuntimeError, "did not become ready"):
            services.start()
        self.assertEqual(self.loaded, set())
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertGreater(self.health_call.call_count, 1)

    def test_start_with_ready_worker_succeeds_and_keeps_jobs(self):
        self.health_call.side_effect = [{"ready": False}, {"ready": True}]
        services.start()
        self.assertEqual(self.loaded, {label for label, _ in self.jobs})
        self.assertEqual(len(list(self.directory.iterdir())), 3)
        self.assertEqual(self.health_call.call_args.args, (8080, self.state))

    def test_swapped_definition_is_preserved_by_stop(self):
        for index in range(3):
            self.target(index).write_bytes(self.definition(index))
        self.loaded = {label for label, _ in self.jobs}
        foreign = plistlib.dumps({"Label": "foreign-job"})
        original = self.native

        def swap_after_preflight(arguments, **options):
            if arguments[1] == "bootout" and arguments[-1].endswith(self.jobs[1][0]):
                self.target(1).unlink()
                self.target(1).write_bytes(foreign)
            return original(arguments, **options)

        self.native_call.side_effect = swap_after_preflight
        with self.assertRaisesRegex(ValueError, "changed during stop"):
            services.stop()
        self.assertEqual(self.target(1).read_bytes(), foreign)
        self.assertFalse(self.target(0).exists())
        self.assertFalse(self.target(2).exists())

    def test_error_log_is_private_and_bounded(self):
        log = self.state / "logs/services.err.log"
        log.parent.mkdir(mode=0o700)
        log.write_bytes(b"x" * (services.ERROR_LOG_LIMIT * 3) + b"newest")
        os.chmod(log, 0o644)
        services.start()
        self.assertLessEqual(log.stat().st_size, services.ERROR_LOG_LIMIT)
        self.assertTrue(log.read_bytes().endswith(b"newest"))
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(log.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(plistlib.loads(self.target(0).read_bytes())["StandardErrorPath"], str(log))


if __name__ == "__main__":
    unittest.main()
