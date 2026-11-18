"""Exercise the installer's actual Python body in a temporary home with no pip execution."""
import ast
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.name == "posix", "macOS installer uses POSIX file semantics")
class InstallerRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.project = self.root / "source"
        self.project.mkdir()
        (self.project / "pyproject.toml").write_text("# synthetic install target\n")
        (self.project / "requirements").mkdir()
        module = self.project / "src/egress_guard/lockfile.py"
        module.parent.mkdir(parents=True)
        module.write_bytes((Path(__file__).resolve().parents[1] / "src/egress_guard/lockfile.py").read_bytes())
        for name in ("runtime.lock", "build.lock"):
            (self.project / "requirements" / name).write_text("demo==1.2.3 \\\n    --hash=sha256:" + "a" * 64 + "\n")
        self.install_root = self.home / "Library/Application Support/Egress Guard"
        self.environment = self.install_root / "venv"
        script = Path(__file__).resolve().parents[1] / "scripts/install-macos.sh"
        body = script.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        tree = ast.parse(body, filename=str(script))
        # Keep imports and the actual install function, excluding the CLI exit wrapper.
        module = ast.Module(body=[item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom, ast.FunctionDef))], type_ignores=[])
        namespace = {}
        exec(compile(module, str(script), "exec"), namespace)
        self.install = namespace["install"]
        for item in (patch.object(Path, "home", return_value=self.home),
                     patch.object(sys, "argv", [str(script), str(self.project)])):
            item.start()
            self.addCleanup(item.stop)
        create = patch("venv.create", side_effect=self.create_environment)
        self.create = create.start()
        self.addCleanup(create.stop)
        pip = patch("subprocess.run", side_effect=self.install_package)
        self.pip = pip.start()
        self.addCleanup(pip.stop)
        self.failure = None
        self.failure_stage = "project"
        self.snapshots = {}
        self.bad_entrypoint = False
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def create_environment(self, environment, **options):
        self.assertEqual(options, {"with_pip": True, "symlinks": False})
        (environment / "bin").mkdir()
        (environment / "bin/python").write_text("synthetic interpreter; never executed")

    def install_package(self, arguments, **options):
        self.assertEqual(arguments[:6], [str(self.environment / "bin/python"), "-I", "-m", "pip", "--isolated",
                                        "--disable-pip-version-check"])
        self.assertTrue(options["check"])
        self.assertEqual(options["env"]["PIP_CONFIG_FILE"], os.devnull)
        self.assertEqual(arguments[6], "--no-cache-dir")
        if arguments[7] == "check":
            if self.failure and self.failure_stage == "check":
                raise self.failure
            return subprocess.CompletedProcess(arguments, 0)
        if "-r" in arguments:
            self.assertIn("--require-hashes", arguments)
            self.assertIn("--only-binary=:all:", arguments)
            self.assertEqual(arguments[arguments.index("--index-url") + 1], "https://pypi.org/simple")
            stage = Path(arguments[-1]).name
            snapshot = Path(arguments[-1])
            self.assertNotEqual(snapshot.parent, self.project / "requirements")
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
            self.snapshots[stage] = snapshot.read_bytes()
        else:
            self.assertIn("--no-deps", arguments)
            self.assertIn("--no-build-isolation", arguments)
            self.assertIn("--no-index", arguments)
            stage = "project"
        if self.failure and stage == self.failure_stage:
            raise self.failure
        if stage != "project":
            return subprocess.CompletedProcess(arguments, 0)
        cli = self.environment / "bin/egress-guard"
        if self.bad_entrypoint:
            cli.symlink_to(self.root / "outside-file")
        else:
            cli.write_text("synthetic command; never executed")
            cli.chmod(0o700)
        return subprocess.CompletedProcess(arguments, 0)

    def private_state(self):
        self.install_root.mkdir(parents=True, mode=0o700)
        state = self.install_root / "data"
        state.mkdir(mode=0o700)
        sentinel = state / "preserve-state"
        sentinel.write_bytes(b"synthetic retained state")
        return sentinel

    def test_install_uses_an_isolated_interpreter_fixed_index_and_private_root(self):
        self.install()
        self.assertEqual(self.install_root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.environment.stat().st_mode & 0o777, 0o700)
        self.create.assert_called_once()
        self.assertEqual(self.pip.call_count, 4)
        self.assertTrue((self.environment / "bin/egress-guard").is_file())

    def test_dependency_hash_failure_prevents_project_install_and_preserves_state(self):
        sentinel = self.private_state()
        self.failure_stage = "runtime.lock"
        self.failure = subprocess.CalledProcessError(1, ["synthetic-hash-mismatch"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertEqual(self.pip.call_count, 1)
        self.assertFalse(self.environment.exists())
        self.assertEqual(sentinel.read_bytes(), b"synthetic retained state")

    def test_linked_or_oversized_lock_is_refused_before_environment_creation(self):
        lock = self.project / "requirements/runtime.lock"
        outside = self.root / "outside-lock"
        outside.write_text("keep")
        lock.unlink()
        lock.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "dependency lock"):
            self.install()
        self.create.assert_not_called()
        self.pip.assert_not_called()
        self.assertEqual(outside.read_text(), "keep")
        lock.unlink()
        lock.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(RuntimeError, "dependency lock"):
            self.install()
        self.create.assert_not_called()

    def test_wheel_installs_runtime_lock_without_source_build_dependencies(self):
        wheel = self.root / "egress_guard-0.1.1-py3-none-any.whl"
        wheel.write_bytes(b"synthetic wheel; pip is mocked")
        with patch.object(sys, "argv", ["installer", str(self.project), str(wheel)]):
            self.install()
        self.assertEqual(self.pip.call_count, 3)
        self.assertTrue(self.pip.call_args_list[0].args[0][-1].endswith("runtime.lock"))
        self.assertEqual(self.pip.call_args_list[1].args[0][-1], str(wheel.resolve()))

    def test_dependency_inconsistency_refuses_to_keep_a_broken_installation(self):
        sentinel = self.private_state()
        self.failure_stage = "check"
        self.failure = subprocess.CalledProcessError(1, ["synthetic-inconsistent-dependency"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertFalse(self.environment.exists())
        self.assertEqual(sentinel.read_bytes(), b"synthetic retained state")

    def test_pip_directive_is_rejected_before_creating_an_environment(self):
        (self.project / "requirements/runtime.lock").write_text("--extra-index-url https://example.invalid\n")
        with self.assertRaisesRegex(RuntimeError, "dependency lock"):
            self.install()
        self.create.assert_not_called()
        self.pip.assert_not_called()

    def test_encoding_declaration_is_rejected_before_environment_creation(self):
        lock = self.project / "requirements/runtime.lock"
        lock.write_bytes(b"# coding: unicode_escape\n" + lock.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "dependency lock"):
            self.install()
        self.create.assert_not_called()
        self.pip.assert_not_called()

    def test_pip_consumes_the_validated_snapshot_despite_later_source_changes(self):
        original = (self.project / "requirements/runtime.lock").read_bytes()
        def changed(environment, **options):
            self.create_environment(environment, **options)
            (self.project / "requirements/runtime.lock").write_text("--extra-index-url https://example.invalid\n")
        self.create.side_effect = changed
        self.install()
        self.assertEqual(self.snapshots["runtime.lock"], original)
        self.assertFalse(list(self.install_root.glob(".install-locks-*")))

    def test_source_directory_with_wheel_suffix_still_uses_the_build_lock(self):
        changed = self.project.with_suffix(".whl")
        self.project.rename(changed)
        self.project = changed
        with patch.object(sys, "argv", ["installer", str(self.project)]):
            self.install()
        self.assertEqual(set(self.snapshots), {"runtime.lock", "build.lock"})

    def test_existing_installation_is_preserved_without_attempting_an_upgrade(self):
        sentinel = self.private_state()
        self.environment.mkdir(mode=0o700)
        previous = self.environment / "previous-command"
        previous.write_bytes(b"existing installation")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.install()
        self.create.assert_not_called()
        self.pip.assert_not_called()
        self.assertEqual(previous.read_bytes(), b"existing installation")
        self.assertEqual(sentinel.read_bytes(), b"synthetic retained state")

    def test_failed_package_install_removes_only_new_environment_and_retains_state(self):
        sentinel = self.private_state()
        self.failure = subprocess.CalledProcessError(1, ["synthetic-pip"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertFalse(self.environment.exists())
        self.assertEqual(sentinel.read_bytes(), b"synthetic retained state")

    def test_interrupted_install_retains_state_and_can_be_retried(self):
        sentinel = self.private_state()
        self.failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.install()
        self.assertFalse(self.environment.exists())
        self.assertEqual(sentinel.read_bytes(), b"synthetic retained state")
        self.failure = None
        self.install()
        self.assertTrue((self.environment / "bin/egress-guard").is_file())

    def test_linked_install_root_is_rejected_before_environment_creation(self):
        parent = self.install_root.parent
        parent.mkdir(parents=True)
        outside = self.root / "outside-directory"
        outside.mkdir()
        sentinel = outside / "preserve"
        sentinel.write_text("keep")
        self.install_root.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "Unsafe install directory"):
            self.install()
        self.create.assert_not_called()
        self.pip.assert_not_called()
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertTrue(self.install_root.is_symlink())

    def test_linked_entrypoint_is_rejected_and_external_target_is_preserved(self):
        outside = self.root / "outside-file"
        outside.write_text("preserve unrelated file")
        self.bad_entrypoint = True
        with self.assertRaisesRegex(RuntimeError, "did not install"):
            self.install()
        self.assertFalse(self.environment.exists())
        self.assertEqual(outside.read_text(), "preserve unrelated file")


if __name__ == "__main__":
    unittest.main()
