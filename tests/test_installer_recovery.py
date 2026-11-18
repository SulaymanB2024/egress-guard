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
        self.bad_entrypoint = False
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def create_environment(self, environment, **options):
        self.assertEqual(options, {"with_pip": True, "symlinks": False})
        (environment / "bin").mkdir()
        (environment / "bin/python").write_text("synthetic interpreter; never executed")

    def install_package(self, arguments, **options):
        self.assertEqual(arguments[:10], [str(self.environment / "bin/python"), "-I", "-m", "pip", "--isolated",
                                         "--disable-pip-version-check", "install", "--index-url", "https://pypi.org/simple", str(self.project)])
        self.assertTrue(options["check"])
        self.assertEqual(options["env"]["PIP_CONFIG_FILE"], os.devnull)
        if self.failure:
            raise self.failure
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
        self.pip.assert_called_once()
        self.assertTrue((self.environment / "bin/egress-guard").is_file())

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
