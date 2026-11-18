"""Configuration errors cannot hang reads or replace linked user entries."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from egress_guard.config import initialize, load_config


class ConfigurationRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.path = self.state / "config.toml"
        environment = patch.dict(os.environ, {"EGRESS_GUARD_DATA": str(self.state), "EGRESS_GUARD_CONFIG": str(self.path)})
        environment.start()
        self.addCleanup(environment.stop)

    def test_nonstring_filter_tiers_are_clean_configuration_errors(self):
        for value in ("[]", "{}", "1", "true"):
            with self.subTest(value=value):
                self.path.write_text("[block]\nlist_tier=" + value + "\n")
                with self.assertRaises(ValueError):
                    load_config()

    def test_configuration_directory_is_rejected_as_a_nonregular_file(self):
        self.path.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            load_config()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_fifo_is_rejected_before_any_blocking_stream_read(self):
        os.mkfifo(self.path, 0o600)
        read_text = Path.read_text
        open_file = Path.open
        def guarded_read(path, *args, **kwargs):
            if path == self.path:
                raise AssertionError("A special config file must not enter a blocking read")
            return read_text(path, *args, **kwargs)
        def guarded_open(path, *args, **kwargs):
            if path == self.path:
                raise AssertionError("A special config file must not enter a blocking open")
            return open_file(path, *args, **kwargs)
        with patch.object(Path, "read_text", guarded_read), patch.object(Path, "open", guarded_open):
            with self.assertRaisesRegex(ValueError, "regular file"):
                load_config()

    @unittest.skipIf(os.name == "nt", "requires POSIX link creation without additional privileges")
    def test_dangling_link_is_rejected_without_falling_back_to_defaults(self):
        self.path.symlink_to(self.state / "missing-target")
        with self.assertRaisesRegex(ValueError, "regular file"):
            load_config()
        self.assertTrue(self.path.is_symlink())

    @unittest.skipIf(os.name == "nt", "requires POSIX link creation without additional privileges")
    def test_initialization_preserves_a_dangling_config_link(self):
        target = self.state / "missing-target"
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "regular file"):
            initialize()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(self.path.readlink(), target)
        self.assertFalse(target.exists())

    def test_stale_size_metadata_cannot_bypass_the_read_limit(self):
        self.path.write_text("# small\n")
        before = self.path.stat()
        self.path.write_bytes(b"#" + b"x" * 65537 + b"\n")
        original = Path.stat
        original_lstat = Path.lstat
        def stale_metadata(path, *args, **kwargs):
            return before if path == self.path else original(path, *args, **kwargs)
        def stale_link_metadata(path, *args, **kwargs):
            return before if path == self.path else original_lstat(path, *args, **kwargs)
        with patch.object(Path, "stat", stale_metadata), patch.object(Path, "lstat", stale_link_metadata):
            with self.assertRaisesRegex(ValueError, "64 KiB"):
                load_config()

    def test_deep_toml_is_a_clean_configuration_error(self):
        self.path.write_text('[block]\nlist_tier=' + '{a=' * 1200 + '"pro"' + '}' * 1200 + '\n')
        with self.assertRaises(ValueError):
            load_config()

    def test_missing_configuration_still_uses_defaults_and_initializes_privately(self):
        self.assertEqual(load_config()["proxy"]["port"], 18080)
        self.assertFalse(self.path.exists())
        initialize()
        if os.name != "nt":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_config()["proxy"]["port"], 18080)


if __name__ == "__main__":
    unittest.main()
