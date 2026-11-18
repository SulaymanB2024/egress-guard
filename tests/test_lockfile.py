from pathlib import Path
import tempfile
import unittest

from egress_guard.lockfile import parse_lock, read_lock


def locked(requirement):
    return (requirement + " \\\n    --hash=sha256:" + "a" * 64 + "\n").encode()


class LockfileTests(unittest.TestCase):
    def test_release_locks_parse_without_reinterpreting_their_bytes(self):
        for name in ("runtime.lock", "build.lock"):
            path = Path(__file__).resolve().parents[1] / "requirements" / name
            data, pins = read_lock(path)
            self.assertEqual(data, path.read_bytes())
            self.assertTrue(pins)

    def test_exported_marker_forms_are_supported_without_execution(self):
        for marker in ("sys_platform == 'darwin'", "python_full_version < '3.14' and os_name != 'nt'",
                       "(os_name == 'nt' or sys_platform == 'darwin')", "implementation_name != 'PyPy'"):
            self.assertEqual(parse_lock(locked("demo==1.2.3 ; " + marker)), [("demo", "1.2.3")])

    def test_directives_urls_unpinned_requirements_and_marker_payloads_are_rejected(self):
        for entry in ("--extra-index-url https://example.invalid", "-r /tmp/other-lock", "--find-links .",
                      "demo @ https://example.invalid/demo.whl", "demo>=1", "demo==${VERSION}",
                      "demo==1 ; os_name == '${OS_NAME}'", "demo==1 ; __import__('os').system('false')",
                      "demo==1 ; os_name == 'nt' --trusted-host example.invalid", "demo==1 ; os_name == other"):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                parse_lock(locked(entry))

    def test_missing_hashes_and_directive_continuations_are_rejected(self):
        for data in (b"demo==1\n", b"demo==1 \\\n", locked("demo==1").replace(b"sha256:", b"sha512:"),
                     locked("demo==1").replace(b"\n    --hash", b"\n--index-url https://example.invalid\n    --hash")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_lock(data)

    def test_encoding_comments_and_non_ascii_cannot_change_pip_interpretation(self):
        valid = locked("demo==1")
        self.assertEqual(parse_lock(valid.replace(b"\n", b"\r\n")), [("demo", "1")])
        for data in (b"# coding: unicode_escape\n" + valid, valid + b"# comment\n",
                     valid + b"\xff", valid + b"\r", valid.replace(b"    ", b"\t")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_lock(data)

    def test_linked_lock_is_rejected_and_the_target_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(locked("demo==1"))
            link = root / "lock"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                read_lock(link)
            self.assertEqual(target.read_bytes(), locked("demo==1"))


if __name__ == "__main__":
    unittest.main()
