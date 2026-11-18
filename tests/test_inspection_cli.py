import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from egress_guard import cli, dnssd
from egress_guard.config import default_config


class InspectionCLITests(unittest.TestCase):
    def test_offline_answers_never_query_dns_or_initialize_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "answers.json"
            fixture.write_text(json.dumps([{"query_type": name, "status": "answered", "aliases": [],
                                            "terminal_names": ["x.example"]} for name in ("A", "AAAA")]))
            output = io.StringIO()
            with patch.object(cli, "load_config", return_value=default_config()), patch.object(
                    cli, "data_dir", return_value=root / "absent-state"), patch.object(
                    dnssd, "resolve_cnames", side_effect=AssertionError("Offline must not query")), patch.object(
                    cli, "initialize", side_effect=AssertionError("Read-only must not initialize")), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["cname-check", "x.example", "--answers-file", str(fixture)]), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["observation_source"], "offline-file")
            self.assertTrue(result["live_policy_unchanged"])
            self.assertFalse(result["policy_ready"])
            self.assertFalse((root / "absent-state").exists())

    def test_offline_file_limits_reject_links_pipes_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "answers.json"
            for raw in (b" " * 65537, b'{"a":1,"a":2}', b"[NaN]", b"\xff", b"[" * 2000 + b"]" * 2000):
                fixture.write_bytes(raw)
                with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                    cli._answers_file(str(fixture))
            link = root / "link"
            link.symlink_to(fixture)
            with self.assertRaises(ValueError):
                cli._answers_file(str(link))
            if hasattr(os, "mkfifo"):
                pipe = root / "pipe"
                os.mkfifo(pipe)
                with self.assertRaises(ValueError):
                    cli._answers_file(str(pipe))

    def test_invalid_host_does_not_query_or_read_a_fixture(self):
        with patch.object(dnssd, "resolve_cnames") as resolve, patch.object(cli, "_answers_file") as read, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["cname-check", "https://x.example", "--answers-file", "unused"]), 1)
        resolve.assert_not_called()
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
