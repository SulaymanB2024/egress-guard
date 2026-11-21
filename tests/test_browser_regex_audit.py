"""The optional RE2 auditor's input, reporting and option contract need no RE2 install."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/audit-browser-regex.py"
SPEC = importlib.util.spec_from_file_location("egress_browser_regex_audit", SCRIPT)
audit_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_tool)

# An injected test dependency checks only the call contract and safe error reporting.
# Real RE2 compilation is an explicit developer gate against built artifacts.
STUB = '''
class error(Exception): pass
class Options:
    class Encoding:
        LATIN1 = "fixture-latin1"
def compile(pattern, options):
    assert isinstance(pattern, bytes)
    assert options.encoding == Options.Encoding.LATIN1
    assert options.max_mem == 2048 and options.log_errors is False
    assert options.case_sensitive is (b"CASE" in pattern)
    assert options.never_capture is (b"CAPTURE" not in pattern)
    if b"LARGE" in pattern: raise error("pattern too large: https://private.example/secret")
    if b"FAIL" in pattern: raise error("bad syntax: https://private.example/secret")
    return object()
'''


class BrowserRegexAuditTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root = self.base / "chrome"
        (self.root / "rules").mkdir(parents=True)
        self.modules = self.base / "modules"
        self.modules.mkdir()
        (self.modules / "re2.py").write_text(STUB)
        self.manifest = {"manifest_version": 3, "declarative_net_request": {"rule_resources": [
            {"id": "fixture", "path": "rules/fixture.json", "enabled": True},
        ]}}
        self.write_manifest()
        self.rule_path = self.root / "rules/fixture.json"
        self.rule_path.write_text(json.dumps([self.rule(1, "DEFAULT")]))

    def write_manifest(self):
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))

    @staticmethod
    def rule(rule_id, pattern, **condition):
        return {"id": rule_id, "action": {"type": "block"},
                "condition": {"regexFilter": pattern, **condition}}

    def run_cli(self, root=None):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), str(root or self.root)],
                                env={**os.environ, "PYTHONPATH": str(self.modules)}, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.stderr, "", "artifact contents must never escape through tracebacks or RE2 logging")
        return result.returncode, json.loads(result.stdout)

    def test_audits_disabled_rulesets_and_applies_capture_case_and_memory_options(self):
        capture = self.rule(3, "CAPTURE")
        capture["action"] = {"type": "redirect", "redirect": {"regexSubstitution": "\\1"}}
        self.rule_path.write_text(json.dumps([self.rule(1, "DEFAULT"), self.rule(2, "CASE", isUrlFilterCaseSensitive=True)]))
        self.manifest["declarative_net_request"]["rule_resources"].append({
            "id": "disabled", "path": "rules/disabled.json", "enabled": False,
        })
        self.write_manifest()
        (self.root / "rules/disabled.json").write_text(json.dumps([capture]))
        code, result = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual((result["rulesets"], result["rulesets_read"], result["regexes"], result["passed"]), (2, 2, 3, 3))
        self.assertTrue(result["complete"])
        self.assertFalse(result["native_chrome"])

    def test_failure_output_is_bounded_and_never_echoes_regexes_or_engine_snippets(self):
        total = audit_tool.MAX_ERRORS + 4
        rows = [self.rule(n, "FAIL-https://artifact.example/private") for n in range(1, total)]
        rows.append(self.rule(total, "LARGE"))
        self.rule_path.write_text(json.dumps(rows))
        code, result = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual((result["regexes"], result["failed"], result["error_count"]), (total, total, total))
        self.assertEqual(len(result["errors"]), audit_tool.MAX_ERRORS)
        self.assertEqual(result["errors_omitted"], 4)
        self.assertEqual(result["error_counts_by_ruleset"], {"fixture": total})
        self.assertTrue(result["complete"])
        self.assertNotIn("https://", json.dumps(result))
        self.assertEqual(result["errors"][0], {"ruleset": "fixture", "id": 1,
                         "bytes": len(rows[0]["condition"]["regexFilter"].encode()), "error": "re2-rejected"})

    def test_missing_dependency_has_a_json_error_and_nonzero_exit(self):
        (self.modules / "re2.py").write_text('raise ImportError("fixture dependency unavailable")\n')
        code, result = self.run_cli()
        self.assertEqual(code, 2)
        self.assertFalse(result["complete"])
        self.assertEqual(result["errors"][0]["error"], "optional-google-re2-unavailable")

    def test_rejects_path_escape_and_duplicate_or_empty_manifest_declarations(self):
        for invalid in ("../outside.json", "/outside.json", "rules/../fixture.json", "rules//fixture.json", "rules\\fixture.json"):
            with self.subTest(path=invalid):
                self.manifest["declarative_net_request"]["rule_resources"][0]["path"] = invalid
                self.write_manifest()
                code, result = self.run_cli()
                self.assertEqual(code, 2)
                self.assertEqual(result["rulesets_read"], 0)
        (self.root / "manifest.json").write_text('{"manifest_version":3,"manifest_version":3}')
        self.assertEqual(self.run_cli()[1]["errors"][0]["error"], "duplicate-json-key")
        self.manifest["declarative_net_request"]["rule_resources"] = []
        self.write_manifest()
        self.assertEqual(self.run_cli()[0], 2)

    def test_rejects_symlinked_root_directories_and_files_and_hard_links(self):
        linked_root = self.base / "linked-root"
        linked_root.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.run_cli(linked_root)[0], 2)
        for relative in ("manifest.json", "rules/fixture.json", "rules"):
            with self.subTest(relative=relative):
                original = self.root / relative
                outside = self.base / "moved"
                original.rename(outside)
                original.symlink_to(outside, target_is_directory=outside.is_dir())
                self.assertEqual(self.run_cli()[0], 2)
                original.unlink()
                outside.rename(original)
        outside = self.base / "outside.json"
        self.rule_path.rename(outside)
        os.link(outside, self.rule_path)
        code, result = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(result["errors"][0]["error"], "not-an-independent-regular-file")

    def test_rejects_fifo_oversized_files_and_excessive_json_depth_without_waiting(self):
        self.rule_path.unlink()
        os.mkfifo(self.rule_path)
        self.assertEqual(self.run_cli()[0], 2)
        self.rule_path.unlink()
        with self.rule_path.open("wb") as handle:
            handle.seek(audit_tool.MAX_RULESET_BYTES)
            handle.write(b" ")
        self.assertEqual(self.run_cli()[1]["errors"][0]["error"], "artifact-byte-limit")
        self.rule_path.write_text("[" * (audit_tool.MAX_DEPTH + 1) + "0" + "]" * (audit_tool.MAX_DEPTH + 1))
        self.assertEqual(self.run_cli()[1]["errors"][0]["error"], "json-depth-limit")

    def test_total_byte_budget_covers_the_manifest_and_every_ruleset(self):
        manifest_bytes = (self.root / "manifest.json").stat().st_size
        with patch.object(audit_tool, "MAX_TOTAL_BYTES", manifest_bytes + self.rule_path.stat().st_size - 1):
            with audit_tool.BuildReader(self.root) as reader:
                reader.read_json("manifest.json", audit_tool.MAX_MANIFEST_BYTES)
                with self.assertRaisesRegex(audit_tool.AuditError, "artifact-byte-limit"):
                    reader.read_json("rules/fixture.json", audit_tool.MAX_RULESET_BYTES)


if __name__ == "__main__":
    unittest.main()
