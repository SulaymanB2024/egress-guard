#!/usr/bin/env python3
"""Audit built Chrome static regexes with optional google-re2==1.1.20251105.

No dependency installation, network access, or native Chrome execution is performed.
Provide the optional package in the developer interpreter or its PYTHONPATH. This
checks RE2 compilation with the selected Chrome options, not complete DNR validity.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import math
import os
import re
import stat
import sys

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RULESET_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_RULESETS = 100
MAX_RULES = 100_000
MAX_REGEX_BYTES = 32 * 1024
MAX_DEPTH = 24
MAX_ERRORS = 100
RULESET_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


class AuditError(ValueError):
    """Fixed error codes only: never include an artifact path or regex text."""


def relative_parts(value):
    if (not isinstance(value, str) or not value or len(value) > 1024
            or any(char in value for char in ("\\", "\0", ":"))):
        raise AuditError("unsafe-ruleset-path")
    parts = value.split("/")
    if any(part in ("", ".", "..") or len(part.encode("utf-8")) > 255 for part in parts):
        raise AuditError("unsafe-ruleset-path")
    return parts


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate-json-key")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise AuditError("invalid-json-number")
    return number


def bounded_int(value):
    if len(value) > 20:
        raise AuditError("invalid-json-number")
    return int(value)


def no_constant(_value):
    raise AuditError("invalid-json-number")


def decode_json(raw):
    try:
        source = raw.decode("utf-8")
        depth = 0
        quoted = escaped = False
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise AuditError("json-depth-limit")
            elif char in "]}":
                depth -= 1
        return json.loads(source, object_pairs_hook=unique_object, parse_float=finite_float,
                          parse_int=bounded_int, parse_constant=no_constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise AuditError("invalid-json") from None


class BuildReader:
    """Walk every component through directory descriptors, without following links."""
    def __init__(self, root):
        self.fd = None
        self.total = 0
        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
                or os.open not in os.supports_dir_fd):
            raise AuditError("secure-filesystem-api-unavailable")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open("/", flags)
        try:
            for part in os.path.abspath(root).split("/")[1:]:
                if part:
                    following = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = following
            self.fd = descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        os.close(self.fd)

    def read_json(self, relative, limit):
        parts = relative_parts(relative)
        directory = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = following
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise AuditError("not-an-independent-regular-file")
                allowance = min(limit, MAX_TOTAL_BYTES - self.total)
                if info.st_size > allowance:
                    raise AuditError("artifact-byte-limit")
                raw = handle.read(allowance + 1)
                if len(raw) > allowance:
                    raise AuditError("artifact-byte-limit")
                self.total += len(raw)
                return decode_json(raw)
        finally:
            os.close(directory)


def resources(manifest):
    if not isinstance(manifest, dict) or type(manifest.get("manifest_version")) is not int or manifest["manifest_version"] != 3:
        raise AuditError("invalid-chrome-manifest")
    declaration = manifest.get("declarative_net_request")
    entries = declaration.get("rule_resources") if isinstance(declaration, dict) else None
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_RULESETS:
        raise AuditError("missing-or-excessive-static-rulesets")
    used = set()
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"id", "enabled", "path"}
                or not isinstance(entry["id"], str) or RULESET_ID.fullmatch(entry["id"]) is None
                or type(entry["enabled"]) is not bool or entry["id"] in used):
            raise AuditError("invalid-static-ruleset-declaration")
        relative_parts(entry["path"])
        used.add(entry["id"])
    return entries


def audit(root):
    result = {"schema": 1, "status": "unavailable", "complete": False, "native_chrome": False,
              "scope": "all-manifest-static-regexes-including-disabled", "engine": "google-re2",
              "package_version": None, "max_mem": 2048, "encoding": "Latin1",
              "rulesets": 0, "rulesets_read": 0, "rules": 0, "regexes": 0, "passed": 0,
              "failed": 0, "error_count": 0, "errors": [], "errors_omitted": 0,
              "error_counts_by_ruleset": {}}

    def error(code, ruleset=None, rule_id=None, size=None):
        result["error_count"] += 1
        if ruleset is not None:
            counts = result["error_counts_by_ruleset"]
            counts[ruleset] = counts.get(ruleset, 0) + 1
        if len(result["errors"]) < MAX_ERRORS:
            result["errors"].append({"ruleset": ruleset, "id": rule_id, "bytes": size, "error": code})
        else:
            result["errors_omitted"] += 1

    try:
        engine = importlib.import_module("re2")
        engine.Options.Encoding.LATIN1
        if not callable(engine.compile) or not issubclass(engine.error, Exception):
            raise ImportError
    except Exception:
        error("optional-google-re2-unavailable")
        return result, 2
    try:
        version = importlib.metadata.version("google-re2")
        if re.fullmatch(r"[A-Za-z0-9.+_-]{1,64}", version):
            result["package_version"] = version
    except (importlib.metadata.PackageNotFoundError, OSError, ValueError):
        pass
    complete = True
    try:
        with BuildReader(root) as reader:
            entries = resources(reader.read_json("manifest.json", MAX_MANIFEST_BYTES))
            result["rulesets"] = len(entries)
            for entry in entries:
                try:
                    rules = reader.read_json(entry["path"], MAX_RULESET_BYTES)
                    if not isinstance(rules, list) or len(rules) + result["rules"] > MAX_RULES:
                        raise AuditError("invalid-or-excessive-rules")
                    result["rulesets_read"] += 1
                    result["rules"] += len(rules)
                    used = set()
                    for rule in rules:
                        if (not isinstance(rule, dict) or type(rule.get("id")) is not int
                                or not 1 <= rule["id"] <= 2 ** 31 - 1 or rule["id"] in used
                                or not isinstance(rule.get("condition"), dict) or not isinstance(rule.get("action"), dict)):
                            raise AuditError("invalid-rule-structure")
                        used.add(rule["id"])
                        condition = rule["condition"]
                        if "regexFilter" not in condition:
                            continue
                        result["regexes"] += 1
                        pattern = condition["regexFilter"]
                        sensitive = condition.get("isUrlFilterCaseSensitive", False)
                        if not isinstance(pattern, str) or not pattern or type(sensitive) is not bool:
                            raise AuditError("invalid-regex-condition")
                        encoded = pattern.encode("utf-8")
                        if len(encoded) > MAX_REGEX_BYTES:
                            raise AuditError("regex-source-byte-limit")
                        action = rule["action"]
                        redirect = action.get("redirect") if action.get("type") == "redirect" else None
                        capture = isinstance(redirect, dict) and "regexSubstitution" in redirect
                        if capture and not isinstance(redirect["regexSubstitution"], str):
                            raise AuditError("invalid-regex-substitution")
                        options = engine.Options()
                        options.encoding = engine.Options.Encoding.LATIN1
                        options.max_mem = 2048
                        options.case_sensitive = sensitive
                        options.never_capture = not capture
                        options.log_errors = False
                        try:
                            engine.compile(encoded, options=options)
                            result["passed"] += 1
                        except engine.error as exc:
                            result["failed"] += 1
                            code = "re2-size-limit" if "pattern too large" in str(exc).lower() else "re2-rejected"
                            error(code, entry["id"], rule["id"], len(encoded))
                except AuditError as exc:
                    complete = False
                    error(str(exc), entry["id"])
                except (OSError, UnicodeError):
                    complete = False
                    error("ruleset-unreadable", entry["id"])
    except AuditError as exc:
        complete = False
        error(str(exc))
    except (OSError, ValueError):
        complete = False
        error("build-unreadable")
    except Exception:
        complete = False
        error("re2-engine-error")
    result["complete"] = complete
    result["status"] = "unavailable" if not complete else "failed" if result["failed"] else "passed"
    return result, 2 if not complete else 1 if result["failed"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("chrome_directory", help="Built Chrome extension directory containing manifest.json")
    args = parser.parse_args(argv)
    result, code = audit(args.chrome_directory)
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
