#!/usr/bin/env python3
"""Compare established-tunnel revocation with a trusted, immutable local baseline.

Requires this repository's test fixtures, CPython 3.12+, Git, and the already
installed mitmproxy==12.3.1 dependency. No installation, download, browser launch,
system proxy change or trust-store change is performed. All network traffic uses
loopback fixtures; all application state is temporary. This executes the selected
trusted source revision, not untrusted code in a sandbox.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import http.client
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shlex
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
BASELINE = "abe2b87b2bb8de298992045c8bb05d4f63554adc"
ENGINE = "12.3.1"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_FILES = 256
MAX_REPORT_BYTES = 16 * 1024
CASES = (
    "manual_authority_deny",
    "grant_expiry_without_revision_change",
    "numeric_peer_deny_under_safety_hostname",
)


class ComparisonError(ValueError):
    """Bounded, fixed diagnostic codes only."""


def bounded_read(path, limit=MAX_FILE_BYTES):
    if path.is_symlink() or not path.is_file():
        raise ComparisonError("source-is-not-a-regular-file")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ComparisonError("source-byte-limit")
    return data


def source_digest(source):
    entries = []
    total = 0
    for path in sorted((source / "egress_guard").rglob("*")):
        if "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            raise ComparisonError("source-symlink")
        if path.is_dir():
            continue
        data = bounded_read(path)
        total += len(data)
        entries.append(f"{path.relative_to(source).as_posix()}\n{hashlib.sha256(data).hexdigest()}\n")
        if len(entries) > MAX_SOURCE_FILES or total > MAX_SOURCE_BYTES:
            raise ComparisonError("source-size-limit")
    if not entries:
        raise ComparisonError("source-missing")
    return hashlib.sha256("".join(entries).encode()).hexdigest()


def package_version(source):
    for node in ast.parse(bounded_read(source / "egress_guard/__init__.py")).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
                return value
    raise ComparisonError("source-version-unavailable")


def export_baseline(commit, destination):
    """Export only bounded regular source files; never checkout or fetch a ref."""
    check = subprocess.run(
        ["git", "cat-file", "-t", commit], cwd=REPOSITORY,
        capture_output=True, check=True, timeout=10,
    )
    if check.stdout != b"commit\n":
        raise ComparisonError("baseline-is-not-a-commit")
    with tempfile.TemporaryFile() as archive:
        subprocess.run(
            ["git", "archive", "--format=tar", commit, "src"], cwd=REPOSITORY,
            stdout=archive, stderr=subprocess.DEVNULL, check=True, timeout=10,
        )
        if archive.tell() > MAX_SOURCE_BYTES + 1024 * 1024:
            raise ComparisonError("baseline-archive-limit")
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:") as bundle:
            members = []
            total = 0
            for member in bundle:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or not path.parts or path.parts[0] != "src"
                        or ".." in path.parts or "\\" in member.name
                        or not (member.isfile() or member.isdir())):
                    raise ComparisonError("unsafe-baseline-entry")
                total += member.size
                members.append(member)
                if (member.size > MAX_FILE_BYTES or total > MAX_SOURCE_BYTES
                        or len(members) > MAX_SOURCE_FILES):
                    raise ComparisonError("baseline-source-limit")
            bundle.extractall(destination, members=members, filter="data")
    return destination / "src"


class CountingMarkerHandler(socketserver.BaseRequestHandler):
    """Count every decrypted application byte, including incomplete marker lines."""
    def handle(self):
        record = {"bytes": 0, "closed": threading.Event()}
        self.request.settimeout(5)
        pending = bytearray()
        try:
            while chunk := self.request.recv(8193):
                record["bytes"] += len(chunk)
                pending.extend(chunk)
                if len(pending) > 8192:
                    return
                while b"\n" in pending:
                    marker, _, remainder = pending.partition(b"\n")
                    pending[:] = remainder
                    marker = bytes(marker)
                    self.server.markers.append(marker)
                    self.server.marker_records[marker] = record
                    self.request.sendall(b"ack:" + marker + b"\n")
        except OSError:
            pass
        finally:
            record["closed"].set()


def observe(case, stream, marker, previous):
    record = case.tls_origin.marker_records[previous]
    before = record["bytes"]
    try:
        result = case.observe_after_change(stream, marker)
    finally:
        stream.close()
    if not record["closed"].wait(5):
        raise ComparisonError("origin-connection-did-not-close")
    result["post_change_origin_application_bytes"] = record["bytes"] - before
    return result


def guard_receipt(case):
    # The production 0.10 health reader correctly rejects a 0.9 transport
    # capability receipt. Authenticate the raw policy report here solely to
    # confirm that the experimental address guard is active in both test arms.
    from egress_guard.health import _verified_policy
    from egress_guard.http_deadline import request_json_object

    nonce = secrets.token_urlsafe(32)
    connection = http.client.HTTPConnection("127.0.0.1", case.proxy_port, timeout=2)
    try:
        status, data = request_json_object(
            connection, "GET", "http://egress-guard.invalid/health?nonce=" + nonce, seconds=2,
        )
        reported = _verified_policy(data, nonce, case.proxy_port, case.state, create_identity=False)
    finally:
        connection.close()
    transport = reported.get("transport") if isinstance(reported, dict) else None
    guard = transport.get("address_guard") if isinstance(transport, dict) else None
    if (status != 200 or not isinstance(guard, dict) or guard.get("selected") is not True
            or guard.get("state") != "active"):
        raise ComparisonError("numeric-address-guard-not-active")


def measure(source, launcher, fixtures, case_type, malware, snapshot):
    version = package_version(source)
    digest = source_digest(source)
    addon_hash = hashlib.sha256(bounded_read(source / "egress_guard/addon.py")).hexdigest()
    case = case_type()
    with (patch.object(fixtures, "SOURCE", source),
          patch.object(fixtures, "__version__", version),
          patch.object(fixtures, "MITMDUMP", launcher)):
        try:
            case.setUp()
            case.tls_origin.RequestHandlerClass = CountingMarkerHandler
            case.tls_origin.marker_records = {}
            case.start_proxy(address_guard=True)
            guard_receipt(case)
            revoked = case.open_stream()
            control = case.open_stream("passthrough.test")
            case.exchange(revoked, b"manual-before")
            for index in range(12):
                case.exchange(control, f"allowed-before-{index}".encode())
            case.change("block.txt", "front.test\n")
            manual = observe(case, revoked, b"manual-after", b"manual-before")
            for index in range(6):
                case.exchange(control, f"allowed-mid-{index}".encode())

            expiry = time.time() + 2.5
            applied = case.change("tracker-exceptions.json", json.dumps({"tracker.test": expiry}))
            granted = case.open_stream("tracker.test")
            case.exchange(granted, b"grant-before")
            case.wait_until(expiry)
            expired = observe(case, granted, b"grant-after", b"grant-before")
            if case.report()["revision"] != applied["revision"]:
                raise ComparisonError("grant-case-policy-revision-changed")
            for index in range(6):
                case.exchange(control, f"allowed-after-{index}".encode())

            numeric = case.open_stream("accounts.google.com")
            case.exchange(numeric, b"peer-before")
            case.change(str(malware.path(case.state).relative_to(case.state)),
                        snapshot({"127.0.0.1"}, time.time()))
            peer = observe(case, numeric, b"peer-after", b"peer-before")
            if b"Traceback" in bounded_read(case.state / "proxy.log"):
                raise ComparisonError("proxy-reported-an-exception")
            observed = {
                "package_version": version, "source_tree_sha256": digest,
                "addon_sha256": addon_hash, "original_certificate_verified": True,
                "manual_authority_deny": manual, "grant_expiry_without_revision_change": expired,
                "numeric_peer_deny_under_safety_hostname": peer,
                "negative_control": {"same_connection": True, "allowed_markers_received": 24},
            }
        finally:
            if not case.doCleanups():
                raise ComparisonError("fixture-cleanup-failed")
    if source_digest(source) != digest:
        raise ComparisonError("source-changed-during-measurement")
    return observed


def compare(commit):
    if (sys.version_info < (3, 12) or platform.python_implementation() != "CPython"
            or sys.platform not in ("linux", "darwin")):
        raise ComparisonError("requires-cpython-312-or-newer-on-linux-or-macos")
    if importlib.metadata.version("mitmproxy") != ENGINE:
        raise ComparisonError("requires-installed-mitmproxy-12.3.1")
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(REPOSITORY / "src"), str(REPOSITORY / "tests")]
    import test_addon as fixtures
    from test_tunnel_revocation import TunnelRevocationIntegrationTests
    from egress_guard.feeds import MALWARE, _snapshot

    helper_paths = [REPOSITORY / "tests" / name for name in
                    ("test_addon.py", "test_tunnel.py", "test_tunnel_revocation.py")]
    helpers = {path.name: hashlib.sha256(bounded_read(path)).hexdigest() for path in helper_paths}
    with tempfile.TemporaryDirectory(prefix="egress-guard-comparison-") as directory:
        temporary = Path(directory)
        baseline_source = export_baseline(commit, temporary)
        # Invoke the already-qualified interpreter, without relying on a different
        # mitmdump from PATH or a stale virtual-environment console-script shebang.
        launcher = temporary / "mitmdump"
        launcher.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable)
                            + " -B -c 'from mitmproxy.tools.main import mitmdump; mitmdump()' \"$@\"\n")
        launcher.chmod(0o700)
        baseline = measure(baseline_source, launcher, fixtures,
                           TunnelRevocationIntegrationTests, MALWARE, _snapshot)
        candidate = measure(REPOSITORY / "src", launcher, fixtures,
                            TunnelRevocationIntegrationTests, MALWARE, _snapshot)
    if helpers != {path.name: hashlib.sha256(bounded_read(path)).hexdigest() for path in helper_paths}:
        raise ComparisonError("fixture-source-changed-during-comparison")
    for name, expected in zip(CASES, (13, 12, 11)):
        if (baseline[name] != {"origin_received_marker": True, "response_bytes": expected + 4,
                              "closed": False, "post_change_origin_application_bytes": expected}):
            raise ComparisonError("baseline-does-not-reproduce-the-documented-boundary")
        if candidate[name] != {"origin_received_marker": False, "response_bytes": 0,
                               "closed": True, "post_change_origin_application_bytes": 0}:
            raise ComparisonError("candidate-did-not-revoke-before-the-next-origin-bytes")
    return {
        "schema": 1, "status": "passed", "baseline_commit": commit,
        "python": platform.python_version(), "mitmproxy": ENGINE,
        "transport": "original-certificate TLS, loopback only",
        "protocol": "bounded newline-delimited synthetic markers; identical policy edits in both arms",
        "measurement": "all decrypted origin recv bytes after each change, through connection closure",
        "fixture_sha256": helpers, "baseline": baseline, "candidate": candidate,
        "scope": "Three targeted established-tunnel cases, not a web-wide privacy percentage or browser measurement.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=BASELINE,
                        help="trusted local full 40-character commit ID; default is the immutable 0.9 release")
    parser.add_argument("--output", type=Path,
                        help="optional new JSON file; parent must exist and existing files are never overwritten")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.baseline):
        parser.error("--baseline must be a full lowercase 40-character commit ID")
    output = None
    try:
        if args.output:
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            output = os.fdopen(descriptor, "w", encoding="utf-8")
        try:
            report = compare(args.baseline)
        except ComparisonError as error:
            report = {"schema": 1, "status": "failed", "reason": str(error)}
        except importlib.metadata.PackageNotFoundError:
            report = {"schema": 1, "status": "unavailable", "reason": "requires-installed-mitmproxy-12.3.1"}
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            report = {"schema": 1, "status": "failed", "reason": "local-git-export-failed"}
        except Exception as error:
            report = {"schema": 1, "status": "failed", "reason": "fixture-or-source-failure",
                      "error_type": type(error).__name__[:80]}
        body = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if len(body.encode()) > MAX_REPORT_BYTES:
            raise ComparisonError("report-byte-limit")
        if output:
            output.write(body)
            output.flush()
        print(body, end="")
        return 0 if report["status"] == "passed" else 1
    except (OSError, ComparisonError):
        print(json.dumps({"schema": 1, "status": "failed", "reason": "report-output-unavailable"}))
        return 1
    finally:
        if output:
            output.close()


if __name__ == "__main__":
    raise SystemExit(main())
