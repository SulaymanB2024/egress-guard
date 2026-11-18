"""Observe CNAMEs through the macOS system resolver on explicit request."""

from __future__ import annotations

import ctypes
import json
import math
import selectors
import subprocess
import sys
import time
from pathlib import Path

from egress_guard.cname import MAX_RECORDS, QUERY_TYPES, normalize_cname_host
from egress_guard.feeds import dns_name

_MORE_COMING = 0x1
_ADD = 0x2
_RETURN_INTERMEDIATES = 0x1000
_NO_SUCH_NAME = -65538
_NO_SUCH_RECORD = -65554
_TIMED_OUT = -65568
_IN = 1
_CNAME = 5
_RECORD_TYPES = {"A": (1, 4), "AAAA": (28, 16)}
_MAX_WIRE_NAME = 255
_MAX_TIMEOUT = 3.0
_WORKER_SCRIPT = """\
import sys
sys.path.insert(0, sys.argv[1])
from egress_guard.dnssd import _worker
_worker()
"""
_CALLBACK = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16,
    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
)


def _dns_sd() -> ctypes.CDLL:
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.DNSServiceQueryRecord.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.c_uint16, ctypes.c_uint16, _CALLBACK, ctypes.c_void_p,
    ]
    lib.DNSServiceQueryRecord.restype = ctypes.c_int32
    lib.DNSServiceRefSockFD.argtypes = [ctypes.c_void_p]
    lib.DNSServiceRefSockFD.restype = ctypes.c_int
    lib.DNSServiceProcessResult.argtypes = [ctypes.c_void_p]
    lib.DNSServiceProcessResult.restype = ctypes.c_int32
    lib.DNSServiceRefDeallocate.argtypes = [ctypes.c_void_p]
    lib.DNSServiceRefDeallocate.restype = None
    return lib


def _decode_target(data: bytes) -> str | None:
    """Decode standalone CNAME RDATA, where compression pointers have no context."""
    labels = []
    offset = 0
    while offset < len(data):
        size = data[offset]
        offset += 1
        if size == 0:
            if offset != len(data) or any(b"." in label for label in labels):
                return None
            try:
                return dns_name(b".".join(labels).decode("ascii"), dotted=True)
            except UnicodeError:
                return None
        if size > 63 or offset + size > len(data):
            return None
        labels.append(data[offset:offset + size])
        offset += size
    return None


def _decode_owner(owner) -> str | None:
    if not owner:
        return None
    value = bytearray()
    for index in range(_MAX_WIRE_NAME):
        octet = owner[index]
        if octet == 0:
            return dns_name(value.decode("ascii"), dotted=True)
        if octet >= 128:
            return None
        value.append(octet)
    return None


def _observation(query_type: str, status: str, error: str | None = None) -> dict:
    row = {"query_type": query_type, "status": status, "aliases": [], "terminal_names": []}
    if error is not None:
        row["error"] = error
    return row


class _Query:
    def __init__(self, query_type: str) -> None:
        self.row = _observation(query_type, "timeout")
        self.rrtype, self.address_size = _RECORD_TYPES[query_type]
        self.ref = ctypes.c_void_p()
        self.fd = None
        self.records = 0
        self.done = False
        self.callback = _CALLBACK(self._record)

    def finish(self, status: str, error: str | None = None) -> None:
        self.row["status"] = status
        if error is not None:
            self.row["error"] = error
        self.done = True

    def _record(self, _ref, flags, interface, error, owner, rrtype, rrclass, length, data, ttl, _context) -> None:
        if self.done:
            return
        # The API leaves all other callback fields undefined on error.
        if error in {_NO_SUCH_NAME, _NO_SUCH_RECORD} and not self.row["terminal_names"]:
            self.finish("negative")
            return
        if error:
            self.finish("timeout" if error == _TIMED_OUT else "error", "dns-sd-result")
            return
        self.records += 1
        if self.records > MAX_RECORDS:
            self.finish("error", "record-limit")
            return
        name = _decode_owner(owner)
        if name is None or rrclass != _IN or not flags & _ADD:
            self.finish("error", "invalid-record")
            return
        if self.row.get("interface_index", interface) != interface:
            self.finish("error", "mixed-interface")
            return
        self.row["interface_index"] = interface
        if rrtype == _CNAME and data and 0 < length <= _MAX_WIRE_NAME:
            target = _decode_target(ctypes.string_at(data, length))
            if target is None:
                self.finish("error", "invalid-cname")
                return
            self.row["aliases"].append({"owner": name, "target": target, "ttl": ttl, "interface_index": interface})
        elif rrtype == self.rrtype and length == self.address_size and data:
            if name not in self.row["terminal_names"]:
                self.row["terminal_names"].append(name)
        else:
            self.finish("error", "invalid-record")
            return
        if self.row["terminal_names"] and not flags & _MORE_COMING:
            self.finish("answered")


def _resolve_native(host: str, timeout: float) -> list[dict]:
    try:
        lib = _dns_sd()
    except (OSError, AttributeError):
        return [_observation(name, "unsupported", "dns-sd-unavailable") for name in QUERY_TYPES]

    fullname = (host + ".").encode("ascii")
    deadline = time.monotonic() + timeout
    queries = [_Query(name) for name in QUERY_TYPES]
    with selectors.DefaultSelector() as selector:
        try:
            for query in queries:
                if time.monotonic() >= deadline:
                    break
                error = lib.DNSServiceQueryRecord(ctypes.byref(query.ref), _RETURN_INTERMEDIATES, 0,
                                                 fullname, query.rrtype, _IN, query.callback, None)
                if error:
                    # No reference is initialized when the API call fails.
                    query.ref = ctypes.c_void_p()
                    query.finish("error", "dns-sd-start")
                    continue
                query.fd = lib.DNSServiceRefSockFD(query.ref)
                if query.fd < 0:
                    query.finish("error", "dns-sd-socket")
                    continue
                selector.register(query.fd, selectors.EVENT_READ, query)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                for key, _ in selector.select(remaining):
                    query = key.data
                    if lib.DNSServiceProcessResult(query.ref):
                        query.finish("error", "dns-sd-process")
                    if query.done:
                        selector.unregister(key.fd)
        except (OSError, ValueError, KeyError):
            for query in queries:
                if not query.done:
                    query.finish("error", "dns-sd-io")
        finally:
            for query in queries:
                if query.ref.value is not None:
                    lib.DNSServiceRefDeallocate(query.ref)
    return [query.row for query in queries]


def resolve_cnames(host: str, timeout: float = _MAX_TIMEOUT) -> list[dict]:
    """Return two bounded observations via the configured macOS resolver."""
    host = normalize_cname_host(host)
    if host is None:
        raise ValueError("CNAME inspection requires a valid, fully qualified DNS hostname")
    if type(timeout) not in (int, float) or not 0 < timeout <= _MAX_TIMEOUT:
        raise ValueError("DNS inspection timeout must be greater than zero and at most three seconds")
    if sys.platform != "darwin":
        return [_observation(name, "unsupported", "macos-only") for name in QUERY_TYPES]
    try:
        # Bound native IPC and load this package independently of the caller's import path.
        package_root = str(Path(__file__).resolve().parents[1])
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", _WORKER_SCRIPT, package_root],
                                input=f"{host}\n{timeout}\n".encode("ascii"), capture_output=True,
                                check=True, timeout=timeout)
        rows = json.loads(result.stdout)
        if isinstance(rows, list):
            return rows
        raise ValueError("invalid worker reply")
    except subprocess.TimeoutExpired:
        return [_observation(name, "timeout", "worker-timeout") for name in QUERY_TYPES]
    except (OSError, ValueError, subprocess.CalledProcessError):
        return [_observation(name, "error", "worker-unavailable") for name in QUERY_TYPES]


def _worker() -> None:
    if sys.platform != "darwin":
        raise SystemExit(1)
    host, time_budget = sys.stdin.buffer.read(320).decode("ascii").splitlines()
    timeout = float(time_budget)
    if normalize_cname_host(host) != host or not math.isfinite(timeout) or not 0 < timeout <= _MAX_TIMEOUT:
        raise SystemExit(1)
    # Leave part of the caller's deadline for process startup and serialization.
    print(json.dumps(_resolve_native(host, timeout * 0.85)))
