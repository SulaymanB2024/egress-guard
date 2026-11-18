import ctypes
import json
import socket
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from egress_guard import dnssd


def wire_name(*labels):
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\0"


def emit(callback, flags, interface, error, owner="", rrtype=5, data=b"", ttl=60):
    owner_buffer = (ctypes.c_ubyte * (len(owner) + 1)).from_buffer_copy(owner.encode() + b"\0")
    rdata = ctypes.create_string_buffer(data)
    callback(None, flags, interface, error, owner_buffer, rrtype, 1, len(data),
             ctypes.cast(rdata, ctypes.c_void_p), ttl, None)


class FakeDNSService:
    def __init__(self, scripts, no_descriptor=()):
        self.scripts = scripts
        self.no_descriptor = no_descriptor
        self.queries = []
        self.refs = {}
        self.freed = []

    def DNSServiceQueryRecord(self, ref, flags, interface, name, rrtype, rrclass, callback, _):
        self.queries.append((name, flags, interface, rrtype, rrclass))
        script = self.scripts[rrtype]
        if isinstance(script, int):
            return script
        reader, writer = socket.socketpair()
        self.refs[rrtype] = reader, writer, callback, script
        ref._obj.value = rrtype
        if script:
            writer.sendall(b"x" * len(script))
        return 0

    def DNSServiceRefSockFD(self, ref):
        return -1 if ref.value in self.no_descriptor else self.refs[ref.value][0].fileno()

    def DNSServiceProcessResult(self, ref):
        reader, _, callback, script = self.refs[ref.value]
        reader.recv(1)
        entry = script.pop(0)
        if isinstance(entry, int):
            return entry
        emit(callback, *entry)
        return 0

    def DNSServiceRefDeallocate(self, ref):
        self.freed.append(ref.value)
        reader, writer, _, _ = self.refs.pop(ref.value)
        reader.close()
        writer.close()


class DNSServiceTests(unittest.TestCase):
    def test_wire_decoder_rejects_compression_and_malformed_labels(self):
        self.assertEqual(dnssd._decode_target(wire_name(b"A", b"Example")), "a.example")
        for data in (b"\xc0\x1a", b"\x05ab\0", b"\0x", b"\x01a", wire_name(b"dot.label", b"example"),
                     wire_name(b"\xff", b"example")):
            with self.subTest(data=data):
                self.assertIsNone(dnssd._decode_target(data))

    def test_real_ctypes_callback_collects_reachable_shape_without_copying_addresses(self):
        lib = FakeDNSService({
            1: [(3, 7, 0, "x.example.", 5, wire_name(b"alias", b"example")),
                (2, 7, 0, "alias.example.", 1, bytes([192, 0, 2, 1]))],
            28: [(3, 7, 0, "x.example.", 5, wire_name(b"alias", b"example")),
                 (2, 7, 0, "alias.example.", 28, bytes(range(16)))],
        })
        with patch("egress_guard.dnssd._dns_sd", return_value=lib):
            observations = dnssd._resolve_native("x.example", 0.5)
        self.assertEqual(sorted(lib.freed), [1, 28])
        self.assertEqual(lib.queries, [(b"x.example.", 0x1000, 0, 1, 1), (b"x.example.", 0x1000, 0, 28, 1)])
        self.assertEqual([row["status"] for row in observations], ["answered", "answered"])
        self.assertEqual(observations[0]["aliases"], [
            {"owner": "x.example", "target": "alias.example", "ttl": 60, "interface_index": 7},
        ])
        self.assertEqual(observations[0]["terminal_names"], ["alias.example"])
        self.assertNotIn("192.0.2.1", json.dumps(observations))

    def test_deallocates_refs_on_timeout_socket_and_processing_error(self):
        for scripts, socket_errors, expected, freed in (
            ({1: [], 28: -1}, (), ["timeout", "error"], [1]),
            ({1: [], 28: [-1]}, (1,), ["error", "error"], [1, 28]),
            ({1: [(0, 0, -65554)], 28: []}, (), ["negative", "timeout"], [1, 28]),
        ):
            lib = FakeDNSService(scripts, no_descriptor=socket_errors)
            with self.subTest(expected=expected), patch("egress_guard.dnssd._dns_sd", return_value=lib):
                rows = dnssd._resolve_native("x.example", 0.03)
                self.assertEqual([row["status"] for row in rows], expected)
                self.assertEqual(lib.freed, freed)
                self.assertFalse(lib.refs)

    def test_mixed_interfaces_invalid_and_excessive_callback_data(self):
        encoded_alias = wire_name(b"alias", b"example")
        scenarios = (
            ([(3, 7, 0, "x.example.", 5, encoded_alias),
              (2, 8, 0, "alias.example.", 1, bytes(4))], "mixed-interface"),
            ([(2, 0, 0, "x.example.", 5, b"x" * 256)], "invalid-record"),
            ([(2, 0, 0, "x.example.", 5, b"\xc0\x0c")], "invalid-cname"),
            ([(3, 0, 0, "x.example.", 5, encoded_alias)] * (dnssd.MAX_RECORDS + 1), "record-limit"),
        )
        for script, error in scenarios:
            with self.subTest(error=error):
                lib = FakeDNSService({1: script, 28: -1})
                with patch("egress_guard.dnssd._dns_sd", return_value=lib):
                    observations = dnssd._resolve_native("x.example", 0.5)
                self.assertEqual(observations[0]["error"], error)
                self.assertEqual(lib.freed, [1])

    def test_supervises_native_timeout_and_reports_unsupported(self):
        with patch.object(dnssd.sys, "platform", "darwin"), patch.object(
                dnssd.subprocess, "run", side_effect=subprocess.TimeoutExpired("worker", 0.2)) as start:
            observations = dnssd.resolve_cnames("x.example", timeout=0.2)
            self.assertEqual([row["status"] for row in observations], ["timeout", "timeout"])
            self.assertEqual(start.call_args.kwargs["timeout"], 0.2)
            command = start.call_args.args[0]
            self.assertEqual(command[1:5], ["-I", "-S", "-B", "-c"])
            self.assertEqual(command[-1], str(Path(dnssd.__file__).resolve().parents[1]))
            self.assertNotIn("x.example", command)
        with patch.object(dnssd.sys, "platform", "linux"), patch.object(dnssd.subprocess, "run") as start:
            self.assertEqual(dnssd.resolve_cnames("x.example")[0]["status"], "unsupported")
            start.assert_not_called()
