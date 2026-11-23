"""Real-TLS framing, partial-write and concurrent functional-control regressions."""
from __future__ import annotations

import io
import os
import socket
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from privacy_accounting import CHANNELS, ConsumedReader, framed_snapshot
from privacy_clients import ack, frame, http_request, response, tunnel, websocket
from privacy_lab import HOSTS, Lab, synthetic_id


class CounterContractTests(unittest.TestCase):
    def test_parent_rejects_failure_pipe_signal_and_closed_diagnostics(self):
        for closed in (False, True):
            reader, writer = os.pipe()
            os.set_blocking(reader, False)
            fixture = object.__new__(Lab)
            fixture.meter_read_fd, fixture.meter_failed = reader, False
            try:
                if closed:
                    os.close(writer)
                    writer = None
                else:
                    os.write(writer, b"!")
                for _ in range(2):
                    with self.assertRaisesRegex(RuntimeError, "metering failed"):
                        fixture.snapshot()
            finally:
                os.close(reader)
                if writer is not None:
                    os.close(writer)

    def test_meter_write_failure_never_suppresses_admitted_commands_and_is_sticky(self):
        from mitmproxy.proxy import commands
        from privacy_proxy_meter import install
        server = SimpleNamespace(id="fixture-tunnel", sockname=("127.0.0.1", 12345))
        context = SimpleNamespace(server=server, client=SimpleNamespace(id="client"))
        emitted = commands.SendData(server, b"opaque TLS bytes")
        class Original:
            def __init__(self):
                self.context = context
            def handle_event(self, _event):
                yield emitted
        module = SimpleNamespace(PolicyRelay=Original)
        failures = []
        with patch("privacy_proxy_meter.atomic_private", side_effect=[None, OSError("synthetic full disk")]) as writer:
            install(module, Path("unused-test-path"), {server.id: HOSTS[0]}, on_failure=lambda: failures.append(True))
            relay = module.PolicyRelay()
            self.assertEqual(list(relay.handle_event(None)), [emitted])
            self.assertEqual(list(relay.handle_event(None)), [emitted])
            self.assertEqual(writer.call_count, 2)
        self.assertEqual(failures, [True])

    def test_consumer_offsets_do_not_follow_underlying_buffer_prefetch(self):
        reader = ConsumedReader(io.BufferedReader(io.BytesIO(b"one\r\nsecond\r\n")))
        self.assertEqual(reader.readline(), b"one\r\n")
        self.assertEqual(reader.position, 5)
        self.assertEqual(reader.read(3), b"sec")
        self.assertEqual(reader.position, 8)

    def test_negative_missing_and_overattributed_evidence_refuse(self):
        valid = {name: 0 for name in CHANNELS}
        for count, fields in ((-1, valid), (0, {}), (0, {**valid, "first_party_functional": 1}),
                              (1, {**valid, "first_party_functional": True})):
            with self.subTest(count=count, fields=fields), self.assertRaises(ValueError):
                framed_snapshot([{"application_bytes": count, "attributed_bytes": fields}])


class StreamAccountingTests(unittest.TestCase):
    def setUp(self):
        self.lab = Lab().__enter__()
        self.addCleanup(self.lab.close)

    def wait_bytes(self, expected):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            result = self.lab.snapshot()
            if result["decrypted_origin_application_bytes"] >= expected:
                return result
            time.sleep(0.01)
        self.fail("Controlled origin did not receive expected raw application bytes")

    def test_reused_and_pipelined_tls_isolate_functional_and_body_bytes(self):
        host, visit = HOSTS[0], "1" * 24
        requests = [http_request(self.lab, host, f"/product?visit={visit}&case=cart"),
                    http_request(self.lab, host, f"/collect/body?visit={visit}&case=opaque", body=synthetic_id(0).encode())]
        for pipelined in (False, True):
            with tunnel(self.lab, host) as stream, stream.makefile("rb") as reader:
                if pipelined:
                    stream.sendall(b"".join(requests))
                    response(reader)
                    response(reader)
                else:
                    for request in requests:
                        stream.sendall(request)
                        response(reader)
        snap = self.lab.snapshot()
        framing = snap["origin_framing"]
        self.assertEqual(framing["raw_application_bytes"], 2 * sum(map(len, requests)))
        self.assertEqual(framing["channel_bytes"]["first_party_functional"], 2 * len(requests[0]))
        self.assertEqual(framing["channel_bytes"]["first_party_body_collector"], 2 * len(requests[1]))
        self.assertEqual(framing["unparsed_or_truncated_bytes"], 0)
        self.assertTrue(framing["conserved"])
        self.assertEqual(len(snap["connections"]), 2)
        for connection in snap["connections"]:
            self.assertEqual(connection["application_bytes"], sum(map(len, requests)))
            events = [row for row in snap["events"] if row["peer_port"] == connection["peer_port"]]
            self.assertEqual([row["request_or_frame_bytes"] for row in events], list(map(len, requests)))
            self.assertEqual(events[0]["identifiers"], [])
            self.assertEqual(events[1]["identifier_sources"], {"url": [], "headers": [], "body": [synthetic_id(0)]})
            wire = [row for row in snap["proxy_emissions"]["tunnels"] if row["peer_port"] == connection["peer_port"]]
            self.assertEqual(len(wire), 1)
            self.assertEqual(wire[0]["host"], host)
            self.assertGreater(wire[0]["to_origin_bytes"], connection["application_bytes"])
            self.assertGreater(wire[0]["to_client_bytes"], 0)
        self.assertFalse(snap["overflow"])
        self.assertEqual(snap["handler_errors"], 0)

    def test_partial_headers_and_bodies_stay_visible_without_complete_events(self):
        host = HOSTS[0]
        partials = [b"POST /never-completed", http_request(self.lab, host,
                    "/collect/body?case=opaque&visit=" + "2" * 24, body=synthetic_id(0).encode())[:-10]]
        total = 0
        for data in partials:
            with tunnel(self.lab, host) as stream:
                stream.sendall(data)
                stream.shutdown(socket.SHUT_WR)
                total += len(data)
                self.wait_bytes(total)
        snap = self.lab.snapshot()
        self.assertEqual(snap["events"], [])
        self.assertEqual(snap["origin_framing"]["completed_frame_bytes"], 0)
        self.assertEqual(snap["origin_framing"]["unparsed_or_truncated_bytes"], total)

    def test_host_sni_mismatch_and_ambiguous_lengths_never_receive_channel_credit(self):
        invalid = [http_request(self.lab, HOSTS[1], "/product?case=cart&visit=" + "6" * 24),
                   http_request(self.lab, HOSTS[0], "/product?case=cart&visit=" + "6" * 24,
                                headers=(("Content-Length", "0"), ("Content-Length", "1")))]
        total = 0
        for request in invalid:
            with tunnel(self.lab, HOSTS[0]) as stream:
                stream.sendall(request)
                self.assertTrue(stream.recv(4096).startswith(b"HTTP/1.1 4"))
                total += len(request)
                self.wait_bytes(total)
        snap = self.lab.snapshot()
        self.assertEqual(snap["events"], [])
        self.assertEqual(snap["origin_framing"]["completed_frame_bytes"], 0)
        self.assertEqual(snap["origin_framing"]["unparsed_or_truncated_bytes"], total)

    def test_partial_websocket_frame_remains_unparsed_and_127_byte_payload_works(self):
        stream, handshake = websocket(self.lab, HOSTS[0], "3" * 24)
        with stream:
            complete = frame(b"x" * 127)
            stream.sendall(complete)
            ack(stream)
            partial = frame(synthetic_id(0).encode())[:-5]
            stream.sendall(partial)
            stream.shutdown(socket.SHUT_WR)
            self.wait_bytes(handshake + len(complete) + len(partial))
        snap = self.lab.snapshot()
        self.assertEqual(len(snap["events"]), 1)
        self.assertEqual(snap["events"][0]["body_bytes"], 127)
        self.assertEqual(snap["events"][0]["identifiers"], [])
        self.assertEqual(snap["origin_framing"]["completed_frame_bytes"], handshake + len(complete))
        self.assertEqual(snap["origin_framing"]["unparsed_or_truncated_bytes"], len(partial))

    def test_revoked_socket_stops_both_emission_and_delivery_while_control_survives(self):
        collector, _ = websocket(self.lab, HOSTS[4], "4" * 24)
        functional, _ = websocket(self.lab, HOSTS[0], "5" * 24, case="cart")
        with collector, functional:
            collector.sendall(frame(synthetic_id(0).encode()))
            ack(collector)
            functional.sendall(frame(b"cart:before"))
            ack(functional)
            before = self.lab.snapshot()
            collector_before = next(row for row in before["connections"] if row["host"] == HOSTS[4])
            emitted_before = next(row for row in before["proxy_emissions"]["tunnels"] if row["host"] == HOSTS[4])
            self.lab.configure(denied=HOSTS[4])
            # This is next-forward revocation, not a claim of proactive idle expiry.
            try:
                collector.sendall(frame(synthetic_id(1).encode()))
                self.assertEqual(collector.recv(32), b"")
            except OSError:
                pass
            for number in range(8):
                functional.sendall(frame(f"cart:after:{number}".encode()))
                ack(functional)
            deadline = time.monotonic() + 2
            while "4" * 24 not in self.lab.snapshot()["closed_sockets"] and time.monotonic() < deadline:
                time.sleep(0.01)
            after = self.lab.snapshot()
        collector_after = next(row for row in after["connections"] if row["host"] == HOSTS[4])
        emitted_after = next(row for row in after["proxy_emissions"]["tunnels"] if row["host"] == HOSTS[4])
        self.assertEqual(collector_after["application_bytes"], collector_before["application_bytes"])
        self.assertEqual(emitted_after["to_origin_bytes"], emitted_before["to_origin_bytes"])
        self.assertIn("4" * 24, after["closed_sockets"])
        self.assertEqual(len([row for row in after["events"] if row["case"] == "cart"]), 9)
        self.assertEqual(len([row for row in after["events"] if row["case"] == "socket"]), 1)
        self.assertEqual(after["origin_framing"]["unparsed_or_truncated_bytes"], 0)
        self.assertEqual(after["handler_errors"], 0)
        self.assertFalse(after["overflow"])

    def test_idle_revocation_closes_without_a_write_while_functional_socket_lives(self):
        collector, _ = websocket(self.lab, HOSTS[4], "7" * 24)
        functional, _ = websocket(self.lab, HOSTS[0], "8" * 24, case="cart")
        with collector, functional:
            collector.sendall(frame(synthetic_id(0).encode()))
            ack(collector)
            functional.sendall(frame(b"functional:before"))
            ack(functional)
            before = self.lab.snapshot()
            old_origin = next(row for row in before["connections"] if row["host"] == HOSTS[4])
            old_wire = next(row for row in before["proxy_emissions"]["tunnels"] if row["host"] == HOSTS[4])
            self.lab.configure(denied=HOSTS[4])
            # No write on collector after denial: only independent functional
            # traffic runs while the owned periodic timer must close the idle peer.
            for number in range(8):
                functional.sendall(frame(f"functional:after:{number}".encode()))
                ack(functional)
                time.sleep(0.15)
            collector.settimeout(3)
            self.assertEqual(collector.recv(32), b"")
            deadline = time.monotonic() + 2
            while "7" * 24 not in self.lab.snapshot()["closed_sockets"] and time.monotonic() < deadline:
                time.sleep(0.01)
            after = self.lab.snapshot()
            self.assertIn("7" * 24, after["closed_sockets"])
            new_origin = next(row for row in after["connections"] if row["host"] == HOSTS[4])
            new_wire = next(row for row in after["proxy_emissions"]["tunnels"] if row["host"] == HOSTS[4])
            self.assertEqual(new_origin["application_bytes"], old_origin["application_bytes"])
            self.assertEqual(new_wire["to_origin_bytes"], old_wire["to_origin_bytes"])
            self.assertEqual(len([row for row in after["events"] if row["case"] == "cart"]), 9)
            self.assertEqual(len([row for row in after["events"] if row["case"] == "socket"]), 1)
            self.assertEqual(after["handler_errors"], 0)
            self.assertFalse(after["overflow"])


if __name__ == "__main__":
    unittest.main()
