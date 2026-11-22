"""Established-stream revocation through the pinned real proxy and local TLS origins."""

import http.client
import json
import socket
from socketserver import StreamRequestHandler
import ssl
import threading
import time
import unittest

import test_addon as fixtures
from egress_guard.feeds import MALWARE, THREAT_TIERS, _snapshot
from egress_guard.health import proxy_health


class MarkerHandler(StreamRequestHandler):
    """A bounded synthetic protocol inside original-certificate TLS or raw TCP."""
    def handle(self):
        self.connection.settimeout(5)
        try:
            while line := self.rfile.readline(8193):
                if len(line) > 8192 or not line.endswith(b"\n"):
                    return
                marker = line[:-1]
                self.server.markers.append(marker)
                if marker == b"wait-for-server-push":
                    self.server.push_waiting.set()
                    if not self.server.push_release.wait(5):
                        return
                    self.wfile.write(b"post-revocation-server-marker\n")
                    self.server.push_sent.set()
                else:
                    self.wfile.write(b"ack:" + line)
                self.wfile.flush()
        except OSError:
            pass


@unittest.skipUnless(fixtures.MITMDUMP, "mitmdump required for the real proxy test")
class TunnelRevocationIntegrationTests(unittest.TestCase):
    serve = fixtures.ProxyIntegrationTests.serve
    start_proxy = fixtures.ProxyIntegrationTests.start_proxy
    stop = staticmethod(fixtures.ProxyIntegrationTests.stop)
    http = fixtures.ProxyIntegrationTests.http

    def setUp(self):
        fixtures.ProxyIntegrationTests.setUp(self)
        for origin in (self.plain_origin, self.tls_origin):
            origin.RequestHandlerClass = MarkerHandler
            origin.markers = []
            origin.push_waiting = threading.Event()
            origin.push_release = threading.Event()
            origin.push_sent = threading.Event()
        script = self.state / "fixture.py"
        script.write_text(script.read_text().replace('"front.test"',
            '"front.test", "pause-only.tracker.test", "accounts.google.com"'))

    def report(self):
        report = proxy_health(self.proxy_port, self.state).get("policy")
        self.assertIsNotNone(report)
        return report

    def wait_revision(self, old):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            report = self.report()
            if report.get("revision") not in (None, old) and report.get("pending") is False:
                return report
            time.sleep(0.05)
        self.fail("changed policy was not acknowledged")

    def change(self, name, body):
        old = self.report()["revision"]
        path = self.state / name
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body)
        return self.wait_revision(old)

    def open_stream(self, host="front.test", *, sni="passthrough.test", port=443, tls=True):
        tunnel = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        tunnel.set_tunnel(host, port)
        self.addCleanup(tunnel.close)
        tunnel.connect()
        stream = tunnel.sock
        if tls:
            stream = self.tls_client.wrap_socket(stream, server_hostname=sni)
            self.assertEqual(stream.getpeercert(binary_form=True), self.expected_cert)
        self.addCleanup(stream.close)
        return stream

    @staticmethod
    def receive(stream):
        data = bytearray()
        while len(data) <= 8192 and not data.endswith(b"\n"):
            chunk = stream.recv(8193 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def exchange(self, stream, marker, *, origin=None):
        origin = origin or self.tls_origin
        stream.sendall(marker + b"\n")
        self.assertEqual(self.receive(stream), b"ack:" + marker + b"\n")
        self.assertIn(marker, origin.markers)

    def observe_after_change(self, stream, marker, *, origin=None):
        """Return measurements also used by the external immutable-baseline comparison."""
        origin = origin or self.tls_origin
        response = b""
        closed = False
        try:
            stream.sendall(marker + b"\n")
            response = self.receive(stream)
            closed = response == b""
        except TimeoutError:
            raise  # An idle hang is not evidence that a stream was revoked.
        except OSError:
            closed = True
        return {"origin_received_marker": marker in origin.markers,
                "response_bytes": len(response), "closed": closed}

    def assert_revoked(self, stream, marker, *, origin=None):
        self.assertEqual(self.observe_after_change(stream, marker, origin=origin), {
            "origin_received_marker": False, "response_bytes": 0, "closed": True,
        })

    @staticmethod
    def wait_until(expiry):
        while (remaining := expiry - time.time()) > 0:
            time.sleep(min(remaining, 0.05))

    def test_established_tls_authority_deny_stops_the_next_origin_marker(self):
        self.start_proxy()
        stream = self.open_stream()
        self.exchange(stream, b"authority-before")
        self.change("block.txt", "front.test\n")
        self.assert_revoked(stream, b"authority-after")

    def test_established_tls_visible_name_deny_is_independent_of_authority(self):
        self.start_proxy()
        stream = self.open_stream()
        self.exchange(stream, b"visible-name-before")
        self.change("block.txt", "passthrough.test\n")
        self.assert_revoked(stream, b"visible-name-after")

    def test_new_threat_data_revokes_an_existing_hostname_allow_and_pause(self):
        (self.state / "allow.txt").write_text("front.test\n")
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": time.time() + 600}))
        self.start_proxy()
        stream = self.open_stream()
        self.exchange(stream, b"threat-before")
        feed = THREAT_TIERS["full"]
        self.change(str(feed.path(self.state).relative_to(self.state)), _snapshot({"front.test"}, time.time()))
        self.assert_revoked(stream, b"threat-after")

    def test_pause_and_exact_grant_expire_without_a_new_policy_revision(self):
        self.start_proxy()
        old = self.report()["revision"]
        pause_until = time.time() + 2.5
        grant_until = pause_until + 1.5
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": pause_until}))
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"tracker.test": grant_until}))
        applied = self.wait_revision(old)
        granted = self.open_stream("tracker.test")
        paused = self.open_stream("pause-only.tracker.test")
        self.exchange(granted, b"grant-before")
        self.exchange(paused, b"pause-before")
        self.wait_until(pause_until)
        self.assert_revoked(paused, b"pause-after")
        self.exchange(granted, b"grant-still-active")
        self.wait_until(grant_until)
        self.assert_revoked(granted, b"grant-after")
        self.assertEqual(self.report()["revision"], applied["revision"])

    def test_hardened_transition_revokes_disallowed_port_and_raw_protocol_only(self):
        self.start_proxy(plaintext_credentials=False)
        wrong_port = self.open_stream(port=8443)
        raw = self.open_stream("plaintext.test", tls=False)
        allowed = self.open_stream()
        self.exchange(wrong_port, b"port-before")
        self.exchange(raw, b"raw-before", origin=self.plain_origin)
        self.exchange(allowed, b"tls-before")
        config = self.state / "config.toml"
        self.change("config.toml", config.read_text().replace('profile = "compatible"', 'profile = "hardened"'))
        self.assert_revoked(wrong_port, b"port-after")
        self.assert_revoked(raw, b"raw-after", origin=self.plain_origin)
        self.exchange(allowed, b"tls-still-allowed")

    def test_selected_guard_rechecks_the_actual_peer_even_for_a_safety_hostname(self):
        self.start_proxy(address_guard=True)
        stream = self.open_stream("accounts.google.com")
        self.exchange(stream, b"numeric-peer-before")
        self.change(str(MALWARE.path(self.state).relative_to(self.state)), _snapshot({"127.0.0.1"}, time.time()))
        self.assert_revoked(stream, b"numeric-peer-after")
        self.assertEqual(self.report()["transport"]["address_guard"]["state"], "active")

    def test_revocation_also_refuses_a_server_originated_chunk(self):
        self.start_proxy()
        stream = self.open_stream()
        self.exchange(stream, b"server-push-before")
        stream.sendall(b"wait-for-server-push\n")
        self.assertTrue(self.tls_origin.push_waiting.wait(2))
        self.change("block.txt", "front.test\n")
        self.tls_origin.push_release.set()
        self.assertTrue(self.tls_origin.push_sent.wait(2))
        try:
            response = self.receive(stream)
        except TimeoutError:
            raise
        except OSError:
            response = b""
        self.assertEqual(response, b"")

    def test_continuously_allowed_tls_stream_survives_unrelated_policy_changes(self):
        self.start_proxy()
        stream = self.open_stream()
        for index in range(12):
            self.exchange(stream, f"allowed-before-{index}".encode())
        self.change("block.txt", "unrelated.test\n")
        for index in range(12):
            self.exchange(stream, f"allowed-after-{index}".encode())
        self.assertEqual(len(self.tls_origin.markers), 24)
        self.assertEqual(self.tls_origin.accepts, 1)
        self.assertNotIn("Traceback", (self.state / "proxy.log").read_text())


if __name__ == "__main__":
    unittest.main()
