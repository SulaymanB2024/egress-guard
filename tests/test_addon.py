"""Isolated acceptance test through the real regular-proxy engine."""

import datetime as dt
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from egress_guard import __version__
from egress_guard.config import load_config
from egress_guard.feeds import _snapshot, selected_feeds
from egress_guard.health import proxy_health
from egress_guard.policy import MAX_CONTROL_BYTES, Policy
from test_tunnel import client_hello

MITMDUMP = Path(sys.executable).with_name("mitmdump")
if not MITMDUMP.is_file():
    MITMDUMP = shutil.which("mitmdump")
SOURCE = Path(__file__).resolve().parents[1] / "src"


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = b"origin response"
        self.server.requests.append((self.path, dict(self.headers.items())))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class Origin(ThreadingHTTPServer):
    def __init__(self, tls=None, *, host="127.0.0.1", port=0):
        super().__init__((host, port), UpstreamHandler)
        self.tls = tls
        self.requests = []
        self.accepts = 0

    def get_request(self):
        connection, address = super().get_request()
        self.accepts += 1
        if self.tls is not None:
            connection.settimeout(4)
            connection = self.tls.wrap_socket(connection, server_side=True)
        return connection, address


def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "passthrough.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=2))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("passthrough.test"), x509.DNSName("tracker.test"),
        ]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "origin.pem", directory / "origin-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client, cert.public_bytes(serialization.Encoding.DER)


@unittest.skipUnless(MITMDUMP, "mitmdump required for the real proxy test")
class ProxyIntegrationTests(unittest.TestCase):
    def serve(self, tls=None, **address):
        server = Origin(tls, **address)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        return server

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = state = Path(directory.name)
        tls, self.tls_client, self.expected_cert = certificate(state)
        self.plain_origin = self.serve()
        self.tls_origin = self.serve(tls)
        (state / "blocklists").mkdir(mode=0o700)
        self.database = state / "events.sqlite3"
        for feed in selected_feeds({}):
            domain = ("blocked.test" if feed.source == "threat-intel" else "tracker.test"
                      if feed.category in ("tracker", "cname") else f"{feed.id}.test")
            feed.path(state).write_bytes(_snapshot({domain}, time.time()))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.proxy_port = sock.getsockname()[1]
        self.manual = state / "block.txt"

        script = state / "fixture.py"
        script.write_text(f"""
from dataclasses import replace
from egress_guard import policy
from egress_guard.addon import EgressGuard

_unchanged = policy.selected_feeds
policy.selected_feeds = lambda cfg: tuple(replace(feed, minimum=1) for feed in _unchanged(cfg))

_rules = policy._rules
def _one_time_read_error(path):
    marker = path.with_name("fail-next-load")
    if path.name == "block.txt" and marker.exists():
        marker.unlink()
        raise ValueError("injected one-time read error")
    return _rules(path)
policy._rules = _one_time_read_error

class LoopbackOnly:
    def server_connect(self, data):
        host, port = data.server.address
        if host in {{"passthrough.test", "blocked.test", "tracker.test", "front.test", "203.0.113.9"}}:
            data.server.address = ("127.0.0.1", {self.tls_origin.server_port})
        elif host in {{"plaintext.test", "127.0.0.1"}}:
            data.server.address = ("127.0.0.1", {self.plain_origin.server_port})
        else:
            data.server.error = "unexpected fixture target"

addons = [EgressGuard(), LoopbackOnly()]
""")
    def start_proxy(self, *, ready=True, plaintext_credentials=True, transport_profile="compatible",
                    connect_ports=None, address_guard=False):
        state = self.state
        log = (state / "proxy.log").open("wb")
        self.addCleanup(log.close)
        config = state / "config.toml"
        # Transport assertions inspect deliberately opted-in fixture history;
        # fresh production configuration defaults to no traffic history.
        config.write_text(f'[proxy]\nport = {self.proxy_port}\n[logging]\nhistory = "full"\n'
                          f'[risk]\nblock_plaintext_credentials = {str(plaintext_credentials).lower()}\n'
                          f'[transport]\nprofile = "{transport_profile}"\n'
                          f'connect_ports = {connect_ports or [443]}\n'
                          f'address_guard = {str(address_guard).lower()}\n')
        process = subprocess.Popen(
            [
                str(MITMDUMP), "--mode", "regular", "--listen-host", "127.0.0.1",
                "--listen-port", str(self.proxy_port), "--ignore-hosts", ".*",
                "--set", "connection_strategy=lazy", "--set", "flow_detail=0",
                "--set", "termlog_verbosity=error", "--set", f"confdir={state / 'mitm'}",
                "-s", str(state / "fixture.py"),
            ],
            stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "EGRESS_GUARD_DATA": str(state), "EGRESS_GUARD_CONFIG": str(config),
                 "PYTHONPATH": str(SOURCE), "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.addCleanup(self.stop, process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                status, body = self.http("http://egress-guard.invalid/health")
            except OSError:
                pass
            else:
                if status == (200 if ready else 503):
                    self.assertEqual(json.loads(body), {
                        "product": "egress-guard", "version": __version__,
                        "ready": ready, "https_decryption": False,
                    })
                    return
            time.sleep(0.05)
        self.fail(f"isolated proxy failed to start: {(state / 'proxy.log').read_text()}")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(4)

    def http(self, target, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        try:
            connection.request("GET", target, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def tls(self, host, *, sni=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        connection.set_tunnel(host, self.tls_origin.server_port)
        try:
            connection.connect()
            with self.tls_client.wrap_socket(connection.sock, server_hostname=sni or host) as tls:
                self.assertEqual(tls.getpeercert(binary_form=True), self.expected_cert)
                tls.sendall(b"GET /fixture-query?token=private-test-value HTTP/1.1\r\n"
                            b"Host: passthrough.test\r\nAuthorization: Bearer fixture-secret\r\n"
                            b"Connection: close\r\n\r\n")
                response = http.client.HTTPResponse(tls)
                response.begin()
                return response.status, response.read()
        finally:
            connection.close()

    def fragmented_tls(self, host):
        """Complete a real origin-verified TLS session after splitting its first flight."""
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        connection.set_tunnel(host, 443)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = self.tls_client.wrap_bio(incoming, outgoing, server_hostname="passthrough.test")
        try:
            connection.connect()
            with self.assertRaises(ssl.SSLWantReadError):
                client.do_handshake()
            hello = outgoing.read()
            body = hello[5:]
            self.assertEqual(len(body), int.from_bytes(hello[3:5], "big"))
            records = b"".join(b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part
                               for part in (body[:1], body[1:40], body[40:]))
            for part in (records[:1], records[1:2], records[2:5], records[5:30], records[30:-1]):
                connection.sock.sendall(part)
                time.sleep(0.03)
                self.assertEqual(self.tls_origin.accepts, 0)
            connection.sock.sendall(records[-1:])
            while True:
                try:
                    client.do_handshake()
                except ssl.SSLWantReadError:
                    if outgoing.pending:
                        connection.sock.sendall(outgoing.read())
                    incoming.write(connection.sock.recv(65536))
                else:
                    break
            self.assertEqual(client.getpeercert(binary_form=True), self.expected_cert)
            client.write(b"GET /fragmented HTTP/1.1\r\nHost: passthrough.test\r\nConnection: close\r\n\r\n")
            connection.sock.sendall(outgoing.read())
            response = b""
            while b"origin response" not in response:
                try:
                    response += client.read(65536)
                except ssl.SSLWantReadError:
                    received = connection.sock.recv(65536)
                    self.assertTrue(received)
                    incoming.write(received)
            self.assertTrue(response.startswith(b"HTTP/1.1 200"), response)
        finally:
            connection.close()

    def test_visible_tls_name_is_checked_independently_of_the_connect_authority(self):
        self.start_proxy()
        for authority, sni in (("front.test", "blocked.test"), ("front.test", "tracker.test"),
                               ("203.0.113.9", "blocked.test"), ("127.0.0.1", "blocked.test")):
            with self.subTest(authority=authority, sni=sni), self.assertRaises(OSError):
                self.tls(authority, sni=sni)
        with self.assertRaisesRegex(OSError, "403"):
            self.tls("blocked.test", sni="passthrough.test")
        self.assertEqual((self.tls_origin.accepts, self.plain_origin.accepts), (0, 0))
        self.assertEqual(self.tls("front.test", sni="passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.tls("203.0.113.9", sni="passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.tls_origin.accepts, 2)
        self.assertNotIn("Traceback", (self.state / "proxy.log").read_text())

    def test_visible_tls_threat_and_manual_blocks_survive_pauses_and_grants(self):
        expiry = time.time() + 600
        (self.state / "allow.txt").write_text("front.test\nblocked.test\nmanual.test\n")
        self.manual.write_text("manual.test\n")
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": expiry}))
        (self.state / "tracker-exceptions.json").write_text(json.dumps({
            "front.test": expiry, "blocked.test": expiry, "manual.test": expiry,
        }))
        self.start_proxy()
        for sni in ("blocked.test", "manual.test"):
            with self.subTest(sni=sni), self.assertRaises(OSError):
                self.tls("front.test", sni=sni)
        self.assertEqual(self.tls_origin.accepts, 0)
        # The ordinary policy pause still permits a tracker name, without transferring
        # the authority's exception to either threat or manual block targets.
        self.assertEqual(self.tls("front.test", sni="tracker.test"), (200, b"origin response"))
        self.assertEqual(self.tls_origin.accepts, 1)

    def test_exact_tls_name_grant_does_not_transfer_to_another_name(self):
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"tracker.test": time.time() + 600}))
        self.start_proxy()
        # CONNECT to the exact excepted host is admitted, but its subdomain has no
        # timed grant. A different name in ClientHello must get its own decision.
        with self.assertRaises(OSError):
            self.tls("tracker.test", sni="sub.tracker.test")
        self.assertEqual(self.tls_origin.accepts, 0)
        self.assertEqual(self.tls("front.test", sni="tracker.test"), (200, b"origin response"))
        self.assertEqual(self.tls_origin.accepts, 1)

    def test_visible_tls_name_checks_remain_active_in_plaintext_compatibility_mode(self):
        self.start_proxy(plaintext_credentials=False)
        plaintext = (b"GET /compatibility HTTP/1.1\r\nHost: plaintext.test\r\n"
                     b"Cookie: fixture-cookie\r\nConnection: close\r\n\r\n")
        self.assertIn(b"origin response", self.tunnel("plaintext.test", plaintext))
        self.assertEqual(self.plain_origin.requests[-1][1]["Cookie"], "fixture-cookie")
        hello = client_hello("blocked.test")
        self.assertEqual(self.tunnel("front.test", hello[:1], chunks=(hello[1:2], hello[2:])), b"")
        self.assertEqual(self.tls_origin.accepts, 0)
        self.assertEqual(self.tls("front.test", sni="passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.tls_origin.accepts, 1)

    def test_fragmented_tls_waits_for_both_name_checks_and_preserves_the_certificate(self):
        self.start_proxy()
        hello = client_hello("tracker.test")
        self.assertEqual(self.tunnel("front.test", hello[:1], chunks=(hello[1:2], hello[2:30], hello[30:])), b"")
        self.assertEqual(self.tls_origin.accepts, 0)
        self.fragmented_tls("front.test")
        self.assertEqual(self.tls_origin.accepts, 1)
        self.assertEqual(self.tls_origin.requests[-1][0], "/fragmented")
        self.assertNotIn("Traceback", (self.state / "proxy.log").read_text())

    def test_connect_authority_is_rechecked_when_a_delayed_hello_completes(self):
        self.start_proxy()
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        connection.set_tunnel("front.test", 443)
        try:
            connection.connect()
            hello = client_hello("passthrough.test")
            connection.sock.sendall(hello[:10])
            revision = proxy_health(self.proxy_port, self.state)["policy"]["revision"]
            self.manual.write_text("front.test\n")
            deadline = time.monotonic() + 10
            current = revision
            while time.monotonic() < deadline:
                current = proxy_health(self.proxy_port, self.state)["policy"]["revision"]
                if current != revision:
                    break
                time.sleep(0.05)
            self.assertNotEqual(current, revision)
            connection.sock.sendall(hello[10:])
            self.assertEqual(connection.sock.recv(1024), b"")
            self.assertEqual(self.tls_origin.accepts, 0)
        finally:
            connection.close()

    def test_health_plain_http_connect_denial_and_original_tls(self):
        self.start_proxy()
        for blocked_host in ("blocked.test", "tracker.test"):
            with self.subTest(blocked_host=blocked_host), self.assertRaisesRegex(OSError, "403"):
                self.tls(blocked_host)
        self.assertEqual(self.tls_origin.accepts, 0)

        for header in ("Cookie", "Authorization"):
            with self.subTest(header=header):
                status, body = self.http("http://plaintext.test/blocked", {header: "fixture-secret"})
                self.assertEqual(status, 403)
                self.assertIn(b"Plaintext credentials blocked", body)
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=4) as client:
            client.sendall(b"POST http://plaintext.test/upload HTTP/1.1\r\n"
                           b"Host: plaintext.test\r\nAuthorization: fixture-secret\r\n"
                           b"Content-Length: 50000000\r\n\r\n")
            self.assertEqual(client.recv(1024), b"")
        self.assertEqual(self.plain_origin.accepts, 0)
        status, _ = self.http("http://tracker.test/blocked", {"Host": "allowed.test"})
        self.assertEqual(status, 403)
        self.assertEqual(self.tls_origin.accepts, 0)

        status, body = self.http("http://127.0.0.1/plain-fixture", {
            "Cookie": "test-local-only", "Proxy-Authorization": "never-forward",
        })
        self.assertEqual((status, body), (200, b"origin response"))
        _, received = self.plain_origin.requests[-1]
        self.assertEqual(received["Cookie"], "test-local-only")
        self.assertNotIn("Proxy-Authorization", received)

        self.assertEqual(self.tls("passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.tls_origin.accepts, 1)
        self.assertEqual(self.tls_origin.requests[-1][1]["Authorization"], "Bearer fixture-secret")

        self.manual.write_text("passthrough.test\nplaintext.test\n")
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            status, _ = self.http("http://plaintext.test/reload")
            if status == 403:
                break
            time.sleep(0.1)
        self.assertEqual(status, 403)
        with self.assertRaisesRegex(OSError, "403"):
            self.tls("passthrough.test")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with sqlite3.connect(self.database) as connection:
                rows = connection.execute("SELECT host, decision, source, transport FROM events").fetchall()
            if ("passthrough.test", "blocked", "local-block", "connect") in rows:
                break
            time.sleep(0.02)
        self.assertIn(("blocked.test", "blocked", "threat-intel", "connect"), rows)
        self.assertIn(("plaintext.test", "blocked", "plaintext-credentials", "http"), rows)
        # The local test origin listens on an ephemeral port, so the allow is labelled as such.
        self.assertIn(("passthrough.test", "allowed", "nonstandard-port", "connect"), rows)
        self.assertIn(("passthrough.test", "blocked", "local-block", "connect"), rows)
        self.assertNotIn("fixture-secret", repr(rows))
        self.assertNotIn("private-test-value", repr(rows))


    def tunnel(self, host, first_bytes, *, chunks=()):
        """Open an admitted CONNECT tunnel, send raw bytes and return what comes back."""
        with socket.create_connection(("127.0.0.1", self.proxy_port), timeout=4) as client:
            client.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode("ascii"))
            head = b""
            while b"\r\n\r\n" not in head:
                data = client.recv(1024)
                if not data:
                    break
                head += data
            self.assertTrue(head.startswith(b"HTTP/1.1 200"), head)
            client.sendall(first_bytes)
            for chunk in chunks:
                time.sleep(0.05)
                try:
                    client.sendall(chunk)
                except OSError:
                    break
            received = b""
            try:
                while data := client.recv(4096):
                    received += data
            except OSError:
                pass
            return received

    def test_connect_tunnel_refuses_plaintext_http(self):
        self.start_proxy()
        plaintext_request = (b"GET /tunnelled HTTP/1.1\r\nHost: plaintext.test\r\n"
                             b"Authorization: Bearer fixture-secret\r\nCookie: fixture-cookie\r\n"
                             b"Connection: close\r\n\r\n")
        cases = {
            "plaintext-http": (plaintext_request, ()),
            "tiny-first-write": (b"\x16", (b"\x03\x01" + plaintext_request,)),
            "tls-header-then-garbage": (b"\x16\x03\x01\x00\x10" + b"\x00" * 16, (plaintext_request,)),
            "oversized-hello": (b"\x16\x03\x01\x40\x00\x01\xff\xff\xff" + b"\x00" * 0x3FFB,
                                (b"\x16\x03\x01\x40\x00" + b"\x00" * 0x4000,) * 5),
        }
        for name, (first, rest) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.tunnel("plaintext.test", first, chunks=rest), b"")
        self.assertEqual(self.plain_origin.accepts, 0)
        self.assertEqual(self.plain_origin.requests, [])

        # TLS through an admitted tunnel still reaches the origin with its own certificate.
        self.assertEqual(self.tls("passthrough.test"), (200, b"origin response"))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with sqlite3.connect(self.database) as connection:
                rows = connection.execute("SELECT host, decision, source, transport FROM events").fetchall()
            if ("plaintext.test", "blocked", "non-tls-tunnel", "connect") in rows:
                break
            time.sleep(0.02)
        self.assertIn(("plaintext.test", "blocked", "non-tls-tunnel", "connect"), rows)
        self.assertNotIn("fixture-secret", repr(rows))
        self.assertNotIn("Traceback", (self.state / "proxy.log").read_text())

    def test_health_authenticates_installation_and_rejects_static_replay(self):
        self.start_proxy()
        self.assertTrue(proxy_health(self.proxy_port, self.state)["ready"])
        self.assertEqual(self.http("http://egress-guard.invalid/health?nonce=too-short")[0], 400)

        _, observed = self.http("http://egress-guard.invalid/health?nonce=" + "A" * 43)
        recorded = json.loads(observed)
        self.assertIsInstance(recorded["proof"], str)

        class StaticImposter(UpstreamHandler):
            def do_GET(self):
                body = json.dumps(self.server.payload).encode("ascii")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with ThreadingHTTPServer(("127.0.0.1", 0), StaticImposter) as imposter:
            thread = threading.Thread(target=imposter.serve_forever, daemon=True)
            thread.start()
            try:
                imposter.payload = recorded
                self.assertFalse(proxy_health(imposter.server_port, self.state)["ready"])
                imposter.payload = {key: val for key, val in recorded.items() if key != "proof"}
                self.assertFalse(proxy_health(imposter.server_port, self.state)["ready"])
            finally:
                imposter.shutdown()
                thread.join(2)

    def assert_origin_status(self, expected):
        # Polls until the expected status; only the allowance for a loaded machine, not the assertion, is generous.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status, _ = self.http("http://plaintext.test/rule-check")
            if status == expected:
                return
            time.sleep(0.05)
        self.assertEqual(status, expected)

    def test_invalid_manual_rules_preserve_running_policy_until_repaired(self):
        self.manual.write_text("plaintext.test\n")
        self.start_proxy()
        self.assert_origin_status(403)

        self.manual.write_bytes(b"#" * (MAX_CONTROL_BYTES + 1))
        # Span a complete watcher tick so an empty replacement policy would be observable.
        end = time.monotonic() + 1.5
        while time.monotonic() < end:
            self.assertEqual(self.http("http://plaintext.test/rule-check")[0], 403)
            time.sleep(0.05)
        self.assertEqual(self.plain_origin.accepts, 0)
        self.manual.write_text("# removed by the user\n")
        self.assert_origin_status(200)

    def test_one_time_read_error_recovers_without_another_edit(self):
        self.start_proxy()
        self.assert_origin_status(200)
        marker = self.state / "fail-next-load"
        marker.touch()
        self.manual.write_text("plaintext.test\n")
        self.assert_origin_status(403)
        self.assertFalse(marker.exists(), "the injected read error never ran")
        with patch("egress_guard.policy.selected_feeds",
                   lambda cfg: tuple(replace(feed, minimum=1) for feed in selected_feeds(cfg))):
            saved = Policy(load_config(self.state / "config.toml"), self.state).revision
        reported = proxy_health(self.proxy_port, self.state)["policy"]
        self.assertEqual(reported["revision"], saved)
        self.assertFalse(reported["pending"] or reported["degraded"])

    def test_live_history_none_is_acknowledged_only_after_disk_logging_stops(self):
        self.start_proxy()
        self.assertEqual(self.http("http://plaintext.test/before-history-change")[0], 200)
        deadline = time.monotonic() + 3
        before = 0
        while time.monotonic() < deadline:
            with sqlite3.connect(self.database) as connection:
                before = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if before:
                break
            time.sleep(0.02)
        self.assertEqual(before, 1)
        path = self.state / "config.toml"
        path.write_text(f'[proxy]\nport = {self.proxy_port}\n[logging]\nhistory = "none"\n')
        with patch("egress_guard.policy.selected_feeds",
                   lambda cfg: tuple(replace(feed, minimum=1) for feed in selected_feeds(cfg))):
            desired = Policy(load_config(path), self.state).revision
        deadline = time.monotonic() + 10
        reported = {}
        while time.monotonic() < deadline:
            reported = proxy_health(self.proxy_port, self.state).get("policy") or {}
            if reported.get("revision") == desired and reported.get("pending") is False:
                break
            time.sleep(0.05)
        self.assertEqual(reported.get("revision"), desired)
        self.assertTrue(reported["logging"]["applied"])
        self.assertEqual(reported["logging"]["history"], "none")
        for _ in range(3):
            self.assertEqual(self.http("http://plaintext.test/after-history-receipt")[0], 200)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("SELECT value FROM meta WHERE key = 'history'").fetchone()[0], "none")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], before)
        self.assertNotIn("Traceback", (self.state / "proxy.log").read_text())

    def test_invalid_manual_rules_at_start_are_unready_and_recover(self):
        self.manual.write_text("plaintext.test\ninvalid/domain\n")
        self.start_proxy(ready=False)
        self.assertEqual(self.http("http://plaintext.test/rule-check")[0], 503)
        self.assertEqual(self.plain_origin.accepts, 0)
        self.manual.write_text("plaintext.test\n")
        self.assert_origin_status(403)
        self.assertEqual(self.http("http://egress-guard.invalid/health")[0], 200)
        self.assertEqual(self.plain_origin.accepts, 0)


if __name__ == "__main__":
    unittest.main()
