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

from egress_guard import __version__
from egress_guard.feeds import _snapshot, selected_feeds
from egress_guard.health import proxy_health
from egress_guard.policy import MAX_CONTROL_BYTES

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
    def __init__(self, tls=None):
        super().__init__(("127.0.0.1", 0), UpstreamHandler)
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("passthrough.test")]), False)
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
    def serve(self, tls=None):
        server = Origin(tls)
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
            domain = "blocked.test" if feed.category == "threat" else "tracker.test"
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

class LoopbackOnly:
    def server_connect(self, data):
        host, port = data.server.address
        if host in {{"passthrough.test", "blocked.test", "tracker.test"}}:
            data.server.address = ("127.0.0.1", {self.tls_origin.server_port})
        elif host in {{"plaintext.test", "127.0.0.1"}}:
            data.server.address = ("127.0.0.1", {self.plain_origin.server_port})
        else:
            data.server.error = "unexpected fixture target"

addons = [EgressGuard(), LoopbackOnly()]
""")
    def start_proxy(self, *, ready=True):
        state = self.state
        log = (state / "proxy.log").open("wb")
        self.addCleanup(log.close)
        config = state / "config.toml"
        config.write_text(f"[proxy]\nport = {self.proxy_port}\n")
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

    def tls(self, host):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        connection.set_tunnel(host, self.tls_origin.server_port)
        try:
            connection.connect()
            with self.tls_client.wrap_socket(connection.sock, server_hostname=host) as tls:
                self.assertEqual(tls.getpeercert(binary_form=True), self.expected_cert)
                tls.sendall(b"GET /fixture-query?token=private-test-value HTTP/1.1\r\n"
                            b"Host: passthrough.test\r\nAuthorization: Bearer fixture-secret\r\n"
                            b"Connection: close\r\n\r\n")
                response = http.client.HTTPResponse(tls)
                response.begin()
                return response.status, response.read()
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
        self.assertIn(("passthrough.test", "allowed", "no-match", "connect"), rows)
        self.assertIn(("passthrough.test", "blocked", "local-block", "connect"), rows)
        self.assertNotIn("fixture-secret", repr(rows))
        self.assertNotIn("private-test-value", repr(rows))


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
        deadline = time.monotonic() + 4
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
