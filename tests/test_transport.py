"""Real local transport qualification: no public targets, proxy settings, or CA changes."""
from dataclasses import replace
import http.client
import json
import socket
import time
import unittest
from unittest.mock import patch

from egress_guard.config import load_config
from egress_guard.feeds import MALWARE, _snapshot, selected_feeds
from egress_guard.health import proxy_health
from egress_guard.policy import Policy
from egress_guard.transport_policy import applied, refusal, runtime_receipt
import test_addon as fixtures


class TransportPolicyTests(unittest.TestCase):
    def test_hardened_request_floor_is_separate_from_numeric_address_policy(self):
        config = {"profile": "hardened", "connect_ports": [443, 8443], "address_guard": False}
        self.assertEqual(refusal(config, "form.test", 80, "http", loopback=False), "plaintext-http")
        self.assertEqual(refusal(config, "93.184.215.14", 443, "connect", loopback=False), "literal-connect")
        self.assertEqual(refusal(config, "::ffff:93.184.215.14", 443, "connect", loopback=False), "literal-connect")
        self.assertEqual(refusal(config, "allowed.test", 22, "connect", loopback=False), "connect-port")
        self.assertIsNone(refusal(config, "allowed.test", 8443, "connect", loopback=False))
        self.assertIsNone(refusal(config, "127.0.0.1", 18081, "http", loopback=True))
        self.assertIsNone(refusal(config, "::1", 18081, "connect", loopback=True))
        config["profile"] = "compatible"
        self.assertIsNone(refusal(config, "93.184.215.14", 22, "connect", loopback=False))
        self.assertIsNone(refusal(config, "form.test", 80, "http", loopback=False))

    def test_runtime_receipt_never_turns_unavailable_or_unknown_fields_into_acknowledgment(self):
        saved = {"profile": "hardened", "connect_ports": [443], "address_guard": True}
        runtime = {"profile": "hardened", "connect_ports": [443], "address_guard": {
            "selected": True, "state": "active", "reason": None}, "scope": "proxy-tcp", "applied": True}
        self.assertTrue(applied(saved, runtime_receipt(runtime)))
        self.assertIsNone(runtime_receipt({**runtime, "private_peer": "must-not-escape"}))
        bad = {**runtime, "address_guard": {"selected": True, "state": "unavailable", "reason": "self-test-failed"}}
        self.assertIsNone(runtime_receipt(bad))
        bad["applied"] = False
        self.assertFalse(applied(saved, runtime_receipt(bad)))
        self.assertIsNone(runtime_receipt({**runtime, "address_guard": {"selected": False, "state": "active", "reason": None}}))


@unittest.skipUnless(fixtures.MITMDUMP, "mitmdump required for the real proxy test")
class TransportIntegrationTests(unittest.TestCase):
    # Reuse only fixture methods, without inheriting and rerunning the 0.8 test suite.
    setUp = fixtures.ProxyIntegrationTests.setUp
    serve = fixtures.ProxyIntegrationTests.serve
    start_proxy = fixtures.ProxyIntegrationTests.start_proxy
    stop = staticmethod(fixtures.ProxyIntegrationTests.stop)
    http = fixtures.ProxyIntegrationTests.http
    tls = fixtures.ProxyIntegrationTests.tls
    tunnel = fixtures.ProxyIntegrationTests.tunnel
    fragmented_tls = fixtures.ProxyIntegrationTests.fragmented_tls

    def dns_fixture(self):
        self.blocked_origin = self.serve(self.tls_origin.tls, host="127.0.0.2", port=self.tls_origin.server_port)
        MALWARE.path(self.state).write_bytes(_snapshot({"127.0.0.2"}, time.time()))
        # Replace hostname rewriting with the actual resolver path used by asyncio.
        # Every possible result remains a loopback sockaddr; unexpected targets fail.
        (self.state / "fixture.py").write_text('''
import socket
from pathlib import Path
from dataclasses import replace
from egress_guard import policy
from egress_guard.addon import EgressGuard
from egress_guard.paths import data_dir
_selected = policy.selected_feeds
policy.selected_feeds = lambda cfg: tuple(replace(feed, minimum=1) for feed in _selected(cfg))
_resolve = socket.getaddrinfo
def local_only_resolve(host, port, *args, **kwargs):
    if host in ("only-blocked.test", "accounts.google.com", "passthrough.test"):
        with (data_dir() / "fixture-lookups.txt").open("a") as log:
            log.write(host + "\\n")
        first = _resolve("127.0.0.2", port, *args, **kwargs)
        return first + (_resolve("127.0.0.1", port, *args, **kwargs) if host == "passthrough.test" else [])
    if host not in ("127.0.0.1", "127.0.0.2", "::1"):
        raise OSError("unexpected fixture target")
    return _resolve(host, port, *args, **kwargs)
socket.getaddrinfo = local_only_resolve
addons = [EgressGuard()]
''')

    def wait_new_revision(self, old):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            report = proxy_health(self.proxy_port, self.state).get("policy") or {}
            if report.get("revision") not in (None, old) and report.get("pending") is False:
                return report
            time.sleep(0.05)
        self.fail("the new policy revision was not acknowledged")

    def test_address_guard_refuses_listed_actual_ips_and_preserves_resolver_fallback(self):
        self.dns_fixture()
        self.start_proxy(address_guard=True)
        report = proxy_health(self.proxy_port, self.state)["policy"]
        self.assertEqual(report["transport"]["address_guard"], {
            "selected": True, "state": "active", "reason": None,
        })
        for host in ("only-blocked.test", "accounts.google.com"):
            with self.subTest(host=host), self.assertRaises(OSError):
                self.tls(host, sni="passthrough.test")
        self.assertEqual(self.blocked_origin.accepts, 0)
        self.assertEqual(self.tls_origin.accepts, 0)
        # The denied first candidate is an ordinary connection failure; asyncio
        # continues to the next candidate. tls() verifies the original certificate.
        self.assertEqual(self.tls("passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.blocked_origin.accepts, 0)
        self.assertEqual(self.tls_origin.accepts, 1)
        self.assertEqual((self.state / "fixture-lookups.txt").read_text().splitlines(), [
            "only-blocked.test", "accounts.google.com", "passthrough.test",
        ])
        MALWARE.path(self.state).write_bytes(_snapshot({"127.0.0.1", "127.0.0.2"}, time.time()))
        self.wait_new_revision(report["revision"])
        with self.assertRaises(OSError):
            self.tls("passthrough.test")
        self.assertEqual((self.blocked_origin.accepts, self.tls_origin.accepts), (0, 1))
        self.assertNotIn("Traceback", (self.state / "proxy.log").read_text())

    def test_disabled_address_guard_preserves_the_explicit_compatible_behavior(self):
        self.dns_fixture()
        self.start_proxy()
        self.assertEqual(self.tls("only-blocked.test", sni="passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.blocked_origin.accepts, 1)
        self.assertEqual(proxy_health(self.proxy_port, self.state)["policy"]["transport"]["address_guard"], {
            "selected": False, "state": "disabled", "reason": None,
        })

    def test_hardened_http_refuses_forms_and_streaming_bodies_before_any_origin_connection(self):
        self.start_proxy(transport_profile="hardened")
        self.assertEqual(self.http("http://plaintext.test/login?token=synthetic-query")[0], 403)
        for framing in (b"Content-Length: 50000000", b"Transfer-Encoding: chunked"):
            with self.subTest(framing=framing), socket.create_connection(("127.0.0.1", self.proxy_port), timeout=4) as client:
                client.sendall(b"POST http://plaintext.test/login HTTP/1.1\r\nHost: plaintext.test\r\n"
                               b"Content-Type: application/x-www-form-urlencoded\r\n" + framing + b"\r\n\r\n")
                # No body is sent: EOF must arrive immediately instead of buffering
                # the declared body or waiting for credentials to appear in it.
                self.assertEqual(client.recv(1024), b"")
        self.assertEqual(self.plain_origin.accepts, 0)
        self.assertEqual(self.http("http://127.0.0.1/local", {"Cookie": "local-fixture"}), (200, b"origin response"))
        health = proxy_health(self.proxy_port, self.state)
        self.assertTrue(health["ready"])
        self.assertTrue(health["policy"]["transport"]["applied"])
        self.assertEqual(health["policy"]["transport"]["profile"], "hardened")

    def test_hardened_connect_port_literal_and_tls_requirements_cannot_be_paused(self):
        expiry = time.time() + 600
        (self.state / "allow.txt").write_text("front.test\nplaintext.test\n")
        (self.state / "tracker-exceptions.json").write_text(json.dumps({"front.test": expiry, "plaintext.test": expiry}))
        (self.state / "filter-controls.json").write_text(json.dumps({"tracker_pause_until": expiry}))
        self.start_proxy(transport_profile="hardened", plaintext_credentials=False)
        for host in ("passthrough.test", "203.0.113.9", "::ffff:203.0.113.9"):
            with self.subTest(host=host), self.assertRaisesRegex(OSError, "403"):
                self.tls(host, sni="passthrough.test")
        raw = b"GET / HTTP/1.1\r\nHost: plaintext.test\r\n\r\n"
        self.assertEqual(self.tunnel("plaintext.test", raw), b"")
        self.assertEqual((self.plain_origin.accepts, self.tls_origin.accepts), (0, 0))
        self.fragmented_tls("front.test")  # CONNECT 443, real TLS, exact original cert.
        self.assertEqual(self.tls_origin.accepts, 1)

    def test_explicit_additional_connect_port_allows_the_original_tls_connection(self):
        self.start_proxy(transport_profile="hardened", connect_ports=sorted([443, self.tls_origin.server_port]))
        self.assertEqual(self.tls("passthrough.test"), (200, b"origin response"))
        self.assertEqual(self.tls_origin.accepts, 1)

    def test_delayed_tunnel_uses_the_live_hardened_profile(self):
        self.start_proxy(plaintext_credentials=False)
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=4)
        connection.set_tunnel("plaintext.test", 443)
        try:
            connection.connect()
            old = proxy_health(self.proxy_port, self.state)["policy"]["revision"]
            path = self.state / "config.toml"
            path.write_text(path.read_text().replace('profile = "compatible"', 'profile = "hardened"'))
            self.wait_new_revision(old)
            connection.sock.sendall(b"GET / HTTP/1.1\r\nHost: plaintext.test\r\n\r\n")
            self.assertEqual(connection.sock.recv(1024), b"")
            self.assertEqual(self.plain_origin.accepts, 0)
        finally:
            connection.close()

    def test_failed_guard_activation_refuses_all_proxy_traffic_but_reports_the_reason(self):
        script = self.state / "fixture.py"
        script.write_text(script.read_text() + '\nfrom egress_guard import address_guard\naddress_guard.supported = lambda loop: False\n')
        self.start_proxy(address_guard=True, ready=False)
        self.assertEqual(self.http("http://plaintext.test/private")[0], 503)
        with self.assertRaisesRegex(OSError, "503"):
            self.tls("passthrough.test")
        self.assertEqual((self.plain_origin.accepts, self.tls_origin.accepts), (0, 0))
        health = proxy_health(self.proxy_port, self.state)
        self.assertFalse(health["ready"])
        self.assertEqual(health["policy"]["transport"]["address_guard"], {
            "selected": True, "state": "unavailable", "reason": "unsupported-runtime",
        })
        self.assertFalse(health["policy"]["transport"]["applied"])

    def test_guard_selection_change_requires_restart_without_a_false_acknowledgment(self):
        self.start_proxy()
        old = proxy_health(self.proxy_port, self.state)["policy"]["revision"]
        path = self.state / "config.toml"
        path.write_text(path.read_text().replace("address_guard = false", "address_guard = true"))
        deadline = time.monotonic() + 10
        report = {}
        while time.monotonic() < deadline:
            report = proxy_health(self.proxy_port, self.state)["policy"]
            if report["pending"] and report["error"]:
                break
            time.sleep(0.05)
        self.assertEqual(report["revision"], old)
        self.assertTrue(report["pending"])
        self.assertIn("restarting", report["error"])
        self.assertEqual(report["transport"]["address_guard"]["state"], "disabled")
        with patch("egress_guard.policy.selected_feeds",
                   lambda cfg: tuple(replace(feed, minimum=1) for feed in selected_feeds(cfg))):
            desired = Policy(load_config(path), self.state).revision
        self.assertNotEqual(report["revision"], desired)


if __name__ == "__main__":
    unittest.main()
