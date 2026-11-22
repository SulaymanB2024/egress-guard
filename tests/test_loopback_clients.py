"""Launcher/health responses come from temporary loopback peers, never real apps."""
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from egress_guard import dashboard_app, health
from egress_guard.config import initialize
from egress_guard.dashboard_http import installation_token
from egress_guard.paths import supports_private_identity


@contextmanager
def endpoint(key, *, first=None, second=None, mode="fast", large=None, slow_phase=None, transport=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, value, phase):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            mode = self.server.mode if self.server.slow_phase in (None, phase) else "fast"
            if self.server.large == phase:
                body += b" " * 4500
            try:
                if mode == "headers":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    self.wfile.flush()
                    for _ in range(20):
                        if self.server.stopping.wait(0.04):
                            return
                        self.wfile.write(b"x")
                        self.wfile.flush()
                    self.wfile.write(b"\r\n")
                else:
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if mode == "body":
                    for offset in range(0, len(body), 8):
                        self.wfile.write(body[offset:offset + 8])
                        self.wfile.flush()
                        if self.server.stopping.wait(0.04):
                            return
                else:
                    self.wfile.write(body)
            except OSError:
                pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/health":
                nonce = query["nonce"][0]
                proof = hmac.new(key.encode(), f"egress-guard/v1:proxy:{nonce}:{self.server.server_port}".encode(), hashlib.sha256).hexdigest()
                value = {"product": "egress-guard", "ready": True, "https_decryption": False, "proof": proof}
                report = {"transport": {"profile": "compatible", "connect_ports": [443],
                          "address_guard": {"selected": False, "state": "disabled", "reason": None},
                          "scope": "proxy-tcp", "tunnel_policy": "per-forward", "applied": True}}
                if transport is False:
                    report = {}
                elif transport is not None:
                    report = {"transport": transport}
                canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
                message = f"egress-guard/v1:proxy-policy:{nonce}:{self.server.server_port}:{canonical}"
                value.update(policy=report, policy_proof=hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest())
            else:
                client = query["client"][0]
                nonce = "n" * 43
                proof = hmac.new(key.encode(), f"egress-guard/v2:server:{self.server.origin}:{client}:{nonce}".encode(), hashlib.sha256).hexdigest()
                value = {"challenge": nonce, "proof": proof}
            if self.server.first is not None:
                value = self.server.first
            self.respond(value, "first")

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.server.posts += 1
            value = self.server.second if self.server.second is not None else {"token": "b" * 43}
            self.respond(value, "second")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.origin = f"http://127.0.0.1:{server.server_port}"
    server.stopping = threading.Event()
    server.first, server.second, server.mode, server.large = first, second, mode, large
    server.slow_phase = slow_phase
    server.posts = 0
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopping.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@unittest.skipUnless(supports_private_identity(), "requires a supported private identity backend")
class LoopbackClientTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.configuration = self.state / "config.toml"
        environment = patch.dict(os.environ, {"EGRESS_GUARD_DATA": str(self.state),
                                              "EGRESS_GUARD_CONFIG": str(self.configuration)})
        environment.start()
        self.addCleanup(environment.stop)
        initialize()
        self.key = installation_token(self.state)

    def select(self, server):
        proxy = 18080 if server.server_port != 18080 else 18082
        self.configuration.write_text(f"[proxy]\nport={proxy}\ndashboard_port={server.server_port}\n")

    def rejected_launcher(self, server):
        self.select(server)
        with patch.object(dashboard_app.webbrowser, "open", return_value=True) as browser:
            with self.assertRaisesRegex(ValueError, "Start a healthy Egress Guard dashboard"):
                dashboard_app.open_dashboard()
        browser.assert_not_called()

    def test_nonobject_challenge_responses_are_clean_failures_before_bootstrap(self):
        for value in ([], "wrong", 42, b"null"):
            with self.subTest(value=value), endpoint(self.key, first=value) as server:
                self.rejected_launcher(server)
                self.assertEqual(server.posts, 0)

    def test_nonobject_bootstrap_responses_are_clean_failures_before_browser_launch(self):
        for value in ([], "wrong", 42, b"null"):
            with self.subTest(value=value), endpoint(self.key, second=value) as server:
                self.rejected_launcher(server)

    def test_deep_json_response_is_a_clean_failure(self):
        nested = b"[" * 1100 + b"0" + b"]" * 1100
        with endpoint(self.key, first=nested) as server:
            self.rejected_launcher(server)
            self.assertEqual(server.posts, 0)

    def test_invalid_bootstrap_token_characters_never_reach_the_browser(self):
        for value in ("\n" * 43, "#" * 43, "/" * 43, "\ud800" * 43):
            with self.subTest(value=repr(value)), endpoint(self.key, second={"token": value}) as server:
                self.rejected_launcher(server)

    def test_oversized_responses_are_rejected_in_both_launcher_phases(self):
        for phase in ("first", "second"):
            with self.subTest(phase=phase), endpoint(self.key, large=phase) as server:
                self.rejected_launcher(server)

    def test_slow_launcher_headers_and_bodies_hit_the_response_deadline(self):
        for mode in ("headers", "body"):
            with self.subTest(mode=mode), endpoint(self.key, mode=mode) as server, patch.object(
                    dashboard_app, "LAUNCHER_RESPONSE_SECONDS", 0.15, create=True):
                self.rejected_launcher(server)
                self.assertEqual(server.posts, 0)

    def test_slow_health_headers_and_bodies_fail_closed(self):
        for mode in ("headers", "body"):
            with self.subTest(mode=mode), endpoint(self.key, mode=mode) as server, patch.object(
                    health, "HEALTH_RESPONSE_SECONDS", 0.15, create=True):
                self.assertFalse(health.proxy_health(server.server_port, self.state)["ready"])

    def test_reconnected_bootstrap_reply_gets_its_own_response_deadline(self):
        for mode in ("headers", "body"):
            with self.subTest(mode=mode), endpoint(self.key, mode=mode, slow_phase="second") as server, patch.object(
                    dashboard_app, "LAUNCHER_RESPONSE_SECONDS", 0.15):
                self.rejected_launcher(server)
                self.assertEqual(server.posts, 1)

    def test_oversized_authenticated_health_response_is_rejected(self):
        with endpoint(self.key, large="first") as server:
            self.assertFalse(health.proxy_health(server.server_port, self.state)["ready"])

    def test_fast_signed_launcher_and_health_responses_remain_usable(self):
        with endpoint(self.key) as server:
            self.assertTrue(health.proxy_health(server.server_port, self.state)["ready"])
            self.select(server)
            with patch.object(dashboard_app.webbrowser, "open", return_value=True) as browser:
                dashboard_app.open_dashboard()
            self.assertEqual(browser.call_args.args[0], server.origin + "/#" + "b" * 43)

    def test_health_requires_an_authenticated_applied_transport_receipt(self):
        unavailable = {"profile": "compatible", "connect_ports": [443], "address_guard": {
            "selected": True, "state": "unavailable", "reason": "self-test-failed"},
            "scope": "proxy-tcp", "tunnel_policy": "per-forward", "applied": False}
        for value in (False, {"applied": True}, unavailable, {**unavailable, "applied": True}):
            with self.subTest(value=value), endpoint(self.key, transport=value) as server:
                result = health.proxy_health(server.server_port, self.state)
                self.assertFalse(result["ready"])
                self.assertIsInstance(result["policy"], dict)
                if value == unavailable:
                    self.assertEqual(result["policy"]["transport"], unavailable)
                else:
                    self.assertIsNone(result["policy"]["transport"])

    def test_authenticated_09_transport_cannot_acknowledge_per_forward_enforcement(self):
        old = {"profile": "compatible", "connect_ports": [443], "address_guard": {
            "selected": False, "state": "disabled", "reason": None}, "scope": "proxy-tcp", "applied": True}
        for value in (old, {**old, "tunnel_policy": "initial-only"}):
            with self.subTest(value=value), endpoint(self.key, transport=value) as server:
                result = health.proxy_health(server.server_port, self.state)
                self.assertFalse(result["ready"])
                self.assertIsInstance(result["policy"], dict)
                self.assertIsNone(result["policy"]["transport"])


if __name__ == "__main__":
    unittest.main()
