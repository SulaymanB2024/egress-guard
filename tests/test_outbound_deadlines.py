"""Slow peers use only loopback TCP and synthetic feed/canary data."""
from contextlib import contextmanager
from dataclasses import replace
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error

from egress_guard import canaries, feeds
from egress_guard.http_deadline import ResponseDeadline


@contextmanager
def peer(kind="feed", mode="fast", tls=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.server.requests += 1
            if self.server.mode == "redirect":
                self.send_response(302)
                self.send_header("Location", self.server.redirect_target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (b"one.test\ntwo.test\n" if self.server.kind == "feed" else
                    json.dumps({"history": {"token_type": "web", "hits": []}}).encode())
            try:
                if self.server.mode == "headers":
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
                self.send_header("Content-Type", "application/json" if self.server.kind == "canary" else "text/plain")
                if self.server.mode != "open-ended":
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.server.mode == "body":
                    for value in body:
                        self.wfile.write(bytes([value]))
                        self.wfile.flush()
                        if self.server.stopping.wait(0.04):
                            return
                else:
                    self.wfile.write(body)
                    self.wfile.flush()
                    if self.server.mode == "open-ended":
                        for _ in range(20):
                            if self.server.stopping.wait(0.04):
                                return
                            self.wfile.write(b"\n")
                            self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.kind, server.mode = kind, mode
    server.requests = 0
    server.stopping = threading.Event()
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopping.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def tls_peer(kind="feed", mode="fast"):
    # Reuse the suite's ephemeral certificate fixture. Trust is scoped to the
    # returned client context; no OS certificate store is changed.
    from test_addon import certificate
    with tempfile.TemporaryDirectory() as directory:
        server_context, client_context, _ = certificate(Path(directory))
        with peer(kind, mode, tls=server_context) as server:
            lookup = socket.getaddrinfo
            def local_address(host, port, *arguments, **options):
                if host != "passthrough.test":
                    raise AssertionError("The TLS fixture may resolve only its synthetic hostname")
                return lookup("127.0.0.1", port, *arguments, **options)
            with patch.object(socket, "getaddrinfo", side_effect=local_address):
                yield server, client_context


class OutboundDeadlineTests(unittest.TestCase):
    def test_feed_body_and_headers_cannot_drip_past_the_response_budget(self):
        for mode in ("body", "headers", "open-ended"):
            with self.subTest(mode=mode), peer(mode=mode) as server:
                fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                                  url=f"http://127.0.0.1:{server.server_port}/fixture")
                with patch.object(feeds, "RESPONSE_SECONDS", 0.2, create=True):
                    with self.assertRaisesRegex(ValueError, "download failed"):
                        feeds._download(fixture)

    def test_canary_body_and_headers_cannot_drip_past_the_response_budget(self):
        connection_type = http.client.HTTPConnection
        for mode in ("body", "headers", "open-ended"):
            with self.subTest(mode=mode), peer(kind="canary", mode=mode) as server:
                def connect(host, *, timeout, context):
                    self.assertEqual(host, canaries.HOST)
                    self.assertEqual(context.verify_mode.name, "CERT_REQUIRED")
                    return connection_type("127.0.0.1", server.server_port, timeout=timeout)
                with patch.object(canaries, "RESPONSE_SECONDS", 0.2, create=True), patch.object(
                        canaries.http.client, "HTTPSConnection", side_effect=connect):
                    with self.assertRaisesRegex(canaries.CanaryError, canaries.PROVIDER_ERROR):
                        canaries._fetch_history("z" * 25, "b" * 32, "web")

    def test_expired_feed_keeps_last_good_snapshot_and_releases_refresh_lock(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name)
        with peer() as server:
            fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                              url=f"http://127.0.0.1:{server.server_port}/fixture")
            with patch.object(feeds, "selected_feeds", return_value=(fixture,)), patch.object(
                    feeds, "RESPONSE_SECONDS", 0.2, create=True):
                self.assertTrue(feeds.update_feeds(state, {})["ok"])
                before = fixture.path(state).read_bytes()
                server.mode = "body"
                failed = feeds.update_feeds(state, {})
                self.assertFalse(failed["ok"])
                self.assertEqual(failed["feeds"][0]["status"], "using-previous")
                self.assertEqual(fixture.path(state).read_bytes(), before)
                server.mode = "fast"
                self.assertTrue(feeds.update_feeds(state, {})["ok"])
                self.assertEqual(feeds.read_cached_feed(state, fixture), {"one.test", "two.test"})

    def test_fast_feed_and_canary_responses_still_work(self):
        with peer() as server:
            fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                              url=f"http://127.0.0.1:{server.server_port}/fixture")
            self.assertEqual(feeds._download(fixture), b"one.test\ntwo.test\n")
        connection_type = http.client.HTTPConnection
        with peer(kind="canary") as server, patch.object(canaries.http.client, "HTTPSConnection",
                side_effect=lambda *_, **options: connection_type("127.0.0.1", server.server_port, timeout=options["timeout"])):
            self.assertEqual(canaries._fetch_history("z" * 25, "b" * 32, "web"), ("web", [], False))

    def test_real_https_feed_deadline_survives_connection_close_socket_ownership(self):
        for mode in ("fast", "body", "headers", "open-ended"):
            with self.subTest(mode=mode), tls_peer(mode=mode) as (server, context):
                fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                                  url=f"https://passthrough.test:{server.server_port}/fixture")
                with patch("egress_guard.http_deadline.ssl.create_default_context", return_value=context), patch.object(
                        feeds, "RESPONSE_SECONDS", 0.2):
                    if mode == "fast":
                        self.assertEqual(feeds._download(fixture), b"one.test\ntwo.test\n")
                    else:
                        with self.assertRaisesRegex(ValueError, "download failed"):
                            feeds._download(fixture)

    def test_real_https_canary_deadline_and_success_control(self):
        for mode in ("fast", "body", "headers", "open-ended"):
            with self.subTest(mode=mode), tls_peer(kind="canary", mode=mode) as (server, context):
                with patch.object(canaries, "RESPONSE_SECONDS", 0.2), patch.object(
                        canaries, "HOST", f"passthrough.test:{server.server_port}"), patch.object(
                        canaries.ssl, "create_default_context", return_value=context):
                    if mode == "fast":
                        self.assertEqual(canaries._fetch_history("z" * 25, "b" * 32, "web"), ("web", [], False))
                    else:
                        with self.assertRaisesRegex(canaries.CanaryError, canaries.PROVIDER_ERROR):
                            canaries._fetch_history("z" * 25, "b" * 32, "web")

    def test_cancelled_deadline_closes_its_duplicate_and_leaves_the_connection_usable(self):
        left, right = socket.socketpair()
        with left, right:
            with ResponseDeadline(0.1) as deadline:
                deadline.attach(left)
                control = deadline._socket
                self.assertNotEqual(control.fileno(), left.fileno())
                self.assertFalse(control.get_inheritable())
            self.assertEqual(control.fileno(), -1)
            time.sleep(0.15)
            right.sendall(b"x")
            self.assertEqual(left.recv(1), b"x")

    def test_closed_owner_with_buffered_reader_still_has_an_effective_deadline(self):
        left, right = socket.socketpair()
        try:
            with left.makefile("rb") as buffered, ResponseDeadline(0.1) as deadline:
                deadline.attach(left)
                left.close()
                self.assertEqual(buffered.read(1), b"")
                with self.assertRaises(TimeoutError):
                    deadline.check()
        finally:
            left.close()
            right.close()

    def test_timer_thread_exhaustion_uses_sanitized_retryable_network_errors(self):
        with peer() as server, patch.object(threading.Timer, "start", side_effect=RuntimeError("synthetic thread limit")):
            fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                              url=f"http://127.0.0.1:{server.server_port}/fixture")
            with self.assertRaisesRegex(ValueError, "feed download failed"):
                feeds._download(fixture)
        connection_type = http.client.HTTPConnection
        with peer(kind="canary") as server, patch.object(threading.Timer, "start", side_effect=RuntimeError("synthetic thread limit")), patch.object(
                canaries.http.client, "HTTPSConnection", side_effect=lambda *_, **options: connection_type(
                    "127.0.0.1", server.server_port, timeout=options["timeout"])):
            with self.assertRaisesRegex(canaries.CanaryError, canaries.PROVIDER_ERROR):
                canaries._fetch_history("z" * 25, "b" * 32, "web")

    def test_real_https_feed_still_rejects_untrusted_certificates(self):
        with tls_peer() as (server, _):
            fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                              url=f"https://passthrough.test:{server.server_port}/fixture")
            with self.assertRaisesRegex(ValueError, "feed download failed"):
                feeds._download(fixture)
            self.assertEqual(server.requests, 0)

    def test_real_https_feed_still_refuses_redirects_without_contacting_the_target(self):
        with peer() as target, tls_peer(mode="redirect") as (server, context):
            server.redirect_target = f"http://127.0.0.1:{target.server_port}/must-not-reach"
            fixture = replace(feeds.TRACKERS["pro"], minimum=2,
                              url=f"https://passthrough.test:{server.server_port}/fixture")
            with patch("egress_guard.http_deadline.ssl.create_default_context", return_value=context):
                with self.assertRaisesRegex(ValueError, "HTTP 302"):
                    feeds._download(fixture)
            self.assertEqual(server.requests, 1)
            self.assertEqual(target.requests, 0)

    def test_feed_http_error_closes_response_without_reading_or_exposing_its_body(self):
        body = io.BytesIO(b"synthetic upstream detail that must stay private")
        error = urllib.error.HTTPError(feeds.TRACKERS["pro"].url, 503, "unavailable", {}, body)
        with patch("urllib.request.OpenerDirector.open", side_effect=error):
            with self.assertRaisesRegex(ValueError, "^feed returned HTTP 503$"):
                feeds._download(feeds.TRACKERS["pro"])
        self.assertTrue(body.closed)


if __name__ == "__main__":
    unittest.main()
