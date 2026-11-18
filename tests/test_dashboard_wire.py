"""Malformed control requests are rejected through a real isolated TCP listener."""
import json
import socket
import threading
import unittest

from egress_guard.dashboard_http import ProtectionServer


class NoMutationApplication:
    def __init__(self):
        self.actions = []

    def action(self, value):
        self.actions.append(value)
        return {"message": "fixture"}


class DashboardWireTests(unittest.TestCase):
    def setUp(self):
        self.application = NoMutationApplication()
        self.server = ProtectionServer(self.application, "q" * 43, port=0)
        self.errors = []
        self.server.handle_error = lambda *_: self.errors.append("worker error")
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def raw(self, method, target, body=b"", extra=(), *, auto_length=True):
        host = f"127.0.0.1:{self.server.server_port}"
        headers = [f"{method} {target} HTTP/1.1", "Host: " + host,
                   "Origin: http://" + host, "Content-Type: application/json", "Connection: close"]
        if auto_length:
            headers.append(f"Content-Length: {len(body)}")
        headers.extend(extra)
        payload = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2) as connection:
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            result = bytearray()
            while data := connection.recv(8192):
                result.extend(data)
        return bytes(result)

    def test_malformed_targets_and_query_overflow_return_client_errors(self):
        for target in ("http://[invalid/", "/api/challenge?client=" + "z" * 43 + "&extra=1"):
            with self.subTest(target=target):
                response = self.raw("GET", target)
                self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertFalse(self.errors)

    def test_deeply_nested_json_is_a_bounded_client_error(self):
        body = b'{"token":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}"
        response = self.raw("POST", "/api/session", body)
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertFalse(self.errors)
        self.assertFalse(self.server.sessions)

    def test_ambiguous_body_framing_is_refused_before_authentication(self):
        fixtures = [
            ("conflicting lengths", ("Content-Length: 2", "Content-Length: 200")),
            ("duplicate lengths", ("Content-Length: 2", "Content-Length: 2")),
            ("signed length", ("Content-Length: +2",)),
            ("empty transfer encoding", ("Content-Length: 2", "Transfer-Encoding:")),
            ("transfer encoding plus length", ("Content-Length: 2", "Transfer-Encoding: chunked")),
        ]
        for label, headers in fixtures:
            with self.subTest(label=label):
                response = self.raw("POST", "/api/session", b"{}", headers, auto_length=False)
                self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertFalse(self.errors)
        self.assertFalse(self.server.sessions)
        self.assertFalse(self.application.actions)

    def test_duplicate_json_fields_cannot_consume_a_bootstrap(self):
        nonce = self.server.new_bootstrap()
        body = ('{"token":"wrong","token":"' + nonce + '"}').encode("ascii")
        response = self.raw("POST", "/api/session", body, ("X-Mac-Guard: 1",))
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertIn(nonce, self.server.bootstraps)
        self.assertFalse(self.server.sessions)

    def test_nonfinite_numbers_are_not_accepted_as_json(self):
        for value in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(value=value):
                response = self.raw("POST", "/api/session", b'{"token":' + value + b"}")
                self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertFalse(self.server.sessions)

    def test_short_body_cannot_consume_a_bootstrap(self):
        nonce = self.server.new_bootstrap()
        body = json.dumps({"token": nonce}).encode("utf-8")
        response = self.raw("POST", "/api/session", body,
                            (f"Content-Length: {len(body) + 10}", "X-Mac-Guard: 1"), auto_length=False)
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertIn(nonce, self.server.bootstraps)
        self.assertFalse(self.server.sessions)

    def test_escaped_surrogate_proof_is_refused_without_a_worker_error(self):
        client = "z" * 43
        nonce = self.server.new_challenge(client)["challenge"]
        body = json.dumps({"challenge": nonce, "client": client, "proof": "\ud800" * 64}).encode("ascii")
        response = self.raw("POST", "/api/bootstrap", body, ("X-Mac-Guard: 1",))
        self.assertTrue(response.startswith(b"HTTP/1.1 401 "), repr(response[:80]))
        self.assertFalse(self.errors)
        self.assertFalse(self.server.bootstraps)

    def test_malformed_post_target_is_refused_before_consuming_a_bootstrap(self):
        nonce = self.server.new_bootstrap()
        response = self.raw("POST", "http://[invalid/", json.dumps({"token": nonce}).encode(), ("X-Mac-Guard: 1",))
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), repr(response[:80]))
        self.assertIn(nonce, self.server.bootstraps)
        self.assertFalse(self.errors)


if __name__ == "__main__":
    unittest.main()
