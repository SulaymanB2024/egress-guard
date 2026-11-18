"""Local HTTP boundaries exercised against a fake, non-mutating application."""
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

from egress_guard.dashboard_http import ProtectionServer, installation_token


class FakeApplication:
    def __init__(self):
        self.actions = []

    def status(self):
        return {"protection": {"state": "active"}}

    def activity(self):
        return {"events": []}

    def domain(self, host):
        return {"host": host, "decision": "allowed"}

    def action(self, value):
        self.actions.append(value)
        return {"message": "Saved"}


class DashboardHttpTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "index.html").write_text("<!doctype html><title>Protection test</title>")
        self.application = FakeApplication()
        self.key = "x" * 43
        self.server = ProtectionServer(self.application, self.key, port=0, static=root)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        supplied = {"Origin": self.server.origin, **(headers or {})}
        if body is not None:
            supplied.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=body, headers=supplied)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def login(self):
        nonce = self.server.new_bootstrap()
        status, headers, _ = self.request("POST", "/api/session", json.dumps({"token": nonce}), {"X-Mac-Guard": "1"})
        self.assertEqual(status, 200)
        return headers["Set-Cookie"].split(";", 1)[0]

    def test_data_requires_auth_and_static_does_not_leak_key(self):
        self.assertEqual(self.request("GET", "/api/status")[0], 401)
        status, headers, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn(self.key.encode(), data)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_rebinding_and_cross_site_requests_are_refused(self):
        self.assertEqual(self.request("GET", "/", headers={"Host": "attacker.invalid"})[0], 403)
        self.assertEqual(self.request("GET", "/", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.request("POST", "/api/session", "{}", {"Origin": "https://attacker.invalid"})[0], 403)

    def test_bad_and_unicode_keys_do_not_create_sessions(self):
        for value in ("wrong", "\u2603", None):
            self.assertEqual(self.request("POST", "/api/session", json.dumps({"token": value}), {"X-Mac-Guard": "1"})[0], 401)
        self.assertFalse(self.server.sessions)

    def test_mutation_needs_session_csrf_and_exact_origin(self):
        cookie = self.login()
        status, _, body = self.request("GET", "/api/status", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        csrf = json.loads(body)["csrf_token"]
        value = json.dumps({"action": "pause", "minutes": 5})
        self.assertEqual(self.request("POST", "/api/action", value, {"Cookie": cookie})[0], 403)
        self.assertEqual(self.request("POST", "/api/action", value, {"Cookie": cookie, "X-CSRF-Token": csrf, "Origin": "https://attacker.invalid"})[0], 403)
        self.assertFalse(self.application.actions)
        self.assertEqual(self.request("POST", "/api/action", value, {"Cookie": cookie, "X-CSRF-Token": csrf})[0], 200)
        self.assertEqual(self.application.actions, [{"action": "pause", "minutes": 5}])

    def test_expired_session_cannot_read_data(self):
        cookie = self.login()
        for session in self.server.sessions.values():
            session["expires"] = time.time() - 1
        self.assertEqual(self.request("GET", "/api/status", headers={"Cookie": cookie})[0], 401)

    def test_browser_bootstrap_is_one_use_and_not_the_persistent_key(self):
        status, _, challenge = self.request("GET", "/api/challenge")
        self.assertEqual(status, 200)
        challenge = json.loads(challenge)
        value = {"challenge": challenge["challenge"], "proof": self.server.proof("client", challenge["challenge"])}
        status, _, body = self.request("POST", "/api/bootstrap", json.dumps(value), {"X-Mac-Guard": "1"})
        self.assertEqual(status, 200)
        nonce = json.loads(body)["token"]
        self.assertNotEqual(nonce, self.key)
        value = json.dumps({"token": nonce})
        self.assertEqual(self.request("POST", "/api/session", value, {"X-Mac-Guard": "1"})[0], 200)
        self.assertEqual(self.request("POST", "/api/session", value, {"X-Mac-Guard": "1"})[0], 401)

    def test_permanent_key_and_reflected_server_proof_are_not_login_credentials(self):
        self.assertEqual(self.request("POST", "/api/session", json.dumps({"token": self.key}), {"X-Mac-Guard": "1"})[0], 401)
        _, _, body = self.request("GET", "/api/challenge")
        reflected = json.loads(body)
        self.assertEqual(self.request("POST", "/api/bootstrap", json.dumps(reflected), {"X-Mac-Guard": "1"})[0], 401)

    def test_expired_bootstrap_does_not_create_a_session(self):
        nonce = self.server.new_bootstrap()
        self.server.bootstraps[nonce] = time.time() - 1
        self.assertEqual(self.request("POST", "/api/session", json.dumps({"token": nonce}), {"X-Mac-Guard": "1"})[0], 401)

    def test_oversized_json_and_non_object_payloads_are_refused(self):
        self.assertEqual(self.request("POST", "/api/session", "x" * 9000)[0], 400)
        self.assertEqual(self.request("POST", "/api/session", "[]")[0], 400)

    def test_install_key_is_private_persistent_and_symlinks_rejected(self):
        state = Path(self.temporary.name) / "state"
        key = installation_token(state)
        self.assertEqual(key, installation_token(state))
        self.assertEqual((state / "dashboard-token").stat().st_mode & 0o777, 0o600)
        link = Path(self.temporary.name) / "linked-state"
        link.symlink_to(state, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            installation_token(link)


if __name__ == "__main__":
    unittest.main()
