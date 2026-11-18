"""Real loopback launcher tests; browser calls and application data are synthetic."""
from contextlib import contextmanager
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from egress_guard.config import initialize
from egress_guard.dashboard_app import open_dashboard
from egress_guard.dashboard_http import ProtectionServer, installation_token


class SyntheticApplication:
    def status(self):
        return {"protection": {"state": "active"}, "marker": "private-fixture"}


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(server, method, path, value=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    body = json.dumps(value) if value is not None else None
    try:
        connection.request(method, path, body, {
            "Origin": server.origin, "Content-Type": "application/json", **(headers or {}),
        })
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class DashboardIdentityTests(unittest.TestCase):
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

    def select_port(self, port):
        proxy = 18080 if port != 18080 else 18082
        self.configuration.write_text(f"[proxy]\nport={proxy}\ndashboard_port={port}\n")

    def test_direct_launcher_creates_one_use_bootstrap_without_sending_install_key(self):
        with running(ProtectionServer(SyntheticApplication(), self.key, port=0)) as server:
            self.select_port(server.server_port)
            with patch("egress_guard.dashboard_app.webbrowser.open", return_value=True) as browser:
                open_dashboard()
            url = browser.call_args.args[0]
            self.assertEqual(urlsplit(url).netloc, urlsplit(server.origin).netloc)
            nonce = urlsplit(url).fragment
            self.assertEqual(len(nonce), 43)
            self.assertNotEqual(nonce, self.key)
            status, session = request(server, "POST", "/api/session", {"token": nonce}, {"X-Mac-Guard": "1"})
            self.assertEqual(status, 200)
            bearer = {"Authorization": "Bearer " + session["session_token"]}
            status, data = request(server, "GET", "/api/status", headers=bearer)
            self.assertEqual((status, data["marker"]), (200, "private-fixture"))
            self.assertEqual(request(server, "POST", "/api/session", {"token": nonce}, {"X-Mac-Guard": "1"})[0], 401)

    def test_cross_port_live_relay_is_rejected_before_client_proof_or_browser_launch(self):
        forwarded = []
        with running(ProtectionServer(SyntheticApplication(), self.key, port=0)) as genuine:
            class Relay(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def forward(self):
                    forwarded.append((self.command, self.path))
                    connection = http.client.HTTPConnection("127.0.0.1", genuine.server_port, timeout=2)
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    try:
                        connection.request(self.command, self.path, body or None, {
                            "Origin": genuine.origin, "Content-Type": "application/json", "X-Mac-Guard": "1",
                        })
                        response = connection.getresponse()
                        payload = response.read()
                        self.send_response(response.status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                    finally:
                        connection.close()

                do_GET = forward
                do_POST = forward

            with running(ThreadingHTTPServer(("127.0.0.1", 0), Relay)) as relay:
                self.select_port(relay.server_port)
                rejected = False
                with patch("egress_guard.dashboard_app.webbrowser.open", return_value=True) as browser:
                    try:
                        open_dashboard()
                    except ValueError:
                        rejected = True
                # If the launcher accepted the relay, demonstrate the consequence
                # using the bootstrap the relay sees, without opening any browser.
                compromised_status = None
                if browser.called:
                    token = urlsplit(browser.call_args.args[0]).fragment
                    status, session = request(genuine, "POST", "/api/session", {"token": token}, {"X-Mac-Guard": "1"})
                    if status == 200:
                        compromised_status, _ = request(genuine, "GET", "/api/status", headers={
                            "Authorization": "Bearer " + session["session_token"],
                        })
                self.assertIsNone(compromised_status, "Cross-port relay minted an authenticated session and read private fixture status")
                self.assertTrue(rejected)
                browser.assert_not_called()
                self.assertEqual([method for method, _ in forwarded], ["GET"])
                self.assertFalse(genuine.bootstraps)
                self.assertFalse(genuine.sessions)

    def test_legacy_origin_free_proofs_cannot_downgrade_either_role(self):
        client = "z" * 43
        def legacy(role, nonce, supplied_client):
            message = f"egress-guard/v1:{role}:{supplied_client}:{nonce}".encode()
            return hmac.new(self.key.encode(), message, hashlib.sha256).hexdigest()

        with running(ProtectionServer(SyntheticApplication(), self.key, port=0)) as server:
            challenge = server.new_challenge(client)["challenge"]
            status, _ = request(server, "POST", "/api/bootstrap", {
                "challenge": challenge, "client": client, "proof": legacy("client", challenge, client),
            }, {"X-Mac-Guard": "1"})
            self.assertEqual(status, 401)
            self.select_port(server.server_port)
            with patch.object(server, "proof", side_effect=legacy), patch(
                    "egress_guard.dashboard_app.webbrowser.open", return_value=True) as browser:
                with self.assertRaises(ValueError):
                    open_dashboard()
            browser.assert_not_called()
            self.assertFalse(server.bootstraps)
            self.assertFalse(server.sessions)


if __name__ == "__main__":
    unittest.main()
