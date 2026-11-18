"""Real local status and narrowly scoped, temporary filtering controls."""
from datetime import datetime, timezone
import json
import hashlib
import hmac
import http.client
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import secrets
from urllib.parse import quote
import webbrowser

from .config import config_path, initialize, load_config
from .feeds import feed_status, dns_name, update_feeds
from .health import proxy_health
from .paths import atomic_private, data_dir, private_dir
from .policy import Policy


def iso(value=None):
    return datetime.fromtimestamp(value if value is not None else time.time(), timezone.utc).isoformat()


class Application:
    def __init__(self, state=None, configuration=None):
        self.state = private_dir(state or data_dir())
        self.config_path = configuration or config_path()
        self.lock = threading.RLock()
        self._policy = None
        self._stamp = None
        self.refreshing = False
        from .canaries import CanaryMonitor
        self.canaries = CanaryMonitor(self.state)

    def policy(self):
        paths = [self.config_path, self.state / "block.txt", self.state / "allow.txt",
                 *sorted((self.state / "blocklists").glob("*"))]
        stamp = tuple((str(path), path.stat().st_mtime_ns, path.stat().st_size) for path in paths if path.is_file())
        with self.lock:
            if self._policy is None or stamp != self._stamp:
                self._policy = Policy(load_config(self.config_path), self.state)
                self._stamp = stamp
            self._policy.reload_controls()
            return self._policy

    def status(self):
        config = load_config(self.config_path)
        policy = self.policy()
        healthy = proxy_health(config["proxy"]["port"], self.state)["ready"]
        pause = self._read("filter-controls.json").get("tracker_pause_until", 0)
        paused = type(pause) in (int, float) and time.time() < pause <= time.time() + 86400
        ready = healthy and policy.ready()
        state = "paused" if paused and ready else "active" if ready else "degraded"
        feeds = feed_status(self.state, config)
        exceptions = self._read("tracker-exceptions.json")
        targets = self.canaries.status()
        return {
            "checked_at": iso(),
            "protection": {"state": state,
                "message": "Ad filtering is paused; threat filtering stays active." if paused and ready else
                           "Verified local filters are active for applications using this proxy." if ready else
                           "Start the proxy, refresh filters, and configure individual applications to use it.",
                "pause_expires_at": iso(pause) if paused else None},
            "proxies": [{"name": "Loopback filtering proxy", "state": "active" if healthy else "degraded",
                         "detail": f"127.0.0.1:{config['proxy']['port']} · original HTTPS certificates"}],
            "filters": [{"name": item["name"], "state": "active" if item["status"] == "current" else "degraded",
                         "detail": item.get("error") or item["status"], "updated_at": item.get("updated_at"),
                         "entries": item.get("entries", 0)} for item in feeds],
            "canaries": [{"name": item.get("label", "Canary"), "state": "degraded" if item.get("error") or item.get("history_truncated") else
                          "active" if item.get("last_success") else "unknown",
                          "detail": item.get("error") or ("History exceeded the 1,024-event polling window; older events may be missed."
                                     if item.get("history_truncated") else "History monitored; alerts delivered locally on macOS."),
                          "checked_at": iso(item["last_success"]) if item.get("last_success") else None} for item in targets]
                         or [{"name": "No canaries registered", "state": "disabled",
                              "detail": "Optional: import a Thinkst token to enable local alerts."}],
            "maintenance": [{"name": "Client routing", "state": "unknown",
                             "detail": "Configure individual clients for this loopback proxy. Automatic system-wide activation is withheld in this alpha; inspection and receipt-based recovery remain available."}],
            "controls": {"pause_minutes": [5, 15, 30], "allow_minutes": [5, 15, 30],
                         "resume": paused, "remove_allow": True, "refresh_filters": not self.refreshing,
                         "block": True, "unblock": True, "pause_canaries": False, "resume_canaries": False},
            "temporary_allows": [{"host": host, "expires_at": iso(expiry)} for host, expiry in exceptions.items()
                                  if dns_name(host) and type(expiry) in (int, float) and time.time() < expiry <= time.time() + 86400],
        }

    def activity(self):
        path = self.state / "events.sqlite3"
        events = []
        if path.is_file() and not path.is_symlink():
            try:
                with sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=0.25) as connection:
                    rows = connection.execute("SELECT ts,host,decision,source FROM events ORDER BY id DESC LIMIT 50").fetchall()
                    events = [{"at": iso(row[0]), "host": row[1], "decision": row[2], "reason": row[3]} for row in rows]
            except sqlite3.Error:
                return {"events": [], "limit": 50, "message": "Local activity is temporarily unavailable"}
        return {"events": events, "limit": 50}

    def domain(self, host):
        host = self._host(host)
        decision = self.policy().decision(host)
        manual = self._manual_rules()
        return {**decision, "host": host, "reason": decision.get("source", "unknown"),
                "can_block": host not in manual and host not in load_config(self.config_path)["block"]["dashboard_hosts"] and host != "canarytokens.org",
                "can_unblock": host in manual}

    def _read(self, name):
        path = self.state / name
        if not path.exists():
            return {}
        if path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError("A local control file is invalid")
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("A local control file is invalid")
        return value

    def _write(self, name, value):
        atomic_private(self.state / name, json.dumps(value, separators=(",", ":")).encode())

    @staticmethod
    def _host(value):
        host = dns_name(value)
        if not host or "." not in host or host.endswith((".local", ".localhost")):
            raise ValueError("Enter a public hostname without a URL, port or path")
        return host

    def _manual_rules(self):
        path = self.state / "block.txt"
        if path.is_symlink() or (path.exists() and path.stat().st_size > 65536):
            raise ValueError("The local block list is invalid")
        text = path.read_text() if path.exists() else ""
        return {name for line in text.splitlines() if (name := dns_name(line.split("#", 1)[0].strip()))}

    def action(self, request):
        with self.lock:
            action = request.get("action")
            if action in {"pause", "resume"}:
                minutes = request.get("minutes", 15)
                if type(minutes) is not int or minutes not in (5, 15, 30):
                    raise ValueError("Choose a pause of 5, 15 or 30 minutes")
                self._write("filter-controls.json", {"tracker_pause_until": time.time() + minutes * 60 if action == "pause" else 0})
            elif action in {"allow", "remove_allow"}:
                host = self._host(request.get("host"))
                values = self._read("tracker-exceptions.json")
                values = {name: expiry for name, expiry in values.items() if type(expiry) in (int, float) and expiry > time.time()}
                if action == "allow":
                    if not self.policy().decision(host).get("can_allow"):
                        raise PermissionError("Threat and manual block rules cannot be bypassed here")
                    minutes = request.get("minutes", 15)
                    if type(minutes) is not int or minutes not in (5, 15, 30) or len(values) >= 200:
                        raise ValueError("Choose a bounded temporary exception")
                    values[host] = time.time() + minutes * 60
                else:
                    values.pop(host, None)
                self._write("tracker-exceptions.json", values)
            elif action in {"block", "unblock"}:
                host = self._host(request.get("host"))
                if action == "block" and not self.domain(host)["can_block"]:
                    raise ValueError("That reporting or security control hostname is protected")
                path = self.state / "block.txt"
                rules = self._manual_rules()
                if action == "block" and len(rules) >= 2000:
                    raise ValueError("The local block list is full")
                lines = path.read_text().splitlines() if path.exists() else []
                if action == "block" and host not in rules:
                    lines.append(host)
                elif action == "unblock":
                    lines = [line for line in lines if dns_name(line.split("#", 1)[0].strip()) != host]
                encoded = ("\n".join(lines) + "\n").encode()
                if len(encoded) > 65536:
                    raise ValueError("The local block list has reached its byte limit; existing rules were preserved")
                atomic_private(path, encoded)
                self._stamp = None
            elif action == "refresh_filters":
                if self.refreshing:
                    raise ValueError("A filter update is already running")
                self.refreshing = True
                def refresh():
                    try:
                        update_feeds(self.state, load_config(self.config_path))
                    finally:
                        self.refreshing = False
                threading.Thread(target=refresh, daemon=True).start()
            else:
                raise ValueError("Unknown protection control")
        return {"message": "Filter update started" if action == "refresh_filters" else "Protection setting saved"}


def serve():
    initialize()
    from .dashboard_http import ProtectionServer, installation_token
    application = Application()
    stopping = threading.Event()
    from .canaries import supports_native_notifications
    worker = threading.Thread(target=application.canaries.run, args=(stopping,), daemon=True) if supports_native_notifications() else None
    if worker:
        worker.start()
    try:
        with ProtectionServer(application, installation_token(data_dir()), port=load_config()["proxy"]["dashboard_port"]) as server:
            server.serve_forever(poll_interval=0.5)
    finally:
        stopping.set()
        if worker:
            worker.join(timeout=2)


def open_dashboard():
    initialize()
    from .dashboard_http import installation_token
    port = load_config()["proxy"]["dashboard_port"]
    key = installation_token(data_dir())
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        origin = f"http://127.0.0.1:{port}"
        client = secrets.token_urlsafe(32)
        connection.request("GET", "/api/challenge?client=" + client)
        response = connection.getresponse()
        challenge = json.loads(response.read(4096))
        nonce = challenge.get("challenge")
        proof = challenge.get("proof")
        if (response.status != 200 or not isinstance(nonce, str) or len(nonce) != 43
                or not isinstance(proof, str) or len(proof) != 64):
            raise ValueError("Start the dashboard before opening its controls")
        expected = hmac.new(key.encode(), f"egress-guard/v2:server:{origin}:{client}:{nonce}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(proof.encode(), expected.encode()):
            raise ValueError("The local service could not prove its identity")
        client_proof = hmac.new(key.encode(), f"egress-guard/v2:client:{origin}:{client}:{nonce}".encode(), hashlib.sha256).hexdigest()
        connection.request("POST", "/api/bootstrap", json.dumps({"challenge": nonce, "client": client, "proof": client_proof}),
                           {"Origin": origin, "Content-Type": "application/json", "X-Mac-Guard": "1"})
        response = connection.getresponse()
        result = json.loads(response.read(4096))
        if response.status != 200 or not isinstance(result.get("token"), str) or len(result["token"]) != 43:
            raise ValueError("The local connection could not be established")
        url = f"{origin}/#{result['token']}"
    except (OSError, ValueError, http.client.HTTPException):
        raise ValueError("Start a healthy Egress Guard dashboard before opening its controls") from None
    finally:
        connection.close()
    if not webbrowser.open(url):
        raise RuntimeError("Start the dashboard, then open it with this command in your desktop session")
