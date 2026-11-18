"""Authenticated, loopback-only control surface for this Mac's protection."""
from __future__ import annotations

import argparse
import hmac
import hashlib
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import plistlib
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
from .paths import data_dir
STATE = data_dir()
PYTHON = Path(sys.executable)
LABEL = "org.egressguard.dashboard"
AGENT = Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
PORT = 18081
COOKIE = "EgressGuardSession"
SESSION_SECONDS = 8 * 3600
MAX_BODY = 8192


def private_write(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def installation_token(state: Path = STATE) -> str:
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("The protection state directory must be private to this user")
    path = state / "dashboard-token"
    if not path.exists():
        value = secrets.token_urlsafe(32)
        # Exclusive creation avoids replacing a token another local process just made.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w") as handle:
                handle.write(value)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("The dashboard key must be a private regular file")
    value = path.read_text().strip()
    if len(value) != 43 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value):
        raise RuntimeError("The dashboard key is invalid")
    return value


class ProtectionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, application, token: str, port: int = PORT, static: Path | None = None):
        self.application = application
        self.installation_key = token
        self.static = static or HERE / "web"
        self.sessions: dict[str, dict] = {}
        self.bootstraps: dict[str, float] = {}
        self.challenges: dict[str, float] = {}
        self.session_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def new_session(self):
        with self.session_lock:
            now = time.time()
            self.sessions = {key: value for key, value in self.sessions.items() if value["expires"] > now}
            if len(self.sessions) >= 64:
                oldest = min(self.sessions, key=lambda key: self.sessions[key]["expires"])
                self.sessions.pop(oldest)
            key = secrets.token_urlsafe(32)
            self.sessions[key] = {"csrf": secrets.token_urlsafe(32), "expires": now + SESSION_SECONDS}
            return key

    def new_challenge(self):
        with self.session_lock:
            now = time.time()
            self.challenges = {key: expiry for key, expiry in self.challenges.items() if expiry > now}
            if len(self.challenges) >= 64:
                self.challenges.pop(next(iter(self.challenges)))
            nonce = secrets.token_urlsafe(32)
            self.challenges[nonce] = now + 60
            return {"challenge": nonce, "proof": self.proof("server", nonce)}

    def proof(self, role, nonce):
        return hmac.new(self.installation_key.encode(), (role + ":" + nonce).encode(), hashlib.sha256).hexdigest()

    def new_bootstrap(self):
        with self.session_lock:
            now = time.time()
            self.bootstraps = {key: expiry for key, expiry in self.bootstraps.items() if expiry > now}
            if len(self.bootstraps) >= 64:
                self.bootstraps.pop(next(iter(self.bootstraps)))
            nonce = secrets.token_urlsafe(32)
            self.bootstraps[nonce] = now + 60
            return nonce

    def consume_bootstrap(self, token):
        with self.session_lock:
            return self.bootstraps.pop(token, 0) > time.time()


class Handler(BaseHTTPRequestHandler):
    server_version = "EgressGuard"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        # Never record authentication material, user domains or full URLs.
        return

    def reply(self, code, payload=None, *, mime="application/json", headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def context_ok(self, *, post=False):
        expected = self.server.origin
        if len(self.headers.get_all("Host", [])) != 1 or self.headers.get("Host") != urlsplit(expected).netloc:
            self.reply(403, {"message": "Use the local Egress Guard address"})
            return False
        origin = self.headers.get("Origin")
        if (post and origin != expected) or (origin and origin != expected):
            self.reply(403, {"message": "This action must come from Egress Guard"})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.reply(403, {"message": "Cross-site requests are not allowed"})
            return False
        return True

    def session(self):
        try:
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            value = jar[COOKIE].value
        except (cookies.CookieError, KeyError):
            return None
        with self.server.session_lock:
            session = self.server.sessions.get(value)
            if session and session["expires"] > time.time():
                return session
        return None

    def require_session(self, *, csrf=False):
        session = self.session()
        if not session:
            self.reply(401, {"message": "Open the Egress Guard launcher to sign in locally"})
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", "").encode(), session["csrf"].encode()):
            self.reply(403, {"message": "Refresh the dashboard before changing protection"})
            return None
        return session

    def do_GET(self):
        if not self.context_ok():
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/api/challenge":
            self.reply(200, self.server.new_challenge())
            return
        if parsed.path.startswith("/api/"):
            session = self.require_session()
            if session is None:
                return
            try:
                if parsed.path == "/api/status":
                    data = {**self.server.application.status(), "csrf_token": session["csrf"]}
                elif parsed.path == "/api/activity":
                    data = self.server.application.activity()
                elif parsed.path == "/api/domain":
                    values = parse_qs(parsed.query, max_num_fields=2)
                    data = self.server.application.domain(values.get("host", [""])[0])
                else:
                    self.reply(404, {"message": "Unknown control"})
                    return
                self.reply(200, data)
            except ValueError as error:
                self.reply(400, {"message": str(error)[:240]})
            except Exception:
                self.reply(503, {"message": "A local protection service could not be read. Try again shortly."})
            return
        routes = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/app.css": ("app.css", "text/css; charset=utf-8")}
        if parsed.path not in routes:
            self.reply(404, {"message": "Not found"})
            return
        filename, mime = routes[parsed.path]
        try:
            self.reply(200, (self.server.static / filename).read_bytes(), mime=mime)
        except OSError:
            self.reply(503, {"message": "The local dashboard is not ready"})

    def read_body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Streaming control requests are not supported")
        length = int(self.headers.get("Content-Length", "-1"))
        if not 0 <= length <= MAX_BODY:
            raise ValueError("The control request is too large or has no size")
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("Send a JSON control request")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("Invalid control request")
        return value

    def do_POST(self):
        if not self.context_ok(post=True):
            self.close_connection = True
            return
        path = urlsplit(self.path).path
        try:
            data = self.read_body()
        except (ValueError, OSError):
            self.reply(400, {"message": "Invalid or oversized control request"})
            self.close_connection = True
            return
        if path == "/api/bootstrap":
            nonce, proof = data.get("challenge"), data.get("proof")
            valid = False
            if isinstance(nonce, str) and isinstance(proof, str) and self.headers.get("X-Mac-Guard") == "1":
                with self.server.session_lock:
                    valid = (self.server.challenges.pop(nonce, 0) > time.time()
                             and hmac.compare_digest(proof.encode(), self.server.proof("client", nonce).encode()))
            if not valid:
                self.reply(401, {"message": "Open the Egress Guard launcher to connect locally"})
                return
            self.reply(200, {"token": self.server.new_bootstrap()})
            return
        if path == "/api/session":
            token = data.get("token")
            if (self.headers.get("X-Mac-Guard") != "1" or not isinstance(token, str)
                    or not self.server.consume_bootstrap(token)):
                self.reply(401, {"message": "Open the Egress Guard launcher to sign in locally"})
                return
            key = self.server.new_session()
            self.reply(200, {"message": "Connected to this Mac"}, headers={
                "Set-Cookie": f"{COOKIE}={key}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}",
            })
            return
        if path != "/api/action":
            self.reply(404, {"message": "Unknown control"})
            return
        if self.require_session(csrf=True) is None:
            return
        try:
            result = self.server.application.action(data)
            self.reply(200, result)
        except ValueError as error:
            self.reply(400, {"message": str(error)[:240]})
        except PermissionError:
            self.reply(403, {"message": "That exception would weaken malware or local protection"})
        except Exception:
            self.reply(503, {"message": "The change could not be saved. Protection remains unchanged."})

