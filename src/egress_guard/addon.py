"""Regular loopback proxy admission and streaming plaintext request protection."""

from __future__ import annotations

import asyncio
import json

from mitmproxy import ctx, http

from egress_guard import __version__
from egress_guard.config import config_path, load_config
from egress_guard.feeds import CNAME_FEEDS, THREATS, TRACKERS
from egress_guard.ledger import Ledger
from egress_guard.paths import data_dir, private_dir
from egress_guard.policy import Policy, is_loopback, normalize_host

HEALTH_HOST = "egress-guard.invalid"
CREDENTIAL_HEADERS = ("Authorization", "Cookie")


class EgressGuard:
    def __init__(self) -> None:
        self.policy: Policy | None = None
        self.ledger: Ledger | None = None
        self._refresh_task: asyncio.Task | None = None
        self._block_plaintext_credentials = True

    @staticmethod
    def _safe_options() -> bool:
        options = ctx.options
        return (
            list(options.mode) == ["regular"]
            and options.listen_host == "127.0.0.1"
            and list(options.ignore_hosts) == [".*"]
            and options.connection_strategy == "lazy"
            and not options.store_streamed_bodies
        )

    def running(self) -> None:
        if not self._safe_options():
            ctx.master.shutdown()
            return
        try:
            self._state = private_dir(data_dir())
        except (OSError, ValueError):
            ctx.master.shutdown()
            return
        self._config_path = config_path()
        self._watched = (
            self._config_path,
            self._state / "block.txt",
            self._state / "allow.txt",
            *(feed.path(self._state) for feed in (*TRACKERS.values(), THREATS, *CNAME_FEEDS)),
        )
        try:
            config = load_config(self._config_path)
        except (OSError, ValueError):
            ctx.master.shutdown()
            return
        self.policy = Policy(config, self._state)
        self._block_plaintext_credentials = config["risk"]["block_plaintext_credentials"]
        self.ledger = Ledger(self._state / "events.sqlite3", **config["logging"])
        self._refresh_task = asyncio.create_task(self._refresh(self._stamp()))

    def configure(self, updated) -> None:
        if self.policy is not None and not self._safe_options():
            self.policy = None
            ctx.master.shutdown()

    def done(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
        if self.ledger is not None:
            self.ledger.close()

    def _stamp(self) -> tuple:
        stamps = []
        for path in self._watched:
            try:
                stat = path.stat()
                stamps.append((stat.st_ino, stat.st_mtime_ns, stat.st_size))
            except OSError:
                stamps.append(None)
        return tuple(stamps)

    def _load_policy(self) -> tuple[Policy, bool]:
        config = load_config(self._config_path)
        return Policy(config, self._state), config["risk"]["block_plaintext_credentials"]

    async def _refresh(self, stamp: tuple) -> None:
        while self.policy is not None:
            await asyncio.sleep(1)
            if self.policy is None:
                return
            self.policy.reload_controls()
            current = self._stamp()
            if current != stamp:
                stamp = current
                try:
                    policy, protect_credentials = await asyncio.to_thread(self._load_policy)
                except (OSError, ValueError):
                    continue
                if self.policy is not None and (policy.ready() or not self.policy.ready()):
                    self.policy = policy
                    self._block_plaintext_credentials = protect_credentials

    @staticmethod
    def _has_body(request: http.Request) -> bool:
        return request.method != "CONNECT" and (
            request.headers.get("Content-Length", "0") != "0" or "Transfer-Encoding" in request.headers
        )

    @staticmethod
    def _deny(flow: http.HTTPFlow, status: int, text: str) -> None:
        if EgressGuard._has_body(flow.request):
            # mitmproxy otherwise buffers a refused request body to return its response.
            flow.kill()
            return
        flow.response = http.Response.make(status, text, {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "Connection": "close",
        })

    def _event(self, host: str, decision: str, source: str, transport: str) -> None:
        if self.ledger is not None:
            self.ledger.record(host, decision, source, transport)

    def _apply(self, flow: http.HTTPFlow, transport: str) -> bool:
        host = flow.request.host
        if self.policy is None or not self.policy.ready():
            self._deny(flow, 503, "Egress Guard policy unavailable.")
            return False
        decision = self.policy.decision(host)
        if decision["decision"] == "blocked":
            self._event(host, "blocked", decision["source"], transport)
            self._deny(flow, 403, "Blocked by Egress Guard.")
            return False
        self._event(host, "allowed", decision["source"], transport)
        return True

    def http_connect(self, flow: http.HTTPFlow) -> None:
        flow.request.headers.pop("Proxy-Authorization", None)
        self._apply(flow, "connect")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        request.headers.pop("Proxy-Authorization", None)
        request.headers.pop("Proxy-Connection", None)
        host = normalize_host(request.host)
        if (
            host == HEALTH_HOST and request.scheme == "http" and request.port == 80
            and request.method == "GET" and request.path == "/health"
        ):
            if self._has_body(request):
                flow.kill()
                return
            ready = bool(self.policy and self.policy.ready() and self.ledger and self.ledger.ready())
            flow.response = http.Response.make(200 if ready else 503, json.dumps({
                "product": "egress-guard",
                "version": __version__,
                "ready": ready,
                "https_decryption": False,
            }), {"Content-Type": "application/json", "Cache-Control": "no-store"})
            return
        if host is None or request.scheme != "http":
            self._deny(flow, 400, "Use a valid HTTP request target or HTTPS CONNECT tunnel.")
            return
        if self._block_plaintext_credentials and not is_loopback(host) and (
            any(header in request.headers for header in CREDENTIAL_HEADERS)
        ):
            self._event(host, "blocked", "plaintext-credentials", "http")
            self._deny(flow, 403, "Plaintext credentials blocked by Egress Guard. Use HTTPS.")
            return
        if self._apply(flow, "http"):
            request.stream = True

    def request(self, flow: http.HTTPFlow) -> None:
        trailers = flow.request.trailers
        if trailers:
            trailers.pop("Proxy-Authorization", None)
            if self._block_plaintext_credentials and not is_loopback(flow.request.host):
                for header in CREDENTIAL_HEADERS:
                    trailers.pop(header, None)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # Forward plaintext response bodies without accumulating a flow body.
        flow.response.stream = True


# Script loading has no filesystem side effects. The running hook owns startup.
addons = [EgressGuard()]
