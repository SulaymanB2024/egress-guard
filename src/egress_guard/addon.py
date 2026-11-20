"""Regular loopback proxy admission and streaming plaintext request protection."""

from __future__ import annotations

import asyncio
import json
import re

from mitmproxy import ctx, http

from egress_guard import __version__
from egress_guard.config import config_path, load_config
from egress_guard.health import policy_proof, response_proof
from egress_guard.ledger import Ledger
from egress_guard.paths import data_dir, private_dir
from egress_guard.policy import Policy, PolicyRuntime, is_loopback, normalize_host, policy_stamp

HEALTH_HOST = "egress-guard.invalid"
HEALTH_QUERY = re.compile(r"nonce=([A-Za-z0-9_-]{43})")
CREDENTIAL_HEADERS = ("Authorization", "Cookie")


class EgressGuard:
    def __init__(self) -> None:
        self.runtime: PolicyRuntime | None = None
        self.ledger: Ledger | None = None
        self._refresh_task: asyncio.Task | None = None

    @property
    def policy(self) -> Policy | None:
        return self.runtime.policy if self.runtime is not None else None

    @property
    def _block_plaintext_credentials(self) -> bool:
        policy = self.policy
        return True if policy is None else policy.block_plaintext_credentials

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
        try:
            config = load_config(self._config_path)
        except (OSError, ValueError):
            ctx.master.shutdown()
            return
        self.runtime = PolicyRuntime(self._load_policy, lambda: policy_stamp(self._config_path, self._state))
        # An invalid rule file leaves no policy: remain loopback-only and unready while retrying.
        self.runtime.poll()
        self.ledger = Ledger(self._state / "events.sqlite3", **config["logging"])
        self._refresh_task = asyncio.create_task(self._refresh())

    def configure(self, updated) -> None:
        if self._refresh_task is not None and not self._safe_options():
            self.runtime.policy = None
            ctx.master.shutdown()

    def done(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
        if self.ledger is not None:
            self.ledger.close()

    def _load_policy(self, previous: Policy | None) -> Policy:
        return Policy(load_config(self._config_path), self._state, previous)

    async def _refresh(self) -> None:
        while True:
            await asyncio.sleep(1)
            if self.policy is not None:
                self.policy.reload_controls()
            if self._safe_options():
                await asyncio.to_thread(self.runtime.poll)

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
        if self.policy is None or not self.policy.enforceable():
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

    def _health(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        path, separator, query = request.path.partition("?")
        if request.scheme != "http" or request.port != 80 or request.method != "GET" or path != "/health":
            self._deny(flow, 404, "Unknown Egress Guard endpoint.")
            return
        challenge = HEALTH_QUERY.fullmatch(query) if separator else None
        if separator and challenge is None:
            self._deny(flow, 400, "Invalid Egress Guard health challenge.")
            return
        if self._has_body(request):
            flow.kill()
            return
        ready = bool(self.policy and self.policy.ready() and self.ledger and self.ledger.ready())
        data = {"product": "egress-guard", "version": __version__, "ready": ready, "https_decryption": False}
        port = ctx.options.listen_port
        if challenge is not None and type(port) is int and self.runtime is not None:
            # Applied revision, pending and degraded state travel only with an authenticated reply.
            status = self.runtime.status()
            try:
                data["policy_proof"] = policy_proof(challenge.group(1), port, self._state, status)
                data["policy"] = status
            except (OSError, RuntimeError, ValueError):
                data.pop("policy_proof", None)
        if ready and challenge is not None:
            if type(port) is int:
                try:
                    data["proof"] = response_proof(challenge.group(1), port, self._state)
                except (OSError, RuntimeError, ValueError):
                    data["ready"] = False
            else:
                data["ready"] = False
        flow.response = http.Response.make(200 if data["ready"] else 503, json.dumps(data), {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        })

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        request.headers.pop("Proxy-Authorization", None)
        request.headers.pop("Proxy-Connection", None)
        host = normalize_host(request.host)
        if host == HEALTH_HOST:
            self._health(flow)
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
