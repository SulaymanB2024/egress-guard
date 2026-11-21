"""Regular loopback proxy admission and streaming plaintext request protection."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable

from mitmproxy import connection, ctx, http
from mitmproxy.net.tls import starts_like_tls_record
from mitmproxy.proxy import commands, events, layer
from mitmproxy.proxy.layers.tcp import TCPLayer
from mitmproxy.proxy.layers.tls import parse_client_hello

from egress_guard import __version__
from egress_guard.config import config_path, load_config
from egress_guard.health import policy_proof, response_proof
from egress_guard.ledger import Ledger
from egress_guard.paths import data_dir, private_dir
from egress_guard.policy import Policy, PolicyRuntime, is_loopback, normalize_host, policy_stamp

HEALTH_HOST = "egress-guard.invalid"
HEALTH_QUERY = re.compile(r"nonce=([A-Za-z0-9_-]{43})")
CREDENTIAL_HEADERS = ("Authorization", "Cookie")
# A ClientHello, even with post-quantum key shares, fits well inside these bounds.
MAX_CLIENT_HELLO_BYTES = 32 * 1024
MAX_CLIENT_HELLO_READS = 32


class TunnelGuard(layer.Layer):
    """Inspect a bounded initial ClientHello before starting an opaque TCP relay.

    Own the protocol decision even when the first write has only one or two bytes:
    mitmproxy's default classifier treats such short writes as non-TLS. Returning
    from ``next_layer`` alone would let that classifier relay a fragmented hello.
    No TLS keys, decrypted contents or new TCP-flow history are created here.
    """

    def __init__(self, context, *, require_tls: bool, admit: Callable[[str | None], bool],
                 invalid: Callable[[], None]) -> None:
        super().__init__(context)
        self._require_tls = require_tls
        self._admit = admit
        self._invalid = invalid
        self._buffer = bytearray()
        self._reads = 0
        self._closed = False

    def _refuse(self, *, invalid: bool = False):
        self._buffer.clear()
        self._closed = True
        if invalid:
            self._invalid()
        yield commands.CloseConnection(self.context.client)

    def _relay(self, remainder: bytes):
        data = bytes(self._buffer) + remainder
        self._buffer.clear()
        child = TCPLayer(self.context, ignore=True)
        self._handle_event = child.handle_event
        yield from child.handle_event(events.Start())
        yield from child.handle_event(events.DataReceived(self.context.client, data))

    def _handle_event(self, event):
        if self._closed or isinstance(event, events.Start):
            return
        if isinstance(event, events.ConnectionClosed):
            yield from self._refuse()
            return
        if not isinstance(event, events.DataReceived) or event.connection != self.context.client:
            return
        self._reads += 1
        room = MAX_CLIENT_HELLO_BYTES - len(self._buffer)
        self._buffer.extend(event.data[:room])
        remainder = event.data[room:]
        data = bytes(self._buffer)
        # A prefix that could become TLS must stay here, including a one-byte write.
        possible_tls = (not data or (data[0] == 0x16 and (
            len(data) < 2 or (data[1] == 0x03 and (len(data) < 3 or data[2] <= 0x03)))))
        if not possible_tls:
            if self._require_tls:
                yield from self._refuse(invalid=True)
            elif self._admit(None):
                yield from self._relay(remainder)
            else:
                yield from self._refuse()
            return
        try:
            hello = parse_client_hello(data) if starts_like_tls_record(data) else None
            # The parser strips the handshake type. Do not mistake a differently
            # typed message with a ClientHello-shaped body for a ClientHello.
            if len(data) >= 6 and data[5] != 1:
                raise ValueError("Expected ClientHello")
            sni = hello.sni if hello is not None else None
            if hello is not None:
                sni_extensions = sum(kind == 0 for kind, _body in hello.extensions)
                if sni_extensions > 1 or (sni_extensions and sni is None):
                    raise ValueError("Invalid or ambiguous server name")
        except ValueError:
            yield from self._refuse(invalid=True)
            return
        if hello is None:
            if remainder or len(data) >= MAX_CLIENT_HELLO_BYTES or self._reads >= MAX_CLIENT_HELLO_READS:
                yield from self._refuse(invalid=True)
            return
        if self._admit(sni):
            yield from self._relay(remainder)
        else:
            yield from self._refuse()


class EgressGuard:
    def __init__(self) -> None:
        self.runtime: PolicyRuntime | None = None
        self.ledger: Ledger | None = None
        self._refresh_task: asyncio.Task | None = None
        # Admitted CONNECT tunnels awaiting their first client bytes: client id -> authority.
        self._tunnels: dict[str, tuple[str, int]] = {}

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
        self._startup_proxy = dict(config["proxy"])
        self.ledger = Ledger(self._state / "events.sqlite3", **config["logging"])
        self.runtime = PolicyRuntime(self._load_policy, lambda: policy_stamp(self._config_path, self._state),
                                     apply=self._apply_runtime_settings)
        # An invalid rule file leaves no policy: remain loopback-only and unready while retrying.
        self.runtime.poll()
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

    def _apply_runtime_settings(self, candidate: Policy) -> None:
        if self.ledger is None or not self.ledger.reconfigure(**candidate.logging):
            raise ValueError("History settings are waiting for the ledger writer to acknowledge them")
        if candidate.proxy != self._startup_proxy:
            raise ValueError("Changed listening ports require restarting the proxy and dashboard")

    async def _refresh(self) -> None:
        while True:
            await asyncio.sleep(1)
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
        decision = self.policy.decision(host, flow.request.port)
        if decision["decision"] == "blocked":
            self._event(host, "blocked", decision["source"], transport)
            self._deny(flow, 403, "Blocked by Egress Guard.")
            return False
        self._event(host, "allowed", decision["source"], transport)
        return True

    def http_connect(self, flow: http.HTTPFlow) -> None:
        flow.request.headers.pop("Proxy-Authorization", None)
        self._apply(flow, "connect")

    def http_connected(self, flow: http.HTTPFlow) -> None:
        host = normalize_host(flow.request.host)
        if host is not None:
            self._tunnels[flow.client_conn.id] = (host, flow.request.port)

    def _admit_tunnel(self, host: str, port: int, sni: str | None) -> bool:
        # Recheck the original authority at the handshake boundary as well: a grant
        # may have expired, or the live policy may have changed since CONNECT.
        policy = self.policy
        if policy is None or not policy.enforceable():
            self._event(host, "blocked", "not-ready", "connect")
            return False
        for candidate in dict.fromkeys((host, sni)):
            if candidate is None:
                continue
            decision = policy.decision(candidate, port)
            if decision["decision"] == "blocked":
                self._event(candidate, "blocked", decision["source"], "connect")
                return False
        return True

    def next_layer(self, nextlayer: layer.NextLayer) -> None:
        # Scripts run before mitmproxy's default next-layer classifier. Keep the entire
        # admission decision in our own bounded layer, then relay original TLS bytes.
        if nextlayer.layer is not None:
            return
        authority = self._tunnels.pop(nextlayer.context.client.id, None)
        if authority is not None:
            host, port = authority
            nextlayer.layer = TunnelGuard(
                nextlayer.context,
                require_tls=self._block_plaintext_credentials and not is_loopback(host),
                admit=lambda sni: self._admit_tunnel(host, port, sni),
                invalid=lambda: self._event(host, "blocked", "non-tls-tunnel", "connect"),
            )

    def client_disconnected(self, client: connection.Client) -> None:
        self._tunnels.pop(client.id, None)

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
            status["logging"] = self.ledger.status() if self.ledger is not None else None
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
