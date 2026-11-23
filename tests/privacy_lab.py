"""Controlled loopback collector and real proxy for the optional browser lab.

Only synthetic .test hosts are routed. No SDK is downloaded, no global resolver
or trust setting is changed, and the fixture retains only issued-format synthetic
identifiers and bounded metadata. This is test infrastructure, not a sandbox.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from contextlib import AbstractContextManager
import datetime as dt
from hashlib import sha1, sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

from privacy_accounting import CHANNELS as BYTE_CHANNELS, ConsumedReader, channel as byte_channel, framed_snapshot

ROOT = Path(__file__).resolve().parents[1]
HOSTS = ("publisher.test", "shop.test", "tracker.test", "alias.test", "allowed.test", "blocked.test")
HINT_HEADERS = ("sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-form-factors", "sec-ch-ua-full-version",
                "sec-ch-ua-full-version-list", "sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-wow64")
IDENTIFIER = re.compile(rb"eglab-id-[0-9a-f]{24}")
VISIT = re.compile(r"[0-9a-f]{24}\Z")
CASES = frozenset({"ga4", "opaque", "third-party", "image", "worker", "service-worker", "cart", "headers", "socket", "deferred"})
MAX_BODY = 8192
MAX_EVENTS = 8192
EXISTING_POLICY = "camera=(), microphone=(), geolocation=()"
POLICIES = {"absent": None, "existing": EXISTING_POLICY, "malformed": "camera=("}
WORKER_PROBE = '''async function probe(){
let returnedHighEntropyKeys=null;
try{if(navigator.userAgentData?.getHighEntropyValues){const values=await navigator.userAgentData.getHighEntropyValues(["architecture","bitness","formFactors","fullVersionList","model","platformVersion","uaFullVersion","wow64"]);returnedHighEntropyKeys=Object.keys(values).filter(k=>["brands","mobile","platform","architecture","bitness","formFactors","fullVersionList","model","platformVersion","uaFullVersion","wow64"].includes(k)).sort();}}catch{}
return {gpcPresent:"globalPrivacyControl" in navigator,gpc:typeof navigator.globalPrivacyControl==="boolean"?navigator.globalPrivacyControl:null,returnedHighEntropyKeys};}
'''


def synthetic_id(subject: int) -> str:
    if type(subject) is not int or not 0 <= subject < 256:
        raise ValueError("Synthetic subject must be an integer in [0, 255]")
    return "eglab-id-" + sha256(f"egress-guard-lab-subject-{subject}".encode()).hexdigest()[:24]


def exact_linkability(events: list[dict], visits: dict[str, dict], *, case: str | None = None) -> dict:
    """Exact-token attacker; ground truth never participates in its decision.

    Score every cross-site pair, including visits with NO observation. Dropping
    empty visits would select on successful collection and inflate the result.
    Only a synthetic identifier actually received by the collector is a feature.
    This is one channel-specific attacker, not a population anonymity metric.
    """
    if not isinstance(visits, dict) or not 4 <= len(visits) <= 512:
        raise ValueError("Need a bounded multi-identity, two-site ground truth")
    sites: dict[str, list[str]] = defaultdict(list)
    subjects: dict[str, set] = defaultdict(set)
    for visit, truth in visits.items():
        if not isinstance(visit, str) or VISIT.fullmatch(visit) is None or set(truth) != {"subject", "site"}:
            raise ValueError("Invalid synthetic visit ground truth")
        if type(truth["subject"]) is not int or not 0 <= truth["subject"] < 256 or truth["site"] not in HOSTS[:2]:
            raise ValueError("Invalid subject or site")
        sites[truth["site"]].append(visit)
        if truth["subject"] in subjects[truth["site"]]:
            raise ValueError("Each subject must have one visit per site")
        subjects[truth["site"]].add(truth["subject"])
    if set(sites) != set(HOSTS[:2]) or len(subjects[HOSTS[0]]) < 2 or subjects[HOSTS[0]] != subjects[HOSTS[1]]:
        raise ValueError("The two sites need the same multi-identity cohort")
    if case is not None and case not in CASES:
        raise ValueError("Unknown channel")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("Invalid bounded events")
    observed = {visit: set() for visit in visits}
    for event in events:
        if event.get("visit") not in visits or (case is not None and event.get("case") != case):
            continue
        tokens = event.get("identifiers")
        if not isinstance(tokens, list) or len(tokens) > 128:
            raise ValueError("Invalid observed identifier list")
        for token in tokens:
            if not isinstance(token, str) or IDENTIFIER.fullmatch(token.encode("ascii", errors="replace")) is None:
                raise ValueError("Only synthetic identifiers are accepted")
            observed[event["visit"]].add(token)
    true_matches = false_matches = positive_pairs = negative_pairs = 0
    for left in sites[HOSTS[0]]:
        for right in sites[HOSTS[1]]:
            # The attacker only sees the two observed token sets.
            predicted = bool(observed[left] & observed[right])
            same = visits[left]["subject"] == visits[right]["subject"]
            positive_pairs += same
            negative_pairs += not same
            true_matches += predicted and same
            false_matches += predicted and not same
    fpr = false_matches / negative_pairs
    return {"attacker": "any-exact-observed-synthetic-token", "threshold": 1,
            "threshold_chosen_from_ground_truth": False, "channel": case or "all",
            "subjects": len(subjects[HOSTS[0]]), "positive_pairs": positive_pairs, "negative_pairs": negative_pairs,
            "true_matches": true_matches, "false_matches": false_matches,
            "true_match_rate": true_matches / positive_pairs, "false_match_rate": fpr,
            "empirical_false_match_ceiling": 0.01, "ceiling_met_on_this_cohort": fpr <= 0.01,
            "visits_without_observed_identifier": sum(not value for value in observed.values()),
            "scope": "Synthetic exact-identifier channel only; finite cohort, no confidence or population linkability claim."}


class MeteredTLS(ssl.SSLSocket):
    """Count every decrypted read, even if HTTP/frame parsing later fails."""

    def read(self, length=1024, buffer=None):
        result = super().read(length, buffer)
        meter = getattr(self, "_lab_meter", None)
        if meter is not None:
            row, lock = meter
            with lock:
                row["application_bytes"] += result if isinstance(result, int) else len(result)
        return result

    def close(self):
        meter = getattr(self, "_lab_meter", None)
        if meter is not None:
            row, lock = meter
            with lock:
                row["closed"] = True
        return super().close()


class Collector(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, tls: ssl.SSLContext):
        super().__init__(("127.0.0.1", 0), Handler)
        self.tls = tls
        self.events: list[dict] = []
        self.closed_sockets: set[str] = set()
        self.connections: list[dict] = []
        self.overflow = False
        self.handler_errors = 0
        self.transport_disconnects = 0
        self.lock = threading.Lock()

    def handle_error(self, _request, _address):
        # No raw request/traceback dump. An unexpected server failure must remain
        # visible so an empty collector cannot be mistaken for blocked traffic.
        with self.lock:
            if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, TimeoutError, ssl.SSLError)):
                self.transport_disconnects += 1
            else:
                self.handler_errors += 1

    def get_request(self):
        connection, peer = super().get_request()
        connection.settimeout(5)
        try:
            wrapped = self.tls.wrap_socket(connection, server_side=True)
            row = {"host": getattr(wrapped, "_lab_host", None), "peer_port": peer[1], "application_bytes": 0,
                   "attributed_bytes": {name: 0 for name in BYTE_CHANNELS}, "closed": False}
            with self.lock:
                if len(self.connections) >= MAX_EVENTS:
                    self.overflow = True
                    wrapped.close()
                    raise OSError("Fixture connection evidence exceeded its bound")
                self.connections.append(row)
            wrapped._lab_meter = row, self.lock
            return wrapped, peer
        except Exception:
            connection.close()
            raise

    def record(self, handler, query: dict, body: bytes = b"", *, websocket=False):
        visit, case = query.get("visit", [""])[0], query.get("case", [""])[0]
        if VISIT.fullmatch(visit) is None or case not in CASES:
            return
        headers = {key.lower(): value for key, value in handler.headers.items()}
        header_data = b""
        for name in ("cookie", "x-posthog-distinct-id", "x-posthog-session-id", "x-posthog-window-id"):
            for value in handler.headers.get_all(name, []):
                header_data += b"\n" + value.encode("utf-8")
        by_source = {name: sorted({match.decode() for match in IDENTIFIER.findall(data)})
                     for name, data in (("url", handler.path.encode("utf-8")), ("headers", header_data), ("body", body))}
        tokens = sorted(set().union(*map(set, by_source.values())))
        event = {"visit": visit, "case": case, "host": handler.host, "method": "WEBSOCKET" if websocket else handler.command,
                 "body_bytes": len(body), "distinct_identifier_bytes": sum(len(t) for t in tokens),
                 "identifiers": tokens, "peer_port": handler.client_address[1],
                 "identifier_sources": by_source,
                 "channel": handler._channel,
                 "request_or_frame_bytes": handler._last_frame_bytes,
                 "high_entropy_headers": [name for name in HINT_HEADERS if name in headers],
                 "posthog_headers": [name for name in ("x-posthog-distinct-id", "x-posthog-session-id", "x-posthog-window-id") if name in headers],
                 "gpc": handler.headers.get_all("sec-gpc", []) == ["1"]}
        with self.lock:
            if len(self.events) >= MAX_EVENTS:
                self.overflow = True
            else:
                self.events.append(event)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.rfile = ConsumedReader(self.rfile)
        self._frame_start = 0
        self._last_frame_bytes = 0
        self._channel = "unclassified_complete"

    def handle_one_request(self):
        self._frame_start = self.rfile.position
        self._last_frame_bytes = 0
        super().handle_one_request()

    def parse_request(self):
        if not super().parse_request():
            return False
        if (not self.raw_requestline.endswith(b"\r\n") or self.rfile.last_line != b"\r\n"
                or self.request_version != "HTTP/1.1"):
            self.close_connection = True
            return False
        return True

    def account(self, route, query, *, websocket=False):
        self._channel = byte_channel(self.host, route, query.get("case", [""])[0], websocket=websocket)
        count = self.rfile.position - self._frame_start
        row, lock = self.connection._lab_meter
        with lock:
            if count < 0 or sum(row["attributed_bytes"].values()) + count > row["application_bytes"]:
                raise RuntimeError("Origin framing counter lost conservation")
            row["attributed_bytes"][self._channel] += count
        self._last_frame_bytes = count
        self._frame_start = self.rfile.position

    def log_message(self, *_args):
        pass

    def send(self, body=b"", *, status=200, content_type="text/plain", policy="absent", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin in {f"https://{host}:{self.server.server_port}" for host in HOSTS}:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-POSTHOG-DISTINCT-ID, X-POSTHOG-SESSION-ID, X-POSTHOG-WINDOW-ID")
        if POLICIES[policy] is not None:
            self.send_header("Permissions-Policy", POLICIES[policy])
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def parse(self):
        authorities = self.headers.get_all("Host", [])
        authority = authorities[0] if len(authorities) == 1 else ""
        try:
            parsed = urlsplit("https://" + authority)
            self.host = parsed.hostname
            valid = (self.host in HOSTS and self.host == getattr(self.connection, "_lab_host", None)
                     and parsed.port == self.server.server_port and parsed.username is None
                     and not (parsed.path or parsed.query or parsed.fragment))
        except ValueError:
            valid = False
        if not valid:
            self.close_connection = True
            self.send(status=421)
            return None
        target = urlsplit(self.path)
        return target.path, parse_qs(target.query, keep_blank_values=True)

    def do_OPTIONS(self):
        parsed = self.parse()
        if parsed is not None and self.empty_body():
            self.account(*parsed)
            self.send(status=204)
        else:
            self.close_connection = True

    def empty_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        return not self.headers.get_all("Transfer-Encoding") and lengths in ([], ["0"])

    def do_POST(self):
        parsed = self.parse()
        if parsed is None:
            return
        lengths = self.headers.get_all("Content-Length", [])
        length = lengths[0] if len(lengths) == 1 else ""
        if self.headers.get_all("Transfer-Encoding") or not length.isascii() or not length.isdecimal() or not 0 <= int(length) <= MAX_BODY:
            self.close_connection = True
            self.send(status=413)
            return
        body = self.rfile.read(int(length))
        if len(body) != int(length):
            self.close_connection = True
            return
        self.account(*parsed)
        self.server.record(self, parsed[1], body)
        if parsed[0] == "/cart" and (body != b'{"sku":"fixture","quantity":1}'
                or self.headers.get_all("X-Lab-CSRF") != ["fixture-session"]):
            self.send(status=409)
            return
        self.send(b'{"ok":true}', content_type="application/json")

    def do_GET(self):
        parsed = self.parse()
        if parsed is None:
            return
        route, query = parsed
        if not self.empty_body():
            self.close_connection = True
            self.send(status=400)
            return
        if route == "/socket" and self.headers.get("Upgrade", "").lower() == "websocket":
            return self.websocket(query)
        self.account(route, query)
        if route == "/page":
            policy = query.get("policy", ["absent"])[0]
            if policy not in POLICIES:
                return self.send(status=400)
            body = b'<!doctype html><html><meta charset="utf-8"><title>Egress Guard controlled collector lab</title><body><main>Local synthetic fixture</main><button id="functional">Functional control</button></body></html>'
            return self.send(body, content_type="text/html; charset=utf-8", policy=policy,
                             extra={"Accept-CH": ", ".join(HINT_HEADERS)})
        if route == "/worker.js":
            source = WORKER_PROBE + 'onmessage=async({data})=>{let blocked=false;try{await fetch(data.url,{cache:"no-store"});}catch{blocked=true;}postMessage({done:true,blocked,...await probe()});};'
            return self.send(source.encode(), content_type="text/javascript")
        if route == "/service-worker.js":
            source = WORKER_PROBE + 'self.addEventListener("install",e=>e.waitUntil(self.skipWaiting()));self.addEventListener("activate",e=>e.waitUntil(self.clients.claim()));self.addEventListener("message",e=>{e.waitUntil((async()=>{let blocked=false;try{await fetch(e.data.url,{cache:"no-store"});}catch{blocked=true;}e.ports[0].postMessage({done:true,blocked,...await probe()});})());});'
            return self.send(source.encode(), content_type="text/javascript", extra={"Service-Worker-Allowed": "/"})
        self.server.record(self, query)
        if route == "/pixel.gif":
            return self.send(base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"), content_type="image/gif")
        self.send(b'{"ok":true}', content_type="application/json")

    def websocket(self, query):
        keys = self.headers.get_all("Sec-WebSocket-Key", [])
        key = keys[0] if len(keys) == 1 else ""
        try:
            if (len(base64.b64decode(key, validate=True)) != 16
                    or self.headers.get_all("Sec-WebSocket-Version") != ["13"]):
                raise ValueError()
        except ValueError:
            return self.send(status=400)
        self.account("/socket", query, websocket=True)
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", base64.b64encode(sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode())
        self.end_headers()
        self.close_connection = True
        try:
            while True:
                prefix = self.rfile.read(2)
                if len(prefix) != 2:
                    break
                first, size = prefix
                if first & 0x70 or not first & 0x80 or not size & 0x80:
                    break
                length = size & 127
                if length == 127:
                    break
                if length == 126:
                    encoded = self.rfile.read(2)
                    if len(encoded) != 2:
                        break
                    length = struct.unpack("!H", encoded)[0]
                    if length < 126:
                        break
                if length > MAX_BODY:
                    break
                mask = self.rfile.read(4)
                body = self.rfile.read(length)
                if len(mask) != 4 or len(body) != length:
                    break
                body = bytes(value ^ mask[i % 4] for i, value in enumerate(body))
                opcode = first & 15
                if opcode == 8:
                    if length == 1 or length > 125:
                        break
                    self.account("/socket", query, websocket=True)
                    break
                if opcode not in (1, 2):
                    break
                self.account("/socket", query, websocket=True)
                self.server.record(self, query, body, websocket=True)
                echo = b"ack"
                self.wfile.write(b"\x81" + bytes([len(echo)]) + echo)
                self.wfile.flush()
        except OSError:
            pass
        finally:
            visit = query.get("visit", [""])[0]
            if VISIT.fullmatch(visit):
                with self.server.lock:
                    self.server.closed_sockets.add(visit)


class Lab(AbstractContextManager):
    def __init__(self):
        if sys.version_info < (3, 12) or importlib.metadata.version("mitmproxy") != "12.3.1":
            raise RuntimeError("Lab requires Python 3.12+ and the existing mitmproxy==12.3.1 environment")
        self.temp = tempfile.TemporaryDirectory(prefix="egress-guard-collector-")
        self.state = Path(self.temp.name)
        self.process = self.server = self.thread = self.log = None
        self.meter_read_fd = self.meter_write_fd = None
        self.meter_failed = False

    def __enter__(self):
        try:
            self.start()
            return self
        except BaseException:
            self.close()
            raise

    def start(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from egress_guard.feeds import _snapshot, selected_feeds
        from egress_guard.paths import atomic_private

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, HOSTS[0])])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
                .not_valid_after(now + dt.timedelta(hours=12))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in HOSTS]), False)
                .sign(key, hashes.SHA256()))
        pem, key_path = self.state / "origin.pem", self.state / "origin.key"
        atomic_private(pem, cert.public_bytes(serialization.Encoding.PEM))
        atomic_private(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.cert_der = cert.public_bytes(serialization.Encoding.DER)
        self.spki = base64.b64encode(sha256(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.sslsocket_class = MeteredTLS
        def server_name(connection, name, _context):
            if name not in HOSTS:
                raise ssl.SSLError("outside controlled fixture")
            connection._lab_host = name
        tls.set_servername_callback(server_name)
        tls.load_cert_chain(pem, key_path)
        tls.set_alpn_protocols(["http/1.1"])
        self.client_tls = ssl.create_default_context(cafile=str(pem))
        self.server = Collector(tls)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.proxy_port = sock.getsockname()[1]
        (self.state / "blocklists").mkdir(mode=0o700)
        for feed in selected_feeds({}):
            host = HOSTS[2] if feed.category == "tracker" else HOSTS[3] if feed.category == "cname" else HOSTS[5]
            atomic_private(feed.path(self.state), _snapshot({host}, time.time()))
        atomic_private(self.state / "config.toml", f'[proxy]\nport = {self.proxy_port}\n[logging]\nhistory = "none"\n'.encode())
        self.route_path = self.state / "routes.jsonl"
        self.wire_path = self.state / "proxy-wire.json"
        self.meter_read_fd, self.meter_write_fd = os.pipe()
        os.set_blocking(self.meter_read_fd, False)
        os.set_blocking(self.meter_write_fd, False)
        script = self.state / "fixture.py"
        script.write_text(f'''from dataclasses import replace
import json
import os
from pathlib import Path
from egress_guard import policy
from egress_guard import addon as addon_module
from egress_guard.addon import EgressGuard
from privacy_proxy_meter import install
_original = policy.selected_feeds
policy.selected_feeds = lambda cfg: tuple(replace(feed, minimum=1) for feed in _original(cfg))
origins = {{}}
install(addon_module, Path({str(self.wire_path)!r}), origins,
        on_failure=lambda: os.write({self.meter_write_fd}, b"!"))
class LoopbackOnly:
    def __init__(self):
        self.targets = {{}}
        self.count = 0
    def server_connect(self, data):
        host, port = data.server.address
        if host not in {HOSTS!r} or port != {self.server.server_port}:
            data.server.error = "outside controlled fixture"
            return
        self.targets[data.server.id] = host
        if len(origins) < {MAX_EVENTS}:
            origins[data.server.id] = host
        data.server.address = ("127.0.0.1", {self.server.server_port})
    def server_connected(self, data):
        host = self.targets.pop(data.server.id, None)
        if host is not None and self.count < {MAX_EVENTS}:
            self.count += 1
            row = {{"host": host, "peer_port": data.server.sockname[1], "tunnel_id": str(data.server.id)}}
            with Path({str(self.route_path)!r}).open("a") as out:
                out.write(json.dumps(row) + "\\n")
    def server_connect_error(self, data):
        self.targets.pop(data.server.id, None)
addons = [EgressGuard(), LoopbackOnly()]
''')
        self.log = (self.state / "proxy.log").open("wb")
        env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL", "SYSTEMROOT"}}
        env.update(EGRESS_GUARD_DATA=str(self.state), EGRESS_GUARD_CONFIG=str(self.state / "config.toml"),
                   PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests"))), PYTHONDONTWRITEBYTECODE="1")
        self.process = subprocess.Popen([sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
                "--mode", "regular", "--listen-host", "127.0.0.1", "--listen-port", str(self.proxy_port),
                "--ignore-hosts", ".*", "--set", "connection_strategy=lazy", "--set", "flow_detail=0",
                "--set", "termlog_verbosity=error", "--set", f"confdir={self.state / 'mitm'}", "-s", str(script)],
                stdout=self.log, stderr=subprocess.STDOUT, env=env, pass_fds=(self.meter_write_fd,))
        os.close(self.meter_write_fd)
        self.meter_write_fd = None
        self.wait_policy()

    def wait_policy(self, *, different=None):
        from egress_guard.health import proxy_health
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Controlled proxy exited; inspect local fixture prerequisites")
            health = proxy_health(self.proxy_port, self.state)
            policy = health.get("policy") or {}
            if health["ready"] and not policy.get("pending") and policy.get("revision") not in (None, different):
                return {"ready": True, "revision": policy["revision"], "transport": policy["transport"]}
            time.sleep(0.05)
        raise RuntimeError("Controlled proxy did not acknowledge the expected policy")

    def configure(self, *, paused=False, denied=None):
        from egress_guard.paths import atomic_private
        if type(paused) is not bool or denied not in (None, *HOSTS):
            raise ValueError("Only fixed fixture policy changes are permitted")
        before = self.wait_policy()
        controls = {"tracker_pause_until": time.time() + 600} if paused else {}
        intended = {self.state / "filter-controls.json": (json.dumps(controls) + "\n").encode(),
                    self.state / "block.txt": ((denied + "\n") if denied else "").encode()}
        if all(path.exists() and path.read_bytes() == body for path, body in intended.items()):
            return before
        for path, body in intended.items():
            atomic_private(path, body)
        return self.wait_policy(different=before["revision"])

    def metadata(self):
        return {"schema": 1, "proxy_port": self.proxy_port, "origin_port": self.server.server_port,
                "hosts": HOSTS, "origin_certificate_sha256": sha256(self.cert_der).hexdigest(), "origin_spki": self.spki,
                "proxy": self.wait_policy(), "history": "none", "mitmproxy": importlib.metadata.version("mitmproxy"),
                "scope": "Synthetic loopback origins, original TLS and fixed host routing; not a network sandbox."}

    def snapshot(self):
        try:
            signal = os.read(self.meter_read_fd, 1)
            # EOF while the child should be running is also incomplete evidence.
            # One byte is a failure signal; EOF is a broken diagnostics channel.
            self.meter_failed = True
        except BlockingIOError:
            pass
        if self.meter_failed:
            raise RuntimeError("Fixture metering failed; traffic was forwarded without qualification credit")
        routes = []
        if self.route_path.exists():
            if self.route_path.stat().st_size > 1024 * 1024:
                raise RuntimeError("Fixture route evidence exceeded its bound")
            routes = [json.loads(line) for line in self.route_path.read_text().splitlines()]
        known = {(row["host"], row["peer_port"]) for row in routes}
        if not self.wire_path.exists() or self.wire_path.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError("Missing or oversized proxy emission evidence")
        wire = json.loads(self.wire_path.read_text())
        if (wire.get("schema") != 1 or not isinstance(wire.get("tunnels"), list)
                or len(wire["tunnels"]) > MAX_EVENTS or type(wire.get("overflow")) is not bool):
            raise RuntimeError("Invalid proxy emission evidence")
        ids = set()
        for row in wire["tunnels"]:
            if (not isinstance(row, dict) or not isinstance(row.get("tunnel_id"), str)
                    or row["tunnel_id"] in ids or row.get("host") not in HOSTS
                    or type(row.get("peer_port")) is not int
                    or any(type(row.get(key)) is not int or row[key] < 0 for key in
                           ("to_origin_bytes", "to_client_bytes", "origin_send_commands", "client_send_commands"))):
                raise RuntimeError("Incomplete proxy tunnel identity or counters")
            ids.add(row["tunnel_id"])
        wire["definition"] = "Encrypted TLS bytes in PolicyRelay SendData commands after admission; excludes CONNECT, TCP overhead and acknowledgement. Not a delivery guarantee."
        with self.server.lock:
            events = [{**row, "proxy_route_observed": (row["host"], row["peer_port"]) in known} for row in self.server.events]
            connections = [{**row, "attributed_bytes": dict(row["attributed_bytes"]),
                            "proxy_route_observed": (row["host"], row["peer_port"]) in known} for row in self.server.connections]
            return {"events": events, "closed_sockets": sorted(self.server.closed_sockets), "handler_errors": self.server.handler_errors,
                    "transport_disconnects": self.server.transport_disconnects,
                    "overflow": self.server.overflow or len(routes) >= MAX_EVENTS or wire["overflow"],
                    "origin_body_bytes": sum(row["body_bytes"] for row in events), "observed_proxy_connections": len(routes),
                    "connections": connections, "decrypted_origin_application_bytes": sum(row["application_bytes"] for row in connections),
                    "origin_framing": framed_snapshot(connections), "proxy_emissions": wire}

    def clear(self):
        with self.server.lock:
            self.server.events.clear()
            self.server.closed_sockets.clear()
            # Connection byte counters and overflow are monotonic for the run.

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(4)
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(2)
        if self.log is not None:
            self.log.close()
        for name in ("meter_read_fd", "meter_write_fd"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)
        self.temp.cleanup()

    def __exit__(self, *_args):
        self.close()


def main():
    # The parent owns a private pipe; no network control endpoint or credential.
    with Lab() as lab:
        print(json.dumps({"ready": lab.metadata()}), flush=True)
        while line := sys.stdin.buffer.readline(65537):
            if len(line) > 65536 or not line.endswith(b"\n"):
                raise ValueError("Bounded JSON line required")
            request = json.loads(line)
            if not isinstance(request, dict) or not isinstance(request.get("id"), int):
                raise ValueError("Invalid request")
            command = request.get("command")
            if command == "snapshot":
                result = lab.snapshot()
            elif command == "configure":
                result = lab.configure(paused=request.get("paused", False), denied=request.get("denied"))
            elif command == "clear":
                lab.clear()
                result = {"cleared": True}
            elif command == "score":
                result = exact_linkability(request["events"], request["visits"], case=request.get("case"))
            elif command == "close":
                print(json.dumps({"id": request["id"], "result": {"closed": True}}), flush=True)
                break
            else:
                raise ValueError("Unknown command")
            print(json.dumps({"id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    main()
