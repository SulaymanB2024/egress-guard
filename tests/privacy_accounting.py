"""Origin-owned framing counters for the synthetic HTTP/1.1 collector.

The proxy never imports this parser. A socket read may contain several requests
or a partial frame: consumed framing offsets, not read boundaries or timing
windows, assign completed bytes. Everything else remains unattributed.
"""
from __future__ import annotations

CHANNELS = (
    "third_party_collector", "first_party_url_or_header_collector",
    "first_party_body_collector", "websocket_telemetry", "first_party_functional",
    "fixture_control", "unclassified_complete",
)


class ConsumedReader:
    def __init__(self, stream):
        self.stream = stream
        self.position = 0
        self.last_line = b""

    def read(self, size=-1):
        data = self.stream.read(size)
        self.position += len(data)
        return data

    def readline(self, size=-1):
        data = self.stream.readline(size)
        self.position += len(data)
        self.last_line = data
        return data

    def __getattr__(self, name):
        return getattr(self.stream, name)


def channel(host, route, case, *, websocket=False):
    # Channel labels belong to the fixed fixture inventory; they are not a
    # classifier for arbitrary internet requests or opaque production traffic.
    if host == "tracker.test":
        return "third_party_collector"
    if websocket or route == "/socket":
        if case == "cart" and host in {"publisher.test", "shop.test", "allowed.test"}:
            return "first_party_functional"
        return "websocket_telemetry"
    if host in {"publisher.test", "shop.test"}:
        if route in {"/collect/url", "/collect/headers", "/headers"}:
            return "first_party_url_or_header_collector"
        if route == "/measure" and case in {"ga4", "worker", "service-worker", "deferred"}:
            return "first_party_url_or_header_collector"
        if route == "/collect/body" or (route in {"/api/data", "/api/fixture"} and case == "opaque"):
            return "first_party_body_collector"
        if route in {"/product", "/cart", "/checkout"} or (route in {"/api/data", "/api/fixture"} and case == "cart"):
            return "first_party_functional"
    if route in {"/page", "/worker.js", "/service-worker.js"}:
        return "fixture_control"
    return "unclassified_complete"


def framed_snapshot(connections):
    totals = {name: 0 for name in CHANNELS}
    raw = 0
    for row in connections:
        count, attributed = row["application_bytes"], row["attributed_bytes"]
        if type(count) is not int or count < 0 or set(attributed) != set(CHANNELS):
            raise ValueError("Incomplete collector framing evidence")
        if any(type(value) is not int or value < 0 for value in attributed.values()) or sum(attributed.values()) > count:
            raise ValueError("Collector framing exceeds received bytes")
        raw += count
        for name in CHANNELS:
            totals[name] += attributed[name]
    remainder = raw - sum(totals.values())
    return {"schema": 1, "protocol": "controlled-http/1.1-and-bounded-websocket",
            "raw_application_bytes": raw, "completed_frame_bytes": sum(totals.values()),
            "channel_bytes": totals, "unparsed_or_truncated_bytes": remainder,
            "conserved": raw == sum(totals.values()) + remainder,
            "scope": "Origin-decrypted request/frame bytes; includes request framing. Not TLS/TCP wire size or general tracker classification."}
