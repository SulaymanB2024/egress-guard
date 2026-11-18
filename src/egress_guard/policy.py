"""Host-based decisions shared by the local proxy and its dashboard."""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path

from egress_guard.feeds import dns_name, read_cached_feed, selected_feeds

MAX_CONTROL_BYTES = 64 * 1024
MAX_EXCEPTION_SECONDS = 24 * 60 * 60
BLOCKED = {"invalid-host", "threat-intel", "local-block", "tracker-feed", "cname-feed"}
ALLOWABLE = {"tracker-feed", "cname-feed"}


def normalize_host(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 254:
        return None
    if "%" not in value:
        try:
            address = value[1:-1] if value.startswith("[") and value.endswith("]") else value
            return ipaddress.ip_address(address).compressed
        except ValueError:
            pass
    return dns_name(value)


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _match(host: str, names: set[str]) -> str | None:
    while host:
        if host in names:
            return host
        _, _, host = host.partition(".")
    return None


def _read_small(path: Path) -> str:
    try:
        with path.open("rb") as file:
            data = file.read(MAX_CONTROL_BYTES + 1)
        return data.decode("utf-8") if len(data) <= MAX_CONTROL_BYTES else ""
    except (OSError, UnicodeError):
        return ""


def _read_controls(path: Path) -> dict:
    try:
        values = json.loads(_read_small(path))
    except (ValueError, RecursionError):
        return {}
    return values if isinstance(values, dict) else {}


def _rules(path: Path) -> set[str]:
    return {
        domain
        for line in _read_small(path).splitlines()
        if (domain := dns_name(line.split("#", 1)[0].strip()))
    }


def _expiry_valid(value: object, now: float) -> bool:
    return type(value) in (int, float) and now < value <= now + MAX_EXCEPTION_SECONDS


class Policy:
    def __init__(self, config: dict, state: Path) -> None:
        self.state = state
        block = config.get("block", {})
        self.feeds = selected_feeds(config)
        self.threats: set[str] = set()
        self.trackers: set[str] = set()
        self.cname: set[str] = set()
        destinations = {"threat": self.threats, "tracker": self.trackers, "cname": self.cname}
        for feed in self.feeds:
            destinations[feed.category].update(read_cached_feed(state, feed))
        self.manual = _rules(state / "block.txt")
        self.manual.update(host for name in block.get("hosts", []) if (host := dns_name(name)))
        self.allow = _rules(state / "allow.txt")
        self.allow.update(host for name in block.get("allow", []) if (host := dns_name(name)))
        self.dashboard_hosts = {
            host for name in block.get("dashboard_hosts", []) if (host := dns_name(name))
        }
        self.reload_controls()

    def ready(self) -> bool:
        return bool(self.threats and self.trackers)

    def reload_controls(self) -> None:
        self.controls = _read_controls(self.state / "filter-controls.json")
        self.exceptions = _read_controls(self.state / "tracker-exceptions.json")

    def _source(self, host: str) -> tuple[str, str | None]:
        # Domain rules are DNS rules. IP literals are accepted by the proxy,
        # but IP text is never matched against a DNS suffix.
        if dns_name(host) is None:
            return "no-match", None
        if match := _match(host, self.threats):
            return "threat-intel", match
        if match := _match(host, self.manual):
            return "local-block", match
        tracker = _match(host, self.trackers)
        if tracker is None and host not in self.cname:
            return "no-match", None
        if host in self.dashboard_hosts:
            return "dashboard-exception", host
        if match := _match(host, self.allow):
            return "local-allow", match
        now = time.time()
        if _expiry_valid(self.controls.get("tracker_pause_until"), now):
            return "tracker-paused", host
        if _expiry_valid(self.exceptions.get(host), now):
            return "temporary-exception", host
        return ("tracker-feed", tracker) if tracker else ("cname-feed", host)

    def decision(self, host: str) -> dict:
        normalized = normalize_host(host)
        source, match = self._source(normalized) if normalized else ("invalid-host", None)
        return {
            "decision": "blocked" if source in BLOCKED else "allowed",
            "source": source,
            "matched_domain": match,
            "can_allow": source in ALLOWABLE,
        }
