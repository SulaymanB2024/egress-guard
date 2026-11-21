"""Host-based decisions shared by the local proxy and its dashboard."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import stat
import time
from pathlib import Path
from typing import Callable

from egress_guard.config import EXEMPTION_PRESETS
from egress_guard.feeds import (ALL_FEEDS, THREAT_TIERS, CachedFeed, HostSet, dns_name, ip_literal,
                                load_cached_feed, selected_feeds)
from egress_guard.heuristics import DOH_RESOLVER_IPS, SAFETY_HOSTS, lookalike

MAX_CONTROL_BYTES = 64 * 1024
MAX_EXCEPTION_SECONDS = 24 * 60 * 60
STANDARD_PORTS = frozenset({80, 443})
BLOCKED = {"invalid-host", "threat-intel", "malware-feed", "phishing-feed", "lookalike-domain", "local-block",
           "doh-feed", "tracker-feed", "cname-feed"}
ALLOWABLE = {"tracker-feed", "cname-feed", "doh-feed"}
# What the dashboard shows for each ledger `source`. The ledger stores only the source, so every
# source maps to exactly one category. Allowed decisions use the last four categories.
CATEGORIES = {
    "invalid-host": "invalid", "invalid-request": "invalid", "not-ready": "invalid",
    "threat-intel": "threat", "malware-feed": "malware", "phishing-feed": "phishing",
    "lookalike-domain": "lookalike", "local-block": "manual", "doh-feed": "doh",
    "tracker-feed": "ads-trackers", "cname-feed": "cname-cloak",
    "plaintext-credentials": "transport", "non-tls-tunnel": "transport",
    "safety-list": "safety",
    "local-allow": "exception", "dashboard-exception": "exception", "temporary-exception": "exception",
    "tracker-paused": "exception",
    "ip-literal": "unfiltered", "nonstandard-port": "unfiltered",
    "no-match": "none",
}


def normalize_host(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 254:
        return None
    if "%" not in value:
        address = value[1:-1] if value.startswith("[") and value.endswith("]") else value
        if (normalized := ip_literal(address)) is not None:
            return normalized
    return dns_name(value)


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _suffixes(host: str) -> list[str]:
    """The host and each parent domain. One list per lookup keeps each string's hash cached."""
    result = []
    while host:
        result.append(host)
        _, _, host = host.partition(".")
    return result


def _first(suffixes: list[str], names) -> str | None:
    for suffix in suffixes:
        if suffix in names:
            return suffix
    return None


def _match(host: str, names) -> str | None:
    return _first(_suffixes(host), names)


def _read_small(path: Path) -> str:
    try:
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return ""
        if not stat.S_ISREG(mode):
            raise ValueError(f"{path.name} must be a regular file")
        with path.open("rb") as file:
            data = file.read(MAX_CONTROL_BYTES + 1)
        if len(data) > MAX_CONTROL_BYTES:
            raise ValueError(f"{path.name} exceeds the 64 KiB limit")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{path.name} could not be read as UTF-8") from exc


def _read_controls(path: Path) -> dict:
    try:
        values = json.loads(_read_small(path))
    except (ValueError, RecursionError):
        return {}
    return values if isinstance(values, dict) else {}


def _rules(path: Path) -> set[str]:
    names = set()
    for number, line in enumerate(_read_small(path).splitlines(), start=1):
        candidate = line.split("#", 1)[0].strip()
        if not candidate:
            continue
        name = dns_name(candidate)
        if name is None:
            raise ValueError(f"{path.name} has an invalid domain on line {number}")
        names.add(name)
    return names


def _expiry_valid(value: object, now: float) -> bool:
    return type(value) in (int, float) and now < value <= now + MAX_EXCEPTION_SECONDS


def watched_paths(config_path: Path, state: Path) -> tuple[Path, ...]:
    """Every file whose contents can change a host decision's policy revision."""
    return (config_path, state / "block.txt", state / "allow.txt", state / "filter-controls.json",
            state / "tracker-exceptions.json", *(feed.path(state) for feed in ALL_FEEDS))


def policy_stamp(config_path: Path, state: Path) -> tuple:
    """The shared change detector for the proxy and the dashboard.

    Inode and ctime catch same-size replacements whose mtime was preserved.
    """
    stamps = []
    for path in watched_paths(config_path, state):
        try:
            info = path.lstat()
            stamps.append((info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size))
        except OSError:
            stamps.append(None)
    return tuple(stamps)


class Policy:
    def __init__(self, config: dict, state: Path, previous: Policy | None = None) -> None:
        self.state = state
        self.logging = dict(config.get("logging", {}))
        self.proxy = dict(config.get("proxy", {}))
        block = config.get("block", {})
        self.feeds = selected_feeds(config)
        # Each enabled feed is validated on its own. An unusable snapshot keeps the
        # last verified component from the running policy instead of becoming empty.
        prior = previous.components if previous is not None else {}
        self.components: dict[str, CachedFeed] = {}
        self.coverage: dict[str, str] = {}
        # Feeds stay separate compact sets, in selection order, rather than one copied union.
        groups: dict[str, list] = {"threat": [], "tracker": [], "cname": [], "doh": []}
        for feed in self.feeds:
            snapshot = load_cached_feed(state, feed)
            if snapshot is not None:
                self.coverage[feed.id] = "verified"
            elif feed.id in prior:
                snapshot = prior[feed.id]
                self.coverage[feed.id] = "last-good"
            elif (substitute := self._other_threat_tier(state, feed)) is not None:
                # After a tier change (or an upgrade to the full tier), keep enforcing the other
                # verified HaGeZi tier until the selected one downloads. Reported as degraded.
                snapshot = substitute
                self.coverage[feed.id] = "substitute"
            else:
                self.coverage[feed.id] = "missing"
                continue
            self.components[feed.id] = snapshot
            names = snapshot.names
            groups[feed.category].append((feed, names if isinstance(names, HostSet) else HostSet.from_names(names)))
        self.threats = groups["threat"]
        self.ip_threats = [(feed, names) for feed, names in self.threats if feed.ips]
        self.trackers = [names for _, names in groups["tracker"]]
        self.cname = [names for _, names in groups["cname"]]
        self.doh = [names for _, names in groups["doh"]]
        self.block_encrypted_dns = block.get("block_encrypted_dns", True)
        self.manual = _rules(state / "block.txt")
        self.manual.update(host for name in block.get("hosts", []) if (host := dns_name(name)))
        self.allow = _rules(state / "allow.txt")
        self.allow.update(host for name in block.get("allow", []) if (host := dns_name(name)))
        # Exemptions are explicit: configured hosts plus any opted-in compatibility preset.
        self.dashboard_hosts = {
            host for name in block.get("dashboard_hosts", []) if (host := dns_name(name))
        }
        for preset in block.get("exemption_presets", []):
            self.dashboard_hosts.update(EXEMPTION_PRESETS.get(preset, ()))
        self.block_plaintext_credentials = config.get("risk", {}).get("block_plaintext_credentials", True)
        self._material = {
            "config": config,
            "manual": sorted(self.manual),
            "allow": sorted(self.allow),
            "feeds": {feed.id: getattr(self.components.get(feed.id), "sha256", None) for feed in self.feeds},
        }
        self.reload_controls()

    @staticmethod
    def _other_threat_tier(state: Path, feed) -> CachedFeed | None:
        if feed not in THREAT_TIERS.values():
            return None
        for other in THREAT_TIERS.values():
            if other != feed and (snapshot := load_cached_feed(state, other)) is not None:
                return snapshot
        return None

    def enforceable(self) -> bool:
        """Threat and tracker data are present, so the proxy can filter at all."""
        return bool(self.threats and self.trackers)

    def ready(self) -> bool:
        """Every enabled feed has verified data (current or last-good)."""
        return self.enforceable() and "missing" not in self.coverage.values()

    def degraded(self) -> bool:
        return not self.ready() or bool({"last-good", "substitute"} & set(self.coverage.values()))

    def published_at(self, feed_id: str) -> float | None:
        component = self.components.get(feed_id)
        return component.published_at if component else None

    def summary(self) -> dict:
        return {"revision": self.revision, "complete": self.ready(), "degraded": self.degraded(),
                "coverage": dict(self.coverage)}

    def reload_controls(self) -> None:
        # Include bounded, effective controls in the same receipt as feed and local
        # rules. The runtime constructs a new Policy; it never mutates a live grant.
        def timestamp(value):
            # Bounds reject NaN/infinity and huge integers without float conversion.
            return type(value) in (int, float) and 0 <= value < 2 ** 53

        pause = _read_controls(self.state / "filter-controls.json").get("tracker_pause_until")
        self.controls = {"tracker_pause_until": pause} if timestamp(pause) else {}
        self.exceptions = {host: expiry for host, expiry in
                           _read_controls(self.state / "tracker-exceptions.json").items()
                           if dns_name(host) == host and timestamp(expiry)}
        material = {**self._material, "controls": self.controls, "exceptions": self.exceptions}
        self.revision = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()

    def _ip_source(self, address: str) -> tuple[str, str | None]:
        # IP literals never match a DNS suffix, only IP entries listed by an IP-capable feed.
        parsed = ipaddress.ip_address(address)
        equivalents = (address,)
        if isinstance(parsed, ipaddress.IPv4Address):
            number = int(parsed)
            # Python releases have emitted both dotted and hexadecimal mapped text.
            equivalents += ("::ffff:" + address, f"::ffff:{number >> 16:x}:{number & 0xffff:x}")
        for feed, names in self.ip_threats:
            # Older verified snapshots may contain compressed mapped-IPv6 spellings.
            if any(candidate in names for candidate in equivalents):
                return feed.source, address
        if self.block_encrypted_dns and address in DOH_RESOLVER_IPS:
            return "doh-feed", address
        # A public address skips every hostname rule; label it so the activity shows that.
        return ("ip-literal", address) if parsed.is_global else ("no-match", None)

    def _source(self, host: str, port: int | None) -> tuple[str, str | None]:
        if dns_name(host) is None:
            # An IP literal is never a valid DNS name (its last label has no letter).
            address = ip_literal(host)
            return self._ip_source(address) if address is not None else ("no-match", None)
        suffixes = _suffixes(host)
        manual = _first(suffixes, self.manual)
        # Built-in exact safety hosts outrank every downloaded list, never the user's own blocks.
        if host in SAFETY_HOSTS and manual is None:
            return "safety-list", host
        # Feeds hold only dotted names (see _parse_feed), so the bare top-level label is skipped.
        listed = suffixes[:-1]
        probes = HostSet.probes(listed)

        def first(stores) -> str | None:
            for names in stores:
                if (position := names.first(probes)) is not None:
                    return listed[position]
            return None

        # Threat data is never overridden by allow rules, exemptions or pauses.
        for feed, names in self.threats:
            if (position := names.first(probes)) is not None:
                return feed.source, listed[position]
        if manual:
            return "local-block", manual
        allowed = _first(suffixes, self.allow)
        if allowed is None and (imitation := lookalike(host)) is not None:
            return "lookalike-domain", imitation[0]
        doh = first(self.doh)
        tracker = first(self.trackers)
        # CNAME data is exact: only the host itself, the first probe, is checked.
        if doh is None and tracker is None and not any(names.first(probes[:1]) is not None for names in self.cname):
            return ("no-match", None) if port is None or port in STANDARD_PORTS else ("nonstandard-port", None)
        if host in self.dashboard_hosts:
            return "dashboard-exception", host
        if allowed:
            return "local-allow", allowed
        now = time.time()
        excepted = _expiry_valid(self.exceptions.get(host), now)
        if doh is not None:
            # A timed exact-host exception covers DoH; pausing ad filtering does not.
            return ("temporary-exception", host) if excepted else ("doh-feed", doh)
        if _expiry_valid(self.controls.get("tracker_pause_until"), now):
            return "tracker-paused", host
        if excepted:
            return "temporary-exception", host
        return ("tracker-feed", tracker) if tracker else ("cname-feed", host)

    def decision(self, host: str, port: int | None = None) -> dict:
        """Decide one request target. `port` is optional; when given, an otherwise unmatched host
        on a port other than 80 or 443 is reported as `nonstandard-port` (still allowed)."""
        normalized = normalize_host(host)
        source, match = self._source(normalized, port) if normalized else ("invalid-host", None)
        return {
            "decision": "blocked" if source in BLOCKED else "allowed",
            "source": source,
            "category": CATEGORIES[source],
            "matched_domain": match,
            "can_allow": source in ALLOWABLE and dns_name(normalized) is not None,
        }

    def explain(self, host: str, port: int | None = None) -> dict:
        """A decision that says `indeterminate` when missing coverage could change an allow."""
        result = self.decision(host, port)
        if result["decision"] == "allowed" and not self.ready():
            result["decision"] = "indeterminate"
        return {**result, "policy_ready": self.ready(), **self.summary()}


class PolicyRuntime:
    """Observed, desired and applied policy generations for the long-running proxy.

    `observed` is the latest filesystem stamp, `applied` the stamp whose load produced
    the running policy. A failed or rejected load keeps the previous policy, stays
    dirty and retries with bounded backoff; a further file change retries at once.
    """

    def __init__(self, load: Callable[[Policy | None], Policy], observe: Callable[[], tuple], *,
                 apply: Callable[[Policy], None] | None = None,
                 clock: Callable[[], float] = time.monotonic, base_delay: float = 1.0,
                 max_delay: float = 60.0) -> None:
        self._load = load
        self._apply = apply
        self._observe = observe
        self._clock = clock
        self._base_delay = base_delay
        self._max_delay = max_delay
        self.policy: Policy | None = None
        self.observed: tuple | None = None
        self.applied: tuple | None = None
        self._attempted: tuple | None = None
        self._retry_at = 0.0
        self._failures = 0
        self._incomplete = False
        self.error: str | None = None

    @property
    def pending(self) -> bool:
        return self.policy is None or self.observed != self.applied

    def _defer(self, error: str | None) -> None:
        self._failures = min(self._failures + 1, 32)
        delay = min(self._max_delay, self._base_delay * 2 ** (self._failures - 1))
        self._retry_at = self._clock() + delay
        self.error = error

    def poll(self) -> bool:
        """Apply the on-disk policy when it changed or is still owed; True on a swap."""
        stamp = self._observe()
        self.observed = stamp
        if self.policy is not None and stamp == self.applied and not self._incomplete:
            return False
        if stamp == self._attempted and self._clock() < self._retry_at:
            return False
        self._attempted = stamp
        try:
            candidate = self._load(self.policy)
        except (OSError, ValueError) as error:
            self._defer((str(error) or "policy could not be loaded")[:160])
            return False
        current = self.policy
        if not candidate.enforceable() and current is not None and current.enforceable():
            self._defer("replacement policy lacks verified threat or tracker data")
            return False
        try:
            if self._apply is not None:
                self._apply(candidate)
        except (OSError, ValueError) as error:
            self._defer((str(error) or "runtime settings could not be applied")[:160])
            return False
        self.policy = candidate
        self.applied = stamp
        self._incomplete = candidate.degraded()
        if self._incomplete:
            # Last-good or missing components may be a transient read; keep retrying.
            self._defer(None)
        else:
            self._failures, self._retry_at, self.error = 0, 0.0, None
        return True

    def status(self) -> dict:
        policy = self.policy
        summary = policy.summary() if policy else {"revision": None, "complete": False, "degraded": True,
                                                   "coverage": {}}
        summary["degraded"] = summary["degraded"] or self.error is not None
        return {**summary, "pending": self.pending, "error": self.error}
