"""Fetch the pinned domain sources and publish bounded, last-good snapshots."""

from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from array import array
from bisect import bisect_right
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from egress_guard.paths import atomic_private, private_dir
from egress_guard.http_deadline import DeadlineHTTPHandler, DeadlineHTTPSHandler, ResponseDeadline
from egress_guard import feed_review
from egress_guard.bounded_json import loads as bounded_json

HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
ADGUARD = "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/"
PHISHING_ARMY = "https://phishing.army/download/phishing-army-domains.txt"
URLHAUS_FILTER = "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains.txt"
# HaGeZi's full threat feed passes 1.2 million names; leave room for growth.
MAX_FEED_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 3_000_000
STALE_SECONDS = 48 * 60 * 60
MAX_CLOCK_SKEW = 24 * 60 * 60
RESPONSE_SECONDS = 60
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DNS_NAME = re.compile(rf"(?:{DNS_LABEL}\.)*{DNS_LABEL}")
LEGACY_IP_PART = re.compile(r"(?:[0-9]+|0x[0-9a-f]+)")


def dns_name(value: object, *, dotted: bool = False) -> str | None:
    """Return a canonical ASCII DNS hostname, accepting punycode labels."""
    if not isinstance(value, str) or len(value) > 254 or not value.isascii():
        return None
    name = value.lower().removesuffix(".")
    if len(name) > 253 or DNS_NAME.fullmatch(name) is None:
        return None
    # Some resolvers interpret one-to-four numeric/hex components as an IPv4
    # address (for example 0x08080808). Never let those spellings become a DNS
    # allow decision. Accept canonical literals only through ip_literal().
    parts = name.split(".")
    if len(parts) <= 4 and all(LEGACY_IP_PART.fullmatch(part) for part in parts):
        return None
    suffix = name.rsplit(".", 1)[-1]
    if (dotted and "." not in name) or not any("a" <= char <= "z" for char in suffix):
        return None
    return name


def ip_literal(value: object) -> str | None:
    """Return one policy identity for an IP, including IPv4-mapped IPv6."""
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return address.compressed
    except ValueError:
        return None


class HostSet:
    """A compact, read-only, exact membership set of ASCII hostnames.

    Names are kept as the sorted, newline-separated snapshot text itself, cut into blocks of
    about 2 KiB at line boundaries. Only each block's first name and start offset are separate
    objects, so memory is about the text size, instead of roughly 150 bytes per name for a `set`
    of `str`, and loading creates no per-name objects. A lookup is a C-level bisect over the
    block index plus a C-level find within one block. Verified snapshots are written sorted.
    """

    __slots__ = ("_blob", "_starts", "_index", "_count")
    STRIDE = 2048

    def __init__(self, blob: bytes = b"") -> None:
        # `blob` must be sorted, de-duplicated, newline-terminated ASCII names.
        self._blob = blob
        self._starts = array("I")
        self._index: list[bytes] = []
        self._count = blob.count(b"\n")
        position, size = 0, len(blob)
        while position < size:
            self._starts.append(position)
            self._index.append(blob[position:blob.index(b"\n", position)])
            boundary = blob.find(b"\n", position + self.STRIDE)
            if boundary < 0:
                break
            position = boundary + 1

    @classmethod
    def from_names(cls, names) -> HostSet:
        return cls("".join(name + "\n" for name in sorted(set(names))).encode("ascii"))

    @staticmethod
    def probes(names: list[str]) -> list[tuple[bytes, bytes, bytes]]:
        """Encode candidate names once for `first`; each must be ASCII without newlines."""
        return [(target, target + b"\n", b"\n" + target + b"\n")
                for target in (name.encode("ascii") for name in names)]

    def first(self, probes: list[tuple[bytes, bytes, bytes]]) -> int | None:
        """Index of the first probe whose name is in the set, or None."""
        index, blob, starts = self._index, self._blob, self._starts
        blocks, size = len(starts), len(blob)
        for position, (target, line, needle) in enumerate(probes):
            block = bisect_right(index, target) - 1
            if block < 0:
                continue
            start = starts[block]
            stop = starts[block + 1] if block + 1 < blocks else size
            if (blob.startswith(line) if start == 0 else False) or blob.find(needle, start - 1 if start else 0,
                                                                             stop) >= 0:
                return position
        return None

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str) or not name.isascii() or "\n" in name:
            return False
        return self.first(self.probes([name])) is not None

    def __len__(self) -> int:
        return self._count

    def clear(self) -> None:
        self._blob, self._starts, self._index, self._count = b"", array("I"), [], 0


@dataclass(frozen=True)
class Feed:
    """One fixed upstream list.

    `category` is the policy group (`tracker`, `threat`, `cname` or `doh`). `source` is the
    ledger reason recorded when this feed decides a block, and `kind` the user-facing category.
    An `ips` feed may also list IP literals, matched against IP-literal request targets
    and actual numeric TCP destinations when the experimental address guard is enabled.
    """
    id: str
    name: str
    url: str
    minimum: int
    category: str
    source: str = ""
    kind: str = ""
    ips: bool = False

    @property
    def exact(self) -> bool:
        return self.category == "cname"

    def path(self, state: Path) -> Path:
        return state / "blocklists" / (self.id + (".exact" if self.exact else ".txt"))


TRACKERS = {
    tier: Feed(f"hagezi-{tier}", label, HAGEZI + f"{tier}-onlydomains.txt", minimum, "tracker",
               "tracker-feed", "ads-trackers")
    for tier, label, minimum in (
        ("pro", "HaGeZi Multi PRO", 20_000),
        ("pro.plus", "HaGeZi Multi PRO++", 50_000),
        ("ultimate", "HaGeZi Multi Ultimate", 50_000),
    )
}
# The medium tier keeps the feed id used before 0.4, so an existing cache stays valid.
THREAT_TIERS = {
    "full": Feed("hagezi-threat-intel-full", "HaGeZi Threat Intelligence (Full)",
                 HAGEZI + "tif-onlydomains.txt", 500_000, "threat", "threat-intel", "threat"),
    "medium": Feed("hagezi-threat-intel", "HaGeZi Threat Intelligence (Medium)",
                   HAGEZI + "tif.medium-onlydomains.txt", 100_000, "threat", "threat-intel", "threat"),
}
THREATS = THREAT_TIERS["medium"]
PHISHING = Feed("phishing-army", "Phishing Army", PHISHING_ARMY, 20_000, "threat", "phishing-feed", "phishing")
# URLhaus malware-distribution hosts and IPs, republished by malware-filter without the popular
# domains (Tranco, Umbrella and Cloudflare Radar top lists) whose compromised pages URLhaus also lists.
MALWARE = Feed("urlhaus-filter", "URLhaus malware hosts (malware-filter)", URLHAUS_FILTER, 1_000, "threat",
               "malware-feed", "malware", ips=True)
DOH = Feed("hagezi-doh", "HaGeZi encrypted DNS servers", HAGEZI + "doh-onlydomains.txt", 1_000, "doh",
           "doh-feed", "doh")
CNAME_FEEDS = tuple(
    Feed(
        f"adguard-cname-{category}",
        f"AdGuard CNAME-cloaked {category}",
        ADGUARD + f"combined_disguised_{category}_justdomains.txt",
        minimum,
        "cname",
        "cname-feed",
        "cname-cloak",
    )
    for category, minimum in (("ads", 1_000), ("trackers", 20_000))
)
ALL_FEEDS = (*TRACKERS.values(), *THREAT_TIERS.values(), MALWARE, PHISHING, DOH, *CNAME_FEEDS)


def selected_feeds(config: dict) -> tuple[Feed, ...]:
    """Enabled feeds. Threat feeds run most specific first; that order names the block source."""
    block = config.get("block", {})
    tier = block.get("list_tier", "pro.plus")
    if not isinstance(tier, str) or tier not in TRACKERS:
        raise ValueError("unsupported HaGeZi tracker tier")
    threat_tier = block.get("threat_tier", "full")
    if not isinstance(threat_tier, str) or threat_tier not in THREAT_TIERS:
        raise ValueError("unsupported HaGeZi threat tier")
    selected = [TRACKERS[tier], MALWARE, PHISHING, THREAT_TIERS[threat_tier]]
    if block.get("block_encrypted_dns", True):
        selected.append(DOH)
    if block.get("cname_protection", True):
        selected.extend(CNAME_FEEDS)
    return tuple(selected)


def _published_at(text: str) -> float | None:
    for line in text.split("\n", 24)[:24]:
        try:
            if line.startswith("# Last modified: "):
                stamp = dt.datetime.strptime(line.removeprefix("# Last modified: ").strip(), "%d %b %Y %H:%M UTC")
                return stamp.replace(tzinfo=dt.timezone.utc).timestamp()
            for prefix in ("# TimeUpdated: ", "# Generated: ", "# Updated: "):
                if line.startswith(prefix):
                    stamp = dt.datetime.fromisoformat(line.removeprefix(prefix).strip())
                    return stamp.timestamp() if stamp.tzinfo else None
        except ValueError:
            return None
    return None


def _valid_clock(value: object, now: float) -> bool:
    return type(value) in (int, float) and 0 <= value <= now + MAX_CLOCK_SKEW


def _parse_feed(data: bytes, feed: Feed) -> tuple[set[str], float | None]:
    if len(data) > MAX_FEED_BYTES or not data.endswith(b"\n"):
        raise ValueError("feed exceeds the size limit or ends partway through a record")
    source = data.decode("utf-8-sig")
    published = _published_at(source)
    if published is not None and not _valid_clock(published, time.time()):
        raise ValueError("feed publication timestamp is outside the permitted clock range")
    names: set[str] = set()
    skipped = 0
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if feed.exact and line.startswith("*."):
            continue
        if name := dns_name(line, dotted=True) or (feed.ips and ip_literal(line)):
            names.add(name)
        else:
            skipped += 1
        if len(names) > MAX_ENTRIES:
            raise ValueError("too many domains in feed")
    # Upstream lists occasionally contain non-host DNS records or malformed labels.
    if len(names) < feed.minimum or skipped > max(10, len(names) // 20):
        raise ValueError("feed has too few domains or too many malformed records")
    return names, published


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Trust the selected fixed URL and system TLS verification only.
        return None


def _download(feed: Feed) -> bytes:
    request = urllib.request.Request(feed.url, headers={"User-Agent": "egress-guard"})
    try:
        with ResponseDeadline(RESPONSE_SECONDS) as deadline:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                                  DeadlineHTTPHandler(deadline), DeadlineHTTPSHandler(deadline))
            with opener.open(request, timeout=20) as response:
                deadline.check()
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isascii() or not length.isdecimal() or len(length) > 10):
                    raise ValueError("invalid feed content length")
                expected = int(length) if length is not None else None
                if response.status != 200 or (expected is not None and expected > MAX_FEED_BYTES):
                    raise ValueError("unexpected feed response")
                data = response.read(MAX_FEED_BYTES + 1)
                deadline.check()
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError(f"feed returned HTTP {error.code}") from None
    except (OSError, http.client.HTTPException):
        raise ValueError("feed download failed") from None
    if expected is not None and len(data) != expected:
        raise ValueError("feed download was incomplete")
    return data


def _read_meta(path: Path, *, snapshot: bool = False) -> dict:
    try:
        with path.open("rb") as file:
            raw = file.readline(4097)
        if len(raw) > 4096 or (snapshot and not raw.startswith(b"# ")):
            return {}
        data = json.loads(raw[2:] if snapshot else raw)
    except (OSError, ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def _attempt_path(path: Path) -> Path:
    return path.with_suffix(".attempt.json")


def _row(state: Path, feed: Feed) -> dict:
    path = feed.path(state)
    cached = _read_meta(path, snapshot=True)
    attempt = _read_meta(_attempt_path(path))
    updated = cached.get("updated_at")
    published = cached.get("published_at")
    entries = cached.get("entries")
    last_attempt = attempt.get("last_attempt")
    error = attempt.get("error")
    now = time.time()
    if not cached:
        status = "missing"
    elif (
        not _valid_clock(updated, now) or (published is not None and not _valid_clock(published, now))
        or type(entries) is not int
    ):
        status = "invalid"
        error = "feed snapshot has invalid metadata"
    elif error and type(last_attempt) in (int, float) and last_attempt >= updated:
        status = "using-previous"
    else:
        error = None
        clock = updated if published is None else published
        status = "stale" if now - clock > STALE_SECONDS else "current"
    return {
        "id": feed.id,
        "name": feed.name,
        "url": feed.url,
        "category": feed.category,
        "kind": feed.kind,
        "entries": entries,
        "updated_at": updated if _valid_clock(updated, now) else None,
        "published_at": published if _valid_clock(published, now) else None,
        "last_attempt": last_attempt,
        "status": status,
        "error": error,
    }


def feed_status(state: Path, config: dict | None = None) -> list[dict]:
    return [_row(state, feed) for feed in selected_feeds(config or {})]


@dataclass(frozen=True)
class CachedFeed:
    """One verified snapshot: its domains and the metadata covered by its digest check.

    `names` supports membership tests only; snapshots loaded from disk use a compact `HostSet`.
    """
    names: HostSet | set[str]
    sha256: str
    published_at: float | None
    updated_at: float | None


def _verified(state: Path, feed: Feed) -> tuple[bytes, dict, str] | None:
    path = feed.path(state)
    try:
        # Read the metadata line and the body separately, so the body is never copied.
        with path.open("rb") as file:
            meta = file.readline(4097)
            contents = file.read(MAX_FEED_BYTES + 1)
        if (len(meta) + len(contents) > MAX_FEED_BYTES or not meta.endswith(b"\n")
                or not meta.startswith(b"# ")):
            return None
        meta = meta[:-1]
        metadata = json.loads(meta[2:])
        if not isinstance(metadata, dict):
            return None
        digest = hashlib.sha256(contents).hexdigest()
        if digest != metadata.get("sha256"):
            return None
        # `_snapshot` writes names sorted, de-duplicated and newline-terminated, and the digest
        # covers that text, so the newline count is the entry count and the order is searchable.
        count = contents.count(b"\n")
        if (not contents.isascii() or (contents and not contents.endswith(b"\n"))
                or count < feed.minimum or count != metadata.get("entries")):
            return None
    except (OSError, ValueError, RecursionError):
        return None
    return contents, metadata, digest


def load_cached_feed(state: Path, feed: Feed) -> CachedFeed | None:
    """Return a verified snapshot, or None when it is missing, unreadable or corrupt."""
    verified = _verified(state, feed)
    if verified is None:
        return None
    contents, metadata, digest = verified
    now = time.time()
    published, updated = metadata.get("published_at"), metadata.get("updated_at")
    return CachedFeed(HostSet(contents), digest, published if _valid_clock(published, now) else None,
                      updated if _valid_clock(updated, now) else None)


def read_cached_feed(state: Path, feed: Feed) -> set[str]:
    """A verified snapshot's names as text, for measurement and tests; empty when unusable."""
    verified = _verified(state, feed)
    return set(verified[0].decode("ascii").splitlines()) if verified else set()


@dataclass(frozen=True)
class ReviewedSnapshot:
    raw: bytes
    contents: bytes
    metadata: dict
    names: HostSet
    sha256: str


@dataclass(frozen=True)
class InstalledSnapshot:
    raw: bytes | None
    verified: ReviewedSnapshot | None
    sha256: str | None


def _reviewed_snapshot(raw: bytes, feed: Feed) -> ReviewedSnapshot:
    """Fully validate a publication/review artifact outside the request hot path."""
    boundary = raw.find(b"\n", 0, 4097)
    if len(raw) > MAX_FEED_BYTES or boundary < 0 or not raw.startswith(b"# "):
        raise ValueError("invalid feed snapshot framing")
    metadata = bounded_json(raw[2:boundary], limit=4096, depth_limit=4)
    if (not isinstance(metadata, dict) or set(metadata) != {"updated_at", "published_at", "entries", "sha256"}
            or type(metadata["entries"]) is not int or not feed.minimum <= metadata["entries"] <= MAX_ENTRIES
            or not feed_review.valid_digest(metadata["sha256"])
            or not _valid_clock(metadata["updated_at"], time.time())
            or (metadata["published_at"] is not None and not _valid_clock(metadata["published_at"], time.time()))):
        raise ValueError("invalid feed snapshot metadata")
    contents = raw[boundary + 1:]
    if (not contents.isascii() or not contents.endswith(b"\n")
            or contents.count(b"\n") != metadata["entries"]
            or feed_review.digest(contents) != metadata["sha256"]):
        raise ValueError("feed snapshot body does not match its metadata")
    previous = b""
    for line in feed_review.records(contents):
        if line <= previous:
            raise ValueError("feed snapshot records must be sorted and unique")
        name = line.decode("ascii")
        valid = dns_name(name, dotted=True) == name
        if not valid and feed.ips and ip_literal(name) is not None:
            # Read historical mapped-IPv6 entries as well as the current normalized
            # IPv4 spelling. Policy already gives these one effective IP identity.
            valid = ipaddress.ip_address(name).compressed == name
        if not valid:
            raise ValueError("feed snapshot contains an invalid record")
        previous = line
    return ReviewedSnapshot(raw, contents, metadata, HostSet(contents), feed_review.digest(raw))


def _installed(state: Path, feed: Feed) -> InstalledSnapshot:
    raw = feed_review.read_regular(feed.path(state), MAX_FEED_BYTES)
    if raw is None:
        return InstalledSnapshot(None, None, None)
    try:
        verified = _reviewed_snapshot(raw, feed)
    except ValueError:
        verified = None
    return InstalledSnapshot(raw, verified, feed_review.digest(raw))


def _validate_transition(candidate: ReviewedSnapshot, previous: ReviewedSnapshot | None) -> None:
    """These download validators cannot be bypassed by approving a held candidate."""
    if previous is None:
        return
    if candidate.metadata["entries"] * 2 < previous.metadata["entries"]:
        raise ValueError("feed domain count fell by more than half")
    old_published = previous.metadata["published_at"]
    published = candidate.metadata["published_at"]
    if old_published is not None and (published is None or published < old_published):
        raise ValueError("feed is older than the installed snapshot")


def _rollback_record(state: Path, feed: Feed, current: InstalledSnapshot, *, strict=False):
    if current.verified is None:
        return None
    # A committed transition survives a crash before the final rename. Prefer it
    # over the old rollback slot, which still describes the preceding generation.
    for slot in ("transition", "rollback"):
        try:
            record = feed_review.read(state, feed, slot, MAX_FEED_BYTES)
            if record is not None and record.metadata["base_sha256"] == current.sha256:
                previous = _reviewed_snapshot(record.payload, feed)
                return record, previous, slot
        except (OSError, ValueError):
            if strict:
                raise ValueError("feed rollback state is unreadable or invalid; installed data was retained") from None
            continue
    return None


def _publish(state: Path, feed: Feed, candidate: ReviewedSnapshot,
             current: InstalledSnapshot, *, cause: str, check_policy=None) -> dict:
    """Publish one snapshot while retaining recoverable, digest-bound rollback.

    An intent contains the previous bytes and the exact future active digest. It
    is written before the active rename, while the prior rollback stays intact.
    After the active rename, the intent itself is a usable rollback even if its
    final rename is interrupted. Cooperative writers share the refresh lock.
    """
    if _installed(state, feed).sha256 != current.sha256:
        raise ValueError("installed feed changed before publication")

    def verify_before_replace():
        raw = feed_review.read_regular(feed.path(state), MAX_FEED_BYTES)
        actual = feed_review.digest(raw) if raw is not None else None
        if actual != current.sha256:
            raise ValueError("installed feed changed before publication")
        if check_policy is not None:
            check_policy()

    prior = _rollback_record(state, feed, current, strict=True)
    if prior is not None and prior[2] == "transition":
        os.replace(feed_review.path(state, feed, "transition"), feed_review.path(state, feed, "rollback"))
    backup = current.verified
    backup_cause = cause
    # Re-fetching unchanged domain data must not replace a useful previous
    # generation with another copy of the same policy and a newer fetch time.
    if backup is not None and backup.metadata["sha256"] == candidate.metadata["sha256"]:
        backup = prior[1] if prior is not None else None
        if prior is not None and cause == "refresh":
            backup_cause = prior[0].metadata["cause"]
    if backup is not None:
        feed_review.write(state, feed, "transition", backup.raw, candidate.sha256,
                          cause=backup_cause, limit=MAX_FEED_BYTES)
    verify_before_replace()
    # The temp write/fsync can be slow. Recheck exact-base authority and the
    # automatic policy guard AFTER it, directly before the active rename.
    atomic_private(feed.path(state), candidate.raw, before_replace=verify_before_replace)
    recovery_pending = False
    if backup is not None:
        try:
            os.replace(feed_review.path(state, feed, "transition"), feed_review.path(state, feed, "rollback"))
        except OSError:
            # The active snapshot is installed. Its intent is already a valid
            # rollback; reporting this as an unapplied update would be false.
            recovery_pending = True
    return {"installed_sha256": candidate.sha256, "rollback_recovery_pending": recovery_pending,
            "runtime_acknowledged": False}


def _discard_candidate_file(state: Path, feed: Feed) -> bool:
    try:
        feed_review.path(state, feed, "candidate").unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _stage(state: Path, feed: Feed, candidate: ReviewedSnapshot, current: InstalledSnapshot):
    # Repeated downloads of an unchanged held update retain its review identity.
    # The candidate's original timestamps are not rewritten into apparent freshness.
    try:
        pending = feed_review.read(state, feed, "candidate", MAX_FEED_BYTES)
        if pending is not None and pending.metadata["base_sha256"] == current.sha256:
            previous_candidate = _reviewed_snapshot(pending.payload, feed)
            if (previous_candidate.metadata["sha256"] == candidate.metadata["sha256"]
                    and previous_candidate.metadata["published_at"] == candidate.metadata["published_at"]):
                return pending
    except (OSError, ValueError):
        pass
    return feed_review.write(state, feed, "candidate", candidate.raw, current.sha256,
                             cause="refresh", limit=MAX_FEED_BYTES)


def _record_attempt(state: Path, feed: Feed, *, started: float, error=None, **details):
    attempt = {"last_attempt": started, "error": error, **details}
    atomic_private(_attempt_path(feed.path(state)), json.dumps(attempt, allow_nan=False).encode("ascii"))


def _record_action_attempt(state: Path, feed: Feed, **details) -> bool:
    # The cache publication/rollback journal is authoritative. Failure to write a
    # display-only attempt record must not falsely report that publication failed.
    try:
        _record_attempt(state, feed, started=time.time(), **details)
        return True
    except (OSError, ValueError):
        return False


def _refresh(state: Path, config: dict, *, config_binding=None) -> dict:
    """Refresh each selected feed independently so a failed source keeps its cache."""
    from .feed_impact import ComponentCache, ImpactContext, attempt_summary, not_covered

    feeds = selected_feeds(config)
    ok = True
    component_cache = ComponentCache()
    impact_checks = []
    for feed in feeds:
        started = time.time()
        error = None
        details = {}
        impact = not_covered("candidate-not-validated")
        context = None
        try:
            names, published = _parse_feed(_download(feed), feed)
            content = _snapshot(names, published)
            candidate, current = _reviewed_snapshot(content, feed), _installed(state, feed)
            _validate_transition(candidate, current.verified)
            previous_names = current.verified.names if current.verified is not None else HostSet()
            assessment = feed_review.assess(feed, previous_names, candidate.names)
            context = ImpactContext(state, config, component_cache=component_cache, config_binding=config_binding)
            impact = context.compare(feed, candidate, base_sha256=current.sha256)
            if impact["status"] != "compared" and impact["reason"] not in {
                    "incomplete-feed-coverage", "invalid-feed-input"}:
                raise ValueError("policy impact could not be checked; installed feed was retained")
            assessment["reasons"].extend(impact["automatic_hold_reasons"])

            def check_policy():
                nonlocal impact
                if not context.stable():
                    impact = not_covered(context.reason or "policy-inputs-changed")
                    raise ValueError("policy inputs changed during the feed check; retry refresh")

            prior = _rollback_record(state, feed, current, strict=True)
            if prior is not None and prior[0].metadata["cause"] == "rollback":
                assessment["reasons"].append("explicit-rollback-hold")
            check_policy()
            if assessment["reasons"]:
                record = _stage(state, feed, candidate, current)
                details = {"review_candidate_sha256": record.sha256,
                           "review_reasons": assessment["reasons"]}
                raise ValueError(f"feed update quarantined; run 'egress-guard feed-review {feed.id}' before approval")
            details = _publish(state, feed, candidate, current, cause="refresh", check_policy=check_policy)
            if not _discard_candidate_file(state, feed):
                details["candidate_cleanup_pending"] = True
        except (OSError, ValueError) as failure:
            ok = False
            error = str(failure) if type(failure) is ValueError else "could not install feed"
            if context is not None and not context.stable():
                impact = not_covered(context.reason or "policy-inputs-changed")
        summary = attempt_summary(impact)
        details["policy_impact"] = summary
        impact_checks.append({"id": feed.id, **summary})
        try:
            _record_attempt(state, feed, started=started, error=error, **details)
        except OSError:
            ok = False
    return {"ok": ok, "feeds": feed_status(state, config),
            "policy_impact": {"mode": "automatic-public-probes", "checks": impact_checks}}


def _snapshot(names: set[str], published: float | None) -> bytes:
    contents = ("\n".join(sorted(names)) + "\n").encode("ascii")
    metadata = {
        "updated_at": time.time(),
        "published_at": published,
        "entries": len(names),
        "sha256": hashlib.sha256(contents).hexdigest(),
    }
    return ("# " + json.dumps(metadata) + "\n").encode("ascii") + contents


class RefreshBusy(ValueError):
    pass


@contextmanager
def _refresh_lock(state: Path):
    directory = private_dir(private_dir(state) / "blocklists")
    connection = sqlite3.connect(directory / ".refresh.sqlite3", timeout=0.1)
    try:
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            raise RefreshBusy("feed refresh lock unavailable") from error
        yield
    finally:
        connection.close()


def update_feeds(state: Path, config: dict, *, config_file: Path | None = None) -> dict:
    """Serialize refreshes and review publications across processes."""
    from .feed_impact import bind_config

    try:
        config, binding = bind_config(config, config_file)
    except (OSError, ValueError):
        return {"ok": False, "feeds": feed_status(state, config),
                "error": "configuration changed or could not be bound; reload settings and retry",
                "policy_impact": {"mode": "automatic-public-probes", "checks": [],
                                  "status": "not-covered", "reason": "configuration-binding-failed"}}
    try:
        with _refresh_lock(state):
            return _refresh(state, config, config_binding=binding)
    except RefreshBusy as error:
        return {"ok": False, "feeds": feed_status(state, config), "error": str(error)}


def _review_feed(config: dict, feed_id: str, *, selected=False) -> Feed:
    enabled = {feed.id: feed for feed in selected_feeds(config)}
    known = enabled if selected else {**{feed.id: feed for feed in ALL_FEEDS}, **enabled}
    if not isinstance(feed_id, str) or feed_id not in known:
        raise ValueError("choose a known enabled feed" if selected else "unknown fixed feed identifier")
    return known[feed_id]


def _snapshot_summary(snapshot: ReviewedSnapshot | None) -> dict | None:
    if snapshot is None:
        return None
    clock = snapshot.metadata["published_at"]
    if clock is None:
        clock = snapshot.metadata["updated_at"]
    return {"snapshot_sha256": snapshot.sha256, "body_sha256": snapshot.metadata["sha256"],
            "entries": snapshot.metadata["entries"], "published_at": snapshot.metadata["published_at"],
            "updated_at": snapshot.metadata["updated_at"], "stale": time.time() - clock > STALE_SECONDS}


def review_feeds(state: Path, config: dict, feed_id: str | None = None, *,
                 config_file: Path | None = None) -> dict:
    """Inspect bounded local artifacts without locks, downloads or state creation."""
    from .feed_impact import ImpactContext, bind_config, file_stamp, not_covered

    config, binding = bind_config(config, config_file)
    selected = selected_feeds(config)
    items = (_review_feed(config, feed_id),) if feed_id is not None else selected
    enabled = {feed.id for feed in selected}
    rows = []
    impact_context = None
    candidate_stamps = {}
    for feed in items:
        current = _installed(state, feed)
        row = {"id": feed.id, "selected": feed.id in enabled, "source_url": feed.url,
               "matching": "exact-host" if feed.exact else "domain-and-descendants",
               "active": {"state": "verified" if current.verified else "invalid" if current.raw is not None else "missing",
                          "snapshot_sha256": current.sha256, "snapshot": _snapshot_summary(current.verified)},
               "candidate": None, "rollback": None}
        candidate_path = feed_review.path(state, feed, "candidate")
        candidate_stamps[feed.id] = candidate_path, file_stamp(candidate_path)
        raw = feed_review.read_regular(candidate_path, MAX_FEED_BYTES + feed_review.MAX_HEADER_BYTES)
        if raw is not None:
            row["candidate"] = {"state": "invalid", "candidate_sha256": feed_review.digest(raw),
                                "policy_impact": not_covered("invalid-candidate")}
            try:
                record = feed_review.decode(raw, feed, "candidate", MAX_FEED_BYTES)
                candidate = _reviewed_snapshot(record.payload, feed)
                state_name = ("already-current" if candidate.sha256 == current.sha256 else
                              "held" if record.metadata["base_sha256"] == current.sha256 else "stale-base")
                previous_names = current.verified.names if current.verified is not None else HostSet()
                assessment = feed_review.assess(feed, previous_names, candidate.names)
                row["candidate"] = {"state": state_name, "candidate_sha256": record.sha256,
                                    "base_sha256": record.metadata["base_sha256"],
                                    "snapshot": _snapshot_summary(candidate), **assessment,
                                    "delta": feed_review.entry_delta(
                                        current.verified.contents if current.verified else b"", candidate.contents,
                                        exact=feed.exact, previous_names=previous_names,
                                        candidate_names=candidate.names),
                                    "policy_impact": not_covered("candidate-not-yet-checked")}
                try:
                    _validate_transition(candidate, current.verified)
                except ValueError as error:
                    row["candidate"]["state"] = "invalid-transition"
                    row["candidate"]["error"] = str(error)
                    row["candidate"]["policy_impact"] = not_covered("invalid-transition")
                else:
                    if feed.id not in enabled:
                        row["candidate"]["policy_impact"] = not_covered("feed-not-selected")
                    elif state_name == "stale-base":
                        row["candidate"]["policy_impact"] = not_covered("stale-candidate-base")
                    else:
                        if impact_context is None:
                            impact_context = ImpactContext(state, config, config_binding=binding)
                        delta = row["candidate"]["delta"]
                        row["candidate"]["policy_impact"] = impact_context.compare(
                            feed, candidate, base_sha256=current.sha256,
                            changed_roots=(*delta["added_sample"], *delta["removed_sample"]))
                        row["candidate"]["reasons"].extend(
                            row["candidate"]["policy_impact"]["automatic_hold_reasons"])
            except ValueError as error:
                row["candidate"]["error"] = str(error)
        try:
            prior = _rollback_record(state, feed, current, strict=True)
        except ValueError as error:
            prior = None
            row["rollback"] = {"state": "invalid", "available": False, "error": str(error)}
        if prior is not None:
            record, previous, slot = prior
            row["rollback"] = {"state": "available", "available": True,
                               "current_sha256": current.sha256, "previous_sha256": previous.sha256,
                               "snapshot": _snapshot_summary(previous), "recovery_pending": slot == "transition",
                               "refresh_held": record.metadata["cause"] == "rollback"}
            if (row["candidate"] is not None and row["candidate"].get("state") == "held"
                    and record.metadata["cause"] == "rollback"):
                row["candidate"]["reasons"].append("explicit-rollback-hold")
        rows.append(row)
    if impact_context is not None and not impact_context.stable():
        # A later change must also invalidate an earlier row in this same report.
        for row in rows:
            if row["candidate"] is not None and row["candidate"]["policy_impact"]["status"] == "compared":
                row["candidate"]["policy_impact"] = not_covered(impact_context.reason or "policy-inputs-changed")
    for row in rows:
        path, observed = candidate_stamps[row["id"]]
        if (row["candidate"] is not None and row["candidate"]["policy_impact"]["status"] == "compared"
                and file_stamp(path) != observed):
            row["candidate"]["policy_impact"] = not_covered("candidate-input-changed")
    return {"schema": 1, "catalog_version": feed_review.CATALOG_VERSION,
            "scope": "feed-cache review; running policy and browser routing are not verified",
            "configuration_status": ("supplied-settings" if binding is None else
                                     "bound" if binding.stable() else "changed"),
            "policy_impact_mode": "automatic-public-probes; configured-host effects advisory", "feeds": rows}


def approve_feed(state: Path, config: dict, feed_id: str, *, candidate_sha256: str,
                 base_sha256: str | None) -> dict:
    feed = _review_feed(config, feed_id, selected=True)
    if not feed_review.valid_digest(candidate_sha256) or not feed_review.valid_digest(base_sha256, missing=True):
        raise ValueError("approval requires exact candidate and base digests")
    with _refresh_lock(state):
        record = feed_review.read(state, feed, "candidate", MAX_FEED_BYTES)
        if (record is None or record.sha256 != candidate_sha256
                or record.metadata["base_sha256"] != base_sha256):
            raise ValueError("candidate changed; review the current candidate before approval")
        candidate, current = _reviewed_snapshot(record.payload, feed), _installed(state, feed)
        if current.sha256 == candidate.sha256:
            # Recovery after publication succeeded but candidate cleanup did not.
            result = {"installed_sha256": current.sha256, "already_current": True,
                      "runtime_acknowledged": False}
        else:
            if current.sha256 != base_sha256:
                raise ValueError("installed feed changed; approval requires a new review")
            _validate_transition(candidate, current.verified)
            result = _publish(state, feed, candidate, current, cause="approval")
        result["candidate_cleanup_pending"] = not _discard_candidate_file(state, feed)
        result["attempt_recorded"] = _record_action_attempt(state, feed, **result)
        return {"ok": True, "action": "approve", "feed_id": feed.id, **result}


def discard_feed(state: Path, config: dict, feed_id: str, *, candidate_sha256: str) -> dict:
    feed = _review_feed(config, feed_id)
    if not feed_review.valid_digest(candidate_sha256):
        raise ValueError("discard requires an exact candidate digest")
    with _refresh_lock(state):
        path = feed_review.path(state, feed, "candidate")
        raw = feed_review.read_regular(path, MAX_FEED_BYTES + feed_review.MAX_HEADER_BYTES)
        if raw is None or feed_review.digest(raw) != candidate_sha256:
            raise ValueError("candidate changed; review the current candidate before discarding")
        path.unlink()
        recorded = _record_action_attempt(state, feed, error="feed update discarded; keeping the installed snapshot")
        return {"ok": True, "action": "discard", "feed_id": feed.id,
                "active_unchanged": True, "attempt_recorded": recorded}


def rollback_feed(state: Path, config: dict, feed_id: str, *, current_sha256: str,
                  previous_sha256: str) -> dict:
    feed = _review_feed(config, feed_id, selected=True)
    if not feed_review.valid_digest(current_sha256) or not feed_review.valid_digest(previous_sha256):
        raise ValueError("rollback requires exact current and previous digests")
    with _refresh_lock(state):
        current = _installed(state, feed)
        if current.sha256 != current_sha256:
            raise ValueError("installed feed changed; review before rollback")
        prior = _rollback_record(state, feed, current, strict=True)
        if prior is None or prior[1].sha256 != previous_sha256:
            raise ValueError("the specified previous feed generation is not available")
        # Only this recorded previous generation can intentionally cross the
        # publication-time rollback floor. Its bytes and original age are retained.
        result = _publish(state, feed, prior[1], current, cause="rollback")
        result["candidate_cleanup_pending"] = not _discard_candidate_file(state, feed)
        result["attempt_recorded"] = _record_action_attempt(state, feed, update_hold="rollback", **result)
        return {"ok": True, "action": "rollback", "feed_id": feed.id,
                "refresh_held_until_approval": True, **result}
