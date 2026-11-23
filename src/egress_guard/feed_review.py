"""Bounded feed-change tripwires and private review records, never host allow rules.

The small catalog detects particular suspicious changes. It does not establish
publisher authenticity, cover every poisoned update or defend against same-user
code changing the application and its state. Feed policy keeps its own precedence.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from .bounded_json import loads as bounded_json
from .paths import atomic_private, private_dir


CATALOG_VERSION = 2
# A removal only matters if this particular component previously covered the
# anchor. A feed is never required to contain all these names on first install.
TRACKER_ANCHORS = (
    "doubleclick.net", "ad.doubleclick.net", "google-analytics.com",
    "www.google-analytics.com", "region1.google-analytics.com",
    "googletagmanager.com", "www.googletagmanager.com", "googlesyndication.com",
    "pagead2.googlesyndication.com", "connect.facebook.net", "bat.bing.com",
    "script.hotjar.com", "static.hotjar.com", "cdn.segment.com",
)
# These are broad shared-service parents, not a protection for every tenant or
# subdomain. Blocking a particular malicious tenant remains within source scope.
CRITICAL_HOSTS = (
    "github.com", "githubusercontent.com", "github.io", "googleapis.com",
    "apple.com", "cloudflare.com", "pypi.org", "pythonhosted.org",
    "npmjs.org", "npmjs.com", "amazonaws.com", "cloudfront.net",
    "azurewebsites.net", "microsoft.com",
    # These service roots sit below a provider parent. Adding one can cover
    # many independent buckets/accounts without adding the provider itself.
    # Official endpoint references are in docs/feed-impact-0.12.md.
    "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
)
MAX_HEADER_BYTES = 4096
MAX_SAMPLE_NAMES = 8
PREFIX = b"# egress-guard-feed-review "
DIGEST = re.compile(r"[0-9a-f]{64}")
KINDS = {"candidate", "rollback"}
CAUSES = {"refresh", "approval", "rollback"}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def valid_digest(value, *, missing=False) -> bool:
    return (missing and value is None) or (isinstance(value, str) and DIGEST.fullmatch(value) is not None)


def match(host, names, *, exact):
    while host:
        if host in names:
            return host
        if exact:
            break
        _, _, host = host.partition(".")
    return None


def assess(feed, previous, candidate) -> dict:
    """Compare component coverage, not global allows/denies or browsing history."""
    removed, added = [], []
    if feed.category in {"tracker", "cname"}:
        for host in TRACKER_ANCHORS:
            old = match(host, previous, exact=feed.exact)
            if old is not None and match(host, candidate, exact=feed.exact) is None:
                removed.append({"host": host, "previous_match": old})
    for host in CRITICAL_HOSTS:
        new = match(host, candidate, exact=feed.exact)
        if new is not None and match(host, previous, exact=feed.exact) is None:
            added.append({"host": host, "candidate_match": new})
    reasons = []
    if removed:
        reasons.append("tracker-coverage-removed")
    if added:
        reasons.append("critical-infrastructure-added")
    return {"catalog_version": CATALOG_VERSION, "reasons": reasons,
            "tracker_coverage_removed": removed, "critical_coverage_added": added}


def records(blob):
    """Iterate sorted snapshot lines without allocating a full list of names."""
    position = 0
    while position < len(blob):
        stop = blob.find(b"\n", position)
        if stop < 0:
            raise ValueError("feed snapshot ends partway through a record")
        yield blob[position:stop]
        position = stop + 1


def entry_delta(previous: bytes, candidate: bytes, *, exact=False, previous_names=None, candidate_names=None) -> dict:
    """Count exact entry churn and changed coverage roots under this feed's semantics.

    The root count is NOT the number of affected descendants or a whole-policy
    decision count. Reuse already validated HostSet indexes when available.
    """
    if previous_names is None or candidate_names is None:
        from .feeds import HostSet  # avoid a module-level feed_review <-> feeds import cycle
        previous_names = HostSet(previous)
        candidate_names = HostSet(candidate)
    old_records, new_records = iter(records(previous)), iter(records(candidate))
    old, new = next(old_records, None), next(new_records, None)
    added = removed = newly_covered = no_longer_covered = 0
    added_sample, removed_sample = [], []
    newly_covered_sample, no_longer_covered_sample = [], []
    while old is not None or new is not None:
        if new is None or (old is not None and old < new):
            removed += 1
            host = old.decode("ascii")
            if len(removed_sample) < MAX_SAMPLE_NAMES:
                removed_sample.append(host)
            if match(host, candidate_names, exact=exact) is None:
                no_longer_covered += 1
                if len(no_longer_covered_sample) < MAX_SAMPLE_NAMES:
                    no_longer_covered_sample.append(host)
            old = next(old_records, None)
        elif old is None or new < old:
            added += 1
            host = new.decode("ascii")
            if len(added_sample) < MAX_SAMPLE_NAMES:
                added_sample.append(host)
            if match(host, previous_names, exact=exact) is None:
                newly_covered += 1
                if len(newly_covered_sample) < MAX_SAMPLE_NAMES:
                    newly_covered_sample.append(host)
            new = next(new_records, None)
        else:
            old, new = next(old_records, None), next(new_records, None)
    return {"entries_added": added, "entries_removed": removed,
            "added_sample": added_sample, "removed_sample": removed_sample,
            "sample_limit": MAX_SAMPLE_NAMES,
            "semantic_coverage": {
                "matching": "exact-host" if exact else "domain-and-descendants",
                "newly_covered_roots": newly_covered,
                "no_longer_covered_roots": no_longer_covered,
                "newly_covered_sample": newly_covered_sample,
                "no_longer_covered_sample": no_longer_covered_sample,
                "scope": ("Changed entry roots under this feed's matching semantics, not a count "
                          "of all affected descendants, other feeds, exceptions or final policy decisions.")
            },
            "scope": ("Exact feed-entry differences and changed-root effects; other feeds and local "
                      "policy can change the final decision.")}


def directory(state: Path, *, create=False) -> Path:
    path = state / "blocklists" / "reviews"
    if create:
        return private_dir(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return path
    if (not stat.S_ISDIR(info.st_mode) or (os.name != "nt" and (
            info.st_uid != os.getuid() or info.st_mode & 0o077))):
        raise ValueError("feed review directory must be private and owned by this user")
    return path


def path(state: Path, feed, slot: str) -> Path:
    if slot not in {"candidate", "rollback", "transition"}:
        raise ValueError("unknown feed review slot")
    # IDs originate only in the fixed catalog. Do not accept paths from a command.
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,79}", feed.id) is None:
        raise ValueError("invalid fixed feed identifier")
    return directory(state) / f"{feed.id}.{slot}"


def read_regular(path: Path, limit: int) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("feed state must be a bounded regular file")
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("feed state exceeds its byte limit")
    return raw


@dataclass(frozen=True)
class Record:
    metadata: dict
    payload: bytes
    sha256: str


def decode(raw: bytes, feed, kind: str, limit: int) -> Record:
    boundary = raw.find(b"\n", 0, MAX_HEADER_BYTES + 1)
    if (kind not in KINDS or not raw.startswith(PREFIX) or boundary < 0
            or len(raw) > limit + MAX_HEADER_BYTES):
        raise ValueError("invalid feed review record")
    metadata = bounded_json(raw[len(PREFIX):boundary], limit=MAX_HEADER_BYTES, depth_limit=4)
    expected = {"schema", "kind", "feed_id", "source_url", "base_sha256", "payload_sha256", "created_at", "cause"}
    if (not isinstance(metadata, dict) or set(metadata) != expected
            or type(metadata["schema"]) is not int or metadata["schema"] != 1
            or metadata["kind"] != kind or metadata["feed_id"] != feed.id or metadata["source_url"] != feed.url
            or not valid_digest(metadata["base_sha256"], missing=(kind == "candidate"))
            or not valid_digest(metadata["payload_sha256"])
            or type(metadata["created_at"]) not in (int, float)
            or not 0 <= metadata["created_at"] <= time.time() + 86400
            or not isinstance(metadata["cause"], str) or metadata["cause"] not in CAUSES
            or (kind == "candidate" and metadata["cause"] != "refresh")):
        raise ValueError("invalid feed review metadata")
    payload = raw[boundary + 1:]
    if len(payload) > limit or digest(payload) != metadata["payload_sha256"]:
        raise ValueError("feed review payload does not match its digest")
    return Record(metadata, payload, digest(raw))


def read(state: Path, feed, slot: str, limit: int) -> Record | None:
    raw = read_regular(path(state, feed, slot), limit + MAX_HEADER_BYTES)
    return decode(raw, feed, "candidate" if slot == "candidate" else "rollback", limit) if raw is not None else None


def write(state: Path, feed, slot: str, payload: bytes, base_sha256: str | None,
          *, cause: str, limit: int) -> Record:
    metadata = {"schema": 1, "kind": "candidate" if slot == "candidate" else "rollback",
                "feed_id": feed.id, "source_url": feed.url, "base_sha256": base_sha256,
                "payload_sha256": digest(payload), "created_at": time.time(), "cause": cause}
    header = PREFIX + json.dumps(metadata, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    if len(header) > MAX_HEADER_BYTES:
        raise ValueError("feed review metadata exceeds its limit")
    raw = header + payload
    record = decode(raw, feed, metadata["kind"], limit)
    directory(state, create=True)
    atomic_private(path(state, feed, slot), raw)
    return record
