"""Fetch the pinned domain sources and publish bounded, last-good snapshots."""

from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import json
import re
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from egress_guard.paths import atomic_private, private_dir
from egress_guard.http_deadline import DeadlineHTTPHandler, DeadlineHTTPSHandler, ResponseDeadline

HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
ADGUARD = "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/"
MAX_FEED_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 1_000_000
STALE_SECONDS = 48 * 60 * 60
MAX_CLOCK_SKEW = 24 * 60 * 60
RESPONSE_SECONDS = 60
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DNS_NAME = re.compile(rf"(?:{DNS_LABEL}\.)*{DNS_LABEL}")


def dns_name(value: object, *, dotted: bool = False) -> str | None:
    """Return a canonical ASCII DNS hostname, accepting punycode labels."""
    if not isinstance(value, str) or len(value) > 254 or not value.isascii():
        return None
    name = value.lower().removesuffix(".")
    if len(name) > 253 or DNS_NAME.fullmatch(name) is None:
        return None
    suffix = name.rsplit(".", 1)[-1]
    if (dotted and "." not in name) or not any("a" <= char <= "z" for char in suffix):
        return None
    return name


@dataclass(frozen=True)
class Feed:
    id: str
    name: str
    url: str
    minimum: int
    category: str

    @property
    def exact(self) -> bool:
        return self.category == "cname"

    def path(self, state: Path) -> Path:
        return state / "blocklists" / (self.id + (".exact" if self.exact else ".txt"))


TRACKERS = {
    tier: Feed(f"hagezi-{tier}", label, HAGEZI + f"{tier}-onlydomains.txt", minimum, "tracker")
    for tier, label, minimum in (
        ("pro", "HaGeZi Multi PRO", 20_000),
        ("pro.plus", "HaGeZi Multi PRO++", 50_000),
        ("ultimate", "HaGeZi Multi Ultimate", 50_000),
    )
}
THREATS = Feed(
    "hagezi-threat-intel",
    "HaGeZi Threat Intelligence (Medium)",
    HAGEZI + "tif.medium-onlydomains.txt",
    100_000,
    "threat",
)
CNAME_FEEDS = tuple(
    Feed(
        f"adguard-cname-{category}",
        f"AdGuard CNAME-cloaked {category}",
        ADGUARD + f"combined_disguised_{category}_justdomains.txt",
        minimum,
        "cname",
    )
    for category, minimum in (("ads", 1_000), ("trackers", 20_000))
)


def selected_feeds(config: dict) -> tuple[Feed, ...]:
    block = config.get("block", {})
    tier = block.get("list_tier", "pro.plus")
    if not isinstance(tier, str) or tier not in TRACKERS:
        raise ValueError("unsupported HaGeZi tracker tier")
    return (TRACKERS[tier], THREATS, *CNAME_FEEDS) if block.get("cname_protection", True) else (
        TRACKERS[tier],
        THREATS,
    )


def _published_at(text: str) -> float | None:
    for line in text.split("\n", 24)[:24]:
        try:
            if line.startswith("# Last modified: "):
                stamp = dt.datetime.strptime(line.removeprefix("# Last modified: ").strip(), "%d %b %Y %H:%M UTC")
                return stamp.replace(tzinfo=dt.timezone.utc).timestamp()
            if line.startswith("# TimeUpdated: "):
                stamp = dt.datetime.fromisoformat(line.removeprefix("# TimeUpdated: ").strip())
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
        if name := dns_name(line, dotted=True):
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
    """One verified snapshot: its domains and the metadata covered by its digest check."""
    names: set[str]
    sha256: str
    published_at: float | None
    updated_at: float | None


def load_cached_feed(state: Path, feed: Feed) -> CachedFeed | None:
    """Return a verified snapshot, or None when it is missing, unreadable or corrupt."""
    path = feed.path(state)
    try:
        with path.open("rb") as file:
            data = file.read(MAX_FEED_BYTES + 1)
        meta, newline, contents = data.partition(b"\n")
        if len(data) > MAX_FEED_BYTES or not newline or not meta.startswith(b"# "):
            return None
        metadata = json.loads(meta[2:])
        if not isinstance(metadata, dict):
            return None
        digest = hashlib.sha256(contents).hexdigest()
        if digest != metadata.get("sha256"):
            return None
        names = set(contents.decode("ascii").splitlines())
        if len(names) < feed.minimum or len(names) != metadata.get("entries"):
            return None
    except (OSError, ValueError, RecursionError):
        return None
    now = time.time()
    published, updated = metadata.get("published_at"), metadata.get("updated_at")
    return CachedFeed(names, digest, published if _valid_clock(published, now) else None,
                      updated if _valid_clock(updated, now) else None)


def read_cached_feed(state: Path, feed: Feed) -> set[str]:
    snapshot = load_cached_feed(state, feed)
    return set(snapshot.names) if snapshot else set()


def _refresh(state: Path, config: dict) -> dict:
    """Refresh each selected feed independently so a failed source keeps its cache."""
    feeds = selected_feeds(config)
    ok = True
    for feed in feeds:
        path = feed.path(state)
        started = time.time()
        error = None
        try:
            names, published = _parse_feed(_download(feed), feed)
            previous = _read_meta(path, snapshot=True)
            old_published = previous.get("published_at")
            previous_clock_valid = _valid_clock(previous.get("updated_at"), started) and (
                old_published is None or _valid_clock(old_published, started)
            )
            # Older releases could persist a future clock. Do not use it as a rollback floor.
            if previous_clock_valid:
                old_count = previous.get("entries")
                if type(old_count) is int and len(names) * 2 < old_count:
                    raise ValueError("feed domain count fell by more than half")
                if old_published is not None and (published is None or published < old_published):
                    raise ValueError("feed is older than the installed snapshot")
            content = _snapshot(names, published)
            if len(content) > MAX_FEED_BYTES:
                raise ValueError("normalized feed exceeds the size limit")
            atomic_private(path, content)
        except (OSError, ValueError) as failure:
            ok = False
            error = str(failure) if type(failure) is ValueError else "could not install feed"
        attempt = {"last_attempt": started, "error": error}
        try:
            atomic_private(_attempt_path(path), json.dumps(attempt).encode("ascii"))
        except OSError:
            ok = False
    return {"ok": ok, "feeds": feed_status(state, config)}


def _snapshot(names: set[str], published: float | None) -> bytes:
    contents = ("\n".join(sorted(names)) + "\n").encode("ascii")
    metadata = {
        "updated_at": time.time(),
        "published_at": published,
        "entries": len(names),
        "sha256": hashlib.sha256(contents).hexdigest(),
    }
    return ("# " + json.dumps(metadata) + "\n").encode("ascii") + contents


def update_feeds(state: Path, config: dict) -> dict:
    """Serialize refreshes across processes and preserve the previous good cache."""
    directory = private_dir(private_dir(state) / "blocklists")
    connection = sqlite3.connect(directory / ".refresh.sqlite3", timeout=0.1)
    try:
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            return {"ok": False, "feeds": feed_status(state, config), "error": "feed refresh lock unavailable"}
        return _refresh(state, config)
    finally:
        connection.close()
