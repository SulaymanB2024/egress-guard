"""Explicit, hash-prefix SponsorBlock lookup with local duration validation.

Community timings are suggestions for manual review, not a content classifier.
No browser state is inspected and no data is retained by this module.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from .http_deadline import DeadlineHTTPSHandler, ResponseDeadline
from .bounded_json import loads

PROVIDER = "https://sponsor.ajay.app"
LICENSE = "https://creativecommons.org/licenses/by-nc-sa/4.0/"
VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}", re.ASCII)
MAX_BYTES = 2 * 1024 * 1024
MAX_GROUPS = 1024
MAX_SEGMENTS = 100
MAX_DURATION = 86400


def _video_id(value: object) -> str:
    if not isinstance(value, str) or not VIDEO_ID.fullmatch(value):
        raise ValueError("Supply an eleven-character YouTube video ID, without a URL")
    return value


def _seconds(value: object) -> bool:
    return type(value) in (int, float) and 0 <= value <= MAX_DURATION and math.isfinite(value)


def _duration(value: object) -> float:
    if not _seconds(value) or value <= 0:
        raise ValueError("Supply the current video's duration in seconds, greater than zero and at most 86400")
    return float(value)


def _decode(raw: bytes):
    return loads(raw, limit=MAX_BYTES)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

    def http_error_302(self, *args):
        # Refuse before urllib parses an untrusted Location into error text.
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _read_reply(response, deadline) -> bytes:
    if response.headers.get_content_type() != "application/json":
        raise ValueError("The timing service did not return JSON")
    lengths = response.headers.get_all("Content-Length", [])
    transfer = response.headers.get_all("Transfer-Encoding", [])
    encodings = response.headers.get_all("Content-Encoding", [])
    if (len(lengths) > 1 or len(transfer) > 1 or (lengths and transfer)
            or (transfer and transfer[0].lower() != "chunked")
            or (encodings and encodings != ["identity"])):
        raise ValueError("The timing response has ambiguous framing or encoding")
    if lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()
                    or len(lengths[0]) > 10 or int(lengths[0]) > MAX_BYTES):
        raise ValueError("The timing response has an invalid size")
    raw = response.read(MAX_BYTES + 1)
    deadline.check()
    if len(raw) > MAX_BYTES or (lengths and len(raw) != int(lengths[0])):
        raise ValueError("The timing response is too large or incomplete")
    return raw


def _fetch(prefix: str, categories: list[str]):
    query = urllib.parse.urlencode({"categories": json.dumps(categories, separators=(",", ":")),
                                   "actionTypes": '["skip"]', "service": "YouTube"})
    request = urllib.request.Request(f"{PROVIDER}/api/skipSegments/{prefix}?{query}",
        headers={"User-Agent": "EgressGuard-manual-timings/1", "Accept": "application/json",
                 "Accept-Encoding": "identity"})
    try:
        with ResponseDeadline(20) as deadline:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                                  DeadlineHTTPSHandler(deadline))
            try:
                response = opener.open(request, timeout=10)
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    error.close()
                    raise ValueError("The timing service refused the request; no export was produced") from None
                response = error
            with response:
                if response.status not in (200, 404):
                    raise ValueError("The timing service returned an unexpected response")
                payload = _decode(_read_reply(response, deadline))
                if response.status == 404 and payload != []:
                    raise ValueError("The timing service returned an invalid empty response")
                return payload
    except (OSError, http.client.HTTPException):
        raise ValueError("The timing lookup failed; no export was produced") from None


def timing_export(video_id: str, duration: float, payload: object, *, include_selfpromo: bool = False) -> dict:
    """Convert one public prefix bucket to a bounded, exact-video local file."""
    video_id = _video_id(video_id)
    duration = _duration(duration)
    if type(include_selfpromo) is not bool:
        raise ValueError("Self-promotion must be an explicit boolean choice")
    if not isinstance(payload, list) or len(payload) > MAX_GROUPS:
        raise ValueError("The timing service returned an invalid video bucket")
    prefix = hashlib.sha256(video_id.encode("ascii")).hexdigest()[:4]
    matches = []
    for row in payload:
        if not isinstance(row, dict):
            raise ValueError("The timing service returned an invalid video group")
        candidate = _video_id(row.get("videoID"))
        if hashlib.sha256(candidate.encode("ascii")).hexdigest()[:4] != prefix:
            raise ValueError("The timing service returned a video outside the requested prefix")
        segments = row.get("segments")
        if not isinstance(segments, list) or not 0 < len(segments) <= 1000:
            raise ValueError("The timing service returned an invalid segment list")
        if candidate == video_id:
            matches.append(segments)
    if not matches:
        raise ValueError("No community sponsor suggestions were returned for this video; this does not mean it has no sponsors")
    if len(matches) != 1 or len(matches[0]) > MAX_SEGMENTS:
        raise ValueError("The timing service returned ambiguous or excessive suggestions")
    categories = {"sponsor", "selfpromo"} if include_selfpromo else {"sponsor"}
    output = []
    for row in matches[0]:
        if (not isinstance(row, dict) or not isinstance(row.get("category"), str)
                or row["category"] not in categories or row.get("actionType") != "skip"):
            raise ValueError("The timing service returned an unrequested segment category or action")
        interval = row.get("segment")
        source_duration = row.get("videoDuration")
        if (not _seconds(source_duration) or source_duration <= 0
                or abs(source_duration - duration) > 1):
            raise ValueError("A community timing has an unknown or mismatched duration; review it manually")
        if (not isinstance(interval, list) or len(interval) != 2 or not all(_seconds(value) for value in interval)
                or not 0 <= interval[0] < interval[1] <= min(duration, source_duration)):
            raise ValueError("A community timing has invalid or out-of-range endpoints")
        output.append({"start": interval[0], "end": interval[1], "category": row["category"], "actionType": "skip"})
    output.sort(key=lambda row: (row["start"], row["end"]))
    if any(right["start"] < left["end"] for left, right in zip(output, output[1:])):
        raise ValueError("Community timings overlap; review them manually before importing")
    if sum(row["end"] - row["start"] for row in output) >= duration * 0.8:
        raise ValueError("Community timings cover most of this video; no export was produced")
    return {"videoId": video_id, "duration": duration, "segments": output,
            "source": {"provider": "SponsorBlock", "url": PROVIDER, "license": "CC-BY-NC-SA-4.0",
                       "licenseUrl": LICENSE, "retrievedAt": datetime.now(timezone.utc).isoformat(),
                       "changes": "Selected exact-video skip suggestions and converted interval fields; sorted by start time."}}


def fetch_suggestions(video_id: str, duration: float, *, include_selfpromo: bool = False) -> dict:
    """Fetch on explicit invocation; send only a four-character SHA-256 prefix."""
    video_id = _video_id(video_id)
    duration = _duration(duration)
    if type(include_selfpromo) is not bool:
        raise ValueError("Self-promotion must be an explicit boolean choice")
    prefix = hashlib.sha256(video_id.encode("ascii")).hexdigest()[:4]
    categories = ["sponsor", "selfpromo"] if include_selfpromo else ["sponsor"]
    return timing_export(video_id, duration, _fetch(prefix, categories), include_selfpromo=include_selfpromo)


def save_export(destination: Path, payload: dict) -> None:
    """Publish a completed file atomically, refusing every existing destination."""
    destination = Path(destination)
    raw = (json.dumps(payload, indent=2, allow_nan=False) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=".egress-timings-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        # link() is a create-only publish, including against dangling symlinks.
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)
