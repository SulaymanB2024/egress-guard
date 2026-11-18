"""Read-only monitoring of existing Thinkst Canarytokens on macOS."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
from threading import Event
import time
from urllib.parse import urlencode

from .paths import atomic_private, private_dir

try:
    import fcntl
except ImportError:
    fcntl = None


HOST = "canarytokens.org"
HISTORY_PATH = "/d3aece8093b71007b5ccfedad91ebb11/history"
INTERVAL = 60
TIMEOUT = 15
MAX_BACKOFF = 900
MAX_RESPONSE = 8 * 1024 * 1024
MAX_PLACEMENTS = 32
MAX_EVENT_IDS = 1024
TOKEN = re.compile(r"[a-z0-9]{25}")
AUTH = re.compile(r"[a-f0-9]{32}")
KIND = re.compile(r"[a-z][a-z0-9_-]{0,63}")
DIGEST = re.compile(r"[a-f0-9]{64}")
TOKEN_IN_LABEL = re.compile(r"(?<![a-z0-9])(?:[a-z0-9]{25}|[a-f0-9]{32})(?![a-z0-9])")
HISTORY_ERROR = "Canarytokens history returned invalid data."
PROVIDER_ERROR = "Could not reach Canarytokens history securely."
CREDENTIAL_ERROR = "Canarytokens rejected the supplied credentials."
NOTIFICATION_ERROR = "macOS Notification Center did not accept the alert."
BACKLOG_ERROR = "The local canary alert backlog is full."
PUBLIC_ERRORS = (HISTORY_ERROR, PROVIDER_ERROR, CREDENTIAL_ERROR, NOTIFICATION_ERROR, BACKLOG_ERROR)
PUBLIC_FIELDS = (
    "label", "kind", "last_poll", "last_success", "next_attempt", "failures",
    "notifications", "events", "error",
)
NOTIFICATION_SCRIPT = (
    "on run argv\n"
    "    display notification (item 1 of argv) with title (item 2 of argv)\n"
    "end run"
)


class CanaryError(RuntimeError):
    """A sanitized local or provider error."""


def supports_native_notifications() -> bool:
    return sys.platform == "darwin" and fcntl is not None


def _matches(pattern: re.Pattern, value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _label_valid(label: object, token: str, auth_token: str) -> bool:
    if not isinstance(label, str) or not label.strip() or len(label) > 80 or not label.isprintable():
        return False
    lowered = label.casefold()
    if TOKEN_IN_LABEL.search(lowered) or any(item in lowered for item in (token, auth_token, "://", "www.", HOST)):
        return False
    for address in re.findall(r"[a-f0-9:.%]+", lowered):
        try:
            ipaddress.ip_address(address.split("%", 1)[0].strip("."))
        except ValueError:
            continue
        return False
    return True


def _token_valid(token: dict) -> bool:
    return (
        _matches(TOKEN, token.get("token")) and _matches(AUTH, token.get("auth_token"))
        and _label_valid(token.get("label"), token["token"], token["auth_token"])
    )


def _timestamp(value: object) -> bool:
    return type(value) in (float, int) and 0 <= value <= 253402300799 and math.isfinite(value)


def _event_id(hit: object, kind: str) -> str:
    if not isinstance(hit, dict) or not _timestamp(hit.get("time_of_hit")):
        raise CanaryError(HISTORY_ERROR)
    if hit.get("token_type", kind) != kind:
        raise CanaryError(HISTORY_ERROR)
    fields = ("input_channel", "src_ip", "useragent", "user_agent")
    if any(hit.get(item) is not None and not isinstance(hit[item], str) for item in fields):
        raise CanaryError(HISTORY_ERROR)
    is_tor = hit.get("is_tor_relay")
    if is_tor is not None and type(is_tor) is not bool:
        raise CanaryError(HISTORY_ERROR)
    stable = [float(hit["time_of_hit"]), *(hit.get(item) for item in fields), is_tor]
    return hashlib.sha256(json.dumps(stable, separators=(",", ":")).encode()).hexdigest()


def _fetch_history(token: str, auth_token: str, expected_kind: str | None) -> tuple[str, list[str]]:
    query = urlencode({"token": token, "auth": auth_token})
    try:
        # Direct TLS avoids forwarding credentials through ambient HTTP proxies.
        # HTTPSConnection does not follow redirects.
        connection = http.client.HTTPSConnection(HOST, timeout=TIMEOUT, context=ssl.create_default_context())
        try:
            connection.request("GET", f"{HISTORY_PATH}?{query}", headers={
                "Accept": "application/json",
                "User-Agent": "EgressGuard/0.1",
            })
            with connection.getresponse() as response:
                if response.status in (400, 401, 403, 404):
                    raise CanaryError(CREDENTIAL_ERROR)
                if response.status != 200:
                    raise CanaryError(PROVIDER_ERROR)
                if response.headers.get_content_type() != "application/json":
                    raise CanaryError(HISTORY_ERROR)
                body = response.read(MAX_RESPONSE + 1)
        finally:
            connection.close()
        if len(body) > MAX_RESPONSE:
            raise CanaryError(HISTORY_ERROR)
        payload = json.loads(body)
    except (OSError, http.client.HTTPException):
        raise CanaryError(PROVIDER_ERROR) from None
    except (ValueError, RecursionError):
        raise CanaryError(HISTORY_ERROR) from None

    if (
        not isinstance(payload, dict) or payload.get("error")
        or not isinstance(history := payload.get("history"), dict)
    ):
        raise CanaryError(HISTORY_ERROR)
    kind, hits = history.get("token_type"), history.get("hits")
    if (
        not _matches(KIND, kind) or token in kind or auth_token in kind
        or (expected_kind is not None and kind != expected_kind)
        or not isinstance(hits, list) or len(hits) > MAX_EVENT_IDS
    ):
        raise CanaryError(HISTORY_ERROR)
    return kind, list(dict.fromkeys(_event_id(hit, kind) for hit in hits))


def _notify(message: str, title: str) -> None:
    if not supports_native_notifications():
        raise CanaryError(NOTIFICATION_ERROR)
    try:
        subprocess.run(
            ["/usr/bin/osascript", "-e", NOTIFICATION_SCRIPT, "--", message, title],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise CanaryError(NOTIFICATION_ERROR) from None


def _require_private_file(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or info.st_nlink != 1 or info.st_mode & 0o077
    ):
        raise CanaryError("Canary state and lock must be private regular files.")


def _validate_state(value: object) -> list[dict]:
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise CanaryError("Canary state is invalid.")
    rows = value.get("placements")
    if not isinstance(rows, list) or len(rows) > MAX_PLACEMENTS:
        raise CanaryError("Canary state is invalid.")
    for row in rows:
        if not isinstance(row, dict) or not _token_valid(row):
            raise CanaryError("Canary state is invalid.")
        if (
            not _matches(KIND, row.get("kind")) or row["token"] in row["kind"]
            or row["auth_token"] in row["kind"]
            or type(row.get("health_alerted")) is not bool
            or row.get("error") not in (*PUBLIC_ERRORS, None)
            or not all(_timestamp(row.get(key)) for key in ("last_poll", "last_success", "next_attempt"))
            or not all(type(row.get(key)) is int and row[key] >= 0 for key in ("failures", "notifications", "events"))
        ):
            raise CanaryError("Canary state is invalid.")
        for key in ("seen", "pending"):
            ids = row.get(key)
            if not isinstance(ids, list) or len(ids) > MAX_EVENT_IDS or not all(_matches(DIGEST, item) for item in ids):
                raise CanaryError("Canary state is invalid.")
    if len({row["token"] for row in rows}) != len(rows) or len({row["label"].casefold() for row in rows}) != len(rows):
        raise CanaryError("Canary state is invalid.")
    return rows


def _public_status(row: dict) -> dict:
    return {**{key: row[key] for key in PUBLIC_FIELDS}, "native_notifications": supports_native_notifications()}


class CanaryMonitor:
    """Manage opt-in token placements and alert batches for one private data directory."""

    def __init__(self, state: Path):
        self.state = Path(state)
        self.path = self.state / "canaries.json"

    def _read(self) -> list[dict]:
        try:
            if not os.path.lexists(self.path):
                return []
            private_dir(self.state)
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                _require_private_file(handle.fileno())
                body = handle.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise CanaryError("Canary state exceeded its size limit.")
            return _validate_state(json.loads(body))
        except (OSError, ValueError, RecursionError):
            raise CanaryError("Could not read private canary state.") from None

    def _write(self, rows: list[dict]) -> None:
        data = json.dumps({"version": 1, "placements": rows}, separators=(",", ":")).encode()
        if len(data) > MAX_RESPONSE:
            raise CanaryError("Canary state exceeded its size limit.")
        try:
            atomic_private(self.path, data)
        except (OSError, ValueError):
            raise CanaryError("Could not save private canary state.") from None

    @contextmanager
    def _lock(self, *, blocking: bool) -> Iterator[bool]:
        try:
            private_dir(self.state)
            fd = os.open(
                self.state / ".canaries.lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600,
            )
            with os.fdopen(fd, "rb") as handle:
                _require_private_file(handle.fileno())
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                except BlockingIOError:
                    yield False
                else:
                    yield True
        except (OSError, ValueError):
            raise CanaryError("Could not lock private canary state.") from None

    def import_token(self, data: dict) -> dict:
        """Verify one existing token and record its history without alerting on old hits."""
        if not supports_native_notifications():
            raise CanaryError("Canary notifications require macOS.")
        if (
            not isinstance(data, dict) or data.keys() - {"label", "token", "auth_token", "kind"}
            or not _token_valid(data) or ("kind" in data and not _matches(KIND, data["kind"]))
        ):
            raise CanaryError("Provide a short placement label and valid Thinkst token and auth values.")
        with self._lock(blocking=True):
            rows = self._read()
            if len(rows) >= MAX_PLACEMENTS:
                raise CanaryError("This monitor supports up to 32 canary placements.")
            label = data["label"].strip()
            if any(row["token"] == data["token"] or row["label"].casefold() == label.casefold() for row in rows):
                raise CanaryError("The token or placement label is already configured.")

            kind, baseline = _fetch_history(data["token"], data["auth_token"], data.get("kind"))
            now = time.time()
            row = {
                "label": label, "token": data["token"], "auth_token": data["auth_token"], "kind": kind,
                "seen": baseline, "pending": [], "last_poll": now, "last_success": now,
                "next_attempt": now + INTERVAL, "failures": 0, "notifications": 0, "events": 0,
                "error": None, "health_alerted": False,
            }
            self._write([*rows, row])
            return _public_status(row)

    def status(self) -> list[dict]:
        if sys.platform != "darwin" and not hasattr(os, "O_NOFOLLOW"):
            return []
        return [_public_status(row) for row in self._read()]

    def _poll_placement(self, row: dict, rows: list[dict]) -> None:
        row["last_poll"] = now = time.time()
        row["next_attempt"] = now + INTERVAL
        self._write(rows)
        error = None
        try:
            _, hits = _fetch_history(row["token"], row["auth_token"], row["kind"])
        except CanaryError as exc:
            error = str(exc)
        else:
            row["last_success"] = time.time()
            known = set(row["seen"]) | set(row["pending"])
            new_ids = [item for item in hits if item not in known]
            room = MAX_EVENT_IDS - len(row["pending"])
            if len(new_ids) > room:
                error = BACKLOG_ERROR
            row["pending"].extend(new_ids[:room])
            self._write(rows)

        if count := len(row["pending"]):
            try:
                _notify(f"Canary triggered: {row['label']} ({count} {'event' if count == 1 else 'events'})",
                        "Egress Guard canary alert")
            except CanaryError as exc:
                error = error or str(exc)
            else:
                row["events"] += count
                row["notifications"] += 1
                row["seen"] = (row["seen"] + row["pending"])[-MAX_EVENT_IDS:]
                row["pending"] = []
                self._write(rows)

        row["error"] = error
        if error is None:
            row["failures"] = 0
            row["health_alerted"] = False
            row["next_attempt"] = time.time() + INTERVAL
        else:
            row["failures"] += 1
            delay = min(MAX_BACKOFF, INTERVAL * 2 ** min(row["failures"], 4))
            row["next_attempt"] = time.time() + delay
            self._write(rows)
            if row["failures"] >= 3 and not row["health_alerted"]:
                try:
                    _notify(f"Repeated polling failures for {row['label']}", "Egress Guard canary monitor")
                except CanaryError:
                    pass
                else:
                    row["health_alerted"] = True
        self._write(rows)

    def poll_once(self) -> list[dict]:
        if not self.status():
            return []
        if not supports_native_notifications():
            raise CanaryError("Canary notifications require macOS.")
        return self._poll()

    def _poll(self, stop_event: Event | None = None) -> list[dict]:
        with self._lock(blocking=False) as locked:
            if not locked:
                return self.status()
            rows = self._read()
            for row in rows:
                if stop_event is not None and stop_event.is_set():
                    break
                if time.time() >= row["next_attempt"]:
                    self._poll_placement(row, rows)
            return [_public_status(row) for row in rows]

    def run(self, stop_event: Event) -> None:
        if not supports_native_notifications():
            return
        while not stop_event.is_set():
            delay = INTERVAL
            try:
                rows = self._poll(stop_event) if self.status() else []
                if rows:
                    delay = min(INTERVAL, max(1, min(row["next_attempt"] for row in rows) - time.time()))
            except CanaryError:
                # State access errors remain available to the explicit status command.
                pass
            stop_event.wait(delay)
