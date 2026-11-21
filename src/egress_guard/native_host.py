"""One-shot, read-only Chrome native messages for authenticated local receipts.

The host accepts no domain, URL, path, command line, policy mutation or page content.
Chrome starts it for runtime.sendNativeMessage(); exactly one bounded request is read.
Registration is an explicit CLI operation, never a consequence of a browser request.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import stat
import struct
import sys
import time

from . import __version__
from .bounded_json import loads
from .config import config_path, load_config
from .health import proxy_health
from .paths import data_dir, private_dir, supports_private_identity
from .policy import Policy
from . import transport_policy

HOST_NAME = "org.egress_guard.receipts"
MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 65536
REQUEST_SECONDS = 5
CAPABILITIES = {
    "read_only": True, "policy_status": True, "health": True,
    "browser_profile_binding": False, "device_wide_enforcement": False, "mutations": False,
}
EXTENSION_ID = re.compile(r"[a-p]{32}")
ORIGIN = re.compile(r"chrome-extension://([a-p]{32})/?")


def extension_origin(extension_id: str) -> str:
    if not isinstance(extension_id, str) or EXTENSION_ID.fullmatch(extension_id) is None:
        raise ValueError("Use the exact 32-character extension ID shown by Chrome")
    return f"chrome-extension://{extension_id}/"


def manifest_path(browser: str) -> Path:
    if browser not in {"chrome", "chromium"}:
        raise ValueError("Supported browsers are chrome and chromium")
    if sys.platform == "darwin":
        product = "Google/Chrome" if browser == "chrome" else "Chromium"
        root = Path.home() / "Library/Application Support" / product
    elif sys.platform.startswith("linux"):
        root = Path.home() / ".config" / ("google-chrome" if browser == "chrome" else "chromium")
    else:
        raise ValueError("Native receipt registration supports macOS and Linux only")
    return root / "NativeMessagingHosts" / f"{HOST_NAME}.json"


def _owned_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError("A native host file must be a private, owned regular file")
        body = handle.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("A native host file exceeds its size limit")
    return body


def _encoded(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def _artifacts(extension_id: str, browser: str, state: Path) -> dict[Path, bytes]:
    origin = extension_origin(extension_id)
    launcher = state / "native-host" / "host"
    # Chrome does not support arguments in manifest.path. The fixed launcher uses
    # shell quoting only for trusted installation paths, never message contents.
    script = ("#!/bin/sh\n"
              f"export EGRESS_GUARD_DATA={shlex.quote(str(state))}\n"
              f"export EGRESS_GUARD_CONFIG={shlex.quote(str(config_path()))}\n"
              f"exec {shlex.quote(sys.executable)} -I -B -m egress_guard native-host serve \"$@\"\n").encode()
    manifest = _encoded({"name": HOST_NAME, "description": "Egress Guard read-only protection receipts",
                         "path": str(launcher), "type": "stdio", "allowed_origins": [origin]})
    receipt = _encoded({"schema": 1, "origin": origin, "browser": browser,
                        "launcher_sha256": hashlib.sha256(script).hexdigest(),
                        "manifest_sha256": hashlib.sha256(manifest).hexdigest()})
    return {launcher: script, manifest_path(browser): manifest, launcher.with_name("registration.json"): receipt}


def register(extension_id: str, browser: str = "chrome") -> dict:
    """Create only this user's fixed launcher and exact-origin browser manifest."""
    if not supports_private_identity():
        raise ValueError("Native receipts require a supported private identity backend")
    state = data_dir()
    artifacts = _artifacts(extension_id, browser, state)
    # Validate the entire existing registration before writing any of its files.
    for path, body in artifacts.items():
        if os.path.lexists(path) and _owned_bytes(path) != body:
            raise ValueError("Native registration differs; unregister the old registration before replacing it")
    private_dir(state)
    private_dir(state / "native-host")
    manifest = manifest_path(browser)
    manifest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = manifest.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022):
        raise ValueError("The native messaging directory must be owned and not writable by other users")
    created = []
    try:
        for path, body in artifacts.items():
            if os.path.lexists(path):
                continue
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o700 if path.name == "host" else 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                info = os.fstat(handle.fileno())
                created.append((path, info.st_dev, info.st_ino))
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
    except BaseException:
        for path, device, inode in reversed(created):
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == (device, inode):
                    path.unlink()
            except FileNotFoundError:
                pass
        raise
    return {"registered": True, "host": HOST_NAME, "origin": extension_origin(extension_id),
            "browser": browser, "manifest": str(manifest), "read_only": True}


def unregister(extension_id: str, browser: str = "chrome") -> dict:
    """Remove only byte-identical files for the explicitly named registration."""
    artifacts = _artifacts(extension_id, browser, data_dir())
    snapshots = []
    for path, body in artifacts.items():
        if not os.path.lexists(path):
            continue
        if _owned_bytes(path) != body:
            raise ValueError("Native registration changed; its files were preserved")
        info = path.lstat()
        snapshots.append((path, info.st_dev, info.st_ino, body))
    for path, device, inode, body in reversed(snapshots):
        info = path.lstat()
        if (info.st_dev, info.st_ino) != (device, inode) or _owned_bytes(path) != body:
            raise ValueError("Native registration changed during removal; remaining files were preserved")
        path.unlink()
    return {"registered": False, "host": HOST_NAME, "browser": browser}


def _registered_origin(state: Path) -> str:
    if not supports_private_identity():
        raise ValueError("Native receipts are unavailable on this platform")
    for directory in (state, state / "native-host"):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Native registration requires private state")
    value = loads(_owned_bytes(state / "native-host/registration.json"), limit=MAX_RESPONSE_BYTES)
    if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1
            or not isinstance(value.get("origin"), str) or ORIGIN.fullmatch(value["origin"]) is None):
        raise ValueError("Native registration is invalid")
    return value["origin"].rstrip("/") + "/"


def status_receipt(state: Path | None = None) -> dict:
    """Read saved policy and authenticated runtime state, without initializing state."""
    state = state or data_dir()
    config = load_config()
    policy = Policy(config, state)
    health = proxy_health(config["proxy"]["port"], state, create_identity=False)
    reported = health.get("policy") if isinstance(health.get("policy"), dict) else {}
    revision = reported.get("revision")
    revision = revision if isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{64}", revision) else None
    logging = reported.get("logging")
    logging = ({key: logging.get(key) for key in ("history", "retention_days", "max_queue", "applied")}
               if isinstance(logging, dict) else None)
    logging_applied = bool(logging and logging.get("applied") is True and all(
        logging.get(key) == value for key, value in config["logging"].items()))
    transport = transport_policy.runtime_receipt(reported.get("transport"))
    saved_transport = transport_policy.settings(config)
    transport_applied = transport_policy.applied(saved_transport, transport)
    pending = (reported.get("pending") is not False or revision != policy.revision
               or not logging_applied or not transport_applied)
    applied = revision == policy.revision and not pending
    return {"checked_at": int(time.time()), "proxy_ready": health.get("ready") is True,
            "policy": {"saved_revision": policy.revision, "applied_revision": revision,
                       "applied": applied, "pending": pending,
                       "degraded": policy.degraded() or reported.get("degraded") is not False or not applied,
                       "complete": policy.ready() and reported.get("complete") is True,
                       "coverage": dict(policy.coverage)},
            "logging": {"saved": dict(config["logging"]), "runtime": logging},
            "transport": {"saved": dict(saved_transport), "runtime": transport}}


def _read_exact(stream, size: int, deadline: float) -> bytes:
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError):
        descriptor = None  # In-memory test fixtures only; real stdin has a descriptor.
    chunks = bytearray()
    while len(chunks) < size:
        if descriptor is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                raise ValueError("Native request timed out")
            chunk = os.read(descriptor, size - len(chunks))
        else:
            chunk = stream.read(size - len(chunks))
        if not chunk:
            raise ValueError("Incomplete native message")
        chunks.extend(chunk)
    return bytes(chunks)


def handle_request(request: object) -> dict:
    if (not isinstance(request, dict) or set(request) != {"schema", "command"}
            or type(request["schema"]) is not int or request["schema"] != 1
            or request["command"] not in ("status", "capabilities")):
        return {"schema": 1, "ok": False, "error": "unsupported-request"}
    result = {"schema": 1, "ok": True, "product": "egress-guard", "version": __version__,
              "capabilities": dict(CAPABILITIES)}
    if request["command"] == "status":
        try:
            result["status"] = status_receipt()
        except (OSError, RuntimeError, ValueError):
            # Never echo filesystem paths, rule contents or exception messages into Chrome.
            return {"schema": 1, "ok": False, "error": "local-status-unavailable"}
    return result


def serve(origin: str, *, incoming=None, outgoing=None) -> int:
    """Validate the Chrome-supplied origin, process one frame and exit."""
    incoming = incoming if incoming is not None else sys.stdin.buffer
    outgoing = outgoing if outgoing is not None else sys.stdout.buffer
    matched = ORIGIN.fullmatch(origin) if isinstance(origin, str) else None
    if matched is None or extension_origin(matched.group(1)) != _registered_origin(data_dir()):
        raise ValueError("The requesting extension is not registered")
    deadline = time.monotonic() + REQUEST_SECONDS
    size = struct.unpack("=I", _read_exact(incoming, 4, deadline))[0]
    if not 1 <= size <= MAX_REQUEST_BYTES:
        raise ValueError("Native message exceeds its size limit")
    request = loads(_read_exact(incoming, size, deadline), limit=MAX_REQUEST_BYTES, depth_limit=4)
    encoded = _encoded(handle_request(request))
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise ValueError("Native response exceeds its size limit")
    outgoing.write(struct.pack("=I", len(encoded)) + encoded)
    outgoing.flush()
    return 0
