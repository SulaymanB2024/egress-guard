"""Opt-in macOS web proxy settings for one named network service."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys


NETWORKSETUP = "/usr/sbin/networksetup"
OSASCRIPT = "/usr/bin/osascript"
LOOPBACK = "127.0.0.1"
PROTOCOLS = {"http": "webproxy", "https": "securewebproxy"}
GETTERS = (
    "-getcurrentlocation",
    "-getwebproxy",
    "-getsecurewebproxy",
    "-getsocksfirewallproxy",
    "-getautoproxyurl",
    "-getproxyautodiscovery",
)
AUTHORIZE = (
    "on run argv\n"
    "    return do shell script (item 1 of argv) with administrator privileges\n"
    "end run"
)


class MacOSProxyError(RuntimeError):
    """A system proxy transaction could not complete safely."""


@dataclass(frozen=True)
class Proxy:
    enabled: bool
    server: str
    port: int
    authenticated: bool

    def output(self) -> str:
        return (
            f"Enabled: {'Yes' if self.enabled else 'No'}\n"
            f"Server: {self.server}\n"
            f"Port: {self.port}\n"
            f"Authenticated Proxy Enabled: {int(self.authenticated)}"
        )


@dataclass(frozen=True)
class Snapshot:
    location: str
    http: Proxy
    https: Proxy
    socks: Proxy
    pac_enabled: bool
    auto_discovery: bool
    outputs: tuple[str, ...]


def _run(*args: str, timeout: int | None = 10) -> str:
    if sys.platform != "darwin":
        raise MacOSProxyError("System proxy settings are available on macOS.")
    try:
        result = subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MacOSProxyError(f"{Path(args[0]).name} could not complete.") from exc
    if result.stdout.startswith("** Error:"):
        raise MacOSProxyError("networksetup could not find or read the selected service.")
    return result.stdout.rstrip("\n")


def _validate_service(service: str) -> None:
    if (
        not isinstance(service, str) or not service.strip()
        or service.startswith(("-", "*")) or not service.isprintable()
    ):
        raise MacOSProxyError("Supply an explicit macOS network service name.")


def _parse_proxy(output: str) -> Proxy:
    match = re.fullmatch(
        r"Enabled: (Yes|No)\nServer: ([^\r\n]*)\nPort: ([0-9]{1,5})\n"
        r"Authenticated Proxy Enabled: ([01])",
        output,
    )
    if match is None or int(match[3]) > 65535:
        raise MacOSProxyError("Unexpected macOS proxy configuration output.")
    return Proxy(match[1] == "Yes", match[2], int(match[3]), match[4] == "1")


def _snapshot(service: str) -> Snapshot:
    _validate_service(service)
    services = _run(NETWORKSETUP, "-listallnetworkservices").splitlines()[1:]
    if service not in services:
        raise MacOSProxyError("Select an enabled service listed by networksetup -listallnetworkservices.")
    location = _run(NETWORKSETUP, GETTERS[0])
    if not location or not location.isprintable():
        raise MacOSProxyError("Could not identify the current network location.")
    outputs = tuple(_run(NETWORKSETUP, option, service) for option in GETTERS[1:])
    web, secure, socks = map(_parse_proxy, outputs[:3])
    pac = re.fullmatch(r"URL: [^\r\n]*\nEnabled: (Yes|No)", outputs[3])
    discovery = re.fullmatch(r"Auto Proxy Discovery: (On|Off)", outputs[4])
    if pac is None or discovery is None:
        raise MacOSProxyError("Unexpected macOS automatic proxy configuration output.")
    return Snapshot(location, web, secure, socks, pac[1] == "Yes", discovery[1] == "On",
                    (location, *outputs))


def inspect_proxy(service: str) -> dict:
    """Return the selected service's proxy status without changing it."""
    result = asdict(_snapshot(service))
    del result["outputs"]
    return result


def _command(option: str, *arguments: str) -> str:
    return shlex.join([NETWORKSETUP, option, *arguments])


def _match(option: str, output: str, *arguments: str) -> str:
    command = _command(option, *arguments)
    return f'[ "$({command})" = {shlex.quote(output)} ]'


def _matches_service(service: str) -> str:
    # A disabled service is prefixed with an asterisk by networksetup.
    return (
        f'{_command("-listallnetworkservices")} | '
        f'/usr/bin/grep -Fqx -- {shlex.quote(service)}'
    )


def _match_proxy(protocol: str, service: str, settings: Proxy) -> str:
    return _match(f"-get{protocol}", settings.output(), service)


def _off(settings: Proxy) -> Proxy:
    return Proxy(False, settings.server, settings.port, settings.authenticated)


def _disable_owned(service: str, protocol: str, installed: Proxy) -> str:
    """Disable our setting if it still matches the installed endpoint."""
    still_owned = _match_proxy(protocol, service, installed)
    disabled = _command(f"-set{protocol}state", service, "off")
    # A server/port write implicitly enables the endpoint in networksetup.
    return f"if {still_owned}; then\n    {disabled} || exit 1\nfi"


def _authorized(script: str) -> None:
    _run(OSASCRIPT, "-e", AUTHORIZE, "--", "export LC_ALL=C\n" + script, timeout=None)


@contextmanager
def _lock(state: Path) -> Iterator[None]:
    if os.geteuid() == 0:
        raise MacOSProxyError("Run this command from your normal macOS account.")
    directory = state.parent.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
        or stat.S_IMODE(directory.st_mode) & 0o077
    ):
        raise MacOSProxyError("The proxy receipt requires an owner-only state directory.")
    lock_path = state.with_name(f".{state.name}.lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd) as handle:
        _require_private_file(handle.fileno())
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _require_private_file(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise MacOSProxyError("Proxy receipt and lock files must be private regular files.")


def _save_receipt(state: Path, service: str, port: int, before: Snapshot) -> None:
    payload = {
        "version": 1, "service": service, "port": port, "location": before.location,
        "previous": {key: asdict(getattr(before, key)) for key in PROTOCOLS},
    }
    fd = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())


def _valid_port(port: int) -> bool:
    return type(port) is int and 1 <= port <= 65535


def _load_receipt(state: Path) -> tuple[str, str, Proxy, dict[str, Proxy]]:
    fd = os.open(state, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        with os.fdopen(fd, encoding="utf-8") as handle:
            _require_private_file(handle.fileno())
            payload = json.loads(handle.read(16385))
        service = payload["service"]
        _validate_service(service)
        location = payload["location"]
        port = payload["port"]
        if payload["version"] != 1 or not _valid_port(port) or not location.isprintable():
            raise ValueError
        previous = {}
        for key in PROTOCOLS:
            proxy = Proxy(**payload["previous"][key])
            if (
                proxy.enabled is not False or proxy.authenticated is not False
                or not isinstance(proxy.server, str) or type(proxy.port) is not int
                or not 0 <= proxy.port <= 65535
            ):
                raise ValueError
            previous[key] = proxy
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise MacOSProxyError("The system proxy receipt is invalid.") from exc
    return service, location, Proxy(True, LOOPBACK, port, False), previous


def _guard_location(service: str, location: str) -> str:
    return (
        f'{_match("-getcurrentlocation", location)} || exit 3\n'
        f'{_matches_service(service)} || exit 3'
    )


def _activation_script(service: str, before: Snapshot, installed: Proxy) -> str:
    unchanged = [
        _match(option, output, service)
        for option, output in zip(GETTERS[1:], before.outputs[1:], strict=True)
    ]
    location = _match("-getcurrentlocation", before.location)
    stage = []
    rollback = []
    for key, protocol in PROTOCOLS.items():
        stage.extend((
            location,
            _match_proxy(protocol, service, getattr(before, key)),
            f"attempted_{key}=1",
            _command(f"-set{protocol}", service, LOOPBACK, str(installed.port), "off"),
            _match_proxy(protocol, service, installed),
        ))
        rollback.append(
            f'if [ "${{attempted_{key}:-0}}" -eq 1 ]; then\n'
            + "(\n" + _disable_owned(service, protocol, installed) + "\n)\nfi"
        )
    stage.extend([
        location,
        *(_match_proxy(protocol, service, installed) for protocol in PROTOCOLS.values()),
        *unchanged[2:],
    ])
    preflight = " &&\n".join(unchanged)
    checks = " &&\n".join(stage)
    return (
        f"{_guard_location(service, before.location)}\n"
        f"{preflight} || exit 3\n"
        f"if {checks}; then\n    exit 0\nfi\n"
        f"{_guard_location(service, before.location)}\n"
        + "\n".join(rollback)
        + "\nexit 1"
    )


def enable_proxy(
    service: str, port: int, state: Path, *, verify_health: Callable[[], None],
) -> dict:
    """Enable the named service after the caller verifies its local proxy identity."""
    if not _valid_port(port):
        raise MacOSProxyError("The local proxy requires a port from 1 to 65535.")
    state = Path(state)
    try:
        with _lock(state):
            if os.path.lexists(state):
                raise MacOSProxyError("A proxy receipt already exists. Restore that transaction first.")
            before = _snapshot(service)
            if (
                before.http.enabled or before.https.enabled or before.socks.enabled
                or before.http.authenticated or before.https.authenticated
                or before.socks.authenticated or before.pac_enabled or before.auto_discovery
            ):
                raise MacOSProxyError("The service is already configured for a web, SOCKS, authenticated, or automatic proxy.")

            verify_health()
            installed = Proxy(True, LOOPBACK, port, False)
            _save_receipt(state, service, port, before)
            try:
                _authorized(_activation_script(service, before, installed))
            except MacOSProxyError as exc:
                current = _snapshot(service)
                if current.location == before.location and all(
                    getattr(current, key) in (getattr(before, key), _off(installed)) for key in PROTOCOLS
                ):
                    if any(getattr(current, key) != getattr(before, key) for key in PROTOCOLS):
                        raise MacOSProxyError(
                            "Activation failed and both proxies are disabled. The receipt records the original endpoints."
                        ) from exc
                    state.unlink()
                    raise MacOSProxyError("Activation did not complete. Both original proxy settings are intact.") from exc
                raise MacOSProxyError(
                    "Activation did not complete. The proxy receipt is available for recovery."
                ) from exc

            current = _snapshot(service)
            if current.location != before.location or any(
                getattr(current, key) != installed for key in PROTOCOLS
            ):
                raise MacOSProxyError("Activation could not be verified. Restore using the saved receipt.")
    except OSError as exc:
        raise MacOSProxyError(f"Could not safely access the proxy receipt: {state}") from exc
    return {"service": service, "port": port}


def restore_proxy(state: Path) -> dict:
    """Disable only HTTP/HTTPS settings that still match this receipt."""
    state = Path(state)
    try:
        with _lock(state):
            try:
                service, location, installed, previous = _load_receipt(state)
            except FileNotFoundError:
                return {"service": None, "restored": [], "preserved": [], "dormant_endpoints": []}
            current = _snapshot(service)
            if current.location != location:
                raise MacOSProxyError("Switch to the original network location before restoring proxy settings.")
            owned = [key for key in PROTOCOLS if getattr(current, key) == installed]
            if owned:
                repair = "\n".join(
                    f"(\n{_disable_owned(service, PROTOCOLS[key], installed)}\n)"
                    " || restore_status=1"
                    for key in owned
                )
                _authorized(
                    f"{_guard_location(service, location)}\nrestore_status=0\n{repair}\n"
                    'exit "$restore_status"'
                )
                current = _snapshot(service)
                if current.location != location or any(
                    getattr(current, key) == installed for key in owned
                ):
                    raise MacOSProxyError("Restore could not be verified. The proxy receipt is available for recovery.")
            restored = [key for key in owned if getattr(current, key) in (previous[key], _off(installed))]
            dormant = [
                key for key in PROTOCOLS
                if getattr(current, key) == _off(installed) and previous[key] != _off(installed)
            ]
            preserved = [
                key for key in PROTOCOLS
                if getattr(current, key) not in (previous[key], _off(installed))
            ]
            state.unlink()
            return {
                "service": service, "restored": restored, "preserved": preserved,
                "dormant_endpoints": dormant,
            }
    except OSError as exc:
        raise MacOSProxyError(f"Could not safely access the proxy receipt: {state}") from exc
