"""Experimental pre-syscall IP policy for the pinned CPython TCP connector.

Importing this module installs nothing. One explicitly started proxy owns a lease;
the interpreter-wide audit dispatcher is installed at most once, only on opt-in.
It never resolves names, writes history, or performs network operations in a hook.
Python audit hooks are not a sandbox against code executing in this interpreter.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
import errno
import socket
import sys

from .feeds import ip_literal

PROBE_EVENT = "egress_guard.address_guard.registration_probe"
QUALIFIED_MITMPROXY = "12.3.1"


def supported(loop) -> bool:
    from mitmproxy import version
    # A different connector needs its own qualification, even if it exposes an
    # asyncio-compatible API. The live probe below also exercises sock_connect.
    return (sys.implementation.name == "cpython" and sys.version_info >= (3, 12)
            and sys.platform in {"linux", "darwin"}
            and type(loop) is asyncio.SelectorEventLoop and loop.is_running()
            and version.VERSION == QUALIFIED_MITMPROXY
            and (not hasattr(sys, "_is_gil_enabled") or sys._is_gil_enabled()))


def _denied() -> PermissionError:
    # A fixed message avoids leaking a target or policy detail into transport logs.
    return PermissionError(errno.EACCES, "Egress Guard refused the TCP address")


class _Dispatcher:
    def __init__(self):
        self.owner: AddressGuard | None = None
        self.orphan_deny = False
        self.attempted = False
        self.registered = False
        self.registration_token = None
        self.registration_seen = None
        self.probe_socket = None
        self.probe_error = None

    def install(self) -> bool:
        if not self.attempted:
            self.attempted = True
            token = self.registration_token = object()
            try:
                sys.addaudithook(self.audit)
                # Earlier audit hooks may silently veto addaudithook. Never infer
                # installation merely because that call returned successfully.
                sys.audit(PROBE_EVENT, token)
                self.registered = self.registration_seen is token
            except Exception:
                self.registered = False
            finally:
                self.registration_token = self.registration_seen = None
        return self.registered

    def audit(self, event, args):
        if event == PROBE_EVENT:
            if len(args) == 1 and args[0] is self.registration_token:
                self.registration_seen = args[0]
            return
        if event != "socket.connect":
            return
        sock, address = args
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_STREAM:
            return
        if sock is self.probe_socket:
            raise self.probe_error
        owner = self.owner
        if owner is None:
            if self.orphan_deny:
                raise _denied()
            return
        if not owner.selected:
            return
        if owner.state != "active":
            raise _denied()
        # asyncio's qualified selector connector supplies numeric sockaddr values.
        # A hostname here would be an unqualified resolution/connect path. Refuse it.
        if (not isinstance(address, tuple) or len(address) not in (2, 4)
                or ip_literal(address[0]) is None or type(address[1]) is not int
                or not 1 <= address[1] <= 65535):
            raise _denied()
        try:
            policy = owner.policy()
            allowed = bool(policy is not None and policy.enforceable()
                           and policy.address_decision(address[0])["decision"] == "allowed")
        except Exception:
            allowed = False
        if not allowed:
            raise _denied()


_dispatcher = _Dispatcher()


class AddressGuard:
    """An explicitly owned, restart-bound selection of the process audit guard."""
    def __init__(self, policy: Callable):
        self.policy = policy
        self.selected = False
        self.state = "unavailable"
        self.reason = "stopped"
        self.closed = False
        self.started = False

    async def start(self, selected: bool) -> None:
        if self.started:
            raise RuntimeError("An address guard lease can only be started once")
        self.started = True
        self.selected = selected
        if self.closed or _dispatcher.owner is not None:
            self.reason = "stopped" if self.closed else "ownership-conflict"
            return
        _dispatcher.owner = self
        _dispatcher.orphan_deny = False
        if not selected:
            self.state, self.reason = "disabled", None
            return
        loop = asyncio.get_running_loop()
        if not supported(loop):
            self.reason = "unsupported-runtime"
            return
        if not _dispatcher.install():
            self.reason = "registration-failed"
            return
        try:
            families = [(socket.AF_INET, ("127.0.0.1", 0))]
            if socket.has_ipv6:
                families.append((socket.AF_INET6, ("::1", 0)))
            for family, target in families:
                with socket.socket(family, socket.SOCK_STREAM) as probe:
                    probe.setblocking(False)
                    expected = _denied()
                    _dispatcher.probe_socket, _dispatcher.probe_error = probe, expected
                    try:
                        await asyncio.wait_for(loop.sock_connect(probe, target), timeout=1)
                    except PermissionError as error:
                        if error is not expected:
                            raise ValueError("The expected audit callback did not refuse the probe") from error
                    else:
                        raise ValueError("The connector bypassed the audit callback")
                    finally:
                        _dispatcher.probe_socket = _dispatcher.probe_error = None
        except Exception:
            self.reason = "self-test-failed"
            return
        self.state, self.reason = "active", None

    def status(self) -> dict:
        if not self.closed and _dispatcher.owner is not self and self.reason != "ownership-conflict":
            return {"selected": self.selected, "state": "unavailable", "reason": "ownership-lost"}
        return {"selected": self.selected, "state": self.state, "reason": self.reason}

    def ready(self) -> bool:
        return self.status()["state"] == ("active" if self.selected else "disabled")

    def close(self) -> None:
        if _dispatcher.owner is self:
            # A late connection from the retiring proxy cannot escape between leases.
            _dispatcher.orphan_deny = self.selected
            _dispatcher.owner = None
        self.closed = True
        self.state, self.reason = "unavailable", "stopped"
        self.policy = lambda: None
