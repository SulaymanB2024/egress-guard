"""Bounded transport settings and authenticated status, without network operations."""
from __future__ import annotations

from .feeds import ip_literal

PROFILES = frozenset({"compatible", "hardened"})
GUARD_REASONS = frozenset({"unsupported-runtime", "ownership-conflict", "registration-failed",
                           "self-test-failed", "ownership-lost", "stopped"})
MAX_CONNECT_PORTS = 32


def settings(config: dict) -> dict:
    value = config.get("transport", {})
    return {"profile": value.get("profile", "compatible"),
            "connect_ports": list(value.get("connect_ports", [443])),
            "address_guard": value.get("address_guard", False)}


def valid_settings(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"profile", "connect_ports", "address_guard"}:
        return False
    ports = value["connect_ports"]
    return (isinstance(value["profile"], str) and value["profile"] in PROFILES
            and type(value["address_guard"]) is bool and isinstance(ports, list)
            and 1 <= len(ports) <= MAX_CONNECT_PORTS
            and all(type(port) is int and 1 <= port <= 65535 for port in ports)
            and ports == sorted(set(ports)))


def runtime_receipt(value: object) -> dict | None:
    """Keep only the fixed transport schema from an authenticated policy report."""
    if not isinstance(value, dict) or set(value) != {
        "profile", "connect_ports", "address_guard", "scope", "tunnel_policy", "applied",
    }:
        return None
    guard = value["address_guard"]
    if not isinstance(guard, dict) or set(guard) != {"selected", "state", "reason"}:
        return None
    selected, state, reason = guard["selected"], guard["state"], guard["reason"]
    if type(selected) is not bool:
        return None
    valid_guard = ((state == "disabled" and not selected and reason is None)
                   or (state == "active" and selected and reason is None)
                   or (state == "unavailable" and isinstance(reason, str) and reason in GUARD_REASONS))
    if (not valid_guard or value["scope"] != "proxy-tcp" or value["tunnel_policy"] != "per-forward"
            or type(value["applied"]) is not bool
            or (value["applied"] and state == "unavailable")
            or not valid_settings({"profile": value["profile"], "connect_ports": value["connect_ports"],
                                   "address_guard": selected})):
        return None
    return {"profile": value["profile"], "connect_ports": list(value["connect_ports"]),
            "address_guard": dict(guard), "scope": "proxy-tcp", "tunnel_policy": "per-forward",
            "applied": value["applied"]}


def applied(saved: dict, runtime: dict | None) -> bool:
    return bool(runtime and runtime.get("tunnel_policy") == "per-forward"
                and runtime["applied"] and runtime["profile"] == saved["profile"]
                and runtime["connect_ports"] == saved["connect_ports"]
                and runtime["address_guard"]["selected"] == saved["address_guard"]
                and runtime["address_guard"]["state"] == ("active" if saved["address_guard"] else "disabled"))


def refusal(config: dict, host: str, port: int, transport: str, *, loopback: bool) -> str | None:
    """A request-target floor, separate from policy decisions on resolved addresses."""
    if config["profile"] != "hardened" or loopback:
        return None
    if transport == "http":
        return "plaintext-http"
    if ip_literal(host) is not None:
        return "literal-connect"
    if port not in config["connect_ports"]:
        return "connect-port"
    return None
