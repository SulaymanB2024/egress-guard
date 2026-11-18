"""Inspect bounded DNS alias observations without changing host policy."""

from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING

from egress_guard.feeds import dns_name

if TYPE_CHECKING:
    from egress_guard.policy import Policy

QUERY_TYPES = ("A", "AAAA")
MAX_RECORDS = 32
MAX_HOPS = 12
STATUSES = {"answered", "negative", "timeout", "error", "unsupported"}


def normalize_cname_host(value: object) -> str | None:
    """Accept absolute DNS names without making guesses about IDNA mappings."""
    if not isinstance(value, str) or len(value) > 254:
        return None
    if not value.isascii():
        value = unicodedata.normalize("NFC", value.lower())
        try:
            ascii_name = value.encode("idna")
            if ascii_name.decode("idna") != value:
                return None
            value = ascii_name.decode("ascii")
        except UnicodeError:
            return None
    return dns_name(value, dotted=True)


def _uint32(value: object) -> bool:
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def _inspect_family(host: str, query_type: str, rows: list[dict], policy: Policy) -> dict:
    result = {"query_type": query_type, "status": "error", "chain": [], "terminal": None,
              "interface_index": None, "complete": False, "issue": None}
    if len(rows) != 1:
        return dict(result, issue="duplicate-observation" if rows else "missing-observation")
    observation = rows[0]
    status = observation.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        return dict(result, issue="invalid-observation")
    result["status"] = status
    aliases = observation.get("aliases")
    terminals = observation.get("terminal_names")
    if not isinstance(aliases, list) or not isinstance(terminals, list):
        return dict(result, issue="invalid-observation")
    if len(aliases) + len(terminals) > MAX_RECORDS:
        return dict(result, issue="record-limit")

    edges = {}
    for record in aliases:
        if not isinstance(record, dict):
            return dict(result, issue="invalid-observation")
        owner = dns_name(record.get("owner"), dotted=True)
        target = dns_name(record.get("target"), dotted=True)
        ttl = record.get("ttl")
        interface = record.get("interface_index")
        if owner is None or target is None or not _uint32(ttl) or not _uint32(interface):
            return dict(result, issue="invalid-observation")
        key = (target, interface)
        choices = edges.setdefault(owner, {})
        choices[key] = min(ttl, choices.get(key, ttl))

    terminal_names = {dns_name(name, dotted=True) for name in terminals}
    if None in terminal_names or (status == "negative" and terminal_names):
        return dict(result, issue="invalid-observation")
    current = host
    seen = {host}
    interface = None
    while choices := edges.get(current):
        if current in terminal_names:
            return dict(result, issue="alias-and-terminal")
        if len(choices) > 1:
            issue = "fork" if len({target for target, _ in choices}) > 1 else "mixed-interface"
            return dict(result, issue=issue)
        (target, next_interface), ttl = next(iter(choices.items()))
        if interface is not None and next_interface != interface:
            return dict(result, issue="mixed-interface")
        if target in seen:
            return dict(result, issue="cycle")
        if len(result["chain"]) == MAX_HOPS:
            return dict(result, issue="hop-limit")
        result["chain"].append({"owner": current, "target": target, "ttl": ttl,
                                "interface_index": next_interface, "policy": policy.decision(target)})
        seen.add(target)
        current = target
        interface = next_interface

    if status == "negative":
        return dict(result, interface_index=interface, complete=True)
    if status != "answered":
        if observation.get("error") == "mixed-interface":
            return dict(result, issue="mixed-interface")
        return dict(result, issue=status)
    if current not in terminal_names:
        return dict(result, issue="missing-terminal")
    reported_interface = observation.get("interface_index", interface)
    if reported_interface is not None and not _uint32(reported_interface):
        return dict(result, issue="invalid-observation")
    if interface is not None and interface != reported_interface:
        return dict(result, issue="mixed-interface")
    return dict(result, terminal=current, interface_index=reported_interface, complete=True)


def inspect_answers(host: str, observations: list[dict], policy: Policy) -> dict:
    """Describe independent policy decisions for the original name and CNAME hops."""
    host = normalize_cname_host(host)
    if host is None:
        raise ValueError("CNAME inspection requires a valid, fully qualified DNS hostname")
    rows = {query_type: [] for query_type in QUERY_TYPES}
    invalid = not isinstance(observations, list) or len(observations) > len(QUERY_TYPES)
    if not invalid:
        for observation in observations:
            name = observation.get("query_type") if isinstance(observation, dict) else None
            if not isinstance(name, str) or name not in rows:
                invalid = True
                continue
            rows[name].append(observation)
    families = [_inspect_family(host, name, rows[name], policy) for name in QUERY_TYPES]
    complete = not invalid and all(family["complete"] for family in families)
    issues = {
        family["issue"] for family in families
        if family["issue"] in {"fork", "cycle", "mixed-interface", "alias-and-terminal", "duplicate-observation"}
    }
    if invalid:
        issues.add("invalid-observations")
    answered = [family for family in families if family["complete"] and family["status"] == "answered"]
    if complete:
        paths = [tuple(hop["target"] for hop in family["chain"]) for family in families
                 if family["status"] == "answered" or family["chain"]]
        if len(set(paths)) > 1:
            issues.add("divergent-families")
        interfaces = {family["interface_index"] for family in families} - {None}
        if len(interfaces) > 1:
            issues.add("mixed-interface")
    policy_ready = policy.ready()
    return {"host": host, "original_policy": policy.decision(host), "policy_ready": policy_ready,
            "live_policy_unchanged": True, "families": families, "complete": complete,
            "ambiguous": bool(issues), "ambiguity": sorted(issues),
            "indeterminate": not complete or not answered or bool(issues) or not policy_ready}
