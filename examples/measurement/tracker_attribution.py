"""Offline reference matcher for caller-supplied, trusted domain metadata."""
from functools import lru_cache
import re

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
OPAQUE = re.compile(r"[a-z0-9-]{24,}")
PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".invalid", ".test")
TRACKER_CATEGORIES = {"Advertising", "Analytics", "Email", "FingerprintingInvasive", "FingerprintingGeneral"}


def _hostname(value):
    if not isinstance(value, str) or not value or len(value) > 254:
        return None
    try:
        host = value.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or labels[-1].isdigit():
        return None
    return host if all(LABEL.fullmatch(label) for label in labels) else None


def _unknown(reason):
    return {"owner": None, "matched_domain": None, "classification": "unknown",
            "categories": [], "match": None, "evidence": [], "reason": reason}


class AttributionIndex:
    """Match an exact hostname or its eligible ancestors up to a public suffix."""

    def __init__(self, entries, suffix_lookup, source, *, shared_boundaries=()):
        self._suffix_lookup = suffix_lookup
        self._source = dict(source)
        self._shared_boundaries = frozenset(shared_boundaries)
        self._domains = {}
        for domain, owner, category, evidence in entries:
            domain = _hostname(domain)
            if domain is None:
                continue
            owners = self._domains.setdefault(domain, {})
            categories, provenance = owners.setdefault(owner, (set(), set()))
            if category:
                categories.add(category)
            provenance.add(evidence)
        self._cached_match = lru_cache(maxsize=2048)(self._match)

    def source(self):
        return {**self._source, "entries": len(self._domains)}

    def lookup(self, hostname):
        host = _hostname(hostname)
        if (host is None or host.endswith(PRIVATE_SUFFIXES)
                or any(OPAQUE.fullmatch(label) for label in host.split(".")[:-1])):
            return _unknown("invalid_or_private_host")
        row = self._cached_match(host)
        return {**row, "categories": list(row["categories"]), "evidence": list(row["evidence"])}

    def _match(self, host):
        suffix = self._suffix_lookup(host)
        if not suffix or not host.endswith("." + suffix):
            return _unknown("invalid_or_private_host")
        candidate = host
        while candidate != suffix:
            if candidate != host and candidate in self._shared_boundaries:
                break
            owners = self._domains.get(candidate)
            if owners:
                if len(owners) != 1:
                    return _unknown("ambiguous_owner")
                owner, (categories, evidence) = next(iter(owners.items()))
                tracker = "Content" not in categories and not TRACKER_CATEGORIES.isdisjoint(categories)
                return {"owner": owner, "matched_domain": candidate,
                        "classification": "listed_tracker" if tracker else "owner_only",
                        "categories": sorted(categories), "match": "exact" if candidate == host else "suffix",
                        "evidence": sorted(evidence), "reason": "listed"}
            candidate = candidate.split(".", 1)[1]
        return _unknown("unmatched")
