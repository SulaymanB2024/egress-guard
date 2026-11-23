"""Bounded, read-only candidate comparisons through the production host policy.

This is a saved-policy dry run. It neither observes traffic nor establishes that
the running proxy, a browser or every possible hostname has this behavior.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import time

from .bounded_json import loads as bounded_json
from . import feed_review
from .feeds import CachedFeed, ReviewedSnapshot, _installed, dns_name
from .policy import MAX_CONTROL_BYTES, MAX_EXCEPTION_SECONDS, Policy, normalize_host, policy_stamp


CORPUS_VERSION = 1
CORPUS_SHA256 = "4a552d749b7a1715069811a2bab5890f81953fee8404f181f0e98b614b738bf4"
MAX_CORPUS_BYTES = 64 * 1024
MAX_PUBLIC_HOSTS = 128
PROBE_PORT = 443
MAX_CONFIGURED_HOSTS = 128
MAX_CHANGED_ROOTS = 16
MAX_PROBES = 384
DESCENDANT_LABEL = "egress-guard-review."
DECISION_FIELDS = ("decision", "source", "category", "matched_domain", "can_allow")
SCOPE = ("One validated feed replacement under frozen saved settings and local rules, "
         "using production hostname Policy decisions at fixed port 443; no network requests. Not a whole-site, "
         "running-proxy, transport, DNS or browser qualification.")


def load_corpus() -> tuple[tuple, dict]:
    """Load the small packaged, digest-pinned public probe catalog."""
    raw = feed_review.read_regular(Path(__file__).with_name("feed-impact-probes.json"), MAX_CORPUS_BYTES)
    if raw is None or feed_review.digest(raw) != CORPUS_SHA256:
        raise ValueError("public probe corpus is missing or does not match its pinned digest")
    value = bounded_json(raw, limit=MAX_CORPUS_BYTES, depth_limit=6)
    if (not isinstance(value, dict) or set(value) != {"schema", "version", "scope", "probes"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["version"]) is not int or value["version"] != CORPUS_VERSION
            or value["scope"] != "hostname-policy; no network or transport qualification"
            or not isinstance(value["probes"], list) or not 1 <= len(value["probes"]) <= MAX_PUBLIC_HOSTS):
        raise ValueError("invalid public probe corpus")
    probes, hosts, contexts = [], set(), set()
    roles = {"tracker", "doh", "shared-service", "service-endpoint", "safety"}
    for probe in value["probes"]:
        if (not isinstance(probe, dict) or set(probe) != {"host", "port", "role", "descendants"}
                or not isinstance(probe["host"], str) or dns_name(probe["host"], dotted=True) != probe["host"]
                or probe["host"] in hosts
                or type(probe["port"]) is not int or probe["port"] != PROBE_PORT
                or not isinstance(probe["role"], str) or probe["role"] not in roles
                or type(probe["descendants"]) is not bool
                or probe["descendants"] != (probe["role"] in {"tracker", "shared-service"})):
            raise ValueError("invalid public probe context")
        host = probe["host"]
        hosts.add(host)
        contexts.add((host, PROBE_PORT))
        if probe["descendants"]:
            child = dns_name(DESCENDANT_LABEL + host)
            if child is None:
                raise ValueError("public probe descendant exceeds DNS bounds")
            contexts.add((child, PROBE_PORT))
        probes.append((host, "public-" + probe["role"], probe["descendants"]))
    return tuple(probes), {"version": CORPUS_VERSION, "sha256": CORPUS_SHA256,
                           "public_hosts": len(hosts), "public_contexts": len(contexts),
                           "synthetic_contexts": len(contexts) - len(hosts),
                           "port": PROBE_PORT, "network_requests": False,
                           "scope": value["scope"]}


def _cached(snapshot: ReviewedSnapshot) -> CachedFeed:
    return CachedFeed(snapshot.names, snapshot.metadata["sha256"],
                      snapshot.metadata["published_at"], snapshot.metadata["updated_at"])


def not_covered(reason: str) -> dict:
    return {"schema": 1, "status": "not-covered", "reason": reason,
            "scope": SCOPE, "corpus_version": CORPUS_VERSION,
            "expected_corpus_sha256": CORPUS_SHA256,
            "read_only": True, "runtime_acknowledged": False, "probes": [],
            "automatic_hold_reasons": []}


def file_stamp(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_mode


@dataclass(frozen=True)
class ConfigBinding:
    path: Path
    initial_stamp: tuple | None

    def stable(self) -> bool:
        try:
            return file_stamp(self.path) == self.initial_stamp
        except OSError:
            return False


def bind_config(config: dict, config_file: Path | None = None) -> tuple[dict, ConfigBinding | None]:
    """Bind supplied normalized settings to an explicit file before any download.

    Pure API callers may omit the path. Never guess or read another user's
    configuration merely because settings were supplied directly.
    """
    frozen = deepcopy(config)
    if config_file is None:
        return frozen, None
    from .config import load_config

    path = Path(config_file).expanduser().absolute()
    stamp = file_stamp(path)
    loaded = load_config(path)
    # Canonical JSON also distinguishes boolean/integer or integer/float values
    # that ordinary Python container equality can consider equivalent.
    try:
        matches = json.dumps(frozen, sort_keys=True, allow_nan=False) == json.dumps(loaded, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        matches = False
    binding = ConfigBinding(path, stamp)
    if not matches or not binding.stable():
        raise ValueError("configuration changed before the feed operation; reload settings and retry")
    return frozen, binding


class ComponentCache:
    """Reuse cold validation within one review/refresh, never persist a verdict.

    Only verified snapshots are retained, keyed by the fixed Feed and exact file
    observation. Failed reads are retried. Context-wide stamps still reject any
    replacement while a comparison is being assembled or used.
    """

    def __init__(self):
        self._entries = {}

    def read(self, state, feed):
        path = feed.path(state)
        stamp = file_stamp(path)
        key = (state, feed)
        cached = self._entries.get(key)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        installed = _installed(state, feed)
        snapshot = _cached(installed.verified) if installed.verified is not None else None
        result = installed.sha256, snapshot, installed.raw is not None and snapshot is None
        if snapshot is not None and file_stamp(path) == stamp:
            self._entries[key] = stamp, result
        else:
            self._entries.pop(key, None)
        return result


def attempt_summary(result: dict) -> dict:
    """Bounded public verdict for the refresh result, without configured domains."""
    signals = result.get("review_signals", {})
    expired = result.get("grant_expiry_counterfactual", {})
    return {"status": result["status"], "reason": result["reason"],
            "corpus_version": result["corpus_version"],
            "corpus": result.get("corpus"), "expected_corpus_sha256": CORPUS_SHA256,
            "before_revision": result.get("before", {}).get("revision"),
            "after_revision": result.get("after", {}).get("revision"),
            "new_critical_deny_count": len(signals.get("new_critical_denies", ())),
            "new_public_canary_allow_count": len(signals.get("new_public_canary_allows", ())),
            "without_temporary_grants": {
                "new_critical_deny_count": len(expired.get("new_critical_denies", ())),
                "new_public_canary_allow_count": len(expired.get("new_public_canary_allows", ()))},
            "automatic_hold_reasons": list(result["automatic_hold_reasons"]),
            "scope": "Bounded public probes for this update attempt; not a runtime acknowledgment."}


def _probes(policy: Policy, changed_roots, public_probes, corpus) -> tuple[list[dict], dict]:
    probes: dict[str, set[str]] = {}

    def add(host, origin, *, descendants=False):
        normalized = normalize_host(host)
        if normalized is None:
            return False
        inserted = normalized in probes or len(probes) < MAX_PROBES
        if inserted:
            probes.setdefault(normalized, set()).add(origin)
        if descendants and dns_name(normalized) is not None:
            child = dns_name(DESCENDANT_LABEL + normalized)
            if child is not None and (child in probes or len(probes) < MAX_PROBES):
                probes.setdefault(child, set()).add(origin + "-synthetic-descendant")
        return inserted

    for host, origin, descendants in public_probes:
        add(host, origin, descendants=descendants)
    public_count = len(probes)
    configured = sorted(policy.allow | policy.dashboard_hosts)
    configured_sampled = set()
    for host in configured[:MAX_CONFIGURED_HOSTS]:
        if host in policy.allow:
            if add(host, "configured-suffix-allow", descendants=True):
                configured_sampled.add(host)
        if host in policy.dashboard_hosts:
            if add(host, "configured-exact-exemption", descendants=True):
                configured_sampled.add(host)
    # Feed entry samples are public source material, never observed browsing.
    roots = sorted({host for host in changed_roots if isinstance(host, str)})[:MAX_CHANGED_ROOTS]
    for host in roots:
        add(host, "changed-entry", descendants=True)
    return ([{"host": host, "port": PROBE_PORT, "origins": sorted(origins)} for host, origins in probes.items()],
            {"maximum": MAX_PROBES, "configured_host_limit": MAX_CONFIGURED_HOSTS,
             "public_contexts_expected": corpus["public_contexts"], "public_contexts_evaluated": public_count,
             "public_contexts_omitted": corpus["public_contexts"] - public_count,
             "configured_hosts_available": len(configured),
             "configured_hosts_attempted": min(len(configured), MAX_CONFIGURED_HOSTS),
             "configured_hosts_sampled": len(configured_sampled),
             "configured_hosts_omitted": len(configured) - len(configured_sampled),
             "changed_root_limit": MAX_CHANGED_ROOTS,
             "synthetic_descendants": "String-only matching examples; no DNS or service requests are made."})


class ImpactContext:
    """Capture one saved baseline and compare candidates without rereading controls.

    Cold validation is deliberately stricter than the request hot path. A missing
    or corrupt selected component never becomes an empty verified comparison.
    Input stamps detect cooperative replacement during the capture/comparison;
    they are not an atomic filesystem snapshot or a same-user tamper boundary.
    """

    def __init__(self, state: Path, config: dict, *, evaluated_at: float | None = None,
                 component_cache: ComponentCache | None = None, config_binding: ConfigBinding | None = None):
        self.state = state
        self.evaluated_at = time.time() if evaluated_at is None else evaluated_at
        self._fixed_evaluation_time = evaluated_at is not None
        self.policy: Policy | None = None
        self.reason: str | None = None
        self.digests: dict[str, str | None] = {}
        self._components: dict[str, CachedFeed | None] = {}
        self._cache = component_cache or ComponentCache()
        self._invalid_component = False
        self.config_binding = config_binding
        self._stamp = self._observe()
        self._public_probes, self.corpus = (), None
        try:
            self._public_probes, self.corpus = load_corpus()
        except (OSError, ValueError, UnicodeError, RecursionError):
            self.reason = "invalid-probe-corpus"
            return
        try:
            # These are explicit policy controls, not activity/history files.
            # Preflight the bounded regular files before production Policy reads
            # them. A malformed control cannot silently qualify as an empty one.
            for name in ("block.txt", "allow.txt", "filter-controls.json", "tracker-exceptions.json"):
                raw = feed_review.read_regular(state / name, MAX_CONTROL_BYTES)
                if raw is not None and name.endswith(".json"):
                    value = bounded_json(raw, limit=MAX_CONTROL_BYTES, depth_limit=16)
                    if not isinstance(value, dict):
                        raise ValueError("invalid policy controls")
            self.policy = Policy(deepcopy(config), state, component_loader=self._load_component)
            if self._invalid_component:
                self.reason = "invalid-feed-input"
            elif not self.policy.ready() or self.policy.degraded():
                self.reason = "incomplete-feed-coverage"
        except (OSError, ValueError, UnicodeError, RecursionError):
            self.reason = "invalid-policy-input"
        self.stable()

    def _observe(self):
        return policy_stamp(self.config_binding.path if self.config_binding is not None else None, self.state)

    def _load_component(self, state, feed):
        if feed.id in self._components:
            return self._components[feed.id]
        try:
            digest, snapshot, invalid = self._cache.read(state, feed)
            self.digests[feed.id] = digest
            if invalid:
                self._invalid_component = True
        except (OSError, ValueError):
            self.digests[feed.id], snapshot = None, None
            self._invalid_component = True
        self._components[feed.id] = snapshot
        return snapshot

    def stable(self) -> bool:
        if self.config_binding is not None and not self.config_binding.stable():
            self.reason = "configuration-input-changed"
            return False
        if self._observe() != self._stamp:
            self.reason = "policy-inputs-changed"
            return False
        return True

    def compare(self, feed, candidate: ReviewedSnapshot, *, base_sha256: str | None,
                changed_roots=()) -> dict:
        """Compare a fully validated, transition-valid candidate against its base."""
        self.stable()
        if self.reason is not None:
            result = not_covered(self.reason)
            if self.policy is not None:
                result["before"] = self.policy.summary()
            result["corpus"] = self.corpus
            return result
        before = self.policy
        if before is None or feed.id not in {item.id for item in before.feeds}:
            return not_covered("feed-not-selected")
        if self.digests.get(feed.id) != base_sha256:
            return not_covered("base-does-not-match-captured-policy")
        after = before.preview_component(feed.id, _cached(candidate))
        if not after.ready() or after.degraded():
            return not_covered("incomplete-candidate-coverage")
        probes, limits = _probes(before, changed_roots, self._public_probes, self.corpus)
        if limits["public_contexts_omitted"]:
            return not_covered("public-probe-limit")
        instant = self.evaluated_at if self._fixed_evaluation_time else time.time()
        # Jump beyond EVERY captured expiry, including a far-future timestamp
        # that is not a valid grant now. Do not accidentally activate such a
        # value by merely adding 24 hours to the current instant.
        expired_at = max([instant + MAX_EXCEPTION_SECONDS,
                          *before.controls.values(), *before.exceptions.values()]) + 1
        counts = {field: 0 for field in DECISION_FIELDS}
        newly_blocked, newly_allowed = [], []
        critical_denies, canary_allows, configured_denies = [], [], []
        expired_critical_denies, expired_canary_allows = [], []
        public_probes = 0
        rows = []

        def decision(policy, host, at):
            return {key: value for key, value in policy.explain(host, PROBE_PORT, at=at).items() if key in DECISION_FIELDS}

        for probe in probes:
            host = probe["host"]
            old, new = decision(before, host, instant), decision(after, host, instant)
            changed = [key for key in DECISION_FIELDS if old[key] != new[key]]
            for key in changed:
                counts[key] += 1
            row = {**probe, "before": old, "after": new, "changed": changed}
            rows.append(row)
            origins = probe["origins"]
            critical = any(origin.startswith(("public-shared-service", "public-service-endpoint", "public-safety"))
                           for origin in origins)
            canary = any(origin.startswith(("public-tracker", "public-doh")) for origin in origins)
            if critical or canary:
                public_probes += 1
                expired_old = decision(before, host, expired_at)
                expired_new = decision(after, host, expired_at)
                row["without_temporary_grants"] = {
                    "before": expired_old, "after": expired_new,
                    "changed": [key for key in DECISION_FIELDS if expired_old[key] != expired_new[key]]}
                if critical and expired_old["decision"] == "allowed" and expired_new["decision"] == "blocked":
                    expired_critical_denies.append(host)
                if canary and expired_old["decision"] == "blocked" and expired_new["decision"] == "allowed":
                    expired_canary_allows.append(host)
            if old["decision"] == "allowed" and new["decision"] == "blocked":
                newly_blocked.append(host)
                if critical:
                    critical_denies.append(host)
                if any(origin.startswith("configured-") for origin in origins):
                    configured_denies.append(host)
            if old["decision"] == "blocked" and new["decision"] == "allowed":
                newly_allowed.append(host)
                if canary:
                    canary_allows.append(host)
        if not self.stable():
            return not_covered(self.reason or "policy-inputs-changed")
        hold_reasons = []
        if critical_denies or expired_critical_denies:
            hold_reasons.append("policy-critical-deny")
        if canary_allows or expired_canary_allows:
            hold_reasons.append("policy-canary-allow")
        return {"schema": 1, "status": "compared", "reason": None, "scope": SCOPE,
                "corpus_version": CORPUS_VERSION, "evaluated_at": instant,
                "corpus": self.corpus,
                "read_only": True, "runtime_acknowledged": False, "input_stamps_unchanged": True,
                "configuration_bound": self.config_binding is not None,
                "settings_scope": (
                    "The caller's actual configuration file matched normalized settings at operation start and remains unchanged."
                    if self.config_binding is not None else
                    "Explicitly supplied settings frozen in memory; no configuration file was read or attested."),
                "base_snapshot_sha256": base_sha256, "candidate_snapshot_sha256": candidate.sha256,
                "before": before.summary(), "after": after.summary(), "limits": limits,
                "probes_evaluated": len(rows), "changed_probes": sum(bool(row["changed"]) for row in rows),
                "changed_fields": counts, "newly_blocked": newly_blocked, "newly_allowed": newly_allowed,
                "review_signals": {"new_critical_denies": critical_denies,
                                   "new_public_canary_allows": canary_allows,
                                   "new_configured_allow_denies": configured_denies},
                "grant_expiry_counterfactual": {
                    "scope": ("All other captured settings, rules and feed bytes frozen; every captured temporary "
                              "grant expired. This is not a prediction of future feed validity or runtime behavior."),
                    "evaluated_at": expired_at, "probes_evaluated": public_probes,
                    "new_critical_denies": expired_critical_denies,
                    "new_public_canary_allows": expired_canary_allows},
                "automatic_hold_reasons": hold_reasons, "probes": rows}
