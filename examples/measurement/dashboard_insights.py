"""Bounded local summaries of guard timings and recorded domain decisions."""

from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
import threading
import time

HOURS = (1, 24, 168)
HOST_LIMIT = 2000
QUERY_SECONDS = .6


def nonnegative(value):
    return value if type(value) is int and value >= 0 else 0


def moment(value):
    return value if type(value) in (float, int) and math.isfinite(value) and value > 0 else None


def histogram(value):
    """Return sampled upper quantiles; never reinterpret a bucket as an average."""
    if not isinstance(value, dict):
        return {"samples": 0, "p50_upper_ns": None, "p95_upper_ns": None, "max_ns": None}
    bounds, counts = value.get("upper_bounds"), value.get("counts")
    if (not isinstance(bounds, list) or not isinstance(counts, list) or len(bounds) > 32
            or len(counts) != len(bounds) + 1
            or any(type(item) is not int or item < 0 for item in [*bounds, *counts])
            or any(a >= b for a, b in zip(bounds, bounds[1:]))):
        return histogram(None)
    samples = sum(counts)
    maximum = value.get("max")
    maximum = maximum if type(maximum) is int and maximum >= 0 and samples else None

    def quantile(fraction):
        if not samples:
            return None
        target, cumulative = math.ceil(samples * fraction), 0
        for index, number in enumerate(counts):
            cumulative += number
            if cumulative >= target:
                return bounds[index] if index < len(bounds) else maximum
        return None

    return {"samples": samples, "p50_upper_ns": quantile(.5),
            "p95_upper_ns": quantile(.95), "max_ns": maximum}


class HealthCache:
    """Cache readings from a caller-provided, authenticated reader."""

    def __init__(self, reader, ports, ttl=5, clock=time.monotonic):
        self.reader, self.ttl, self.clock = reader, ttl, clock
        self.cells = {}
        self.locks = {port: threading.Lock() for port in ports}

    def read(self, port):
        if port not in self.locks:
            return {"ready": False}
        with self.locks[port]:
            cached = self.cells.get(port)
            if cached and self.clock() - cached[0] < self.ttl:
                return cached[1]
            value = self.reader(port)
            self.cells[port] = self.clock(), value
            return value


class Insights:
    def __init__(self, state, host_filter, health_reader, attribution=None, clock=time.time):
        self.state, self.host_filter = Path(state), host_filter
        self.health_reader, self.clock = health_reader, clock
        self.attribution = attribution
        self.cache = {}
        self.lock = threading.Lock()

    def lookup(self, host):
        attribution = self.attribution
        if attribution:
            return attribution.lookup(host)
        return {"owner": None, "matched_domain": None, "classification": "unknown",
                "categories": [], "match": None, "evidence": None,
                "reason": "Owner metadata is not available."}

    def _cached(self, key, loader, seconds):
        with self.lock:
            now = self.clock()
            cached = self.cache.get(key)
            if cached and 0 <= now - cached[0] < seconds:
                return cached[1]
            started = time.monotonic()
            result = loader(now)
            result["summary_time_ms"] = round((time.monotonic() - started) * 1000, 3)
            self.cache[key] = now, result
            return result

    def _database(self):
        db = sqlite3.connect((self.state / "ledger.sqlite3").resolve().as_uri() + "?mode=ro",
                             uri=True, timeout=.2)
        deadline = time.monotonic() + QUERY_SECONDS
        db.execute("PRAGMA query_only=ON")
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 2500)
        return db

    def intelligence(self, hours=24):
        if type(hours) is not int or hours not in HOURS:
            raise ValueError("Choose the last hour, day, or seven days.")
        return self._cached(("intelligence", hours), lambda now: self._intelligence(now, hours), 15)

    def _intelligence(self, now, hours):
        attribution = self.attribution
        source = attribution.source() if attribution else None
        report = {
            "available": False, "state": "collecting", "checked_at": now,
            "window": {"from": None, "to": None, "kind": "recorded_windows", "requested_hours": hours},
            "units": "Guard-visible TLS handshake decisions and plaintext HTTP requests",
            "totals": dict.fromkeys(("events", "matched", "blocked", "allowed", "observed", "unmatched", "owner_known", "other"), 0),
            "owners": [], "unattributed": [], "sources": [source] if source else [],
            "coverage": {"events_recorded": 0, "events_analyzed": 0, "domains_recorded": 0,
                         "domains_analyzed": 0, "overflow_events": 0, "truncated": False,
                         "gaps": 0, "hidden_domains": 0, "owners_total": 0, "owners_shown": 0},
            "origin_app": "unknown", "origin_site": "unknown",
        }
        try:
            with closing(self._database()) as db:
                if not db.execute("SELECT 1 FROM sqlite_master WHERE name='domain_windows'").fetchone():
                    return report
                where = "w.started_at >= ? AND w.ended_at <= ?"
                params = now - hours * 3600, now
                windows = db.execute(
                    "SELECT started_at,ended_at,recorded,overflow FROM domain_windows w WHERE " + where +
                    " ORDER BY started_at LIMIT 10080", params).fetchall()
                if not windows:
                    return report
                domains = db.execute(
                    "SELECT COUNT(DISTINCT c.host) FROM domain_counts c JOIN domain_windows w ON w.id=c.window_id WHERE " + where,
                    params).fetchone()[0]
                rows = db.execute(
                    "SELECT c.host,SUM(c.count) AS events,"
                    "SUM(CASE WHEN c.decision='blocked' THEN c.count ELSE 0 END),"
                    "SUM(CASE WHEN c.decision='passed' THEN c.count ELSE 0 END),"
                    "SUM(CASE WHEN c.event='tls_handshake' THEN c.count ELSE 0 END),"
                    "SUM(CASE WHEN c.event='http_request' THEN c.count ELSE 0 END) "
                    "FROM domain_counts c JOIN domain_windows w ON w.id=c.window_id WHERE " + where +
                    " GROUP BY c.host ORDER BY events DESC,c.host LIMIT ?", (*params, HOST_LIMIT + 1)).fetchall()
        except sqlite3.Error:
            report.update(state="unavailable")
            return report

        coverage = report["coverage"]
        coverage.update(events_recorded=sum(nonnegative(row[2]) for row in windows),
                        overflow_events=sum(nonnegative(row[3]) for row in windows),
                        domains_recorded=nonnegative(domains), truncated=len(rows) > HOST_LIMIT)
        coverage["gaps"] = sum(later[0] > earlier[1] + 5 for earlier, later in zip(windows, windows[1:]))
        report["window"].update({"from": windows[0][0], "to": windows[-1][1]})
        report.update(available=True, state="available")
        owners = {}
        totals = report["totals"]
        for host, events, blocked, passed, tls, http in rows[:HOST_LIMIT]:
            host = self.host_filter(host)
            if not host:
                coverage["hidden_domains"] += 1
                continue
            events, blocked, passed = map(nonnegative, (events, blocked, passed))
            coverage["domains_analyzed"] += 1
            coverage["events_analyzed"] += events
            totals["events"] += events
            detail = self.lookup(host)
            owner = detail.get("owner")
            listed = detail.get("classification") == "listed_tracker"
            if owner:
                totals["owner_known"] += events
            else:
                totals["unmatched"] += events
                if len(report["unattributed"]) < 12:
                    report["unattributed"].append({"host": host, "events": events, "blocked": blocked, "allowed": passed})
            if not listed or not owner:
                totals["other"] += events
                continue
            totals["matched"] += events
            totals["blocked"] += blocked
            totals["allowed"] += passed
            row = owners.setdefault(owner, {"owner": owner, "matched": 0, "blocked": 0, "allowed": 0,
                                             "observed": 0, "domains": []})
            row["matched"] += events
            row["blocked"] += blocked
            row["allowed"] += passed
            row["domains"].append({"host": host, "matched": events, "blocked": blocked, "allowed": passed,
                                   "observed": 0, "categories": detail.get("categories", []),
                                   "matched_domain": detail.get("matched_domain"), "evidence": detail.get("evidence"),
                                   "reason": detail.get("reason", ""), "tls_handshakes": nonnegative(tls),
                                   "http_requests": nonnegative(http)})
        ranked = sorted(owners.values(), key=lambda row: (-row["matched"], row["owner"]))
        coverage.update(owners_total=len(ranked), owners_shown=min(20, len(ranked)))
        for row in ranked:
            row["domains_count"] = len(row["domains"])
            row["domains"] = sorted(row["domains"], key=lambda item: (-item["matched"], item["host"]))[:20]
        report["owners"] = ranked[:20]
        return report

    def performance(self):
        return self._cached("performance", self._performance, 5)

    def _performance(self, now):
        health = self.health_reader()
        # A verified 503 can still explain why the guard is not ready.
        current = health.get("performance")
        report = {"state": "collecting", "checked_at": now, "started_at": None,
                  "window": {"from": now - 3600, "to": now}, "connections": {}, "timing": [],
                  "ledger": {}, "resources": {}, "points": [], "timing_period": None,
                  "proxy_ready": health.get("ready") is True,
                  "collection": {"snapshot_interval_s": 60, "retention_days": 7, "sample_every": 16}}
        if not isinstance(current, dict) or current.get("version") != 1 or not moment(current.get("started_at_unix_s")):
            report["state"] = "collecting" if health.get("ready") else "unavailable"
            return report
        started = current["started_at_unix_s"]
        report.update(state="available", started_at=started, pid=current.get("pid"),
                      timing_period={"from": started, "to": now, "kind": "since_restart"})
        resources = current.get("resources", {})
        report["resources"] = {key: value for key, value in resources.items()
                               if key in {"cpu_user_s", "cpu_system_s", "peak_rss_bytes", "host_load_1m", "host_load_5m", "logical_cpus"}
                               and type(value) in (int, float) and math.isfinite(value) and value >= 0}
        connections = current.get("connections", {})
        report["connections"] = {
            "connect_requests": nonnegative(connections.get("proxy_connect_requests")),
            "upstream_attempts": nonnegative(connections.get("upstream_connect_attempts")),
            "client_opened": nonnegative(connections.get("client_opened")),
            "client_closed": nonnegative(connections.get("client_closed")),
        }
        ledger = current.get("ledger", {})
        report["ledger"] = {key: nonnegative(ledger.get(key)) for key in (
            "queue_depth", "queue_capacity", "outstanding_writes", "committed_writes", "dropped_writes",
            "storage_failures", "retry_attempts", "committed_batches", "history_write_failures", "domain_windows_dropped")}
        domain = current.get("domain_filter", {})
        report["collection"]["sample_every"] = nonnegative(domain.get("sample_every"))
        for name, values in domain.get("by_hook", {}).items():
            report["timing"].append({"label": name.replace("_", " "), "sampled": True,
                                     **histogram(values.get("elapsed_ns"))})
        for name, value in (("policy reload", current.get("policy_reload", {}).get("elapsed_ns")),
                            ("ledger transaction", ledger.get("transaction_elapsed_ns")),
                            ("ledger batch to commit", ledger.get("batch_elapsed_ns"))):
            report["timing"].append({"label": name, "sampled": False, **histogram(value)})
        try:
            with closing(self._database()) as db:
                history = db.execute(
                    "SELECT captured_at,snapshot FROM performance_samples "
                    "WHERE captured_at >= ? AND captured_at <= ? AND length(snapshot)<=8192 "
                    "ORDER BY captured_at LIMIT 10080", (now - 3600, now)).fetchall()
        except sqlite3.Error:
            return report
        previous = None
        for at, raw in history:
            try:
                sample = json.loads(raw)
                identity = sample["pid"], sample["started_at_unix_s"]
                count = sample["connections"]["proxy_connect_requests"]
                if not moment(at) or type(count) is not int or count < 0:
                    continue
            except (ValueError, TypeError, KeyError):
                continue
            point = {"at": at, "from": None, "interval_s": None, "proxy_connect_per_minute": None, "break_before": True}
            if previous:
                prior_at, prior_identity, prior_count = previous
                elapsed = at - prior_at
                if identity == prior_identity and 0 < elapsed <= 150 and count >= prior_count:
                    point.update({"from": prior_at, "interval_s": elapsed,
                                  "proxy_connect_per_minute": (count - prior_count) * 60 / elapsed,
                                  "break_before": False})
            report["points"].append(point)
            previous = at, identity, count
        return report
