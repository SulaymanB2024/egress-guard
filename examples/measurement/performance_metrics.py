"""Fixed-size aggregate telemetry for the local guard's health response."""

from bisect import bisect_left
import os
import resource
import sys
from threading import Lock
from time import monotonic_ns, time


HISTORY_INTERVAL_SECONDS = 60
HISTORY_MAX_SAMPLES = 7 * 24 * 60
DOMAIN_SAMPLE_EVERY = 16
DOMAIN_BOUNDS_NS = (1_000, 4_000, 16_000, 64_000, 256_000, 1_000_000, 4_000_000)
IO_BOUNDS_NS = (
    100_000, 500_000, 1_000_000, 5_000_000, 10_000_000, 50_000_000, 100_000_000,
    250_000_000, 500_000_000, 750_000_000, 1_000_000_000, 5_000_000_000, 10_000_000_000,
)


class Latency:
    """Noncumulative buckets with inclusive upper bounds and a final overflow."""

    def __init__(self, upper_bounds):
        self.upper_bounds = upper_bounds
        self.counts = [0] * (len(upper_bounds) + 1)
        self.maximum = None

    def record(self, elapsed_ns):
        self.counts[bisect_left(self.upper_bounds, elapsed_ns)] += 1
        if self.maximum is None or self.maximum < elapsed_ns:
            self.maximum = elapsed_ns

    def snapshot(self):
        return {"upper_bounds": self.upper_bounds, "counts": list(self.counts), "max": self.maximum}


class DomainFilterMetrics:
    def __init__(self):
        self.decisions = 0
        self.blocked = 0
        self.elapsed = Latency(DOMAIN_BOUNDS_NS)

    def evaluate(self, decide, host, process):
        if self.decisions % DOMAIN_SAMPLE_EVERY == 0:
            started = monotonic_ns()
            match = decide(host, process)
            self.elapsed.record(monotonic_ns() - started)
        else:
            match = decide(host, process)
        self.decisions += 1
        if match:
            self.blocked += 1
        return match

    def snapshot(self):
        return {"decisions": self.decisions, "blocked": self.blocked, "elapsed_ns": self.elapsed.snapshot()}


class GuardMetrics:
    # These counters are owned by the guard's event-loop thread.
    def __init__(self):
        self.pid = os.getpid()
        self.started_at = time()
        self.started_ns = monotonic_ns()
        self.client_opened = 0
        self.client_closed = 0
        self.proxy_connect_requests = 0
        self.upstream_connect_attempts = 0
        self.domain_filter = {
            hook: DomainFilterMetrics()
            for hook in ("dns_question", "tls_clienthello", "tls_failed_client", "upstream_connect", "http_admission")
        }
        self.reload_checks = 0
        self.reload_rebuilds = 0
        self.reload_rebuild_failures = 0
        self.reload_elapsed = Latency(IO_BOUNDS_NS)

    def snapshot(self, ledger):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        load = os.getloadavg()
        return {
            "version": 1,
            "pid": self.pid,
            "started_at_unix_s": self.started_at,
            "uptime_s": (monotonic_ns() - self.started_ns) / 1_000_000_000,
            "resources": {
                "cpu_user_s": usage.ru_utime, "cpu_system_s": usage.ru_stime,
                "peak_rss_bytes": usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024,
                "host_load_1m": load[0], "host_load_5m": load[1], "logical_cpus": os.cpu_count(),
            },
            "connections": {
                "client_opened": self.client_opened,
                "client_closed": self.client_closed,
                "proxy_connect_requests": self.proxy_connect_requests,
                "upstream_connect_attempts": self.upstream_connect_attempts,
            },
            "domain_filter": {
                "sample_every": DOMAIN_SAMPLE_EVERY,
                "by_hook": {hook: stats.snapshot() for hook, stats in self.domain_filter.items()},
            },
            "policy_reload": {
                "checks": self.reload_checks,
                "rebuilds": self.reload_rebuilds,
                "rebuild_failures": self.reload_rebuild_failures,
                "elapsed_ns": self.reload_elapsed.snapshot(),
            },
            "ledger": ledger,
        }


class LedgerMetrics:
    """Producer counters belong to the event loop; worker totals use one lock per batch or status probe."""

    def __init__(self):
        self.enqueued = 0
        self.dropped = 0
        self._lock = Lock()
        self._committed = 0
        self._batches = 0
        self._failures = 0
        self._retries = 0
        self._history_write_failures = 0
        self._domain_windows_dropped = 0
        self._transaction_elapsed = Latency(IO_BOUNDS_NS)
        self._batch_elapsed = Latency(IO_BOUNDS_NS)

    def failed(self):
        with self._lock:
            self._failures += 1

    def retrying(self):
        with self._lock:
            self._retries += 1

    def history_write_failed(self):
        with self._lock:
            self._history_write_failures += 1

    def domain_window_dropped(self):
        with self._lock:
            self._domain_windows_dropped += 1

    def committed(self, writes, elapsed_ns, batch_elapsed_ns):
        with self._lock:
            self._committed += writes
            self._batches += 1
            self._transaction_elapsed.record(elapsed_ns)
            self._batch_elapsed.record(batch_elapsed_ns)

    def snapshot(self, pending_queue):
        with self._lock:
            return {
                "queue_capacity": pending_queue.maxsize,
                "queue_depth": pending_queue.qsize(),
                "outstanding_writes": max(0, self.enqueued - self._committed),
                "enqueued_writes": self.enqueued,
                "committed_writes": self._committed,
                "dropped_writes": self.dropped,
                "storage_failures": self._failures,
                "retry_attempts": self._retries,
                "history_write_failures": self._history_write_failures,
                "domain_windows_dropped": self._domain_windows_dropped,
                "committed_batches": self._batches,
                "transaction_elapsed_ns": self._transaction_elapsed.snapshot(),
                "batch_elapsed_ns": self._batch_elapsed.snapshot(),
            }
