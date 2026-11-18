"""A bounded asynchronous SQLite ledger containing domain-level metadata."""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from pathlib import Path

from egress_guard.policy import normalize_host

SOURCES = frozenset({
    "invalid-host", "invalid-request", "threat-intel", "local-block", "tracker-feed",
    "cname-feed", "tracker-paused", "local-allow", "temporary-exception",
    "dashboard-exception", "no-match", "plaintext-credentials", "not-ready",
})
MAX_QUEUE = 2048
MAX_EVENTS = 10_000
BATCH_SIZE = 128


class Ledger:
    def __init__(self, path: Path, *, max_queue: int = MAX_QUEUE, retention_days: int = 7) -> None:
        self.path = path
        if not 1 <= max_queue <= 10_000 or not 1 <= retention_days <= 30:
            raise ValueError("invalid ledger bounds")
        self._retention_seconds = retention_days * 86400
        self._queue: queue.Queue[tuple] = queue.Queue(max_queue)
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._admission = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="egress-guard-ledger", daemon=True)
        self._thread.start()

    def ready(self) -> bool:
        return self._ready.is_set() and not self._stop.is_set()

    def record(self, host: str, decision: str, source: str, transport: str) -> bool:
        # Never accept arbitrary strings for auxiliary fields or retain an unparseable host.
        hostname = normalize_host(host)
        if hostname is None or decision not in {"allowed", "blocked"} or source not in SOURCES:
            return False
        if transport not in {"http", "connect"}:
            return False
        with self._admission:
            if self._stop.is_set():
                return False
            try:
                self._queue.put_nowait((int(time.time()), hostname, decision, source, transport))
            except queue.Full:
                return False
        return True

    def close(self) -> None:
        with self._admission:
            self._stop.set()
        self._thread.join(timeout=2)

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=0.25)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        host TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        source TEXT NOT NULL,
                        transport TEXT NOT NULL
                    )
                """)
                connection.execute("SELECT id, ts, host, decision, source, transport FROM events LIMIT 0")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def _take_batch(self) -> list[tuple]:
        try:
            first = self._queue.get(timeout=0.1)
        except queue.Empty:
            return []
        rows = [first]
        for _ in range(BATCH_SIZE - 1):
            try:
                rows.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return rows

    def _run(self) -> None:
        connection = None
        pending: list[tuple] = []
        next_sweep = 0.0
        try:
            while not self._stop.is_set() or pending or not self._queue.empty():
                try:
                    if connection is None:
                        connection = self._open()
                    now = time.time()
                    if now >= next_sweep:
                        with connection:
                            connection.execute("DELETE FROM events WHERE ts < ?", (int(now - self._retention_seconds),))
                        next_sweep = now + 60
                    self._ready.set()
                    if not pending:
                        pending = self._take_batch()
                    if pending:
                        with connection:
                            connection.executemany(
                                "INSERT INTO events(ts,host,decision,source,transport) VALUES (?,?,?,?,?)",
                                pending,
                            )
                            connection.execute("""
                                DELETE FROM events WHERE id <= (
                                    SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?
                                )
                            """, (MAX_EVENTS,))
                        pending = []
                except (OSError, sqlite3.Error):
                    self._ready.clear()
                    if connection is not None:
                        connection.close()
                        connection = None
                    if self._stop.wait(0.25):
                        break
        finally:
            self._ready.clear()
            if connection is not None:
                connection.close()
