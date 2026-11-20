"""A bounded asynchronous SQLite ledger containing domain-level metadata.

History modes (``[logging] history``):

* ``full``      one row per decision (timestamp, hostname, decision, reason, transport).
* ``aggregate`` per-UTC-day counts by decision and reason. Allowed traffic is stored with no
                hostname. Blocked traffic keeps its hostname as a per-day count, with no
                per-event timestamp.
* ``none``      no traffic rows are written; only in-memory counters exist for this process.

Switching modes never deletes existing rows: an ``events`` table written under ``full`` stays in
the database file, untouched and unread, until the user deletes it or the file. Deleting rows or
the file is ordinary deletion, not secure erasure. Request bodies, cookies and authorization
values are never passed to this module. The only other stored value is a drop counter.
"""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from egress_guard.policy import normalize_host

SOURCES = frozenset({
    "invalid-host", "invalid-request", "threat-intel", "local-block", "tracker-feed",
    "cname-feed", "tracker-paused", "local-allow", "temporary-exception",
    "dashboard-exception", "no-match", "plaintext-credentials", "not-ready",
    "non-tls-tunnel",
})
MAX_QUEUE = 2048
MAX_EVENTS = 10_000
BATCH_SIZE = 128
HISTORY_MODES = ("full", "aggregate", "none")


class Ledger:
    def __init__(self, path: Path, *, max_queue: int = MAX_QUEUE, retention_days: int = 7,
                 history: str = "full") -> None:
        self.path = path
        if not 1 <= max_queue <= 10_000 or not 1 <= retention_days <= 30 or history not in HISTORY_MODES:
            raise ValueError("invalid ledger bounds")
        self.history = history
        self._counter_lock = threading.Lock()
        self._dropped = 0
        self._dropped_saved = -1
        self._counts: dict[tuple[str, str], int] = {}
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
            with self._counter_lock:
                self._counts[(decision, source)] = self._counts.get((decision, source), 0) + 1
            if self.history == "none":
                return True
            try:
                self._queue.put_nowait((int(time.time()), hostname, decision, source, transport))
            except queue.Full:
                # Count only; the dropped event itself is not kept anywhere.
                with self._counter_lock:
                    self._dropped += 1
                return False
        return True

    def status(self) -> dict:
        with self._counter_lock:
            return {"history": self.history, "dropped": self._dropped,
                    "decisions": sum(self._counts.values())}

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
                connection.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute("INSERT OR REPLACE INTO meta VALUES ('history', ?)", (self.history,))
                self._dropped_saved = -1
                if self.history == "aggregate":
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS daily (
                            day INTEGER NOT NULL, host TEXT NOT NULL, decision TEXT NOT NULL,
                            source TEXT NOT NULL, count INTEGER NOT NULL,
                            PRIMARY KEY (day, host, decision, source)
                        )
                    """)
                if self.history != "full":
                    return connection
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

    def _save_dropped(self, connection: sqlite3.Connection) -> None:
        # The dashboard runs in another process, so the counter is mirrored into the database.
        with self._counter_lock:
            value = self._dropped
        if value != self._dropped_saved:
            with connection:
                connection.execute("INSERT OR REPLACE INTO meta VALUES ('dropped', ?)", (str(value),))
            self._dropped_saved = value

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
                            cutoff = int(now - self._retention_seconds)
                            if self.history == "full":
                                connection.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                            elif self.history == "aggregate":
                                connection.execute("DELETE FROM daily WHERE day < ?", (cutoff // 86400 * 86400,))
                        next_sweep = now + 60
                    self._save_dropped(connection)
                    self._ready.set()
                    if not pending:
                        pending = self._take_batch()
                    if pending and self.history == "aggregate":
                        with connection:
                            for ts, host, decision, source, _transport in pending:
                                connection.execute(
                                    "INSERT INTO daily VALUES (?,?,?,?,1) ON CONFLICT(day,host,decision,source) "
                                    "DO UPDATE SET count = count + 1",
                                    (ts // 86400 * 86400, host if decision == "blocked" else "", decision, source),
                                )
                            connection.execute("""
                                DELETE FROM daily WHERE rowid IN (
                                    SELECT rowid FROM daily ORDER BY day DESC LIMIT -1 OFFSET ?
                                )
                            """, (MAX_EVENTS,))
                        pending = []
                    elif pending:
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


def read_activity(path: Path, limit: int = 50) -> dict:
    """Read recent activity for the dashboard from whichever mode wrote the database."""
    def iso(value: int) -> str:
        return datetime.fromtimestamp(value, timezone.utc).isoformat()

    result: dict = {"events": [], "limit": limit, "history": "full", "dropped": 0}
    if not path.is_file() or path.is_symlink():
        return result
    with sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=0.25) as connection:
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall()) \
            if connection.execute("SELECT 1 FROM sqlite_master WHERE name='meta'").fetchone() else {}
        history = meta.get("history") if meta.get("history") in HISTORY_MODES else "full"
        result["history"] = history
        result["dropped"] = int(meta["dropped"]) if str(meta.get("dropped", "")).isdigit() else 0
        if history == "full":
            rows = connection.execute("SELECT ts,host,decision,source FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            result["events"] = [{"at": iso(r[0]), "host": r[1], "decision": r[2], "reason": r[3]} for r in rows]
        elif history == "aggregate":
            rows = connection.execute(
                "SELECT day,host,decision,source,count FROM daily ORDER BY day DESC, count DESC LIMIT ?", (limit,)).fetchall()
            result["events"] = [{"at": iso(r[0]), "host": r[1], "decision": r[2], "reason": r[3],
                                 "count": r[4], "day_only": True} for r in rows]
    return result
