"""Bounded system-proxy verdict windows for the private traffic ledger."""

import re


MAX_KEYS_PER_WINDOW = 2_048
MAX_DETAIL_ROWS = 100_000
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
PRIVATE_SUFFIXES = (".local", ".localhost", ".localdomain", ".internal", ".lan", ".home.arpa", ".invalid", ".test")

SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_windows(
    id INTEGER PRIMARY KEY, started_at REAL NOT NULL, ended_at REAL NOT NULL,
    pid INTEGER NOT NULL, guard_started_at REAL NOT NULL,
    recorded INTEGER NOT NULL, overflow INTEGER NOT NULL, detail_rows INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS domain_windows_ended_at ON domain_windows(ended_at);
CREATE TABLE IF NOT EXISTS domain_counts(
    window_id INTEGER NOT NULL, host TEXT NOT NULL, event TEXT NOT NULL,
    decision TEXT NOT NULL, count INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS domain_counts_window_id ON domain_counts(window_id);
"""


class DomainRollups:
    """The event loop owns the active counts and swaps them at each capture."""

    def __init__(self):
        self.started_at = None
        self.counts = {}
        self.overflow = 0

    def record(self, host, event, blocked):
        if not isinstance(host, str) or event not in ("tls_handshake", "http_request"):
            return
        key = (host, event, "blocked" if blocked else "passed")
        count = self.counts.get(key)
        if count is not None:
            self.counts[key] = count + 1
            return
        if (len(host) > 253 or host.endswith(PRIVATE_SUFFIXES) or DOMAIN.fullmatch(host) is None):
            return
        if len(self.counts) < MAX_KEYS_PER_WINDOW:
            self.counts[key] = 1
        else:
            self.overflow += 1

    def finish_window(self, ended_at, pid, guard_started_at):
        started_at = self.started_at
        counts, overflow = self.counts, self.overflow
        self.started_at, self.counts, self.overflow = ended_at, {}, 0
        if started_at is not None and ended_at > started_at:
            return started_at, ended_at, pid, guard_started_at, counts, overflow
        return None


def store_window(db, window, max_windows):
    started_at, ended_at, pid, guard_started_at, counts, overflow = window
    with db:
        inserted = db.execute(
            """INSERT INTO domain_windows(started_at, ended_at, pid, guard_started_at, recorded, overflow, detail_rows)
               VALUES(?, ?, ?, ?, ?, ?, ?)""",
            (started_at, ended_at, pid, guard_started_at, sum(counts.values()), overflow, len(counts)),
        )
        window_id = inserted.lastrowid
        db.executemany(
            "INSERT INTO domain_counts(window_id, host, event, decision, count) VALUES(?, ?, ?, ?, ?)",
            ((window_id, *key, count) for key, count in counts.items()),
        )
        expired = "(ended_at < ? OR id <= ?)"
        limits = ended_at - 7 * 86400, window_id - max_windows
        db.execute(f"DELETE FROM domain_counts WHERE window_id IN (SELECT id FROM domain_windows WHERE {expired})", limits)
        db.execute(f"DELETE FROM domain_windows WHERE {expired}", limits)

        excess = db.execute("SELECT COALESCE(SUM(detail_rows), 0) FROM domain_windows").fetchone()[0] - MAX_DETAIL_ROWS
        if excess > 0:
            # Trim whole oldest windows so counts and coverage always agree.
            for oldest_id, rows in db.execute("SELECT id, detail_rows FROM domain_windows ORDER BY id"):
                excess -= rows
                if excess <= 0:
                    break
            db.execute("DELETE FROM domain_counts WHERE window_id <= ?", (oldest_id,))
            db.execute("DELETE FROM domain_windows WHERE id <= ?", (oldest_id,))
