"""Read-only outcome summaries for the dashboard, computed from the local ledger.

Every number here is a count of rows the ledger actually holds. Nothing is estimated: the proxy
sees hostnames only (TLS is passed through), so there are no byte, page-load or time figures.

* ``full`` history gives hourly and daily series in local time, top hosts and recent threats.
* ``aggregate`` history only has per-UTC-day counts, so there is no hourly series and "today"
  means the current UTC day. Allowed traffic has no hostname there.
* ``none`` history stores nothing, so every figure is ``None``.

The ledger keeps at most ``ledger.MAX_EVENTS`` rows and ``retention_days`` of history; the
``coverage`` block says how far back the retained rows reach so the page can mark partial days.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import time
from urllib.parse import quote

from .ledger import HISTORY_MODES, MAX_EVENTS
from .policy import CATEGORIES as POLICY_CATEGORIES

# Block sources mapped to the categories the dashboard shows. Unknown or future sources fall back
# to "other" so a new ledger value never breaks the page.
CATEGORIES = {
    "threats": "Malware and phishing",
    "ads": "Ads and trackers",
    "cname": "Cloaked trackers (CNAME)",
    "doh": "Encrypted DNS servers",
    "manual": "Your block rules",
    "other": "Other protections",
}
# Dashboard category for each policy category (``policy.CATEGORIES`` maps every ledger source to one).
# Look-alike domains count as threats. Anything not listed here shows as "other".
_POLICY_TO_DASHBOARD = {
    "threat": "threats", "malware": "threats", "phishing": "threats", "lookalike": "threats",
    "ads-trackers": "ads", "cname-cloak": "cname", "doh": "doh", "manual": "manual",
}
SOURCE_CATEGORY = {
    source: _POLICY_TO_DASHBOARD.get(kind, "other") for source, kind in POLICY_CATEGORIES.items()
}
# Older ledgers may hold these shorter source names.
SOURCE_CATEGORY.update({
    "malware": "threats", "phishing": "threats", "tracker": "ads", "ads": "ads", "cname-cloak": "cname",
})
TOP_LIMIT = 8
THREAT_LIMIT = 5
DAYS = 7
SCAN_LIMIT = 200_000  # A safety bound well above the ledger's own row cap.


def category(source: object) -> str:
    return SOURCE_CATEGORY.get(source, "other") if isinstance(source, str) else "other"


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _empty_totals() -> dict:
    return {"blocked": 0, "allowed": 0}


def _base(history: str, now: float) -> dict:
    return {
        "history": history, "generated_at": _iso(now), "day_basis": "local", "dropped": 0,
        "coverage": {"oldest": None, "newest": None, "rows": 0, "row_cap": MAX_EVENTS, "capped": False},
        "today": None, "yesterday": None, "same_time_yesterday": None,
        "hourly": None, "daily": None,
        "categories": None, "top_blocked": None, "threats": None,
        "categories_list": [{"id": key, "label": label} for key, label in CATEGORIES.items()],
        "source_categories": dict(SOURCE_CATEGORY),
    }


def _categories(counts: dict) -> list[dict]:
    return [{"id": key, "blocked": counts.get(key, 0)} for key in CATEGORIES]


def read_insights(path: Path, now: float | None = None) -> dict:
    """Summarize the ledger at ``path`` without writing to it."""
    now = time.time() if now is None else now
    if not path.is_file() or path.is_symlink():
        result = _base("full", now)
        result.update(_zero_full(now))
        return result
    with sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=0.25) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall()) if "meta" in tables else {}
        history = meta.get("history") if meta.get("history") in HISTORY_MODES else "full"
        result = _base(history, now)
        result["dropped"] = int(meta["dropped"]) if str(meta.get("dropped", "")).isdigit() else 0
        if history == "full":
            result.update(_full(connection, now, meta) if "events" in tables else _zero_full(now))
        elif history == "aggregate":
            result.update(_aggregate(connection, now, meta) if "daily" in tables else _zero_aggregate(now))
        return result


def _local_midnight_ts(day) -> float:
    """Start of the local calendar ``day``, using the zone rules in force on that date."""
    return datetime(day.year, day.month, day.day).astimezone().timestamp()


def _windows(now: float):
    local_now = datetime.fromtimestamp(now).astimezone()
    today_date = local_now.date()
    dates = [today_date - timedelta(days=offset) for offset in range(DAYS - 1, -1, -1)]
    days = [_local_midnight_ts(day) for day in dates]
    hour = int(local_now.replace(minute=0, second=0, microsecond=0).timestamp())
    # Hour buckets are absolute 3600 s spans, so a 23 or 25 hour day never double counts or drops one.
    hours = [hour - offset * 3600 for offset in range(23, -1, -1)]
    return local_now, dates, days, hours


def _same_time_yesterday(local_now: datetime, yesterday_start: float) -> float:
    """Yesterday at the same wall-clock time as ``local_now`` (not 24 elapsed hours earlier)."""
    day = local_now.date() - timedelta(days=1)
    wall = datetime(day.year, day.month, day.day, local_now.hour, local_now.minute, local_now.second)
    return max(yesterday_start, wall.astimezone().timestamp())


def _number(value) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def _floor(meta: dict, oldest, now: float, capped: bool) -> float | None:
    """Earliest time the ledger can vouch for, or None when that is unknown."""
    created = _number(meta.get("created"))
    if created is None:
        created = oldest  # Ledgers made before the creation time was recorded.
    elif oldest is not None:
        created = min(created, oldest)
    if created is None:
        return None
    floor = float(created)
    retention = _number(meta.get("retention_days"))
    if retention and retention > 0:
        floor = max(floor, now - retention * 86400)
    if capped and oldest is not None:
        floor = max(floor, oldest)
    return floor


def _zero_full(now: float) -> dict:
    _, dates, days, hours = _windows(now)
    return {
        "today": {**_empty_totals(), "start": _iso(days[-1])},
        "yesterday": {**_empty_totals(), "complete": False},
        "same_time_yesterday": {**_empty_totals(), "complete": False},
        "hourly": [{"start": _iso(h), **_empty_totals(), "complete": False} for h in hours],
        "daily": [{"start": _iso(ts), "day": date.isoformat(), **_empty_totals(), "complete": False}
                  for ts, date in zip(days, dates)],
        "categories": {"today": _categories({}), "week": _categories({})},
        "top_blocked": {"today": [], "week": []},
        "threats": {"today": 0, "week": 0, "recent": []},
    }


def _full(connection: sqlite3.Connection, now: float, meta: dict) -> dict:
    local_now, dates, days, hours = _windows(now)
    result = _zero_full(now)
    week_start = int(days[0])
    today_start = int(days[-1])
    yesterday_start = int(days[-2])
    same_time_end = int(_same_time_yesterday(local_now, yesterday_start))

    oldest, newest, rows = connection.execute("SELECT MIN(ts), MAX(ts), COUNT(*) FROM events").fetchone()
    capped = rows >= MAX_EVENTS
    result["coverage"] = {"oldest": _iso(oldest) if oldest else None, "newest": _iso(newest) if newest else None,
                          "rows": rows, "row_cap": MAX_EVENTS, "capped": capped}
    # A period is complete only when the ledger existed, kept history that long, and (when capped)
    # still holds rows reaching back to its start.
    floor = _floor(meta, oldest, now, capped)
    reaches = lambda start: floor is not None and floor <= start

    # Hourly buckets, aligned to the local hour, cover the whole week; days are sums of hours.
    # Align the origin to the hour grid and put it at or before the start of the week.
    gap = max(0, hours[0] - week_start)
    origin = hours[0] - (gap + 3599) // 3600 * 3600
    buckets: dict[int, dict] = {}
    category_today: dict[str, int] = {}
    category_week: dict[str, int] = {}
    query = """SELECT (ts - ?) / 3600 AS bucket, decision, source, COUNT(*) FROM events
               WHERE ts >= ? AND ts <= ? GROUP BY bucket, decision, source LIMIT ?"""
    for bucket, decision, source, count in connection.execute(query, (origin, origin, int(now) + 60, SCAN_LIMIT)):
        if decision not in ("blocked", "allowed"):
            continue
        start = origin + bucket * 3600
        totals = buckets.setdefault(start, _empty_totals())
        totals[decision] += count
        if decision == "blocked" and start >= week_start:
            key = category(source)
            category_week[key] = category_week.get(key, 0) + count
            if start >= today_start:
                category_today[key] = category_today.get(key, 0) + count

    def total(start: int, end: int) -> dict:
        values = _empty_totals()
        for bucket_start, counts in buckets.items():
            if start <= bucket_start < end:
                values["blocked"] += counts["blocked"]
                values["allowed"] += counts["allowed"]
        return values

    hourly = []
    for start in hours:
        hourly.append({"start": _iso(start), **buckets.get(start, _empty_totals()), "complete": reaches(start)})
    daily = []
    for index, day in enumerate(days):
        start = int(day)
        end = int(days[index + 1]) if index + 1 < len(days) else int(now) + 3600
        daily.append({"start": _iso(start), "day": dates[index].isoformat(), **total(start, end),
                      "complete": reaches(start)})
    # Same-time-yesterday is exact rather than hour-bucketed.
    same_time = dict(connection.execute(
        "SELECT decision, COUNT(*) FROM events WHERE ts >= ? AND ts < ? GROUP BY decision",
        (yesterday_start, same_time_end)).fetchall())
    today_totals = dict(connection.execute(
        "SELECT decision, COUNT(*) FROM events WHERE ts >= ? GROUP BY decision", (today_start,)).fetchall())

    def tops(start: int) -> list[dict]:
        rows = connection.execute(
            """SELECT host, source, COUNT(*) AS hits, MAX(ts) FROM events
               WHERE decision = 'blocked' AND ts >= ? GROUP BY host, source ORDER BY hits DESC, host LIMIT ?""",
            (start, TOP_LIMIT * 3)).fetchall()
        merged: dict[str, dict] = {}
        for host, source, hits, last in rows:
            item = merged.setdefault(host, {"host": host, "count": 0, "category": category(source), "last": last})
            item["count"] += hits
            item["last"] = max(item["last"], last)
            if category(source) == "threats":
                item["category"] = "threats"
        ranked = sorted(merged.values(), key=lambda item: (-item["count"], item["host"]))[:TOP_LIMIT]
        return [{**item, "last": _iso(item["last"])} for item in ranked]

    threat_sources = tuple(source for source, key in SOURCE_CATEGORY.items() if key == "threats")
    marks = ",".join("?" * len(threat_sources))
    threat_rows = connection.execute(
        f"SELECT ts, host, source FROM events WHERE decision = 'blocked' AND ts >= ? AND source IN ({marks}) "
        f"ORDER BY ts DESC LIMIT ?", (week_start, *threat_sources, THREAT_LIMIT)).fetchall()
    result.update({
        "today": {"blocked": today_totals.get("blocked", 0), "allowed": today_totals.get("allowed", 0),
                  "start": _iso(today_start)},
        "yesterday": {**total(yesterday_start, today_start), "complete": reaches(yesterday_start)},
        "same_time_yesterday": {"blocked": same_time.get("blocked", 0), "allowed": same_time.get("allowed", 0),
                                "complete": reaches(yesterday_start)},
        "hourly": hourly,
        "daily": daily,
        "categories": {"today": _categories(category_today), "week": _categories(category_week)},
        "top_blocked": {"today": tops(today_start), "week": tops(week_start)},
        "threats": {"today": category_today.get("threats", 0), "week": category_week.get("threats", 0),
                    "recent": [{"at": _iso(ts), "host": host, "source": source} for ts, host, source in threat_rows]},
    })
    return result


def _utc_days(now: float) -> list[int]:
    today = int(now) // 86400 * 86400
    return [today - offset * 86400 for offset in range(DAYS - 1, -1, -1)]


def _zero_aggregate(now: float) -> dict:
    days = _utc_days(now)
    return {
        "day_basis": "utc",
        "today": {**_empty_totals(), "start": _iso(days[-1])},
        "yesterday": {**_empty_totals(), "complete": False},
        "daily": [{"start": _iso(day), "day": datetime.fromtimestamp(day, timezone.utc).date().isoformat(),
                   **_empty_totals(), "complete": False} for day in days],
        "categories": {"today": _categories({}), "week": _categories({})},
        "top_blocked": {"today": [], "week": []},
        "threats": {"today": 0, "week": 0, "recent": []},
    }


def _aggregate(connection: sqlite3.Connection, now: float, meta: dict) -> dict:
    days = _utc_days(now)
    result = _zero_aggregate(now)
    by_day: dict[int, dict] = {}
    category_today: dict[str, int] = {}
    category_week: dict[str, int] = {}
    oldest, newest, rows = connection.execute("SELECT MIN(day), MAX(day), COUNT(*) FROM daily").fetchone()
    result["coverage"] = {"oldest": _iso(oldest) if oldest is not None else None,
                          "newest": _iso(newest) if newest is not None else None,
                          "rows": rows, "row_cap": MAX_EVENTS, "capped": rows >= MAX_EVENTS}
    for day, decision, source, count in connection.execute(
            "SELECT day, decision, source, SUM(count) FROM daily WHERE day >= ? GROUP BY day, decision, source LIMIT ?",
            (days[0], SCAN_LIMIT)):
        if decision not in ("blocked", "allowed"):
            continue
        totals = by_day.setdefault(day, _empty_totals())
        totals[decision] += count
        if decision == "blocked":
            key = category(source)
            category_week[key] = category_week.get(key, 0) + count
            if day == days[-1]:
                category_today[key] = category_today.get(key, 0) + count

    def tops(start: int) -> list[dict]:
        rows = connection.execute(
            """SELECT host, source, SUM(count) AS hits, MAX(day) FROM daily
               WHERE decision = 'blocked' AND host != '' AND day >= ? GROUP BY host, source
               ORDER BY hits DESC, host LIMIT ?""", (start, TOP_LIMIT * 3)).fetchall()
        merged: dict[str, dict] = {}
        for host, source, hits, last in rows:
            item = merged.setdefault(host, {"host": host, "count": 0, "category": category(source), "last": last,
                                            "day_only": True})
            item["count"] += hits
            item["last"] = max(item["last"], last)
            if category(source) == "threats":
                item["category"] = "threats"
        ranked = sorted(merged.values(), key=lambda item: (-item["count"], item["host"]))[:TOP_LIMIT]
        return [{**item, "last": _iso(item["last"])} for item in ranked]

    floor = _floor(meta, oldest, now, result["coverage"]["capped"])
    trimmed = _number(meta.get("trimmed_through"))
    complete = lambda day: floor is not None and floor <= day and (trimmed is None or day > trimmed)
    result.update({
        "today": {**by_day.get(days[-1], _empty_totals()), "start": _iso(days[-1])},
        "yesterday": {**by_day.get(days[-2], _empty_totals()), "complete": complete(days[-2])},
        "daily": [{"start": _iso(day), "day": datetime.fromtimestamp(day, timezone.utc).date().isoformat(),
                   **by_day.get(day, _empty_totals()), "complete": complete(day)} for day in days],
        "categories": {"today": _categories(category_today), "week": _categories(category_week)},
        "top_blocked": {"today": tops(days[-1]), "week": tops(days[0])},
        "threats": {"today": category_today.get("threats", 0), "week": category_week.get("threats", 0), "recent": []},
    })
    return result
