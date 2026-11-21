"""Capture harness: the real dashboard server and web assets, a seeded synthetic ledger, and a
status that can be switched between scenarios (the temp install has no running proxy, so a
"protected" status is overlaid on the real one; "degraded" is the real status unchanged).

Run with EGRESS_GUARD_DATA / EGRESS_GUARD_CONFIG pointing at a private temp dir.
  python harness.py seed        -> writes ledgers full/aggregate/none/empty
  python harness.py serve       -> serves on the config's dashboard_port
  python harness.py url         -> prints a single-use authenticated URL
Scenario: <state>/scenario.json {"status": "protected|reduced|paused|degraded", "ledger": "full|aggregate|none|empty"}
"""
import json
import sqlite3
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from egress_guard import dashboard_app
from egress_guard.dashboard_app import Application, iso
from egress_guard.ledger import read_activity
from egress_guard.insights import read_insights
from egress_guard.paths import data_dir

STATE = data_dir()

ADS = ["stats.g.doubleclick.net", "securepubads.g.doubleclick.net", "browser-intake-datadoghq.com", "ib.adnxs.com",
       "www.google-analytics.com", "connect.facebook.net", "api.mixpanel.com", "pagead2.googlesyndication.com"]
ALLOWED = ["app.example-maps.test", "api.example-notes.test", "push.example-mail.test", "cdn.example-shop.test",
           "eu-west-2.cdn.internal-billing-portal.example-enterprise.co.uk", "img.example-news.test",
           "auth.example-maps.test", "accounts.sso.login.internal-billing-portal.example-enterprise.co.uk"]


def scenario():
    try:
        return json.loads((STATE / "scenario.json").read_text())
    except (OSError, ValueError):
        return {"status": "protected", "ledger": "full"}


def seed():
    now = int(time.time())
    hour = now - now % 3600
    # Full history: 7 days of hourly traffic, a daytime shape, two threats, one look-alike.
    rows = []
    shape = [6, 3, 2, 1, 1, 0, 0, 1, 2, 4, 8, 11, 15, 10, 8, 7, 6, 5, 6, 4, 3, 5, 4, 4]
    for offset in range(24 * 6 + 20, -1, -1):
        start = hour - offset * 3600
        h = datetime.fromtimestamp(start).hour
        blocked = shape[h] + (offset % 3)
        allowed = blocked * 6 + 3
        if offset > 24 * 5:
            blocked, allowed = blocked // 2, allowed // 2
        for i in range(blocked):
            src = "cname-cloak" if i % 9 == 4 else "local-block" if i % 47 == 11 else "tracker-feed"
            host = "metrics.example-shop.test" if src == "cname-cloak" else "ads.example-blocked.test" if src == "local-block" else ADS[(i + offset) % len(ADS)]
            rows.append((start + 60 + i * 37 % 3500, host, "blocked", src, "https"))
        for i in range(allowed):
            rows.append((start + 30 + i * 53 % 3500, ALLOWED[(i + offset) % len(ALLOWED)], "allowed", "no-match", "https"))
    rows.append((now - 7200, "login-verify.example-phish.test", "blocked", "phishing-feed", "https"))
    rows.append((now - 3 * 86400, "update-cdn.malware-sample.test", "blocked", "malware-feed", "https"))
    rows.append((now - 400, "dns.example-resolver.test", "blocked", "doh-feed", "https"))
    # The latest few minutes, in a readable order for the Activity list.
    recent = [("stats.g.doubleclick.net", "blocked", "tracker-feed"), ("app.example-maps.test", "allowed", "no-match"),
              ("browser-intake-datadoghq.com", "blocked", "tracker-feed"), ("metrics.example-shop.test", "blocked", "cname-cloak"),
              ("eu-west-2.cdn.internal-billing-portal.example-enterprise.co.uk", "allowed", "no-match"),
              ("securepubads.g.doubleclick.net", "blocked", "tracker-feed"), ("xn--pypal-4ve.com", "blocked", "lookalike-domain"), ("ads.example-blocked.test", "blocked", "local-block"),
              ("api.example-notes.test", "allowed", "no-match")]
    for index, (host, decision, source) in enumerate(reversed(recent)):
        rows.append((now - 20 - (len(recent) - index) * 40, host, decision, source, "https"))
    rows.sort()
    path = STATE / "ledger-full.sqlite3"
    path.unlink(missing_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.executemany("INSERT INTO meta VALUES (?,?)", [("history", "full"), ("retention_days", "7"), ("created", str(rows[0][0]))])
        db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, host TEXT NOT NULL,"
                   " decision TEXT NOT NULL, source TEXT NOT NULL, transport TEXT NOT NULL)")
        db.executemany("INSERT INTO events(ts,host,decision,source,transport) VALUES (?,?,?,?,?)", rows)
    # Aggregate: UTC-day tallies from the same rows; history started 4 days ago, so earlier days are "no data".
    path = STATE / "ledger-aggregate.sqlite3"
    path.unlink(missing_ok=True)
    start = (now // 86400 - 4) * 86400
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.executemany("INSERT INTO meta VALUES (?,?)", [("history", "aggregate"), ("retention_days", "7"), ("created", str(start))])
        db.execute("CREATE TABLE daily (day INTEGER NOT NULL, host TEXT NOT NULL, decision TEXT NOT NULL, source TEXT NOT NULL,"
                   " count INTEGER NOT NULL, PRIMARY KEY (day, host, decision, source))")
        for ts, host, decision, source, _ in rows:
            if ts < start:
                continue
            db.execute("INSERT INTO daily VALUES (?,?,?,?,1) ON CONFLICT(day,host,decision,source) DO UPDATE SET count = count + 1",
                       (ts // 86400 * 86400, host if decision == "blocked" else "", decision, source))
    for mode in ("none",):
        path = STATE / f"ledger-{mode}.sqlite3"
        path.unlink(missing_ok=True)
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.executemany("INSERT INTO meta VALUES (?,?)", [("history", mode), ("created", str(now))])
    # A brand-new install: full history, nothing recorded yet (created now).
    path = STATE / "ledger-empty.sqlite3"
    path.unlink(missing_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.executemany("INSERT INTO meta VALUES (?,?)", [("history", "full"), ("retention_days", "7"), ("created", str(now))])
        db.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, host TEXT NOT NULL,"
                   " decision TEXT NOT NULL, source TEXT NOT NULL, transport TEXT NOT NULL)")
    print("seeded", len(rows), "events")


class CaptureApplication(Application):
    def status(self):
        real = super().status()
        kind = scenario().get("status", "protected")
        if kind == "degraded":
            return real
        now = time.time()
        real["proxies"][0]["state"] = "active"
        real["proxies"][1].update(state="active", detail="Revision 3f9c2a71b0de applied by the proxy.")
        names = ["Ads and trackers (HaGeZi Pro)", "Malware and phishing (HaGeZi TIF)", "Cloaked trackers (AdGuard CNAME)",
                 "Encrypted DNS servers (HaGeZi DoH)", "Look-alike domains (built in)"]
        stale = kind == "reduced"
        real["filters"] = [{"name": name, "state": "degraded" if stale and i < 2 else "active",
                            "detail": "stale" if stale and i < 2 else "current",
                            "updated_at": iso(now - (3 * 86400 if stale and i < 2 else 7200)),
                            "published_at": iso(now - 9000), "entries": [412_388, 186_204, 61_520, 3_311, 1][i]}
                           for i, name in enumerate(names)]
        real["protection"]["state"] = "paused" if kind == "paused" else "active"
        real["protection"]["pause_expires_at"] = iso(now + 900) if kind == "paused" else None
        real["controls"]["resume"] = kind == "paused"
        real["footprint"] = {"rss_bytes": 96 * 1024 * 1024, "cpu_seconds": 41.0, "uptime_seconds": 13 * 3600}
        real["temporary_allows"] = [{"host": "cdn.example-video.test", "expires_at": iso(now + 600)}] if kind != "degraded" else []
        return real

    def _ledger(self):
        return self.state / f"ledger-{scenario().get('ledger', 'full')}.sqlite3"

    def activity(self):
        return read_activity(self._ledger(), 50)

    def insights(self):
        return read_insights(self._ledger())


def serve():
    dashboard_app.initialize()
    from egress_guard.config import load_config
    from egress_guard.dashboard_http import ProtectionServer, installation_token
    with ProtectionServer(CaptureApplication(), installation_token(data_dir()), port=load_config()["proxy"]["dashboard_port"]) as server:
        server.serve_forever(poll_interval=0.5)


def url():
    captured = []
    webbrowser.open = lambda value, *a, **k: captured.append(value) or True
    dashboard_app.open_dashboard()
    print(captured[0])


if __name__ == "__main__":
    {"seed": seed, "serve": serve, "url": url}[sys.argv[1]]()
