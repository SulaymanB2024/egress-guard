#!/usr/bin/env python3
"""Measure what a verified feed cache blocks, offline.

Reports domains per enabled feed, how many of each feed's entries no other enabled feed already
covers, policy load time and memory, and the decisions for a committed sample of labelled
public hostnames (scripts/coverage-sample.txt). It reads only the local cache; nothing is fetched.

    EGRESS_GUARD_DATA=/path/to/state PYTHONPATH=src python3 -B scripts/measure-coverage.py

`--state` and `--config` override the environment. Use a temporary state directory refreshed
with `egress-guard refresh`, never a live installation's directory, for repeatable numbers.
Only APIs present since 0.3.0 are used, so the same script measures older releases.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import time
from collections import Counter
from pathlib import Path

from egress_guard import feeds
from egress_guard.config import load_config
from egress_guard.policy import Policy

SAMPLE = Path(__file__).with_name("coverage-sample.txt")
BLOCK_LABELS = ("ad", "tracker", "malware", "phishing", "doh", "lookalike")


def _rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def read_sample(path: Path) -> list[tuple[str, str]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        label, _, host = line.partition(" ")
        if label not in (*BLOCK_LABELS, "good") or not host.strip():
            raise SystemExit(f"{path.name}:{number}: expected '<label> <hostname>'")
        rows.append((label, host.strip()))
    return rows


def _covered(name: str, others: list[tuple[bool, set[str]]]) -> bool:
    for exact, names in others:
        if exact:
            if name in names:
                return True
            continue
        host = name
        while host:
            if host in names:
                return True
            _, _, host = host.partition(".")
    return False


def feed_report(state: Path, config: dict) -> list[dict]:
    selected = feeds.selected_feeds(config)
    loaded = [(feed, feeds.read_cached_feed(state, feed)) for feed in selected]
    rows = []
    for feed, names in loaded:
        others = [(other.exact, other_names) for other, other_names in loaded if other is not feed]
        unique = sum(not _covered(name, others) for name in names)
        rows.append({"id": feed.id, "category": feed.category, "entries": len(names), "unique": unique})
    return rows


def sample_report(policy: Policy, sample: list[tuple[str, str]]) -> dict:
    by_label: dict[str, Counter] = {}
    misses: dict[str, list[str]] = {}
    for label, host in sample:
        result = policy.decision(host)
        counts = by_label.setdefault(label, Counter())
        counts["total"] += 1
        blocked = result["decision"] == "blocked"
        counts["blocked"] += blocked
        counts[result["source"]] += 1
        if blocked == (label == "good"):
            misses.setdefault(label, []).append(f"{host} ({result['source']})")
    return {"labels": {label: dict(counts) for label, counts in by_label.items()}, "misses": misses}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--state", type=Path, default=os.environ.get("EGRESS_GUARD_DATA"))
    parser.add_argument("--config", type=Path, default=os.environ.get("EGRESS_GUARD_CONFIG"))
    parser.add_argument("--sample", type=Path, default=SAMPLE)
    parser.add_argument("--skip-overlap", action="store_true", help="skip the slower per-feed overlap pass")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.state is None:
        parser.error("set --state or EGRESS_GUARD_DATA to a refreshed state directory")
    config = load_config(args.config or args.state / "config.toml")

    base = _rss_mb()
    started = time.perf_counter()
    policy = Policy(config, args.state)
    load_seconds = time.perf_counter() - started
    policy_rss = _rss_mb()
    report = {
        "policy": {"load_seconds": round(load_seconds, 2), "peak_rss_mb": round(policy_rss),
                   "baseline_rss_mb": round(base), "ready": policy.ready(), "coverage": policy.coverage},
        "sample": sample_report(policy, read_sample(args.sample)),
    }
    if not args.skip_overlap:
        report["feeds"] = feed_report(args.state, config)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    p = report["policy"]
    print(f"Policy load {p['load_seconds']} s, peak RSS {p['peak_rss_mb']} MB "
          f"(interpreter {p['baseline_rss_mb']} MB), ready={p['ready']}")
    for row in report.get("feeds", []):
        share = row["unique"] / row["entries"] if row["entries"] else 0
        print(f"  {row['id']:28} {row['category']:8} {row['entries']:>10,} entries "
              f"{row['unique']:>10,} not covered by any other feed ({share:.0%})")
    print("Sample (blocked / total):")
    for label, counts in sorted(report["sample"]["labels"].items()):
        sources = ", ".join(f"{key} {value}" for key, value in sorted(counts.items())
                            if key not in ("total", "blocked"))
        print(f"  {label:10} {counts['blocked']:>3} / {counts['total']:<3} {sources}")
    for label, hosts in sorted(report["sample"]["misses"].items()):
        kind = "blocked (false positive)" if label == "good" else "not blocked"
        print(f"  {label} {kind}: {', '.join(hosts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
