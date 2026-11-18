# Standalone measurement reference

These POSIX Python examples accompany [the measurement and attribution
notes](../../docs/measurement-and-tracker-attribution.md). They are reference
code for the instrumentation design. Egress Guard 0.2.0 runs independently
of these examples.

- `performance_metrics.py` collects in-process resource counters and fixed-size
  timing histograms.
- `domain_rollups.py` writes bounded hostname, event and decision counts into
  SQLite. A caller owns the collection schedule and private database.
- `dashboard_insights.py` computes summaries from a caller-supplied health
  reader and a read-only database connection. The caller authenticates health
  responses and gates access to hostname details.
- `tracker_attribution.py` matches trusted, in-memory attribution records.
  Supply a public-suffix lookup that includes private boundaries, source
  attribution and any shared-hosting boundaries. The tests use reserved
  example names and a fixture suffix lookup.

This reference has no listener, network requests, licensed dataset, or
connection to an existing installation. Review caller integration, trust
boundaries and storage permissions before using it with real traffic.
Callers provide validated health snapshots and trusted attribution records.
History persistence, collection scheduling and authentication stay with the
integrating application; this directory is not a running dashboard or daemon.
History starts at rollout. A missing interval cannot be reconstructed from
these summaries.

Run the synthetic tests from the repository root with Python 3.12 or later
on macOS or Linux:

```sh
python -B -m unittest discover -s examples/measurement -v
```
