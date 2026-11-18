# Measuring filter decisions and attributing destinations

This note describes the separate Egress Guard instrumentation implementation and
the scope of its local measurements. The public release notes list the features
included in each published build.

## What gets measured

- The proxy's heartbeat schedules a performance snapshot, including writer
  status, once a minute while active. History retains up to seven days and
  10,080 samples. Resource measurements
  include user and system CPU time for the proxy process, that process's peak
  resident memory, and the host's one- and five-minute load. The collector does
  not enumerate other processes.
- Filter checks are counted by hook, and one in every 16 checks is timed. Fixed
  histogram buckets bound the reported p50 and p95 for sampled checks. These
  are upper bounds, with the largest observed sample used for the overflow
  bucket. The counts and timing describe rule evaluation, not network
  round trips or page-load time.
- Domain summaries group observed TLS-handshake and plaintext HTTP decisions
  by destination hostname, event type, and verdict. Each window retains at most
  2,048 keys. The database retains at most 100,000 detail rows and removes
  whole oldest windows when trimming. The dashboard reports overflow, dropped
  windows and gaps in collection so a partial window is visible as partial.
- CONNECT counts are tunnel requests. A tunnel can carry multiple HTTPS
  requests, and the proxy leaves its encrypted contents opaque. The summaries
  cannot count HTTPS requests, page visits or individual in-page trackers.
  Traffic outside the observed proxy path is outside this measurement.

Authentication applies to both views of the data. The proxy's signed health
response exposes aggregate timings and counters. Hostname detail is available
through the Bearer-authenticated local dashboard. Domain summaries do not
contain request paths, cookies, headers or bodies.

## Attributing a destination

Matching runs offline against one identified public Disconnect revision,
combined with a Public Suffix List snapshot that includes private suffix
boundaries. The reviewed snapshot indexed 8,314 domain keys. Matching uses
an exact hostname or a qualifying suffix and stops at suffix boundaries.
An ambiguous owner or a shared infrastructure boundary can leave a result
unknown. No hostname is sent to Disconnect for classification.

- **Listed tracker** means Disconnect lists the matched domain in a tracker
  category under the attribution rules.
- **Owner only** means the source supports an owner association without a
  qualifying tracker classification.
- **Unknown** means the matcher has no eligible, unambiguous attribution.

These results annotate the destination. They do not establish a request's
purpose or the intent of an owner, and attribution labels do not determine
the proxy's filtering verdict. Disconnect metadata is licensed CC BY-NC-SA
4.0 and stays in a private, separately acquired cache. The public distribution
does not bundle that dataset or claim a commercial-use grant.
[Disconnect source and licensing](https://github.com/disconnectme/disconnect-tracking-protection)
[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)
[Public Suffix List](https://publicsuffix.org/)

## Local fixture results

In a 2,403-line parsing fixture, median runtime fell from 1.002 ms to 0.484 ms.
In a separate 4,096-decision CPU fixture, per-decision measurements were
3.65 µs for the baseline, 3.94 µs with telemetry, and 5.30 µs with telemetry
and the original domain rollup. That last measurement predates the change
that avoids repeated hostname validation for existing rollup keys.

These fixture timings describe specific operations on a local test setup.
They do not measure browsing speed, whole-system overhead, production latency
or the effectiveness of blocking.
