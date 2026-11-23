# Exact channel accounting in the controlled collector

The production proxy still forwards opaque TLS. It does not parse HTTPS paths,
cookies, headers or bodies. This lab owns the origin certificate and the origin
server, so it can measure decrypted bytes there without changing that boundary.

## Two observations, different meanings

| Observation | What is counted | What it does not establish |
|---|---|---|
| Proxy emission | TLS bytes in actual `PolicyRelay` `SendData` commands after the current admission check, by tunnel ID, origin host, peer port and direction | Kernel delivery, TCP acknowledgements, TCP overhead, decrypted request attribution |
| Origin raw input | Every decrypted socket read, before HTTP or WebSocket parsing succeeds | HTTP/2 or HTTP/3 coverage; arbitrary internet traffic classification |
| Origin completed frames | Exactly consumed HTTP/1.1 request or supported WebSocket frame bytes, including request/frame headers | Identification of an arbitrary tracking protocol |
| Unparsed or truncated | Raw origin input minus completed frame bytes | Evidence that an unknown partial payload contains no identity |

The fixed accounting identity is:

```text
origin raw application bytes = completed request/frame bytes + unparsed remainder
```

`ConsumedReader` tracks bytes consumed by framing operations. It does not use
socket-read boundaries as request boundaries: one buffered read can contain two
pipelined requests, or a partial request after a complete one. This is why a
functional `/product` request and a `/collect/body` request can share one TLS
connection and still receive separate origin-side totals.

The channels are a fixed inventory belonging to synthetic `.test` routes:
third-party collector, first-party URL/header collector, first-party body
collector, WebSocket telemetry, first-party functional traffic, fixture control
traffic and otherwise unclassified completed traffic. They are not a classifier
for real websites. An HTTP `Host` that disagrees with the controlled TLS SNI is
rejected before receiving channel credit.

## Evidence must not manufacture blocking

The proxy meter is a test-only wrapper. A metadata-write failure must still yield
every command that the real relay admitted. A separate inherited one-byte pipe
reports a sticky failure to the parent, which refuses qualification. The pipe is
independent of the filesystem that stores the byte counters. Closed diagnostics
also invalidate the run. Neither a stale counter file nor an instrumentation
exception can earn a zero-byte protection result.

No production telemetry, database, body log, packet capture, global resolver or
trust-store setting is added. Retained identifiers must match the lab's issued
synthetic-token format. Request URLs, cookies and arbitrary payloads are not
retained by the fixture.

## Reproduce the portable qualification

Use the project's pinned Python 3.12+ environment with `mitmproxy==12.3.1`:

```sh
python -B scripts/qualify-channel-lab.py --out /absolute/new-channel-receipt.json
```

The output path is exclusive and private. An interrupted execution cannot replace
an earlier receipt. The run checks the original origin certificate on every TLS
connection and confirms a matching proxy tunnel observation for each receiving
origin connection.

Each arm has four synthetic subjects visiting two separate registrable `.test`
sites. Each visit sends five requests on one persistent TLS connection: a
functional product request, a URL identifier, an identifier in Cookie and
`X-POSTHOG-DISTINCT-ID`, a body identifier, and a functional cart POST. The cart
requires its exact synthetic payload and `X-Lab-CSRF` session control. Separate
requests exercise the known third-party collector and a first-party WebSocket.

The baseline pauses tracker filtering. The protected arm enables the real proxy's
tracker policy. It does **not** pretend that a Python client has a browser
extension or manually remove headers and credit DNR for the result.

Required outcomes are:

| Channel | Baseline cross-site matches | Protected proxy cross-site matches |
|---|---:|---:|
| Third-party collector | 4/4 | 0/4 |
| First-party URL/header collector | 4/4 | 4/4 |
| First-party body collector | 4/4 | 4/4 |
| First-party WebSocket telemetry | 4/4 | 4/4 |
| All observed channels | 4/4 | 4/4 |

Every row retains all four same-subject and twelve different-subject pairs.
All different-subject matches must remain zero. Each arm must preserve **16/16
functional responses** and **8/8 visits using a shared TLS connection**. Known
third-party denial must produce both zero new proxy-to-origin emissions and zero
new origin application bytes. Complete successful scenarios must have no
unparsed remainder and exact totals equal to the authored request/frame lengths.

The all-channel byte total includes the functional traffic; its matching result
uses only identifiers actually extracted from received events. Removing the
extractor's identifiers is an explicit negative regression: both arms must fail,
even though bytes, responses, connection reuse and event inventory still pass.

The repository's [validation receipt](validation-0.12.json) records the executed
run. [The per-channel receipt](benchmarks/channel-lab-0.12.json) retains the exact
observed bytes and the source-file hashes that produced them.

## Additional real-stream regressions

`tests/test_privacy_accounting.py` exercises sequential and pipelined requests,
partial request lines, truncated bodies, duplicate framing lengths, mismatched
Host/SNI, a valid 127-byte WebSocket payload, a truncated masked frame, evidence
write failures and a collector socket revoked alongside an allowed functional
socket. The allowed socket must deliver every subsequent frame. Idle revocation
has its own production behavior and real-stream control; see the
[tunnel note](tunnel-revocation-0.12.md).

## Remaining boundaries

This is HTTP/1.1 and a deliberately small WebSocket fixture. It does not qualify
HTTP/2/3 multiplexing, arbitrary frame fragmentation, server-side identity relays,
opaque bounce redirects, application-encrypted payload extraction or public-IP
linkability. A JSON body is encrypted by TLS in transit; the fixture does not
claim to decode a separately encrypted application payload.

Native Chrome header/cookie sanitation and Client Hints/GPC observations remain
separate. No native Chrome run was executed in this environment. Header-only
identity can be removed by an appropriately scoped browser rule, but that claim
does not become a measured success until the actual browser arm runs. The
first-party body and WebSocket residuals above are intentionally preserved.
