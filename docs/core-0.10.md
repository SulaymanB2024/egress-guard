# Revocable opaque proxy tunnels in 0.10

Version 0.10 rechecks an admitted CONNECT tunnel before forwarding each subsequent chunk in either direction. A new manual deny, a changed threat list, an expired temporary exception or a stricter transport profile can therefore stop an already established connection. TLS still terminates at the original destination. Egress Guard does not decrypt these chunks, parse their HTTP requests or replace the destination certificate.

This closes a specific limitation of 0.9. That version checked the CONNECT authority and the initial visible TLS name, then handed the stream to an unchecked opaque relay. Its socket-address guard checked each new TCP connection candidate, but it did not revisit an already connected peer when IP policy changed. An existing stream could consequently outlive the permission that admitted it.

## The forwarding decision

Each relay send reads one current policy generation and applies the following checks:

| Evidence or setting | Continuing requirement |
|---|---|
| Running policy | Threat and tracker policy remains enforceable; the proxy is not stopping. |
| CONNECT authority | The original requested hostname remains permitted at the original requested port. |
| Initial visible SNI | If present, this name independently remains permitted. A grant for the authority does not transfer to the TLS name. |
| Temporary permission or tracker pause | The existing exact-host and expiry rules are evaluated using the current time, even when the policy revision has not changed. |
| Transport profile | The current literal-target and CONNECT-port restrictions still admit the original request. |
| Initially non-TLS stream | It remains permitted only while the current profile and plaintext-credential setting allow that protocol for this authority. Numeric loopback exceptions retain their existing behavior. |
| Experimental address guard | When selected, the actual connected numeric peer independently passes the current IP policy. A hostname safety exception cannot override an IP denial. |

Threat and manual blocks retain their existing precedence. Ordinary hostname allows and tracker pauses do not override those blocks or the transport restrictions. The guard-selection setting is still restart-bound, as documented in [the 0.9 transport design](core-0.9.md). No additional setting is needed to enable the continuing hostname checks.

Policy publication retains the existing last-good behavior. A saved file is not necessarily the active policy: an invalid or unapplied edit leaves the previous enforceable generation running and is reported as pending. Once a new generation applies, subsequent relay decisions use it. Time-limited grants also expire without a file edit or a new revision.

## Where the check runs

`TunnelGuard` still bounds and inspects only the initial ClientHello. After admission it creates `PolicyRelay`, a small subclass of the pinned mitmproxy `TCPLayer` with `ignore=True`. That setting avoids constructing a TCP flow with a retained message history.

The new layer checks emitted `SendData` commands before passing them to mitmproxy. It does not rely solely on incoming-data events. This distinction matters because the underlying layer can queue client bytes while `OpenConnection` is pending: when the connection completes and those bytes become sendable, the current policy is checked again.

The pinned connector obtains `server.peername` from the actual connected socket before delivering `OpenConnectionCompleted`. The continuing IP check uses that numeric peer, including the candidate that succeeded after an earlier resolver candidate failed. It does not perform a second DNS lookup, use the requested hostname as address evidence or compare an independently observed DNS result with a different connection. A missing or malformed peer cannot satisfy an enabled address check.

On refusal, the relay discards its pending event queue and emits full closes for both TCP sides. It remains revoked even if a later policy update permits the same destination; the client must establish a new connection. A failed policy evaluation also closes the stream. Ordinary permitted half-closes, connection errors and the remaining direction of a half-closed exchange retain the pinned relay's behavior.

There is no positive admission cache. A cached hostname allowance could otherwise outlive an exception or tracker pause without any revision change. The check uses existing in-memory policy data; it adds no DNS request, file read, timer or retained payload. Optional activity history may record one refusal with the original authority or initial TLS name and its existing block reason. The numeric peer and encrypted bytes are not added to activity history.

The implementation depends on the `Layer` and `TCPLayer` command semantics in mitmproxy 12.3.1. The official [event documentation](https://docs.mitmproxy.org/stable/api/events.html) explains that one connection can carry multiple requests and that CONNECT success under lazy connection setup can precede the upstream connection. The pinned implementation in `mitmproxy/proxy/layer.py`, `mitmproxy/proxy/layers/tcp.py` and `mitmproxy/proxy/server.py` is the source of the queue, send and actual-peer ordering used here. Changes to that dependency require the transport tests to be rerun.

## Exact timing and visibility limits

The enforcement boundary is the next attempted forwarding command. An otherwise idle TCP connection is not closed by a separate revocation timer. If its next data arrives from the server, the server-to-client send is checked too. This prevents an idle connection from resuming under a revoked permission without maintaining per-flow timers.

An upstream connection may already have been initiated while the destination was allowed. Revocation during that pending connection does not undo the connection attempt; it can suppress the queued application bytes when the connection completes. Bytes already delivered, or already handed to the transport's write buffers by an earlier allowed send, cannot be recalled. The implementation does not claim that a policy edit retroactively removes them.

Only the original CONNECT authority, the initially visible SNI and, when selected, the actual TCP peer are available to these checks. They do not reveal an ECH inner name, subsequent encrypted HTTP authorities, request paths, credentials or payloads. Multiplexed requests sharing an allowed TLS connection remain opaque to this proxy. Browser request filtering is a separate layer. Clients that do not use the proxy, UDP traffic, the device's public IP and first-party account identity remain outside this feature.

## Runtime acknowledgment and upgrade

The authenticated transport runtime receipt now requires the exact field:

```json
"tunnel_policy": "per-forward"
```

For example, the default transport reports:

```json
{
  "profile": "compatible",
  "connect_ports": [443],
  "address_guard": {
    "selected": false,
    "state": "disabled",
    "reason": null
  },
  "scope": "proxy-tcp",
  "tunnel_policy": "per-forward",
  "applied": true
}
```

Saved configuration remains unchanged. Health checks, dashboard status and the read-only native host use the strict shared runtime validator. The browser popup also requires the exact capability value before displaying a ready receipt. A still-running 0.9 process lacks this field and cannot acknowledge the new protection, even if its saved revision, transport profile and logging settings otherwise match.

Restart the proxy after upgrading. Replacing the package alone does not change an already running process or retrofit existing 0.9 connections. The receipt is an authenticated capability assertion by the running proxy, subject to the existing local identity trust boundary. It is not independent proof of browser routing, device-wide coverage or remote network behavior.

## Qualification and before/after evidence

The targeted comparison exported the unchanged 0.9 source at commit `abe2b87b2bb8de298992045c8bb05d4f63554adc`. Both arms used mitmproxy 12.3.1, private temporary state, the same synthetic marker protocol and local TLS origins. Each client verified the original origin certificate. The three post-change markers were submitted only after policy acknowledgment, or after the exact grant expiry in the no-new-revision case.

| Established-connection scenario | 0.9 origin application bytes after the change | 0.10 origin application bytes after the change |
|---|---:|---:|
| Original authority receives a manual deny | 13 | 0 |
| Exact-host tracker grant expires with the same policy revision | 12 | 0 |
| Actual connected IP becomes blocked while the hostname is on the safety list | 11 | 0 |

In all three baseline cases the origin received the complete marker and returned its acknowledgment. The new relay closed the corresponding stream without delivering the marker. A separate continuously allowed stream delivered all 24 control markers on the same connection in each arm, across the unrelated policy changes. These deliberately selected regression cases establish the new boundary. They do not estimate a percentage reduction in web tracking or substitute for a browser corpus.

The [committed comparison receipt](benchmarks/tunnel-revocation-0.10.json) records the measured bytes, original-certificate verification and exact package-source and fixture hashes for both arms.

The reusable comparison runs directly from a repository checkout with CPython 3.12 or newer and the already installed pinned dependency:

```sh
python -B scripts/compare-tunnel-revocation.py
```

The tool exports the full baseline commit from local Git into temporary state; it does not fetch missing history or change the checkout. Both arms use the current common test fixture and the same interpreter with mitmproxy 12.3.1. The origin counts every decrypted application byte it receives, including partial marker lines, and the comparison waits for the measured connection to close before calculating the post-change delta. Package-source and fixture hashes accompany the bounded JSON result. A nonzero exit means the comparison did not pass, including when prerequisites or the baseline commit are unavailable. `--output PATH` optionally saves a new report without overwriting an existing file; `--baseline` accepts a trusted local full commit ID. The default baseline is the 0.9 commit above, and an alternate baseline must reproduce the same three documented limitations for the comparison to pass.

The comparison authenticates the raw baseline policy receipt to verify its numeric address guard. It does not relax the production 0.10 health validator: an old receipt still cannot attest to the new per-forward capability. This is a local measurement tool that executes trusted project code, not a sandbox for arbitrary source revisions.

The committed tests also cover an independent visible-SNI deny, a threat-feed update despite hostname allowances, tracker-pause expiry, a live hardened-profile transition, server-originated data, queued bytes awaiting connection setup, policy evaluation failure and permitted half-close behavior. The new established-stream tests run against the real pinned proxy; layer tests exercise its actual command classes.

Relevant focused commands are:

```sh
PYTHONPATH=src:tests python -B -m unittest -v test_tunnel test_transport.TransportPolicyTests test_configuration test_native_host test_loopback_clients
PYTHONPATH=src:tests python -B -m unittest -v test_tunnel_revocation test_addon test_transport.TransportIntegrationTests
```

The qualification uses only local origins and temporary application state. It does not modify system routing or trust stores and does not launch a browser. macOS service behavior, installed-browser routing and real-site compatibility remain separate qualifications.
