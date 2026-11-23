# Idle tunnel revocation, 0.12

An activated opaque TCP tunnel now rechecks its current admission policy while idle. Previously, an already open tunnel noticed a new deny or expired permission only when another chunk became sendable. `PolicyRelay` retains that per-forward check and adds one scheduled policy check with a **1.0-second event-loop cadence**.

## Lifecycle

The timer starts only after the first admitted `SendData` command. It does not run while the initial connector is pending, when the actual remote peer may still be unknown. Data buffered by mitmproxy during that pending connection is checked when it becomes sendable, as before.

| Event | Result |
| --- | --- |
| First admitted send | Forward the unchanged bytes, then request one wakeup. |
| More traffic while a wakeup is pending | Recheck every send; keep the existing wakeup. |
| Owned wakeup and policy still admits the tunnel | Schedule one replacement wakeup; send no data. |
| Owned wakeup and policy denies, is unavailable or raises an error | Clear paused relay work and close both peers. |
| Foreign, repeated or stale wakeup | Ignore it before mitmproxy's TCP handler or paused-event queue sees it. |
| Normal half-close | Preserve the remaining read direction and continue its policy checks. |
| Both read directions finish, or the relay is revoked | Stop scheduling. An already pending callback becomes inert. |

Revocation is terminal for that relay. Restoring a permission does not revive an old connection or replay its discarded data. The caller must establish a newly admitted connection. Wakeups never flush a buffer, open a connection or forward a heartbeat.

The wakeup calls the same admission function used before each forward. It therefore checks the current applied policy, original CONNECT authority, visible TLS name, transport rules, readiness and the actual peer address when the optional address guard is selected. It does not inspect encrypted request paths or bodies. An allowed first-party tunnel carrying an unknown tracker remains allowed by this mechanism.

## Pinned mitmproxy contract

The implementation was checked against the installed **mitmproxy 12.3.1** sources:

- [`commands.py`](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/proxy/commands.py) defines a nonblocking `RequestWakeup` command.
- [`events.py`](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/proxy/events.py) returns that exact command in `Wakeup`.
- [`layer.py`](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/proxy/layer.py) normally queues unrelated events while a layer waits for a blocking command. `PolicyRelay` handles wakeups before that queue.
- [`layers/tcp.py`](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/proxy/layers/tcp.py) preserves the opposite direction on half-close and has no wakeup handler of its own.
- [`server.py`](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/proxy/server.py) schedules wakeups on the existing asyncio loop and cancels remaining timers during client teardown. HTTP layer routing tracks the originating child for these commands.

Source behavior was inspected locally rather than inferred from a newer online API. No new thread, payload buffer, TCP message history or background network request is introduced. The relay retains `ignore=True`. Existing configured denial logging remains subject to the same history settings.

## Timing and evidence limits

One second is a scheduling interval, **not a hard wall-clock expiry guarantee**. Loading a policy change is separate; a delayed or stalled event loop can delay the next callback. Once a callback or forward check observes a denial, that relay issues full closes and cannot send again through its own handler. It cannot recall bytes already admitted to a transport buffer or already received by the destination.

CONNECTs that have not reached their first admitted send are outside this idle timer. Their existing handshake, open-failure and next-forward checks remain in force. Normal timeout/cleanup behavior continues to belong to mitmproxy.

The authenticated `tunnel_policy: "per-forward"` receipt is unchanged. It still describes the established per-forward capability; that field alone must not be presented as independent proof of idle revocation. The new lifecycle needs its own real-socket qualification and remains separate from native Chrome/DNR qualification.

## Validation

`tests/test_tunnel.py` exercises the actual pinned mitmproxy command/layer classes without opening sockets. Its 26 tests cover handshake admission, deferred upstream opening, unchanged data, both forwarding directions, policy failure, one outstanding timer, repeated idle checks, idle denial, stale/foreign tokens, discarded paused work, normal completion and half-close. The valid tunnel fixtures now supply the connection state that the real connector sets before `OpenConnectionCompleted`.

All 26 passed, as did the existing 13 addon and 11 transport regressions. Those regression suites include real disposable proxy and original-TLS connections. They do not substitute for the new idle-only observation described next or for native browser execution.

The required real transport case keeps a WebSocket idle after one positively received frame, acknowledges a new deny, and observes closure without sending a trigger frame. A separate functional WebSocket must continue succeeding during that interval. Compare both the proxy's admitted `SendData` counters and the collector's received application-byte counters, with errors and incomplete evidence invalidating the result. Such a result qualifies the controlled proxy path; it does not establish browser routing or internet-wide tracking prevention.
