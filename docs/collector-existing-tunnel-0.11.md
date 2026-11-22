# Collector-host receiver bytes across existing TLS tunnels (0.11 follow-up)

## Reproduced evidence-integrity defect

Before this change, `tests/browser/chrome-collector-lab.mjs::summarizeArm` computed the total receiver-byte delta across the entire collector connection history, but counted `trackerHostApplicationBytes` **only on connections created after the arm checkpoint**. A keep-alive TLS connection established before the checkpoint could receive fresh application bytes afterward without contributing to the tracker-host counter. As a result, the isolated tracker-host assessment could incorrectly pass a **zero-byte** protected arm despite new bytes reaching that receiver.

Minimal controlled example: prior snapshot contains `tracker.test:29100` with 21 decrypted application bytes; later snapshot contains the **same connection** with 28 bytes, and no new connections. Previously the tracker-host delta was recorded as **0**, now it is **7**. A live recipient is not allowed to disappear from the measurement because a TCP tunnel is reused. The same defect affected `connectionsClosed`: existing still-open connections were omitted from that field.

## Changes

`summarizeArm` now calls the existing `measureActionWindow(before, snapshot, "tracker.test")` validator to account for *all* appended and preexisting per-connection byte-counter changes. It requires monotonically increasing counts, conserves the total collector bytes, and refuses a fresh byte delta without proxy-route evidence. The tracker-host count comes from the validated target-origin delta, and the raw total is target plus other origins. The reported number of *new* connections remains separate from the closure assertion, which now covers all receiver connections. This is a measurement correction, **not a new blocking rule**.

Two repository regression cases cover preexisting-tunnel delivery, zero-byte qualification failure, still-open existing connections, invalid route and counter rollback, plus same-port reused connections with old and new received bytes.

## Qualification

The modified GitHub branch source and existing standalone receiver-byte module were evaluated together in an isolated JavaScript execution. **6/6 direct assertions passed**: preexisting seven-byte delivery, prior unclosed connection, missing proxy-route refusal, counter rollback refusal, new same-port connection plus existing bytes, and forged aggregate refusal.

**NOT COVERED:** The complete installed repository Node/Python test suites; native Chrome startup (previous restriction was not retried); browser service-worker/proxy lifecycle qualification; macOS deployment; delayed sends after the final collector snapshot. The two new repository test cases were authored but not executed under the Node test runner in this environment. Those missing gates must not be labeled passing.

**Residual:** Positive receiver bytes on a shared publisher origin cannot be assigned to an individual tracking action without distinct origin or transport identity. Opaque first-party POST bodies remain an admitted cross-site identifier channel. A zero-byte interval does not rule out a delayed send after that interval.

## Next

Run complete Node/Python test suites on a permitted checkout and the optional native Chrome/real-proxy lab in a permitted environment. Add controlled delayed-send experiments and explicit closed-connection/final-drain receipts. Investigate pinned, locally redirected SDK protocol drift only when the full collector/functional controls can run; never send events to production collectors.
