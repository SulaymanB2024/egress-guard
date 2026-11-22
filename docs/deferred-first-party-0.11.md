# Controlled deferred first-party receiver test (0.11 follow-up)

## Defect and experiment

The earlier per-action byte window sampled the origin immediately after each synthetic browser action returned. A tracker that schedules its network call for a later turn could produce a zero-byte window even when the controlled origin ultimately receives bytes. A browser-close snapshot alone also did not report whether any additional first-party bytes arrived during its bounded drain.

The optional real-Chrome/real-proxy laboratory now opens a separate controlled `publisher.test` page **outside the four-subject scoring cohort**. An explicitly synthetic sender schedules a GA4-shaped GET to that same origin after a 150 ms timer. The triggering evaluation returns before the timer fires. The harness records receiver-side decrypted application-byte counters (including pre-existing connections) before scheduling, immediately after scheduling, and after the sender's completion marker plus a 300 ms drain. Every delta is checked for monotonic counters, route proof and byte conservation.

The receiver's parsed event for that unique synthetic visit is also counted; no raw identifier is included in the report. The independent baseline must prove a sender was scheduled, ran, completed, delivered one event and caused positive bytes. In the protected arm, either a new receiver byte or event is a **FAIL**, even if the immediate sample was zero. A missing timer, missing positive baseline, missing route proof, inconsistent counters or unrelated-origin positive bytes does **not** earn blocking credit; it is **NOT COVERED** or fails the validator.

A separate snapshot before browser shutdown and a final snapshot after browser closure and a 300 ms wait report additional first-party bytes during that bounded drain. A zero after closure is only a sampled interval observation, not proof against future requests.

## Evidence and safety boundary

- Standalone Node 22.16.0 `tests/browser/deferred-first-party.test.cjs`: **5/5 passed** with no failures, skips or cancellations. Cases include reused TLS connections, delayed escapes, missing sender/timer evidence, invalid route/counter evidence, and unrelated-origin ambiguity.
- The modified runner's module syntax was checked as isolated JavaScript source; full ESM imports/package/fixture integration were **not executed**.
- The full repository Python and Node suites remain **NOT COVERED** because a complete repository checkout is unavailable here.
- Real Chrome/extension/proxy interaction remains **NOT COVERED**. Native Chromium startup was previously denied in this environment and was not attempted.
- No installed browser, system proxy, network policy, production SDK endpoint, stored browser data or actual user identity was touched.

## Interpretation and next

This change is an **evidence-gate improvement**, not a new tracking prevention claim. It cannot attribute positive bytes on a multiplexed first-party connection to one specific request, detect arbitrary future sends, or inspect opaque encrypted first-party tracking bodies. The prior aggregate synthetic linkability residual (4/4 via permitted opaque first-party bodies) remains. The experiment samples one delayed transport and a bounded 300 ms drain; neither proves a real SDK's lifetime behavior.

Next: run the complete repository tests on a permitted checkout, then run the optional native browser test in an expressly permitted environment. Only after those controls are qualified should source-pinned SDK drift experiments be promoted as evidence. Never contact production collectors with lab events or automatically alter live policy based on a drift observation.
