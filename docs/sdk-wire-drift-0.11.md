# Source-pinned SDK collector-wire drift comparator (0.11 follow-up)

## Why this exists

An SDK bundle can change how it sends tracking requests without changing a listed hostname. The existing collector lab measures receiver-side decrypted bytes and synthetic cross-site identifiers, but it does not provide a pinned, bounded comparison format for two SDK revisions. This adds an **offline evidence comparator**, not an SDK downloader, an executable SDK runner, a new live filter, or proof of a vendor's real-world behaviour.

Files: `scripts/lib/sdk-wire-drift.cjs`, `scripts/compare-sdk-wire-drift.mjs`, and `tests/browser/sdk-wire-drift.test.cjs`.

## Inputs and execution

```sh
node scripts/compare-sdk-wire-drift.mjs \
  --before /absolute/controlled-before.json \
  --after /absolute/controlled-after.json \
  --before-bundle /absolute/pinned-before.js \
  --after-bundle /absolute/pinned-after.js \
  --out /absolute/new-exclusive-report.json
```

All four inputs must be local files. Both receipts have a `schema: 1`, a fixed lowercase SDK name, 40-hex source revision, 64-hex bundle SHA-256, fixed fixture/policy/extension digests, a declared execution mode, evidence booleans, and 2–256 controlled case rows. The executable hashes each provided local bundle and refuses a mismatch; no remote SDK is fetched or executed. Receipts are capped at 128 KiB, bundles at 16 MiB. The optional output is created with exclusive `wx` mode and permissions `0600`; existing reports are never overwritten.

Each case has a short synthetic ID, tracking/functional kind, explicit method/resource transport, context-completion flag, received synthetic-canary event count, received decrypted application-byte count, and functional outcome. Both revisions must describe the **same case IDs, kinds, transports and setup**, so a changed fixture or policy cannot masquerade as SDK wire drift. The output contains no raw request URLs, captured bodies, canary values, cookies, credentials or personal identifiers. Extra input fields are rejected.

The comparator records newly escaping canary cases, stopped and persistent escapes, functional regressions, and tracking cases where **positive receiver bytes arrived without a parsed canary**. It never credits such opaque positive first-party traffic as zero leakage. A regression in completed functional controls, or loss of their received bytes, is explicitly a regression. Missing sender completion, route/meter proof, valid positive functional controls or a declared real-browser execution produces `NOT COVERED`, not a PASS. `NO NEW OBSERVED CANARY ESCAPE` means exactly that for the two provided, frozen observations; it does not mean no tracking, no pre-existing escapes, or no future sends.

The input's `native-chrome-proxy` flag, its provenance pins and its evidence booleans are **assertions in a supplied receipt**. This tool does **not independently attest** that Chrome ran, the extension rules were installed, traffic passed the proxy or a collector saw the claimed bytes. For a qualified result, upstream collection must independently produce native browser, origin TLS, proxy-route, sender and byte receipts.

## Test evidence and limitations

During this pass, the pure comparator was executed in an isolated JavaScript evaluator with seven targeted assertions; all seven passed. Six of the seven authored Node test callbacks were additionally executed using a compatibility adapter for `node:test` and assertion functions: **6 passed, 0 failed**. The seventh case uses a real Node child process and filesystem operations; it was authored but **not executed**, as was the complete installed Node/Python suite. Native Chromium remains **NOT COVERED** under the existing startup restriction; this pass did not retry it or touch any real SDK collector.

This makes SDK comparison possible once two independently qualified local recordings exist; it does not create those recordings. Positive opaque same-origin traffic cannot be reliably attributed to a particular SDK on multiplexed connections, requests scheduled after the bounded drain may still escape, and server-to-server tracking is beyond this tool's boundary. Nothing here changes Egress Guard's live grant/deny authority, blocklists, installed browser settings or user data.

Next: run all seven test cases as genuine `node --test` on a permitted complete checkout and execute the CLI against local, hash-pinned sample bundles. Only then feed in native controlled collector receipts from a permitted Chrome/proxy environment. Keep all discovery advisory and never promote rules automatically.
