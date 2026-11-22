# Collector window origin-contamination guard (November 22, 2026)

## Reproduced false-positive qualification

The optional real proxy/Chrome collector harness already obtains monotonic origin-side decrypted application-byte counters from every controlled origin. `measureActionWindow(before, after, host)` correctly returns `targetOriginApplicationBytes` and `otherOriginApplicationBytes`. However, `summarizeActionWindows` previously discarded the second field, and `assessFirstPartyActionWindows` could award a `PASS` based only on zero bytes at `publisher.test`.

In an isolated synthetic counterexample, both baseline GA4 actions deliver 20 and 25 bytes to the publisher, while the protected actions deliver 0 bytes to that publisher **and 15 and 18 new decrypted bytes to `tracker.test`**. The previous gate would report `PASS` despite 33 bytes at a different controlled sink. The new gate reports `NOT COVERED`. The other-origin traffic cannot safely be attributed to the initiating GA4 request, but it also cannot be silently counted as no collector delivery. A clean two-window baseline with no unrelated traffic and an entirely zero-byte protected arm still passes its narrow, sampled-window gate.

## Patch

- Carry per-window other-origin counters into the summary: number of positive other-origin windows and total other-origin received application bytes.
- Require every included window to supply finite, nonnegative, safe-integer target **and** other-origin byte evidence. Refuse summary integer overflow.
- Award bounded `PASS` only when the baseline positively delivers target bytes, the protected arm delivers zero target bytes, **and neither arm records non-target-origin delivery during its measured windows**.
- Update the existing receiver test fixture to supply the newly required counter and repair an existing scope-string mismatch. Add a separate four-test regression suite exercising both contaminated arms, the clean path, and invalid/overflowing counters.

The change affects **only offline/native-lab evidence assessment**, not proxy or DNR grant/deny decisions, list updates, browser configuration or a user's traffic. A non-target positive byte counter yields `NOT COVERED`, not a speculative claim that an SDK caused it. A protected positive target counter remains disqualified by the existing gate. Shared-origin request causality, arbitrarily delayed activity, and a real Chrome integration run remain unqualified.

## Executed qualification

Environment: Node v22.16.0 on Linux, isolated exact GitHub source mirrors. The original `collector-byte-windows.cjs` and `collector-byte-windows.test.cjs` matched Git blob IDs `168ab20f07919390aad565e5a8876b4b6db9539a` and `0a438ff04297eb68932e78322db3f3c60508f238` before patching.

Actual `node --test` on both existing and newly added collector-window suites: **10 passed, 0 failed, 0 skipped**. Modified files' Git blob IDs match the tested bytes:

- `tests/browser/collector-byte-windows.cjs`: `53879e987e0ffc80d69554388313aec21d464d71`
- `tests/browser/collector-byte-windows.test.cjs`: `76adb12c49bb191e7f72a6107b6ac765d46c32a1`
- `tests/browser/collector-origin-contamination.test.cjs`: `6918d4833492f2070b45c051b0a11b0350650335`

Full installed Node/Python suite, the runner's imported ESM/CDP lifecycle, native Chrome, macOS installed routing, WebRTC, vendor SDKs and any user-device results are **NOT COVERED**. The previous Chromium startup restriction was not retried or bypassed. The observed synthetic count is an evidence-integrity test, not a newly prevented tracking request or privacy-effect percentage.

Next: independently qualify the complete tests and controlled proxy/browser collector lifecycle in an allowed environment; retain explicit `NOT COVERED` for shared-origin and delayed attribution. Do not authorize live block decisions based on these counters.
