# 0.11: reviewed feed updates and collector evidence

**Status: alpha source revision.** This revision adds digest-bound feed review and rollback, optional verified regex optimization, an experimental browser-native Client Hints control, and controlled collector infrastructure. It retains origin TLS, the existing runtime dependency and privacy-preserving history default. It does not install or activate anything on the user's device.

The work follows the [bounded autonomous work program](autonomy/2026-11-21-program.md). Private raw handoff material and fingerprint details are not part of the repository. The program's [checkpoint](autonomy/2026-11-21-checkpoint.json) records what remains for subsequent passes.

## Feed updates can no longer silently pass the demonstrated substitution

The old count and integrity checks admitted a same-sized synthetic update that removed `google-analytics.com` and added `github.com`. Both policy instances remained ready while the tracker became allowed and the shared service became blocked. A valid download hash did not establish that its new policy was sensible.

The new tripwires compare selected known tracker coverage and shared-infrastructure additions using the feed's actual exact-host or suffix semantics. Suspicious candidates are kept separate from active bytes. Approval names the fixed feed, exact candidate-envelope SHA256 and exact installed-snapshot SHA256. A stale review cannot approve a different generation. Approval still cannot bypass syntax, size, minimum-entry, catastrophic-drop or publication-time checks.

The last distinct verified policy generation is retained. A two-slot transition record protects rollback through interruption before and after active publication. Rollback is restricted to the exact recorded previous generation; it retains its original timestamps and holds automatic replacement until explicit candidate approval. Cache publication returns `runtime_acknowledged: false`, since it does not prove a running proxy has applied the change.

These are a small audit catalog and recoverable update mechanics, not authentication of every publisher or comprehensive poisoning detection. Existing policy precedence is unchanged. Process-interruption tests do not establish power-loss durability. [Commands, threat boundary and recovery](feed-review-0.11.md).

## More room for deterministic browser defenses

On the same verified production-source snapshots:

| Artifact | Static rules | Regex rules | Regex count headroom |
| --- | ---: | ---: | ---: |
| Frozen 0.10 | 14,086 | 955 | 45 |
| 0.11 ordinary build | 14,180 | 941 | 59 |
| 0.11 with explicit verified optimization | 14,069 | **830** | **170** |

The optional path saves **125 regex slots relative to 0.10**, a **13.09% count reduction**. Ordinary finite lowering saves fourteen slots; exact-action union/factoring saves another 111. This increases capacity for future rules. It does not itself block more trackers.

Lowering preserves a bounded representable language. Union applies only to identical complete actions, priorities and all non-regex conditions. Captured substitutions and repeated header modifications are excluded. Requested optimization requires an existing pinned RE2 verifier, validates the full resulting artifact before publication, and packages replayable proof records in its build identity. Unavailable or incomplete verification fails the requested build.

The invariant is the same set of eligible `(priority, full action)` pairs for every request. Matching rule IDs can change; Chrome's unspecified tie choice among different equal-priority redirects is not promised identical. The existing 34-case tracking challenge retains exactly the same outcomes, including its nine escaped cases and two imported-filter functional overblocks. No new efficacy percentage is attributed to this work. [Compiler proof boundary and evidence](compiler-0.11.md).

## Experimental Client Hints control

The new choice starts **off**. Two fixed non-regex DNR rules remove eight detailed UA request headers and add a restrictive native document policy only when the response has no existing Permissions-Policy header. Existing empty, duplicate, malformed and valid policy headers all stand down rather than being blindly combined. The control does not spoof JavaScript or alter low-entropy UA hints.

Its saved intent, application and release use the existing serialized DNR owner. Exact readback, quota failure, restart, corrupt state and failed release have explicit receipts. Those receipts describe rule installation, with `behaviorVerified: false`. Native browser effects remain unqualified here.

The settings page now counts seven current profile controls separately from three legacy advertising preferences. Saved legacy overrides remain releasable. The GPC shim preserves existing Navigator values and documents its document-only, detectable scope; network, window and worker signals can differ. [Design, official source references and remaining native cases](browser-privacy-0.11.md).

## Measure delivery without hiding the residual

The controlled Python experiment uses four synthetic identities on two distinct registrable sites through the actual pinned proxy and original TLS. A decrypted-read byte meter sees partial requests as well as complete collector events. Prior delivery, functional controls and proxy-route evidence accompany zero-byte assertions.

Enabling tracker blocking prevents the eight listed-collector deliveries with zero application bytes on those attempts. All eight admitted first-party identity POSTs still arrive. The exact-token attacker therefore loses that third-party channel while retaining **4/4 true matches across all observed channels**. That is an explicit residual, not an anonymity gain.

A separate actual TLS/WebSocket regression confirms that a new deny stops subsequent origin application bytes after the proxy acknowledges the changed policy. The optional combined Chrome/proxy runner covers fetch, image and worker cases plus Client Hints/GPC observations; its static contracts are tested, but native execution is **NOT COVERED** in this environment. [Method, results and commands](privacy-lab-0.11.md).

## Qualification and remaining work

The [machine-readable release qualification](validation-0.11.json) records the full Python/JavaScript suites, both complete browser builds, actual-artifact RE2 audits, the unchanged frozen protocol challenge, package checks, source hashes and native gaps. Historical 0.10 benchmark results are retained rather than rewritten to match this revision.

| Gate | Observed result |
| --- | --- |
| Full Python suite | 361 passed; no failures or skips |
| Full JavaScript suite | 377 passed; no failures, skips or cancellations |
| Ordinary artifact RE2 audit | 941 / 941 passed across all 17 static rulesets |
| Optimized artifact RE2 audit | 830 / 830 passed across all 17 static rulesets |
| Frozen protocol challenge versus 0.10 | Identical outcomes; zero new false positives or regressions |
| Controlled collector | Both intended arms pass; broken-extractor injection correctly fails |
| Wheel | 31 source/assets files exactly matched; clean target install and empty-cache refusal passed |
| Native Chrome | NOT COVERED; source-contract checks only |

The same explicit parameter quarantine for `analytics_trace_id` remains. Native Chrome acceptance, actual header/document behavior, macOS service lifecycle, native messaging and device-wide routing remain separate target work. Dependency versions are unchanged; prior unresolved advisory records remain visible in [the dependency assessment](../requirements/README.md).

After updating source or installing a newly built package, restart the proxy and separately rebuild/reload the companion. Existing installations do not acquire these changes from a source merge. New Client Hints restrictions require explicit enablement and a document reload. Feed review never grants a broad network exception, and optional models still have no authority to grant live requests.
