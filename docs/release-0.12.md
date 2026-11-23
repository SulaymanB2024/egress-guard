# 0.12: policy-aware feed publication and idle revocation

This revision starts from `74b1ec5`, after the earlier autonomous window and
PRs #6–14 completed. It changes live enforcement in three places: automatic
feed publication, activated idle tunnels and selected Prebid user-sync requests.
It also adds source and collector qualification that keep unmeasured behavior
separate from tested protection.

## Feed updates are evaluated as policy changes

A count-preserving update can still remove a tracker, add a critical service or
move an allowed hostname into a threat category that the user's repair cannot
override. The new comparison replaces one verified feed in an in-memory copy of
the actual production `Policy`. Every other selected component, local rule and
configuration setting stays fixed. Both versions use the same decision logic,
evaluation instant and port context.

The packaged, digest-pinned corpus contains **64 public hosts and 95 hostname
contexts**, including 31 explicit synthetic descendants. It includes shared
infrastructure, actual developer endpoints, authentication/update/revocation
hosts, tracker anchors and four DoH hosts. These are string-only evaluations at
port 443. They do not generate requests to those services. The set is deliberately
reviewed and bounded; it was not padded to a larger headline count.

Automatic publication holds a complete candidate comparison that newly blocks a
public critical probe or allows a previously blocked public canary. A separate
counterfactual expires temporary grants while keeping all other captured inputs
fixed, so a tracking pause cannot hide a future critical deny. Permanent allows
retain production precedence. Configured allow/exemption effects are reported
for review, including changes in category and override authority; they do not
become new automatic allow rules.

Missing, corrupt or incomplete baselines are explicitly uncovered. Individually
validated bootstrap and repair still use the existing hard feed validators.
Digest-bound approval and rollback remain available, with the existing exact
candidate/base authority and rollback hold. The checker does not read browsing
history, SQLite activity, DNS or network traffic.

Review uncovered a publication race after the first implementation: a control
edit during the active temporary-file write could outlast the earlier check.
The base digest and policy checks now run after the temporary file is flushed,
immediately before the final replacement. An injected edit at that fsync boundary
must refuse publication and retain the active policy and usable rollback. This
is not a transaction across independently edited files; the small final
check/rename interval remains outside that claim.

[Decision-impact design, commands and configuration binding](feed-impact-0.12.md).

## Activated idle tunnels can now be revoked

`PolicyRelay` keeps checking every outgoing command in both directions and adds
one owned timer after its first admitted send. A changed deny, expired grant or
failed admission check can close an idle connection without waiting for a new
application frame. The timer uses the pinned transport's existing event loop;
it creates no heartbeat, payload buffer, TCP history or thread.

The real loopback experiment first confirms collector delivery and a concurrent
functional socket. After acknowledging a deny, it sends no more collector data.
The collector closes; both post-deny collector emission and origin application
byte deltas are zero; all **8/8** subsequent functional frames arrive. Separate
tests cover stale timers, queued connect bytes, half-close, policy errors and
terminal revocation.

The one-second cadence is not a hard expiry guarantee. Initial pending tunnels
before their first admitted send retain their existing next-forward checks.
Already forwarded bytes cannot be recalled. [Lifecycle and timing limits](tunnel-revocation-0.12.md).

## Bounded Prebid coverage and pinned SDK evidence

The Prebid signature now recognizes one plain public path prefix, such as
`/prebid/setuid` or `/pbs/setuid`, while preserving the exact final endpoint,
singleton query fields, method and resource-type constraints. Empty-UID deletion,
duplicate identities, encoded/unknown keys and unsupported resource types still
decline the signature. No broad allow is added.

All six changed patterns fit the existing 2,048-byte RE2 budget. Two- and
four-prefix alternatives failed that gate and were rejected. The rule catalog
stays at 29 rules. Three authored prefixed cases become recognized with no newly
blocked functional controls in their separate 16-case development check.

The authoritative seven-family manifest is
[`tests/fixtures/sdk_drift/manifest.json`](../tests/fixtures/sdk_drift/manifest.json).
It records immutable URLs, acquisition dates, byte hashes and evidence tiers for
11 acquired files. Matomo and PostHog include selected SDK source; Prebid is
server source; Fingerprint Pro is integration documentation. GA4, GTM and Meta
deployed SDK bundles remain unacquired. None of these source checks executes a
vendor lifecycle or qualifies native collection prevention.

Pinned PostHog source supports the recorded bundled-recorder and compressed-body
escape analysis. The proposed Meta November default date and exact GA4-to-Meta
sharing scope were not verified from accessible primary text. Google's reviewed
Meta Links documentation describes the opposite data-import direction. No rule
was built from an unverified rollout claim. [Sources, phase inventory and CLI](sdk-drift-0.12.md).

## The collector now separates shared-connection channels

The proxy counts admitted TLS emission commands. The owned origin independently
counts every decrypted read and assigns complete HTTP/1.1 requests or supported
WebSocket frames by consumed framing offsets. Buffered prefetch and connection
reuse do not mix a functional request into a collector request. Partial and
truncated input remains in an explicit remainder.

Evidence failures cannot manufacture a block: a failed meter write still forwards
the admitted command and signals the parent through an independent error pipe.
The run then refuses qualification. Exact issued-token extraction, expected visit
identity, origin certificate, proxy route, functional responses and complete
cross-site pair denominators remain required.

| Channel | Baseline matches | Protected proxy matches |
|---|---:|---:|
| Third-party collector | 4/4 | 0/4 |
| First-party URL/header collection | 4/4 | 4/4 |
| First-party body collection | 4/4 | 4/4 |
| First-party WebSocket telemetry | 4/4 | 4/4 |
| All observed channels | 4/4 | 4/4 |

Both arms preserve **16/16 functional responses** and **8/8 visits sharing one
TLS connection**. Every row retains twelve different-subject comparisons with
zero false matches. A broken extractor makes the qualification fail even when
all bytes and functional responses arrive. These are synthetic exact-identifier
results, not a population anonymity estimate.

[Accounting definitions and reproduction](channel-accounting-0.12.md),
[actual channel receipt](benchmarks/channel-lab-0.12.json).

## Native regex qualification is implemented, not executed here

The combined browser runner now inventories every manifest static regex,
including disabled rulesets, and has a gate that calls Chrome's actual
`isRegexSupported` with each rule's case and capture options. It checks the
loaded package bytes, every response, input hashes and final artifact stability.
Missing or partial API evidence stays uncovered; native rejections fail.

Both complete offline artifacts passed the separate pinned RE2 audit:

| Artifact | Static rules | Regexes audited | Rejected at 2,048-byte budget |
|---|---:|---:|---:|
| Default | 14,180 | 941/941 | 0 |
| Explicitly optimized | 14,069 | 830/830 | 0 |

Chrome still requires version 145. Existing Permissions-Policy headers remain
preserved. Blanket `Accept-CH`/`Critical-CH` removal was not added: it would not
close the document JavaScript API gap and could remove an empty `Accept-CH`
instruction that clears stored preferences. [Primary references and native scope](browser-privacy-0.12.md).

## Qualification and remaining work

The [machine-readable validation](validation-0.12.json) records the full test
results, package checks, source hashes and exact artifact receipts. The starting
main tree passed all 363 Python tests but had three stale JavaScript fixtures;
those fixtures were repaired without weakening their runtime guards. The final
JavaScript suite passes **429 tests**; the final Python suite passes **420 tests**. Neither suite has failures or skips. A fresh wheel install verifies all **33 source and asset files**, including the pinned public corpus, and refuses empty-cache startup before any network or subprocess attempt.

The frozen 68-case protocol challenge retains its previous outcomes: **25/34
tracking cases prevented, nine escaping, and two imported-filter functional
overblocks**. There are no new regressions or false positives in that challenge,
and its measured relative improvement remains **0%**. The new prefix examples
are separate development evidence. This revision makes no 30% privacy claim.

Native Chrome did not run. Browser header/cookie sanitation, Client Hints in
Window/worker contexts, GPC behavior, real SDK retries/unload, opaque bounce
chains, server-side relays, HTTP/2/3 multiplexing, macOS installed lifecycle and
device-wide routing retain explicit qualification gaps. The earlier Chromium
startup restriction was not retried or bypassed.

Dependency versions and privileges are unchanged. The prior dependency advisory
assessment still applies. No inline LLM request authority was added: the proxy
cannot expose encrypted first-party bodies to a model, and speculative decisions
would not repair that visibility limit. Existing optional local-model suggestions
retain their bounded review role.

Source merge does not update an installed device. A manual package update needs a
proxy restart; the companion needs a separate rebuild and reload. The existing
parameter quarantine remains explicit. Runtime changes should be qualified on
the intended macOS and permitted Chromium installation before claiming broader
coverage.
