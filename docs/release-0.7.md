# 0.7 implementation and qualification record

Reviewed base: `be1cb768059fba995d0470ca6f700fbfbd48639a` (0.6.0). Implementation and review: 2026-11-21.

This change expands browser ad filtering and repairs enforcement/privacy failures reproduced against that base. It is an alpha source update, not a claim of anonymity or completed native deployment.

## Material additions

| Area | New behavior | Practical boundary |
| --- | --- | --- |
| Scoped cosmetics | Build verified EasyList/EasyPrivacy domain-scoped hide rules and exceptions into safe runtime data. | Restricted selector subset; no arbitrary scriptlets or full upstream grammar. |
| Sponsored cards | Deterministic paid-card evidence, reversible hiding, explicit local-model review interface. | Cosmetic effects do not prevent every network request; no model efficacy claim. |
| Policy application | Desired, saved and read-back applied states; recoverable reconciliation and visible failure. | Chrome's dynamic and session updates are separate operations; partial application is reported. |
| Temporary repair | Journaled, reconciled tab/site grants with sanitation and threat/manual-deny precedence. | Scheduled expiry, not browser-enforced hard wall-clock leases. |
| Site boundaries | Full pinned Public Suffix List, private suffixes, safer stored-scope migration and top-level Chrome conditions. | Default Strict has a documented first-navigation race for previously unseen sites. |
| Live logging | Writer acknowledgment and generation-based discard of old queued/dequeued records. | Already committed history is retained. |
| Native status | Optional exact-origin read-only bridge for authenticated proxy/logging receipts. | No browser-profile binding or proof of routing. |
| Build integrity | Complete-source and effective-compilation gates, bounded streaming reads, recoverable output publication, atomic filter-cache snapshots. | Source authenticity still depends on the selected HTTPS publishers; large changes need review. |

## Reproduced defects addressed

The 0.6 review found saved Strict policy presented as active after DNR failure, startup failures that never retried, orphaned session allows after storage failure, grants able to outrank newly classified threats, and a small hand-maintained suffix table that could widen permissions across tenants. The reconciler and compiler now have regression coverage for these boundaries.

Content regressions cover the old “busy page restores all hides” behavior, broad picker choices, newly inserted protected content remaining hidden, and embed retries dropping integrity/type/CORS/referrer policy/nonce. Late SPA embeds and documented custom GTM queues are handled without evaluating arbitrary global property paths.

Core regressions cover the live full-to-none logging failure, temporary controls missing from revision receipts, equivalent mapped IPv4/IPv6 decisions, ambiguous numeric spellings, incomplete-feed explanations and readiness checks for preexisting services.

The full component explanations are in [enforcement](enforcement-0.7.md), [content filtering](content-0.7.md) and [proxy/native receipts](core-0.7.md).

## Local-model boundary

The experimental model feature is user-initiated, uses Chrome's on-device Prompt API and has no remote inference fallback. A fresh session receives at most 24 short card candidates. The output schema permits known IDs and four labels only. Selection and application are separate user actions; every candidate is checked again by deterministic content code. No model output can weaken network protections.

Extraction has sensitive-page heuristics, URL/email/long-ID redaction, size bounds and protected-card exclusion. These do not prove that an arbitrary page contains no personal data. The review page requires explicit confirmation that the source is public and contains no private information. Navigation cancels inference and clears the captured snippets. Timeout and late-session cleanup are tested.

This implements a constrained local inference interface, not a packaged or benchmarked small quantized model. Chrome owns model download, support and execution. There is no measured recall, false-positive, battery or latency result for this release.

## Source compilation check

The 2026-11-21 build-time check used EasyList and EasyPrivacy version `202611211610`:

| Source | SHA-256 |
| --- | --- |
| EasyPrivacy | `84e1f89c2783f1b3ada395d8a8f0bcd3fd43c07b0fd7149a2d6c5bbd4695c6c7` |
| EasyList | `08d8efac3d18fa78e5656070769926fe2bf694d057545fce7c34dbf9deddf271` |
| AdGuard click-throughs | `8eeaa753f30270bd47c05fb34f3e34b11eb55a086896796897946ec940c873d8` |

The cosmetic compiler examined 24,864 relevant lines and emitted **9,043 scoped hide rules plus 324 exceptions**. It rejected 13,638 unscoped hides, 1,247 unsupported selectors, 323 unsupported domain scopes and 289 procedural/scriptlet lines. These are compiler counts, not a measured number of ads removed or trackers prevented.

The runtime caps per-page scoped rules and work. A large rule bundle therefore does not imply that every matching source rule will run on a complex page. See the content document for bounds and prioritization.

## Qualification record

The integrated Python suite passed **264 tests** and the Node suite passed **196 tests**, with no failures or skips. These cover Python unit and real loopback transport behavior, compiler/worker/DOM-model behavior and model-interface failure handling. They are 460 tests, not 460 independent attack classes.

The wheel built and installed into an empty temporary target. Its version, private initialization, default history setting, refusal to start with an empty cache, indeterminate empty-cache lookup, native-host module and dashboard assets were checked. `pip check` reported no broken requirements. The source archive was separately checked for the new browser modules, PSL source/notices, native host and documentation, and for exclusion of runtime state.

The current EasyList/EasyPrivacy browser build produced 13,825 static rules and 56 regex rules, within the configured 30,000/1,000 budgets. This validation build omitted domain feeds and correctly reported reduced coverage; it is not a complete production feed bundle or proof that Chrome indexed the result. The attempted proxy feed refresh could not complete in this environment.

Chromium aborted before opening a browser context because its required process-singleton socket was denied with `Operation not permitted`. No bypass was attempted. Actual browser fixtures, screenshots, local-model inference and installed-native-host operation therefore remain unqualified here. macOS service tests are mocked; earlier release measurements are not reused as 0.7 results.

An explicit OSV review of all 51 locked package versions again found the four documented Tornado 6.5.10 advisories. The latest released parent transport remained mitmproxy 12.3.1, with its existing dependency constraint. No dependency version was silently overridden and no clean vulnerability-scan claim is made. See [dependency reachability and upstream limits](../requirements/README.md).

Run these checks from a clean checkout with the pinned dependencies:

```sh
PYTHONPATH=src python -B -m unittest discover -s tests -v
node --test tests/browser/*.test.cjs
node scripts/update-psl.mjs --check
git diff --check
```

The real proxy fixtures use loopback servers, temporary state and the pinned transport. Native service operations are mocked. No private browser profile, operating-system routing, trust store or real native-host registration is changed by these tests.

Before distributing an installable release, qualify:

1. Chrome 145+ DNR readback, nested-frame scopes, session grants, cookie/referrer sanitation and actual alarm/restart behavior.
2. Real page layout, picker and protected-content behavior, SRI/CSP-preserving embed retry, and the actual GTM redirected-script contract.
3. Chrome Prompt API availability/download/cancel behavior and an independently labeled ad/non-ad corpus on supported hardware.
4. Installed Chrome-to-native-host framing and registration on macOS and Linux, including absence, mismatch and upgrade cases.
5. macOS service lifecycle, receipts, sleep/restart and recovery on a target device.

The normal source update does not activate a native system filter, install a root service, alter LuLu, replace a VPN, hide the public IP address or block traffic from applications that bypass the proxy. Browser logins, first-party identifiers, fingerprinting and network observers remain separate privacy problems.

## Upgrade and recovery

The Python and browser manifests are versioned `0.7.0`. Preserve your existing installation until choosing a manual upgrade plan; the project still has no automatic installed-application upgrade transaction.

Fresh configurations now default to `history = "none"`. Existing explicit history settings remain unchanged. Changing to none discards outstanding old-generation records but does not erase prior rows from disk. Browser state migrates to stricter scope semantics; old permissive settings may need to be created again. Rebuild the extension and reload it, then check its policy and coverage receipts.

Keep the existing firewall and browser defenses while qualifying the new build. The native receipt bridge unifies status inspection, not system-wide enforcement. A signed native network filter, broader first-party behavioral learning, fingerprint normalization and device-wide routing enforcement remain separate engineering work.
