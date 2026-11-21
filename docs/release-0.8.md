# 0.8 implementation and qualification record

Reviewed base: `cbed36aca18ac8461f7d40b89089178e584629f7` (merged 0.7.0). Implementation and review: 2026-11-21.

This source update extends four protection boundaries: initial TLS hostname checks, default-Strict admission of active browser resources, imported cosmetic coverage, and explicit Chrome profile privacy controls. It remains an alpha. The implementation does not claim anonymity, universal ad removal or completed native deployment.

## Material changes

| Area | Implemented behavior | Practical cost or boundary |
| --- | --- | --- |
| Proxy tunnel admission | Independently check the CONNECT destination and visible initial TLS server name before upstream TCP contact. | ECH inner names, later encrypted requests and traffic outside the proxy remain invisible to this check. |
| Default Strict | Keep an installed hold on scripts, subframes, fonts and objects until the complete named site policy is installed atomically with its exclusion. | Initial first-party resources can be held. Some addresses cannot be prepared safely, and a partly loaded page may need a user-selected reload. |
| Imported cosmetics | Add indexed generic ID/class rules, PSL entity scopes and bounded native `:has()` selectors, preserving selector and page exceptions. | A restricted grammar with explicit work caps; cosmetic hiding cannot undo network requests or impressions. |
| Browser profile controls | Explicitly manage ten fixed Chrome privacy settings with save-before-write, actual-value/owner readback and recovery. | Requires optional permission; browser policy or other extensions can override a choice. WebRTC and cookie controls have compatibility costs and exceptions. |

### A concrete tunnel bypass closed

A proxy-aware client can CONNECT to an allowed IP address or hostname while naming a listed tracker in the subsequent TLS ClientHello. The old transport admitted the CONNECT authority without applying hostname policy to that visible TLS name. Version 0.8 checks both inputs using the current policy. A temporary grant for the first name does not transfer to the second, and a grant or policy that changes while the hello is fragmented is checked again at admission.

The new `TunnelGuard` holds short prefixes that the pinned transport's default classifier could otherwise treat as non-TLS. It accepts fragmented hellos within explicit 32 KiB/32-read bounds, refuses malformed or ambiguous server-name extensions, and passes accepted bytes unchanged into the opaque relay. Integration tests assert zero upstream accepts for refused names and verify the exact origin certificate for accepted TLS.

This is not TLS interception or a mechanism for decoding ECH. The original client still validates the origin certificate. A deliberate allowed relay, a later request inside an accepted connection or a protocol that upgrades to TLS after a plaintext start retains the documented limits. See [transport design and test evidence](core-0.8.md).

### Default Strict without the old unknown-site gap

The new preparation hold does not depend on the immediate request initiator's party classification. It therefore covers the cold nested-frame case before the outer site's exact policy exists. The compiler represents the complement of prepared PSL sites, including nested private boundaries. Preparing `amazonaws.com` cannot release an unknown `s3.amazonaws.com` tenant.

Preparation is an atomic replacement of dynamic rules. There is no temporary permissive release rule and no automatic page reload. Failed post-mutation readback invalidates the old preparation receipt; later bookkeeping failure can report a prepared site alongside an overall degraded policy. The popup explains held, prepared and unknown states separately.

Current tabs and at most 128 transient navigation contexts drive automatic preparation. Those contexts are in memory, keyed by source tab and scheduled for expiry after 60 seconds. Inactive sites are not restored from local receipts. Final deletion of retired tabs runs after earlier queued messages/prewarms, and replacement explicitly retires the old tab ID. This avoids a persistent inactive-site cache and the reproduced queue races that could recreate closed-site metadata.

The hold begins only after the new default-Strict policy has been installed. It does not remove inline scripts, navigation cookies, request bodies, browser storage or cached/service-worker-generated responses. Unscopable IP addresses, localhost, single-label hosts, public-suffix addresses and certain wildcard registry bases remain held. The popup keeps the default-mode choice available so Standard can be selected explicitly. See [enforcement, lifecycle and recovery](enforcement-0.8.md).

## Source-rule coverage

This comparison uses the same verified EasyList/EasyPrivacy snapshot, version `202611211610`, as the 0.7 record. It isolates compiler capability from changes in list contents.

| Compiled output | 0.7 | 0.8 |
| --- | ---: | ---: |
| Generic hide rules | 0 | 13,079 |
| Scoped hide rules | 9,043 | 9,718 |
| Total imported hide rules | 9,043 | 22,797 |
| Identical-selector exceptions | 324 | 326 |
| Cosmetic page exceptions | 0 | 167 |

The 0.8 scoped set includes 482 native relational rules; 278 accepted entries contain an entity scope. Those categories overlap. They are not additional independent totals. The complete source hashes and reproduction inputs are recorded in [content filtering](content-0.8.md) and [the machine-readable validation record](validation-0.8.json).

Generic rules use ID/class indices and bounded traversal of changed DOM subtrees. The runtime does not run 13,079 document queries per mutation or append all imported rules to an unchecked stylesheet. Existing reversible records protect forms, editors, players, focus and structural context; later token, descendant or relationship changes are revalidated.

Source exceptions remain part of enforcement. Unsupported exception scopes quarantine the affected selector or disable the affected imported family, with visible reduced coverage. A normal complete build refuses that fallback before replacing previous output. The current snapshot needs no such fallback. A bounded finite-state matcher handles page exception patterns without executing arbitrary source regexes; exhaustion conservatively disables the affected family. Same-document navigation updates exception policy, including the case where local-model scanning occurs before the worker's location notification.

These counts measure accepted source rules. They do not establish ad-detection recall, false-positive rate, tracking prevention, rendering speed or battery use. Real Chrome CSS and real-page qualification remain outstanding.

## Chrome profile privacy controls

**Settings → Browser privacy → Manage browser privacy** opens the new explicit selection page. The ten choices cover speculative loading, non-proxied WebRTC UDP, hyperlink auditing, third-party cookies, exposed Topics/ad-auction/ad-measurement APIs, search suggestions, remote spelling and navigation-error services.

The extension requests `privacy` permission only through Apply. It persists selected catalog IDs before mutating any setting, uses Chrome's reported control level, and reads actual values afterward. Another owner already supplying the requested value is shown separately from Egress Guard ownership. Unknown or unreadable values are incomplete.

Release calls ChromeSetting `clear()` for this extension's regular-scope overrides; it does not restore an old snapshot of user preferences. Failed removal of a hidden lower-precedence override stays pending and is retried after restart. The controller's independent queue remains usable if DNR is stalled. Only the exact top-level extension settings page can send its fixed control messages.

The feature has no general setting-write bridge, inference call or setting-inspection history. It does not change Safe Browsing, password managers, OS routing or another extension's configuration. Read [the fixed catalog, tradeoffs and ownership contract](browser-privacy-0.8.md).

The existing on-device model remains a bounded, explicitly invoked review tool. It does not decide network admission or generate permissions. The new protection paths operate without it; no model-accuracy or latency result is claimed.

## Verification

The final integrated suites passed **280 Python tests and 252 Node tests**, with zero failures or skips. This is 532 tests, not 532 independent attack classes. Python includes real loopback proxy/TLS fixtures; Node exercises the compiler, worker, setting controller and DOM/UI models.

| Check | Observed result |
| --- | --- |
| Python suite | 280 passed, including initial TLS fragmentation, pre-upstream refusal, grant separation and changed-policy admission. |
| Node suite | 252 passed, including private-tenant holds, atomic failure/readback, retired-tab races, indexed cosmetics, conservative exemptions and profile-control recovery. |
| Pinned PSL regeneration | Matches; 10,470 rules, snapshot `2026-11-20_10-39-09_UTC`. |
| Real browser-list compilation | 22,797 hide rules, 326 selector exceptions, 167 page exceptions, 13,825 static DNR rules and 56 regex rules. |
| Wheel | Built and installed in a fresh temporary target; version, private initialization, default history, empty-cache refusal, indeterminate lookup and packaged modules/assets verified. |
| Dependency consistency | `pip check` passed in the pinned validation environment. Dependencies are unchanged. |
| Source archive | Required new modules, tests, browser assets, PSL/notices and documentation included; runtime state/caches excluded. |

The real-list validation build intentionally omitted proxy domain feeds and correctly reported reduced overall coverage. It is not a complete production feed bundle or evidence that Chrome indexed the output. The earlier attempt to refresh all proxy feeds could not complete in this environment; this release does not replace that missing qualification with fixture data.

Native Chromium startup was previously denied by the environment's socket policy. The restriction was not bypassed, and no native browser was launched for 0.8. Real DNR/header effects, native CSS matching, ChromeSetting behavior, model inference and installed native messaging therefore remain unqualified. macOS service operations are mocked. The release includes a dedicated disposable-profile qualification runner; its syntax and fixture contracts can be checked here, but its browser results must be obtained on a permitted target.

The same-day 0.7 dependency review found four documented advisories against the unchanged Tornado 6.5.10 pin. No fresh online dependency scan was performed for this patch, no dependency constraint was overridden, and no clean vulnerability-scan claim is made. See [dependency reachability and upstream limits](../requirements/README.md).

Reproduce the isolated gates with the pinned environment:

```sh
PYTHONPATH=src python -B -m unittest discover -s tests -v
node --test tests/browser/*.test.cjs
node scripts/update-psl.mjs --check
git diff --check
```

These checks use temporary state. No live browser profile, native-host registration, operating-system proxy setting, firewall configuration or trust store was changed.

## Upgrade and remaining qualification

Python and both browser manifests are versioned `0.8.0`. The source update does not install itself. Preserve the existing installation until selecting a manual upgrade path, rebuild the browser extension from verified sources, reload it and inspect both policy and coverage receipts. Chrome's minimum version remains 145. `webNavigation` is newly required for preparation hints; profile controls use separately requested optional `privacy` permission.

Existing Standard policy retains its behavior. An existing default Strict choice adopts the stronger preparation hold after the new policy applies, with the compatibility costs described above. Profile choices begin unapplied. Fresh Python configurations still default to no domain history; existing explicit history settings and old committed records are preserved.

Before distributing an installed release, qualify cold navigation, nested frames, private tenants, prerender/BFCache, actual request/header observations, native relational CSS, protected-content restoration and profile-setting precedence/release in a disposable Chrome profile. Verify actual WebRTC paths and cookie exemptions separately from API readback. Existing local-model, native-host and macOS lifecycle gates from 0.7 remain open. The [release checklist](releasing.md) records these requirements.

This work closes specific bypass and coverage gaps. Device-wide routing, malicious software running as the local user, first-party identity, authenticated accounts and fingerprint correlation still require separate defenses. The proxy and extension do not make an Internet session invisible.
