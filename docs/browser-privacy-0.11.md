# Browser privacy: Client Hints, setting receipts and GPC

This update adds an **optional, experimental high-entropy User-Agent Client Hints control**. It is off until explicitly enabled. It uses two fixed Chrome DNR rules and consumes no regex slots. The existing seven current profile settings remain separate. Three older advertising preferences remain manageable for compatibility, with their own legacy count.

The implementation has deterministic compiler, service-worker, setting-controller and DOM-model tests. Those tests do **not** qualify Chrome's network or document-policy behavior. The development environment does not permit native Chrome execution, and that restriction has not been bypassed. An installed-rule receipt states what Chrome returned from its rule store; it is not a fingerprinting, traffic-routing or anonymity measurement.

## 1. What the experimental control changes

Open **Settings → Browser privacy → Manage browser privacy**, then the **Limit high-entropy Client Hints · Experimental** section. Select the checkbox and use **Apply Client Hints choice**. The feature uses the extension's existing DNR and HTTP(S) host access; it does not request the optional `privacy` permission or alter the separate profile-setting choices.

| Layer | Change | Boundary |
| --- | --- | --- |
| Outgoing requests | Remove the eight detailed UA headers listed below from exposed HTTP(S) requests | Requires current extension host access and a request exposed to DNR. This is not a claim about every browser-owned request, other schemes or another extension's higher-precedence modifications. |
| Document responses | Add a fixed restrictive `Permissions-Policy` only when the original response has **no** `Permissions-Policy` header | Main-frame and subframe responses only. Existing policies, including empty or malformed headers, are not rewritten or combined. |
| JavaScript | Ask Chrome's native policy implementation to restrict `getHighEntropyValues()` in eligible documents | Workers, cached/synthetic responses, existing documents and other execution contexts require separate native qualification. There is no UA JavaScript spoofing. |
| Release | Remove the two rules through the same DNR owner that installed them | Reload affected pages. Removing rules cannot erase a policy already attached to an open document. |

The removed request fields are:

```text
Sec-CH-UA-Arch
Sec-CH-UA-Bitness
Sec-CH-UA-Form-Factors
Sec-CH-UA-Full-Version
Sec-CH-UA-Full-Version-List
Sec-CH-UA-Model
Sec-CH-UA-Platform-Version
Sec-CH-UA-WoW64
```

Low-entropy `Sec-CH-UA`, `Sec-CH-UA-Mobile` and `Sec-CH-UA-Platform` remain. The ordinary User-Agent, DNT, GPC, functional application headers, `Accept-CH` and `Critical-CH` are not changed by this control. The response policy contains empty allowlists for `ch-ua-high-entropy-values` and the eight corresponding UA hint directives. It does not restrict cameras, microphones, Bluetooth, local networking, fonts, workers or storage.

Chrome's [144 release notes](https://developer.chrome.com/release-notes/144#user-agent-client-hints-ch-ua-high-entropy-values-permissions-policy) introduce the document policy. The [UA Client Hints specification](https://wicg.github.io/ua-client-hints/#getHighEntropyValues) describes returning low-entropy values when that feature is denied and identifies separate HTTP hint policies. The implemented header/directive names are fixed in `browser/core/privacy-hardening.js`; the UI cannot submit new names, policy strings, resource types or priorities.

The restriction can affect sites that choose download packages, platform-specific behavior or compatibility workarounds using detailed UA information. The absence of these hints does not eliminate other fingerprinting surfaces, account identifiers or network metadata. No reduction in real-world linkability is claimed from merely installing these rules.

### Why existing Permissions-Policy headers stand down

Appending a second policy is not equivalent to adding an independent CSP restriction. Permissions-Policy is parsed as a structured dictionary. [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2) specifies that later duplicate dictionary keys replace earlier ones. The current Chromium parser rejects a malformed dictionary and rejects policy strings longer than 65,536 characters. Extending a valid policy close to that limit can therefore invalidate the entire policy, including unrelated server restrictions.

The implementation avoids that risk with:

```js
condition: {
  urlFilter: "|http",
  resourceTypes: ["main_frame", "sub_frame"],
  excludedResponseHeaders: [{header: "permissions-policy"}]
}
```

The exclusion checks presence, not a guessed value grammar. Empty headers, multiple fields, unusual casing, conflicting keys, invalid syntax and large existing values all decline this document-policy insertion. The outgoing request rule remains separate and does not depend on a response arriving. Chrome documents response-header conditions and their timing in its [DNR reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#type-RuleCondition).

This is a deliberate coverage limit: a document with an existing policy can still expose detailed UA values to its scripts unless its own policy restricts them. Another extension can independently alter response headers; Egress Guard does not claim authority over that extension. Native testing must check the actual response and document behavior, not just reproduce this condition in JavaScript.

Primary source inspection was pinned to Chromium commit `43721015c05f1c69cfa571cb8f6780837a00c976`:

- [Permissions policy parser](https://chromium.googlesource.com/chromium/src/+/43721015c05f1c69cfa571cb8f6780837a00c976/third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.cc): dictionary parsing and the 64 KiB input bound.
- [Navigator UA data implementation](https://chromium.googlesource.com/chromium/src/+/43721015c05f1c69cfa571cb8f6780837a00c976/third_party/blink/renderer/core/frame/navigator_ua_data.cc): policy check before setting requested high-entropy values.
- [Privacy API schema](https://chromium.googlesource.com/chromium/src/+/43721015c05f1c69cfa571cb8f6780837a00c976/chrome/common/extensions/api/privacy.json): the exposed setting surface at that source revision.

## 2. Authority and applied-state contract

The control stores only:

```json
{"schema":1,"revision":1,"enabled":true}
```

The key is `egressGuardPrivacyHardening`. There is no site history, page content, fingerprint value, old preference snapshot or telemetry in that record. Valid state requires an actual Boolean, a positive safe-integer revision and exactly the supported field names.

An explicit action first saves the new intent. A failed save cannot authorize a browser-rule change. The existing serialized DNR reconciler then includes the two rules in its complete desired policy, applies them atomically with that policy and reads the actual rules back. Exact rule contents matter, including priority, action, header names and response exclusions. The reserved rule IDs are `2000000000` and `2000000001`, at priority 48. They are header modifications above existing grants and Isolation's priority-46 header sanitation. They are never an `allow`, redirect or block override.

Ordinary site reconciliation and worker restart retain a valid saved selection. Relaxed mode is not an implicit release of this profile-wide option. An unreadable or corrupt saved choice does not silently remove an already installed restriction; the policy enters recovery until an explicit valid choice replaces it. If removal fails, the receipt remains `release-pending`. A partial, changed or unreadable rule set cannot produce an installed success claim.

These messages are accepted only from the exact extension-owned `privacy.html`, current extension ID and top-level frame zero:

| Message | Input | Effect |
| --- | --- | --- |
| `browser-privacy-hardening-status` | No additional fields | Read intent and actual DNR rules. |
| `browser-privacy-hardening-apply` | `enabled: boolean` | Save explicit intent, reconcile and read back. |
| `browser-privacy-hardening-retry` | No additional fields | Retry a valid saved choice. With no saved choice, inspect only. |
| `browser-privacy-hardening-release` | No additional fields | Save disabled intent and remove the two rules. |

Unknown messages, extra fields and non-Boolean choices are rejected. Content scripts, framed copies, popup messages and foreign extensions do not gain this authority.

The receipt uses `state`, `rulesConfirmed`, `installed`, `expectedRuleCount`, `observedRuleCount`, `verifiedRuleCount`, `revision` and `appliedRevision`. `installed` is `null` when Chrome's rule store could not be read. `rulesConfirmed` can be true for a confirmed disabled state; it does not mean the feature is enabled. `behaviorVerified` remains **false**, `experimental` remains **true**, and `evidence` is **installed-rules-only**. These values must not be relabeled as native behavioral qualification by the UI or a test model.

The existing ChromeSetting controller keeps its separate recovery queue. A stalled DNR update does not prevent releasing its WebRTC, cookie or browser-service overrides. The new Client Hints control uses the DNR queue because a second independent dynamic-rule writer would race the existing policy owner.

## 3. Current settings and legacy advertising preferences

The seven current setting choices cover speculative loading, WebRTC non-proxied UDP, hyperlink auditing, third-party cookies, address-bar suggestions, remote spelling and navigation-error services. Their mechanisms and compatibility costs remain in [the profile-control design](browser-privacy-0.8.md).

Google [announced retirement of Topics, Protected Audience, Attribution Reporting and Private Aggregation](https://privacysandbox.google.com/blog/update-on-plans-for-privacy-sandbox-technologies) in October 2025, with browser changes following its phase-out process. The [current Chrome privacy API reference](https://developer.chrome.com/docs/extensions/reference/api/privacy) and the inspected source still expose `topicsEnabled`, `fledgeEnabled` and `adMeasurementEnabled`. An exposed preference is not evidence that the associated web API still functions in the installed browser.

The three setting IDs remain valid so existing choices and hidden extension overrides can still be inspected and released. Previously authorized selections remain selected. New users do not get those legacy boxes preselected, and the page reports legacy preference confirmations separately from current setting confirmations. There is no automatic release, re-enabling or migration to an invented replacement API.

Profile receipts now label their evidence `chrome-setting-readback` and keep `behaviorVerified: false`. A confirmed value establishes the value returned by Chrome, not collector behavior. **Release profile settings** removes only Egress Guard's ChromeSetting layers; **Release Client Hints control** removes only the experimental DNR pair.

### WebRTC remains a routing control with limits

The existing selected value, `disable_non_proxied_udp`, is supported by Chrome's privacy API. Chromium's [WebRtcIPHandling policy definition](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/WebRtc/WebRtcIPHandling.yaml) describes proxied UDP and TCP/public-interface behavior. It does not promise that a public IP becomes hidden. A server-reflexive candidate by itself does not establish whether a particular configured route was bypassed.

Actual qualification needs a controlled STUN/TURN receiver, known proxy/exit configuration and positive connection controls. It must distinguish no usable ICE candidates from a working call through the expected path. This update does not set the system proxy, install a VPN, probe a public STUN service or change operating-system policy. ChromeSetting regular/incognito precedence remains as documented in [Chrome's types reference](https://developer.chrome.com/docs/extensions/reference/api/types#type-ChromeSetting).

## 4. GPC audit and deliberate limits

Egress Guard's existing eligible request rules send `Sec-GPC: 1`. Its MAIN-world document script supplies `navigator.globalPrivacyControl` only if no property already exists. This update also checks for an **own** property on `navigator`, so it does not install a misleading prototype fallback behind an existing own value.

Existing true and false values are preserved without invoking their getters. A frozen prototype, missing document `Navigator` or unavailable context receives no fabricated success. Re-injection does not replace the first installed getter. Worker globals are outside this script.

The fallback is distinguishable from a native WebIDL accessor: for example, its getter accepts a foreign receiver. A native-looking function string is not evidence of stealth or conformance. Existing false/native values and worker contexts can disagree with the outgoing HTTP signal. The UI and docs explicitly state those limits instead of inferring agreement from one document check.

The [W3C GPC Working Draft](https://www.w3.org/TR/gpc/) defines the HTTP and Navigator/WorkerNavigator signals and their relationship. Sending the signal is not technical proof that a website honors it. No Do Not Track preference is changed, and the supplied private fingerprint dump is not reproduced or persisted in this documentation.

## 5. Assessment of the supplied privacy recommendations

The executive guidance and all four assigned raw notes (05–08) were read, including their long unbroken lines. The recommendations were treated as hypotheses, not as verified measurements of the user's installed environment.

| Recommendation | Assessment for this implementation |
| --- | --- |
| Native high-entropy Client Hints policy | Supported by official Chrome documentation; implemented as a bounded opt-in experiment with existing-policy preservation. |
| Broadly append device/local-network policies | The directives have separate platform support and functional costs. Chrome [145 split local and loopback permissions](https://developer.chrome.com/release-notes/145#local-network-access-split-permissions), but that is not proof of universal transport coverage or zero breakage. No blanket device denial was added. |
| Delete the three old ad-API switches | Too abrupt: exposed preferences and saved extension overrides still need a release path. Marked legacy instead. |
| Automatically disable DNT | Rejected. It would override user intent based on an unmeasured uniqueness claim. |
| Infer a WebRTC proxy leak from one fingerprint excerpt | Unsupported without configured-route and receiver evidence. The selected setting and its readback remain available; no private IP is reported. |
| Assert zero prototype lies or anonymity | Unsupported. A consistency detector does not measure cross-site matching, and native restrictions can still be distinguishable. |
| Stop form reads by suppressing input/blur events | Incomplete. Scripts can read field values directly; content-script event suppression is not a script-origin isolation boundary. |
| Destroy all unpinned site storage automatically | Not adopted. It can remove drafts, logins and application state, while identity/account/network joins can survive. |
| Add cookie TTL decay for known tracker names | Existing code already removes named tracker cookies immediately. A longer TTL for those names is not an improvement. Unknown-cookie classification and regeneration need separate evidence. |
| Use email aliases or multiple exits | Potentially useful against particular join channels. Neither eliminates account, phone, shipping, timing or other correlations; generic Chrome PAC does not provide authoritative top-level compartment identity. |
| Treat JavaScript analytics hooks as a complete encrypted-payload defense | Incomplete and detectable; workers, clean realms and direct value reads remain. Keep any future experiment bounded and measure receiver outcomes. |
| Use a multi-identity linkability fixture | Worth pursuing with actual collector receipts, functional controls, separated ground truth and an attacker false-match metric. An exposed development corpus is not an internet-wide privacy estimate. |

## 6. Validation and remaining native cases

Focused source tests cover the pure rule catalog, sensitive-header boundaries, existing-policy stand-down, strict sender/input validation, persistence ordering, quota failure, rejected/partial/altered/unreadable DNR, worker restart, corrupt intent, release failure, concurrency, legacy preference retention/release, UI scope and GPC realm behavior. They run against deterministic models and the actual implementation source.

Required native cases remain:

1. A positive baseline must actually send the requested high-entropy headers before removal is credited. Check the controlled receiver, then enable the option from the real privacy page and repeat.
2. An eligible document with no existing policy should return only the low-entropy values requested by the relevant API contract. Preserve unrelated server headers and compare parent/subframe contexts.
3. Existing, duplicate, malformed and large policy headers must remain untouched. A present policy without a high-entropy restriction is an explicit residual case, not a passed JS reduction test.
4. Dedicated/shared/service workers, preloads, cached or synthetic responses, BFCache, already-open documents, site-access restrictions and competing extensions require separate results.
5. Verify release, restart and recovery against real dynamic-rule readback. Do not substitute hypothetical DNR matches for transmitted bytes.
6. Observe document/HTTP/worker GPC separately, retain native values, and leave DNT unchanged. A worker mismatch must not be hidden by aggregating it into a document pass.

No source or UI test in this update substitutes for those native outcomes. The optional collector runner is provided, but its native cases remain **NOT COVERED** until run on a permitted browser environment.

### Optional native collector runner

Source-only checks, which start no Chrome, Python process or listening socket:

```sh
node tests/browser/chrome-collector-lab.mjs --check
node --test tests/browser/collector-lab-contract.test.cjs
```

On a separately permitted machine with Chrome 145+, Python 3.12+ and the project's pinned `mitmproxy==12.3.1` environment:

```sh
node tests/browser/chrome-collector-lab.mjs \
  --chrome /absolute/path/to/chrome \
  --python /absolute/path/to/venv/bin/python \
  --extension /absolute/path/to/dist/chrome \
  --out /absolute/path/to/new-native-receipt.json
```

The runner requires an already built extension containing this Client Hints implementation. It records the artifact identity and coverage status without downloading lists or installing dependencies. It creates fresh profiles, runs the controlled Python proxy/collector, permits only the fixture certificate SPKI, denies browser external DNS resolution and compares the browser-observed leaf certificate DER with the collector's certificate hash through [CDP `Network.getCertificate`](https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-getCertificate). Missing certificate support is **NOT COVERED**; a different certificate fails qualification. No existing profile, global trust override, OS resolver or OS proxy configuration is accepted. The output file is created exclusively and is never overwritten.

The default cohort has four synthetic subjects visiting two distinct registrable sites. `--subjects` accepts two to eight. All cross-site pairs enter the exact-token attacker score, including visits with no observed identifier. Separate visit IDs carry scoring truth; the attacker only receives tokens actually delivered to the collector. The no-extension baseline runs with the fixture's tracker pause, while the protected arm runs the actual extension and normal proxy policy. This measures the combined stack. It does not isolate every improvement to the extension.

The cases cover first-party GA4 query collection, an opaque first-party POST residual, tracker fetch/image delivery, dedicated-worker and service-worker query collection, and functional POST controls before and after each visit. An expected-blocked case receives no credit unless its baseline actually delivered identifiable data and both contexts completed. Functional controls and the opaque residual are mandatory. Document/worker GPC observations and received HTTP signals are reported separately without a native override or worker-shim claim.

First-party GA4/worker case results establish absence of a completed semantic collector event. They do **not** establish zero partial request bytes on connections also carrying allowed assets and controls. Only the isolated tracker host has a separate whole-host zero-application-byte assertion, using the fixture's monotonic decrypted-read meter, actual baseline bytes, route correlation and browser closure. The receipt names its bounded observation interval. Handler errors, overflow, uncorrelated origin bytes or missing completion prevent qualification.

The Client Hints phase uses the real `privacy.html` sender, native DNR readback, absent/existing/malformed document policies, received header names, returned API key names and release. Header or API suppression cannot pass without actual baseline exposure. Raw fingerprint values are not retained. Duplicate/large policy headers, subframes, worker JavaScript restriction guarantees, BFCache, restart, optional privacy-permission handoff, WebRTC routing and WSS live revocation remain separate native cases. The shared driver includes `--no-pings`; this runner makes no hyperlink-auditing claim.

Only syntax and deterministic source-contract tests were executed during development. No Chrome process was launched.
