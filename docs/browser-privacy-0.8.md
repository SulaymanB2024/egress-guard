# Optional Chrome profile privacy controls

Version 0.8 adds a separate page for managing ten fixed Chrome privacy settings. These settings address connections and browser features that ordinary page-request rules do not fully control. They apply to the current Chrome profile across sites. They do not install a network route, change the system proxy, hide the public IP address or verify that traffic uses Egress Guard.

Open **Settings → Browser privacy → Manage browser privacy** in the Chrome popup. Review the choices, then select **Apply selected protections**. Chrome requests the optional `privacy` permission at that explicit action. Opening the page, checking a box, inspecting status or installing the extension does not apply an unsaved choice. The initial checked boxes are only a proposed selection. Applying them can produce a partial result, which the per-control receipts show.

Firefox's existing manual companion does not load this controller or expose this page. Chrome 145+ remains the companion's minimum version. Each privacy API is detected separately because platform, policy and browser implementation can differ.

## Fixed controls and their costs

The controller accepts only the identifiers in `browser/core/browser-privacy.js`. The page cannot supply an arbitrary setting path, value or scope.

| Choice | Chrome setting and target | Meaning and limits |
| --- | --- | --- |
| Stop speculative page loading | `network.networkPredictionEnabled = false` | Disables Chrome prediction/preloading, including Speculation Rules. Page-initiated preconnect and DNS-prefetch remain outside this setting. Some navigation may feel slower. |
| Restrict WebRTC UDP | `network.webRTCIPHandlingPolicy = "disable_non_proxied_udp"` | Restricts WebRTC to proxied UDP or allowed TCP behavior. Calls may be slower or fail. TCP can still expose a public interface/address; this is not an IP-masking control. |
| Disable link-auditing pings | `websites.hyperlinkAuditingEnabled = false` | Disables HTML hyperlink auditing in the profile. It does not stop other request mechanisms. |
| Block third-party cookies | `websites.thirdPartyCookiesAllowed = false` | Applies Chrome's third-party cookie restriction. Browser exemptions and Storage Access grants can still permit access. Cross-site sign-in and embeds may break. |
| Disable advertising Topics | `websites.topicsEnabled = false` | Disables Topics where the browser still exposes this setting. |
| Disable browser ad auctions | `websites.fledgeEnabled = false` | Disables Fledge / Protected Audience where exposed. |
| Disable ad measurement APIs | `websites.adMeasurementEnabled = false` | Disables Attribution Reporting and Private Aggregation where exposed. |
| Stop sending typed searches for suggestions | `services.searchSuggestEnabled = false` | Stops search-provider suggestions while typing. A submitted search still goes to the chosen provider. |
| Disable the online spelling service | `services.spellingServiceEnabled = false` | Disables the remote spelling service while leaving local spell checking outside this control. |
| Disable the navigation-error service | `services.alternateErrorPagesEnabled = false` | Disables Chrome's web service for resolving navigation errors. |

These are profile settings, not per-site repair grants. A site permission in Egress Guard cannot bypass a selected profile restriction. Change the relevant selection deliberately if its compatibility cost is unacceptable. Safe Browsing, password managers, autofill and certificate verification are not in this catalog.

Chrome documents the setting semantics and their availability in its [privacy API reference](https://developer.chrome.com/docs/extensions/reference/api/privacy). The [Chromium WebRTC policy definition](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/WebRtc/WebRtcIPHandling.yaml) describes the remaining TCP/public-interface behavior. The implementation does not reinterpret the name `disable_non_proxied_udp` as proof that every WebRTC connection uses a proxy.

## Intent, ownership and actual values

Applying choices first writes a schema-checked local intent record containing a revision and selected catalog IDs. If that write fails, no browser setting is changed. Each selected control is then inspected through Chrome's `get({incognito: false})` API. The controller changes only settings that Chrome reports as controllable by this extension or already controlled by it. Every operation is followed by a fresh readback; successful completion of `set()` alone is insufficient.

The page reports the current value and whether it comes from Egress Guard, another extension, Chrome preferences or a browser/organization policy. These distinctions matter:

- A selected setting at the intended value is effective, even if another owner currently supplies that value. The receipt calls this `effective-elsewhere`; it does not claim ownership.
- A selected setting overridden to another value is degraded, and the page identifies the owner. The controller does not fight another extension or organization policy.
- An unavailable API, denied permission, malformed response or unreadable value is not reported as effective.
- A setting may change after inspection. Status describes the values returned at readback time; it is not continuous traffic attestation or a promise about a future value.

Readbacks must contain a known control level and a value of the correct type. The WebRTC setting accepts only Chrome's documented enum. An incognito-specific receipt cannot attest to the regular profile. Unknown rows make the overall receipt incomplete, even when an earlier operation returned successfully.

The page has a separate queue from DNR policy updates. If a request-rule API stalls, browser privacy status and recovery can still operate. Refreshing the page's status preserves checkbox edits that have not yet been applied. Errors are rendered as text.

## Release and recovery

Unchecking a choice and applying it calls ChromeSetting `clear({scope: "regular"})` for that setting. **Release all controls** first saves an empty selection, then clears this extension's overrides. The implementation never writes a captured copy of an old user preference. That avoids overwriting a preference the user, another extension or an administrator changed while Egress Guard was active.

Clearing also matters when another extension currently has higher precedence: Egress Guard can have a hidden lower-precedence override. The controller calls `clear()` even in that case. A failed clear remains `release-pending`; seeing another extension's current value is not proof that the hidden layer was removed. A subsequent worker restart retries the saved empty selection, so an interrupted release can recover without reconstructing the old values.

Use **Retry saved choices** after a transient API failure. It reconciles the persisted selection and reads the results again. With no saved intent, retry is read-only. If a permission has been revoked, the page reports that state; an unrelated permission event does not apply choices automatically. Applying again is the explicit path to request the optional permission.

If saved state is malformed, the controller reports a configuration error and makes no inferred setting changes. Apply a new valid selection or release the controls to replace that intent. Missing APIs cannot be made effective by a successful storage write.

ChromeSetting precedence and `clear()` semantics are defined in [Chrome's types reference](https://developer.chrome.com/docs/extensions/reference/api/types). Egress Guard uses the persistent `regular` scope. Chrome may inherit regular settings into incognito unless a separate scope overrides them; this page reads and attests only to the regular profile. It neither creates incognito-specific settings nor claims to verify every incognito window.

## Message boundary and stored information

The service worker accepts `browser-privacy-status`, `browser-privacy-apply`, `browser-privacy-retry` and `browser-privacy-release` only from the exact extension-owned `privacy.html`, with the current extension ID and top-level frame ID zero. Content scripts, popup messages, framed copies, arbitrary extension pages and foreign extensions do not receive write authority. Selection validation rejects unknown identifiers and duplicates. There is no general-purpose ChromeSetting bridge.

The local intent record contains only the selected control IDs, schema and revision. The controller does not retain previous preference values, visited sites, page contents or a history of setting inspections. It makes no inference or telemetry request. An explicit Chrome permission prompt is part of Apply; no operating-system or browser-profile setting was changed while developing and testing this feature.

## Verification and remaining target work

The controller tests run the actual source against isolated Chrome/storage models. They cover read-only first use, permission absence, all fixed controls, save-before-write failure, setting/readback errors, malformed receipts, managed/foreign precedence, hidden-layer release, restart recovery, no-saved-intent retry, corrupt persisted intent and invalid selections. UI tests cover explicit permission, denial, partial status, unsaved checkbox preservation and release. Worker tests cover the exact sender boundary and operation while the DNR queue is stalled.

These tests do not execute Chrome's real settings implementation. Native browser startup was denied by the development environment, and that restriction was not bypassed. Qualification still requires a disposable Chrome profile with real permission prompts, a second settings-owning extension or managed policy, regular/incognito overrides, worker restart and permission revocation. WebRTC behavior needs an actual connection-path test; cookie restrictions need browser exemption/Storage Access fixtures. API readback alone cannot prove either traffic outcome.
