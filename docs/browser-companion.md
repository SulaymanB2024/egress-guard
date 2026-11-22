# Browser companion 0.10

The companion supplies URL-level request rules, source-backed tracking-protocol signatures, maintained tracking-parameter and cookie cleaning, named-site isolation, indexed generic and scoped page-element hiding, optional local review of sponsored cards, and explicit Chrome profile privacy controls. Chrome is the primary implementation. Firefox retains manual HTTP/S request/cosmetic rules; it does not have the Chrome built-in list, protocol-signature, socket-deny, isolation, model or profile-control feature set.

The extension remains an unsigned alpha. It works without the proxy. An optional read-only bridge can show the proxy's authenticated state in the popup; that connection does not route browser traffic or establish device-wide protection.

## Build and load

Use Chrome 145 or newer and Node 20 or newer. The local model has additional browser/device requirements and may be unavailable even when filtering works.

1. Refresh the proxy's verified source cache:

   ```sh
   egress-guard refresh
   ```

2. Build the extensions:

   ```sh
   node scripts/build-browser.mjs
   ```

3. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `dist-browser/chrome`. Reload the extension after rebuilding.

The browser extension itself reads packaged filter data. The build process downloads EasyList, EasyPrivacy, the AdGuard click-through list and AdGuard/uBO URL Tracking Protection when its own verified cache needs a refresh. It does not execute downloaded filter text as code.

| Option | Meaning |
| --- | --- |
| `--feeds DIR` | Read proxy feed snapshots from this state directory. |
| `--filters DIR` | Use a separate browser-filter cache. |
| `--tier pro\|pro.plus\|ultimate` | Select the tracker list; default `pro.plus`. |
| `--threat-tier full\|medium` | Select the required threat tier; default `full`. |
| `--offline` | Use cached browser lists without downloading. |
| `--out DIR` | Choose the output folder. |
| `--allow-missing` | Explicitly permit a reduced build. |
| `--allow-parameter-quarantine NAME` | Acknowledge one reviewed parameter name that must remain untouched; all required-source and other completeness checks still apply. Repeat for separately reviewed names. The receipt stays reduced. |
| `--allow-small` | Development fixtures only; skip production feed-size checks. |
| `--no-lists` / `--no-filters` | Explicitly leave out those sources; the result is reduced. |
| `--accept-list-change ID` | Accept a reviewed large change in a named source's size, entries or exceptions. |

Normal builds require every selected source. A Medium fallback does not fulfill a request for Full threat coverage. Choose Medium explicitly if that is the intended tier. Required network sources must produce blocking rules, and the parameter source must produce effective imported removers; having a source file alone is insufficient. Missing sources, ineffective compilation, development size overrides and conservative source-exception fallbacks are recorded in `rules/build.json`; the popup reports reduced coverage. Normal builds refuse unsafe ambiguous source exceptions. Explicit reduced builds remain available for review. Stale snapshots are also reported.

The compiler supports a bounded subset of filter syntax. A complete source receipt means the selected required sources are present and produced the required output; it does **not** mean every upstream rule was implemented. Conversion and rejection counts are in the build output and receipt.

Source-backed protocol signatures are compiled into the existing `fp-trackers` category at the hand-filter priority. They recognize selected exact URL fields and types even on publisher-owned routes; they do not inspect request bodies. The package includes `tracking-protocols.json` with source references and limits, a compiler hash, and a catalog hash in `rules/build.json`. See [the signatures](tracking-protocols-0.10.md) and [the fixed development benchmark](benchmarks/protocols-v1.md). Category toggles and explicit repair grants retain their existing authority. The category label is now **First-party tracking request** because these rules cover collection as well as scripts.

The reviewed 0.9 URL Tracking Protection snapshot has one unrepresentable named exception for `analytics_trace_id`. It is preserved everywhere, including in overlapping built-in policy, rather than removed on an incorrectly guessed scope. After reviewing that documented tradeoff, build with:

```sh
node scripts/build-browser.mjs --allow-parameter-quarantine analytics_trace_id
```

That acknowledgment cannot permit missing threat feeds, a disabled parameter policy, ambiguous all-parameter exceptions or another newly quarantined name. The popup and build receipt continue to report the one-name reduction. An updated upstream list can require a new review.

Each browser filter is committed as one private `<id>.snapshot` containing bounded metadata and the exact verified body. A failed write or interrupted update leaves either the prior or new complete snapshot. Legacy `.txt`/`.json` pairs remain readable until the first successful snapshot refresh; an invalid existing snapshot cannot be masked by an old pair. Interrupted private staging folders are ignored. Ordinary output-publication failures restore the previous Chrome and Firefox folders; if rollback itself fails, the builder preserves its backup folder and reports its location.

The fixed development public key gives the unpacked build the ID `danbhmcinakkkkbobacafgidgkfibfmg`. The old private key is not in the repository. Publishing through a store requires a separate distribution plan, including extension identity, source licenses and native-host registration.

## Protection levels and repairs

| Level | Behavior |
| --- | --- |
| Relaxed | Domain lists, threat protection and manual rules; reduced URL and cleaning behavior. |
| Standard | Domain and URL filters, supported tracker substitutes, beacon/link protections and normal cleaning. |
| Strict | Standard plus restrictions on third-party scripts, frames and fonts, stronger header cleaning, and held supported embeds. Default Strict additionally holds active resources on unprepared sites. |
| No scripts | Strict plus script-request blocks and response policy restrictions, intended for reading. Existing execution and cached/service-worker responses require separate care. |
| Isolated | A named-site choice that blocks all cross-top-site subresource types, including images, fetches and socket handshakes. Removes Cookie, Authorization, Referer and Set-Cookie for covered site resources and navigations to the site. Sign-in and third-party services can stop working. |

Named site rules use Chrome's top-level-domain condition, so nested frames do not acquire a different site's permissions through their initiator. Registrable-site boundaries come from the complete pinned Public Suffix List, including private suffixes. A hosted tenant is not automatically trusted because its hostname ends with a larger platform's name.

The popup shows the last verified applied policy. A saved change that Chrome has not installed is **Pending** or **Degraded**, with a **Retry policy update** action. Dynamic rules, session grants and their receipts are reconciled; a local storage write alone is not a successful application.

Ordinary endpoint exceptions are exact-path/type, bound to the source tab and top-level site, and temporary. Each has paired sanitation to remove Cookie, Set-Cookie and Referer headers. Threat, manual-deny and isolation rules remain above these grants. Strict host allowances repair Strict blocking without turning off header cleaning. An explicitly requested embed-with-cookies permission has separate semantics and still cannot lift tracker, threat, manual-deny or isolation rules.

The threat warning has a separate two-step **Continue anyway** action. It permits the named host's navigation in that tab, with sanitation; the threat host's subresources remain blocked. This can produce an incomplete page. Leaving the site, closing the tab or expiry revokes the grant.

Expiry uses scheduled worker reconciliation. Chrome does not provide a DNR rule with a built-in wall-clock expiration. Sleep, delayed alarms and API failures can delay revocation, so “15 minutes” is a scheduled lifetime, not a hard security lease. Browser restart clears session grants. See [the grant journal and recovery](enforcement-0.7.md).

### Named-site isolation

Choose **Isolated** under **Protection on this site** for a site whose cross-site network access you want to contain. It is separate from No scripts: first-party scripts may still execute, but new cross-site subresources in the covered page context are blocked across all resource types. Functional-provider allowlists, Strict allowances and ordinary temporary grants do not override the boundary. Activating the mode removes conflicting temporary permissions; Pause is unavailable until you explicitly choose another mode.

The popup reports whether isolation rules have been read back as installed. A failed activation must not display an isolated page. If a later change fails while the previous isolation remains confirmed, that retained state is reported separately. Sites that cannot be represented safely by the existing PSL domain conditions remain unsupported rather than receiving an unsafe broad scope.

Isolation removes HTTP cookies, authorization and referrers on covered requests, and response `Set-Cookie`. Version 0.10 also removes the source-verified `X-POSTHOG-DISTINCT-ID`, `X-POSTHOG-SESSION-ID` and `X-POSTHOG-WINDOW-ID` fields from ordinary application requests in that scope. These operations stay above ordinary grants and cover initial navigations to the isolated destination. They do not remove unknown custom headers, generic tracing headers or identifiers encoded in bodies. The [research record](adversarial-tracking-0.10.md#a-separate-request-is-not-required) explains this separate channel.

Installing new rules does not terminate an existing WebSocket or WebTransport session. Use the browser's own Reload when appropriate. Isolation does not automatically reload, clear cookies, unregister workers or erase storage. First-party scripts can still read available storage and send identifiers to the first party. Outbound main-frame navigations, form submissions, popups, unrelated worker contexts, service-worker-generated responses, public IP and TLS identity need separate controls. This mode is a subresource boundary with HTTP header reduction, not an anonymous session. [Implementation and test contract](enforcement-0.9.md).

### Maintained tracking-parameter policy

The Chrome build converts a bounded subset of AdGuard/uBO URL Tracking Protection into top-level GET navigation rules and shared click-time data. Source exceptions constrain the same effective policy as built-in names, so an old global remover cannot undo a maintained exception. The build retains exact source hashes and conversion/quarantine diagnostics.

Signed URLs, authentication flows, protected names, sensitive hosts and unsubscribe/preferences links have conservative preservation rules. Imported exceptions never become general network permissions. The fixed preservation brakes sit below header sanitation and apply only to top-level GET navigation, closing the former Strict subframe bypass.

The network compiler proves a removable key is present before applying a redirect. Unsupported remove-all, inversion, arbitrary-regex and scope forms remain counted rather than guessed. Page-side cleanup preserves untouched query spelling and order, but it is not evidence that an earlier request was cleaned. Native qualification must check the actual request received by the origin, including first-position keys and redirect iteration. [Supported syntax, preserved flows and limitations](parameters-0.9.md).

Chrome reconstructs queries during a declarative transformation. The network policy therefore preserves links with bare or empty query components and encoded query keys; the page-side cleaner can retain those components exactly. The two bracketed tracking names `__cft__[0]` and `__xts__[0]` are deferred to page-side cleaning to avoid a matching rule whose native transformation changes nothing. Entity-based exemptions are conservatively widened to documented three-character DNS-label prefixes to fit Chrome's compiled-regex memory budget.

### Default Strict preparation

Once default Strict's new policy is applied, scripts, subframes, fonts and objects are blocked on an unknown top-level site until its complete named policy is installed. Other subresources receive Cookie, Referer and Set-Cookie stripping. Navigation itself can proceed. This closes the earlier gap where a nested frame's same-origin resources could pass before the outer site's rules were ready. A prepared hosting company never releases independent private tenants.

The popup distinguishes **Held**, **Prepared** and unknown preparation. **Prepare this site** requests the full policy and verifies it; it never reloads the page or replays a request. If early resources were held and the page is incomplete, use Chrome's Reload after preparation. A reload following a form submission still has the browser's normal resubmission implications.

IP literals, localhost, single-label hosts, public-suffix addresses and certain wildcard registry bases cannot receive a safe preparation exclusion. They remain held under default Strict, including local dashboard scripts. The popup explains the limitation and keeps the default-mode control available; explicitly choose Standard when needed. These addresses are not given an unsafe broad exception.

Automatic preparation uses current tabs plus bounded in-memory navigation targets scheduled to expire after 60 seconds. Closing a tab drops its context; inactive sites are not restored from receipts at worker restart. Dynamic rules and local applied receipts can retain stale scopes until successful reconciliation. Preparation is not a persistent browsing-history cache or a hard deletion timer.

The installed hold protects requests that race navigation events. Prewarming improves compatibility but has no timing guarantee. First extension activation/upgrade, failed migration, responses generated by service workers and Cache Storage retain explicit limits. Read [the 0.8 enforcement design](enforcement-0.8.md) before using default Strict as a blanket default.

## More page-level blocking

The content engine uses these mechanisms without a model:

- The fixed set of common ad-slot selectors.
- Indexed generic ID/class rules and scoped cosmetic rules compiled from verified filter sources.
- Conservative sponsored-card detection using a short disclosure and repeated linked-card structure.

Imported rules use a restricted selector grammar and reversible hide records. Forms, editors, players, focused controls and protected structure are checked before hiding and during later changes. Work is processed in bounded subtree tasks, so a busy page no longer exhausts a per-minute counter and automatically restores every ad.

Use **Rules → Block an element** for a manual rule. The picker tries a precise ID or attribute value before broader shared attributes. **Restore everything hidden here** and individual Show/Hide controls remain available.

Generic rules use token maps and bounded DOM traversal, not a query for every imported rule. Scoped rules support PSL-derived entity scopes and narrowly bounded native `:has()` relations. Entity names describe cosmetic scope, not verified ownership; they never grant network access or change the manual-rule grammar.

Imported `#@#` exceptions suppress imported rules with the same canonical selector and matching scope. Supported `generichide`, `specifichide` and `elemhide` page exceptions disable their imported families, including after same-document URL changes. Unsupported exceptions quarantine the affected selector or disable the affected family and mark coverage reduced. Exceptions do not disable the independent fixed slot stylesheet; the site's built-in-hiding switch controls that. Complex generic selectors, procedural filters, scriptlets and unrestricted CSS remain unsupported.

Discovery and retained hides have explicit work/record caps. Reaching a cap or a degraded exception evaluation appears as reduced imported coverage in the popup. A legitimate source page exception is reported as an exemption, not an error.

Cosmetic hiding changes display. It cannot undo a request, cookie write or impression that already happened. See [0.8 content engine details](content-0.8.md) and [the existing reversible/protected-content design](content-0.7.md).

## Optional Chrome profile controls

Open **Settings → Browser privacy → Manage browser privacy**. Review the ten fixed choices and click **Apply selected protections** to request Chrome's optional `privacy` permission. No settings are changed by opening the page. Choices cover speculative loading, non-proxied WebRTC UDP, link auditing, third-party cookies, exposed advertising APIs, search suggestions and selected remote browser services.

The page reports actual read-back values and ownership. Another extension or organization policy can prevent a requested setting from taking effect. **Release all controls** removes only Egress Guard's overrides; it never writes back a stale copy of previous user preferences. This controller has its own queue, so a stalled request-policy update does not block privacy-setting recovery.

These are regular-profile controls with compatibility costs, not IP masking or verified routing. WebRTC may still use TCP and expose a public address; Chrome's cookie exemptions remain possible. No Safe Browsing or password-manager setting is changed. See [the setting catalog, ownership and recovery contract](browser-privacy-0.8.md).

## Optional local ad review

Open the popup on a public web page, choose **Rules → Review sponsored cards**, and confirm that the page contains no private information.

1. **Scan page** collects at most 24 bounded card candidates and shows their excerpts.
2. **Analyze locally** asks Chrome's built-in model for labels. If necessary, Chrome may download its model after this explicit action.
3. Review the labels and select the paid cards to hide. Nothing is selected automatically.
4. **Hide selected cards** applies only candidate IDs from that snapshot. **Restore reviewed cards** reverses semantic hiding for that page load.

The classifier can return `paid-placement`, `organic`, `essential-commerce` or `uncertain`. It receives short whitelisted fields, not raw page HTML, cookies, request bodies, form values or arbitrary attributes. Visible URLs, email addresses and obvious long IDs are redacted by extraction. Known sensitive surfaces are excluded by heuristics, and public-page confirmation is still required because those heuristics are incomplete.

The model cannot create selectors, run JavaScript, grant network access, change protection levels or call the native host. Output is schema-checked. The content engine independently rejects unknown, protected, changed or expired candidates. Snapshots expire after two minutes; source navigation discards the UI's snippets and cancels inference. Every analysis gets a separate session that is destroyed afterward. There is no cloud fallback and snippets are not persisted by Egress Guard.

Model support is detected at runtime using the [Chrome Prompt API](https://developer.chrome.com/docs/ai/prompt-api). The model needs substantial local resources and is not shipped inside this repository. Its availability, ad-classification accuracy, latency and language coverage require target-device testing. It is optional, experimental and outside the request decision path. Deterministic protections continue without it.

## Check the local proxy from Chrome

Install the Python package first, then explicitly register the exact extension ID:

```sh
egress-guard native-host register \
  --extension-id danbhmcinakkkkbobacafgidgkfibfmg \
  --browser chrome
```

Use the ID actually shown in Chrome if your build identity differs. `--browser chromium` selects Chromium's standard user directory. Registration supports standard Chrome/Chromium user directories on macOS and Linux, one registration at a time. Firefox, Windows, custom user-data directories and Chrome for Testing registration are not implemented.

In **Settings → Local proxy**, click **Check local proxy**. Chrome asks for the optional `nativeMessaging` permission. The popup then requests one read-only status receipt from `org.egress_guard.receipts` and validates its revision, coverage and logging acknowledgment.

The bridge accepts only `status` and `capabilities`. It cannot change policy or routes, expose hostname history or credentials, or run arbitrary commands. Read the [protocol and registration details](core-0.7.md).

To remove the matching registration:

```sh
egress-guard native-host unregister \
  --extension-id danbhmcinakkkkbobacafgidgkfibfmg \
  --browser chrome
```

## Upgrade behavior

- Chrome's minimum version remains 145. The extension now requires `webNavigation` for preparation hints and requests optional `privacy` only through the new settings page.
- The 0.7 suffix/scope migration remains in place. Permissive older settings whose scope cannot be trusted are discarded; re-create only the repairs you still need.
- An existing default Strict choice now has the preparation behavior and compatibility costs above after the new policy is applied. Standard remains available, and profile privacy choices start unapplied.
- Saved settings may remain pending when Chrome or storage rejects an update. Check the popup receipt and retry.
- Fresh Python configuration uses `history = "none"`. Existing explicit `full` or `aggregate` values are retained. Choose `none` in an existing configuration if wanted; old rows are not erased.
- Refresh and rebuild to update packaged lists. They are not silently downloaded or replaced inside the running extension.

## Qualification

Run the isolated regressions:

```sh
node --test tests/browser/*.test.cjs
```

Optional real-browser fixture scripts remain in `tests/browser/`. They use throwaway profiles and loopback fixtures. They need a permitted Chrome environment and are separate from the DOM-stub/worker tests. The current source tests do not establish actual browser header behavior, CSS/SRI/CSP enforcement, model quality or installed-native-host operation.

The dedicated `tests/browser/chrome-0.8.mjs` adds native imported-CSS cases, Chrome's hypothetical Strict rule evaluator and an optional visible privacy-permission/setting check. Its `--check` mode only validates fixture contracts and launches no browser. See [commands and the remaining native matrix](releasing.md#focused-08-chrome-fixture).

The [0.6 guide and measurements](browser-companion-0.6.md), [0.7 record](release-0.7.md), [0.8 record](release-0.8.md) and [0.9 record](release-0.9.md) are historical evidence. Current checks and remaining target work are recorded in the [0.10 release notes](release-0.10.md).
