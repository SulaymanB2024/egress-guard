# Browser companion 0.7

The companion supplies controls a domain proxy cannot: URL-level request rules, tracking-parameter and cookie cleaning, page-element hiding, and optional local review of sponsored cards. Chrome is the primary implementation. Firefox retains manual request/cosmetic rules; it does not have the Chrome built-in list and model feature set.

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

The browser extension itself reads packaged filter data. The build process downloads EasyList, EasyPrivacy and the AdGuard click-through list when its own verified cache needs a refresh. It does not execute downloaded filter text as code.

| Option | Meaning |
| --- | --- |
| `--feeds DIR` | Read proxy feed snapshots from this state directory. |
| `--filters DIR` | Use a separate browser-filter cache. |
| `--tier pro\|pro.plus\|ultimate` | Select the tracker list; default `pro.plus`. |
| `--threat-tier full\|medium` | Select the required threat tier; default `full`. |
| `--offline` | Use cached browser lists without downloading. |
| `--out DIR` | Choose the output folder. |
| `--allow-missing` | Explicitly permit a reduced build. |
| `--allow-small` | Development fixtures only; skip production feed-size checks. |
| `--no-lists` / `--no-filters` | Explicitly leave out those sources; the result is reduced. |
| `--accept-list-change ID` | Accept a reviewed large change in a named source's size, entries or exceptions. |

Normal builds require every selected source. A Medium fallback does not fulfill a request for Full threat coverage. Choose Medium explicitly if that is the intended tier. Required URL sources must produce at least one blocking rule; having a source file alone is insufficient. Missing sources, ineffective compilation and development size overrides are recorded in `rules/build.json` and the popup reports reduced coverage. Stale snapshots are also reported.

The compiler supports a bounded subset of filter syntax. A complete source receipt means the selected required sources are present and produced the required output; it does **not** mean every upstream rule was implemented. Conversion and rejection counts are in the build output and receipt.

Each browser filter is committed as one private `<id>.snapshot` containing bounded metadata and the exact verified body. A failed write or interrupted update leaves either the prior or new complete snapshot. Legacy `.txt`/`.json` pairs remain readable until the first successful snapshot refresh; an invalid existing snapshot cannot be masked by an old pair. Interrupted private staging folders are ignored. Ordinary output-publication failures restore the previous Chrome and Firefox folders; if rollback itself fails, the builder preserves its backup folder and reports its location.

The fixed development public key gives the unpacked build the ID `danbhmcinakkkkbobacafgidgkfibfmg`. The old private key is not in the repository. Publishing through a store requires a separate distribution plan, including extension identity, source licenses and native-host registration.

## Protection levels and repairs

| Level | Behavior |
| --- | --- |
| Relaxed | Domain lists, threat protection and manual rules; reduced URL and cleaning behavior. |
| Standard | Domain and URL filters, supported tracker substitutes, beacon/link protections and normal cleaning. |
| Strict | Standard plus restrictions on third-party scripts, frames and fonts, stronger header cleaning, and held supported embeds. |
| No scripts | Strict plus JavaScript restrictions, intended for reading. |

Named site rules use Chrome's top-level-domain condition, so nested frames do not acquire a different site's permissions through their initiator. Registrable-site boundaries come from the complete pinned Public Suffix List, including private suffixes. A hosted tenant is not automatically trusted because its hostname ends with a larger platform's name.

The popup shows the last verified applied policy. A saved change that Chrome has not installed is **Pending** or **Degraded**, with a **Retry policy update** action. Dynamic rules, session grants and their receipts are reconciled; a local storage write alone is not a successful application.

Ordinary endpoint exceptions are exact-path/type, bound to the source tab and top-level site, and temporary. Each has paired sanitation to remove Cookie, Set-Cookie and Referer headers. Threat and manual-deny rules remain above these grants. Strict host allowances repair Strict blocking without turning off header cleaning. An explicitly requested embed-with-cookies permission has separate semantics and still cannot lift tracker, threat or manual-deny rules.

The threat warning has a separate two-step **Continue anyway** action. It permits the named host's navigation in that tab, with sanitation; the threat host's subresources remain blocked. This can produce an incomplete page. Leaving the site, closing the tab or expiry revokes the grant.

Expiry uses scheduled worker reconciliation. Chrome does not provide a DNR rule with a built-in wall-clock expiration. Sleep, delayed alarms and API failures can delay revocation, so “15 minutes” is a scheduled lifetime, not a hard security lease. Browser restart clears session grants. See [enforcement and recovery](enforcement-0.7.md) for failure behavior and the first-navigation limitation of default Strict.

## More page-level blocking

Three mechanisms run without a model:

- The fixed set of common ad-slot selectors.
- Safe domain-specific cosmetic rules compiled from verified filter sources.
- Conservative sponsored-card detection using a short disclosure and repeated linked-card structure.

Imported rules use a restricted selector grammar and reversible hide records. Forms, editors, players, focused controls and protected structure are checked before hiding and during later changes. Work is processed in bounded subtree tasks, so a busy page no longer exhausts a per-minute counter and automatically restores every ad.

Use **Rules → Block an element** for a manual rule. The picker tries a precise ID or attribute value before broader shared attributes. **Restore everything hidden here** and individual Show/Hide controls remain available.

Imported `#@#` exceptions suppress imported rules with the same canonical selector and matching scope. They do not disable the independent fixed slot stylesheet; the site's built-in-hiding switch controls that. Unsupported generic list selectors, procedural filters, scriptlets and unrestricted CSS are not imported.

Cosmetic hiding changes display. It cannot undo a request, cookie write or impression that already happened. See [content engine details](content-0.7.md) for exact limits and protected-content behavior.

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

- Chrome's minimum version is now 145.
- Old browser state is migrated to the new suffix/scope semantics. Permissive settings whose old scope cannot be trusted are discarded; re-create only the repairs you still need.
- Saved settings may remain pending when Chrome or storage rejects an update. Check the popup receipt and retry.
- Fresh Python configuration uses `history = "none"`. Existing explicit `full` or `aggregate` values are retained. Choose `none` in an existing configuration if wanted; old rows are not erased.
- Refresh and rebuild to update packaged lists. They are not silently downloaded or replaced inside the running extension.

## Qualification

Run the isolated regressions:

```sh
node --test tests/browser/*.test.cjs
```

Optional real-browser fixture scripts remain in `tests/browser/`. They use throwaway profiles and loopback fixtures. They need a permitted Chrome environment and are separate from the DOM-stub/worker tests. The current source tests do not establish actual browser header behavior, CSS/SRI/CSP enforcement, model quality or installed-native-host operation.

The [0.6 guide and measurements](browser-companion-0.6.md) are preserved as historical evidence, not 0.7 qualification. Current checks and remaining target work are recorded in the [0.7 release notes](release-0.7.md).
