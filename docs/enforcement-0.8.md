# Chrome Strict preparation and independent browser controls

This note describes the Chrome enforcement changes for 0.8. It supplements [the 0.7 controller and grant design](enforcement-0.7.md). The rules, receipts and tests discussed here are implemented in `browser/core/dnr.js` and `browser/background-chrome.js`; they have not been qualified in a running Chrome instance in the implementation environment.

## The protection change

Once the new default-Strict policy has been installed, an unknown top-level context no longer relies on Chrome's immediate-initiator party classification. Its external scripts, subframes, fonts and objects are blocked until the complete named site policy is installed. Other subresources can still load, with Cookie, Referer and Set-Cookie removed by the preparation policy. Top-level navigation is not held.

The previous policy could miss an iframe's same-origin requests before the worker installed rules for the outer page. It could also exclude an unknown private tenant because its hosting company's domain was already prepared. The new unknown-context conditions do not use `domainType`. They remain installed while the worker is asleep or navigation reconciliation is pending. The worker replaces the whole dynamic set in one update: the site's hold exclusion and its ordinary Strict rules are in the same candidate.

This is a bounded network policy. Inline JavaScript, cookies on the main navigation, identifying request bodies and URLs, browser storage, and a server's view of the connecting IP are not removed by the preparation hold. An image or XHR can still communicate while sanitized. Existing higher-priority tracker, threat and manual rules continue to apply. A local classifier is not involved in this synchronous decision.

### Conditions while preparing and after preparation

| Context | Active resources | Other subresources | Navigation |
| --- | --- | --- | --- |
| Default Strict, unprepared site | Script, subframe, font and object requests are held regardless of initiator | Allowed by this layer, with Cookie/Referer/Set-Cookie stripping | Existing navigation rules apply |
| Prepared Strict site | Existing Strict policy: cross-top-site active resources blocked, with the existing functional and explicit host exceptions | Existing Strict cookie/referrer policy | Existing navigation rules apply |
| Explicit Standard or Relaxed site | Its existing named policy, scoped to the actual PSL site | Its existing policy | Existing policy |
| Independent tenant below a prepared parent | Held until that tenant receives its own named policy | Preparation sanitation | Existing navigation rules apply |

The temporary hold has no implicit functional-provider exception. The existing compatibility exceptions return as part of the named policy. Otherwise a guessed provider exception could recreate the unknown-context gap.

No release rule uses `allow` or `allowAllRequests`. Preparation does not alter the priority ladder. Manual denies and threats still beat ordinary resource permissions; a timed endpoint repair remains a source-tab allow with a higher-priority sanitation pair. An explicit embed cookie grant retains its existing priority and consent meaning.

## Public-suffix complement

Chrome domain conditions match subdomains. Therefore the complement of prepared PSL sites cannot be represented by one `excludedTopDomains` list alone.

The compiler emits a global unknown-context condition excluding all prepared or explicitly configured sites, then restores the hold at every nested PSL boundary under those exclusions. A recovery condition excludes only prepared sites inside that boundary. Conditions with identical exclusion sets share a domain list, split at 1,000 entries.

For example, preparing `amazonaws.com` and `bob.s3.amazonaws.com` leaves `alice.s3.amazonaws.com` held. Under the packaged PSL, the 583 nested boundaries beneath `amazonaws.com` require two grouped recovery conditions for that example, in addition to the global condition. Preparing an actual tenant installs its own full named policy; preparing the hosting company never grants that tenant an exception.

The compiler refuses more than 4,096 excluded prepared/configured scopes. The controller also checks Chrome's dynamic, unsafe-action, session and regex capacities before attempting an update. A refusal leaves the previous dynamic policy in place and reports a degraded receipt. It does not omit the hold to make the policy fit.

### Conservative addresses that remain held

Some wildcard registry bases cannot receive the same treatment as an ordinary registrable site. For example, `af-south-1.airflow.amazonaws.com` itself belongs to the `amazonaws.com` site under the packaged PSL, while its wildcard children are separate registries. A `topDomains` exclusion cannot spare that base without also sparing its descendants. The compiler therefore keeps the base held. The receipt checks the actual hostname, so a prepared parent does not incorrectly make the base appear prepared.

IP literals, localhost, other single-label HTTP(S) hosts and public-suffix addresses also lack a supported preparation scope. Under default Strict they remain held, including their local dashboard scripts. The UI reports `held`, `canPrepare: false`, and a reason. These addresses are never inserted into an ad-hoc broad exclusion. The user can explicitly change the default to Standard if the compatibility cost is unacceptable. Non-web pages such as `chrome://settings` are outside this preparation policy.

An embed grant now uses the same nested-PSL top-scope exclusions as endpoint grants and named policy. A grant on `amazonaws.com` cannot follow its source tab into an independent `s3.amazonaws.com` tenant during the interval before asynchronous navigation revocation.

## Preparation lifecycle

The Chrome worker registers top-frame `webNavigation.onBeforeNavigate` and `onCommitted` listeners. They request early preparation for trusted navigation targets. A prerender target can be prepared before it becomes visible to `tabs.query`. `onTabReplaced` triggers reconciliation. Child-frame navigation cannot request a new top-site preparation context.

These events improve the chance that a site's policy is ready before its subresources arrive. They are not a security barrier or a timing guarantee. Chrome documents no defined ordering between webNavigation and webRequest events. The installed hold is what protects requests that arrive first. See [Chrome webNavigation concepts](https://developer.chrome.com/docs/extensions/reference/api/webNavigation#concepts-and-usage).

All preparation requests join the existing DNR serial queue. The sequence is:

1. Read current tabs and actual dynamic/session rules; validate saved state and grants.
2. Select current sites and a bounded set of transient navigation targets.
3. Compile complete named rules and the complementary unknown-context hold together.
4. Check quotas and revoke obsolete session permissions.
5. Replace dynamic rules atomically if needed, then read them back.
6. Publish the verified dynamic snapshot, then finish the existing session journal and local-receipt steps.

Automatic preparation covers current tabs and at most 128 in-memory navigation contexts, keyed by source tab. A new target replaces that tab's previous target. Each context is scheduled to expire after 60 seconds; the existing expiry/recovery alarms and reconciliation prune it. Closing or replacing its tab retires both the remembered sender and navigation context in the same queue that can create them. This final deletion runs after any earlier queued page message or prewarm, before cleanup reconciliation, so an earlier writer cannot resurrect a closed tab behind a slow DNR call. Replacement explicitly retires `replacedTabId` rather than assuming Chrome also delivers `onRemoved`. Current tabs remain prepared for as long as they need the site policy. Explicit user-selected site modes remain separate persistent settings.

There is no persistent inactive-site cache. A worker restart does not restore navigation candidates from the local receipt, even when its digest matches the actual rules. Reconciliation rebuilds automatic scopes from current tabs, removing a closed or expired scope and its hold exclusion in the same dynamic replacement. Registered dynamic rules and the local applied receipt necessarily name the currently prepared scopes; a stale scope can remain in those records until the next successful reconciliation. The 60-second schedule is not a hard deletion deadline during browser suspension or API/storage failure.

No paths or query strings enter preparation metadata. Timed permissions do not derive authority from automatic preparation: source-tab, site, expiry, threat and actual-journal checks still control them. A navigation prewarm neither transfers a grant nor grants cookies to another site.

### Failure behavior

A rejected dynamic update leaves the previous preparation hold and named policy installed. A successful update immediately invalidates the old dynamic receipt until readback verifies the replacement. If that readback fails, the popup reports unknown preparation and mode; it does not continue attesting to the previous policy. A later successful reconciliation establishes a new receipt.

A confirmed dynamic update can coexist with a later session-journal or local-storage failure. In that case the site's preparation may truthfully be `prepared` while the overall policy is `degraded`, with no complete applied revision. Existing failure cleanup still revokes session grants and invalidates their receipts. Preparation is not a substitute for the global policy or source-coverage status.

The guarantee begins after this new default-Strict rule set has been applied. An extension's first activation, upgrade or failed preference load is not represented as an already verified hold. Old dynamic rules may remain until migration succeeds. No maximum preparation duration is promised.

## Popup and message contract

`popup-state` now includes:

```js
{
  preparation: {
    state: "prepared" | "held" | "not-applicable" | "unknown",
    site: "publisher.example" | null,
    revision: "verified dynamic revision" | null,
    canPrepare: true | false,
    reason: "present for unsupported Strict address scopes"
  },
  policy: {
    // Existing receipt fields are retained.
    topPartyCoverage: "closed-until-prepared" | "explicit-top-sites" | "unknown"
  }
}
```

`prepared` means the named rules have been read back for this actual host. `held` means the preparation policy applies; it is not proof that a particular request was observed or blocked. `not-applicable` covers other effective modes and non-web pages. `unknown` means a complete current dynamic receipt is unavailable.

Unsupported web addresses still return the effective and requested default mode, so the popup can explain the hold and expose the explicit default-mode choice. Hold matches use the separate `preparation` category, not the `strict` third-party category. A held first-party script is not presented as a tracker or as a reason to add a permanent host allowance.

The popup alone may send:

```js
{type: "prepare-strict-site", tabId, tabUrl}
```

The worker checks that the source tab still has the exact URL, validates that the actual host has a representable site scope, reconciles, and returns `{ok: true, preparation}` only when prepared. Content scripts and unrelated extension pages have no authority to invoke this operation. A changed tab or unsupported address receives an explicit error.

There is no worker reload API. No script, fetch, form body or history entry is replayed. After preparation, the popup can tell the user to use Chrome's Reload if the page is incomplete. Some initial first-party resources may already have been blocked; their execution order cannot be reconstructed safely. Preparation never claims to repair a partly executed page automatically.

## Independent optional browser-privacy controller

The worker also instantiates `EGBrowserPrivacy.createController(chrome)`. Its startup and queue are independent of DNR. Only an exact `chrome-extension://<fixed-extension-id>/privacy.html` sender with this extension's id and `frameId: 0` can issue `browser-privacy-status`, `browser-privacy-apply`, `browser-privacy-retry` or `browser-privacy-release`.

These messages are authenticated before entering any DNR queue. A stalled rule API therefore does not prevent the user from reading or recovering profile-control settings. The page supplies only selected catalog identifiers; the controller retains its fixed setting/value catalog and its own saved-intent/readback rules. Content, popup, framed settings pages and foreign extension senders are rejected. The worker does not add a permission-event retry or unconditionally apply settings when the optional permission is granted.

The tab-URL notification used by cosmetic content is likewise fixed: `{type: "page-location"}`. The content script rereads its own location after a same-document navigation. No URL payload or new grant authority is passed with that notification.

## Validation and remaining qualification

The focused Node suite runs the actual compiler and service-worker source with isolated browser/storage doubles. It covers:

- Cold nested-frame and no-top-frame initiator-fallback requests; post-preparation same-site and cross-site decisions.
- Unknown private tenants, explicitly non-Strict parent scopes, and more than 1,500 samples from the packaged private-suffix hierarchy.
- Conservative wildcard-base, IPv4, IPv6, localhost and single-label receipts.
- Atomic publication, rejected updates, failed readback, failed final bookkeeping, bounded transient navigation contexts, close/expiry pruning, queued-sender/prewarm retirement races, tab replacement and no inactive-site restoration after restart.
- Threat/manual precedence, tab-bound sanitation, and embed grants during a parent-to-private-tenant navigation.
- Exact settings-page authentication and privacy recovery while the DNR queue is deliberately stalled.

Compiler-model success is not packet-level evidence from Chrome. The implementation environment previously rejected native Chromium startup with an OS socket-permission error, and that restriction was not bypassed. The release still needs a disposable-profile qualification on supported Chrome: fast cold navigation, nested foreign frames, private tenants, prerender/BFCache/history transitions, user-selected reload after a POST result, and origin hit/header assertions before and after preparation.

Chrome's DNR documentation defines `topDomains` with a fallback to the initiator when no associated top frame exists. DNR does not cover responses generated by a service worker or supplied directly from Cache Storage; service-worker fetches reaching the network stack are covered. The existing targeted worker/cache clearing on explicit Strict or No-scripts changes remains bounded by the origins the adapter can identify. See [Chrome DNR matching and limits](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest).

Scheduled grant expiry remains scheduled, not a hard wall-clock deadline. This release does not change the 0.7 journal, rollback, browser-restart or threat-reclassification rules, and it does not make the extension a device-wide egress boundary.
