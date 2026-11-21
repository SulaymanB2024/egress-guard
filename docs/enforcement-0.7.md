# Browser enforcement in 0.7

This release makes Chrome's installed rules and saved preferences independently observable, gives ordinary resource permissions narrower authority, and replaces the approximate suffix heuristic with the complete offline Public Suffix List. It does not make a browser invisible. Network policy also cannot remove identifiers a site receives through an account, URL, request body, browser fingerprint, or its own server-side records.

## Enforcement invariants

1. Manual endpoint denies outrank ordinary permissions and the warning-page navigation permission. A normal exception cannot override a threat rule.
2. An ordinary endpoint permission grants an exact destination, path, resource type and top-level site. In Chrome it is installed as a session rule for the single source tab where the user approved it. Another tab showing the same site receives no permission. It has a separate higher-priority rule removing `Cookie`, `Referer` and `Set-Cookie`. Loading a resource does not implicitly restore cookies.
3. Loading an embed without cookies remains below baseline cookie stripping. The separate, explicit “with cookies” action can lift that baseline, but remains below tracker lists, threats and manual denies. It cannot override an endpoint permission's own sanitation pair. Other authentication mechanisms are not removed by these rules.
4. The warning page grants only an exact-host navigation in one tab, with a paired cookie/referrer removal rule. The host's scripts, frames, images and other subresources retain their ordinary threat/tracker blocks. A related subdomain does not inherit navigation permission. This is deliberately narrower than the former two-allow implementation; continued pages may remain incomplete.
5. A permission whose bookkeeping or installation fails is never reported as successful. Runtime read-back must confirm the requested grant, and the requested entry must survive reclassification, expiry and tab checks.
6. Dynamic and session rule sets are not treated as one atomic transaction. Revocations happen before new permissions. Failed session application or bookkeeping triggers removal of all session rules, with a degraded receipt if removal itself cannot be confirmed.

The meaningful priority order is:

| Policy | Priority | Consequence |
| --- | ---: | --- |
| Global Privacy Control | 50 | No permission in this extension disables the header. |
| No-scripts response policy | 45 | An ordinary resource exception cannot lift the CSP. |
| Manual endpoint deny | 40 | Denies remain authoritative. |
| Threat-navigation sanitation | 32 | The navigation permission keeps its cookie/referrer restrictions. |
| Explicit threat navigation | 31 | Main frame only, exact host and tab. |
| Threat list | 30 | Ordinary permissions cannot override it. |
| Ordinary permission sanitation | 22 | Cookie, Set-Cookie and Referer removal accompanies the allow. |
| Timed endpoint permission | 21 | Lifts ordinary tracker blocking only for its exact endpoint and context. |
| Stored endpoint allow | 20 | Same sanitation and tab-binding requirements. |
| Bundled surrogates / host lists | 18 / 17 | An explicit embed cookie choice does not override these. |
| Relaxed / embed with cookies | 14 / 13 | Explicit, separate choices; below the host lists and threats. |
| Baseline header cleaning | 9 | Above normal click-to-load embeds. |
| Embed without cookies / Strict blocks | 8 / 7 | Loading an embed can lift Strict's resource hold while retaining sanitation. |

The lower EasyList/EasyPrivacy, scanner and parameter-cleaning tiers remain distinct. Rules with different purposes must not be merged merely to reduce their count: Chrome applies `modifyHeaders` only above a matching allow, so priority changes can otherwise restore cookies accidentally.

## Desired, saved and applied state

`browser/background-chrome.js` owns a single serialized queue for messages that read or mutate policy, tab events, grant changes and reconciliation. A tab event cannot observe a half-saved mode change or overwrite a simultaneous rule-store edit. `RuleStore.commit()` publishes an in-memory change only after its persistence adapter succeeds.

Each reconciliation:

1. Loads and validates saved state if necessary, reads actual dynamic/session rules, and obtains current tabs.
2. Revalidates expiry, clock continuity and threat classification. It drops unknown, malformed, interrupted or invalid session grants.
3. Compiles the complete candidate. It checks dynamic, unsafe-dynamic, session and regular-expression capacities before replacing rules.
4. Removes session rules that do not belong to the candidate, including orphan rules left by older implementations.
5. Atomically replaces the dynamic set when changed, reads it back, and records the independently confirmed dynamic mode.
6. Writes a session journal intent, installs the session set, reads it back, and writes the applied journal and local receipt.
7. Recreates expiry and recovery alarms.

Dynamic rules and session rules each have an atomic Chrome update API. There is no cross-set transaction with `chrome.storage`. The intent journal and read-back handle interruption at those boundaries. A worker restart accepts a temporary grant only when its applied journal, policy epoch, tab context and actual installed rule group agree. Timed endpoint repairs have stable paired rule IDs and canonical exception metadata in `journal.endpoints`; both the allow and its sanitation rule must still be installed. Missing rules are not recreated from old local records. Unknown rules are removed.

The policy epoch includes extension version, build identifier and PSL digest. An extension/policy-bundle update revokes temporary endpoint exceptions and pauses. Old ephemeral journal records cannot cross epochs. Timed endpoint exceptions do not survive a fresh browser session without their applied session journal and actual DNR group. Closing the source tab or leaving its PSL site revokes the repair; returning to that site does not regenerate it. The shared exception schema accepts an optional `tabId` for Firefox compatibility, but Chrome requires it and validates the current source tab before accepting a repair.

Existing explicit request rules with `action: "allow"` are a different, persistent rule class. They remain site-scoped across matching tabs, with the same independent cookie sanitation and threat/manual-deny limits, in a separate session-ID range. The Chrome popup does not create this class. They must not be described as one-tab temporary repairs.

A startup failure resolves initialization into a degraded state rather than permanently rejecting every later message. The popup can request `retry-policy`, and a recurring recovery alarm tries again. Static protection may remain active while a dynamic update fails; a rejected update must not be described as an applied Strict mode.

### Popup integration contract

`popup-state` includes:

```js
{
  policy: {
    state: "applied" | "pending" | "degraded",
    desiredRevision,
    savedRevision,
    appliedRevision,
    dynamicRevision,
    sessionRevision,
    error,
    grantsPending,
    expirySemantics: "scheduled",
    warnings,
    topPartyCoverage: "explicit-top-sites" |
      "current-tabs-with-initiator-backstop"
  },
  coverage,
  mode, defaultMode, siteMode, strictAllowed, cleaning,
  requestedMode, requestedDefaultMode
}
```

`mode`, `defaultMode`, `siteMode`, `strictAllowed` and the cleaning switch use the verified dynamic snapshot. Before any snapshot can be verified, mode is `unknown`. A confirmed dynamic change can coexist with a later session or storage failure; the state remains degraded and the separate revisions describe that partial outcome. `appliedRevision` and `sessionRevision` are invalidated when session permissions are removed after a failed reconciliation.

`desiredRevision` names the compiled candidate. `savedRevision` names the complete intent whose session journal write succeeded; individual local preferences can already have been saved before that step. `requestedMode` exposes those saved mode preferences even when compilation or application failed. `grantsPending` means failed cleanup left the actual session state unknown or permissions still installed. It must not be presented as successful revocation.

`coverage` is the build's separate source-completeness receipt. An applied controller revision does not establish that all intended filter sources were packaged. The UI must inspect both, and must distinguish browser state from native-proxy receipts.

The retry request is `{type: "retry-policy"}` from the extension popup. Its successful result includes `{ok: true, policy, coverage}`. It runs the same reconciliation path as startup and alarms.

## Expiry and failure semantics

Chrome DNR session rules have **no built-in wall-clock expiry**. They persist across service-worker termination and are cleared at browser-session end or extension update. Chrome alarms can be delayed; sleep does not wake the machine to revoke a grant. A request already allowed cannot be undone.

| Permission | Scheduled removal | Other revocation triggers |
| --- | --- | --- |
| Threat navigation | 10 minutes | Leaving the exact host, closing the tab, epoch change, invalid journal/context. |
| Scanner pass | 60 seconds | A committed web navigation, tab closure, threat reclassification, epoch change. |
| Loaded embed | 60 minutes | Top-level loading/navigation, tab closure, provider threat classification, epoch change. |
| Endpoint exception | Chosen 1–1440 minutes | Source tab closure or leaving its PSL site, browser-session end, missing/interrupted journal or DNR pair, explicit successful removal, target threat classification, epoch change. |
| Site pause | 15 minutes | Explicit successful Resume, clock rollback, epoch change, invalid scope. |

These are scheduled deadlines, not hard maximum exposure bounds. Expiry is checked at reconciliation and startup; an expiry alarm targets the earliest deadline, with a one-minute recovery heartbeat. Browser suspension, delayed alarm delivery, unavailable storage or rejected DNR operations can delay a confirmed result. The warning page and policy receipt use scheduled language.

The controller persists a wall-clock high-water mark. A detected backward jump revokes temporary permissions and pauses and records a warning. A forward jump expires permissions immediately at the next reconciliation. This is conservative clock handling, not trusted time: elapsed time cannot be proven across every browser/OS suspension or clock change. While the clock remains below the high-water mark, a new temporary request can be refused rather than silently granted with an extended lifetime.

If a session journal write fails after DNR installation, cleanup removes the installed session rules. If that cleanup also fails, the popup reports degraded state with `grantsPending: true`; it does not claim the permission ended. The recovery path re-reads actual rules and retries.

Endpoint removal proceeds through DNR reconciliation even if deletion of its local saved record fails. Success requires actual rule removal and the applied journal/receipt; the stale local entry cannot resurrect a permission without its matching installed pair and applied journal. If DNR removal or the journal/receipt write also fails, the operation returns an error and the receipt reports the incomplete result. A local deletion warning alone is never proof that the browser has revoked a rule.

## Top-level scope, nested frames and service workers

Chrome 145 introduced `topDomains`/`excludedTopDomains`. These match the associated top-level frame; when no associated top frame exists, Chrome falls back to the initiator. The manifest therefore requires Chrome 145. Timed endpoint permissions additionally require their single explicit non-negative source tab ID, so another tab or a background-only request cannot borrow a top-page allowance through that fallback.

Manual endpoint rules use `topDomains`. Because their destination and rule site are known, first/third-party selection is calculated against PSL site boundaries rather than DNR `domainType`. An unrelated iframe can no longer evade a site's manual endpoint rule by becoming the immediate initiator.

Named Strict sites use `topDomains` and exclude their own registrable site from the destination set. This applies Strict to an embedded provider's requests even when that provider is first-party to its own iframe. A Strict host allowance exempts resource blocking, not cookie stripping.

Nested private suffixes require two more safeguards. A permission for a hosting company's site must not cover independently hosted tenant top pages, and a same-site destination exemption must not exempt those tenant resources. The compiler excludes nested PSL boundaries from top scopes and emits separate Strict resource/header rules for those destinations. For example, an `amazonaws.com` page treats `alice.s3.amazonaws.com` as another site. Wildcard-registry parent scopes that DNR cannot express safely are refused; users can scope the actual hosted site instead.

**Default Strict remains bounded by MV3's declarative interface.** The controller creates per-top-site rules for currently observed tabs and retains a generic initiator-based `domainType` backstop. For a never-seen top site, initial requests can race the asynchronous navigation reconciliation. The generic backstop cannot distinguish a request that is first-party to its iframe but third-party to the top page. A known parent-site exclusion can also cover a not-yet-observed independent tenant until its per-site rule is installed. The receipt exposes `current-tabs-with-initiator-backstop`; this is not a claim of race-free total top-site isolation.

Service workers can serve cached responses that DNR never sees. Switching a named site to Strict or No scripts still clears the service workers and Cache Storage of the origins the adapter can identify; unopened subdomains and arbitrary cached responses are not proven covered. No-scripts uses destination scope for the main-frame CSP and top-frame scope for subframe CSP, plus script blocking. This browser policy does not replace a system-wide mandatory egress boundary.

## Complete packaged PSL and conservative migration

The checked-in list includes both ICANN and PRIVATE sections:

- Source: <https://publicsuffix.org/list/public_suffix_list.dat>
- Snapshot: `2026-11-20_10-39-09_UTC`
- Upstream commit: `d7d7f1fd55166aaf73ad2f526e72634490acd9c8`
- SHA-256: `f3df783daf6bdf4c4d71759bc8a4b39f2d228a567078560a00e11f70df0703f4`
- Rules: 10,470; license: MPL-2.0.

`browser/vendor/public_suffix_list.dat` retains upstream notices and attribution. `browser/vendor/PSL-NOTICE.md` documents provenance and maintenance. `node scripts/update-psl.mjs` regenerates `browser/core/psl-data.js` offline from that source, normalizing IDN rules with Node's WHATWG URL implementation. The generated module exposes source/version/commit/hash/license metadata. The parser implements exact, wildcard and exception rules and the implicit unknown-TLD wildcard. It makes no network request and sends no visited hostname to the PSL service.

The shared loader must load `psl-data.js` before `hosts.js`. Chrome's worker bundle, the Firefox classic background list and the warning page all follow this order.

Rule-store schema 2 records `scope: "top-level-psl-v2"` and the PSL digest. Legacy allows/exceptions are revoked because changing immediate-initiator scope into top-frame scope can widen permission. Valid manual blocks and cosmetic rules survive revalidation. Legacy Relaxed/cleaning/host exemptions and pauses are revoked; stricter site choices survive. PSL digest changes revalidate all scopes and revoke old permissive rule/mode state rather than guessing how it should expand. The parser now rejects shared boundaries such as `ca.us`, `k12.ca.us` and `uk.com` as whole-site permission scopes.

## Other integration seams

`cosmetic-style` accepts only `{type: "cosmetic-style", on: boolean}` from a trusted top-frame content script. The worker chooses `EGCosmeticList.stylesheet()` itself and uses `chrome.scripting.insertCSS`/`removeCSS` with `origin: "USER"` for that sender's tab/frame. Incoming CSS, tab IDs and frame IDs have no authority. Load `core/cosmetic.js` in the worker before this handler can be used.

There is no translation of a browser page-scoped allowance into a global native-proxy host allowance. Native status and optional local-model UI integration belong to extension-owned pages; this worker does not expose a page-to-native command broker.

## Validation and remaining qualification

The focused core, Chrome-adapter, DNR, extension and filter suites passed 114 tests after the final source-tab implementation. This includes a regression for the shared queue/storage race. Cases cover:

- Saved Strict intent after rejected application, transient startup recovery and truthful partial receipts.
- Storage rollback, interrupted session journals, orphan rules, missing/expired grants and failed revocation read-back.
- Source-tab isolation with two tabs showing the same site, close/leave revocation, missing allow/sanitation pairs, fresh-browser reset, stable group IDs after earlier expiry, and stale local deletion without resurrection.
- Threat reclassification, denied embed requests without false success, backward-clock handling and quota refusal.
- Nested-frame scope, tenant isolation, wildcard/exception PSL parsing, IDNs and source-hash provenance.
- Cookie-preserving priority failures corrected by sanitation pairs, explicit manual-deny precedence and navigation-only threat continuation.

The real-browser headless/lifecycle fixtures were updated for source-tab session endpoint permissions, paired sanitation, the journal schema and a real warning tab. They remain future qualification gates. The environment available for this change rejected Chromium startup with a socket-permission error; no successful native Chrome run is claimed. Parent integration runs the complete project suites separately. Controller receipts verify registered rules and saved/applied state; they are not independent packet-level proof of every request outcome.

Primary API references consulted for this design:

- Chrome DNR: <https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest> — matching priorities, header modification after allows, per-set atomic updates, quotas, session lifetime and Chrome 145 top-frame conditions.
- Chrome alarms: <https://developer.chrome.com/docs/extensions/reference/api/alarms> — delayed delivery, sleep behavior and alarm persistence/recreation.
- Public Suffix List: <https://publicsuffix.org/list/> — canonical source, format and update guidance.
