# Browser enforcement in 0.9

## Isolation is a named site policy

Chrome's new `isolated` mode blocks every cross-site **subresource** represented by the compiler's `SUBRESOURCE_TYPES`. This includes images, stylesheets, media, scripts, frames, fonts, objects, fetch/XHR, pings, CSP reports, WebSocket and WebTransport handshakes, Web Bundles and `other` requests. The comparison is against the associated top-level site's packaged Public Suffix List boundary. A foreign iframe does not become first party merely by fetching its own origin.

Isolation has no payment, sign-in, CAPTCHA, CDN, embed or saved Strict-host exemptions. Existing persistent endpoint allows remain saved, but their priority is below the Isolation block. An explicit change to another site mode is how the user relaxes this policy. Ordinary Pause is rejected while Isolation is either requested or still confirmed as applied.

This is a Chrome capability. Firefox remains a manual HTTP/S rule baseline in this release; it does not claim Isolation or transport-handshake parity.

### What is covered

| Request/context | Installed Isolation policy |
| --- | --- |
| Cross-site subresource with an associated top-level site | Block, for every supported subresource type |
| Same-site subresource | Existing list/manual policy still applies; remove `Cookie`, `Authorization` and `Referer` request headers and `Set-Cookie` response headers |
| Initial main-frame navigation **to** the isolated site | Destination-scoped header removal, independent of an early worker/navigation event |
| Navigation to another site, including a form or new window | No general navigation containment; the destination's existing policy applies |
| Independent private tenant below the isolated site's DNS parent | Treated as cross-site; the parent's mode does not cover the tenant's own top page |
| Already established connection | Not closed by installing these rules |
| Request without an associated top frame | Chrome's initiator fallback, which is a different and narrower attribution claim than universal tab isolation |

The compiler uses `topDomains` and `excludedTopDomains`, available at the project's Chrome 145 minimum, for top-page scopes. `requestDomains: [site]` alone includes independent nested tenants, so a second block restores those PSL destination boundaries. For example, `alice.s3.amazonaws.com` is cross-site to `amazonaws.com`. The destination navigation sanitizer also excludes nested boundaries so a parent's mode cannot strip an independent tenant's sign-in.

IP addresses, single-label hosts, public suffixes and conservatively excluded wildcard registry bases cannot be activated as isolated contexts. A wildcard base that has the same registrable parent as an isolated site receives an `unsupported` receipt, `active: false` and effective mode `unknown`. It never inherits a false claim of Isolation. Default Strict's separate preparation hold remains in effect on unprepared contexts where applicable.

## Priority and credential invariants

| Priority | Action class | Security purpose |
| ---: | --- | --- |
| 50 | Global Privacy Control | Independent of resource allowances |
| 46 | Isolation header removal | Ordinary repairs and explicit threat navigation consent cannot restore HTTP credentials |
| 45 | No-scripts response policy | Existing No-scripts behavior |
| 40 | Manual endpoint deny | Retains precedence over all ordinary permissions |
| 32 / 31 | Threat navigation sanitation / explicit Continue | Exact host, source tab, main frame only |
| 30 | Threat rules | Threats remain classified above Isolation and ordinary repairs |
| 24 | Isolation cross-site block | Above stored endpoint allows, temporary repairs, embeds, compatibility allowances and surrogates |
| 22 / 21 / 20 | Grant sanitation / timed endpoint repair / saved allow | Cannot lift Isolation, threats or manual denies |
| 14 / 13 / 8 | Relaxed / embed with cookies / ordinary embed | Existing lower-priority permissions |
| 10 | Ordinary header and link cleaning | A parameter-preservation brake cannot suppress sanitation |
| 9 | Parameter transforms and fixed preservation brakes | GET main-frame only; no generic frame permission |
| 7 | Strict and preparation blocks | Existing Strict resource policy |

An isolated ordinary site adds three dynamic rules: one block and two header rules. Sites with nested PSL boundaries add a second block. Both header rules count toward Chrome's unsafe dynamic-rule quota. The controller retains its complete-policy capacity preflight; it refuses the requested activation if the full set cannot fit and does not install a partial or broader fallback.

The navigation sanitizer is destination-scoped intentionally. The extension does not infer that a new top-level navigation has the old page as its associated top frame. It also does not try to reconstruct or replay authenticated submissions.

Header removal is not a stateless browsing session. Same-site code still runs, can read application storage, and can encode an identifier in a body, a custom header or an unrecognized URL parameter. IP addresses, TLS client certificates and TLS session state are not erased. The [Fetch standard's credentials definition](https://fetch.spec.whatwg.org/#credentials) includes more than the HTTP header fields controlled here. Sign-in and other stateful features can break because the HTTP credentials are deliberately removed.

## Controller, authority and recovery

Only the extension popup's existing mode-change handler can select Isolation. Content messages, the warning page and the unwrap page cannot change site modes. Content's narrowly scoped embed request is refused when its provider would cross an isolated site's boundary. The endpoint and Strict-host repair handlers reject the equivalent cross-site requests. Same-site endpoint permissions remain tab-bound and cannot override the priority-46 sanitizer.

Activating Isolation saves the new mode and removal of that site's existing Pause in one `storage.local.set` operation. The effective-mode calculation also refuses to overlay a Pause on Isolation, independently of that storage write. Startup and reconciliation delete inconsistent stale Pause entries. A failed preference save restores the previous in-memory intent and does not publish new rules.

Reconciliation revalidates temporary permissions against the desired mode. It removes cross-site timed endpoint repairs and provider grants, removes their actual session rules before changing dynamic policy, and then installs the complete named mode in the existing atomic dynamic update. Revoked repairs do not reappear when the user later leaves Isolation. Explicitly saved persistent allow rules remain separate user intent and can matter again after an explicit mode change.

Isolation is a restrictive mode and survives the existing conservative PSL/scope migration. Relaxed modes, cleaning exceptions and host permissions retain their existing migration revocation. Old matching grant journals do not resurrect a cross-site permission under a newly isolated site. Persistent Isolation does not depend on session storage or a live service worker.

This release adds no automatic reload, request replay, cookie deletion, IndexedDB deletion or other browsing-data clear when Isolation is selected. The UI directs the user to reload if needed. A reload is not attested to close every old worker or transport connection.

### Popup receipt

`popup-state.isolation` is `null` when neither the requested nor the applied site mode is isolated. Otherwise it has this shape:

```js
{
  state: "applied" | "pending" | "degraded" | "unsupported",
  active: true | false,
  requested: true | false,
  revision: "confirmed dynamic revision" | null,
  resourceScope: "cross-top-site-subresources",
  httpHeaders: ["cookie", "authorization", "referer", "set-cookie"],
  navigationScope: "destination-site-headers",
  existingConnections: "not-revoked",
  reloadNeeded: true,
  reason: "present for unsupported host scopes"
}
```

`active` means a matching supported host has a confirmed dynamic readback for Isolation. It does not mean every browser transport or header behavior has been independently observed at an origin. `reloadNeeded` is a standing compatibility instruction; the controller does not track or attest completion of a reload.

The global `policy.state` remains authoritative for overall controller health. A rejected activation yields `degraded`, `active: false` and the previous effective mode. A rejected request to leave Isolation yields `degraded`, `active: true` while the previous rules remain confirmed. If the dynamic update succeeds but readback fails, the old receipt is invalidated and `active` is false until recovery. If dynamic readback succeeds but later journal/local bookkeeping fails, `active` can truthfully remain true alongside a degraded global receipt.

Temporary permissions still use the existing scheduled expiry semantics. There is no new hard deadline or wall-clock guarantee.

## Two repaired enforcement gaps

### Manual WebSocket denies

The old `other` rule mapped to Chrome's WebSocket resource type, but its endpoint regex accepted only `http:` and `https:` URLs. The deny compiler now permits `ws:` and `wss:` schemes only for a block rule whose type set includes WebSockets. It keeps the exact destination host, path pattern and top-site scope, with no positive HTTP method condition.

Saved allows retain their HTTP-only regex. Timed `other` repairs retain their exact `other` resource type. The repair therefore does not silently grant new transport permissions to existing allow records. Firefox's HTTP/S subscription is unchanged.

The no-method-filter choice follows Chromium's own [DNR WebSocket and WebTransport browser tests](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/browser/extensions/api/declarative_net_request/declarative_net_request_browsertest.cc): socket matching is not safely modeled by adding an ordinary positive `get` method condition.

### Parameter-preservation frames

The previous generic unsubscribe/preferences `allow` rule applied to main frames and subframes at priority 9. A foreign frame could use a matching path to outrank Strict's priority-7 block and suppress equal-priority cookie sanitation. The repaired legacy `compileParams` API restricts all parameter redirects, the Amazon path rewrite, and preservation brakes to GET main-frame navigations. It assigns them priority 9 while ordinary sanitation moves to 10.

Thus a preserved unsubscribe navigation keeps its functional URL while still losing a bounce tracker's cookies. The same path in a foreign iframe creates no permission. POST and other non-GET submissions are not redirected. Generic declarative iframe query rewriting is intentionally removed; this avoids category-wide `allow` exceptions that would weaken frame blocking.

The production maintained-parameter compiler replaces the legacy parameter ruleset rather than adding a second competing set. Its fixed guard conditions and runtime page cleaner must share the same policy. Source exceptions must be expressed as restrictions on their own transforms, never broad network `allow` rules.

The legacy compiler consumes the shared fixed `PRESERVE_URL_REGEXES` guards too. Auth/payment paths, sensitive signature/auth keys, URL userinfo and conservatively encoded query keys receive the same GET main-frame-only brake as unsubscribe pages. Short RE2-compatible source patterns still require Chrome's native compiled-regex-size qualification; JavaScript regex acceptance alone does not prove that limit.

## Evidence and qualification boundary

The focused tests exercise compiler matching intent, the exact worker in an isolated mocked Chrome environment, failure injection, saved/applied receipt separation, pre-update revocation, single-write Pause removal, migration, restart, capacity refusal, private tenants, request types and preservation precedence. They do not launch a native browser or change a real profile.

The implementation pass verified 62 Chrome adapter tests, 24 DNR tests and 30 filter tests. The final filter-only rerun corrected an older OAuth expectation to preserve the complete potentially signed auth URL under the new fixed guards. All 116 focused cases pass in the resulting source state.

Native Chrome qualification remains required for origin-observed HTTP header removal, cached HTTP authentication behavior, real handshake blocking, redirects, browser-cache behavior, and existing-connection behavior. The environment's previously rejected Chrome startup is not bypassed. Compiler and mock results are not reported as native transport captures.

Chrome's [DNR reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) defines the relevant rule priority, top-frame fallback, quota and network-stack boundaries. Responses generated by a service worker or read from CacheStorage are outside that boundary; worker fetches that reach the network can be filtered. The [webRequest transport documentation](https://developer.chrome.com/docs/extensions/reference/api/webRequest) distinguishes handshakes from already established WebSocket/WebTransport traffic. These are architectural limits, not promises that a larger blocklist or local classifier can remove.
