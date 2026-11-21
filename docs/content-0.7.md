# Content filtering and local classification in 0.7

This release adds a deterministic native-ad detector, a bounded interface for an optional local classifier, and site-scoped cosmetic list data. The content engine still makes display decisions. Hiding something does not undo a request or impression that already occurred, and it is not proof that a site cannot identify the browser.

## What runs without a model

The existing 35 generic ad-slot selectors remain. In Chrome their fixed stylesheet is now requested through `cosmetic-style` and inserted by the extension worker with `scripting.insertCSS`, rather than as a page-readable `<style data-eg-page-ui>`. The worker chooses the bundled CSS; content messages cannot supply CSS. This removes that default DOM signature, but blocking outcomes and interactive controls remain observable.

Stylesheet status reports the confirmed applied state, pending work and any error. A later policy broadcast retries a rejected operation, so a temporary worker failure does not permanently disable the stylesheet for an already-open page.

The builder can additionally provide domain-scoped cosmetic rules. They use the same protected, reversible actuator as manual rules. A rule that matches a form, player, editor, focused content or protected structure is not applied. Scoped lists do not authorize scriptlets, arbitrary JavaScript, or unrestricted CSS.

The small native-ad detector recognizes an exact short disclosure such as “Sponsored”, “Promoted” or “Advertisement” in a linked, repeated card structure. Several French, German, Spanish and Portuguese equivalents are included. A headline mentioning sponsored content is not itself a disclosure. The detector requires structural evidence as well as the label and does not infer advertising merely from a shared class name. It runs with built-in cosmetic protection and makes the hide reversible.

This is deliberately conservative. It does not recognize every language, hidden disclosure, non-card layout, video ad, closed shadow root or ad mixed into a necessary first-party API response. A model may help with residual candidates; no model accuracy or latency claim has been established by these source-level tests.

## Work scheduling and safety

Page mutations no longer exhaust a 40-scans-per-minute quota and restore every hidden item. Changed subtrees become work items. At most 12 tasks run in one scheduled turn, with an elapsed-time check; remaining work continues on a later turn. Pending subtree roots are bounded and coalesced. There are at most 500 live hide records, 200 scoped rules on a page, 25 new matches per rule/subtree task, and 24 candidates in a semantic snapshot. Expensive native candidate traversal is also bounded.

These are work limits, not hard real-time guarantees: an individual browser selector query or DOM traversal can still take time. On very large documents, a discovery pass can stop at its bounds; later relevant mutations trigger further work. Existing validated hides remain in place while discovery is deferred.

Existing records are rechecked, including protected descendants, target editability, effective role tokens, focus, connectivity, selector membership and placement. Semantic records also carry a bounded content/structure fingerprint. Changing the card invalidates its semantic decision; adding an unrelated sibling does not invalidate it. User Show/Undo decisions persist for that page load.

The picker starts with the selected node's ID or precise attribute value. A shared attribute name is not treated as proof that all matches are ads. Multiple-match proposals require independent deterministic paid-placement evidence; otherwise the picker continues looking for a precise single-card candidate.

## Candidate interface

The interface is extension runtime messaging, not a DOM event or `window.postMessage` bridge. It exposes no arbitrary-selector, JavaScript, network-allow or permission action.

### Extract

```js
{type: "semantic-candidates"}
```

Response:

```js
{
  ok: true,
  documentId: "opaque per-document ID",
  domGeneration: 3,
  site: "publisher.example",
  candidates: [{
    id: "c7",
    kind: "card",
    disclosures: ["Sponsored"],
    accessibleLabel: "",
    structure: {tag: "article", repeatedPeers: 2, hasLink: true, textLength: 81},
    destinationRelation: "same-host", // other-host, mixed or none
    classification: "paid-placement", // organic, essential-commerce or uncertain
    confidence: "high",              // deterministic evidence level, not calibrated probability
    text: "A bounded, redacted card snippet"
  }]
}
```

`domGeneration` identifies an extraction snapshot. A new extraction invalidates the old IDs. Related mutations mark candidate records stale; application also rechecks structure, location, age and protection. Snapshots expire after two minutes. Actual URLs, arbitrary attributes, request bodies, cookie values and form values are not fields in the response. Snippets are at most 400 characters; accessible labels are at most 160. Visible URLs, email addresses and obvious long identifiers are redacted. Protected cards export no snippet.

Known account/message/payment and patient/medical/health-record paths, pages containing password fields, and known private messaging applications disable extraction and automatic semantic detection. This is a conservative heuristic, **not a complete detector of sensitive pages or personal data**. It may exclude a public health article while missing a private application at an unfamiliar URL. The optional classifier is explicitly invoked on the selected page; inputs must remain local and ephemeral. Do not add a cloud fallback or persist the snippets as browsing history. Sensitive surfaces require separate design and qualification before extending coverage.

### Apply labels

```js
{
  type: "semantic-apply",
  documentId: "same ID",
  domGeneration: 3,
  labels: [{id: "c7", category: "paid-placement"}]
}
```

Labels accept only `id` and one of four category names. The batch has at most 24 unique IDs. Only a current, safe `paid-placement` can create a reversible hide. A protected `essential-commerce` candidate cannot be overridden by a model label. Unknown, changed, detached, aged or navigated candidates are rejected; the response separately lists applied and rejected results. The model cannot create selectors, page code, endpoint exceptions, broader permissions or persistent rules through this API.

### Restore

```js
{type: "semantic-restore"}
```

This lifts native/model semantic hides, invalidates the snapshot, and pauses automatic semantic hiding for the page load. It does not remove user request rules or other cosmetic rules. Each hidden item also has Show/Hide again. The existing page Restore/Resume control remains available.

## Build-time cosmetic data

The builder loads `core/cosmetic-data.js` before `core/cosmetic.js`:

```js
globalThis.EGCosmeticData = {
  schema: 1,
  rules: [{include: ["publisher.example"], exclude: [], selector: ".advert-unit"}],
  exceptions: [{include: ["account.publisher.example"], exclude: [], selector: ".advert-unit"}],
  stats: {}
};
```

Every hide needs at least one explicit include domain. Exceptions may have an empty include list to apply globally. Every scope must be valid; an invalid entry is rejected as a whole rather than having an invalid exclusion silently dropped. A matching exception suppresses the identical canonical selector. Only the existing bounded standard-selector grammar is accepted. The runtime checks the data again and caps the per-page rules. Remote list data cannot inject scriptlets or executable code.

Imported `#@#` exceptions govern imported identical-selector rules only. The fixed 35 built-in slot rules are independent; use the site's built-in-hiding switch to lift those. An imported exception for `.ad-slot` does not by itself turn off the built-in `.ad-slot` rule. This boundary is deliberate and should be preserved in UI/help claims until the engines share a reviewed exception contract.

## Embed retries and tracker substitutes

Supported script-built embeds are discovered after initial page load as well as on SPA mutations. Iframe source changes replace stale placeholders. The saved source and script contract are rechecked before requesting a load permission and again before retrying it. A page cannot silently change the held resource while retaining the old placeholder's decision.

A retried script is a fresh element because cloning can preserve the HTML “already started” state. It copies the original script type, integrity, CORS, referrer policy, nonce and relevant loading attributes before setting its source. Non-async retries retain ordered dynamic execution. No retry removes an integrity or CSP check to force success. Retrying after load cannot reproduce the original parser-blocking timing, and the code does not claim to do that.

The GTM/gtag surrogate reads the documented `l=` custom data-layer name from the original script element. It permits only a bounded direct global name, rejects prototype-sensitive names, does not invoke a global accessor, and drains the existing array and subsequent callbacks. It never evaluates a property path, fetches a script or scans unrelated globals. The real-browser redirect path still needs qualification on supported browsers; VM tests exercise the documented original-src contract.

## Verification and limits

`tests/browser/content-advanced.test.cjs` exercises busy-page endurance, precise picker selection, protected/focused/edited records, native disclosure positives and editorial negatives, model snapshot/permission boundaries, related versus unrelated mutations, sensitive-page exclusion, cosmetic scope exceptions, Chrome style dispatch, late embeds, retained script constraints, stale resources and safe custom GTM queues. Existing content and page tests continue to pass.

These tests use a DOM stub and controlled timer/observer deliveries. They do not establish actual-browser layout, SRI enforcement, CSP behavior, click visibility, network headers or model effectiveness. The separate browser fixture qualification remains necessary on a permitted target environment. Do not report the VM fixtures as browser-network tests or treat cosmetic success as proof of anonymity.

## Primary design references

- [Chrome content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts): isolated JavaScript worlds share the page DOM.
- [Chrome scripting API](https://developer.chrome.com/docs/extensions/reference/api/scripting): browser-origin stylesheet insertion/removal and execution contexts.
- [HTML script element](https://html.spec.whatwg.org/multipage/scripting.html#the-script-element): source fetching, integrity, CORS, script type, nonce and execution semantics.
- [Google data-layer contract](https://developers.google.com/tag-platform/tag-manager/datalayer): custom `l=` queue names and callback ordering.

These primary documents were checked during the implementation. Their platform capabilities do not substitute for running the extension's own browser fixtures.
