# Imported ad-hiding coverage in 0.8

This release increases the portion of the verified filter lists that the content engine can enforce. It adds indexed generic ID/class rules, Public Suffix List entity scopes, a constrained native `:has()` grammar and the cosmetic exceptions needed to apply those rules without discarding the source lists' compatibility decisions.

These are display controls. They do not undo requests or impressions, stop an inline fingerprinting script, hide the browser's IP address or establish anonymity. The optional semantic model remains a separate, explicitly invoked review flow with the 0.7 authority limits.

## Measured source-rule coverage

The following comparison uses the same EasyList and EasyPrivacy source snapshot, version `202611211610`, with the 0.7 compiler at `cbed36a` and the 0.8 compiler. It measures accepted source rules, **not advertising detection accuracy or a live-site blocking percentage**.

| Compiled category | 0.7 | 0.8 |
| --- | ---: | ---: |
| Site-scoped hide rules | 9,043 | 9,718 |
| Indexed generic hide rules | 0 | 13,079 |
| Identical-selector exceptions | 324 | 326 |
| Cosmetic page exceptions | 0 | 167 |

Of the new scoped rule set, 482 rules use the supported native relational grammar. Across accepted entries, 278 contain an entity scope. These categories overlap and must not be added as independent coverage gains. Generic exceptions intentionally keep generic rules off some pages, including matching Amazon, Google Search and account surfaces; specific rules may still apply there.

The same compilation explicitly rejects 479 unsupported generic selectors, 931 unsupported selectors, eight unsupported scope lines and 323 procedural/scriptlet forms. No conservative exception fallback was required for this source snapshot. The build records the current counts; they will change as the source lists change.

Reproduction inputs:

- EasyList SHA-256: `08d8efac3d18fa78e5656070769926fe2bf694d057545fce7c34dbf9deddf271`.
- EasyPrivacy SHA-256: `84e1f89c2783f1b3ada395d8a8f0bcd3fd43c07b0fd7149a2d6c5bbd4695c6c7`.
- Source URLs and licenses remain in the verified cache metadata and generated `NOTICE.txt`.

## Indexed generic rules

Only a single validated `#id` or `.class` is accepted as a generic hide selector. Examples are `##.ad-card` and `###advert-container`. The compiler also supports negative-only scopes such as `~example.com##.ad-card`; the exclusion remains part of the rule.

The runtime builds ID and class maps from the packaged data. It walks changed DOM subtrees and looks up the tokens it actually encounters. It does not append thousands of generic selectors to a stylesheet or run one document query per source rule.

A matching token is only a candidate. The existing reversible actuator checks the target, its descendants, its protected form/editor/media context, focus and connectivity before hiding it. A later class or ID change can release the hide. Adding protected descendants also releases it. Show, the site's built-in-hiding switch, Restore and Resume retain their existing behavior. A Show decision survives subsequent scans for that page load.

The fixed 35 slot selectors remain an independent stylesheet. Imported selectors use protected hide records. Neither the imported data nor a page message can add arbitrary CSS declarations, scripts or network permissions.

## Scope matching

A literal domain keeps suffix matching: `publisher.example` can cover `www.publisher.example`. An entity such as `google.*` matches the hostname prefix to the left of its actual prevailing public suffix. It can match `google.com`, `www.google.co.uk` and `images.google.com.br`; it does not match `google.evil.biz`. A more specific entity such as `www.google.*` retains that hostname prefix.

The runtime uses the complete packaged PSL, including private suffixes, wildcards and exceptions. It does not treat `tenant.github.io` as part of a `github.*` entity, or `tenant.s3.amazonaws.com` as part of `amazonaws.*`. An explicit `tenant.*` entity can match the former: this syntax describes a naming family, **not verified common ownership**. Entity scope support is confined to imported cosmetic rules and exceptions. It creates no network allow, trust relationship or cross-tenant permission.

Any invalid scope in a hide rule rejects the whole rule. The compiler does not drop an invalid exclusion and retain a wider hide. Public suffixes are not hide scopes. They may appear in cosmetic exceptions, where they only reduce hiding; the cached lists use this for `gov.uk`.

## Native relational selectors

`core/cosmetic-selectors.js` is separate from the manual-rule and picker parser. Imported rules may use up to two non-nested `:has()` conditions. Each condition has at most two relative alternatives, three selector parts and 160 characters. The entire selector retains the 300-character limit and the existing restrictions on attributes, target elements and executable-looking syntax.

Removing every `:has()` must still leave an independently specific target. For example:

```text
publisher.example##.ad-card:has(> .paid-disclosure)
publisher.example##.ad-card:has(+ .advertisement-note)
```

A broad ancestor selector such as `div:has(.ad)` is rejected. Nested `:has`, `:has-text`, arbitrary regular expressions, XPath, property inspection, `:remove`, scriptlets and CSS declarations remain unsupported. The engine does not import a general procedural filtering language.

Chrome evaluates accepted selectors through its native selector APIs. Relational rules still use protected reversible records. After relevant changes, each applicable relational rule is rescheduled once against the document, because a changed descendant or sibling can affect a target outside the immediate dirty subtree. Attributes inside the relation are included in observation. A hidden record is also checked against the current selector before it remains hidden.

## Cosmetic exception contract

An imported `#@#` exception suppresses the identical canonical selector in both generic and scoped imported rules when its scope matches. It does not disable the fixed slot stylesheet, manual rules or the independent semantic detector. This preserves the separation documented in 0.7.

The compiler recognizes cosmetic page exceptions with these options and aliases:

| Option | Imported family suppressed |
| --- | --- |
| `generichide`, `ghide` | Generic ID/class rules |
| `specifichide`, `shide` | Site-scoped rules |
| `elemhide`, `ehide` | Both imported families |

Supported exception patterns use literal URL text, `*`, the separator `^`, domain anchoring `||`, and start/end anchoring `|`. An optional `domain=` scope may include bounded positive/negative domain or entity names. Extra modifiers and source regular expressions are rejected. A finite-state matcher advances URL positions; it does not execute source regexes or use wildcard regex backtracking. Pattern length is capped at 512 characters with at most eight wildcards. A URL longer than 8,192 characters retains a potentially applicable exception conservatively.

Every page-policy evaluation shares a 250,000-step position budget across its exception patterns. If matching exhausts that budget, the affected imported family is disabled and the status includes the reason and exhausted-budget flag. This bounds adversarial wildcard-heavy inputs without assuming that a partially checked exception does not apply. Generic and scoped discovery reuse the same policy receipt.

Unsupported exceptions have explicit fallbacks:

- An otherwise supported `#@#` selector with an unrepresentable scope quarantines that exact selector across imported rules. The original exception is counted as rejected; the quarantine is recorded separately.
- An unrepresentable cosmetic page exception disables its affected imported family in the generated data. An unknown combination affecting both families disables both.
- A malformed runtime exception shape also disables imported coverage conservatively. It is not silently ignored while hides remain active.
- An unsupported selector that cannot be used by the hiding engine is counted and rejected; it does not authorize an alternative selector.

These fallbacks only reduce imported hiding. They cannot grant network access. Counts and flags are carried in `stats.dropped`, `stats.fallbacks` and `fallback` so a source change cannot silently become a claimed coverage gain.

URL changes refresh the imported policy. Content checks its own location on mutation/status/history events and on the worker's fixed `page-location` notification. No URL supplied by a page message is trusted. The worker notification covers SPA URL changes without a DOM mutation. Application and restoration still occur through the bounded work queue, so these are not synchronous navigation or impression-prevention guarantees.

## Work and data bounds

The 0.7 per-turn task/time checks remain. Each generic traversal task visits at most 96 nodes before yielding. It holds at most 64 ancestor frames and visits at most 50,000 nodes per dirty subtree. Each node contributes at most 32 class tokens. A generic selector can own at most 25 hide records; all hiding shares the 500-record document limit. Scoped rules remain capped at 200 per page. The compiled rule budget is 30,000 entries, including hide rules and exceptions.

The caps stop additional discovery; they do not restore existing validated hides or disable the page's protection permanently. Later relevant mutations can schedule new work. Extremely large/deep documents or nodes with many classes may contain unmatched ads. `status().imported` reports active rule counts, applicable exception reasons, visited work and reached limits. These are local runtime receipts, not browsing-history telemetry.

The data remains schema 1 with additive fields:

```js
{
  schema: 1,
  rules: [{include: ["publisher.example"], exclude: [], selector: ".ad-card:has(> .paid-label)"}],
  genericRules: [{include: [], exclude: [], selector: ".advert-container"}],
  exceptions: [{include: ["account.publisher.example"], exclude: [], selector: ".advert-container"}],
  hideExceptions: [{kind: "generic", pattern: "||publisher.example/account^", include: [], exclude: []}],
  fallback: {generic: false, scoped: false, selectors: []},
  stats: {}
}
```

Chrome's content bundle loads the packaged PSL and hosts module, the original selector parser, `cosmetic-selectors.js`, cosmetic data and `cosmetic.js` before `content.js`. Firefox's existing manual controls remain separate; this release does not claim imported-list parity there.

## Verification

`tests/browser/cosmetic-coverage.test.cjs` covers the independent manual/import grammar boundary, nested/broad selector rejection, PSL entities, private tenants, global and scoped exceptions, unsupported-exception fallbacks, hostile wildcard patterns, 13,000 indexed rules without per-rule DOM queries, protected context, continuation under load, record caps, reversible controls, SPA exceptions, deep descendant and sibling invalidation, and explicit depth/token limits.

The relational DOM tests use named fixture oracles for native selector matches. They test scheduling and revalidation independently of the import parser; they **do not test Chrome's CSS engine**. Existing source-level content and page regressions remain part of the gate. Real-browser selector/cascade, SRI/CSP, visibility and live-site false-positive qualification must run on a permitted environment. No native Chrome run was performed for these changes in the constrained workspace.

## Primary references

- [Selectors Level 4, relational pseudo-class](https://www.w3.org/TR/selectors-4/#relational): native relative-selector semantics and the prohibition on nested `:has()`.
- [uBlock Origin static filter syntax](https://github.com/gorhill/uBlock/wiki/Static-filter-syntax): entity scopes, cosmetic exceptions and the generic/specific distinction.
- [uBlock Origin procedural cosmetic filters](https://github.com/gorhill/uBlock/wiki/Procedural-cosmetic-filters): why procedural operators require narrow scopes and should be used only when plain CSS cannot express the match.
- [Public Suffix List](https://publicsuffix.org/list/): public and private suffix boundaries; the actual packaged snapshot and its hash are recorded separately in the build.
