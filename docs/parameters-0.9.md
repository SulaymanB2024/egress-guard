# Maintained query-parameter protection in 0.9

Chrome builds now compile the maintained **AdGuard/uBO – URL Tracking Protection** source in addition to the existing hand-written parameter policy. The result supplies both navigation rules and the JavaScript link/address cleaner. Source exceptions constrain the combined policy, including older global and site-specific removers.

This removes known identifiers from addresses. It does not anonymize an account, hide the destination IP address, prevent every fingerprint, or identify every first-party identifier. Counts of accepted filters are coverage measurements, not measured reductions in tracking.

## Source and build receipt

The canonical source is [`uBlockOrigin/uAssets/filters/privacy-removeparam.txt`](https://github.com/uBlockOrigin/uAssets/blob/master/filters/privacy-removeparam.txt). The builder fetches the raw file with its own `url-tracking` source identity, verifies its title, license and homepage, enforces minimum parameter-rule coverage, and records the content hash and fetch time. The current upstream header contains `%timestamp%`; that template is recorded as no publisher date.

The source retains [GPL-3.0](https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE). Generated `core/param-data.js` and parameter rules contain derived source data and carry the generated build's attribution and source receipt. The compiler/runtime implementation is project code; it does not change the imported data's license. The full upstream list is not committed to this repository. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for redistribution details.

The verified November 21, 2026 snapshot has SHA-256 `c7d4e2295262e9e509a522ba689cada33119ce05ddffb2cd18a2af00a641bf53`, 182,518 bytes and 2,749 non-comment rows. Initial compiler results for that snapshot are:

| Receipt | Count | Meaning |
| --- | ---: | --- |
| Parameter rows | 2,747 | Includes removers, exceptions and inactive conditional rows |
| Productive imported remover rows | 1,977 | Accepted source rows retaining at least one permitted destination; these can overlap one another or legacy rules |
| JavaScript parameter names | 1,676 | Distinct names in the combined policy; the development baseline has 346 |
| Native parameter names | 1,674 | Two bracket-bearing names are retained in JavaScript cleaning but deliberately deferred by DNR |
| Parameter DNR rules | 801 | Includes 52 fixed preservation guards and one Amazon path rule |
| Source exception rows | 80 | Six apply only outside the declared main-frame scope |
| Conservatively widened exceptions | 44 | Usually a path-specific exemption widened to its whole destination host |
| Unsupported remover rows | 610 | Explicitly counted by reason; these rows do not execute |
| Other resource-type removers | 40 | Outside the main-frame-only navigation policy |
| Protected-name remover rows | 25 | Refused because their names are in `KEPT` |
| Inactive conditional rows | 4 | The source's `!ext_ubol` branch is inactive under this MV3 compatibility profile |
| Legacy compatibility exclusions | 3 | `sr`, `crid` and `sprefix` kept on hosts with a label starting `ama` so legacy data cannot recreate the inactive Amazon removers |
| Coarsened entity prefixes | 5 | `aliexpress` → `ali`, `amazon` → `ama`, `audible` → `aud`, `google` → `goo`, `uploadnow` → `upl` |
| Globally quarantined names | 1 | `analytics_trace_id` |
| Incidental non-removal rows | 2 | A header-removal rule and a cosmetic rule, neither executed by this compiler |

`analytics_trace_id` has an unanchored exception with path and query syntax that this compiler cannot represent safely. The key is therefore preserved everywhere, including where a legacy rule might otherwise remove it. All other accepted removers remain active. This is an explicitly **reduced** conversion: source availability is true, reduced coverage is true, and the policy is not disabled. A complete build rejects it by default. The narrow `--allow-parameter-quarantine analytics_trace_id` option acknowledges this particular preserved key while retaining every other required-source, effectiveness and cosmetic-coverage gate. It does not accept a new quarantine or disabled policy, and the receipt still says reduced. Merely downloading every feed does not make the conversion complete.

## Supported language and deliberate bounds

The implementation follows the documented [uBO filter syntax](https://github.com/gorhill/uBlock/wiki/Static-filter-syntax), with a smaller declared subset suitable for literal Chrome query transforms:

| Source form | Treatment |
| --- | --- |
| `$removeparam=literal_name` | Supported; parameter names are case-sensitive |
| `||host.example^$removeparam=literal_name` | Supported for the destination host and its subdomains |
| `to=host.example\|other.example\|~exempt.example` | Finite literal destination predicates; every arm must validate |
| `doc`, `document`, `all`, or omitted resource type | Supported only as top-level GET navigation rules |
| Positive resource types that exclude documents; `~document` | Counted as outside the navigation policy |
| Matching `$badfilter` | Disables the matching source identity; option order is normalized, and overlapping legacy removers cannot recreate a literal disabled removal |
| Known boolean conditional expressions | Parsed without evaluation of source code; bounded nesting and expression size |
| Named/all-name exceptions with a literal destination anchor | Preserved, conservatively widening path restrictions to that whole host |
| Entity exceptions such as `||google.*/maps^` | Conservatively preserve the named key on every hostname with a DNS label starting with the entity's first three characters |
| First-party-only exceptions with finite positive initiator domains | Conservatively preserve parameters on the corresponding registrable destination sites, using the pinned public and private PSL |
| Initiator-scoped removers (`domain=`, `from=`) | Unsupported; the cleaner does not have equivalent initiator context in every caller |
| Path-specific removers, arbitrary URL patterns and end anchors | Unsupported; never silently converted into whole-host removal |
| Regex/inverted names and remove-all instructions | Unsupported removers; literal transforms cannot reproduce them generally |
| An exception whose named key is known but whose scope is not representable | Global quarantine of that key, reduced coverage, complete-build rejection |
| An ambiguous/unbounded all-name exception or unknown/malformed conditional | Complete-build failure; an explicit reduced build disables the entire combined cleaning policy |

The compatibility environment explicitly sets `ext_ubol`, `env_chromium` and `env_mv3` true and `env_firefox` false. It is a chosen MV3 compatibility profile, not a claim that this extension is uBlock Origin Lite. Unknown flags are never guessed. The existing source uses only `!ext_ubol`.

Finite `to=~host` exclusions also constrain an older remover for the same key. This conservative rule prevents the hand-written global policy from undoing an upstream compatibility exclusion. Source exceptions never emit `allow` or `allowAllRequests`; they remove authority from the cleaning predicates.

Coarsening can preserve extra tracking parameters. For example, the upstream Google Maps exception preserves `utm_campaign` across hostnames with a label starting `goo`, including `good.example`, rather than only Maps URLs. Exact full-label complements exceeded Chrome's compiled-regex budget; the same broader prefix predicate is applied to runtime data and native rules. If several unrelated entity prefixes constrain one key, the compiler conservatively shortens them further to their first characters and counts that fallback; the current source needs no such fallback. A site-specific all-parameter exception preserves the older Amazon path transformation too where the destination overlaps. These are deliberate compatibility losses, visible in the receipt.

## Shared effective policy

`compileRemoveParams(text, {priority: 9, allowReduced: false})` returns:

```javascript
{
  data,       // schema 1, normalized groups and exception/quarantine receipts
  rules,      // complete replacement parameter DNR ruleset
  stats,      // importedRules, supported/dropped/coarsened counts and reasons
  coverage: {
    available, reduced, disabled, quarantined, nativeDeferredNames,
    supportedSyntax: "literal-query-names-v1",
    mainFrameGetOnly: true,
    unsafe
  }
}
```

Chrome content scripts and the worker load the same generated `param-data.js`, followed by `param-policy.js` and `params.js`. The build hashes the generated policy independently and includes it in the build identity. It replaces the old production query-rule generation completely. Loading both rulesets would let an older global rule defeat a newer exception.

The source `param-data.js` file is an explicit development placeholder. An absent policy or that placeholder uses the legacy data. A malformed **generated** policy disables cleaning; it never falls back to legacy rules that lack the imported exceptions. The runtime independently enforces fixed excluded hosts, protected names and sensitive-URL brakes, even if generated names contain a protected entry.

The Firefox companion remains on its existing manual/content support path and does not receive the imported Chrome query policy.

## Redirect correctness and fixed brakes

Each query transform has a positive, query-aware proof that at least one key it removes is present. A tracking name inside a pathname, fragment, nested URL value or longer parameter name is insufficient. Valueless parameters and duplicate occurrences are handled. This addresses the [documented no-op removeparam starvation problem](https://github.com/uBlockOrigin/uBOL-home/discussions/575), where an ineffective matching redirect can prevent a useful transform from running.

Overlapping host predicates are partitioned into destination regions. Within one policy family, each region's transform removes all of that family's permitted keys. Regex chunks share the full action, so matching another chunk does not require another identical redirect. Global, conditional and site-scoped families can still require successive redirects. Every modeled query transform must make progress; this is not a claim that arbitrary upstream redirects or repeated path components have an unlimited browser redirect budget.

All parameter redirects and fixed preservation rules use priority 9 and only `main_frame` plus GET. Header sanitation uses the higher cleaning priority. Source exception handling does not release network requests, cross-site frames, tracker requests, or isolation rules. Fixed code-owned preservation rules can win over a same-priority redirect, so their scope is intentionally limited to navigation and excluded from hosts where the cleaner never runs.

Preservation includes:

- The existing `KEPT` names, excluded sign-in/payment/admin hosts, and unsubscribe/preferences paths.
- Authentication, OAuth, sign-in, callback, checkout and payment paths.
- Recognized signature and authentication query keys, including AWS/Google signatures, SAML and OAuth exchange keys. The entire address is preserved because a signature can cover otherwise removable fields.
- Addresses carrying URL credentials.
- For declarative rules, any percent-encoded query key. Literal `queryTransform.removeParams` behavior for encoded keys needs native qualification. The JavaScript cleaner can decode the key, preserve recognized sensitive fields and remove a safely identified tracking key.
- For declarative rules, any bare or empty query component. Chromium reconstructs retained components as `key=value`; preserving the whole navigation prevents that reconstruction from changing unrelated bytes. The JavaScript cleaner can remove tracking fields while retaining the raw remaining components.

Chromium [escapes removal names when indexing a transform](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/browser/api/declarative_net_request/flat_ruleset_indexer.cc). Its [query escaping character set](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/base/strings/escape.cc) leaves alphanumerics and `!'()*-._~` literal. The native compiler excludes names outside that set from both removal actions and presence triggers. In the current policy, `__cft__[0]` and `__xts__[0]` remain supported by JavaScript cleaning but are listed in `coverage.nativeDeferredNames`. It also defers names beyond its conservative native length/program bounds. An unescaped bracket name must never trigger a transform that cannot remove it. The query reconstruction behavior is visible in Chromium's [`GetModifiedQuery`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/browser/api/declarative_net_request/ruleset_matcher_base.cc).

These are compatibility heuristics, not a complete recognizer for signed or authenticated URLs. Sites use arbitrary path and parameter names. The per-site cleaning switch remains the recovery control when a needed address changes. Unchanged addresses are returned verbatim; when cleaning changes a query, other query values retain their raw spelling, order, empty components, duplicates and fragment.

## Validation and remaining qualification

Run the deterministic compiler/runtime suite with:

```sh
node --test tests/browser/removeparam-compiler.test.cjs tests/browser/parameter-build.test.cjs tests/browser/filters.test.cjs
```

The tests exercise legacy/import overlap, named/all-name exceptions, entity-label boundaries, nested private PSL sites, negative destination predicates, active/inactive conditionals, badfilter identities, unsupported syntax, malformed generated data, signed URLs, encoded keys, raw query preservation and redirect progress in either rule-selection order. Build tests check matching worker/content policy bytes and hashes, reduced-coverage receipts, and preservation of previous output on a rejected complete build.

A separate source-snapshot probe compared the runtime's effective native-supported names against modeled DNR predicates across 2,294 cases covering every imported destination inclusion and exclusion boundary, subdomains and the documented entity-prefix cases. It found no mismatch. Deferred names were counted separately. This is a deterministic policy check, not a live-site or native browser measurement.

The compiler bounds source size and rows, line lengths, condition nesting, normalized data cells, destination boundaries, regex source length and emitted rule count. Entity exclusions use a finite regular-language complement rather than lookaround. **RE2-compatible syntax and a short source string do not prove Chrome's compiled-regex memory limit.** The final snapshot's 801 parameter patterns passed a separate audit using the official `google-re2==1.1.20251105` wrapper with Latin-1 encoding, the rule's case-sensitivity, capture mode appropriate to substitutions and `max_mem=2048`. No dependency was added to the extension or normal Python runtime. This catches the observed compiled-size failures, but native `isRegexSupported`, ruleset acceptance and actual navigation behavior remain necessary qualification. This environment does not permit launching Chrome; no native result is claimed.

Native qualification should cover first/last/valueless/duplicate query keys, both transform ordering possibilities, root and nested Amazon path segments, encoded keys, case and trailing-dot hosts, signed URLs, entity exclusions, `testMatchOutcome`, main-frame POST versus GET, sub-frame non-application, and coexistence with higher-priority denial/header rules. See [Chrome's declarativeNetRequest reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) for rule evaluation, query transforms and regex limits.
