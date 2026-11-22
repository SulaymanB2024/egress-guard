# Source-backed tracking protocols in 0.10

The browser build adds **29 static blocking rules for seven request signatures across five vendor families**. They recognize selected wire formats when a publisher changes the collector hostname, path, parameter order, or intervening query fields. Existing domain lists still participate. A request already blocked by those lists does not count as a new success.

The implementation is `browser/core/tracking-protocols.js`. It runs at build time, accepts no browsing data, and performs no IO. Its rules join the existing `fp-trackers` ruleset at the handwritten-filter priority. The existing category switch, Relaxed mode, explicit rules, and scoped repair precedence apply. No new network permission or allow rule is introduced. Existing replay rules remain independently enabled, so their coverage can overlap the new Fingerprint signature.

## Supported requests

Every required field below must be a distinct literal query key with the stated value. Field names and values are case-sensitive. The rule consumes the HTTP(S) URL up to its first query delimiter; a tracker-shaped URL inside another parameter, a fragment, or a path is not a second endpoint.

| Signature | Required evidence | Method and resource type | Rules |
| --- | --- | --- | ---: |
| GA4 collection | `v=2` and `tid=G-` followed by 4–16 uppercase letters/digits; any HTTP(S) path | GET/POST image, XHR/fetch, or ping | 2 |
| GTM loader | `id=GTM-` followed by 4–16 uppercase letters/digits; any HTTP(S) path | GET script | 1 |
| Meta Pixel | Exact `/tr` or `/tr/`, numeric `id` of at least five digits, and `ev` equal to PageView, ViewContent, AddToCart, or Purchase | GET/POST image, XHR/fetch, or ping | 2 |
| Matomo visitor query | Positive-integer `idsite`, `rec=1`, and a 16-character lowercase hexadecimal `_id`; any HTTP(S) path | GET/POST image, XHR/fetch, or ping | 6 |
| Matomo image query | Positive-integer `idsite`, `rec=1`, and `send_image=1`; any HTTP(S) path | GET image | 6 |
| Fingerprint Pro v3 loader | Alphanumeric `apiKey` of at least ten characters, `version=3`, and a numeric/dotted `loaderVersion`; any HTTP(S) path | GET script | 6 |
| Prebid identity synchronization | Exact `/setuid`, singleton `bidder` and `uid`, and the restricted query envelope below | GET image or subframe | 6 |

The first six signatures cover every order of their required fields, including unrelated preceding, intervening, and following fields. Their identity length and character restrictions are conservative policy choices; they are not universal vendor guarantees. Meta's documentation demonstrates image GETs. The catalog also rejects that same exact four-event URL signature if sent as XHR/ping GET or POST; it does not claim that the documentation demonstrates every such transport.

Matomo's two signatures cover different cases. The current JavaScript SDK builds `idsite`, `rec`, and a visitor ID; its image helper changes `send_image=0` to `send_image=1`. A valid image request can omit the optional visitor ID, so the second rule family uses the documented image transport markers. It is deliberately restricted to GET/image. Bare `idsite` plus `rec` is insufficient. The pinned SDK does not automatically add `apiv`, and the rules do not invent that requirement. [Matomo request builder and transport](https://github.com/matomo-org/matomo/blob/4cc2fa000b20f3c11eb0138fa782de89a3e5485e/js/piwik.js), [tracking API](https://developer.matomo.org/api-reference/tracking-api).

No request-body classifier is present. For example, a Matomo POST carrying those fields only in a form body remains unrecognized on a neutral route. The same applies to arbitrary renamed PostHog, Amplitude, Segment, or Clarity collectors. The protocol catalog never blocks a generic `/collect`, `/api/events`, `/v1/t`, `/upload`, or `/rpc` solely because that path is sometimes used for tracking.

## Prebid: preserve deletion before blocking new synchronization

Prebid's `/setuid` handler reads the first decoded `uid` value. If it is missing or empty, it removes that bidder's existing sync. A rule that skips an earlier empty `uid` and matches a later nonempty occurrence could block deletion. This signature therefore uses a different compiler path from ordinary marker recognition. [Pinned handler](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/endpoints/setuid.go), [endpoint contract](https://docs.prebid.org/prebid-server/endpoints/pbs-endpoint-setuid.html).

It requires exactly one literal `bidder` and exactly one literal `uid`, followed by the end of the complete query. The bidder key begins with a lowercase letter and then uses lowercase letters, digits, `_`, or `-`. The UID begins with an ASCII letter or digit and contains at least two characters using letters, digits, `_`, or `-`. This conservative token grammar leaves missing/empty values, single-character values including `0`, negative values including `-1`, and encoded values outside the new signature. The inspected server treats empty/absent UID as deletion; `0` is separately rejected for AudienceNetwork. It does not establish that every vendor treats `0` or `-1` as a deletion command. [Cookie sync implementation](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/usersync/cookie.go).

Only these optional query keys are supported: `gdpr`, `gdpr_consent`, `gpp`, `gpp_sid`, `account`, and `f`. They may form one contiguous group before, between, or after the two identity fields, in any order within that group. Their values can contain percent-encoded text; an encoded value does not create another query key. Both orders of the two identity fields are supported. Spreading optional fields into multiple groups is outside this deliberately limited subset.

Unknown keys, encoded keys, duplicate `bidder` or `uid` keys, bare fields, and empty query segments cause this signature to decline. This includes `uid=&bidder=pubmatic&uid=buyer12345`, `%75id=&bidder=pubmatic&uid=buyer12345`, and an ordinary `/setuid` request without `bidder`. It also declines requests carrying unknown privacy-control keys such as `optout` or `delete`. No broad allow rule is installed to achieve this behavior, and independent list rules can still match a request outside this signature.

The endpoint's documented responses support image and iframe synchronization. The new rule excludes main-frame navigation, XHR, and POST. It does not block all of `/cookie_sync`, `/setuid`, `/event`, or `/cache`, and it does not intercept a server-to-server auction or an advertisement already stitched into a media stream. [Prebid endpoint overview](https://docs.prebid.org/prebid-server/endpoints/pbs-endpoint-overview.html), [cookie-sync transport](https://docs.prebid.org/prebid-server/endpoints/pbs-endpoint-cookieSync.html).

## Compiler and browser limits

The pure API is:

```js
const {rules, stats, catalog} = EGTrackingProtocols.compile({firstId, priority});
```

The CommonJS export provides the same API. The catalog is deeply immutable and includes source URLs, revision pins, supported conditions, and limitations. Each call returns fresh rule objects. Invalid IDs, priorities, or allocation overflow fail before an output can be used. The compiler has a 32-rule local ceiling; the current catalog emits 29. The whole build separately enforces Chrome's aggregate static-regex limit.

All emitted actions are `block`. Every rule has explicit method/resource-type restrictions. The build adds the rules and emits the catalog, stats, and their artifact hashes. It does not run the compiler in response to page content or let a model modify its authority.

RE2 does not support the lookarounds that would make an informal “contains all fields” regex easy. Large alternatives also exceed Chrome's compiled-memory budget even when the source text looks short. The compiler therefore emits separate required-field orders. Prebid's grouped optional fields similarly keep each program small while preserving singleton identity semantics.

All 29 generated regexes passed `google-re2==1.1.20251105` with Latin-1 encoding, the actual case-sensitive condition, `never_capture=true`, and `max_mem=2048`. Their reported program sizes are 59–91. This verifies compilation under selected Chrome-equivalent RE2 options. It does **not** establish native Chrome installation, request interception, cross-extension precedence, or behavior on an installed browser. The release's full-artifact audit remains a separate gate.

The ordinary signatures are presence recognizers: if a required field has a matching occurrence, another occurrence does not negate it. They do not claim to reproduce every server's duplicate-field semantics. Prebid requires singleton identity fields because deletion makes that ambiguity material. Percent-encoded keys, percent-encoded identity values, different protocols, and arbitrary field renaming remain unsupported rather than being silently decoded with a different parser from Chrome.

## Evidence and measurement

The independent evaluator froze `tests/browser/fixtures/protocols-v1.json` before the catalog implementation. Its SHA-256 is `074d616ba05c929adb76007048b644dd1cc9ebf3fb5ac39ecd9f588061852423`. It contains 34 tracking cases and 34 functional controls across nine families, including body-only and encoded residuals. It uses the complete compiled 0.9 artifact and identical upstream snapshots, rather than comparing only this catalog with the old handwritten rules.

The primary score averages variants within mechanisms, mechanisms within families, and the nine families equally. Its target is a 30% relative reduction in escaped requests, with no tracking regressions and no newly blocked functional controls. Raw request counts are a secondary measure. The corpus is an exposed **development challenge**, not a held-out estimate of performance on unknown sites. Additional compiler tests do not enter its frozen denominator. [Method, immutable receipts, and results](benchmarks/protocols-v1.md).

The first 17-rule candidate reduced raw escapes from 21 to 11 (47.6190%) but improved the primary equal-family metric by only 22.9508%, below the target. That result is retained as stage-one evidence. The later Matomo image and Prebid synchronization signatures address source-backed cases already in the frozen corpus, with their own compatibility tests. The final full-artifact result prevents **25 of 34** tracking cases: escapes fall from **21 to 9**, or **57.1429%** by raw count. The primary equal-family escape rate falls from **56.4815% to 38.8889%**, a **31.1475% relative reduction**, meeting the predefined 30% development-challenge target. There are no tracking regressions and no newly blocked functional controls. Two pre-existing imported-filter overblocks remain. Neither header sanitation nor native-proxy connection revocation is added to this request-blocking score. [Final receipt](benchmarks/protocols-v1-candidate-0.10.json).

A source-concordance error was found after freezing: the synthetic Prebid fixture used `bidder=sample`, which the pinned server would reject. The original corpus and results were preserved. A separate replay substitutes the source-valid `pubmatic` bidder in **both** baseline and candidate arms; the request decisions and all scores are identical. This correction and its scope are recorded in the [errata sensitivity receipt](benchmarks/protocols-v1-errata-sensitivity.json). These are source-derived synthetic request shapes, not captured or server-accepted production traffic.

Focused regression command:

```sh
node --test tests/browser/tracking-protocols.test.cjs
```

The 19 focused tests cover all required-field orders, intervening fields, type/method bounds, ID boundaries, nested URLs, fragments, encoded keys, observable body-only twins, allocation limits, immutable source data, and loading the same module without browser APIs. Prebid tests include duplicate and encoded identity-key insertions at every position, first-empty deletion, unsupported optional-field layouts, and privacy-control query keys. They run offline. No production SDK or collector is exercised.

## Source revisions and remaining gaps

The catalog derives request shapes from the following primary sources. The repository does not bundle or execute these SDKs.

| Family | Source used |
| --- | --- |
| Google | [Server-container delivery](https://developers.google.com/tag-platform/tag-manager/server-side/send-data), [debugging example](https://developers.google.com/tag-platform/learn/sst-fundamentals/6-testing) and its [request screenshot](https://developers.google.com/static/tag-platform/learn/images/incoming-request.png), [GTM data-layer loader](https://developers.google.com/tag-platform/tag-manager/datalayer) |
| Meta | [Pixel base code](https://developers.facebook.com/documentation/meta-pixel/get-started) and [documented image requests](https://developers.facebook.com/documentation/meta-pixel/advanced) |
| Matomo | `matomo-org/matomo@4cc2fa000b20f3c11eb0138fa782de89a3e5485e`, `js/piwik.js` |
| Fingerprint | [Maintained Cloudflare integration changelog](https://github.com/fingerprintjs/cloudflare-worker-proxy/blob/0d41a591f82b1f132c029a9a3e9d2ac8dfd9c524/CHANGELOG.md), which explicitly retains v3 compatibility while introducing a different v4 protocol |
| Prebid | `prebid/prebid-server@0f7916bfd975b82a185e9677d8196d94b2ea4dcc`, `endpoints/setuid.go` and `usersync/cookie.go` |

The source review also inspected PostHog `7babace5aa013d34a32e4595fec255a019cd8693`, Amplitude `d656d16bea9aba05a7266f76b12fc6c15ca052d7`, Segment `d549330ad9bda3a6765c36057eb1b2f4c72f640c`, and Clarity `5a596f36893d06fba4c4dfb9b4d05ffd04673162`. Their configurable transports establish important gaps rather than additional universal URL rules. Current PostHog initializes `/e/`, permits a configured endpoint, and places capture metadata in a body; `/i/v0/e/` is a recognizable/configured route, not a guaranteed current default. Arbitrary proxy rewriting can remove even that clue. [PostHog request builder](https://github.com/PostHog/posthog-js/blob/7babace5aa013d34a32e4595fec255a019cd8693/packages/browser/src/request.ts), [path configuration](https://posthog.com/docs/libraries/js/config).

Blocking these signatures can affect functionality: a tag manager can carry essential code, and fingerprinting can be part of fraud prevention. The precise existing site controls remain relevant. Conversely, a missed signature is not evidence that the request is harmless. A site can collect through a body-only API, use a bundled implementation, encode a protocol, or forward information from its own server. These rules improve selected blocking behavior; they do not establish anonymity or invisibility.
