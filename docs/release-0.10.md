# 0.10: tracking protocols and revocable tunnels

**Status: alpha source revision.** This revision adds request-shape recognition for selected first-party tracking protocols, continuing policy checks on established opaque proxy tunnels, and removal of three known analytics identity headers in Isolated mode. It preserves origin TLS and adds no cloud service, extension network permission or runtime dependency.

The fixed development benchmark records a **31.1475% relative reduction in weighted escaped tracking-request shapes** against 0.9, exceeding its declared 30% target. This is a result on a synthetic, source-backed challenge corpus. It is not an estimate of tracking prevented across the internet, a native Chrome traffic measurement, or a percentage improvement in anonymity.

## Measured browser result

The corpus contains 34 tracking shapes and 34 functional controls across nine families. It was frozen before the initial protocol compiler. Both versions use the same verified community-list snapshots and their complete enabled static rules, including exceptions and surrogates. Mechanisms are averaged within families; the nine families then receive equal weight. The metric does not give additional weight to a family simply because it has more query permutations.

| Measure | Complete 0.9 reference | Final 0.10 candidate |
| --- | ---: | ---: |
| Tracking shapes prevented | 13 / 34 | 25 / 34 |
| Tracking shapes escaping | 21 / 34 | 9 / 34 |
| Equal-family/mechanism escape rate | 56.4815% | 38.8889% |
| Weighted escape reduction relative to baseline | — | **31.1475%** |
| Raw escaped-case reduction relative to baseline | — | 57.1429% |
| Functional controls prevented | 3 / 34 | 2 / 34 |
| Newly prevented functional controls | — | 0 |
| Previously prevented tracking cases that regress | — | 0 |

The first implementation reached 22.9508% on the primary metric. Its [intermediate result](benchmarks/protocols-v1-stage1-0.10.json) is retained. A source-backed Matomo image-transport signature and a narrowly qualified Prebid identity-sync signature then closed two further cases. The corpus, weights and opaque residuals were not changed. Developers could inspect the corpus throughout; this is an exposed development benchmark, not a held-out estimate of generalization.

Source review also found that one frozen Prebid fixture used the symbolic bidder `sample`, whereas the pinned server validates bidder names. The [erratum](benchmarks/protocols-v1-errata.json) records that issue without rewriting the corpus. A [separate sensitivity replay](benchmarks/protocols-v1-errata-sensitivity.json) substitutes the source-tested `pubmatic` bidder in both versions: decisions and both scores remain identical. All IDs remain synthetic; no request was sent to an advertising service and no server-acceptance claim is made.

The two remaining functional overblocks come from existing imported filters: an EasyPrivacy-derived PostHog path pattern also matches a nested query value, and an EasyList auction pattern matches `/openrtb2/auction/status`. This revision adds no broad allow rule above those filters. The legacy handwritten Meta nested-query overblock is fixed. The handwritten PostHog rule is also path-anchored, but the independent upstream match remains visible.

Evidence: [method and baseline](benchmarks/protocols-v1.md), [final machine-readable comparison](benchmarks/protocols-v1-candidate-0.10.json), [qualification record](validation-0.10.json).

## Protocol-aware blocking

Seven source-backed signatures compile into 29 native DNR regex rules. They are packaged in the existing `fp-trackers` category at priority 6. User repairs, manual denies, threat rules and Isolated-mode precedence retain their existing ordering. The category is labeled **First-party tracking request** because it includes collection and identity synchronization as well as script loaders.

| Supported shape | New coverage and deliberate limits |
| --- | --- |
| GA4 browser query | Literal `v=2` plus a bounded `G-` measurement ID on a publisher-controlled path, in either order with unrelated fields between them. GET/POST image, XHR and ping types. Encoded or body-only fields remain outside this signature. |
| GTM loader | Literal `id=GTM-…` on GET script loads, including extensionless routes and reordered parameters. A container may also load functional code; explicit scoped repairs remain available. |
| Meta pixel | Exact `/tr` or `/tr/`, a numeric pixel ID and one of four documented standard events, in either order. Existing hand/list coverage remains separate for other events. |
| Matomo visitor query | All of `idsite`, `rec=1` and the SDK's 16-hex `_id`, in all six orders. Generic `idsite` and `rec` alone are insufficient. |
| Matomo image transport | GET/image with all of `idsite`, `rec=1` and `send_image=1`; it covers the documented image form when the visitor ID is absent. |
| Fingerprint Pro v3 loader | Literal public-key, version and loader-version fields in every order. This does not claim v4 coverage or prevention of all fingerprinting. |
| Prebid identity synchronization | Exact GET `/setuid`, image/frame resource type, singleton literal bidder and UID fields, a restricted nonempty token grammar and a documented optional-field envelope. Deletion and ambiguous query forms do not match this new signature. |

Prebid required a different query treatment. Its server uses the first decoded UID field; missing or empty UID removes an existing bidder mapping. A loose regex could match a later nonempty duplicate and accidentally block that removal. The new signature rejects duplicate or percent-encoded identity keys, unknown keys and empty segments. Approved optional keys must occupy one contiguous group before, between or after the identity fields. This is a conservative supported subset, not a universal parser for every deployment. No network allow rule is introduced to preserve deletion requests.

The package contains a catalog with primary-source references, SDK commit pins and explicit limits. Its bytes and compiler source enter the extension build identity. No upstream SDK code is downloaded or executed by the extension. [Detailed catalog](tracking-protocols-0.10.md), [research and design decisions](adversarial-tracking-0.10.md).

## Established proxy connections can lose permission

Previously, an admitted CONNECT stream passed to an unchecked opaque relay. Updating a hostname/IP rule or letting a grant expire did not stop that established connection.

The new `PolicyRelay` evaluates each emitted forwarding command in both directions using one current policy generation. It checks the original CONNECT authority, the initially visible TLS name, policy availability, live expiry and current transport restrictions. With the experimental address guard selected, it also checks the actual connected numeric peer. Checking emitted commands covers bytes queued while an upstream connection was pending.

A failed decision discards pending relay events and closes both sides; a later relaxation cannot revive the revoked stream. Ordinary permitted half-close behavior stays with the pinned transport implementation. The relay performs no new DNS resolution, decrypts no TLS data and retains no TCP message history.

A real local-TLS comparison ran the unchanged 0.9 source and this implementation under mitmproxy 12.3.1. The observer counted every decrypted byte received by the controlled origin, including partial markers:

| Change after the stream was established | 0.9 post-change bytes at origin | 0.10 post-change bytes at origin |
| --- | ---: | ---: |
| Authority receives a manual deny | 13 | 0 |
| Exact-host tracker grant expires without a revision change | 12 | 0 |
| Connected IP becomes blocked beneath a safety hostname | 11 | 0 |

Both arms delivered 24 allowed control markers over the same connection and verified the original origin certificate. Eight new real-proxy tests also cover independent SNI denial, threat updates, pause expiry, hardened-profile changes and server-originated forwarding. [Measured comparison receipt](benchmarks/tunnel-revocation-0.10.json), [boundary, timing limits and reusable comparison](core-0.10.md).

Revocation acts at the next forwarding boundary. It cannot recall bytes already handed to transport buffers, undo a previously admitted connection attempt, reveal later encrypted authorities or close an idle connection through a separate expiry timer. It does not add ongoing inspection to an already streaming ordinary plaintext HTTP body. Traffic must actually use the proxy.

## Identity headers on allowed application requests

The pinned PostHog browser source attaches visitor, session and window identifiers to configured ordinary fetch/XHR calls. These can survive blocking a dedicated analytics endpoint.

Isolated mode now removes `X-POSTHOG-DISTINCT-ID`, `X-POSTHOG-SESSION-ID` and `X-POSTHOG-WINDOW-ID`, alongside its existing cookie, authorization and referrer removal. These operations remain above ordinary grants and cover the existing site-resource and destination-navigation scopes. The applied receipt names the fields actually compiled into the mode.

This is opt-in through the existing Isolated mode. Other modes retain their prior header behavior. Unknown custom headers, generic trace headers, body identifiers, local storage, public IP and account identity remain outside this narrow control. Source and controller tests passed; origin-side native Chrome qualification is still outstanding.

## Rule capacity and build evidence

The first candidate consumed 999 of Chrome's 1,000 static regex slots. The upstream compiler had expanded four flat literal unions into one rule per literal. It now groups at most four alternatives per rule, preserving the same Boolean union and every non-pattern condition. Quantified/nested splits, partial branch sets and omission of protecting exceptions remain prohibited. This reclaimed 56 slots without dropping a source alternative or granting network access, leaving room for the additional protocol defenses.

The final artifact contains **14,086 static rules, 955 regex rules and 17 rulesets**. Every one of the 955 regexes passed actual `google-re2` compilation using the Chrome-aligned Latin-1, capture and 2 KiB memory settings. The remaining count headroom is 45. Native Chrome rule acceptance remains a separate gate.

The same verified 0.9 feed snapshots are used intentionally for the comparison. The existing `analytics_trace_id` parameter quarantine remains preserved and visible; unsupported filter syntax is still counted. CNAME publication age remains separately reported. The benchmark does not reclassify a reduced coverage receipt as complete.

## Validation and activation

The complete source suites passed: **325 Python tests** and **324 Node tests**, with no failures or skips. The Python run includes 29 real loopback proxy cases. Static Chrome fixture contracts, PSL regeneration and the full artifact RE2 audit passed. The qualification record separately records package verification and the exact artifact hashes.

Upgrade the Python installation through the existing reviewed installation procedure, then restart the proxy. The authenticated runtime transport receipt must contain `tunnel_policy: "per-forward"`. A running 0.9 process cannot satisfy 0.10 readiness merely because newer files are installed. Rebuild and reload the Chrome companion separately. Firefox still supplies its existing manual HTTP/S rules and does not gain the Chrome protocol signatures or Isolation feature set.

This work did not qualify macOS launchd, installed-browser native messaging/routing, native Chrome interception or local-model quality. The execution environment's prior browser startup was blocked; no attempt was made to bypass that restriction. Package and source validation do not establish an installed-device result. Follow the [target qualification matrix](releasing.md#additional-010-gates) before treating a specific device installation as qualified.

The nine remaining escaped request shapes are retained in the evidence. They include opaque or body-only first-party delivery and a cookie-sync endpoint. Several opaque residuals have exact functional twins in the corpus; blocking those observable shapes would block both. The remaining cookie-sync case also stays unrecognized. A local model cannot recover information absent from its observations; the existing local review mechanism remains advisory and does not acquire network-grant authority in this revision.
