# Publisher-hosted tracking challenge v1

This benchmark was frozen on 21 November 2026 (America/Chicago; 22 November UTC in the corpus metadata), before the new protocol catalog was implemented. The reference is the complete production Chrome artifact for Egress Guard 0.9.0 at commit `abe2b87b2bb8de298992045c8bb05d4f63554adc`. It evaluates synthetic requests against compiled rules. It does not launch Chrome, contact a collector, execute an SDK, or measure actual web traffic.

The final 0.10 artifact reduces the predeclared equal-family escaped-request metric by **31.1475%**, with no new functional false positives and no tracking-case regressions in this corpus. The raw number of escapes falls from **21 to 9**. These are results on an exposed development benchmark of request shapes, not a percentage of tracking stopped across the internet. The initial candidate missed the target; its exact receipt is retained below.

## Frozen inputs

- Fixture file: `tests/browser/fixtures/protocols-v1.json`.
- SHA-256: `074d616ba05c929adb76007048b644dd1cc9ebf3fb5ac39ecd9f588061852423`.
- 34 tracking cases and 34 functional controls, across nine families.
- Baseline results and source-input hashes: `docs/benchmarks/protocols-v1-baseline-0.9.json`.
- Baseline rules/manifest/model-input digest: `74b70a5327c4a63e3b0934482b453e2a1fd51189628e1a096f0be8df4f20b0c0`.
- Baseline upstream-source digest: `b2f4a7ff538b24b9bd757c286776bcefda5e55654a4c9f2b5b6292e673960ded`.

The fixture itself records the primary source URLs and pinned SDK revisions. Query reordering, interposed fields, publisher-owned hosts, and renamed routes are labeled controlled transformations. Opaque tokens and bodies are synthetic examples of documented transport mechanisms, not captured production requests. Meta's documented IMG wire format is tested as GET/image. Prebid cases are browser-originating requests; the corpus makes no claim about server-side bidding or advertisements stitched into video.

“Canonical” fixture labels identify a recognizable collector route already represented in the old rules, not a promise that a current SDK always uses that route. In particular, the pinned PostHog source initializes `/e/` and permits a configured endpoint; the `/i/v0/e/` fixture is a recognized/configured route. The second PostHog fixture captures the current body-only visibility limit on a neutral configured path.

All manifest-enabled static rules participate, including domain lists, CNAME names, EasyPrivacy, EasyList, existing handwritten filters, and surrogates. Standard mode and empty user rules/grants are fixed. This prevents a new signature from receiving credit for a request that the existing host lists or URL rules already block. The build's known parameter quarantine and unsupported upstream syntax remain part of the reference artifact; “complete artifact” does not mean complete interpretation of every filter language.

## Metric fixed before implementation

For each tracking mechanism, compute the fraction of its variants that escape. Average those mechanism fractions within each family, then average the nine family rates equally. The primary improvement is `(baseline escape rate − candidate escape rate) / baseline escape rate`. Raw request counts and raw relative reduction are reported separately. Repeating a successful permutation does not give that mechanism a larger weight.

An opaque/body-only case remains in the primary denominator for Google/Stape, Matomo, Fingerprint v4, PostHog, Amplitude, Segment, Clarity, and Prebid. Several have exact observable functional twins: URL, method, resource type, and frame context are identical; only their uninspected bodies differ. These cases make the URL-condition visibility boundary explicit. A general block on those neutral endpoints would count as a new functional false positive.

The corpus is visible to implementers and may guide subsequent source-backed improvements. It is a reproducible **development challenge**, not a held-out estimate of performance on unknown sites. Follow-up compiler controls and source checks can expand without entering the frozen score; those checks must not be described as additional independent benchmark observations.

The 30% target is met only if the **equal-family** escaped-request reduction reaches 30%, there are no newly blocked functional controls, and no previously prevented tracking fixture regresses. A higher raw percentage does not substitute for this primary metric. Neither percentage estimates prevalence, privacy gained on the whole web, or anonymity.

## Baseline

The 0.9 reference prevents 13 of the 34 tracking requests; 21 escape. Its equal-family/mechanism escape rate is **56.4815%**. Three of the 34 functional controls are already prevented: a Meta-looking URL inside a renderer parameter, a PostHog-looking URL inside another parameter, and `/openrtb2/auction/status`, which an existing broad upstream path filter matches. These remain visible in the report. The compatibility gate rejects new false positives rather than silently deleting the old ones from the corpus.

| Family | Tracking cases | Escaped in 0.9 | Equal-mechanism escape rate |
| --- | ---: | ---: | ---: |
| Google / Stape | 8 | 5 | 58.3333% |
| Meta | 4 | 2 | 33.3333% |
| Matomo | 6 | 4 | 66.6667% |
| Fingerprint | 4 | 3 | 83.3333% |
| PostHog | 2 | 1 | 50% |
| Amplitude | 2 | 1 | 50% |
| Segment | 2 | 1 | 50% |
| Clarity | 2 | 1 | 50% |
| Prebid | 4 | 3 | 66.6667% |

## First 0.10 candidate result

The intermediate artifact was evaluated on 21 November 2026 (America/Chicago; 22 November UTC). Its exact receipt is preserved in `docs/benchmarks/protocols-v1-stage1-0.10.json`, with artifact digest `eeb8d7f014355a86b7f58f520ea0dd9f22dafdc3a4e0fce390397a024a1ce6ee`. Later source-backed changes are evaluated separately; this result and the exposed development corpus remain unchanged.

Using the identical upstream snapshots and frozen cases, the first complete 0.10 candidate prevents **23 of 34** tracking requests. Escapes fall from **21 to 11**, a **47.6190% raw reduction**. The predeclared equal-family/mechanism escape rate falls from **56.4815% to 43.5185%**, a **22.9508% relative reduction** and a **12.9630 percentage-point** reduction. The **30% primary target is not met**.

No previously prevented tracking case regresses, and no new functional control is blocked. The Meta nested-URL overblock is fixed. The existing PostHog nested-URL and Prebid path-suffix overblocks remain because imported rules still match them; the latter comes from EasyList, not EasyPrivacy. Functional overblocks therefore fall from three to two of the 34 controls.

The 11 residual tracking cases at this intermediate stage were opaque Stape; Matomo without the optional visitor field and body-only Matomo; Fingerprint v4; renamed body-only PostHog, Amplitude, Segment and Clarity; Prebid cookie synchronization, UID synchronization and an opaque renamed auction. Header sanitation and native-proxy connection revocation are separate improvements and do not enter this request-blocking score.

## Final 0.10 result and source-validity erratum

The final artifact adds two further source-backed mechanisms: Matomo's GET/image request with `idsite`, `rec=1` and `send_image=1`, and a narrowly bounded Prebid identity-sync envelope. The latter declines missing or empty IDs, duplicate identity keys, encoded identity keys, unsupported keys, and ambiguous query layouts; its source review explicitly checked the server's deletion path. Both changes were tested after the frozen challenge was already visible. No fixtures or weights were added to obtain the final result.

| Measure | 0.9 baseline | First 0.10 candidate | Final 0.10 |
| --- | ---: | ---: | ---: |
| Prevented tracking shapes / 34 | 13 | 23 | 25 |
| Escaped tracking shapes / 34 | 21 | 11 | 9 |
| Equal-family/mechanism escape rate | 56.4815% | 43.5185% | 38.8889% |
| Relative reduction in primary escape metric | — | 22.9508% | 31.1475% |
| Relative reduction in raw escapes | — | 47.6190% | 57.1429% |
| Functional shapes prevented / 34 | 3 | 2 | 2 |
| New functional false positives | — | 0 | 0 |
| Previously prevented tracking cases that regress | — | 0 | 0 |

The final primary reduction is **17.5926 percentage points**, or **31.1475% relative to the baseline**. The nine remaining tracking cases are opaque Stape, body-only Matomo, Fingerprint v4, renamed body-only PostHog/Amplitude/Segment/Clarity, Prebid cookie synchronization and a renamed opaque auction. The original two imported-list overblocks also remain visible. These limits are not erased by the target being met.

The final receipt is `docs/benchmarks/protocols-v1-candidate-0.10.json`, for artifact digest `5565431dace562ca101702443ab5409605a02360975b754e04d9ec75c835725d`. All three evaluations use the same corpus digest and the same upstream-source digest. The build contains 955 static regex rules; matching behavior here is still modeled rather than qualified in native Chrome.

During the deeper Prebid source review, we found that the frozen UID fixture's `bidder=sample` was a symbolic placeholder, whereas the actual server validates bidder names against its known bidders. This matters: the original shape is not evidence that a real Prebid server would accept that synchronization. We retained the frozen bytes and recorded a separate correction to `bidder=pubmatic`, which appears in the [pinned server tests](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/endpoints/setuid_test.go#L35-L71); the [same revision's endpoint](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/endpoints/setuid.go#L321-L338) validates the bidder.

`docs/benchmarks/protocols-v1-errata.json` records that correction and its source pin. `docs/benchmarks/protocols-v1-errata-sensitivity.json` records a separate full-artifact replay: the source-corrected request still escapes 0.9 and is prevented by 0.10, and **both the primary and raw scores remain exactly unchanged**. The correction does not create any headline gain or alter the primary denominator. Other project and user identifiers are synthetic too; the benchmark establishes request-shape matching, not successful acceptance of real credentials or IDs by a collector.

## Reproduction

```sh
node scripts/benchmark-browser-protocols.mjs \
  --artifact /path/to/built/chrome \
  --baseline docs/benchmarks/protocols-v1-baseline-0.9.json \
  --out /path/to/protocol-comparison.json

node --test tests/browser/protocol-benchmark.test.cjs

node scripts/check-protocol-benchmark-errata.mjs \
  --baseline-artifact /path/to/0.9/chrome \
  --candidate-artifact /path/to/0.10/chrome \
  --out /path/to/source-validity-sensitivity.json
```

The script performs no fetch or build. Supply a reviewed artifact built from the same snapshots recorded in the baseline. A different corpus digest or source-input digest is an error. Result files include the decisive rule and condition for each fixture, the enabled rulesets and hashes, family/mechanism rates, raw counts, compatibility regressions, and whether the declared target was met.

## Model boundary and qualification

The evaluator implements the [Chrome DNR pre-request priority and condition contract](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) for the artifact's rule shapes: URL/domain/PSL party matching, resource types, request methods, top/initiator domains, and same-extension action precedence. A block or redirect to an extension-local surrogate counts as preventing the original collector request. Header changes, HTTP-to-HTTPS upgrades, external redirects, and response-header-stage decisions do not receive request-prevention credit. Bodies are never inspected.

Unrecognized condition or action forms fail the run. Frame-inherited `allowAllRequests`, redirects followed by subsequent requests, service-worker/cache behavior, cross-extension precedence, browser URL parsing outside the deliberately restricted ASCII HTTP(S) fixtures, and retries are not emulated. URL regular expressions use Node's engine on these fixtures; the release's separate real-RE2 audit verifies compilation budgets. Neither test establishes native Chrome acceptance or actual network interception. Native-browser qualification remains outstanding because the execution environment does not permit the required browser startup.

Future source families or attack mechanisms belong in a new version of this corpus or a separately labeled exploratory cohort. They must not alter this frozen denominator after seeing the result.
