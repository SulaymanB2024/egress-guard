# SDK source drift and bounded Prebid prefix coverage

This pass adds a seven-family source inventory to the existing SDK drift comparator and extends the selected Prebid identity-sync signature to **one plain path prefix**. It does not execute vendor SDKs or qualify native browser enforcement.

The authoritative inventory is [tests/fixtures/sdk_drift/manifest.json](../tests/fixtures/sdk_drift/manifest.json). Its [source verification receipt](benchmarks/sdk-source-review-0.12.json) checks **11 acquired files across four families**. GA4, GTM, and Meta Pixel bundles remain unacquired. Fingerprint's acquired artifact is integration documentation, not its proprietary agent. The [Prebid qualification receipt](benchmarks/prebid-prefix-0.12.json) separately records standalone RE2 compilation and authored request-shape checks.

## Evidence inventory

All 11 artifacts were fetched again from their immutable source URLs on **22 November 2026 UTC**. Their returned bytes matched the reviewed copies. Each manifest entry records the exact URL, acquisition date, repository, 40-character revision, relative path, byte length, SHA-256 and Git blob SHA-1. Source versions are pinned observations; this is not a claim that future releases retain the same behavior.

| Requested family | Acquired evidence | What is established | SDK execution |
|---|---|---|---|
| GA4 | Primary documentation; no SDK bundle | Server-container delivery can use image, Fetch, XHR and an iframe service worker | NOT COVERED |
| GTM | Primary documentation; no configured container or SDK bundle | Documented loader and data-layer protocols | NOT COVERED |
| Meta Pixel | Primary image-protocol documentation; no SDK bundle | Selected `/tr` image wire format; two newer claims remain unverified below | NOT COVERED |
| Matomo | `matomo-org/matomo@4cc2fa000b20f3c11eb0138fa782de89a3e5485e`, one tracker source file | Query construction, image flag, custom endpoint and transport fallback paths | NOT COVERED |
| PostHog | `PostHog/posthog-js@7babace5aa013d34a32e4595fec255a019cd8693`, four source files | Bundled recorder startup, compressed transport and request rewrite paths | NOT COVERED |
| Prebid | `prebid/prebid-server@0f7916bfd975b82a185e9677d8196d94b2ea4dcc`, five server files | Callback URL construction, native route and identity deletion semantics | NOT COVERED; these are server files, not Prebid.js |
| Fingerprint Pro | `fingerprintjs/cloudflare-worker-proxy@0d41a591f82b1f132c029a9a3e9d2ac8dfd9c524`, integration changelog | Maintained v3 compatibility and different v4 configuration | NOT COVERED; the agent itself was not acquired |

Google's [transport guide](https://developers.google.com/tag-platform/tag-manager/server-side/send-data) and [data-layer guide](https://developers.google.com/tag-platform/tag-manager/datalayer), Meta's [image-protocol documentation](https://developers.facebook.com/documentation/meta-pixel/advanced), and every acquired source path are linked in the manifest. Selected source files are not complete deployed bundles. No missing bundle is assigned a fabricated digest.

## Lifecycle inventory

The table records the phase evidence actually reviewed. **Source** means a relevant code path was inspected in a pinned file. **Docs** means a published interface was read. Neither means the phase ran. Request-shape tests are authored models of selected URLs, methods and resource types; they do not reproduce SDK initialization, timers, consent, storage, retry queues or page termination.

| Family | Bootstrap | Event | Retry / fallback | Unload |
|---|---|---|---|---|
| GA4 | Docs: Google tag/server-container configuration | Docs: measurement delivery and transport families | Unavailable in acquired evidence | Unavailable in acquired evidence |
| GTM | Docs: loader and custom data-layer name | Docs: queued data-layer events | Unavailable in acquired evidence | Unavailable in acquired evidence |
| Meta Pixel | Docs: image installation, not the full JavaScript SDK | Docs: four selected standard-event image examples | Unavailable in acquired evidence | Unavailable in acquired evidence |
| Matomo | Source: tracker configuration queue | Source: request fields and image/POST selection | Source: XHR failure can fall back to image or beacon | Source: unloading path selects beacon, with its documented queueing uncertainty |
| PostHog | Source: queued calls and recorder startup, including bundled recorder | Source: capture requests and compression selection | Source: retry-queue dispatch and transport fallbacks; queue timing implementation not acquired | Source: pagehide/unload registration, queue unload calls and beacon transport |
| Prebid | No browser SDK acquired | Server source: identity-sync handler only | No browser SDK acquired | No browser SDK acquired |
| Fingerprint Pro | Integration docs: v3/v4 configuration | Agent implementation unavailable | Agent implementation unavailable | Agent implementation unavailable |

Matomo's relevant transport paths are in [js/piwik.js](https://github.com/matomo-org/matomo/blob/4cc2fa000b20f3c11eb0138fa782de89a3e5485e/js/piwik.js), including the image function and XHR fallback. PostHog's entry points are in [posthog-core.ts](https://github.com/PostHog/posthog-js/blob/7babace5aa013d34a32e4595fec255a019cd8693/packages/browser/src/posthog-core.ts) and [request.ts](https://github.com/PostHog/posthog-js/blob/7babace5aa013d34a32e4595fec255a019cd8693/packages/browser/src/request.ts). The manifest pins the complete selected files, while the review makes claims only about the paths identified here.

No vendor lifecycle replay was run for any of the seven families. The comparator now accepts the explicit `simulated-lifecycle` execution label so future authored lifecycle models cannot be mislabeled as native receipts. Even with all other evidence booleans set, that label returns **NOT COVERED** for native SDK delivery. Unit tests exercise that classification; they do not create simulated vendor traffic and claim it was received by a collector.

## Claims checked against primary material

**Meta on-device conversion default.** The proposed 12 November 2026 default rollout is not confirmed by accessible primary text in this review. Meta's [about article](https://www.facebook.com/business/help/4237575203200036) and [configuration article](https://www.facebook.com/business/help/2192875204996675) returned sign-in pages. The manifest marks the claim `unverified-primary`. No rollout date, eligibility condition, payload signature or local processing behavior is inferred from that inaccessible material.

**GA4 to Meta sharing.** Meta's [integration article](https://www.facebook.com/business/help/483077987527740) also returned a sign-in/temporary-block page. Google's accessible [Meta Links documentation](https://support.google.com/analytics/answer/16536051?hl=en) describes importing Meta campaign and cost data **into Google Analytics**. It does not establish the opposite direction or automatic sharing of all GA4 traffic. The exact GA4-to-Meta integration scope remains unverified here. Once an allowed server has received data, a device firewall cannot control a later server-to-server transfer.

**PostHog bundled and compressed replay.** The pinned [recorder startup](https://github.com/PostHog/posthog-js/blob/7babace5aa013d34a32e4595fec255a019cd8693/packages/browser/src/extensions/replay/session-recording.ts) can skip the separate recorder fetch when both required recorder components already exist. The request transport supports gzip and Base64 bodies; gzip can omit the `compression` query marker. The [router](https://github.com/PostHog/posthog-js/blob/7babace5aa013d34a32e4595fec255a019cd8693/packages/browser/src/utils/request-router.ts) also applies a configured request rewrite. These paths explain why a renamed same-origin collector may not expose a reliable URL signature. This release does not invent a broad `/event` block or claim to decode opaque bodies.

## Prebid: one public prefix, unchanged identity safeguards

The pinned [configuration](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/config/config.go) defaults the user-sync callback to a configurable external URL followed by `/setuid`; the [template builder](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/usersync/syncer.go) substitutes that URL literally. Its [native router](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/router/router.go) still registers `/setuid`. A prefixed public callback therefore needs a deployment rewrite. This is not a claim that Prebid has a native route-prefix switch.

The selected endpoint grammar is now:

```text
/(?:[A-Za-z0-9_-]+/)?setuid
```

It covers `/setuid`, `/pbs/setuid` and `/prebid/setuid`. The full request must still satisfy the existing singleton `bidder`/`uid` query envelope, exact approved optional fields, GET method, and image or subframe resource type. Priorities, actions, the six Prebid rules and the 29-rule catalog total are unchanged. No allow rule or new permission is added.

The handler's [empty-UID deletion](https://github.com/prebid/prebid-server/blob/0f7916bfd975b82a185e9677d8196d94b2ea4dcc/endpoints/setuid.go) remains protected by declining missing or empty identity values, duplicate identity keys, encoded identity keys and unknown privacy/control fields. Deeper prefixes, dotted or encoded prefix segments, empty segments, endpoint suffixes, top-level navigations, POST and XHR remain outside this signature. Recognition is still a selected wire-format policy; it does not prove every matching endpoint is a genuine Prebid deployment or that every privacy parameter is accepted by a server.

All **29** emitted regexes compiled with `google-re2==1.1.20251105`, Latin-1 encoding, actual case sensitivity, `never_capture=true` and `max_mem=2048`. The six changed programs have sizes **89, 89, 91, 89, 89, 91**. Both the two-prefix and four-prefix counted alternatives failed that memory gate for all six patterns and were not emitted. The receipt preserves those failed probes. An unrestricted prefix loop was not substituted to expand the accepted grammar.

The separate 16-case development check contains four tracking shapes, one explicit deep-prefix residual and 11 functional controls. Against the pinned baseline module, three prefixed tracking shapes become recognized and no functional control becomes blocked. These cases were authored during development. They are not a frozen holdout, captured SDK traffic, or a full-list comparison, and establish no general privacy percentage. The older frozen protocol benchmark is unchanged.

## Running the existing comparator's source mode

Prepare reviewed source checkouts under a local directory with `matomo/`, `posthog/`, `prebid/` and `fingerprint-pro/` children matching `source_directory` in the manifest. The CLI never downloads or executes these files.

```sh
node scripts/compare-sdk-wire-drift.mjs \
  --source-manifest tests/fixtures/sdk_drift/manifest.json \
  --source-root /path/to/reviewed-source-checkouts \
  --out /path/to/new-source-receipt.json
```

The mode requires the seven-family denominator, matching immutable source URLs, explicit acquisition dates and valid evidence references. Reads are bounded to 2 MiB per file and 8 MiB total, with at most 32 declared files. Linked and non-regular source files are rejected. The tool checks both byte digests, records the manifest and verifier hashes, and creates output exclusively. It exits 2 with a receipt if acquired sources are missing, unreadable or changed; invalid input or output paths exit 1.

`SOURCE PINS VERIFIED` means all **declared acquired files** match. It does not convert the three unacquired SDKs into successes, authenticate the publisher, prove Git history, re-evaluate human source interpretation, or establish runtime protection. The separate per-family statuses and fixed native/SDK/receiver **NOT COVERED** fields retain those limits.

The original `--before`, `--after`, `--before-bundle`, `--after-bundle` receiver-comparison mode remains available. Source mode cannot be mixed with it. Native evidence, source-only inputs and authored lifecycle models remain distinct execution classes; only independently supplied qualifying native receiver receipts can reach that mode's observed-escape result. The comparator itself does not launch a browser or independently attest the caller's measurements.

## Validation

The focused source-review, wire-comparator and protocol suites pass **39 tests**. They cover byte mismatch, missing inputs, unsafe source paths, exclusive output, evidence-tier errors, seven-family completeness, simulated/native separation, and the identity/control boundaries above. The real Node CLI and standalone RE2 engine ran. Vendor SDK execution, native Chrome installation/interception, live collector receipt and server-to-server visibility remain **NOT COVERED**.
