# Reviewed feed updates and rollback in 0.11

Feed refresh now holds two specific kinds of suspicious change before they reach the active cache: removal of previously covered tracker anchors, and new coverage of selected broad infrastructure domains. The held candidate can be inspected, explicitly approved against the exact installed generation, or discarded. A previous verified generation is available for explicit rollback.

The motivating regression was small and concrete. With the same four-entry count, a synthetic update replaced `google-analytics.com` with `github.com`. Version 0.10 accepted it: Google Analytics became allowed, GitHub became blocked, and the policy still reported ready. The new guard retains the previous active bytes and queues that candidate for review. This demonstrates a publication boundary; it is not a measurement of real-world poisoning prevalence or a claim that a particular upstream source was compromised.

## What triggers review

The versioned catalog is in [`feed_review.py`](../src/egress_guard/feed_review.py). It contains 14 tracker anchors and 14 broad shared-service parents.

| Change | Result |
|---|---|
| A tracker or CNAME component previously covered a catalog tracker anchor and its candidate no longer covers it | Hold the complete candidate. |
| Any component newly covers a catalog infrastructure parent | Hold the complete candidate. |
| A particular tenant beneath a protected infrastructure parent becomes listed | Continue ordinary validation; the parent catalog does not allow that tenant. |
| A first installation lacks one or more tracker anchors | Continue ordinary validation; every feed is not required to contain every anchor. |
| A first installation would block a catalog infrastructure parent | Hold the candidate; the missing active feed remains missing. |
| An explicitly rolled-back feed receives another update | Hold it until a concrete candidate is approved. |
| A candidate fails existing hard validation | Refuse publication; approval cannot bypass the failure. |

Coverage follows each component's actual matching semantics. Ordinary domain feeds cover the listed domain and its descendants. CNAME feeds match exact hosts. Replacing a listed child with its listed parent can preserve tracker coverage in an ordinary domain feed while losing it in an exact-host CNAME feed.

These are finite tripwires. An attacker can change domains outside the catalog, retain the anchors while weakening other entries, or add disruptive names absent from the infrastructure catalog. No statistical detector, publisher-signature system or general semantic proof is introduced here. Existing threat, manual-block, exemption and temporary-grant precedence is unchanged. The catalog does not become a host allowlist or a new set of forced permanent blocks.

## Changed-root impact in review output

A quarantined candidate's `delta.semantic_coverage` now reports **newly covered roots** and **no-longer-covered roots**, alongside bounded samples. A root is counted only when the exact changed domain is not already covered by an unchanged parent under that feed's matching semantics. For example, adding `metrics.shop.test` beneath an already blocked `shop.test` is entry churn, but not new domain blocking. Replacing `metrics.shop.test` with `shop.test` broadens blocking and counts `shop.test` as one newly covered root. Exact-host CNAME entries are assessed differently: parent and child are separate hosts.

Root counts are **not** total affected descendant counts or a calculation of the application's actual final policy. Other feeds, threat priority, manual rules, grants and local exceptions can change the eventual decision. A newly covered parent could affect many descendant hosts that are not individually counted. The semantic field is inspection evidence only: it neither changes existing publication/quarantine criteria nor silently grants or blocks traffic.

## Inspect and approve exact artifacts

Inspection reads local files. It does not initialize application state, download a list, contact a domain, open a browser or change policy:

```sh
egress-guard feed-review
egress-guard feed-review hagezi-pro.plus
```

The result separates the installed cache, a held candidate and an available rollback. It includes exact entry-addition/removal counts, up to eight examples of each, catalog coverage changes, source identity and original timestamps. Entry differences are component-level facts: other feeds, local rules and suffix matching still determine the final request decision.

An approval requires two values from the same inspection:

```sh
egress-guard feed-approve hagezi-pro.plus \
  --candidate CANDIDATE_SHA256 \
  --base BASE_SHA256
```

`candidate_sha256` identifies the entire review envelope, including the fixed feed identity, source URL, base digest and candidate snapshot. `base_sha256` identifies the complete installed snapshot, including its metadata. The separately displayed `body_sha256` identifies only the entry body and must not be substituted for either command argument. When the initial active cache is missing, use `--base none`.

The command verifies the candidate again and checks that the installed base still matches. A changed candidate or base requires a new review. If inspection reports `stale-base`, refresh and inspect again; the old approval cannot be transferred to a different installed generation. Approval only accepts an enabled, fixed-catalog feed. It cannot import an arbitrary file or choose a new download URL.

The byte limit, entry minimum and maximum, canonical sorted unique records, digest checks and clock constraints remain mandatory. Relative to a valid installed snapshot, a drop of more than half the entries and an older or missing publisher clock remain non-overridable download failures. An invalid clock left by an older release does not establish a permanent future rollback floor.

To discard one candidate while retaining installed data:

```sh
egress-guard feed-discard hagezi-pro.plus --candidate CANDIDATE_SHA256
```

Discard also accepts the exact hash of a bounded but invalid candidate shown by inspection, allowing that inactive artifact to be removed. It does not create an ongoing exception: if the same suspicious source data is downloaded again, it is held again.

## Rollback and update intent

Inspection exposes `current_sha256` and `previous_sha256` when a usable previous generation exists:

```sh
egress-guard feed-rollback hagezi-pro.plus \
  --current CURRENT_SHA256 \
  --previous PREVIOUS_SHA256
```

Rollback restores only those recorded previous bytes. Its specific authority to restore a known older generation does not let ordinary approval bypass the publisher-clock check or accept an arbitrary historical file. The restored snapshot keeps its original fetch and publication timestamps. If it is stale, inspection and feed status report that age; rollback does not manufacture a fresh timestamp.

After rollback, automatic publication for that feed is held until a candidate is explicitly approved. Otherwise a scheduled refresh could immediately reinstall the change the user deliberately reverted. Other selected feeds can continue updating independently.

Only one useful previous generation is retained. A refresh with an unchanged entry body preserves the last distinct body instead of replacing the rollback with another copy of current data. A subsequent distinct publication replaces the previous generation. Rollback itself makes the generation just left available as the next previous generation.

## Publication and failure recovery

Refresh, approval, discard and rollback share the existing cross-process SQLite refresh lock. Approval checks the exact installed digest before preparing publication and again before replacing the active snapshot. These checks coordinate application-owned writers. They do not establish a security boundary against arbitrary code running as the same user.

The private review directory has mode `0700`; records created there have mode `0600`. Each fixed feed has at most one named candidate, one rollback record and one transition record. A record has a bounded 4 KiB metadata header and a snapshot no larger than the existing 64 MiB feed limit. Standard atomic-write staging can leave an unreferenced temporary file if a process dies inside a low-level write. There is no retained browsing history or per-request data in these records.

The transition record contains the previous snapshot and the exact digest of the intended new active snapshot. It is written before active publication, while the existing rollback record remains intact.

| Interruption or failure | Retained result |
|---|---|
| Candidate write fails | Existing candidate and active cache remain available. |
| Preparation completes but active replacement fails or the process exits first | Existing active cache and its previously applicable rollback remain usable. |
| Active replacement completes but the process exits before journal finalization | New active cache is installed; the transition itself supplies its exact previous generation. |
| Journal finalization fails | Publication reports the installed digest with recovery pending; it does not falsely report an unapplied update. |
| Another update encounters an applicable unfinalized transition | Finalize that record before preparing a replacement; failure preserves the current cache and recovery record. |
| Rollback state is unreadable or invalid | Refuse a new publication and retain installed data. Fix the local storage/access problem before retrying. |
| A display-only attempt record cannot be written after an explicit action succeeds | Return the actual action result with `attempt_recorded: false`. |

A held candidate does not enter the active cache and does not change the proxy's policy revision. With a verified installed cache, the existing policy can continue running while feed status reports `using-previous` and the review requirement. If no usable active feed exists, a candidate does not make the policy ready.

Publishing an approved snapshot is a filesystem operation. Command results explicitly report `runtime_acknowledged: false`; the normal authenticated policy receipt must separately acknowledge the proxy's loaded revision. The browser extension's packaged rules are also a separate publication path. None of these feed commands demonstrates browser routing or device-wide coverage.

## Qualification

The focused tests cover the same-count regression, exact and suffix matching, first installation, disabled/fixed-feed scope, private records, malformed and duplicate JSON fields, changed hashes and bases, non-overridable validation, candidate corruption, lock contention, original rollback age, rollback update holds, unchanged-body refreshes, failed writes and truthful action results.

Two tests terminate a real child process with `os._exit` immediately before and after the active-file replacement. A subsequent process reads the correct active and previous generations and can continue publication. These are process-interruption tests on the Linux test host. Power-loss persistence, filesystem corruption behavior and native macOS lifecycle behavior are not qualified by them.

```sh
PYTHONPATH=src:tests python -B -m unittest -v \
  test_feed_review test_feeds test_configuration test_config_recovery test_policy
```

No production feed, collector, browser profile or OS setting is touched by these tests. The feature changes feed publication; it does not add proxy containment, a filesystem sandbox, machine-wide packet filtering or hardware-backed approval.

## Primary references and scope

- [Google Analytics Measurement Protocol](https://developers.google.com/analytics/devguides/collection/protocol/ga4/reference) documents collection endpoints under `google-analytics.com`, the concrete anchor used in the regression.
- [HaGeZi's source documentation](https://github.com/hagezi/dns-blocklists/blob/main/README.md) describes differences between list tiers and regular removal of dead entries. A catalog change can be legitimate; review is a decision about a concrete update, not an accusation that its publisher is compromised.
- [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) separates signed metadata, versions, hashes, sizes and update roles. Egress Guard's local hash-bound review records do not implement that publisher-authentication framework. Download-source authentication continues to use the existing fixed HTTPS URLs and system TLS verification; source authenticity and semantic safety remain distinct questions.
