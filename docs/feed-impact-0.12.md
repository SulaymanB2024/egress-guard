# Feed decision checks in 0.12

Automatic refresh now compares candidate feeds through the same `Policy` implementation used by the proxy. The comparison can hold an update even when its size, entry count and publication date pass the existing validators.

Two changes trigger this additional review requirement:

- A public service probe changes from allowed to blocked: `policy-critical-deny`.
- A previously blocked public tracker or DoH probe changes to allowed: `policy-canary-allow`.

These checks quarantine a candidate and retain the installed generation. They do not create allow rules, require a feed to contain every probe, or authorize an exception to a threat block. Exact approval and rollback remain available through the existing digest-bound commands.

The existing component tripwires and changed-root inspection remain in place. A component can lose coverage while another feed still blocks the same host. The report now distinguishes that loss from an actual change in the combined saved policy.

## The comparison uses real policy decisions

The baseline loads the selected snapshots with the full cold validator and captures the saved settings, manual rules, allows, compatibility exemptions, tracker pause and temporary exceptions. A candidate replaces exactly one selected component in memory. Production policy grouping, matching, precedence and revision calculation are shared with the normal policy constructor.

Every probe reports its host, fixed port **443**, origins, and these fields before and after replacement:

- `decision`
- `source`
- `category`
- `matched_domain`
- `can_allow`

A host can remain blocked while becoming eligible for a tracker exception. For example, removing a threat entry can expose an existing tracker block: the result changes from `malware-feed`, category `malware`, `can_allow=false` to `tracker-feed`, category `ads-trackers`, `can_allow=true`. That change is reported even though both decisions say blocked. It does not by itself trigger the two new automatic hold rules.

Threat and manual precedence, exact safety hosts, permanent allows and opted-in compatibility presets retain their normal behavior. An explicit configured allow can therefore change to a non-allowable threat block. Those configured-host changes are advisory; they do not automatically prevent a legitimate threat update.

This evaluates **hostname policy at port 443**. It makes no DNS query, TLS connection or HTTP request. It does not qualify hardened transport restrictions, the numeric socket guard, DNS resolution, active tunnels, browser rules or operating-system routing. A numeric feed entry appearing in a changed-entry sample is only a literal request-target policy sample, not evidence about a resolved peer address.

## A second view prevents temporary grants from masking a change

Each public context has two evaluations:

1. **Current view:** both policies use one fixed evaluation instant.
2. **Grant-expiry counterfactual:** all captured temporary grants are expired while every other captured input remains fixed.

The second evaluation chooses an instant beyond every captured expiry, including future-dated timestamps that are not valid grants now. It cannot accidentally activate such a timestamp by simply advancing the clock 24 hours. Neither evaluation modifies a control file or the loaded baseline.

The automatic public-probe gate uses either view. A new `api.github.com` tracker entry therefore cannot pass merely because tracker filtering is temporarily paused, or that exact host has a short exception. The report shows that it remains allowed in the current view and would be newly blocked with the captured temporary grants expired.

Permanent allows still apply in both views. The counterfactual does not remove them or change threat, manual, safety or exact-CNAME precedence. It is **not a prediction** that a feed will remain valid, a configuration will remain unchanged or the running proxy will behave that way in the future.

## Pinned public corpus

The complete public input is packaged in [`feed-impact-probes.json`](../src/egress_guard/feed-impact-probes.json). The loader bounds the file to 64 KiB, refuses non-regular files, checks its pinned SHA-256 and validates every host, port and role. A missing, malformed or mismatched corpus refuses automatic publication rather than disabling the check silently.

Corpus version **1** contains **64 named public hosts**:

| Role | Named hosts | Purpose |
| --- | ---: | --- |
| Tracker anchors | 14 | Detect loss of a previously blocked tracker decision |
| Shared-service parents | 17 | Detect new denials at selected infrastructure roots |
| Authentication, update and revocation safety hosts | 25 | Exercise existing exact safety and manual-rule precedence |
| Specific service endpoints | 4 | Cover GitHub API/raw content, npm registry and PyPI distribution endpoints |
| DoH endpoints | 4 | Detect loss of previously blocked Google, Cloudflare, Quad9 or AdGuard resolver decisions |

The corpus SHA-256 is:

```text
4a552d749b7a1715069811a2bab5890f81953fee8404f181f0e98b614b738bf4
```

There are also **31 synthetic descendant contexts**, one beneath each tracker anchor and shared-service parent. Those are string-only matching examples, not assertions that the synthetic names resolve or provide a real service. The result is **95 distinct public `(host, 443)` contexts**, each evaluated before and after in both views. Host counts, context counts, corpus version and the verified hash are reported separately.

The four DoH probes are `dns.google`, `cloudflare-dns.com`, `dns.quad9.net` and `dns.adguard-dns.com`. If an enabled baseline never blocked a probe, keeping it allowed is not a regression. Disabling encrypted-DNS blocking does not create a new requirement to block those names.

### Additional bounded probes

Review adds up to 128 explicitly configured hosts from the effective permanent allows and exact compatibility exemptions. That includes `allow.txt`, configuration `block.allow`, configured dashboard hosts and expanded opt-in presets. Each selected host also gets a labeled descendant example where DNS length permits. All configured rules still affect every decision, including rules whose own host is outside this bounded sample.

The existing entry-difference samples supply up to 16 changed roots, with descendant examples. These come from the feed snapshots, not activity records. They explain changes outside the public corpus and do not expand the automatic gate to arbitrary user or feed-sample hosts.

The total cap is 384 contexts. The report distinguishes configured hosts available, attempted, actually sampled and omitted. A full cap cannot silently claim that an uninserted configured host was examined. Every public context must fit; otherwise the check reports `not-covered` and automatic publication refuses.

The comparison does not read browsing history, the event ledger, cookies, request bodies or a browser profile. Full configured-host results are returned only by the requested review. The saved refresh-attempt summary contains counts, public hold reasons and revision hashes, not configured domain probes.

## Specific hierarchy checks, not every registrable domain

Catalog version 2 adds three explicit shared-service roots:

| Root | Why it has a broad effect |
| --- | --- |
| `s3.amazonaws.com` | S3 documents bucket hostnames beneath this legacy global endpoint. |
| `storage.googleapis.com` | Cloud Storage documents shared path-style requests and bucket subdomain requests. |
| `blob.core.windows.net` | Azure documents storage-account names beneath this Blob Storage domain. |

Adding one of these roots is different from adding one malicious bucket or account beneath it. The latter remains a normal blockable target. The feed's actual matching semantics still govern the effect: tracker/threat/DoH components match descendants; CNAME components match exact hosts.

A rule that flags every newly listed registrable domain would also flag ordinary tracker roots such as `google-analytics.com` and `doubleclick.net`. Being a registrable domain does not establish a large legitimate-service blast radius. This release uses a small, reviewable service catalog and real decision changes instead. The catalog is incomplete: it does not cover every regional cloud endpoint, tenant platform or critical service.

## Refresh and review behavior

At operation start, CLI and dashboard refresh bind the supplied normalized settings to the **actual configuration file**, including a custom path. The file must remain unchanged across the verification read, and its loaded settings must equal the supplied settings. This happens before downloads. The initial configuration observation is retained across every candidate in the refresh.

Refresh then performs these steps for each selected feed:

1. Download and apply the existing source, byte, framing, canonical-entry, minimum-count, count-loss and publication-time validators.
2. Capture the saved policy and compare one in-memory candidate against its exact installed base.
3. Apply the existing component tripwires, the new public decision-delta holds and any explicit rollback hold.
4. If held, write the private digest-bound candidate record and retain the installed feed.
5. Otherwise prepare the existing rollback journal and a private temporary active file.
6. After the temporary file has been written and synced, recheck the installed base digest, initial configuration observation and policy input observations immediately before replacement.

Validated component data is reused within a refresh only while its fixed feed identity and inode/ctime/mtime/size/mode observations remain unchanged. Failed reads are not reused as verified data. Controls and the comparison instant are captured again for each candidate; there is no persistent allow cache.

`egress-guard feed-review [FEED_ID]` includes `policy_impact` automatically. There is no additional `--impact` option. It also reports the existing exact entry difference and changed coverage roots, so source changes and combined-policy changes remain distinguishable.

The review command does not initialize state, acquire the refresh write lock, download data or write a report into application state. Replacing its candidate file or changing policy inputs while review runs invalidates the corresponding comparison. A complete comparison has status `compared`; this does not mean the candidate is safe or that every hostname was tested.

### When comparison is unavailable

| Situation | Result |
| --- | --- |
| Missing or corrupt enabled baseline feed, or a substituted/degraded baseline | `not-covered`; bootstrap and repair can proceed under existing validators and component tripwires. |
| Malformed or unreadable policy controls | Automatic publication refuses. |
| Supplied settings do not match the actual configuration file at operation start | The operation refuses before downloading or publishing feeds. |
| Missing or invalid pinned corpus, or omitted public contexts | Automatic publication refuses. |
| The bound configuration changes during a download, or policy inputs/the installed base change during the automatic check | The attempt refuses; reload settings and retry refresh against the new inputs. |
| Held candidate has a stale base or fails hard transition validation | Review marks the comparison unavailable; existing approval checks still refuse the invalid/stale publication. |
| Disabled feed is explicitly inspected | Its hypothetical activation is not evaluated. |

The refresh response includes a small `policy_impact.checks` result for each attempted source. Incomplete bootstrap is explicitly labeled `not-covered`; it is never represented as a successful comparison against an installed baseline.

CLI refresh, CLI review and dashboard refresh pass their actual default or custom configuration path. A file edit or replacement during a download or temporary-file fsync invalidates that binding. A missing configuration file becoming present is also a change, even when its normalized values equal the defaults. Updating one feed does not invalidate the separate configuration binding for later feeds in the same operation.

Python API callers can supply `config_file=...` to receive the same protection. With `config_file=None`, the API uses only the explicitly supplied settings, frozen in memory; it does not guess or read a separate configuration file. That mode is labeled `supplied-settings`, and `configuration_bound` is false. The `settings_scope` field distinguishes the two modes. Neither mode acknowledges the running proxy's applied revision.

## Publication authority and remaining race boundary

Candidate approval still requires the exact candidate-record digest and installed-base digest. Rollback still requires the exact current generation and recorded immediately previous generation. Approval does not bypass the hard candidate validators, and rollback preserves the previous snapshot's original age. This release does not change those tokens or add a broad allow exemption.

The final installed-base check now also runs after temporary-file fsync for **approval and rollback**, not just automatic refresh. If the installed generation changes during the write, publication refuses and preserves the concurrent generation. An automatic refresh additionally rechecks policy inputs at that boundary. A refusal preserves the previous usable rollback record; the uncommitted transition is not mistaken for the active generation's rollback. Private temporary files are removed by the normal cleanup path.

This is not an atomic transaction across controls, configuration and feed files. A narrow interval remains between the last check and the final rename. The change closes the potentially long temporary-write/fsync interval and detects cooperative file replacement; it does not provide same-user malware containment or defeat code that can rewrite the application. A later configuration edit or an explicit approval under changed controls can change effective decisions without changing the approved feed bytes.

## Regression evidence

The focused tests cover equal-count updates that were outside the old component tripwires: a new GitHub API block, removal of the only threat block covering a public tracker probe, and removal of a previously blocked DoH endpoint. The installed generation is retained and the candidate is held for exact review.

Other cases cover overlapping feeds, manual and safety precedence, blocked-to-blocked category/exception changes, configured allows overridden by threat data, exact CNAME matching, temporary-grant masking, permanent allows in both views, missing/corrupt baselines, candidate/configuration races, bounded sampling and corpus integrity. Default and custom configuration tests cover stale supplied settings, edits during the initial binding read, edits during downloads, missing-to-present changes and edits at temporary-file fsync. CLI and dashboard tests verify that they pass the actual configuration path. A subprocess audit hook rejects writes, network attempts, SQLite access, activity-file reads and child-process creation during real review.

The fsync-boundary regressions remove a masking allow or replace the active generation after the candidate temporary file is synced. They verify refusal, preservation of installed/concurrent bytes and prior rollback, and temporary-file cleanup. The existing real process-interruption tests before and after active rename also remain in the focused gate.

Run the focused suite in the project's pinned isolated environment:

```sh
PYTHONPATH=src:tests python -B -m unittest -v test_feed_impact test_policy test_feed_review test_feeds
```

These are deterministic local policy and filesystem tests. They do not establish production feed authenticity, actual service compatibility, macOS behavior, browser enforcement or universal poisoning detection.

## Public endpoint references

- [AWS S3 virtual hosting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html)
- [Google Cloud Storage request endpoints](https://docs.cloud.google.com/storage/docs/request-endpoints)
- [Azure Storage account endpoints](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview)
- [GitHub dependency-submission network requirements](https://docs.github.com/en/code-security/reference/supply-chain-security/automatic-dependency-submission)
- [npm registry documentation](https://docs.npmjs.com/using-npm/registry.html/)
- [PyPI Index API](https://docs.pypi.org/api/index-api/)
- [Google Public DNS over HTTPS](https://developers.google.com/speed/public-dns/docs/doh)
- [Cloudflare DoH API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/)
- [Quad9 services](https://docs.quad9.net/services/)
- [AdGuard public DNS](https://adguard-dns.io/en/public-dns.html)

Existing safety-host provenance and exact-only limitations remain documented in the project's policy and earlier core review documentation. The corpus does not convert these service documents into a promise that all hosted content is trustworthy.
