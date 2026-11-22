# Bounded regex compilation in 0.11

The controlled full-build experiment recovered **125 static regex slots**, taking the 0.10 artifact from **955 to 830** with the same verified feed snapshots. Available count headroom increased from **45 to 170**. The count reduction is **13.09%**. This is capacity for future defenses; the existing tracking challenge produced exactly the same decisions.

The [machine-readable experiment receipt](benchmarks/regex-optimization-0.11.json) records the input digest, each ruleset's hashes and counts, source-conversion agreement, verifier result, proof-record hashes, and fixed-corpus comparison. It describes a controlled compiler experiment. A release build can have a different build identity after other reviewed source changes.

| Build | Static rules | Static regex rules | Regex count headroom |
|---|---:|---:|---:|
| Frozen 0.10 baseline | 14,086 | 955 | 45 |
| New ordinary build | 14,180 | 941 | 59 |
| New build with verified optimization | 14,069 | 830 | 170 |

Chrome documents a 1,000-regex limit for each applicable rule category and a compiled-size limit of 2 KiB per regex. A regex can fit the count budget and still fail its individual memory budget. [Chrome DNR reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#rules-that-use-regular-expressions).

## What the inventory changed

Of the 955 baseline regex rules, 801 came from parameter cleaning. Threat navigation used another 66, link handling 26, first-party tracker rules 31, EasyList 24, EasyPrivacy 6, and replay detection 1. Optimizing only imported ABP regex syntax could therefore address at most 30 of the existing slots.

The threat-navigation rules repeat a capture pattern over separate domain chunks. This work keeps those chunks and all capture-based redirects unchanged. Consolidating their very large domain arrays would sidestep existing resource bounds and require separate native evidence.

The two implemented transformations have separate roles:

| Transformation | Where it runs | Controlled saving |
|---|---|---:|
| Bounded regex-to-URL-filter lowering | Ordinary ABP compilation | 14 regex slots |
| Verified union of identical-action predicates | Explicit optional build pass | 111 further slots |

The union pass saves 105 parameter slots, 3 first-party tracker slots, and 3 remaining EasyList slots. Within parameters, 64 saved slots are redirects and 41 are fixed preservation brakes. The actions of those brakes remain `allow`; their priority and navigation/method constraints stay intact.

## Exactness boundary

### Finite lowering

[`regex-language.cjs`](../scripts/lib/regex-language.cjs) parses a deliberately bounded language. It can lower ASCII literals, concatenation, finite alternatives, bounded finite repetition, optional terms, `.*`, and appropriately placed start/end anchors. Expansion stops at 128 filters, 512 characters per filter, and the parser's depth/node limits. Refusal leaves the original regex on the established compilation path.

The transformation preserves the language of the predicate over the same ASCII canonical URL supplied to DNR. Literal characters stay literal; `.*` becomes URL-filter `*`; a start or end assertion becomes the corresponding edge anchor. Canonical network URLs contain no raw newline, which is the relevant qualification when translating regex dot-star. Literal URL-filter metacharacters, word boundaries, character classes, arbitrary single-character matching, unbounded literal repetition, flags, backreferences, and other unrepresented syntax refuse lowering. The broader parser can retain some of these atoms for union factoring, but that does not make them eligible for URL-filter lowering.

For example, a predicate for HTTP **or** HTTPS yields two explicit protocol filters. It never becomes a wildcard protocol. No domain anchor or separator is invented. The code preserves the original `isUrlFilterCaseSensitive` value and every other condition, including initiator/request domains, exclusions, method, resource type, and party restriction. Chrome documents canonical ASCII URL matching and the shared case-sensitivity field for the two predicate forms. [RuleCondition reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#type-RuleCondition).

Source authorization, `$badfilter`, exception validation, and the existing counted-repetition rejection run before lowering. A previously rejected broad exception cannot gain authority through the optimizer. Existing source rows rejected by the supported-subset compiler are not resurrected.

In the measured lists, two EasyList source rows formerly produced 14 regex rules. They now produce 108 URL-filter rules. `regexLoweredFilters`, `regexLoweredRules`, and `regexLoweredSlots` distinguish those three counts. EasyList and EasyPrivacy preserve their original network-row, converted-row, exception-row, and dropped-reason counts.

### Same-action union

[`regex-optimizer.cjs`](../scripts/lib/regex-optimizer.cjs) considers two or more rules only when their **complete action, priority, and every non-regex field are equal**. It never combines parameter-removal action lists or expands a scope. It accepts only `allow`, `block`, and redirects without `regexSubstitution`.

The transformation uses the regular-language identity:

```text
P A S | P B S = P (A | B) S
```

The bounded parser identifies atom boundaries before factoring. It does not split escaped characters or character classes by string prefix. Capturing parentheses become ordinary grouping only within this Boolean-match setting; capture-sensitive actions are excluded. `modifyHeaders` is also excluded because repeated append operations can have a different effect from one operation. Frame-level `allowAllRequests` is outside the pass.

Each candidate contains at most eight source rules. The deterministic first-fit algorithm makes at most 10,000 candidate attempts per ruleset; it makes no claim to find a minimum-size solution. A candidate is adopted only after the pinned verifier accepts its exact pattern with the original case flag. A memory rejection retains the original rules. Unsupported parser syntax also retains the originals. A verifier failure aborts requested optimization.

The resulting invariant is precise: **for every request, the set of eligible `(priority, complete action)` pairs is unchanged** within the declared grammar. Matching rule IDs and debug match counts can change.

**Redirect tie qualification:** Chrome leaves ordering among equal-priority, equal-action-type rules unspecified. If different redirect payloads tie, preserving the eligible action set does not promise the same winner under an undocumented internal tie order. The pass preserves every candidate action and does not merge distinct redirect payloads. This distinction is part of the proof boundary. [Chrome rule evaluation](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#rule-evaluation).

These are algebraic rewrites within an explicit parser grammar. Finite test agreement is additional regression evidence; it is not a proof for arbitrary regex syntax or the complete browser engine.

## Explicit build option and verification

Ordinary builds continue to require Node alone. They receive the finite ABP lowering and keep the unmerged regex rules.

To request the optional pass, use an existing isolated interpreter containing `google-re2==1.1.20251105`:

```sh
node scripts/build-browser.mjs \
  --feeds /path/to/verified-state \
  --offline \
  --out /path/to/build \
  --optimize-regex \
  --re2-python /path/to/isolated/bin/python
```

The normal source-completeness and explicit parameter-quarantine requirements still apply. The command above does not approve a particular source fallback. Review any reported quarantine before acknowledging its exact name.

The build does not install packages or start Chrome. [`optimize-browser-regex.cjs`](../scripts/optimize-browser-regex.cjs) talks to a bounded local verifier process. It requires the exact package version, Latin1 encoding, a 2,048-byte memory budget, the actual case flag, and captures only where an unchanged action requires them. Chromium's source uses these option choices and defines the memory budget as 2 KiB. The pinned standalone package is **not** a claim to be the embedded RE2 version of a target Chrome release. [Chromium options](https://chromium.googlesource.com/chromium/src/+/refs/tags/150.0.7871.92/extensions/browser/api/declarative_net_request/utils.cc), [Chromium memory constant](https://chromium.googlesource.com/chromium/src/+/refs/tags/150.0.7871.92/extensions/browser/api/declarative_net_request/constants.h), [RE2 syntax](https://github.com/google/re2/wiki/Syntax).

A requested pass fails if the interpreter/package is absent, the version differs, the verifier exits early, a required output check fails, or the proof record is incomplete. It does not silently publish an unoptimized artifact as a successful optimized build. The previous published Chrome/Firefox directories remain intact when staging fails.

The complete generated Chrome artifact then passes through the existing bounded static-regex auditor before publication. This includes every manifest ruleset and untouched capture-based patterns. It verifies actual staged files, checks that their hashes stayed unchanged during the audit, and rejects incomplete traversal. The auditor's existing POSIX and no-symlink path requirements apply.

## Proof records and receipts

Optimized builds package:

- `rules/regex-optimization-plan.json`: exact before/after ruleset hashes, each source index and ID in a merge, invariant-field hashes, input/output predicate hashes, per-ruleset statistics, and helper-source hashes.
- `rules/regex-optimization-certificate.json`: the pinned engine/options, complete output verification, verification-log digest, plan digest, and the complete staged-artifact audit with ruleset hashes.
- `rules/build.json`: whether optimization was enabled, the before/after regex counts, and the plan/certificate hashes.

[`regex-optimization-plan.cjs`](../scripts/lib/regex-optimization-plan.cjs) replays each merge from the original rule arrays. Every untouched rule must survive unchanged. Each altered predicate must be reconstructed by the declared union function; its action and all other fields must be identical. Removed, duplicated, changed, or unaccounted-for source rules invalidate the record.

Both packaged record hashes participate in the extension build identity. The records contain structural evidence and resource-verification receipts. `nativeChrome` remains false; they do not certify successful indexing or activation in an installed browser.

## Validation evidence

The controlled build uses the same upstream-input digest as the frozen 0.10 full artifact:

```text
b2f4a7ff538b24b9bd757c286776bcefda5e55654a4c9f2b5b6292e673960ded
```

Focused tests exercise protocol/port/encoding/fragment boundaries, case flags, unsupported atoms, expansion limits, exception authority, `$badfilter`, unchanged conditions, quantified alternatives, capture/header exclusions, different-action refusal, absent/wrong-version verifiers, proof tampering, and preservation of the previous build after failure.

An additional standalone RE2 differential regression compared all 78 merged groups over 10,283 synthetic URLs: 802,074 paired decisions, including 4,526 positive comparisons, with no differences. This finite challenge is a regression check, not web coverage or a substitute for the algebraic boundary. The existing frozen protocol corpus also retained all prior decisions: 25 of 34 tracking fixtures prevented, 9 escaped, no new functional false positives, and no regressions. The two pre-existing functional false positives remain visible in the receipt.

The staged artifact audit passed all **830** regexes across **17** rulesets. **Native Chrome qualification is NOT COVERED.** Qualification on the intended browser must load the exact artifact and exercise the actual DNR support/matching APIs, including lowered URL-filter cases, exceptions, method/type restrictions, and parameter-preservation brakes. No performance or latency improvement is inferred from rule counts.

## Assessment of the supplied compiler proposals

Raw handoff notes 01, 02, and 04 correctly identify regex pressure, source drift, reproducible receipts, and an explicit promotion gate as useful engineering work. Their proposed compression percentages and sub-millisecond performance figures are hypotheses. The actual inventory placed most of the cost in parameter cleaning, rather than the imported ABP regex catalog.

A complete SMT/DFA proof would require a formal model of canonicalization, matching, scope, action evaluation, redirects, and browser lifecycle. This change uses a smaller, reviewable proof envelope and labels the remaining browser boundary. It introduces no runtime learned-rule authority, automated broad exceptions, domain-union expansion, or synthetic tracking efficacy score.
