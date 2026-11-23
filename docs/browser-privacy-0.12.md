# Browser privacy audit and native regex attestation, 0.12

This pass leaves the production Client Hints control unchanged. It adds an optional native regex gate to the collector runner and repairs three pre-existing collector test fixtures. No native Chrome process was run in this environment. Native regex acceptance, response-policy behavior and collector outcomes therefore remain **NOT COVERED** here.

## Supported Chrome version and the historical header-condition defect

The shipped Chrome manifest already requires **Chrome 145**. Chrome's [DNR reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#type-RuleCondition) dates `responseHeaders` and `excludedResponseHeaders` to Chrome 128, and `topDomains` and `excludedTopDomains` to Chrome 145. The latter conditions are used by the site's enforcement policy. There is no reason to lower the minimum version or add a new version gate for a feature older than that minimum.

The older response-header problem was real. In [this pinned Chromium parser](https://chromium.googlesource.com/chromium/src/+/4aa90bdde17fb4416efc92bd13a95ca88bd1f88e/extensions/browser/api/declarative_net_request/indexed_rule.cc), the condition arrays are copied only inside the response-header feature-flag branch, while processing can continue afterward. The [Chromium 127 feature definition](https://chromium.googlesource.com/chromium/src/+/refs/tags/127.0.6488.0/extensions/common/extension_features.cc) has that flag disabled by default. Under that configuration, a rule could lose its response-header restriction instead of being rejected. [Mozilla's API documentation](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/declarativeNetRequest/HeaderInfo) documents the Chrome 121–127 affected window and links [Chromium issue 347186592](https://issues.chromium.org/issues/347186592).

The issue page required sign-in during this review; its discussion and exact fix history were not independently inspected. The pinned parser and flag establish the historical mechanism. They do not establish a current defect in supported Chrome 145+. Current [Chromium feature definitions](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/common/extension_features.cc) enable response-header matching, and Chrome's [October 2024 extension update](https://developer.chrome.com/blog/extension-news-october-2024) documents its release in Chrome 128.

The existing absent-only `Permissions-Policy` rule still needs behavioral qualification. A minimum version and exact DNR readback do not prove that an existing, duplicate or malformed response header survives unchanged. Those cases remain in the native test matrix described in [the 0.11 design](browser-privacy-0.11.md).

## Why this pass does not remove Accept-CH or Critical-CH

HTTP hint negotiation and JavaScript access are different controls. Removing a response's `Accept-CH` or `Critical-CH` does not change the permissions policy already attached to a document. It also does not deny the default `ch-ua-high-entropy-values` feature, whose allowlist is `*` in the [UA Client Hints specification](https://wicg.github.io/ua-client-hints/#policy-controlled-features). An existing policy that permits the feature can still leave `getHighEntropyValues()` available.

The current [Chromium Client Hints implementation guide](https://chromium.googlesource.com/chromium/src/+/main/docs/client_hints/README.md) describes origin preferences as durable since M103. Stored preferences can be consulted before the next navigation response arrives. A response-header change cannot retract request hints already transmitted, and silently deleting a response header is not a storage-clearing operation. In particular, an **empty** `Accept-CH` is an explicit clearing instruction; stripping that header can discard the instruction. Older material describing session-only storage should not be used to infer current behavior.

The same implementation guide describes meta-based opt-in, connection-level negotiation and `Critical-CH` retries. A response-only deletion does not cover those mechanisms. Critical hints can participate in content negotiation, so suppressing them can also change functional behavior. These distinctions rule out the claim that blanket removal is a complete, compatibility-free remedy for detailed Client Hints exposure.

The existing opt-in control already removes its fixed eight high-entropy UA request headers where Chrome exposes the request to the relevant rule. For documents without an existing `Permissions-Policy`, it also adds the fixed native policy. Its existing-policy and worker limits remain explicit. This review found no demonstrated incremental benefit that justifies a broader response-header mutation. It does not clear site data, change DNT, rewrite a server's existing policy or claim that detailed fingerprinting has been eliminated.

## External RE2 audit and the new native gate

The existing `scripts/audit-browser-regex.py` already uses the relevant Chromium-style options: Latin-1 encoding, `max_mem=2048`, each rule's case-sensitivity flag, and capture preservation when the redirect uses `regexSubstitution`. These choices are supported by [Chromium's DNR regex options](https://chromium.googlesource.com/chromium/src/+/eb225dae29d8e1c2ce6bef24877a102bc7890064/extensions/browser/api/declarative_net_request/utils.cc) and the [earlier explicit 2 KiB implementation](https://chromium.googlesource.com/chromium/src/+/f332c49cabf7d657b8af5584d004b11e9f3d79c5/extensions/browser/api/declarative_net_request/utils.cc). Source length is not a compiled-memory check. That external audit remains useful, but it is not a call into the installed Chrome build.

`tests/browser/native-regex-attestation.mjs` supplies the missing native API step. The collector runner loads the actual built extension, waits for its worker, and calls [`chrome.declarativeNetRequest.isRegexSupported`](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#method-isRegexSupported) in that worker for every `condition.regexFilter` in every manifest-declared static ruleset. Disabled rulesets are included. Equal patterns in different rules receive separate calls and separate coverage credit.

The API's `isCaseSensitive` default is **true**, while a DNR condition's omitted `isUrlFilterCaseSensitive` means **false**. The helper passes both native flags explicitly. `requireCapturing` is true exactly when the redirect action contains `regexSubstitution`; it is not guessed by counting parentheses. The [native API implementation](https://chromium.googlesource.com/chromium/src/+/c0c871525956cda90559fee66d6fb3584d6107a1/extensions/browser/api/declarative_net_request/declarative_net_request_api.cc) confirms these defaults and its syntax/memory rejection results.

### Artifact and coverage contract

The source reader requires an absolute artifact directory. It refuses path traversal, encoded paths, resource symlinks, hard links and nonregular files. It checks ancestor identities and the opened file before and after reads; changed paths cannot silently supply a different resource. It rejects duplicate JSON keys, duplicate rule IDs within a ruleset, malformed flags and excessive nesting. Explicit bounds cover files, total bytes, static sets, entries and regex input sizes. These are validation controls for a locally supplied artifact, not a sandbox against a hostile process with equal filesystem access.

The receipt records:

- SHA-256 and byte size for the manifest and every declared static rule file, including files with no regexes.
- Per-ruleset rule and regex counts, enabled state and a hash of the ordered regex rule IDs.
- An ordered hash binding each regex's ruleset, rule ID, pattern and both native options, without publishing its raw source in the receipt.
- Expected, attempted, checked, accepted, rejected and unavailable counts, with per-ruleset coverage.
- The browser product, actual packaged-file comparison, and artifact rechecks after attestation and after the collector experiment.

The browser fetches only its own packaged assets, hashes their bytes and compares them with the local inventory before API calls. Native work runs in batches of at most 16. Calls may start in any order within a batch, but each returned answer is bound to its original ordinal and options hash. Missing, duplicate, reordered or malformed acknowledgements cannot earn complete coverage. `attempted` counts acknowledged complete batch submissions; a lost transport response does not manufacture an exact call count.

Only an exact native supported result counts as accepted. A native `syntaxError` or `memoryLimitExceeded` is **FAIL**, even if every input was checked. Missing API access, interrupted calls or malformed result shapes are **NOT COVERED**. An asset mismatch or changed artifact is **FAIL**. Zero regexes do not produce a vacuous native success. A failed native gate stops the collector run; an unavailable gate leaves the overall qualification incomplete.

This gate attests regex compilation support for the inventoried **static** regexes. It does not prove whole-ruleset installation, enabled-rule quota availability, redirect rewrite validity, URL matching semantics, dynamic/session rule acceptance or transmitted-byte outcomes. Existing collector, policy-readback and compatibility gates remain separate.

## Execution and validation

Source-only checks do not start Chrome, Python, a proxy or a listening socket:

```sh
node tests/browser/chrome-collector-lab.mjs --check
node tests/browser/chrome-collector-lab.mjs --check \
  --extension /absolute/path/to/built/chrome
node --test tests/browser/native-regex-attestation.test.cjs \
  tests/browser/collector-lab-contract.test.cjs \
  tests/browser/collector-origin-contamination.test.cjs \
  tests/browser/collector-byte-windows.test.cjs
```

The optional `--extension` check inventories a supplied artifact and reports hashes/counts while retaining native **NOT COVERED**. It never substitutes a JavaScript regexp or external RE2 result for the native API.

On a permitted machine, the existing explicit-path collector command includes the gate automatically:

```sh
node tests/browser/chrome-collector-lab.mjs \
  --chrome /absolute/path/to/chrome \
  --python /absolute/path/to/venv/bin/python \
  --extension /absolute/path/to/built/chrome \
  --out /absolute/path/to/new-native-receipt.json
```

The runner still uses a disposable profile, fixed loopback fixture, SPKI-scoped trust and exclusive output creation. It does not accept an existing profile or a blanket certificate-error override. Missing native facilities remain visible in the receipt.

The fresh-main baseline at `74b1ec5d89b5d7fdad6b22c48116ef101279b74d` had **405 of 408 Node tests passing** before these edits. The three failures were stale collector test fixtures after stricter origin-accounting guards landed. Valid aggregate fixtures omitted the required non-target-origin counters; two raw negative fixtures also omitted their required first-party target host and failed before reaching their intended checks. Those fixtures now supply the required evidence. The missing-counter and overflow cases still fail for their intended reasons, and no runtime guard was weakened.

Focused tests additionally exercise exact case/capture flags, repeated patterns, disabled sets, every-input coverage, missing API support, incomplete batches, contradictory results, changed artifacts, unsafe paths and a directory swapped during opening. They use injected API results and are **contract tests**, not Chrome acceptance evidence. A source-only inventory of the existing 0.11 release-default artifact read 17 declared rulesets, 14,180 rules and 941 regexes successfully; that historical artifact count is not a claim about the current release build.

No native execution occurred during this pass. The production Client Hints control remains off by default and experimental, with installed-rule receipts explicitly distinguished from browser behavior.
