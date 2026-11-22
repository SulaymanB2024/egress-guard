# Release checks

1. Run all isolated unit tests and the loopback transport test with the pinned mitmproxy version.
   Run `node --test tests/browser/*.test.cjs` and `node scripts/update-psl.mjs --check` for the browser source. A test model of Chrome APIs is not actual browser qualification; run the throwaway-profile browser fixtures on a permitted target as well. Exercise cold default-Strict navigation, private-tenant boundaries, prerender/history transitions and actual origin/header assertions. Verify that preparation failure never releases the installed hold, and that recovery never automatically replays a POST or page action.
2. Build an sdist and wheel; install the wheel into a clean temporary target and exercise its version, initialization, empty-cache refusal and packaged dashboard assets.
3. Exercise dashboard authentication, hostile origins/hosts, CSRF and timed controls using temporary state only. Inspect the actual desktop and phone rendering.
4. Review the final source, package file list and dependency/license metadata. Exclude secrets, logs, generated certificates, feed caches, local records and personal paths.
   Check that browser coverage receipts distinguish required-source completeness from supported filter syntax and report conservative cosmetic-exception fallbacks. Qualify native relational-selector matching, URL-change exceptions and protected-content restoration in the actual browser. Retain the bundled PSL source and MPL notice, plus upstream notices for any distributed generated filter data. Exercise optional local-model and native-host behavior on the target platform before calling those integrations qualified.
   Build with all required sources and review parameter exceptions before acknowledging an explicit quarantine. Run the artifact-wide regex audit below. Neither a JavaScript regex test nor a short regex source string proves Chrome's compiled-memory limit. Include disabled static rulesets because the user can enable them later.
   Test optional browser-privacy controls in an isolated Chrome profile, including permission denial, organization/extension precedence, restart, revoked permission and release of a hidden lower-precedence override. Inspect actual regular/incognito scope behavior; a successful mock readback does not qualify Chrome's setting implementation.
5. Create a tagged release with the reviewed source archive, wheel and SHA256SUMS. Download the assets again and verify their checksums.

For dependency changes, regenerate and review both [hash locks](../requirements/README.md), run the explicit OSV query and assess every advisory match. A match is not a runtime reachability assessment; unresolved upstream alerts must stay visible. Exercise the actual installer function with a temporary home and real pip, including source build and supplied-wheel paths. Verify hash failure prevents project installation and that `pip check` passes. Never test against a real user's installation.

Do not trigger or wait for GitHub Actions as a substitute for these checks. Do not label this unsigned alpha as notarized or imply that it protects clients which have not been configured to use the proxy.

## Focused 0.8 Chrome fixture

The new runner separates static fixture checks from native execution:

```sh
# Builds and inspects synthetic fixtures only; no browser or HTTP listener.
node tests/browser/chrome-0.8.mjs --check

# On a permitted machine with Chrome 145+; always a fresh disposable profile.
node tests/browser/chrome-0.8.mjs --chrome /path/to/chrome

# Opens a visible disposable window; approve the optional permission prompt.
node tests/browser/chrome-0.8.mjs --chrome /path/to/chrome --privacy
```

Native cases exercise computed-style results for generic/scoped/entity/relational rules, exact exceptions, SPA refresh, protected restoration and Restore/Resume. Strict cases use Chrome's `testMatchOutcome` with explicit top-page/initiator inputs before and after preparation, including a private tenant under a prepared parent. These are native rule-evaluator results, not actual cold-navigation timing or wire-header observations.

The optional privacy run first obtains permission with no controls selected, then checks real prediction, WebRTC and auditing setting targets/ownership, release and permission revocation. It waits up to 60 seconds for the explicit native prompt. Denial, unavailable controls or an incomplete handoff yield incomplete qualification, not a pass. Other catalog controls, organization/extension precedence, incognito, browser restart, real WebRTC routes and cookie exemptions remain separate target cases.

The shared driver includes `--no-pings` to limit test-browser background traffic. This fixture therefore makes no causal hyperlink-ping suppression claim. It also makes no IP-masking or routing claim. `--check` was run for 0.8; neither native command was run in the implementation environment.

## 0.9 artifact regex gate

Use an isolated developer interpreter with the optional `google-re2==1.1.20251105` package, then audit the **actual generated extension**, not an earlier rule dump:

```sh
python -B scripts/audit-browser-regex.py /absolute/build/chrome
```

The auditor does not install dependencies, contact a network or launch Chrome. It reads every manifest-registered static ruleset, including disabled resources, and uses the [Chromium DNR compilation options](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/extensions/browser/api/declarative_net_request/utils.cc): Latin-1 byte patterns, each rule's case-sensitivity, captures only when a regex substitution needs them, and a 2 KiB memory budget. The optional developer dependency is separate from the application's locked runtime and is not distributed in its wheel.

Exit `0` means every regex passed and traversal completed. Exit `1` records compiled-regex rejections. Exit `2` means the result is incomplete or unavailable, including a missing optional package or invalid artifact. The JSON includes bounded ruleset/rule IDs and fixed error codes; raw regexes and engine error snippets are excluded. Input paths must be actual POSIX directories with no symlink components; file and aggregate size limits apply. A passing result is a standalone RE2 check, not complete DNR validation or native Chrome acceptance. Repeat the check whenever source lists or compiler output change, and also exercise Chrome's actual `isRegexSupported`/ruleset APIs on the target browser version.

The November 21 source snapshot preserves `analytics_trace_id` globally because its source exception is not safely representable. A normal complete build refuses this reduction. After reviewing that exact preserved name, the production-source build command is:

```sh
node scripts/build-browser.mjs --feeds /path/to/verified-state \
  --filters /path/to/verified-state/browser-filters --offline \
  --allow-parameter-quarantine analytics_trace_id --out /absolute/build
```

The acknowledgment does not make the coverage receipt complete and does not waive missing sources, ineffective compilation, unsafe/disabled parameter policy, unreviewed names or reduced cosmetics. Avoid `--allow-missing` for a release qualification. The [parameter record](parameters-0.9.md) explains the accepted subset, prefix coarsening, deferred native names and preserved query forms.

## Additional 0.9 target qualification

The Python integration suite runs the real pinned proxy against local HTTP/TLS fixtures. Before describing a device installation as qualified, repeat it on the intended platform and exercise these separate browser cases in a disposable profile:

| Boundary | Required observation |
| --- | --- |
| Actual-address guard | Selected guard self-test succeeds; a denied numeric candidate causes zero origin accepts; allowed fallback retains the origin certificate; changed IP policy affects later attempts; unavailable selection remains refusing. |
| Hardened transport | External HTTP forms/chunked bodies are refused at headers; non-loopback literal CONNECT and disallowed external ports stay refused during grants; an explicitly admitted port carries unchanged TLS. |
| Isolation | Initial destination navigation and same-site resource origins observe the intended missing headers; cross-site images, styles, frames, fetches and socket handshakes never reach their origins; private tenants remain separate. |
| Retained state | Inspect cached HTTP authentication, service workers/CacheStorage, established sockets, source-page outbound navigations and policy changes without reload. Do not infer storage erasure or connection revocation from rule installation. |
| Parameter policy | Actual redirects make progress, preserve unrelated query bytes and signed/authentication flows, respect imported exceptions, and exclude POST/subframes. Exercise encoded, bracket-bearing, bare, duplicate and valueless keys and Amazon path variants. |
| Receipts and recovery | Failed activation/readback never shows applied Isolation; saved transport changes remain pending until acknowledged; changing address-guard selection requires restart; an older proxy cannot satisfy 0.9 readiness. |

The 0.8 runner's static `--check` mode remains useful but does not execute these new native cases. The implementation environment did not run Chrome because its prior startup was denied by socket policy. Source merge and local package verification are not an installed-release or target-device qualification.

## Additional 0.10 gates

Run the complete Python and Node suites, the actual artifact RE2 audit above, and the fixed browser protocol benchmark against the same upstream snapshots as its baseline:

```sh
node scripts/benchmark-browser-protocols.mjs \
  --artifact /absolute/build/chrome \
  --baseline docs/benchmarks/protocols-v1-baseline-0.9.json \
  --out /absolute/qualification/protocol-comparison.json
```

The benchmark refuses different corpus or input-source hashes. Read both the equal-family reduction and compatibility/regression lists. Its corpus is visible to developers and is a reproducible development challenge, not a held-out generalization estimate. Header removal, proxy revocation and cosmetic hiding are separate results. An external percentage claim must retain that scope.

The flat literal-alternative compiler now groups at most four alternatives into each output rule. This preserves the same Boolean union while reserving static regex capacity for protocol defenses and future list changes. It still refuses unsafe quantified/nested splits, partial branch sets and silent omission of protecting exceptions. Small groups are not a universal memory proof: every final generated regex must pass the independent 2 KiB RE2 gate, and the complete static set must remain under Chrome's count limit.

| Boundary | Required target observation |
| --- | --- |
| Live proxy revocation | An allowed original-certificate TLS stream passes its control markers; a new authority/SNI/IP deny or expired grant stops the next forwarding in both directions, including queued connect data. Repeat on the intended macOS runtime. |
| Running-version acknowledgment | A running 0.9 process cannot satisfy 0.10 health/dashboard/native readiness; the restarted proxy reports authenticated `tunnel_policy: "per-forward"`. |
| Native protocol rules | Chrome accepts all actual static rules and reports supported regexes; controlled origins observe no recognized collection or loader request. Include reordered/interposed fields, typed resource distinctions and functional controls. |
| Identity-header channel | Under Isolated mode, same-site application POSTs and destination navigations omit all three documented PostHog identity headers; ordinary repairs cannot restore them. Other modes retain their specified behavior. |
| Lifecycle and compatibility | Exercise retries, alternate transports, cache/worker responses, first navigation, malformed/duplicate/encoded query fields and identity-removal requests. Do not infer SDK lifecycle prevention from isolated request matches. |

Native Chrome execution remained unavailable in the implementation environment. A modeled DNR result or standalone RE2 success must not be labeled a passed installed-browser test. See [the 0.10 release evidence](release-0.10.md) and [tracking/ad-delivery analysis](adversarial-tracking-0.10.md).
