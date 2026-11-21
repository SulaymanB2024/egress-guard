# Release checks

1. Run all isolated unit tests and the loopback transport test with the pinned mitmproxy version.
   Run `node --test tests/browser/*.test.cjs` and `node scripts/update-psl.mjs --check` for the browser source. A test model of Chrome APIs is not actual browser qualification; run the throwaway-profile browser fixtures on a permitted target as well. Exercise cold default-Strict navigation, private-tenant boundaries, prerender/history transitions and actual origin/header assertions. Verify that preparation failure never releases the installed hold, and that recovery never automatically replays a POST or page action.
2. Build an sdist and wheel; install the wheel into a clean temporary target and exercise its version, initialization, empty-cache refusal and packaged dashboard assets.
3. Exercise dashboard authentication, hostile origins/hosts, CSRF and timed controls using temporary state only. Inspect the actual desktop and phone rendering.
4. Review the final source, package file list and dependency/license metadata. Exclude secrets, logs, generated certificates, feed caches, local records and personal paths.
   Check that browser coverage receipts distinguish required-source completeness from supported filter syntax and report conservative cosmetic-exception fallbacks. Qualify native relational-selector matching, URL-change exceptions and protected-content restoration in the actual browser. Retain the bundled PSL source and MPL notice, plus upstream notices for any distributed generated filter data. Exercise optional local-model and native-host behavior on the target platform before calling those integrations qualified.
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
