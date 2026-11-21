# 0.9 implementation and qualification record

Reviewed base: `5b8d05fe36ba82511de09bc6a527a3eed4d71c9e` (merged 0.8.0). Implementation and review: November 21, 2026.

This update adds actual TCP-address policy, an explicit hardened proxy profile, named-site browser Isolation and maintained query-parameter protection. It also repairs browser rules that could silently fail Chrome's compiled-regex budget or let a URL-preservation exception weaken frame blocking. Python and both browser manifests are versioned `0.9.0`.

The changes are source development and isolated qualification. They do not install themselves, bind every application to the proxy, make an account anonymous or establish that all data leakage has been prevented.

## Protection added

| Area | New behavior | Remaining boundary |
| --- | --- | --- |
| Experimental actual-address guard | Check the numeric TCP destination at CPython's `socket.connect` audit event, immediately before the qualified connector attempts the connection. | Explicit opt-in; pinned transport and supported selector runtime; DNS can happen before the check. |
| Hardened proxy profile | Refuse external HTTP at request headers, non-loopback literal CONNECT destinations and CONNECT ports outside an explicit list. Initial TLS and visible-SNI checks remain mandatory. | Applies to clients using this proxy; existing admitted connections and encrypted application contents remain outside the check. |
| Chrome Isolation | Block all represented cross-top-site subresource types and remove selected HTTP identity headers on site resources and navigations to the site. | Named-site policy, not navigation containment, storage erasure, fingerprint prevention or IP masking. |
| Maintained URL tracking policy | Compile upstream literal parameter rules and exceptions into one shared native/runtime policy, replacing the old production parameter ruleset. | Declared syntax subset; conservative preservation can leave identifiers in a URL. |
| Artifact regex audit | Check every built static regex, including disabled rulesets, using official RE2 with Chrome-style memory, case and capture settings. | Standalone RE2 qualification; native Chrome acceptance remains a separate gate. |

### Checking the address actually used

A hostname decision alone cannot reject a listed IP hidden behind an otherwise allowed hostname. The new address guard checks the numeric candidate used by the TCP connector against current IP policy. It does not perform a separate check-time DNS lookup, pin the first answer, or grant an IP exception because the hostname was allowed.

The real proxy tests demonstrate a blocked first candidate followed by an allowed second candidate, one resolver lookup per requested hostname, and preservation of the exact origin TLS certificate. A blocked candidate receives zero TCP accepts. The same refusal holds behind an exact built-in safety hostname, and newly applied IP-feed data affects later connection attempts. This makes the existing IP-capable threat feed useful at a previously unchecked boundary.

The hook installs only after explicit selection. Startup checks the interpreter, loop and pinned mitmproxy version, confirms hook registration, and probes the connector before reporting active. An unavailable selected guard leaves authenticated health reachable but refuses filtering traffic. Ownership and shutdown are explicit; a retired enabled owner cannot leave late TCP attempts unchecked between leases. Changing the selection requires a process restart, and the saved/runtime receipts show that pending state.

The callback adds no DNS query, request history, peer-address log or remote classifier. CPython audit hooks are not a sandbox against hostile code executing in the interpreter. Native code that bypasses this connector, other processes, UDP, QUIC, system DNS and direct traffic remain outside its scope. See [transport design, failure behavior and integration evidence](core-0.9.md).

### Preventing common plaintext and tunnel escape paths

The separate `hardened` profile refuses non-loopback HTTP without first deciding whether a particular header or body contains a secret. A form submission with no Cookie or Authorization header is still refused. Requests carrying a declared body are closed at the header boundary so the transport does not wait for or buffer the body before refusal.

The profile also refuses non-loopback literal IP CONNECT targets and limits external CONNECT ports, initially to 443. Tracker grants, pauses and hostname exceptions cannot lift these floors. A delayed tunnel is checked against the profile current when its first bytes arrive. Accepted TLS remains opaque and retains the original certificate; there is no trust-store change or HTTPS interception.

Defaults remain `profile = "compatible"`, `connect_ports = [443]`, `address_guard = false`. Existing explicit local-history choices remain intact; fresh configurations continue to use no traffic history. The selected profile and port list can reload through the existing authenticated policy transaction. A simultaneous change to the address-guard selection waits for restart as a whole.

### A stronger per-site browser policy

Isolation blocks cross-site images, styles, media, frames, scripts, fonts, fetch/XHR, pings, CSP reports, WebSocket/WebTransport handshakes and the remaining declared subresource types. Classification uses the associated top-level site's bundled public/private PSL boundary. A third-party frame cannot become first party simply by requesting its own origin. Independent private tenants remain separate even when the isolated site's DNS parent contains them.

The block sits at priority 24, above ordinary endpoint grants, embeds, saved allows, compatibility exceptions and surrogates. Header removal sits at 46 and covers Cookie, Authorization, Referer and Set-Cookie. A separate destination-scoped rule handles initial main-frame navigation without depending on the worker seeing the navigation first.

Activating Isolation revokes crossing temporary repairs and saves removal of an existing Pause with the new mode. Pause is refused while Isolation is requested or remains confirmed as applied. Failed installation/readback retains accurate requested/applied/degraded state. Unsupported addresses do not inherit a protected receipt. Changing site mode is the deliberate relaxation control.

Isolation can break sign-in, payment providers, CAPTCHAs, CDNs and embeds because it has no compatibility bypass. It does not close existing connections, delete site storage, block every navigation away from the site or remove arbitrary identifiers from bodies/custom headers. Same-site application code still runs. Firefox remains the existing manual HTTP/S baseline. Read [enforcement priorities, recovery and limitations](enforcement-0.9.md).

## Maintained blocklists and parameter coverage

This pass fetched all seven selected proxy sources and all four browser sources into isolated validation state. Each exact public response passed the corresponding source, size, syntax, hash and minimum-count validators before the build used it. The production profile is HaGeZi PRO++ plus full threat intelligence, URLhaus, Phishing Army and the AdGuard CNAME aliases; the proxy's encrypted-DNS list was validated separately because Chrome's own DNS is not a page request the extension can filter.

The sources were retrieved with explicit public HTTPS `curl` for this validation. The application's direct downloader was unchanged; this exercise does not claim that its live networking path was qualified in this environment. Fresh retrieval is also distinct from publisher freshness: the AdGuard CNAME source retained its November 5 publication date. Source hashes, source times, normalized snapshot hashes and compiled totals are in [validation-0.9.json](validation-0.9.json).

The new **AdGuard/uBO – URL Tracking Protection** snapshot contributes 1,977 productive imported remover rows. The combined policy covers 1,676 distinct JavaScript parameter names, compared with 346 in the development baseline. Native rules cover 1,674 of those names. These are policy counts, not measured tracking-prevention rates; overlapping rules and source omissions prevent interpreting the ratio as an equivalent gain in privacy.

The parameter compiler preserves upstream exceptions across both new and old removers. Source exceptions narrow the relevant transforms; they never become broad network allow rules. The worker and content cleaner load the same generated policy, whose bytes are hashed into the build identity. Malformed generated data disables cleaning instead of restoring an older policy without those exceptions.

Several deliberate compatibility reductions remain:

- `analytics_trace_id` is preserved globally because its unanchored exception cannot be represented safely. A complete build rejects this by default. The narrow `--allow-parameter-quarantine analytics_trace_id` option acknowledges only that preserved name; the receipt remains reduced and other required-source gates remain enforced.
- Entity exceptions use conservative DNS-label prefixes `ali`, `ama`, `aud`, `goo` and `upl`. Exact full-label complements exceeded the compiled-regex budget. Some extra tracking parameters are therefore preserved on matching labels.
- The bracket-bearing names `__cft__[0]` and `__xts__[0]` remain supported by JavaScript cleaning but are excluded from native transforms. Chromium escapes removal names in a way that could otherwise cause an ineffective redirect.
- Native cleaning preserves addresses with encoded query keys or bare/empty query components. Chromium can reconstruct retained query components as `key=value`; the JavaScript cleaner can preserve the untouched raw bytes directly.

The declared compiler excludes unsupported regex/inverted parameter names, path-specific removers, remove-all operations and scopes it cannot reproduce. It reports 610 unsupported remover rows, 44 conservatively widened exceptions and one quarantined name. Recognized signed/authentication addresses, sensitive keys and unsubscribe flows are preserved. This is not a general detector for every signature scheme. See [the complete syntax, counters and exception contract](parameters-0.9.md).

## Concrete browser defects repaired

Manual endpoint blocks now include `ws:` and `wss:` handshakes without adding a positive HTTP method condition that could exclude socket traffic. Native handshake behavior still needs target-browser verification.

The old unsubscribe/preferences preservation permission applied to frames at a priority above Strict blocking. A foreign frame could use a matching path to gain unintended permission. All parameter redirects and fixed preservation rules now apply only to GET main-frame navigations, at priority 9. Ordinary header sanitation is at 10. Preserving a functional URL cannot release a cross-site frame or suppress the higher-priority cookie/header policy.

Actual RE2 compilation also exposed failures that JavaScript regex checks and source-length caps missed. The complete fixed preservation set now contains 52 bounded expressions: 49 for authentication, sensitive keys and unsubscribe/preferences paths, plus userinfo, encoded-key and bare-query guards. The maintained parameter compiler uses smaller presence predicates, grouped equivalent path rules and conservative exception predicates. The optional artifact auditor makes this check reproducible against the output a browser would load.

The same audit identified 15 failures in the existing EasyList/EasyPrivacy output. The ABP compiler now splits eligible flat, top-level, unquantified literal alternatives into an exact union of separate rules, retaining every original domain, type, party, method and case condition. Four EasyList source rows produce 72 additional rule outputs; source-row conversion and generated-rule counts remain separate. Eleven EasyList and one EasyPrivacy block rows exceed a conservative counted-repetition expansion budget and are explicitly counted as unsupported. Their repetition constraints are never shortened to force a match. Protecting regex exceptions cannot be silently discarded by these new budgets. The structural check does not replace the real artifact audit.

An adjacent authority defect is also repaired: `||host^|` retains its native URL end anchor instead of being folded into a whole-domain predicate. An end-anchored exception therefore cannot release arbitrary assets, and neither that form nor `||host|` can be promoted to a whole-document exception. Ordinary `||host^` grouping is unchanged.

## Verification and package record

The final integrated suites passed **307 Python tests and 297 Node tests**, with zero failures, cancellations or skips. These are 604 regression cases, not 604 independent attack classes. The production-source build contains **14,113 static rules across 17 rulesets**. All **981 static regexes passed** the independent RE2 audit, including the 801 parameter expressions. The current build leaves 19 regex slots below the 1,000 limit; future source growth must pass the same budget gate before replacing prior output.

| Check or compiled output | Observed result |
| --- | --- |
| Python suite | 307 passed; includes 21 real proxy integration cases, eight added in this revision |
| Browser suite | 297 passed; deterministic compiler, worker, ChromeSetting, DOM and UI models |
| Actual-address/TLS fixtures | Blocked candidates received zero TCP accepts; permitted fallback retained the origin certificate and one resolver lookup |
| Parameter boundary probes | 2,294 modeled destination/subdomain/prefix cases; no mismatch for native-supported names |
| Required sources | Seven selected proxy sources and four browser sources validated; no missing required source or development size override |
| Compiled threat domains | 1,628,452 after list grouping/minimization; IP indicators remain in the proxy feed rather than Chrome host rules |
| Compiled tracker domains | 257,921 |
| Compiled CNAME aliases | 178,125 after grouping/minimization |
| Imported cosmetics | 9,720 scoped and 13,079 generic hide rules; 326 selector exceptions and 167 page exceptions |
| Source-rule regex output | EasyList 80, EasyPrivacy 6; all passed the same RE2 audit |
| PSL regeneration | Matches the 10,470-rule bundled snapshot |
| Wheel install | Version, private initialization, history/transport defaults, empty-cache refusal, indeterminate lookup, new modules and dashboard assets passed in a fresh target |
| Source archive | Required source, tests, browser assets, PSL/notices and documentation present; files match the checkout and exclude runtime state/feed caches |

These groups can overlap; their domain counts must not be summed as a unique global total. Overall conversion remains explicitly reduced only by the reviewed parameter quarantine, within the declared supported syntax. The CNAME publisher-age warning remains visible even though the snapshots were freshly retrieved. Full source hashes, counts, package checks and artifact rule hashes are in [validation-0.9.json](validation-0.9.json). The test commands are:

```sh
PYTHONPATH=src python -B -m unittest discover -s tests -v
node --test --test-reporter=tap tests/browser/*.test.cjs
node scripts/update-psl.mjs --check
node tests/browser/chrome-0.8.mjs --check
python -B scripts/audit-browser-regex.py /absolute/build/chrome
git diff --check
```

The auditor needs the optional developer-only `google-re2==1.1.20251105` package. It does not download that package, access a network or launch a browser. The ordinary test suite does not require it, and the application's runtime dependency graph is unchanged. Exit 2 means unavailable/incomplete, never a pass.

The Python evidence includes actual loopback TCP/TLS behavior. The browser evidence includes deterministic compiler/worker/UI models, 2,294 source-boundary parameter probes with no mismatch for native-supported names, static fixture checks and independent RE2 compilation. These are different evidence classes and are not combined into a browser success-rate claim.

Native Chromium previously failed to start because the environment denied its process-singleton socket. That restriction was not bypassed. Chrome ruleset indexing, real header effects, redirect behavior, native profile-setting precedence, local-model inference and installed native messaging remain unexecuted target qualifications. macOS service operations are mocked. No user browser profile, OS proxy, LuLu/native firewall setting or trust store was changed.

The unchanged locked dependency graph retains the previously documented Tornado advisories imposed by mitmproxy's constraint. No fresh online dependency scan or patched-dependency claim is made here. The existing reachability assessment and open package alerts remain in [requirements/README.md](../requirements/README.md).

## Using the new controls

After a manual source/package upgrade, restart the proxy so it can emit the new authenticated transport acknowledgment. An already running older proxy cannot satisfy 0.9 readiness. Rebuild and reload the companion separately, inspect its coverage receipt and qualify it in a disposable profile before relying on it for sensitive browsing.

For a deliberately restricted proxy setup, select:

```toml
[transport]
profile = "hardened"
connect_ports = [443]
address_guard = true
```

The address guard must report active after restart; a saved selection is insufficient. Add an unusual HTTPS port only when that service is required. Select **Isolated** for a named Chrome site when its compatibility cost is acceptable, and reload for a fresh page. The extension does not automatically revoke established connections.

These controls do not use an LLM to admit traffic. The existing local model remains an explicit, bounded page-review aid. Request admission and rule authority stay deterministic, so model uncertainty, malformed output and page prompt injection cannot create network permissions.

The largest remaining protection gaps require different enforcement boundaries: verified OS-level routing and DNS control, browser handling of first-party storage/fingerprinting, and isolation of authenticated identities. The [release qualification checklist](releasing.md) separates those device/browser tasks from the checks completed for this source update.
