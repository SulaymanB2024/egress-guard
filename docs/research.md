# Research and next work

Reviewed November 18, 2026. These choices describe the current release, not a claim of universal protection.

| Finding | Current response | Primary source |
| --- | --- | --- |
| Regular explicit proxy mode is a robust supported transport; ignored domains preserve TLS rather than requiring browser trust. | Fixed loopback regular mode, lazy connection establishment, ignored TLS hosts and certificate-preservation integration test. | [mitmproxy modes](https://docs.mitmproxy.org/stable/concepts/modes/), [ignored domains](https://docs.mitmproxy.org/stable/howto-ignoredomains/) |
| Trackers can disguise third-party endpoints as first-party CNAME aliases. | Download curated AdGuard aliases as exact names, alongside HaGeZi data. No added DNS query is needed for each request. | [AdGuard CNAME dataset](https://github.com/AdguardTeam/cname-trackers), [Brave's analysis](https://brave.com/privacy-updates/6-cname-trickery/) |
| Local browser-facing services need DNS-rebinding, cross-site and cross-port credential controls. | Exact Host/Origin validation, nonce-authenticated launcher, expiring origin-scoped bearer session and CSRF checks. Cookies are not used for authentication. | [OWASP DNS rebinding](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/21-DNS_Rebinding), [CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| Semantic/vision ad classification is promising research but adds latency, cost and additional handling of page content. | Keep enforcement local and deterministic in this release. Evaluate semantic detectors in an isolated, consented benchmark before sending page data or letting a model block live traffic. | [AdGuard's LLM experiments](https://adguard.com/en/blog/beyond-filter-lists-rethinking-ad-blocking-with-llms.html) |
| Browser-level protections cover cosmetic filtering, fingerprinting and other traffic outside a domain proxy. | Preserve compatibility with maintained browser blockers and document the separate coverage. | [uBO Lite](https://github.com/uBlockOrigin/uBOL-home), [Brave Shields](https://brave.com/shields/) |

## Next work

1. Design an OS-managed routing endpoint with lifetime ownership across boot, logout and service failure before enabling machine-wide routing. Test installation and restoration on supported macOS versions and Intel hardware; add signing/notarization when an appropriate identity is available.
2. Windows and Linux native routing adapters with ownership-preserving rollback and OS-specific integration tests.
3. Benchmark bypasses, first-party ads and breakage against a reproducible local corpus. Track effectiveness separately from rule counts.
4. Evaluate on-device semantic detection and DNS-level integration with explicit resource, privacy and false-positive budgets.
5. Add a signed, reversible application-update channel. Runtime/build hash locks and explicit OSV checks are now available; upstream Tornado advisories remain tracked in the [dependency notes](../requirements/README.md). Current releases are manually installed; feed data does not execute application updates.
