# Third-party notices

The application code is MIT licensed. Downloaded blocking feeds retain their own licenses and are not bundled in source or wheel releases. The Public Suffix List is bundled separately under MPL-2.0. A locally built Chrome browser companion (`dist-browser/chrome`, never committed) contains rulesets, parameter policy and generic/scoped cosmetic data derived from the feeds below; see the browser companion section.

| Component | Role | License/source |
| --- | --- | --- |
| mitmproxy 12.3.1 | Local proxy transport | [MIT](https://github.com/mitmproxy/mitmproxy/blob/main/LICENSE) |
| Public Suffix List | Complete pinned ICANN and PRIVATE suffix data in browser source and generated scope module | [MPL-2.0](https://mozilla.org/MPL/2.0/); [upstream source](https://publicsuffix.org/list/public_suffix_list.dat); original notices in `browser/vendor/` |
| HaGeZi DNS Blocklists | Ad/tracker, threat-intelligence and encrypted-DNS server data fetched at runtime; compiled into a locally built Chrome companion | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| AdGuard CNAME trackers | Exact alias data fetched at runtime; compiled into a locally built Chrome companion | [MIT](https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE) |
| URLhaus, via malware-filter `urlhaus-filter` | Malware-distribution hosts and IP addresses fetched at runtime | List: [CC0-1.0 and MIT](https://gitlab.com/malware-filter/urlhaus-filter#license); URLhaus data: [CC0](https://urlhaus.abuse.ch/) (abuse.ch does not endorse the republished list). Its popular-domain exclusions use Tranco (MIT), Cisco Umbrella and Cloudflare Radar rankings. |
| Phishing Army | Phishing domains fetched at runtime | [Usage and licensing](https://phishing.army/license/): no restriction added by Phishing Army; generator code GPL-3.0. The list aggregates [upstream sources](https://phishing.army/sources/) whose own terms continue to apply, which matters for commercial use or redistribution. |
| Thinkst Canarytokens | Optional remote history service | [Project](https://github.com/thinkst/canarytokens), [service terms](https://canarytokens.org/nest/legal) |
| SponsorBlock community timings | Optional, explicit video hash-prefix lookup and local timing export | Data: [CC BY-NC-SA 4.0](https://github.com/ajayyy/SponsorBlock/wiki/Database-and-API-License), [service terms](https://gist.github.com/ajayyy/9e8100f069348e0bc062641f34d6af12) |

## Browser companion builds

`scripts/build-browser.mjs` compiles the proxy's verified HaGeZi (GPL-3.0), AdGuard CNAME (MIT), URLhaus via malware-filter (CC0-1.0 and MIT; host names only) and Phishing Army snapshots into Chrome `declarativeNetRequest` rulesets. HaGeZi, AdGuard and URLhaus licenses permit this. Phishing Army adds no restriction of its own, but its upstream sources' terms continue to apply; check them before passing a build on, especially commercially. The proxy's HaGeZi encrypted-DNS list is not compiled.

The companion's fixed ad-slot selectors (`browser/core/cosmetic.js`) are a first-party list under the project's MIT license. Builds additionally compile a restricted subset of EasyList/EasyPrivacy generic ID/class rules, scoped selectors (including bounded native `:has()` and entity scopes), exact-selector exceptions and cosmetic page exceptions into `core/cosmetic-data.js`; that generated data keeps the upstream source license. The index and selector/compiler code are first-party implementation, not a relicensing of the imported filter data.

The Chrome build also downloads, at build time and into its own cache (`<data>/browser-filters/`, never the proxy's feed cache), and converts into `declarativeNetRequest` rules:

| Component | Role | License/source |
| --- | --- | --- |
| EasyPrivacy | Network (URL) filters, supported generic/scoped cosmetic rules and exceptions | Dual [GPL-3.0 or CC BY-SA 3.0](https://easylist.to/pages/licence.html); used under GPL-3.0 |
| EasyList | Network (URL) filters, supported generic/scoped cosmetic rules and exceptions | Dual [GPL-3.0 or CC BY-SA 3.0](https://easylist.to/pages/licence.html); used under GPL-3.0 |
| AdGuard CNAME trackers, disguised click-throughs | Host names whose cookies are stripped on a redirect hop (never blocked) | [MIT](https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE) |
| AdGuard/uBO – URL Tracking Protection | Bounded query-parameter removers and conservatively preserved exceptions, compiled into DNR rules and shared runtime policy | [GPL-3.0](https://github.com/uBlockOrigin/uAssets/blob/master/LICENSE); [canonical source](https://github.com/uBlockOrigin/uAssets/blob/master/filters/privacy-removeparam.txt) |

Each download is checked for HTTPS origin, size and source identity. EasyList/EasyPrivacy require their `[Adblock Plus]` header, exact title, license line and minimum count. The domain source requires valid host names. URL Tracking Protection has a different exact title/license/homepage check and a minimum parameter-rule count; its raw `%timestamp%` template is never presented as a publication date. SHA-256, size, fetch time and available upstream version are recorded in the build's `NOTICE.txt` and coverage metadata.

The built-in tracking-parameter, link-wrapper, cookie-name, surrogate and fingerprinting/session-replay path lists in `browser/core/` and `browser/surrogates/` remain first-party code/data under MIT. Beginning with 0.9, generated parameter rules and `core/param-data.js` also contain data derived from the GPL-3.0 URL Tracking Protection source. The compiler and runtime implementation do not relicense that imported data. Unsupported syntax is excluded or conservatively quarantined, with diagnostics retained in build receipts.

For blocking feeds, the repository holds only compilers and small synthetic fixtures; the separately attributed Public Suffix List is bundled. Each build writes `NOTICE.txt` next to the rulesets with source URLs, licenses, available dates and SHA-256 values. Anyone who redistributes a generated build must retain the upstream notices and satisfy the applicable source and license requirements, including the GPL-3.0 obligations for the HaGeZi-, EasyPrivacy-, EasyList- and URL Tracking Protection-derived data.

Each user's installation downloads blocking lists directly from their publishers for local filtering. Release archives intentionally omit those caches and all device state. The pinned Public Suffix List is an explicit exception: its complete source and generated representation are shipped with preserved upstream notices. Retain the relevant upstream attribution and licenses when redistributing either data set.

The optional on-device classifier uses Chrome's Prompt API. Model weights are managed by Chrome and are not bundled, relicensed or redistributed in this repository. There is no downloaded third-party executable extension code.

SponsorBlock timing data is not bundled. Its noncommercial, attribution and share-alike terms apply separately from this application's MIT code license. Exports retain the provider, license link, retrieval time and description of format changes. Preserve that information when sharing exports; the code license does not relicense community data.

The reference screenshots under `docs/design/references` illustrate AdGuard, Objective-See and Mullvad interfaces for design review. Their copyrights remain with those upstream owners; the application's MIT license does not apply to those images. Sources and uses are listed in [DESIGN_REFERENCES.md](DESIGN_REFERENCES.md).
