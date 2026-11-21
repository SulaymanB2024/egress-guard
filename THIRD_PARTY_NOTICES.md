# Third-party notices

The application code is MIT licensed. Downloaded blocking feeds retain their own licenses and are not bundled in source or wheel releases. The Public Suffix List is bundled separately under MPL-2.0. A locally built Chrome browser companion (`dist-browser/chrome`, never committed) contains rulesets and scoped cosmetic data derived from the feeds below; see the browser companion section.

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

The companion's fixed ad-slot selectors (`browser/core/cosmetic.js`) are a first-party list under the project's MIT license. Builds additionally compile a restricted subset of domain-scoped EasyList/EasyPrivacy cosmetic rules and exceptions into `core/cosmetic-data.js`; that generated data keeps the upstream source license.

The Chrome build also downloads, at build time and into its own cache (`<data>/browser-filters/`, never the proxy's feed cache), and converts into `declarativeNetRequest` rules:

| Component | Role | License/source |
| --- | --- | --- |
| EasyPrivacy | Network (URL) filters, supported scoped cosmetic rules and exceptions | Dual [GPL-3.0 or CC BY-SA 3.0](https://easylist.to/pages/licence.html); used under GPL-3.0 |
| EasyList | Network (URL) filters, supported scoped cosmetic rules and exceptions | Dual [GPL-3.0 or CC BY-SA 3.0](https://easylist.to/pages/licence.html); used under GPL-3.0 |
| AdGuard CNAME trackers, disguised click-throughs | Host names whose cookies are stripped on a redirect hop (never blocked) | [MIT](https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE) |

Each download is checked (HTTPS, size, `[Adblock Plus]` header, title, the licence line, minimum filter count, host-name syntax for the AdGuard list) and recorded with its SHA-256, size, fetch time and upstream version; the build's `NOTICE.txt` lists them. The tracking-parameter, link-wrapper, cookie-name, surrogate and fingerprinting/session-replay path lists in `browser/core/` and `browser/surrogates/` are written for this project (MIT); ClearURLs, Brave, Firefox and AdGuard URL-tracking lists were used only to check coverage, and no data was copied from them. For blocking feeds, the repository holds only the compiler and a small hand-written fixture (`tests/browser/fixtures/feeds`); the separately attributed Public Suffix List is bundled. Each build writes `NOTICE.txt` next to the rulesets with every source URL, license, entry count, publication time and SHA-256. Using a build yourself needs nothing further. Anyone who passes a build on must include that notice, the GPL-3.0 text and the list sources, as GPL-3.0 requires for the HaGeZi-, EasyPrivacy- and EasyList-derived rulesets.

Each user's installation downloads blocking lists directly from their publishers for local filtering. Release archives intentionally omit those caches and all device state. The pinned Public Suffix List is an explicit exception: its complete source and generated representation are shipped with preserved upstream notices. Retain the relevant upstream attribution and licenses when redistributing either data set.

The optional on-device classifier uses Chrome's Prompt API. Model weights are managed by Chrome and are not bundled, relicensed or redistributed in this repository. There is no downloaded third-party executable extension code.

SponsorBlock timing data is not bundled. Its noncommercial, attribution and share-alike terms apply separately from this application's MIT code license. Exports retain the provider, license link, retrieval time and description of format changes. Preserve that information when sharing exports; the code license does not relicense community data.

The reference screenshots under `docs/design/references` illustrate AdGuard, Objective-See and Mullvad interfaces for design review. Their copyrights remain with those upstream owners; the application's MIT license does not apply to those images. Sources and uses are listed in [DESIGN_REFERENCES.md](DESIGN_REFERENCES.md).
