# Third-party notices

The application code is MIT licensed. Downloaded feeds retain their own licenses and are not bundled in source or wheel releases. A locally built Chrome browser companion (`dist-browser/chrome`, never committed) does contain rulesets derived from the feeds below; see the browser companion section.

| Component | Role | License/source |
| --- | --- | --- |
| mitmproxy 12.3.1 | Local proxy transport | [MIT](https://github.com/mitmproxy/mitmproxy/blob/main/LICENSE) |
| HaGeZi DNS Blocklists | Ad/tracker, threat-intelligence and encrypted-DNS server data fetched at runtime; compiled into a locally built Chrome companion | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| AdGuard CNAME trackers | Exact alias data fetched at runtime; compiled into a locally built Chrome companion | [MIT](https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE) |
| URLhaus, via malware-filter `urlhaus-filter` | Malware-distribution hosts and IP addresses fetched at runtime | List: [CC0-1.0 and MIT](https://gitlab.com/malware-filter/urlhaus-filter#license); URLhaus data: [CC0](https://urlhaus.abuse.ch/) (abuse.ch does not endorse the republished list). Its popular-domain exclusions use Tranco (MIT), Cisco Umbrella and Cloudflare Radar rankings. |
| Phishing Army | Phishing domains fetched at runtime | [Usage and licensing](https://phishing.army/license/): no restriction added by Phishing Army; generator code GPL-3.0. The list aggregates [upstream sources](https://phishing.army/sources/) whose own terms continue to apply, which matters for commercial use or redistribution. |
| Thinkst Canarytokens | Optional remote history service | [Project](https://github.com/thinkst/canarytokens), [service terms](https://canarytokens.org/nest/legal) |
| SponsorBlock community timings | Optional, explicit video hash-prefix lookup and local timing export | Data: [CC BY-NC-SA 4.0](https://github.com/ajayyy/SponsorBlock/wiki/Database-and-API-License), [service terms](https://gist.github.com/ajayyy/9e8100f069348e0bc062641f34d6af12) |

## Browser companion builds

`scripts/build-browser.mjs` compiles the proxy's verified HaGeZi (GPL-3.0) and AdGuard CNAME (MIT) snapshots into Chrome `declarativeNetRequest` rulesets. Both licenses permit this. The repository holds only the compiler and a small hand-written fixture (`tests/browser/fixtures/feeds`), not list data. Each build writes `NOTICE.txt` next to the rulesets with every source URL, license, entry count, publication time and SHA-256. Using a build yourself needs nothing further. Anyone who passes a build on must include that notice, the GPL-3.0 text and the list sources, as GPL-3.0 requires for the HaGeZi-derived rulesets.

Each user's installation downloads these lists directly from their publishers for local filtering; nothing is mirrored or redistributed by this project. Retain upstream attribution and licenses if redistributing downloaded feed caches. Release archives intentionally omit those caches and all device state.

SponsorBlock timing data is not bundled. Its noncommercial, attribution and share-alike terms apply separately from this application's MIT code license. Exports retain the provider, license link, retrieval time and description of format changes. Preserve that information when sharing exports; the code license does not relicense community data.

The reference screenshots under `docs/design/references` illustrate AdGuard, Objective-See and Mullvad interfaces for design review. Their copyrights remain with those upstream owners; the application's MIT license does not apply to those images. Sources and uses are listed in [DESIGN_REFERENCES.md](DESIGN_REFERENCES.md).
