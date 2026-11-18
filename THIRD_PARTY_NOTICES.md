# Third-party notices

The application code is MIT licensed. Downloaded feeds retain their own licenses and are not bundled in source or wheel releases.

| Component | Role | License/source |
| --- | --- | --- |
| mitmproxy 12.3.1 | Local proxy transport | [MIT](https://github.com/mitmproxy/mitmproxy/blob/main/LICENSE) |
| HaGeZi DNS Blocklists | Ad/tracker and threat data fetched at runtime | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| AdGuard CNAME trackers | Exact alias data fetched at runtime | [MIT](https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE) |
| Thinkst Canarytokens | Optional remote history service | [Project](https://github.com/thinkst/canarytokens), [service terms](https://canarytokens.org/nest/legal) |
| SponsorBlock community timings | Optional, explicit video hash-prefix lookup and local timing export | Data: [CC BY-NC-SA 4.0](https://github.com/ajayyy/SponsorBlock/wiki/Database-and-API-License), [service terms](https://gist.github.com/ajayyy/9e8100f069348e0bc062641f34d6af12) |

Retain upstream attribution and licenses if redistributing downloaded feed caches. Release archives intentionally omit those caches and all device state.

SponsorBlock timing data is not bundled. Its noncommercial, attribution and share-alike terms apply separately from this application's MIT code license. Exports retain the provider, license link, retrieval time and description of format changes. Preserve that information when sharing exports; the code license does not relicense community data.

The reference screenshots under `docs/design/references` illustrate AdGuard, Objective-See and Mullvad interfaces for design review. Their copyrights remain with those upstream owners; the application's MIT license does not apply to those images. Sources and uses are listed in [DESIGN_REFERENCES.md](DESIGN_REFERENCES.md).
