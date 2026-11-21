# Dashboard design references

The public dashboard reuses the local prototype's existing design. The release changes setup guidance, optional-monitor status and control safety. Reference screenshots illustrate upstream products and remain the property of their respective owners.

| Date | Reference | Screenshot | Take | Avoid | Used in | Added by |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-18 | [AdGuard query log](https://adguard.com/en/blog/adguard-home-beta-version-1-0.html) | [Official capture](docs/design/references/adguard-query.png) | Separate a decision from its rule reason. | Client identity the proxy cannot verify. | Activity and domain lookup | Codex |
| 2026-11-18 | [Objective-See LuLu / Netiquette](https://objective-see.org/products/lulu.html#networkMonitor) | [Official capture](docs/design/references/lulu-monitor.png) | Fixed-width destinations and times. | Clipped names and excessive density. | Activity and lookup | Codex |
| 2026-11-18 | [Mullvad connection details](https://mullvad.net/en/help/using-mullvad-vpn-app#connection-details) | [Official capture](docs/design/references/mullvad-connection.png) | Lead with explicit state and nearby scope. | Device-wide coverage claims and unverifiable traffic totals. | Protection overview | Codex |
| 2026-11-20 | Egress Guard dashboard (`src/egress_guard/web/app.css`, accepted) | [Dashboard review](docs/dashboard-review.md) | Paper/ink/forest tokens, forest protection card with mono eyebrow, shield mark. | New palettes or decoration. | Browser popup hero and warning page | Claude |
| 2026-11-20 | [Mullvad connection details](https://mullvad.net/en/help/using-mullvad-vpn-app#connection-details) (logged above) | [Official capture](docs/design/references/mullvad-connection.png) | Lead the popup with the explicit result for this page before any controls. | Totals the extension cannot verify. | Browser popup | Claude |
| 2026-11-20 | [Objective-See LuLu / Netiquette](https://objective-see.org/products/lulu.html#networkMonitor) (logged above) | [Official capture](docs/design/references/lulu-monitor.png) | Monospace endpoints with the list as a separate tag. | Clipped names: endpoints ellipsize with the full value in a tooltip. | Browser popup rows | Claude |
| 2026-11-20 | [AdGuard query log](https://adguard.com/en/blog/adguard-home-beta-version-1-0.html) (logged above) | [Official capture](docs/design/references/adguard-query.png) | Name which list blocked each request. | Rule syntax in the main view. | Browser popup and warning page | Claude |

See the [phone and desktop comparison](docs/dashboard-review.md).
