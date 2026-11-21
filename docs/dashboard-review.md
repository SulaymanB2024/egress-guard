# Dashboard review

## 0.4 outcome dashboard (2026-11-20)

The 0.3 dashboard was a status checklist: equal-weight cards, a column of "Needs attention" pills and no numbers. It never answered "what did this block for me today?". The redesign leads with that answer and folds health into one line.

What changed, top to bottom:

- **Health line.** One calm sentence when everything is fine ("Protected · policy applied · feeds updated 2 h ago"). Stale feeds turn the dot amber and are named in the line. When protection is not running the line turns red, the detail panel opens by itself and numbered setup steps appear. A proxy footprint (memory, uptime) joins the line only when the proxy reports it.
- **Blocked today.** One large number, its share of all connections, and the change against the same elapsed time yesterday. Malware and phishing stops get their own red callout with the hostnames. A week with none says so in one quiet line.
- **Timeline.** Stacked hourly (24 h) or daily (7 d) bars, blocked at the base. Hover or arrow keys give exact counts. A hidden table carries the same data for screen readers.
- **What was blocked.** Counts by reason (malware and phishing, ads and trackers, cloaked CNAME trackers, your block rules) and the top blocked domains, both following the time range.
- **Activity.** A hostname list in mono with decision, plain-language reason, relative time and a row action (Allow…, Block…, Unblock…) that checks policy first. The search field filters as you type; Enter runs the domain check.

Every figure comes from `GET /api/insights`, which reads the local ledger read-only. The proxy only sees hostnames, so the page never shows bytes or time saved. History modes have their own states: `full` (everything above), `aggregate` (UTC-day totals, no hourly chart, per-day activity tallies) and `none` (says history is off and how to turn it on; the domain check still works).

Captures use isolated temp state and a synthetic ledger: `.test` hostnames plus well-known public tracker hostnames. No real browsing data appears.

| State | Width | Before (0.3) | After light | After dark |
| --- | --- | --- | --- | --- |
| Populated | 1440 px | [before](screenshots/before-full-1440-light.jpg) | [light](screenshots/after-full-1440-light.jpg) | [dark](screenshots/after-full-1440-dark.jpg) |
| Populated | 390 px | [before](screenshots/before-full-390-light.jpg) | [light](screenshots/after-full-390-light.jpg) | [dark](screenshots/after-full-390-dark.jpg) |
| New install | 1440 px | [before](screenshots/before-empty-1440-light.jpg) | [light](screenshots/after-empty-1440-light.jpg) | [dark](screenshots/after-empty-1440-dark.jpg) |
| New install | 390 px | [before](screenshots/before-empty-390-light.jpg) | [light](screenshots/after-empty-390-light.jpg) | [dark](screenshots/after-empty-390-dark.jpg) |
| Aggregate history | 1440 px | | [light](screenshots/after-aggregate-1440-light.jpg) | |
| History off | 1440 px | | [light](screenshots/after-none-1440-light.jpg) | |

1440 px captures come from headless Firefox through Marionette; 390 px captures from headless Chrome with CDP device metrics (Firefox will not render narrower than about 500 px). Both widths fit without horizontal scrolling. References are logged in [DESIGN_REFERENCES.md](../DESIGN_REFERENCES.md).

![Outcome dashboard at 1440 px](screenshots/after-full-1440-light.jpg)

## 0.3 release

These captures use isolated, empty local state. Missing feeds, an inactive proxy and unregistered optional canaries are reported directly. No real traffic, credentials or device status appear in them.

| Width | Initial package | Release |
| --- | --- | --- |
| 390 px | [Before](screenshots/before-390.jpg) | [After](screenshots/first-run-390.jpg) |
| 1440 px | [Before](screenshots/before-1440.jpg) | [After](screenshots/first-run-1440.jpg) |

Both widths fit without horizontal scrolling. The release states per-application scope, gives explicit setup/recovery guidance, and explains that canaries are optional. The isolated browser flow exercised hostname lookup, manual block confirmation and removal. Native browser input became unreliable during the later phone control check; the phone layout and confirmation state were inspected, and HTTP/control regressions cover the mutations separately.

The initial-package render fixture permits top-level navigation to its public document, matching the release's narrow navigation fix. API requests retain their authentication and cross-site checks.
