# Dashboard review

These captures use isolated, empty local state. Missing feeds, an inactive proxy and unregistered optional canaries are reported directly. No real traffic, credentials or device status appear in them.

| Width | Initial package | Release |
| --- | --- | --- |
| 390 px | [Before](screenshots/before-390.jpg) | [After](screenshots/first-run-390.jpg) |
| 1440 px | [Before](screenshots/before-1440.jpg) | [After](screenshots/first-run-1440.jpg) |

Both widths fit without horizontal scrolling. The release states per-application scope, gives explicit setup/recovery guidance, and explains that canaries are optional. The isolated browser flow exercised hostname lookup, manual block confirmation and removal. Native browser input became unreliable during the later phone control check; the phone layout and confirmation state were inspected, and HTTP/control regressions cover the mutations separately.

The initial-package render fixture permits top-level navigation to its public document, matching the release's narrow navigation fix. API requests retain their authentication and cross-site checks.

![Release dashboard at 1440 px](screenshots/first-run-1440.jpg)
