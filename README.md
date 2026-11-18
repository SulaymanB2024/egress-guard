# Egress Guard

Local ad, tracker and threat filtering for macOS, with a portable Python core.

Egress Guard runs a loopback proxy and a private control dashboard. HTTPS keeps the origin server's certificate and encrypted contents. No root daemon, browser certificate trust, or account credentials are needed for filtering.

**0.1.0 is an alpha release.** The filtering transport has been exercised on macOS ARM64 with Python 3.12. Native proxy transactions are covered by mocked macOS commands; this release has not been tested on every Mac configuration. The core has no macOS routing dependency, but Windows transport has not been tested. Windows dashboard authentication and verified health are unavailable until a private ACL-backed identity store is implemented. Guided setup and native canary notifications are macOS features.

## What it does

- Blocks domains from HaGeZi's ad/tracker and threat feeds, plus curated, exact-match AdGuard CNAME aliases.
- Updates feeds daily when macOS background services are enabled. Invalid, truncated or failed downloads retain the last good copy; the dashboard shows publication age separately from download success.
- Refuses external plaintext HTTP requests carrying cookies or authorization headers before forwarding them.
- Provides an authenticated local dashboard with decision explanations, temporary exact-host exceptions, ad-filter pauses, manual rules and local activity.
- Monitors canaries you explicitly register with Thinkst and sends batched macOS notifications. Registration verifies access and establishes a history baseline without exposing token values in logs or the dashboard.
- Leaves system-wide routing unchanged. Automatic native activation is withheld until endpoint ownership can be guaranteed across logout, crashes and reboot. Inspection and ownership-preserving recovery are retained.

## Install on macOS

Requirements: Python 3.12 or newer, an ordinary macOS account, and Internet access to install the pinned transport and download filter data. Do not run the installer with `sudo`.

1. Download the source archive and `SHA256SUMS` from [Releases](https://github.com/SulaymanB2024/egress-guard/releases). Check the archive with `shasum -a 256`, then extract it.
2. From the extracted directory, run:

```sh
sh scripts/install-macos.sh
```

The installer creates a private virtual environment and prints its command path. It changes no proxy settings. If your default Python is older, select a suitable interpreter with `EGRESS_GUARD_PYTHON=/path/to/python3.12`.

```sh
EG="$HOME/Library/Application Support/Egress Guard/venv/bin/egress-guard"
"$EG" init
"$EG" refresh
"$EG" start
"$EG" open
```

The dashboard opens on this machine only. Configure individual proxy-aware applications for `http://127.0.0.1:18080`. For example:

```sh
curl --proxy http://127.0.0.1:18080 https://example.com/
```

You can inspect existing system routing without changing it:

```sh
/usr/sbin/networksetup -listallnetworkservices
"$EG" proxy inspect --service "Wi-Fi"
```

This alpha does not enable a persistent machine-wide proxy. A per-user process cannot reserve an unprivileged port after its login session ends, while a network service's proxy setting may survive. On a Mac with untrusted local accounts, do not rely on an unattended unprivileged listener as a persistent routing endpoint.

## Restore or stop

```sh
"$EG" proxy restore
"$EG" stop
```

`stop` restores any pre-existing receipt-owned proxy settings before stopping its services. Recovery may require administrator approval; if declined or restoration fails, it leaves the proxy available. Logs and registrations are retained. A disabled proxy's dormant server fields may remain at loopback because macOS cannot rewrite those fields without briefly enabling that server; the result reports those fields.

For recovery without the CLI, turn off the matching `127.0.0.1:18080` HTTP and HTTPS settings for the affected service in macOS Network settings. Preserve any settings another application has since installed.

## Portable use

```sh
python -m pip install ./egress_guard-0.1.0-py3-none-any.whl
egress-guard init
egress-guard refresh
egress-guard run
```

Configure individual clients for `http://127.0.0.1:18080`. On macOS/Linux, run `egress-guard dashboard` in another terminal and `egress-guard open` to access controls. The dashboard uses port `18081` by default. A fresh install cannot start filtering with an empty or unverified feed cache. On Windows, `doctor` reports identity verification unavailable and the dashboard refuses to start; it never substitutes an unsigned readiness response.

## Canary registration

Create a canary through [Thinkst Canarytokens](https://canarytokens.org/). Thinkst receives and stores trigger history. This application polls that history; it does not create provider accounts, change existing email/webhook settings, or provision cloud credentials automatically.

Import the management token, management auth value and a placement label as a JSON object through stdin:

```sh
egress-guard canary-import < /path/to/private-token.json
```

The JSON fields are `label`, `token`, `auth_token`, and optional `kind`. Keep this file private and outside repositories and backups. Do not put management credentials in command arguments. The dashboard service performs polling while logged in. Provider-side logging can delay AWS alerts; the Mac must be awake and online to display them.

## Coverage

Filtering applies to clients using this proxy. Existing encrypted tunnels, applications that bypass proxy settings, opaque UDP, and ads sharing a content origin need other controls. Browser cosmetic filtering remains useful: Chrome's [uBlock Origin Lite](https://github.com/uBlockOrigin/uBOL-home) and maintained Firefox/Brave protections provide capabilities outside a domain proxy. No certificate is installed or trusted. The transport may create unused private CA files inside its private configuration directory.

Domain activity is stored locally with bounded buffering and retention. Request paths, bodies, cookies, authorization values and canary management keys are excluded from the activity log. A long storage outage can exhaust the bounded queue; health reports unavailable storage rather than claiming complete logging.

See [architecture and threat model](docs/architecture.md), [security review and fixes](docs/security-review.md), [research and next steps](docs/research.md), [security policy](SECURITY.md), and [third-party notices](THIRD_PARTY_NOTICES.md).

## Dashboard

See the [390 px and 1440 px review](docs/dashboard-review.md). These first-run captures use empty, isolated state.

![First-run dashboard](docs/screenshots/first-run-1440.jpg)

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md). Tests use temporary state and mocks for native settings. Do not run tests against a live installation or submit real credentials, traffic logs, private machine paths or generated feed caches.
