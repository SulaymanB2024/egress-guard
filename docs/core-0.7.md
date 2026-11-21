# Core receipts and the browser bridge in 0.7

Version 0.7 makes the proxy's applied-state report cover live history settings and temporary filtering controls. It also adds a read-only native messaging bridge that can show this report inside the Chrome companion. These changes do not make a regular proxy a device-wide firewall: only applications routed through the proxy receive its filtering.

## Live history settings

The `[logging]` settings now apply to the running ledger. Editing a file is not an acknowledgment: the proxy reports the new policy revision only after the ledger writer has committed its configuration metadata.

```toml
[logging]
history = "none"
retention_days = 7
max_queue = 10000
```

The existing modes remain:

| Mode | Newly retained traffic data |
| --- | --- |
| `full` | One row per decision, with timestamp, canonical host, decision, source and transport. |
| `aggregate` | Daily counts by decision and source. Allowed traffic has no stored host. Blocked traffic retains a host with a daily count. |
| `none` | No new traffic rows. Process counters remain in memory; configuration metadata and the dropped-event counter can still be written. |

Fresh configuration defaults to `none`. Existing explicitly saved `full` or `aggregate` choices remain in effect; choose `none` in that configuration when local domain history is unwanted. Hostnames can contain identifying information even when URLs, cookies and bodies are absent.

A change to any logging setting creates a new admission generation and discards events waiting under the old generation. This includes a batch the writer has already removed from its queue but has not committed. A transition barrier orders the change against database commits, while ordinary request admission uses a separate short lock. After switching to `none`, new traffic is not queued. The writer updates SQLite's mode metadata and signals its acknowledgment before the policy revision becomes applied.

If the writer cannot commit, the new admission mode remains in effect and the configuration remains pending. A more restrictive request therefore does not silently revert to full logging when SQLite is unavailable. The runtime retries the configuration and exposes `logging.applied = false` until the writer acknowledges it.

Already committed rows remain. Changing to `none` does not erase an earlier `events` or `daily` table, its WAL contents, backups, or disk remnants. Ordinary deletion and secure erasure are different operations. A setting change also discards some pre-change queued events by design; it is a privacy boundary, not a promise of lossless analytics.

Authenticated health reports contain a `logging` object alongside the policy revision:

```json
{
  "history": "none",
  "retention_days": 7,
  "max_queue": 10000,
  "applied": true,
  "dropped": 0,
  "decisions": 12
}
```

The browser bridge returns the configuration fields and acknowledgment only. It omits decision and dropped-event counters, individual events, and hostname history.

Listening-port changes require restarting the proxy and dashboard. The runtime reports that configuration as pending instead of acknowledging a port that it has not rebound. A valid logging change in the same file is still applied before that restart requirement is reported.

## Temporary grants and policy revisions

Policy revisions now include effective pause controls and exact-host timed exceptions. Both control files are part of the shared file watcher. The proxy constructs a new policy and swaps it only after its runtime settings can be applied; it no longer mutates live controls separately from the revision.

The dashboard can therefore distinguish “saved pause or exception” from “proxy acknowledged this revision.” Expiration is still checked at decision time. An expired grant is ineffective without requiring another file write or watcher tick. Threat and manual block precedence stays in force.

Invalid or unbounded control timestamps do not authorize an exception. Equivalent malformed representations do not become valid policy just because a file can be parsed as JSON.

The dashboard's domain lookup now uses the same explanation semantics as `egress-guard check`: a known block can be reported with incomplete feed coverage, but an otherwise allowed target is `indeterminate` when an enabled feed is missing. `indeterminate` is a coverage statement, not an assertion that the domain is malicious.

## Equivalent IP addresses

IPv4-mapped IPv6 forms use their IPv4 policy identity. For example, `8.8.8.8`, `::ffff:8.8.8.8`, and `[::ffff:808:808]` receive the same IP-feed and resolver-rule decision. Existing verified snapshots containing a mapped spelling remain enforceable during migration.

Legacy numeric host spellings such as `0x08080808`, shortened IPv4 notation, or octal-looking dotted IPv4 are refused as invalid targets. Egress Guard does not ask the resolver to interpret these ambiguous spellings and then treat them as ordinary DNS names. Legitimate DNS names such as `0x8.example` remain valid.

This is an IP policy consistency fix. It does not infer a hostname from an arbitrary IP, inspect encrypted request paths, or prevent an allowed server from acting as a relay. IP-based resolver decisions do not advertise a timed host exception that the domain-only control API cannot create.

## Background service readiness

`egress-guard start` checks the authenticated proxy and dashboard on every successful startup, including when launchd already has the jobs loaded. A loaded job alone is insufficient.

The dashboard check uses its existing challenge and installation-key proof. It does not create a dashboard session, issue a browser login token, or open a browser. If either required worker fails its check, new setup changes are rolled back; preexisting jobs and definitions are preserved. The scheduled feed-refresh job is still governed by its launchd definition, not claimed to have completed a refresh during this readiness check.

The lifecycle tests use temporary files and mocked launchctl operations. Real macOS launchd behavior still needs a target-machine release check; this change does not authorize or perform system routing or trust-store changes.

## Read-only Chrome native messaging

The host name is `org.egress_guard.receipts`. Registration is optional and explicit. The companion should call it from its extension service worker using `runtime.sendNativeMessage`, which starts a one-request host process. Content scripts must not forward arbitrary objects to this bridge.

Install Egress Guard into the Python environment that will remain available to Chrome. Then copy the exact extension ID shown in `chrome://extensions` and register it:

```sh
egress-guard native-host register --extension-id YOUR_32_CHARACTER_EXTENSION_ID --browser chrome
```

The placeholder must be replaced with an actual 32-character ID using letters `a` through `p`. Wildcards, URLs, and arbitrary executable paths are not accepted. `--browser chromium` selects Chromium's standard user location instead.

Registration writes a fixed launcher in the current Egress Guard state directory and a private manifest in the browser's standard per-user `NativeMessagingHosts` directory. The launcher pins the current Python interpreter, Egress Guard state path, and configuration path, and runs Python with `-I -B`. Chrome's manifest lists one exact extension origin. The host also checks the origin passed by Chrome against its private registration receipt before reading a message.

Registration does not start the proxy, fetch feeds, create a dashboard identity key, change routing, or install a certificate. Running the CLI from an uninstalled source checkout is insufficient for the isolated launcher: install the package into the selected environment first.

For removal, use the same installed environment and state/configuration selection:

```sh
egress-guard native-host unregister --extension-id YOUR_32_CHARACTER_EXTENSION_ID --browser chrome
```

Removal checks that the files still match this registration. Changed or foreign files are preserved rather than guessed at. Use one extension/browser registration at a time; unregister before changing its ID, browser, interpreter, or pinned configuration path. Custom browser user-data directories, Chrome for Testing, Firefox native manifests, and Windows registration are not implemented by this setup command.

### Protocol

The request contains exactly two fields:

```json
{"schema":1,"command":"status"}
```

`capabilities` is the only other command. There are no command arguments, request URLs, page content, paths, shell commands, exception grants, or policy mutations. Unknown fields and commands are rejected without echoing their values. The host processes one message and exits, so clients should use `sendNativeMessage`, not a persistent `connectNative` subscription.

The response envelope is:

```json
{
  "schema": 1,
  "ok": true,
  "product": "egress-guard",
  "version": "0.7.0",
  "capabilities": {
    "read_only": true,
    "policy_status": true,
    "health": true,
    "browser_profile_binding": false,
    "device_wide_enforcement": false,
    "mutations": false
  }
}
```

For `status`, the envelope also contains:

| Field | Meaning |
| --- | --- |
| `status.checked_at` | Unix time when the local receipt was assembled. |
| `status.proxy_ready` | Whether the proxy answered the installation-key challenge and reported ready. |
| `status.policy.saved_revision` | Revision calculated from saved policy and effective controls. |
| `status.policy.applied_revision` | Authenticated runtime revision, or `null`. |
| `status.policy.applied` | Saved revision matches the runtime, no update is pending, and logging settings are acknowledged. |
| `status.policy.pending` | Saved and applied state do not yet agree, or a required acknowledgment is absent. |
| `status.policy.degraded` | Missing/last-good coverage, a runtime degradation, or an unapplied saved configuration. |
| `status.policy.complete` | Saved and reported runtime policy both have complete enabled-feed coverage. |
| `status.policy.coverage` | Feed identifiers mapped to their saved policy coverage state. |
| `status.logging.saved` | Desired `history`, `retention_days`, and `max_queue`. |
| `status.logging.runtime` | The same fields plus `applied`, or `null` without an authenticated report. |

The receipt describes shared local proxy state. It does not establish which browser profile sent it, whether that profile is routed through the proxy, or whether other applications are filtered. Several browser profiles can share the same installed extension ID. Keeping this protocol read-only prevents an extension in one profile from granting a machine-wide exception on behalf of another.

The wire format follows [Chrome's native messaging protocol](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging): UTF-8 JSON with a four-byte length in native byte order. Egress Guard imposes tighter application limits: 8 KiB inbound, 64 KiB outbound, nesting depth four, and five seconds total to read a request. The JSON decoder rejects duplicate fields and non-finite numbers. Status queries use bounded loopback health checks. The host emits only framed protocol output on stdout; failures use generic errors and do not expose local file contents or secret values.

Read-only health checks do not initialize missing state or trigger first-use identity-key creation. If the installation is unavailable or an expected runtime report cannot be authenticated, the extension receives unavailable/pending state. It must not replace that with an optimistic “protected” indicator.

### Qualification and regression coverage

Targeted tests exercise held and queued ledger batches across privacy transitions, failed metadata commits, restored aggregation/full modes, mapped-IP feed matching, ambiguous numeric targets, grant revisions, incomplete-feed explanations, and existing-job readiness. A real mitmdump loopback fixture changes `history` to `none`, waits for the authenticated revision, sends additional requests, and verifies that no additional traffic rows appear.

Native host tests use temporary home/state directories and in-memory or socket-pair framing. They cover exact-origin admission, foreign-registration preservation, size and read-time bounds, unsupported commands and extra fields, one-frame behavior, and omitted history/counters. Dashboard readiness is also checked against the real loopback dashboard challenge handler.

An installed package launched by Chrome on macOS or Linux still needs end-to-end browser qualification. These tests do not claim to have installed a native host into the developer's real browser, exercised macOS system settings, or established device-wide routing.
