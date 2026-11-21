# Transport controls and actual TCP-address checks in 0.9

Version 0.9 adds two independent, explicit controls for applications using the local proxy: a hardened transport profile and an experimental guard on the numerical address passed to the TCP connection syscall. Defaults preserve existing clients. These controls do not prove that an application uses the proxy or make the device anonymous.

## Configuration and upgrade behavior

New and existing configurations inherit these defaults when no transport section is saved:

```toml
[transport]
profile = "compatible"
connect_ports = [443]
address_guard = false
```

For an explicitly restricted client setup:

```toml
[transport]
profile = "hardened"
connect_ports = [443]
address_guard = true
```

`connect_ports` must contain 1–32 sorted, distinct integer ports between 1 and 65535. An additional required HTTPS port can be declared, for example `[443, 8443]`. The list is enforced only by the hardened profile. Configuration does not accept implicit wildcard ports or per-domain exceptions to these transport floors.

Changing `profile` or `connect_ports` uses the ordinary authenticated policy reload. Changing `address_guard` requires stopping and starting the proxy process. The saved selection remains pending until that restart; the current process keeps its previously acknowledged selection and policy. A combined edit that changes the address guard and the profile therefore waits as a whole. Saving a value alone is never an applied receipt.

An upgrade also requires restarting an already running older proxy. The 0.9 health client requires an authenticated, valid, applied transport receipt before reporting readiness. A transport-less response from an older process does not establish 0.9 readiness.

## What the hardened profile refuses

| Request through the proxy | Compatible profile | Hardened profile |
| --- | --- | --- |
| Non-loopback HTTP | Existing host filtering and optional Cookie/Authorization protection | Refused at request headers, including forms and query tokens without those headers |
| Non-loopback CONNECT to a literal IP | Existing IP-list decision | Refused even when the IP is not listed |
| Non-loopback CONNECT on a port outside `connect_ports` | Existing host decision; unusual ports remain labeled | Refused |
| Non-loopback CONNECT starting with a plaintext protocol | Governed by `block_plaintext_credentials` | Refused, including when that older setting is false |
| Admitted hostname, admitted port, valid initial TLS | Existing authority and visible-SNI checks | Same independent checks, then original TLS passthrough |
| Numeric loopback HTTP or CONNECT | Existing local compatibility | Existing local compatibility, still subject to applicable policy blocks |

Only a numeric loopback target qualifies for the local transport exception. A hostname such as `localhost`, or an arbitrary hostname that resolves to loopback, does not gain that exception. The fixed `http://egress-guard.invalid/health` endpoint remains local to the proxy and reachable while protection is unready.

Threat and manual hostname decisions retain precedence. Tracker pauses, timed grants, local allows and the hostname safety list do not override a hardened transport refusal. The hardened profile does not redirect HTTP to HTTPS, retry a form submission, replay a request body, or infer that a server will support TLS.

A refused request with a declared body closes immediately at the header boundary. Returning an ordinary refusal response can cause the underlying proxy to read the body first, so these cases use the existing immediate flow-kill path. The implementation does not search form fields or inspect body contents for secrets. Mitmproxy documents that `requestheaders` occurs before the request body has been read; see its [HTTP event hooks](https://docs.mitmproxy.org/stable/api/events.html#http-events).

Transport requirements are checked again at initial tunnel admission. A tunnel opened under the compatible profile, but not yet used, cannot retain permission to send plaintext after the hardened profile applies. An already admitted opaque connection is not re-inspected or forcibly disconnected by a later profile edit.

## Experimental address guard

Hostname rules leave a distinct boundary: an allowed hostname can resolve to an IP that appears in an IP-capable threat feed. Version 0.8 evaluated a directly requested IP, but did not independently evaluate a numerical result selected by the TCP connector. The opt-in guard closes that gap for the qualified connector path.

The guard runs at CPython's `socket.connect` audit event. It checks the actual numeric sockaddr presented by the selector connector against the current immutable policy's IP threat entries and, when configured, known encrypted-DNS resolver IPs. IPv4-mapped IPv6 addresses retain the existing canonical identity. An unexpected hostname at this boundary is refused instead of being treated as a checked numerical address. Python documents audit events for both [`socket.connect` and `socket.connect_ex`](https://docs.python.org/3.12/library/socket.html#socket.socket.connect).

No extra DNS query is introduced. The guard does not resolve a name once for checking and then allow the transport to resolve it again. It also does not pin the first resolver answer. A refused numerical candidate raises an ordinary permission error before the TCP syscall; the qualified asyncio connector can continue to the next address. Python describes the address-candidate connection behavior in its [`create_connection` documentation](https://docs.python.org/3.12/library/asyncio-eventloop.html#asyncio.loop.create_connection). The release test exercises this behavior through the pinned mitmproxy process, not only a mocked connector.

The IP check is independent of hostname exceptions. **A listed actual IP blocks even when the CONNECT hostname is an exact built-in safety host.** This can refuse a legitimate hostname on a shared or incorrectly listed address. An exact-host tracker exception is not an IP exception. Conversely, the hardened profile's restriction on literal CONNECT request targets does not apply to a hostname's resolved sockaddr; applying it there would reject every hostname connection.

`Policy.address_decision` handles only numeric IP policy. It does not claim a live CNAME-chain decision. `cname-check` remains diagnostic, and ECH-hidden inner names remain unavailable. The authority and visible outer SNI still receive their independent 0.8 decisions; a name mismatch alone is not rejected and ECH is not removed.

### Activation, ownership and failure

The audit module has no import-time side effect. A proxy start explicitly obtains a single owner lease. With the default disabled selection, no audit hook is installed.

An enabled start checks CPython 3.12 or newer with the GIL enabled, an exact standard Unix selector event-loop type, Linux or macOS, and the pinned mitmproxy 12.3.1 transport. Other runtimes, event loops and connector versions remain unavailable until qualified. The development test run used CPython 3.12.14 on Linux; it did not qualify a native macOS installation.

Activation has two checks. A private event confirms that registration actually reached the hook: earlier hooks can silently veto `sys.addaudithook`. Then the running loop executes bounded IPv4 and, when available, IPv6 socket-connect probes. The guard must intercept each probe with its exact private refusal exception before becoming active. Probe destinations are numeric loopback port zero; a successful qualified probe never reaches the TCP syscall. See Python's [`addaudithook` registration and exception contract](https://docs.python.org/3.12/library/sys.html#sys.addaudithook).

The installed dispatcher remains for the interpreter lifetime. A retiring enabled owner leaves late TCP connections refused until a new explicit owner takes the lease. A competing owner cannot replace or release the existing lease. Repeated hook registration is avoided. Reload workers read the current policy through the owner; there is no captured stale feed snapshot in the callback.

If a selected guard cannot activate, the proxy remains available for its local health endpoint, reports the bounded reason, and refuses proxy traffic. Missing or unusable policy also refuses numerical connection attempts. The audit callback does no DNS lookup, network operation, asynchronous work or history write. It does not save peer IPs, hostnames, URLs or request contents. Its refusal text is fixed.

Audit hooks are **not a sandbox against hostile code running in the interpreter**. Python explicitly documents that limitation. This feature applies to the pinned regular-proxy TCP connector, not native libraries that bypass that connector, other processes, UDP, QUIC, a system DNS provider or a macOS Network Extension. DNS lookups can still occur before an address is denied. An allowed relay or an allowed remote service can still receive data sent by a client.

## Authenticated state, without a routing claim

The proxy adds a `transport` object to its authenticated policy report:

```json
{
  "profile": "hardened",
  "connect_ports": [443],
  "address_guard": {
    "selected": true,
    "state": "active",
    "reason": null
  },
  "scope": "proxy-tcp",
  "applied": true
}
```

The read-only native receipt carries `transport.saved` and `transport.runtime`. The dashboard shows those same saved and running settings. A missing, malformed, contradictory or unavailable runtime report cannot acknowledge saved settings. A matching profile and port list are required as well as the matching address-guard selection. Hook activation alone does not make incomplete feeds complete.

Address-guard states are `disabled`, `active` and `unavailable`. Unavailable reasons are bounded values: `unsupported-runtime`, `ownership-conflict`, `registration-failed`, `self-test-failed`, `ownership-lost` or `stopped`. Private exception text and peer details are not part of the schema.

The receipt attests to the proxy's current reported configuration and runtime state. It does not establish browser-profile binding, OS routing, device-wide coverage, TLS certificate validation by the original client, or a successful connection to a particular destination. A CONNECT allowance in optional local history describes CONNECT admission; a later SNI or socket-address refusal can still prevent that connection. The address callback intentionally does not add per-address history.

Fresh configuration continues to keep no traffic history. Existing explicitly saved full or aggregate history stays as selected, and these features do not erase older records. The guard preserves the original TLS certificate and encrypted bytes; it adds no decryption or trust-store installation.

## Validation and release gates

The focused qualification uses temporary state, local HTTP/TLS origins and the pinned real proxy executable. No browser profile, OS proxy, native filter or trust store is modified. Eighteen added core regression cases cover the transport schema/settings, address-only policy, audit ownership/failure modes, authenticated readiness and the eight new real-proxy scenarios.

The new transport integration cases demonstrate:

- A blocked actual IP receives zero TCP accepts, including behind a built-in safety hostname.
- A denied first address falls through to an allowed second address, with one resolver lookup per requested hostname and the exact original TLS certificate.
- A newly applied IP-feed revision is used by later connection attempts.
- Disabled guard selection preserves the existing compatible behavior.
- Hardened GET, form and chunked/large-body POST requests are refused before origin contact; a body need not be supplied to receive the immediate close.
- Literal CONNECT and non-admitted ports remain refused during grants and pauses; TLS remains mandatory when hardened even if credential-header protection is disabled.
- An explicitly admitted additional port still carries original TLS, and a delayed tunnel sees the newly applied hardened profile.
- Failed guard activation remains signed, unready and refusing; saved guard-selection changes remain pending until restart.

Four audit lifecycle tests run in disposable subprocesses so a permanent audit hook never contaminates the test runner. The existing thirteen proxy integration cases also pass, including fragmented ClientHello handling, authority/SNI policy independence, original-certificate verification and live history acknowledgment. Relevant commands are:

```sh
PYTHONPATH=src:tests python -B -m unittest -v test_address_guard test_configuration test_policy test_tunnel test_transport.TransportPolicyTests test_loopback_clients
PYTHONPATH=src:tests python -B -m unittest -v test_transport.TransportIntegrationTests test_addon
```

Rerun the real transport qualification before changing the pinned connector version. macOS launchd/native routing, real browser routing, real-site compatibility and end-to-end ECH negotiation remain separate release qualifications; this development host did not run them.
