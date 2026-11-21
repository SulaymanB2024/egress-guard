# Visible TLS hostname enforcement in 0.8

Egress Guard now checks the server name visible in an initial TLS ClientHello as well as the destination named in HTTP CONNECT. Both names must independently pass the current policy before the proxy opens the upstream TCP connection. The original TLS bytes continue to the origin unchanged; there is no TLS termination, replacement certificate, trust-store change or decrypted-content inspection.

This strengthens a concrete boundary in the regular proxy. For example, a client can ask the proxy to connect to an IP address while sending `tracker.example` as its TLS server name. Previously, the IP address received a policy decision but that visible tracker hostname did not. Version 0.8 checks both. It also checks a different visible hostname behind an otherwise permitted CONNECT hostname.

## Decisions and exceptions

The existing `Policy.decision` function makes each decision. Threat feeds, manual rules, encrypted-DNS rules, tracker lists, exact CNAME lists, explicit safety exceptions and temporary controls retain their existing precedence. This release does not add an exception based on a name mismatch.

| CONNECT destination | Visible TLS name | Result |
| --- | --- | --- |
| Blocked | Any | CONNECT is denied before TLS begins. |
| Allowed | Blocked | The tunnel closes after the ClientHello is inspected, before an upstream connection opens. |
| Allowed | A different allowed name | Original TLS passes through. A mismatch alone is not a block. |
| A name with a temporary tracker grant | Another listed tracker without its own applicable permission | The second name is blocked. A grant does not transfer across names. |
| Allowed | Threat or manual-block target during an ad-filter pause | The second name is blocked under the ordinary policy. |
| Allowed | No SNI extension | The original CONNECT destination supplies the hostname decision. |
| Allowed | ECH outer name | Only the visible outer name and CONNECT destination can be checked. The encrypted inner name is unavailable. |

The CONNECT destination is checked again when the initial handshake completes. A policy update or expiring grant that takes effect while a client is still sending its first handshake therefore affects admission. After admission, the TCP stream remains opaque; subsequent requests on that stream are outside this initial-handshake check.

## Why the implementation owns the initial tunnel bytes

The proxy retains its required regular mode, loopback listener, ignored TLS streams and lazy upstream connection strategy. Mitmproxy documents that the successful-CONNECT hook may run before an upstream connection exists when using the lazy strategy. That creates the opportunity to reject a visible TLS name without contacting its destination. See [mitmproxy's HTTP connection hooks](https://docs.mitmproxy.org/stable/api/events.html#http-events).

`TunnelGuard` in `src/egress_guard/addon.py` takes responsibility for the initial protocol decision before mitmproxy's default classifier runs. Merely returning from an addon hook to wait for another byte would be insufficient: the pinned transport's default TLS prefix classifier treats an initial write shorter than three bytes as non-TLS. The guard holds such a prefix until it can identify the handshake or another protocol.

The guard accepts a ClientHello split across TCP reads and TLS records. It bounds the bytes retained for inspection to 32 KiB and permits at most 32 data reads while waiting for the initial hello. An incomplete hello at either bound closes the connection. A complete hello followed in the same read by additional encrypted data is checked and relayed without treating the later data as part of the hello limit. TLS-shaped messages that the parser cannot accept, a different initial handshake message type, and ambiguous or invalid SNI extensions close instead of falling back to raw forwarding.

After admission, the guard hands the original buffered bytes and subsequent data to an ignored TCP layer. It does not reconstruct a ClientHello, change its extension order, remove ECH, rewrite SNI, or collect a TLS fingerprint. The byte/read limits can refuse unusually large or excessively fragmented legitimate handshakes; they are explicit resource bounds, not a claim to accept every future TLS handshake size. Idle connections continue to use the transport's ordinary connection lifecycle.

## Plaintext compatibility mode and local destinations

Visible-SNI policy checks remain active when `[risk] block_plaintext_credentials = false`. The setting permits recognizable non-TLS protocols through an admitted CONNECT tunnel, so the guard forwards those protocols after rechecking the CONNECT destination. It still inspects a connection that begins as TLS and holds ambiguous short TLS prefixes until the protocol can be decided.

The existing exemption for plaintext connections to numeric loopback destinations remains. A connection to loopback that begins with TLS still receives the visible-SNI check. This avoids using loopback authority as an automatic exception for a listed visible hostname.

With plaintext protection enabled, non-loopback CONNECT tunnels still require an acceptable initial TLS ClientHello. A protocol that starts in plaintext and upgrades to TLS later, such as STARTTLS, remains opaque in the compatibility mode. This release does not implement an application-specific STARTTLS parser.

## Privacy and protection limits

No network lookup, cloud inference call or additional resolver is used to classify the ClientHello. The guard reads the same visible hostname metadata that is already present on the proxied connection. The inspection buffer is discarded on admission, refusal or disconnect. It does not store the raw handshake.

Fresh configurations continue to use `history = "none"`. If the user has explicitly enabled full or aggregate traffic history, a refused visible TLS name can appear as a blocked domain with its ordinary policy source and `connect` transport. There is no separate allowed-SNI event, and neither handshake contents nor encrypted traffic bodies are added to the ledger. Previously stored history is not erased by this feature or by choosing `history = "none"`.

Encrypted ClientHello protects the real server name inside an encrypted inner message and can expose a different public outer name. Version 0.8 applies policy to the visible name; it does not infer, decrypt or authenticate an inner hostname. It does not disable ECH to increase visibility. See [RFC 9849, section 6.1](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1).

The two names are client-supplied admission inputs, not proof of the final application destination. TLS certificate validation remains with the original client. An allowed relay, later requests inside an admitted encrypted connection, ECH-hidden names, non-TLS upgrades, and traffic that never uses this proxy retain the documented coverage limits. Direct UDP/QUIC is not brought into the regular HTTP proxy by this change. This feature does not establish a boundary against malicious software running as the same local user or make the proxy a device-wide firewall.

Live CNAME resolution remains separate from enforcement. The existing `cname-check` is a diagnostic and does not bind the eventual upstream connection to the DNS answer it inspected. Adding that binding would require retaining terminal addresses, dealing with address selection and split DNS, and qualifying the real macOS resolver path; the visible-SNI check does not claim to solve those problems.

## Validation

The focused suite comprises ten command-level guard/policy tests in `tests/test_tunnel.py` and thirteen real proxy integration tests in `tests/test_addon.py`. The transport tests use temporary application state, fixture blocklists, a local HTTP origin and a local TLS origin. The fixture redirects only a fixed set of test authorities to loopback; it rejects every other target. No operating-system proxy setting, certificate trust store or browser profile is modified.

Six new integration cases cover:

- Blocked visible names behind allowed DNS, IP and loopback CONNECT destinations, with zero origin TCP accepts.
- Threat and manual blocks during pauses and grants, including an allowed paused tracker for comparison.
- An exact-host grant that permits that hostname but does not transfer to another visible name.
- Continued SNI checking when plaintext compatibility is enabled, while permitted raw HTTP still works.
- Tiny first writes and a handshake split across TLS records, followed by a successful origin-verified TLS request with the exact original certificate.
- A changed CONNECT rule applied while the initial ClientHello is incomplete, refusing the completed handshake before origin contact.

The command-level cases also cover missing SNI, duplicate/ambiguous/malformed SNI, oversized or over-fragmented incomplete handshakes, disconnect cleanup, and a complete hello followed by a large encrypted-data fragment. One case includes an opaque ECH extension and asserts that only its outer name is inspected; it is not an end-to-end ECH negotiation or compatibility qualification.

The tests exercise the pinned mitmproxy transport on the available development host. They do not qualify a real macOS Network Extension, the user's browser routing, real-site behavior, or every browser's ECH implementation. Rerun the transport regressions when changing the pinned mitmproxy version because the guard uses its protocol-layer interfaces.
