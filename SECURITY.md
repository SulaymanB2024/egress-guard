# Security policy

## Supported release

Version 0.10.x is the current alpha development line. Fixes target this line; consult the release page for published artifacts and the qualification record before upgrading. The application does not execute downloaded application updates automatically.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/SulaymanB2024/egress-guard/security/advisories/new). Avoid public issues for exploitable details or credential disclosures. Include the affected version, operating system, relevant configuration, expected boundary, minimal synthetic reproduction and practical impact. Never include live keys or real browsing logs.

## Security boundaries

- The dashboard must remain authenticated, loopback-only, protected from cross-site requests and DNS rebinding, and unable to execute arbitrary commands.
- Threat-feed and manual security rules must remain enforced during ad-filter pauses and tracker exceptions.
- Initial visible TLS names and CONNECT destinations must independently pass current policy before upstream contact. Malformed or ambiguous TLS names must not fall back to an unchecked relay. Initial inspection must stay bounded and preserve accepted TLS bytes.
- Admitted opaque tunnels must recheck their original authority, initial visible TLS name, expiry and transport readiness before each forwarding operation in either direction. A refusal discards queued child events and cannot revive. If the address guard is selected, current address policy must also accept the actual connected peer. The runtime must acknowledge this capability before newer management clients report readiness. Bytes already forwarded and inner encrypted destinations remain outside this boundary.
- When hardened transport is selected, external plaintext requests must be refused before upstream contact or body buffering; a blocked request must not be automatically upgraded or replayed. An enabled but unavailable address guard must refuse filtering traffic. Its hook checks actual numeric TCP connection candidates without resolving names or logging requests and is not a sandbox against code in its own process.
- Browser policy receipts must distinguish saved intent from rules read back as applied. Ordinary repair grants must not override threat/manual-deny rules or restore tracking headers. A threat warning's separate deliberate Continue is exact-host, tab-bound and navigation-only.
- Once default Strict's preparation policy is installed, releasing a site's hold must be atomic with installing its complete named policy. Prepared parent scopes must not release independent private tenants. Automatic preparation must not become a persistent inactive-site history.
- Applied named-site isolation must block cross-top-site subresource requests, including socket handshakes, above ordinary repair permissions. Pause, embed repairs and saved allows must not silently relax it. Header removal must also cover initial navigations to the isolated destination. It does not revoke existing connections, erase storage or contain every outbound navigation.
- Protocol signatures must use bounded, source-backed method/type/path/query constraints, never inspect bodies or promote data into executable code. They remain below explicit repair grants and manual security denies. Known analytics identity headers removed by Isolation must stay above ordinary grants, without claiming all custom identifiers are removed.
- Imported cosmetic exceptions must survive compilation conservatively. Unsupported exceptions must reduce or quarantine the affected imported coverage visibly. Rule text must not become executable code or expand the manual-selector grammar.
- Imported parameter exceptions must constrain overlapping built-ins in both network and click-time cleaning. Generated parameter redirects are top-level GET only, must prove a removable key is present, and must preserve recognized signed/authentication flows. Source-derived exceptions must not become broad network allow rules. Unsafe ambiguous source coverage must stop a full build or be explicitly reported as reduced.
- Optional browser privacy controls accept fixed setting identifiers and values from the exact extension-owned settings page only. Persist intent before mutation, verify actual values and ownership, and release only this extension's override rather than overwriting current user or foreign preferences.
- A local model may return bounded labels for current page candidates. It must not generate executable selectors, arbitrary browser actions, network exceptions or native commands. Page text is untrusted data, and no cloud inference fallback is permitted.
- Native messaging accepts only exact-origin, bounded read-only receipt requests. It must not expose history, keys or paths, initialize missing identity state, or imply that a browser/profile is routed through the proxy.
- Fresh configurations keep no domain history. Applied logging status requires writer acknowledgment; changing history mode must discard outstanding old-generation records.
- Feed downloads must have fixed trusted origins, HTTPS verification, response limits and validation before replacement. A failed update must preserve the last good cache.
- Native settings require explicit service selection and administrator authorization. Root must not execute user-writable project code. Restore must not overwrite newer foreign settings.
- Private state and management credentials must not enter source archives, wheels, screenshots, HTTP logs or public diagnostics.

The system does not provide a boundary against malware already executing as the same local user or an administrator. Traffic outside the proxy, encrypted inner destinations and data already forwarded are outside the proxy's domain enforcement. Established tunnels through a restarted 0.10 proxy are rechecked at subsequent forwarding boundaries; browser Isolation by itself does not revoke established transports. These coverage limits do not excuse broken controls on the stated entry points.
