# Security policy

## Supported release

Version 0.7.x is the current alpha development line. Fixes target this line; consult the release page for published artifacts and the qualification record before upgrading. The application does not execute downloaded application updates automatically.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/SulaymanB2024/egress-guard/security/advisories/new). Avoid public issues for exploitable details or credential disclosures. Include the affected version, operating system, relevant configuration, expected boundary, minimal synthetic reproduction and practical impact. Never include live keys or real browsing logs.

## Security boundaries

- The dashboard must remain authenticated, loopback-only, protected from cross-site requests and DNS rebinding, and unable to execute arbitrary commands.
- Threat-feed and manual security rules must remain enforced during ad-filter pauses and tracker exceptions.
- Browser policy receipts must distinguish saved intent from rules read back as applied. Ordinary repair grants must not override threat/manual-deny rules or restore tracking headers. A threat warning's separate deliberate Continue is exact-host, tab-bound and navigation-only.
- A local model may return bounded labels for current page candidates. It must not generate executable selectors, arbitrary browser actions, network exceptions or native commands. Page text is untrusted data, and no cloud inference fallback is permitted.
- Native messaging accepts only exact-origin, bounded read-only receipt requests. It must not expose history, keys or paths, initialize missing identity state, or imply that a browser/profile is routed through the proxy.
- Fresh configurations keep no domain history. Applied logging status requires writer acknowledgment; changing history mode must discard outstanding old-generation records.
- Feed downloads must have fixed trusted origins, HTTPS verification, response limits and validation before replacement. A failed update must preserve the last good cache.
- Native settings require explicit service selection and administrator authorization. Root must not execute user-writable project code. Restore must not overwrite newer foreign settings.
- Private state and management credentials must not enter source archives, wheels, screenshots, HTTP logs or public diagnostics.

The system does not provide a boundary against malware already executing as the same local user or an administrator. Traffic outside the proxy and existing opaque tunnels are outside domain enforcement. These coverage limits do not excuse broken controls on the stated entry points.
