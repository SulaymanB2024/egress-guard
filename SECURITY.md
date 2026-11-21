# Security policy

## Supported release

Version 0.5.x is an alpha. Fixes will target the latest published 0.5.x release; 0.4.x and earlier are no longer supported. Review release notes before upgrading; the application does not execute downloaded application updates automatically.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/SulaymanB2024/egress-guard/security/advisories/new). Avoid public issues for exploitable details or credential disclosures. Include the affected version, operating system, relevant configuration, expected boundary, minimal synthetic reproduction and practical impact. Never include live keys or real browsing logs.

## Security boundaries

- The dashboard must remain authenticated, loopback-only, protected from cross-site requests and DNS rebinding, and unable to execute arbitrary commands.
- Threat-feed and manual security rules must remain enforced during ad-filter pauses and tracker exceptions.
- Feed downloads must have fixed trusted origins, HTTPS verification, response limits and validation before replacement. A failed update must preserve the last good cache.
- Native settings require explicit service selection and administrator authorization. Root must not execute user-writable project code. Restore must not overwrite newer foreign settings.
- Private state and management credentials must not enter source archives, wheels, screenshots, HTTP logs or public diagnostics.

The system does not provide a boundary against malware already executing as the same local user or an administrator. Traffic outside the proxy and existing opaque tunnels are outside domain enforcement. These coverage limits do not excuse broken controls on the stated entry points.
