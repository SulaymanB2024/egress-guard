# Release checks

1. Run all isolated unit tests and the loopback transport test with the pinned mitmproxy version.
2. Build an sdist and wheel; install the wheel into a clean temporary target and exercise its version, initialization, empty-cache refusal and packaged dashboard assets.
3. Exercise dashboard authentication, hostile origins/hosts, CSRF and timed controls using temporary state only. Inspect the actual desktop and phone rendering.
4. Review the final source, package file list and dependency/license metadata. Exclude secrets, logs, generated certificates, feed caches, local records and personal paths.
5. Create a tagged release with the reviewed source archive, wheel and SHA256SUMS. Download the assets again and verify their checksums.

Do not trigger or wait for GitHub Actions as a substitute for these checks. Do not label this unsigned alpha as notarized or imply that it protects clients which have not been configured to use the proxy.
