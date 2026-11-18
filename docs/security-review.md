# Pre-release security review

The November 18, 2026 source review identified six issues before the first public release. The release includes the following changes and regression checks. This is an alpha review, not a certification or a claim that no other issues exist.

| Issue | Release behavior | Regression checks |
| --- | --- | --- |
| A static health response could impersonate a proxy, and a per-user listener cannot own its port after logout. | Health uses a fresh installation-key proof. Automatic system-wide activation is disabled before any native work; clients are configured individually. | Static/stale proof rejection, genuine transport proof, public activation refusal before side effects. |
| Loopback cookies can be sent to other ports on the same host. | Authentication uses an expiring bearer value held in origin-scoped tab sessionStorage; the server never accepts session cookies. | No Set-Cookie; cookie replay cannot authorize reads or mutations. |
| Replaying a server proof could impersonate the dashboard to its launcher. | Both peers prove knowledge of the private key over a fresh client nonce and server nonce, with separate roles. Bootstrap values are short-lived and one-use. | Old server proofs fail for new client challenges; bootstrap replay is refused. |
| A future feed publication time could poison subsequent freshness comparisons. | Downloads and caches reject timestamps beyond a bounded clock-skew window; invalid historical metadata cannot prevent a valid update. | Future-date rejection and recovery using a valid subsequent feed. |
| A manual rule edit could exceed the reader limit and discard existing blocks. | Writes validate the prospective encoded size. The running proxy retains its last good rules and reports unhealthy controls until an invalid file is repaired. | Oversized write preserves prior rules; live invalid-file refusal and repair recovery. |
| Unauthenticated connections could create unbounded dashboard threads. | Admission is capped before thread creation, with idle and total request deadlines. | Concurrent socket admission and stalled-request release checks. |

Additional checks cover Host/Origin validation, CSRF, plaintext credential refusal, CONNECT blocking before upstream contact, unchanged upstream TLS certificates, corrupted/empty feed refusal, atomic cache replacement, bounded activity storage, private files, and mocked macOS recovery. Canary tests use synthetic values and mocked provider/native notification calls; history beyond the polling window appears as degraded status.

The release does not activate native routing on the development Mac. Native transactions are tested with mocks. Hardware and macOS-version coverage, an OS-managed routing service, signed distribution, a dependency artifact lock, browser-level sponsored-content filtering and a reproducible effectiveness benchmark remain follow-up work.
