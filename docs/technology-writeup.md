# Beyond domain lists: inspecting hidden trackers and reviewing sponsor timings

Egress Guard 0.2.0 adds two explicit tools around the existing filtering proxy:
system-resolver CNAME inspection and a privacy-conscious SponsorBlock timing
export. Both expand what a user can investigate. Neither silently changes the
traffic or content already being allowed by the filtering policy.

## Where domain filtering runs out of information

The proxy blocks destination hostnames using validated, locally cached HaGeZi
feeds and exact AdGuard CNAME aliases. It preserves the server's HTTPS
certificate and does not decrypt page contents. That keeps credentials and
page text outside the filter's decision path, while leaving two coverage gaps:
a previously unknown first-party alias can point to a tracker, and a sponsor
segment can share its video's hostname and encrypted media connection.

These need different information. A resolver can expose an alias chain. A
community timing database can identify intervals within a particular video.
Treating either as a universal ad detector would overstate the evidence.

## CNAME inspection through the current macOS resolver

`egress-guard cname-check HOST` asks macOS DNS-SD for A and AAAA records with
`ReturnIntermediates`, which includes intermediate CNAME observations. A normal
address-only lookup discards the chain needed for this analysis. Using the
configured resolver also avoids introducing a public-resolver fallback that
could ignore private DNS routes or disclose internal hostnames elsewhere.

The native adapter copies bounded names and metadata, never address bytes.
It deallocates each native reference and runs in a supervised child process
with isolated Python imports pinned to the already-imported package location.
That isolation closes a review finding where the caller's working directory
could substitute a different module for the resolver worker.

The portable evaluator follows only edges rooted at the requested hostname.
It checks record/hop limits, cycles, forks, conflicting interfaces, missing
terminals and different family paths. Review found and fixed an edge case:
a direct IPv4 answer plus an explicit IPv6 alias followed by a negative reply
must remain ambiguous. A negative family without an alias is not equivalent
to that conflicting evidence.

The report shows the original policy and each reachable alias's policy
independently. Existing analytics exceptions, threat precedence, manual rules
and pauses retain their meaning. `indeterminate` remains true when an answer
or verified policy cache is missing. Offline JSON observations exercise the
same evaluator on other platforms without making DNS queries.

This is a snapshot, not enforcement. A later connection may use a different
answer, application-specific DNS, or a changed VPN route. A safe future
enforcement adapter must inspect the answer actually used for the connection,
handle resolver context and rebinding, and preserve the same policy priorities.
Apple's cached callback TTL is not a fresh-cache lifetime. `.local` queries may
use multicast on the LAN. [Adapter details](cname-inspection.md).

## Community timing suggestions with reduced identifier disclosure

`sponsor-fetch` requires a video ID and a separately supplied current duration.
It hashes the case-sensitive ID locally and requests a four-hex-character
prefix bucket from SponsorBlock. The exact match is selected locally. No
browser history, full video ID, cookies, or authorization is sent in the HTTP
request. A prefix can still uniquely identify a video, and the service sees
the connection, so this is not an anonymity guarantee.

The importer accepts only the requested sponsor/self-promotion skip categories.
It rejects stale or unknown duration, invalid bounds, overlaps and suggestions
covering most of a video. Empty results remain unknown coverage. The JSON
reader bounds bytes, nesting and structure before allocating containers, then
rejects duplicate fields and non-finite values. The transport refuses redirects
and ambiguous framing and applies a response deadline after TLS connects.

Completed exports are published with a create-only filesystem operation, so
existing files and dangling links survive. Exports retain SponsorBlock's
CC BY-NC-SA 4.0 attribution and describe the format conversion. Community data
is not bundled or relicensed under our MIT code license. Timings still require
manual audio/video review; the command changes no playback. [Format and
privacy](sponsor-timings.md).

## Validation and the next boundary

The new tests cover rooted and conflicting DNS graphs, real ctypes callbacks,
multi-batch replies, native reference cleanup, worker isolation/deadlines,
unsupported platforms, offline file handling, hash collisions, malformed
timings, response framing, bounded JSON and create-only output. A read-only Mac
smoke check observed `www.python.org` through its Fastly alias and `example.com`
directly through the current resolver. That is not a split-DNS/VPN or Intel
qualification. Release checks also exercise the installed wheel's new commands.

The page-controls browser companion and reversible updater remain separate
candidates. Browser models and a mocked popup do not establish real-site
accuracy, native extension permissions or media behavior. The Mac's heavy
concurrent load prevented completing the browser qualification in this release.
Automatic system-wide proxy activation also remains withheld until endpoint
ownership is safe across logout and reboot. Existing upstream Tornado package
advisories remain documented in the [dependency notes](../requirements/README.md).

## Research informing further development

Recent work argues for measuring breakage and uncertainty alongside detection:

- [SINBAD, IEEE S&P 2024](https://arxiv.org/abs/2405.05196) studies interaction-dependent blocker breakage. Our browser qualification therefore needs play, seek, resume, navigation and editing workflows, alongside screenshots.
- [Brave's procedural filtering engineering](https://brave.com/privacy-updates/31-procedural-filtering/) shows why shared CSS classes need surrounding structure and visible labels. We use that as a design direction, not a claim of measured coverage here.
- [AutoFR, USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/le) treats rule discovery as an effectiveness/breakage tradeoff. Candidate rules should face a paired local replay before promotion.
- [A 2025 Hamburg thesis on podcast ad detection](https://www.inf.uni-hamburg.de/en/inst/ab/lt/teaching/theses/completed-theses/2025-ma-wolf.pdf) illustrates how stricter false-positive budgets reduce recall. Caption-only sponsor inference should abstain when context is absent and remain a scorer before controlling playback.

A practical next experiment is an offline sponsor-candidate scorer on
hand-labeled, consented clips. Hold out entire channels, include organic brand
mentions and missing/visual-only inputs, and measure legitimate seconds marked
per viewing hour, extra sponsor seconds found, abstentions and latency. No
cloud page uploads or inferred automatic skipping are needed to run it.
