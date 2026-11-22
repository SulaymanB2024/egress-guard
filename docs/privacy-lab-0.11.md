# Controlled collectors and linkability in 0.11

The lab asks what reaches an origin through the actual proxy. It includes the failure that a useful privacy test must retain: blocking a listed third-party collector does not remove a stable identifier sent in an admitted first-party request body.

This is synthetic development evidence. The Python qualification runs real sockets, the pinned proxy and original-certificate TLS. The optional Chrome runner additionally exercises the built companion and real browser contexts, but **native Chrome was not run in the implementation environment**. Its source-contract check is not native qualification.

## Portable experiment

Run with the existing Python 3.12+ environment containing `mitmproxy==12.3.1`:

```sh
python -B scripts/qualify-collector-lab.py --out /absolute/new-collector-receipt.json
```

The command creates a new private receipt and refuses to overwrite an existing file. It does not install dependencies. All generated keys, origins, proxy state and routing overrides belong to temporary test processes. No OS resolver, trust store, user browser profile or system proxy is changed. A fixed routing addon permits only the fixture's six `.test` hostnames and its one local origin port. This routing fixture is not a sandbox for arbitrary software.

The two publisher sites are `publisher.test` and `shop.test`, which are distinct registrable sites under the packaged public-suffix rules. Four synthetic subjects visit both sites. Each subject carries a deliberately stable synthetic token; no real account, hardware fingerprint, browsing history or public IP is collected.

Each arm attempts eight listed-collector POSTs, eight admitted first-party POSTs carrying the same tokens, and eight functional cart POSTs. The baseline pauses the tracker category. The protected arm resumes it. The client verifies TLS normally against the exact private fixture certificate and compares the received certificate's DER bytes with that certificate. Every delivered event must correlate with the proxy's observed origin connection.

The [portable evidence](benchmarks/collector-proxy-0.11.json) records the actual results:

| Observation | Tracker category paused | Tracker category active |
| --- | ---: | ---: |
| Listed-collector events | 8 | 0 |
| New application bytes during each listed-collector attempt | Positive | 0 |
| Admitted first-party identity events | 8 | 8 |
| Functional cart events | 8 | 8 |
| True matches using only the listed collector | 4 / 4 | 0 / 4 |
| True matches using all observed identity channels | 4 / 4 | **4 / 4** |
| False matches across different synthetic subjects | 0 / 12 | 0 / 12 |

The byte meter runs at each decrypted TLS socket read, before HTTP or WebSocket semantic parsing. An incomplete or malformed request can therefore add received bytes even without producing a completed event. A dedicated regression sends a partial HTTP request and checks that the meter retains it. Counters and overflow state are monotonic; clearing the event list cannot reset that evidence.

Zero-byte results use before/after application-byte counters with a prior successful delivery control. Semantic request counts alone cannot establish zero leakage. Unexpected handler failures, evidence overflow or absent route correlation invalidate the qualification. Expected transport disconnects have a separate counter.

This experiment qualifies a pre-existing proxy boundary and the new measurement infrastructure. It is not an additional blocking-efficacy gain over 0.10. The opaque first-party residual is intentional evidence of the proxy's encryption boundary.

## Attacker model and denominators

The attacker predicts a match when two received token sets have any exact synthetic token in common. The threshold is fixed at one shared token before scoring. Subject labels are used only after the prediction to decide whether it was correct.

The scorer includes every cross-site pair, including visits that yielded no identifier. Dropping such visits would select only successful collection and distort the denominator. Tests also permute the subject labels while keeping observations unchanged, and supply a token shared by every subject: the latter produces a false-match rate of one and fails the declared ceiling.

The receipt reports an empirical false-match ceiling of 0.01 **on this cohort**. Zero false matches among twelve negative pairs does not establish a population false-match rate below 1%. The pairs are not independent people sampled from the internet. These are synthetic identity-channel results, not a browser fingerprinting or population anonymity estimate.

Both channel-specific and all-channel scores are mandatory. Qualification requires the exact expected identifier, body length and identifier-byte count in each delivered identity control, empty identifier sets in cart controls, the complete event inventory, and the expected true/false/pair counts. A fault-injection regression clears the extracted tokens while retaining real received bytes; that run must fail instead of rewarding a broken observer. A blocked GA4 or third-party channel cannot hide a surviving identifier in an ordinary application POST. The fixture retains only matching synthetic token strings, fixed header names, counts and bounded test metadata. High-entropy UA values are never recorded.

## Established WebSocket revocation

The Python regression also establishes an actual TLS WebSocket through the pinned proxy, receives a first masked frame and acknowledgment, then applies a manual deny through the fixture's temporary state. After the proxy acknowledges the changed revision, another frame cannot add origin application bytes; the origin observes connection closure.

This exercises the existing per-forward tunnel check through a WebSocket lifecycle. It does not recall bytes already handed to the transport, add an idle-stream timer, or prove behavior on the intended macOS installation. The optional native browser runner currently reports its own WebSocket-revocation case as NOT COVERED.

## Optional native browser runner

```sh
# Source contracts only: no browser, Python child, proxy or listener.
node tests/browser/chrome-collector-lab.mjs --check

# On a separately permitted target; requires an existing built Chrome artifact.
node tests/browser/chrome-collector-lab.mjs \
  --chrome /absolute/path/to/chrome \
  --python /absolute/path/to/python \
  --extension /absolute/build/chrome \
  --out /absolute/new-native-receipt.json
```

The runner uses disposable profiles, the actual proxy and the actual built extension. The baseline has no extension and pauses the tracker category; the protected arm loads the companion and resumes the category. These arms measure the combined stack, not causal attribution between its individual components.

Cases cover recognized GA4 query requests, third-party fetches, images, dedicated workers, service workers, opaque POSTs and functional cart operations. Completed execution contexts and successful baseline deliveries are required before blocking credit. Functional controls bracket each visit. Timeouts receive no blocking credit, and final snapshots follow browser closure. Worker support failures remain NOT COVERED.

The Client Hints phase applies and releases the option from the real extension privacy page. It observes request headers at the collector, response policies and returned JavaScript property names. Existing and malformed policy headers are preserved. Missing baseline high-entropy emission cannot count as successful suppression. Window, HTTP and worker GPC observations are retained separately; an existing false native value is not overwritten to make them agree.

First-party sites also deliver permitted documents, worker scripts and controls. The raw socket meter cannot attribute every partial byte on these shared origins to an individual first-party case. Such channel results mean no completed matching collector event; the separate tracker-host check measures zero application bytes. This distinction remains a native coverage limitation.

The shared browser driver disables hyperlink ping auditing, so this fixture cannot establish a causal ping-blocking effect. It does not qualify IP hiding, VPN/Tor routing, arbitrary SDK behavior, encoded tracking bodies, a real user's browser state or the optional Chrome privacy-permission prompt. It does not launch Chrome in the implementation environment, where a prior startup restriction remains in force.

## Next useful experiments

Use additional isolated collector origins to attribute partial bytes to first-party channels without mixing document and worker traffic. Add complete SDK lifecycle fixtures, including retries and alternate transports, only from pinned source snapshots. Measure a broader attacker on held-out synthetic behavior before proposing any linkability percentage. Browser-native behavior and source-level tests remain separate evidence throughout.
