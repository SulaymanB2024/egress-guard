# Browser companion (experimental)

The proxy sees only the hostname of each connection. It cannot tell
`https://publisher.example/article` from `https://publisher.example/collect`,
cannot strip `?utm_source=` from a link, and cannot touch page elements. The
companion in `browser/` can. One set of sources builds two extensions:

- **Chrome** (primary): built-in ad, tracker and malware lists, URL filters
  (EasyPrivacy and EasyList) that catch first-party and proxied trackers,
  link and cookie cleaning, Global Privacy Control, per-site protection levels
  (Relaxed, Standard, Strict, No scripts) with click-to-load embeds, a local
  warning page for malware and phishing sites, plus your own per-site rules.
  Built on `declarativeNetRequest`.
- **Firefox**: your own per-site rules through blocking `webRequest`. The
  built-in lists are Chrome-only for now.

It is unsigned, not released, and not connected to the proxy. It works with
or without the proxy running.

## Chrome: build and load

1. **Get the lists.** The build reads the proxy's verified feed cache, the
   same files the proxy blocks with. If the proxy has run at least once, they
   are already there. Otherwise refresh them with the proxy's own downloader
   and validation:

   ```sh
   egress-guard refresh
   ```

2. **Build** (plain Node 20+, no dependencies):

   ```sh
   node scripts/build-browser.mjs
   ```

   It prints the Chrome and Firefox folders, the extension id and the size of
   each list. A missing malware and phishing feed stops the build (pass
   `--allow-missing` to build without it on purpose); feed files must be
   regular files, not links. Options: `--feeds DIR` (a feed cache other than the proxy's
   data directory), `--tier pro|pro.plus|ultimate` (default `pro.plus`, the
   proxy's default), `--no-lists` (your own rules and parameter stripping
   only), `--out DIR` (default `dist-browser/`, which git ignores).

   The build also keeps its own cache of the URL filter lists,
   `<data>/browser-filters/` (EasyPrivacy, EasyList, AdGuard's disguised
   click-through list). It downloads a list only when the cached copy is
   missing or more than a day old, checks it (HTTPS, size, header, title,
   licence line, minimum size, host-name syntax) and records its SHA-256, size,
   fetch time and upstream version. `--offline` never downloads,
   `--no-filters` leaves them out, `--filters DIR` uses another cache. The
   proxy's feed cache and `feeds.py` are not touched. Behind an HTTP proxy, run
   the build with `NODE_USE_ENV_PROXY=1` so Node's `fetch` uses
   `HTTPS_PROXY`.

3. **Load it once**: open `chrome://extensions`, turn on **Developer mode**
   (top right), choose **Load unpacked** and select `dist-browser/chrome`.
   Pin the shield from the puzzle-piece menu if you want the blocked count
   in the toolbar.

That is the whole setup; nothing else needs configuring. After a rebuild,
press the reload arrow on the extension's card (or restart Chrome).

Chrome does not let a script install an unpacked extension into your normal
profile: branded Chrome ignores `--load-extension`, and the DevTools
`Extensions.loadUnpacked` command the tests use needs a debugging flag and a
separate profile. So step 3 stays manual. Steps 1 and 2 can run from a
script or a daily job; the loaded extension picks up a rebuild when reloaded.

The manifest carries a fixed public `key`, so the extension id is always
`danbhmcinakkkkbobacafgidgkfibfmg`. The warning page redirect needs a known
id. The matching private key was never kept; this build cannot be published
to the Chrome Web Store as is.

## What Chrome blocks with no rules of your own

| What | How | Source |
| --- | --- | --- |
| Ads and trackers | Every request type except top-level navigation, to the listed domains and their subdomains | HaGeZi Multi PRO++ (or the tier you build) |
| Disguised (CNAME-cloaked) trackers | Same, for first-party subdomains that alias a tracker | AdGuard CNAME-cloaked ads and trackers |
| Malware and phishing | Every request type, and navigations go to a local warning page | URLhaus (malware-filter), Phishing Army, HaGeZi Threat Intelligence (Full; Medium with `--threat-tier medium` or when only Medium is cached) |
| Empty ad slots | One stylesheet hides common ad containers (AdSense and Google Publisher Tag slots, ad-server frames, AMP ads, Taboola and Outbrain widgets, labelled ad containers). Switch it off per site in the popup | First-party list in `browser/core/cosmetic.js` |
| First-party and proxied trackers | URL filters: `gtm.js`, `gtag/js`, `/g/collect`, `/j/collect`, `fbevents.js`, `/tr?id=…&ev=`, Segment `analytics.js/v1/`, Matomo `matomo.js`/`piwik.php`, Adobe `/b/ss/`, Plausible, Umami, PostHog and thousands more, on any host including the site's own | EasyPrivacy network filters (path rules match on every host), plus a short hand-written set in `browser/core/dnr.js` |
| Ads by address | URL filters for ad paths that host lists cannot name | EasyList network filters |
| Fingerprinting and session replay | FingerprintJS / Fingerprint Pro custom-subdomain and proxy loaders, ThreatMetrix `fp/` paths, iovation, proxied Hotjar, FullStory, LogRocket, Clarity, Mouseflow, Contentsquare, PostHog recorder, Smartlook | Hand-written paths in `browser/core/dnr.js`, plus EasyPrivacy |
| Third-party beacons | `navigator.sendBeacon` and `<a ping>` to another site are blocked; `ping` attributes are removed before a click can fire them | `beacons` ruleset, `page-guard.js` |
| Link trackers | Known redirectors (Google `/url`, Facebook and Messenger `l.php`, Instagram, Threads, Reddit `out.`, Tumblr, VK, YouTube `/redirect`, Slack, LinkedIn, DuckDuckGo, Bing `ck/a`, Yahoo `RU=`, Google AMP, Disqus) are skipped when the click starts on the redirector's own site; affiliate and email click trackers with no safety check of their own (href.li, Skimlinks, Rakuten, Awin, Mandrill) from anywhere. The destination is checked against the threat list first | `browser/core/links.js` |
| Mail security scanners | Microsoft Safe Links, Proofpoint URL Defense, Mimecast, Barracuda and Trend Micro links show a local page with the destination first; **Continue through the scanner** is the default | `unwrap.html` |
| Tracking parameters | 147 names removed everywhere and 214 more on the 67 sites that use generic names for tracking, on every navigation and at click time; Amazon's `/ref=` path segment | `browser/core/params.js` |
| Tracking cookies | 44 name patterns (`_ga*`, `_gcl_*`, `_fbp`, `_fbc`, `_uet*`, `_ttp`, `_scid`, Hotjar's ids, `ajs_*`, `mp_*`, `amplitude_id_*`, `_clck`, …; names that are not unique to one tracker only on their vendor's domains; never an opt-out or consent cookie) deleted the moment they are set; third-party cookies stripped for tracker hosts and opaque redirectors | `browser/core/cookies.js`, `cookies` and `bounce` rulesets |
| Global Privacy Control | `Sec-GPC: 1` on every request and `navigator.globalPrivacyControl === true` (a getter on `Navigator.prototype` that reads as native code) | `gpc` ruleset, `page-gpc.js` |
| Full-address referrers | A page or frame whose `Referrer-Policy` would send full addresses cross-site (`unsafe-url`, `no-referrer-when-downgrade`, `origin-when-cross-origin`) gets Chrome's default instead | `referrer` ruleset |
| Trackers pages depend on | `ga()`, `gtag()`/`dataLayer` callbacks, `fbq()`, `analytics.*`, `_satellite`, `googletag` answered by inert local stubs | `browser/surrogates/` |

These are the proxy's own feeds and tiers. URLhaus also lists IP addresses;
those are skipped (DNR matches host names). The proxy's DoH list is not used:
DNR cannot see Chrome's own secure-DNS lookups, so blocking pages' requests to
resolver hosts would protect nothing. With 2026-11-20 data the build holds
about 257,000 tracker, 384,000 threat (Medium tier) and 178,000 CNAME
domains. The Full threat tier is about 1.47 million names: a synthetic
1.5 million-name threat list (68 MB) indexed and matched in headless Chrome
157, both as one file and split. The build caps each ruleset file at 32 MB
and splits larger lists (`threats`, `threats-2`, …), which the popup shows as
one list.

**Ad-slot stylesheet.** It is CSS only, added at `document_start`, with no
per-element script. Selectors must be class, id-prefix or tag-qualified
attribute selectors (Chrome matches those from a bucket), never `:has()` or a
bare attribute, at most 80; a test enforces that. EasyList's generic hiding
rules were evaluated: the licence (GPL-3.0 or CC BY-SA 3.0) fits next to the
GPL HaGeZi data, but its generic section is thousands of selectors including
costly universal ones, it is not in the proxy's verified feed cache (adding
a feed belongs in `feeds.py`), and every selector would need the review this
small set gets. The first-party set covers the common slot conventions; see
the real-site results below for what it leaves.

**Warning page.** A navigation to a threat-listed site never reaches it. The
page shows the host, the full address, the list and its date. **Go back** is
the one filled button and has the focus. **Continue anyway…** (quiet) reveals
a confirmation with the consequence and **Open <host> once** (Escape closes
it again), which adds two session `allow` rules for that tab and that host only:
the navigation, and the host's own requests. Ads and trackers stay blocked on
the continued page, and so does every other threat-listed host the page pulls
in (an `allowAllRequests` rule would have lifted those for the whole frame
tree; the headless check proves they stay blocked). The exception ends when
the tab leaves the site, after 10 minutes, or when Chrome restarts.

The worker only continues to the address the page displayed: the page sends
it, and it must equal the address in the page's own URL at click time. If
anything changes the fragment after load the page reloads. Inside a frame the
page refuses to offer Continue (and the extension CSP sets `frame-ancestors
'none'`). The host must really be on the bundled threat list (Chrome's
`testMatchOutcome` in unpacked builds, the packaged ruleset otherwise).
Threat-listed requests never get a one-click **Allow** in the popup.

**Parameters removed.** The list lives in `browser/core/params.js` and was
built from what each vendor documents its parameters for, then checked for
coverage against ClearURLs, Brave's and Firefox's query stripping and
AdGuard's URL tracking filter (names only; nothing copied). Global (147):
campaign tags (`utm_*`, `pk_*`, `piwik_*`, `mtm_*`, `hsa_*`, `mc_cid`,
`mc_eid`, `oly_*`, `vero_*`, `_openstat`, `yclid`, `ysclid`, `s_kwcid`,
`ef_id`, Eloqua campaign and Silverpop ids), click ids (`gclid`, `gclsrc`,
`gbraid`, `wbraid`, `dclid`, `gad_source`, `gad_campaignid`, `fbclid`,
`msclkid`, `twclid`, `ttclid`, `li_fat_id`, `igshid`, `igsh`, `epik`,
`sccid`, `rdt_cid`, `irclickid`, `srsltid`, `_gl`, Branch, Taboola,
Outbrain), email-platform subscriber ids (Klaviyo, Drip, ActiveCampaign,
beehiiv, Bronto) and HubSpot's analytics ids. `campaign_id`, `ad_id`,
`adset_id` and `cmpid` are not global: inside ad and email platforms'
dashboards they are the page's own data (`cmpid` stays on Bloomberg and
`campaign_id` on the New York Times, where they are tracking).
Per site (214 names on 67 sites): generic names that are tracking only there,
for example `si` and `feature` on YouTube and Spotify, `s`/`t`/`ref_src` on
X, `trk` and `trackingId` on LinkedIn, `ref`, `tag`, `linkCode`,
`ascsubtag`, `pd_rd_*`, `pf_rd_*`, `psc` and the `/ref=` path on Amazon,
`spm`/`scm` on AliExpress and Taobao, `ved`/`ei`/`sxsrf`/`oq` on Google
search, `cvid`/`form` on Bing, `source` on Medium, eBay's `mk*` ids. Never
removed anywhere (`KEPT`, honoured by both the navigation rules and the page
cleaner): recipient tokens that unsubscribe and preference links need
(`mkt_tok`, `_hsenc`, `_hsmi`, ConvertKit `ck_subscriber_id`, MailerLite
`ml_subscriber` and `ml_subscriber_hash`, Eloqua `elq` and `elqTrackId`,
LinkedIn `midToken` and `midSig`, New York Times `nl`, `user_id` and
`segment_id`), OAuth and session parameters (`code`, `state`, `token`,
`session`, `nonce`, `client_id`, `redirect_uri`, SAML), search queries and
pagination. A `ref` on any site outside the per-site sets (a GitHub branch,
say) is kept.

**Pages that are never cleaned.** An address whose path is an unsubscribe,
opt-out, preferences, email-settings or subscriptions page keeps every
parameter (one `allow` at the cleaning tier, mirrored in the page cleaner).
Sign-in, payment, cloud-console and advertiser, affiliate and email-platform
console hosts (`accounts.google.com`, `pay.google.com`, `ads.google.com`,
`console.aws.amazon.com`, `affiliate-program.amazon.com`,
`sellercentral.amazon.com`, `business.facebook.com`, `app.hubspot.com`, …;
`EXCLUDED_HOSTS` in `core/params.js`) are left alone entirely, although the
Google and Amazon per-site sets cover their consumer sites.

**Popup.** Built to the design system in `docs/design/` (`DESIGN.md`
section 12; `browser/ui.css` carries `docs/design/tokens.css` unchanged, and
`tests/browser/ui-tokens.test.cjs` fails if they drift). A 360 px popup with
a header (site host, truncated in the middle by whole labels, and a status
dot and word) and four tabs, operable with the arrow keys:

- **This page**: requests blocked on this page as the one large number (a
  stopped malware or phishing request adds "1 threat stopped" in the threat
  colour), then links cleaned, cookies removed and elements hidden, then
  **Protection on this site**: Relaxed, Standard, Strict or No scripts, with a
  quiet **Pause** beside the heading that shows everything hidden on this page
  until **Resume** (blocking continues). "Newer lists have been built" and a
  paused page each add one callout. It fits 520 px without scrolling.
- **Blocked**: grouped by named category (Ads and trackers, Disguised
  trackers, Malware and phishing, First-party tracker script, Tracking
  request, Ad request, Fingerprinting or session replay, Third-party beacon,
  Link tracker unwrapped, Tracker answered by a stub, Strict mode, Scripts
  off, Your rules), one row per endpoint with its type. **Allow 15 min**
  appears only on the hovered or keyboard-focused row (never for malware and
  phishing hosts, navigations, or WebSocket-like types; Strict blocks also
  offer **Allow host**).
- **Rules**: this site's rules with **Remove** and **Add…** (the endpoint
  form; Escape closes it), timed exceptions with **End now**, and page tools:
  **Block an element…**, **Show hidden ad slots** / **Hide ad slots on this
  site**, **Restore everything hidden here** / **Resume hiding**, and **Stop
  cleaning on this site** / **Clean links and cookies on this site**.
- **Settings**: the default level for other sites (Standard or Strict),
  **Always open scanned links directly**, and each list file with its date;
  **List files and hashes** shows every SHA-256.

Each second-level view has an empty state; a browser page says it cannot be
filtered. It follows the system light or dark setting. The toolbar badge
shows Chrome's own per-tab count of blocked requests.

What the popup can list depends on how the extension is installed, and it
says which:

| Install | Blocked list in the popup |
| --- | --- |
| Unpacked (Load unpacked, today's only route) | Every blocked endpoint with type and list (`onRuleMatchedDebug`) |
| Packed | Counts by list since the page loaded (`getMatchedRules`, which reports rules, never addresses); the note says addresses are not available |
| Neither API, or Chrome's `getMatchedRules` quota spent | The toolbar badge only, and the popup says so |

**Fresh lists: one click, not zero.** Chrome reads an unpacked extension's
files from its folder live. The build writes `rules/build.json` (a hash of
the rulesets, list metadata and sources); the worker compares it with its own
build id every hour and, when the folder was rebuilt, the popup says "Newer
lists have been built" and asks for the reload arrow on
`chrome://extensions`. It reads only its own file: no network request, no
server, no local port. Running `node scripts/build-browser.mjs` after each
proxy feed refresh keeps the folder current; the user still presses reload.

Reloading automatically was built and tested, then withdrawn: in headless
Chrome 157 an unpacked extension that calls `runtime.reload()` came back
**disabled** (with developer mode on or off), which would silently turn all
protection off. Whether a normal profile behaves differently was not
verified, so the extension never reloads itself. Truly zero-touch updates
need a packed, signed build with an `update_url` (Chrome's own updater);
that needs a signing key and a hosted update manifest, which this project
does not have.

A loopback endpoint on the dashboard serving domain lists as dynamic rules
was considered and not built. Dynamic and session rules share a 30,000-rule
budget meant for user rules; Chrome documents no size limit for a dynamic
rule's `requestDomains`, so a 1.5 million-name list there is untested
territory; removals cannot be expressed against static rulesets without
allow rules that could unblock a name still listed elsewhere; and a fixed
loopback port is visible to every web page (port probing reveals that Egress
Guard runs; CORS hides the body but timing does not), while DNS rebinding and
CSRF checks would have to stay perfect on a new unauthenticated route. The
rebuild-and-reload path gets the same freshness with none of that.

## URL filters (EasyPrivacy, EasyList)

Host lists cannot see a tracker that lives on a host which must stay
reachable: server-side Google Tag Manager on `sgtm.example.com`, Meta's
pixel proxied through the site, self-hosted Matomo, Plausible or PostHog
behind `/js/` or `/ingest/`. Their paths give them away. The build compiles
EasyPrivacy's and EasyList's **network** filters (not their cosmetic ones)
with `scripts/lib/abp-dnr.cjs`:

- converted: URL patterns (`||`, `|`, `^`, `*`), regular expressions RE2 can
  run, `$third-party` and first-party, resource types (including negated
  ones), `domain=`/`from=`, `to=`, `denyallow=`, `method=`, `match-case`,
  `important`, exceptions (`@@`) and `$badfilter`. Host-only filters with the same
  options fold into one `requestDomains` rule, so 47,000 EasyPrivacy hosts cost
  85 rules.
- exceptions and `$important` filters only when anchored to a concrete host:
  a `||host…` pattern on a real registrable name, a `to=` host, or a
  `domain=` restriction (public suffixes removed from it). Anything else
  (`@@||*^$document`, `@@^$document`, `@@|http$document`, `@@/./$document`,
  `@@|https://$all`, a bare `@@/path`) would let one hostile or broken
  upstream line allow, or block, everything: it is dropped and counted as
  *suspicious*. A `$document` exception never becomes `allowAllRequests`: it
  compiles to a plain `allow` for that host's own requests, at that list's
  exception tier; `$all` allows requests to that host and nothing more. The
  2026-11-21 lists have 7 (EasyList) and 4 (EasyPrivacy) such lines.
- dropped, and counted by reason: anything that would block a top-level
  navigation, `$popup`, `$csp`, `$removeparam`, `$rewrite`,
  `$redirect-rule`, entity domains (`example.*`) where dropping them would
  widen a filter, non-ASCII patterns, regexes RE2 cannot run.

With the 2026-11-21 lists: EasyPrivacy 56,730 network filters, 56,722
converted into 9,267 rules, 8 dropped (2 `$csp`, 2 entity-domain
exclusions that would have widened the filter, 1 `$rewrite`, 1
`$redirect-rule`, 1 negated `$document`, 1 that matched every request);
EasyList 53,735 network filters, 50,026 converted into 3,768 rules, 3,709
dropped (2,969 `$popup`, 563 `$document` blocks, 166 cosmetic-only
exceptions, 7 `$rewrite`, 4 `$csp`). They land in four rulesets:
`fp-trackers` (EasyPrivacy path filters that match on any host, which is
what catches first-party and proxied trackers, 3,513 rules), `easyprivacy`
(4,920), `easylist` (3,251) and `filter-allow` (1,360 exceptions). With the
host lists, parameters and everything else the build has 13,545 static rules
of Chrome's guaranteed 30,000 and 104 regular-expression rules of 1,000 (the
build refuses to exceed either; limits from Chrome's
`declarativeNetRequest` reference).

**Exceptions** (`@@`). Each list has its own pair of tiers: its filters, and
its exceptions directly above them. EasyList sits below EasyPrivacy, so an
EasyList exception lifts only EasyList filters. The reverse cannot be kept
apart on one priority ladder: an EasyPrivacy exception (there are about 850)
also lifts an EasyList filter that matches the same request. Tracking blocks
were put on top on purpose. No list exception reaches the hand-written
fingerprinting, session-replay and first-party tracker filters, third-party
beacon blocking, cookie and bounce stripping, parameter stripping, link
unwrapping or the Referrer-Policy fix: all of those sit above every list
exception (DNR applies a `modifyHeaders` rule only above every matching
`allow`, and an `allow` lifts only lower tiers). A list exception never
unblocks a host on the HaGeZi or CNAME lists, a threat, or one of your own
block rules, and `$important` filters beat it. Your timed exceptions and a
site set to Relaxed still win over all of it.

**Unpinned lists, checked twice.** The build fails when a list has more than
25 suspicious lines, or when a fresh download's size, entry count or
exception count moved by more than 2× from the last accepted copy (those
counts are recorded beside its SHA-256 in the cache's `<id>.json`); review
the list, then rebuild with `--accept-list-change ID`. The AdGuard
click-through list has the same cap. Each list's SHA-256 and last-modified
date are written to `NOTICE.txt` and shown under **List files and hashes**
in the popup's Settings tab.

## Link and cookie cleaning

Every link is cleaned in two places. On **every top-level or frame
navigation** (so a link opened from Mail, Slack or any other app is cleaned
too) the `params` ruleset strips the parameters above and cuts Amazon's
`/ref=` segment, and the `links` ruleset sends a known redirector to the
local unwrap page, which decodes the destination, checks it against the
malware and phishing list (a listed one goes to the warning page) and
replaces itself with it: the redirector never sees the click, and Back
returns to where the link was.

**Where a redirector is unwrapped.** Many redirectors run a safety check of
their own on the way through: Google's redirect notice, Facebook's and
LinkedIn's "leaving" pages, VK's and YouTube's warnings. A phishing email that
links to `https://www.google.com/url?q=https://evil.example` relies on a
blocker skipping that notice. So each redirector is unwrapped only when the
navigation or click starts on its own site (DNR `initiatorDomains`; at click
time, the page's own site): a Google result clicked on Google, a link clicked
in Gmail, a Facebook post's link on Facebook. The same address arriving from
anywhere else (a mail client, another site, the address bar, another app) is
left alone, and only tracking parameters on it are removed. Inner layers of a
nested link are unwrapped only while they belong to that same site. Affiliate
and email click trackers that check nothing (href.li, Skimlinks, Rakuten,
Awin, Mandrill) are unwrapped from anywhere.
**At click time** (`page-guard.js`, on mousedown, click, middle click, the
context menu and Enter) the link's `href` is rewritten to its clean,
unwrapped destination before Chrome reads it, so "Copy link address" copies
the clean address; a page that swaps the `href` during the same mousedown
(Google's `rwt`, Facebook's `l.php` and `lynx`) is undone before the click;
X's `t.co` links become the real address the page itself shows
(`data-expanded-url` or the title). The right-click menu also has **Copy
clean link**, which writes through an offscreen extension page so the site
never sees the copy. After a page loads, global tracking parameters that a
client-side redirect put back into the address bar are removed with
`history.replaceState` (never a reload).

The unwrap page (`unwrap.html`, `core/links.js`) only ever opens an absolute
`http:` or `https:` address without credentials. `javascript:`, `data:`,
`file:`, extension addresses, control characters, credentials, a lookalike
host and a redirector whose payload fails to decode are refused at every
nesting depth (up to four), and the address is shown as text instead. A
destination that is not `http(s)` never even matches the redirect rule.
Redirectors that keep the destination on their server (`t.co`, `bit.ly`,
most email-platform click links, Mimecast) cannot be unwrapped without a
network lookup, which the extension never makes; the `bounce` ruleset lets
the hop happen but strips its cookies both ways (63 short-link, email and
affiliate redirectors plus AdGuard's 37,000 disguised click-through
subdomains).

**Mail security scanners are never unwrapped automatically.** Microsoft Safe
Links, Proofpoint URL Defense (v2 and v3), Mimecast, Barracuda Link
Protection and Trend Micro Click Time Protection links go, from anywhere, to
a local page (`unwrap.html`, reachable only by the DNR redirect: it is
web-accessible by its per-session dynamic address alone, refuses to render
inside a frame and never navigates by itself). It shows the destination host
in a monospace face under the question "Open this link through <scanner>?",
the full address below it and, for an internationalized name, one
"Look-alike letters" callout with the Unicode form it may imitate (the `xn--`
form is what opens). **Continue through <scanner>** has the focus:
the worker adds a session rule that lets the next navigation to that scanner
host in that tab pass once, so the scanner gets its own address, signature
and parameters untouched. **Open directly** (its accessible name and tooltip
say it skips the mail scan) opens the
decoded destination after the threat-list check. Mimecast keeps the address
on its server, so only the host is shown and only Continue is offered. The
click-time cleaner and **Copy clean link** never change a scanner's link. The
popup setting **Always open scanned links directly** (off by default) skips
the page for every scanner link whose address is readable; the threat-list
check still applies. This replaces the earlier behaviour (Safe Links and
Proofpoint unwrapped automatically) and its escape hatch, which could not be
reached: the scanner's host was never a page you could open the popup on.

The interstitial at 1440 px and 390 px, light and dark, is captured by
`node tests/browser/chrome-privacy.mjs --shots DIR`. Every extension page and
popup state, with awkward real strings, is captured and audited (clipping,
sizes, spacing, filled buttons, names, the 520 px budget) by
`node docs/design/review/capture.mjs --extension`. A link tracker whose
destination cannot be read shows the link, **Go back** and **Copy link**.

**Tracking cookies** (`core/cookies.js`, 44 name patterns, using the
`cookies` permission) are deleted the moment they are set, first or third
party: Google Analytics and Ads (`_ga*`, `_gid`, `_gat*`, `_gcl_*`,
`_gac_*`, `__utm*`, `__gads`, first-party tagging `FPID`), DoubleClick
(`IDE`, `DSID`, `test_cookie` on `doubleclick.net` only), Meta (`_fbp`, `_fbc`), Microsoft Advertising (`_uetsid`, `_uetvid`,
`_uetmsclkid`), TikTok, Snap, Pinterest, Reddit, LinkedIn (`li_fat_id`), X,
Hotjar (`_hj*`), Segment (`ajs_*`), Mixpanel, Amplitude, Clarity, Matomo,
Snowplow, Heap, Yandex, Parse.ly, HubSpot (`__hstc`, `hubspotutk`), Marketo,
PostHog, LogRocket, FullStory, Contentsquare, Taboola, Outbrain, Quantcast,
Chartbeat and the cookies that click ids are written into (the full table is
below). Microsoft's `MUID`
is left alone: cutting it to a session cookie made Bing search render no
results in the real-site run, and Microsoft sign-in reads it too.
Nothing else is touched: sessions, carts, consent records and preferences
keep working. A script that sets the cookie again gets a fresh, unlinked id
every time. Third-party requests to tracker hosts that stay reachable
(social embeds, ad hosts a list's exception lets through) go without cookies
(`cookies` ruleset); payment, sign-in and captcha providers are excepted.
The `bounce` ruleset takes only subdomains from AdGuard's click-through list
(a bare registrable domain would strip a whole site's cookies on every
navigation to it) and never a payment, sign-in or console host, so
`go.checkout.com`, `link.afterpay.com` and `*.affirm.com` from today's
list are left out.

Every cookie pattern, and why it is safe to delete. A name that is not
unique to one tracker is matched only on its vendor's domains; any name that
looks like an opt-out, consent, GDPR/CCPA or do-not-track record is never
deleted, whatever pattern it resembles (deleting one would switch tracking
back on).

| Pattern | Vendor | Where | Why it is safe to delete |
| --- | --- | --- | --- |
| `_ga`, `_ga_<id>` | Google Analytics | everywhere | Client id; GA's own naming, used by nothing else |
| `_gid` | Google Analytics | everywhere | 24-hour visitor id |
| `_gat`, `_gat_*` | Google Analytics | everywhere | Request throttle flag |
| `_gcl_au`, `_gcl_aw`, `_gcl_dc`, `_gcl_gb`, `_gcl_gf`, `_gcl_ha`, `_gcl_ag`, `_gcl_gs` | Google Ads | everywhere | Stored click ids and conversion linker |
| `_gac_*` | Google Ads | everywhere | Campaign click id |
| `_dc_gtm_*` | Google Tag Manager | everywhere | Throttle flag |
| `__utma`, `__utmb`, `__utmc`, `__utmv`, `__utmt`, `__utmz` | Google Analytics (legacy) | everywhere | Visitor, session and campaign ids |
| `__gads`, `__gpi`, `__eoi` | Google Ad Manager | everywhere | Ad-serving visitor ids |
| `IDE`, `DSID`, `test_cookie` | DoubleClick | `doubleclick.net` | Ad ids. Elsewhere `DSID` is the Pulse / Ivanti Connect Secure VPN session and `test_cookie` a generic probe |
| `FPID`, `FPLC`, `FPGCLAW`, `FPAU` | Google first-party tagging | everywhere | Server-side tagging ids |
| `_fbp`, `_fbc` | Meta | everywhere | Browser id and stored click id |
| `_uetsid`, `_uetvid`, `_uetmsclkid` | Microsoft Advertising | everywhere | UET visitor and click ids |
| `_ttp`, `_tt_enable_cookie`, `ttcsid*` | TikTok | everywhere | Pixel ids |
| `_scid`, `_scid_r`, `_sctr`, `_screload` | Snap | everywhere | Pixel ids |
| `_pin_unauth`, `_pinterest_ct_ua`, `_pinterest_ct_rt`, `_epik`, `_derived_epik` | Pinterest | everywhere | Tag ids and stored click id |
| `_rdt_uuid`, `_rdt_cid`, `_rdt_em` | Reddit | everywhere | Pixel ids |
| `li_fat_id`, `_li_dcdm_c`, `li_sugr` | LinkedIn | everywhere | Insight tag ids |
| `_twclid` | X | everywhere | Stored click id |
| `muc_ads` | X | `twitter.com`, `x.com` | Ad id; generic-looking name |
| Hotjar ids: `_hjSessionUser_*`, `_hjSession_*`, `_hjid`, `_hjFirstSeen`, `_hjAbsoluteSessionInProgress`, `_hjIncludedIn(Session\|Pageview)Sample*`, `_hjRecording*`, `_hjSessionRejected`, `_hjCachedUserAttributes`, `_hjUserAttributesHash` | Hotjar | everywhere | Visitor, session and sampling ids. Not `_hjOptOut`, not poll and survey state |
| `ajs_anonymous_id`, `ajs_user_id`, `ajs_group_id` | Segment | everywhere | Visitor ids |
| `mp_<hex>_mixpanel` | Mixpanel | everywhere | Visitor id |
| `amplitude_id_*`, `AMP_<hex>`, `AMP_MKTG_<hex>` | Amplitude | everywhere | Visitor ids |
| `_clck`, `_clsk` | Microsoft Clarity | everywhere | Visitor and session ids |
| `_pk_id.*`, `_pk_ses.*`, `_pk_ref.*`, `_pk_cvar.*`, `_pk_hsr.*` | Matomo | everywhere | Visitor, session and referrer; not `mtm_consent*` |
| `_sp_id.*`, `_sp_ses.*` | Snowplow | everywhere | Visitor and session ids |
| `_hp2_id.*`, `_hp2_ses_props.*`, `_hp2_props.*` | Heap | everywhere | Visitor ids |
| `_ym_uid`, `_ym_d`, `_ym_isad`, `_ym_visorc` | Yandex Metrica | everywhere | Visitor ids |
| `_parsely_session`, `_parsely_visitor` | Parse.ly | everywhere | Visitor and session ids |
| `__hstc`, `__hssc`, `__hssrc`, `hubspotutk` | HubSpot | everywhere | Visitor and session ids; not `__hs_opt_out` |
| `_mkto_trk` | Marketo | everywhere | Visitor id |
| `ph_phc_*_posthog` | PostHog | everywhere | Visitor id |
| `_lr_uf_*`, `_lr_hb_*`, `_lr_tabs_*` | LogRocket | everywhere | Session-replay ids |
| `_fs_uid`, `_fs_cd`, `fs_uid` | FullStory | everywhere | Session-replay ids |
| `_cs_id`, `_cs_s` | Contentsquare | everywhere | Visitor and session; not `_cs_c` (consent) or `_cs_optout` |
| `_tq_id.*` | TaboolaPush | everywhere | Visitor id |
| `taboola_session_id`, `taboola_fp_td_user_id`, `taboola_select`, `taboola_global_user_id` | Taboola | everywhere | Visitor ids; not `taboola_optout` |
| `t_gid` | Taboola | `taboola.com` | Visitor id; generic-looking name |
| `outbrain_cid_fetch`, `obuid` | Outbrain | everywhere | Visitor ids |
| `_kuid_`, `_cc_id`, `_cc_cc`, `_cc_aud` | Salesforce DMP (Krux) | `krxd.net` | Audience ids; short generic names |
| `_an_uid` | Xandr | everywhere | Visitor id |
| `uuid2`, `anj` | Xandr | `adnxs.com` | Ad ids; generic names |
| `__qca` | Quantcast | everywhere | Visitor id |
| `_cb_ls`, `_cb_svref`, `_chartbeat<n>` | Chartbeat | everywhere | Visitor and referrer. Bare `_cb` dropped: too short to be unique |

The popup shows **links cleaned** (this tab) and **cookies removed** (tracking
cookies, this site). **Stop cleaning on this site**: links to that site keep their
parameters and are not unwrapped, and its own tracking cookies stay. Its
pages' third-party requests to tracker hosts still go without cookies: an
allow at the cleaning tier for its subresources would also lift every URL
filter below that tier. **Relaxed** is the level that lifts third-party
cookie stripping too. URL filters and everything else stay on.

## Privacy signals and leak reducers

| Measure | Protects against | Could break | Escape hatch |
| --- | --- | --- | --- |
| `Sec-GPC: 1` and `navigator.globalPrivacyControl` | Sites that honour GPC (it is a legal opt-out of sale/sharing in California, Colorado and others) | Nothing observed | None needed; no allow rule can switch it off |
| Third-party beacons blocked | `sendBeacon` and `<a ping>` reporting to another site | A site whose own analytics lives on a separate registrable domain | Relaxed, or a timed exception |
| `ping` attributes removed | First-party click tracking via hyperlink auditing | Nothing: the link still navigates | Cleaning off for the site |
| `Referrer-Policy` tightened | A page that opted into sending full addresses (with query strings) to every third party | Partner sites that check a full `Referer`; rare | Relaxed |
| Referer removed from third-party frames (Strict) | The frame's server learning which page embeds it | Embeds that check the Referer (YouTube does; it is excepted) | Standard, or Allow host |

The Referer is cut to the origin only where a page asked for more: Chrome's
default policy already sends only the origin cross-site, and DNR cannot
rewrite a header to a computed value. A page can still override the policy
per element or with a `<meta>` tag. Removing the Referer header from a frame
request does not empty that frame's `document.referrer`, and Chrome also
gives every frame `location.ancestorOrigins`, which no extension can change:
a third-party frame's own script can still learn the embedding site. No
tracking request headers were stripped: the ones that matter are cookies
(handled above) and Chrome's `X-Client-Data`, which extensions cannot see.

**What a site can still notice.** `navigator.globalPrivacyControl` is a
getter on `Navigator.prototype` (never on `navigator` itself) made from a
bound native function, so `toString()` reads `function () { [native code]
}`, it has no `prototype` and its name is `get globalPrivacyControl`; a
script comparing it with Firefox's or Brave's native getter can still tell
(the native `toString` includes the name, and the native getter throws on a
foreign receiver). A tracking cookie a script sets disappears within
milliseconds, which the script can observe by reading it back. An unwrapped
link arrives with no `Referer` and no hop through the redirector, which the
destination can notice. Blocked requests fail, as with any blocker. None of
this identifies the person; it says some privacy tool runs.

## Fingerprinting

Fingerprinting and session-replay scripts are **blocked by address**, which
works when they are served first-party or through a vendor's custom
subdomain: the loaders keep telltale paths and parameters
(`?apiKey=…&loaderVersion=`, `?ci=js/`, `/fp/tags?org_id=`,
`/hotjar-<id>.js?sv=`, `/s/fs.js`, `/rec/bundle`). Fraud-prevention
fingerprinting (ThreatMetrix, iovation) is on that list too; a bank or a
checkout that requires it may ask for extra verification. Set that site to
Relaxed.

The browser APIs themselves (canvas, WebGL, audio, fonts, screen) are **not
changed**. An experimental fingerprint-noise switch (0.3.0) was **removed**
in 0.3.1 rather than shipped half-fixed: it keyed the noise by each frame's
own site, so a third-party frame got one stable value on every site that
embedded it (a cross-site identifier, the opposite of the point); its key was
handed to the page world through DOM events a page script could listen for or
fake; and it was easy to detect. Doing it soundly needs a per-session secret
mixed with the top-level site, delivered to every frame (including
`about:blank` and `srcdoc` frames, workers and `OffscreenCanvas`) through a
channel no page script can reach, which this pass could not prove. The
worker unregisters the old scripts on installs that had it on.

Egress Guard never generates fake traffic to trackers or advertisers (no
automatic ad clicks, fake page views or decoy searches): that sends deceptive
requests to third parties, costs them money, can break site terms, and makes
this browser more conspicuous, not less.

## Site modes and click-to-load

The popup's **Protection on this site** sets one of four levels, and
**Default for other sites** sets Standard or Strict for every site without its
own level:

| Mode | What it does |
| --- | --- |
| Relaxed | Host lists, malware protection, GPC and your rules only. URL filters, beacon blocking, link unwrapping, parameter and cookie stripping, Strict and the Referrer-Policy fix stand down (`allowAllRequests` below the threat list, so threats stay blocked) |
| Standard | Everything described above |
| Strict | Standard, plus third-party scripts, frames, fonts and plugins blocked except a short list of payment, sign-in, captcha and public script CDN providers (`FUNCTIONAL_HOSTS` in `core/dnr.js`, each justified there); third-party `Cookie` and `Set-Cookie` removed on its subresources; the Referer removed from third-party frames; third-party `preconnect`, `dns-prefetch`, `prefetch` and `prerender` hints removed from the page (best effort: Chrome may act on a hint before the page script sees it, and DNR cannot see connection hints); YouTube, X, Instagram, Facebook, TikTok and Disqus embeds held |
| No scripts | Strict, plus every script the site's pages request is blocked and a `script-src 'none'` Content-Security-Policy is appended to them, so inline scripts do not run either. Switching a site to No scripts (or Strict) unregisters its service workers and clears its Cache Storage, so a worker cannot serve cached pages and scripts no rule sees. That reaches the origins the extension can name (the site, `www.`, and every origin of the site open in a tab); another subdomain's worker stays until Chrome's own site-data clearing removes it, and the popup says so |

**Click-to-load.** Under Strict and No scripts a held embed is replaced by a
local placeholder in the embed's own box: "Held by Egress Guard", the
provider and kind ("YouTube video"), **Load video** and a quiet **Load signed
in**. One real click (synthetic clicks are
ignored) adds a session rule for that provider in that tab only and loads it;
the allowance ends when the tab navigates. The embed still loads **without
cookies**: the allow sits below Strict's and the tracker-host cookie
stripping. **Load signed in** (loads with cookies) is the explicit second
choice. A refused click adds one line in the threat colour.
The page owns the DOM around the placeholder, so it is hardened against
clickjacking: the host element has `!important` inline styles and
`all:initial !important`, and a click counts only when Chrome's
IntersectionObserver v2 (`trackVisibility`) has reported the button fully
visible and unobscured for half a second, the button is at least 24 × 16 px,
no ancestor is transparent, hidden or filtered, and the pointer is on the
button itself. For script-built embeds (tweets,
Instagram posts) the page's own provider script is added back.

**One-click repair.** A request Strict blocked shows **Allow host** in the
popup's list; that host is then allowed on this site under Strict until you
remove it there.

**Strict is not the default.** Measured on the 23-site real-site run
(2026-11-21, headless Chrome 157, below): of the 18 sites that render in the
control run, Strict broke or degraded these, while Standard broke none:

| Site | What Strict did | One-click repair |
| --- | --- | --- |
| tomsguide.com | Page hung (main thread busy, nothing painted): its own scripts on `vanilla.futurecdn.net` were blocked, and with them allowed its ad-recovery scripts (`html-load.com`, `content-loader.com`) still loop | Set the site to Standard. **Allow host** for `vanilla.futurecdn.net` was not enough |
| login.live.com | Sign-in form blank: its scripts are on `msftauth.net` / `msauth.net` | Fixed: both are now on the functional list; the form renders under Strict |
| theguardian.com | Renders, but 20 of its own scripts and fonts on `assets.guim.co.uk` blocked (no menus, comments or live updates; fallback fonts) | **Allow host** `assets.guim.co.uk` |
| foodnetwork.com | Renders, 17 own scripts and fonts on `food.fnr.sndimg.com` blocked (5 new page errors) | **Allow host** `food.fnr.sndimg.com` |
| checkout.stripe.dev | Renders and the payment frame works; 29 Google Fonts requests blocked, so fallback fonts | None needed |

Most large sites serve their own code from a separately registered CDN
domain, which Strict treats as third party, so as a default it would degrade
most news and shopping sites and silently break some. It ships as an opt-in
level per site (or as the default, for someone who accepts the repairs);
Standard stays the default.

## Surrogates

When a blocked tracker is something the page calls into, blocking it can
break the page: a link that waits for `dataLayer`'s `eventCallback` never
navigates, `googletag.cmd` never runs. Eleven requests for Google Analytics
(`analytics.js`, `ga.js`), Google Tag Manager (`gtm.js`, `gtag/js`), the Meta
pixel, Segment, Adobe Launch and Google Publisher Tag / AdSense are redirected
to small stubs in `browser/surrogates/` (written for this project, no network,
no storage, web-accessible only by a per-session address). They define the
same API, call the callbacks pages wait for, and do nothing else. The tracker
receives nothing: the request never leaves the browser. A surrogate sits above
the host lists and below your own rules, so your block rule or timed exception
still decides.

## CNAME-cloaked trackers: what else was evaluated

The build already ships AdGuard's CNAME-cloaked ads and trackers lists (the
first-party subdomains themselves, which is what a browser sees). Measured on
2026-11-20 against HaGeZi PRO++ and those lists:

- **NextDNS cname-cloaking-blocklist**: about 120 entries, and they are the
  CNAME *targets* (`eulerian.net`, `omtrdc.net`, …), useful to a resolver that
  follows CNAMEs, useless to a browser rule that sees only the first-party
  name. Its raw file now returns 404. Not added.
- **AdGuard disguised mail trackers** (308,642 names, 308,380 not on the
  shipped lists): mostly Salesforce Marketing Cloud and similar subdomains,
  including the landing and preference-centre pages subscribers need. Webmail
  proxies images anyway. Blocking their subresources would break unsubscribe
  pages for little gain. Not added.
- **AdGuard disguised click-throughs** (37,348 names, 37,105 new): navigations,
  which the lists never block, so blocking adds nothing; but they are exactly
  the bounce redirectors whose cookies should not survive the hop. Added to
  the `bounce` ruleset (cookies stripped, never blocked), MIT, recorded in
  `NOTICE.txt`.

### What it does not do (Chrome)

- **No YouTube or other in-stream video ads.** In-stream ads are chosen in
  the player's own data (`ytInitialPlayerResponse`, `/youtubei/v1/player`)
  and served from the same hosts as the video. DNR can block separate ad
  endpoints (for example `doubleclick.net`, already on the lists) but cannot
  edit JSON responses. MV3 blockers that do this (uBlock Origin Lite) ship
  bundled scriptlets injected into the page's main world with the
  `scripting` permission: bundled code, not remote code, so it is possible,
  but it needs a scriptlet per site, breaks when YouTube changes its player,
  and could only be verified on a page that actually serves an ad. Headless
  Chrome without a signed-in profile or consent state does not reliably get
  ads, so nothing was implemented and nothing is claimed.
- **Cosmetic hiding is a small built-in set plus your own rules.** No
  third-party cosmetic lists, no `:has()`, no text matching: an
  "Advertisement" label in plain text next to a hidden slot can remain.
- **No anti-adblock or consent-wall handling.** Out of scope; no scriptlets.
- Lists update when the folder is rebuilt (see above); nothing in the
  extension downloads them. The build warns when a list is more than 48 hours
  old.
- Domain blocking covers subdomains, so a CNAME entry also blocks names below
  it. The proxy matches those CNAME entries exactly.
- Your per-site rules are scoped by the requesting frame's site (DNR
  `initiatorDomains`). On the page's own requests this is the page's site;
  requests made inside a third-party iframe are scoped to that iframe's site.
- Fingerprinting. `warning.html` is web-accessible with `use_dynamic_url`, so
  a page cannot fetch it at the fixed id (the headless check confirms the
  fetch is refused); Chrome still performs the DNR redirect to it. A site can
  still infer that *some* blocker runs from requests that fail, as with any
  blocker.

## Your own rules (both browsers)

- **Endpoint rules.** A request rule names a top-level site, one exact
  destination host, a path pattern, resource types and an action. A
  same-origin `/collect` beacon can be refused while the article, login and
  video on that page still load. Add one under **Rules for this site → Add an
  endpoint rule**.
- **Element hiding, reversible.** Each hidden element gets a small placeholder
  with **Show** and **Hide again**. **Restore this page** puts everything back
  for the current page load.
- **Block an element…** Click the ad; the companion proposes a specific
  selector (never class-only, since sponsored and organic cards often share
  every class), shows how many elements it matches, and saves a rule only
  after a real click on **Create rule**. **Undo** removes it.
- **Timed exceptions.** **Allow 15 min** on a blocked request allows that
  exact path, site and resource type only.

In Chrome these compile to dynamic `declarativeNetRequest` rules on one
priority ladder (`browser/core/dnr.js`):

| Priority | Rules |
| --- | --- |
| 22 | `Sec-GPC: 1` (header only; above every allow so nothing switches it off) |
| 21 | Timed exceptions (allow) |
| 20 | Your allow rules |
| 19 | Your block rules |
| 18 | Surrogates (stub instead of block) |
| 17 | Ad, tracker and CNAME host lists |
| 16 | Continue once (session `allow`, one tab, one host and its own requests) |
| 15 | Malware and phishing lists |
| 14 | Relaxed sites (`allowAllRequests`) |
| 13 | A clicked-to-load embed "with cookies" |
| 12 | "Continue through the scanner" (session `allow`, one tab, one scanner host, one navigation) |
| 11 | Mail scanners to the interstitial |
| 10 | No scripts' `script-src 'none'` header |
| 9 | Cleaning: parameter stripping, link unwrapping, unsubscribe-page allow, Referrer-Policy fix, tracker-host, bounce and Strict cookie stripping, Strict's Referer removal, the per-site "Stop cleaning" brake |
| 8 | A clicked-to-load embed (lifts Strict's blocks, not its cookie stripping) |
| 7 | Strict and No scripts blocks |
| 6 | Hand-written fingerprinting, session-replay and first-party tracker filters; third-party beacons |
| 5 | `$important` URL filters |
| 4 | EasyPrivacy's own exceptions |
| 3 | EasyPrivacy filters |
| 2 | EasyList's own exceptions |
| 1 | EasyList filters |

So an exception really wins over every list, no list exception reaches cookie stripping, cleaning or the hand-written filters, continuing to a flagged site
does not unblock that site's trackers, and nothing a filter list or a site
mode allows can reach the threat list.

### Rule limits

The validator (`browser/core/rules.js`, `selectors.js`, `hosts.js`) refuses
anything it is unsure about:

- Site is required and must be a real hostname. IP addresses, single labels
  (`localhost`, `com`) and public suffixes (`co.uk`, `github.io`) are refused.
  The suffix guard is a short built-in list plus a heuristic for country
  registries; unlisted suffixes may be accepted.
- Destination host is exact: no wildcards or subdomain matching.
- Paths start with `/`, match the URL path only (never the query), allow at
  most three `*` wildcards, and must contain real literal text. `/`, `*`,
  `/*`, regular-expression characters, queries and dot segments are refused.
  Chrome rules use an anchored, escaped regular expression built from the
  validated pattern; Firefox uses a plain glob.
- `main_frame` cannot be blocked by your rules or the ad and tracker lists.
- Selectors use a small grammar: tag, `#id`, `.class`, attribute tests,
  structural pseudo-classes and `:not()`. `*`, `html`, `body`, `main`, bare
  tags like `div`, pseudo-elements, `:has()`, and anything script-like are
  refused.
- When applied, a rule never hides the page body, main content, forms,
  inputs, video, audio or dialogs, or anything that contains them. A rule that
  matches more than 25 elements on a page is skipped and reported.

## Firefox: load temporarily

Build as above, or use the sources directly: open
`about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on…**
and select `dist-browser/firefox/manifest.json` (or `browser/manifest.json`).
If host access shows as optional, allow it under `about:addons` →
Permissions, then reload open pages. The add-on and its rules disappear when
Firefox quits.

## Permissions and why

| Permission | Browser | Why |
| --- | --- | --- |
| `declarativeNetRequest` | Chrome | Built-in lists, your rules and exceptions as browser-enforced rules |
| `declarativeNetRequestFeedback` | Chrome | List what was blocked on the current tab in the popup |
| `webRequest`, `webRequestBlocking` | Firefox | Cancel matching requests before they are sent |
| `http://*/*`, `https://*/*` | Both | Run the hiding script on pages and apply rules to them |
| `storage` | Both | Keep rules and exceptions locally |
| `alarms` | Both | Remove exceptions and rules when they expire |
| `cookies` | Chrome | Delete tracking cookies (by name, `core/cookies.js`) the moment they are set |
| `contextMenus`, `offscreen`, `clipboardWrite` | Chrome | "Copy clean link": the offscreen extension page writes the clipboard so the site never sees the copy |
| `browsingData` | Chrome | Unregister a site's service workers and clear its Cache Storage when it is switched to No scripts or Strict |
| `scripting` | Chrome | Only to unregister the retired fingerprint-noise scripts on installs that had them; due to be dropped next release |

No `tabs`, `history`, `webRequest` or native messaging. There is
no remote code: extension pages allow only their own scripts. In Chrome,
`connect-src 'self'` lets the worker read its own packaged threat ruleset
(packed builds, to check a host before Continue); it makes no network
requests. Firefox keeps `connect-src 'none'`. List data is compiled into the
extension at build time.

## Licences of bundled list data

The extension code is MIT licensed. A Chrome build contains rulesets derived
from HaGeZi DNS Blocklists (GPL-3.0), EasyPrivacy and EasyList (dual GPL-3.0
or CC BY-SA 3.0, used under GPL-3.0) and the AdGuard CNAME tracker and
disguised click-through lists (MIT). The build writes `NOTICE.txt` with each source URL, licence, entry
count, publication time and SHA-256. Building and using it yourself needs
nothing more. If you give a built copy to someone else, include that notice,
the GPL-3.0 text and the list sources. See
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Honest limits (both)

- Hiding happens after load. Hiding an ad does not undo requests it already
  made; add an endpoint rule for that.
- Request blocking is not proof of zero contact. The browser may resolve DNS
  or preconnect before a rule applies. The proxy and DNS layers stay
  responsible for that.
- First-party, server-side processing is out of reach.
- Sites change markup and paths; remove a rule that breaks a page.
- This complements uBlock Origin Lite rather than replacing it: no cosmetic
  filter lists, scriptlets or per-site filter syntax. EasyList's and
  EasyPrivacy's network filters are compiled; their element-hiding rules are
  not.
- YouTube in-stream ads remain out of scope: no method was verified in
  headless Chrome, so none is claimed.

## Code layout

`browser/core/` has no browser APIs: validation, decisions, the store
(storage injected), picker candidates, and `dnr.js`, which compiles both the
list rulesets (at build time) and your rules (at run time). `background.js`
is the Firefox adapter; `background-chrome.js` is the Chrome service worker.
`content.js`, `popup.*`, `ui.css` are shared; `warning.*` and `unwrap.*` are Chrome-only.
`scripts/build-browser.mjs` assembles both builds, verifies the feeds again
and bundles the Chrome worker into one file.

## What was verified, and how

Node tests (no dependencies): `node --test 'tests/browser/*.test.cjs'`
cover validation and hostile inputs, fixture request decisions, the Firefox
adapter, the Chrome adapter with a fake `chrome`, the DNR compiler (list
chunking, priority ladder, exceptions against lists, continue-once, regex
equivalence with the Firefox glob, parameter stripping), the build (snapshot
tampering, feed metadata in sync with `feeds.py`, output layout), content
script, picker and popup, and a source scan for `innerHTML`, `eval`, remote
URLs and networking calls. `filters.test.cjs` adds the filter compiler
(conversion, drops and their reasons, folding, `$badfilter`, exception
precedence against host lists, threats, your rules and `$important`),
link unwrapping with hostile inputs (nested, double-encoded, IDN, repeated
and empty parameters, `javascript:`/`data:`/`file:`/extension destinations,
credentials, control characters, lookalike hosts, too-deep nesting), the
link cleaner (global versus per-site names, a legitimate `ref` elsewhere,
OAuth and unsubscribe parameters kept, encoding preserved) and its agreement
with the navigation rules, tracking-cookie names (and the session, login,
cart and consent cookies that must not match), cookie and bounce rules and
the per-site brake, GPC, beacons, the Referrer-Policy patterns, site modes,
click-to-load rules, and the surrogates (run in a VM: callbacks fire, queues
drain, no network or storage APIs). With the build tests, 91 tests.

`node tests/browser/chrome-privacy.mjs [--real-filters] [--shots DIR]`
(headless Chrome, throwaway profile, loopback fixture, 44 checks): a
first-party `gtm.js` and `/g/collect` blocked while the list's own exception
loads; proxied Hotjar and a Fingerprint Pro agent blocked; Relaxed lifts URL
filters but not host lists; `Sec-GPC: 1` on page and subresource requests and
`navigator.globalPrivacyControl`; third-party `sendBeacon` blocked and a
first-party one sent; no ping request from a clicked `<a ping>`;
`Referrer-Policy: unsafe-url` cut to the origin; `google.com/url` opens the
destination without contacting Google, a credentialed or `javascript:`
destination is refused and the latter never redirected; GA, GTM and GPT
surrogates run the page's callbacks; click-time cleaning (mousedown, right
click, a page that swaps the href on mousedown, `t.co` with
`data-expanded-url`, a functional `ref` kept), navigation-time cleaning with
unsubscribe tokens kept, address-bar cleaning after a client-side
`replaceState`, Copy clean link through the offscreen page, `_ga` and `_fbp`
removed while a preference cookie stays, the popup's counts, the per-site
brake; Strict blocking a third-party script while the site's own and inline
code run, holding a Disqus frame and dropping connection hints, attributing
the block, loading the embed on one real click and ending that allowance on
navigation, **Allow host**, removing the Referer from a third-party frame;
No scripts stopping own and inline scripts and clearing a service worker and
its caches; unwrapping only from the redirector's own site (Chrome's own
`testMatchOutcome` agrees), an unwrapped threat-listed destination landing
on the warning page, the scanner interstitial (no auto-navigation, no
framing, Continue passing the scanner its untouched address once, Open
directly to a listed host landing on the warning page, the setting), a
loaded embed carrying no cookies, a click on a transparent placeholder
loading nothing, surrogate callbacks with no extension frame on the stack,
and the GPC getter's shape.

Real Chrome (157, headless, throwaway profile, loopback fixture only):
`node tests/browser/chrome-headless.mjs [--feeds DIR] [--shots DIR]`. It
builds the extension with the fixture lists (with `--feeds`, the full lists
plus the fixture names), loads it with `Extensions.loadUnpacked` over
`--remote-debugging-pipe`, maps only fixture hostnames to 127.0.0.1 and every
other name to NOTFOUND, with no proxy. Verified there: the fixed id; all four
rulesets enabled; a user rule blocks `/collect` on the publisher but not on an
IP origin; the page, script, stylesheet and session XHR load; the sponsored
card is hidden; a listed tracker and a CNAME-cloaked host are blocked and an
unlisted host loads; the popup state names each blocked request's list; a
15-minute exception lets exactly that tracker endpoint through while another
path on the same host stays blocked; `utm_source`, `fbclid` and `gclid` are
removed before the request and `id` is kept; a threat navigation shows the
warning page with host and list and the site receives nothing; two real
clicks continue once, loading the page and its own asset while its tracker
stays blocked; leaving the site removes the exception and returning shows the
warning again.

Real Firefox (headless, throwaway profile):
`node tests/browser/firefox-headless.mjs` covers the Firefox build's rules,
hiding, the picker and Undo.

Service-worker lifecycle (Chrome, headless, loopback fixture, about two
minutes): `node tests/browser/chrome-lifecycle.mjs`. A user rule, two timed
exceptions and a continue-once survive the worker being stopped and started;
Chrome keeps enforcing them while it is stopped; an exception and a continue
that expire while the worker is stopped are removed because `chrome.alarms`
wakes it (nothing else touches it); continue-once is stored with a 10-minute
expiry; a rebuilt folder is noticed and the popup asks for a reload.

### Real websites

`node tests/browser/real-sites.mjs [--feeds DIR] [--sites a,b] [--modes control,extension,strict]`
(opt-in; it contacts the public sites). Each site is loaded in headless
Chrome 157 with a throwaway profile and no proxy: without the extension, with
it (Standard), and with Strict as the default. It only navigates and reads:
no clicks, logins, forms or cookie banners. Before = the v0.4.0 build (same
lists, same day); after = this build. Run 2026-11-21 with HaGeZi PRO++,
HaGeZi Threat Intelligence Full, URLhaus, Phishing Army, AdGuard CNAME,
EasyPrivacy and EasyList. Blocked counts vary from load to load with ad
auctions (cnn.com: 7,220 host-list blocks before, 1,763 after, the same
lists). "Links with tracking" counts the page's links that carry tracking
parameters v0.4.0 would strip, then the links this build cleans or unwraps;
"tracker cookies" are cookies matching `core/cookies.js` present after the
load.

| Site | Kind | Host lists before → after (trackers/CNAME) | New categories after | Links with tracking v0.4 / now | Tracker cookies control → ext | JS errors control → before → after | Text control → after | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cnn.com | news | 7220/0 → 1763/0 | easylist 3 | 13 / 53 | 0 → 0 | 10 → 10 → 9 | 10,148 → 9,905 | renders |
| theguardian.com | news | 27/0 → 18/0 | fp-trackers 1, surrogates 1 | 0 / 0 | 0 → 0 | 18 → 17 → 16 | 18,236 → 18,236 | renders |
| foxnews.com | news | 37/2 → 36/2 | easyprivacy 1, easylist 1, beacons 1, surrogates 3 | 2 / 18 | 0 → 0 | 13 → 13 → 14 | 22,339 → 22,337 | renders |
| dailymail.co.uk | news | 0/0 → 0/0 | – | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 216 → 214 | bot interstitial in all runs |
| weather.com | news | 33/0 → 7/0 | fp-trackers 1 (Vercel speed insights), easyprivacy 1 (mParticle identify), easylist 1 | 1 / 1 | 0 → 0 | 1 → 2 → 1 | 1,999 → 1,966 | renders (forecast loads slowly in headless in every mode) |
| allrecipes.com | recipe | 0/0 → 0/0 | – | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 316 → 316 | headless challenge in all runs |
| foodnetwork.com | recipe | 20/1 → 17/1 | easyprivacy 5, surrogates 2 | 2 / 2 | 0 → 0 | 0 → 0 → 0 | 2,303 → 2,303 | renders |
| theverge.com | tech | 13/0 → 0/0 | fp-trackers 1 | 3 / 7 | 3 → 0 | 1 → 1 → 1 | 22,104 → 23,088 | renders |
| techcrunch.com | tech | 8/0 → 7/0 | surrogates 2 | 0 / 0 | 0 → 0 | 0 → 1 → 0 | 11,081 → 11,081 | renders |
| tomsguide.com | tech | 1/0 → 0/0 | fp-trackers 2 | 0 / 0 | 0 → 0 | 3 → 3 → 3 | 20,546 → 20,548 | renders |
| bing.com search | search | 0/0 → 0/0 | easyprivacy 1 (`/fd/ls/l` logging) | 0 / 22 (22 unwrappable `ck/a` links) | 0 → 0 | 0 → 0 → 0 | 104 → 104 | Bing's own `rdr=1` hop mid-load in both runs; separate runs rendered 2,880–3,183 characters |
| html.duckduckgo.com | search | 0/0 → 0/0 | easyprivacy 1 | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 205 → 205 | bot challenge in all runs |
| github.com/login | sign-in | 2/0 → 2/0 | – | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 282 → 282 | form renders |
| accounts.google.com | sign-in | 0/0 → 0/0 | fp-trackers 1 | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 1,038 → 1,038 | form renders |
| login.live.com | sign-in | 0/0 → 0/0 | easyprivacy 2 (OneCollector telemetry) | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 231 → 231 | form renders |
| paypal.com/signin | sign-in | 0/0 → 0/0 | easyprivacy 1 | 0 / 0 | 0 → 0 | 2 → 2 → 2 | 0 → 0 | captcha in all runs |
| checkout.stripe.dev | checkout | 0/0 → 0/0 | – | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 584 → 584 | renders |
| allbirds.com/cart (Shopify) | checkout | 10/1 → 4/1 | fp-trackers 31, easyprivacy 6, surrogates 1 | 0 / 0 | 1 → 0 | 1 → 1 → 2 | 2,479 → 2,479 | renders |
| stape.io | server-side GTM | – | – | – | – | – | – | connection closed to headless Chrome in all runs |
| simoahava.com | server-side GTM | 2/0 → 2/0 | – | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 3,129 → 3,129 | renders |
| plausible.io | self-hosted | – | – | – | – | – | – | connection closed to headless Chrome in all runs |
| posthog.com | self-hosted | 0/0 → 0/0 | easyprivacy 2 | 0 / 0 | 0 → 0 | 1 → 0 → 3 | 10,058 → 10,006 | renders; the extra errors are PostHog's own loader reporting its blocked SDK |
| matomo.org | self-hosted | 0/0 → 19/0 | fp-trackers 1 | 0 / 0 | 0 → 0 | 0 → 0 → 0 | 7,627 → 7,627 | renders |

What this layer adds: 73 requests caught by the new categories on the 23
sites (first-party tracker scripts 38, EasyPrivacy 20, surrogates 9,
EasyList 5, beacons 1), none of which the host lists catch; 103 tracking-
decorated links cleaned or unwrapped across the pages against 21 that v0.4.0
would have cleaned; tracker cookies left after a load 4 → 0. Standard broke
nothing: every site that rendered in the control run rendered the same text
with the extension (weather.com and Bing vary between runs in every mode).
Two problems were found and fixed: cutting Microsoft's `MUID` cookie to a
session cookie made Bing render no results (Bing rendered again once `MUID`
was left alone), and Strict blanked the login.live.com form (Microsoft's
sign-in CDNs are now on the functional list). The Strict results are above,
under "Site modes". Server-side GTM sites in the set either use a renamed
loader that EasyPrivacy does not name (simoahava.com, whose two host-list
blocks are its Google hosts) or refused headless Chrome, so first-party sGTM
paths were verified on the fixture, not on a live site.

Not verified in a real browser: the popup opened from the toolbar (captures
open `popup.html?tab=<id>` in a tab), a packed build (the counts fallback is
covered by the adapter tests only), automatic reload after a rebuild in a
normal profile, Firefox dark mode, and YouTube.
