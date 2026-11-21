# Browser companion (experimental)

The proxy sees only the hostname of each connection. It cannot tell
`https://publisher.example/article` from `https://publisher.example/collect`,
cannot strip `?utm_source=` from a link, and cannot touch page elements. The
companion in `browser/` can. One set of sources builds two extensions:

- **Chrome** (primary): built-in ad, tracker and malware lists, tracking
  parameter stripping, a local warning page for malware and phishing sites,
  plus your own per-site rules. Built on `declarativeNetRequest`.
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
   each list. Options: `--feeds DIR` (a feed cache other than the proxy's
   data directory), `--tier pro|pro.plus|ultimate` (default `pro.plus`, the
   proxy's default), `--no-lists` (your own rules and parameter stripping
   only), `--out DIR` (default `dist-browser/`, which git ignores).

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
| Malware and phishing | Every request type, and navigations go to a local warning page | HaGeZi Threat Intelligence (Medium) |
| Tracking parameters | Removed from page and frame navigations before the request is sent | Built-in list in `browser/core/dnr.js` |

These are the proxy's own feeds and tiers. With 2026-11-20 data the build
holds about 257,000 tracker, 376,000 threat and 178,000 CNAME domains
(about 25 MB of rules); Chrome indexed and enforced them in the headless
check below.

**Warning page.** A navigation to a threat-listed site never reaches it. The
page shows the host, the full address, the list and its date. **Go back** is
the default. **I understand the risk…** reveals **Continue to this site
once**, which adds a session rule for that tab and that host only. Ads and
trackers stay blocked on the continued page. The exception ends when the tab
leaves the site, after 10 minutes, or when Chrome restarts.

**Parameters removed** (exact names): `utm_source`, `utm_medium`,
`utm_campaign`, `utm_term`, `utm_content`, `utm_id` and other `utm_*` names
listed in the source, `fbclid`, `gclid`, `gclsrc`, `dclid`, `gbraid`,
`wbraid`, `msclkid`, `yclid`, `twclid`, `ttclid`, `igshid`, `li_fat_id`,
`mc_eid`, `_hsenc`, `_hsmi`, `mkt_tok`, `oly_anon_id`, `oly_enc_id`,
`vero_id`, `rb_clickid`, `s_cid`, `wickedid`, `epik`, `_openstat`,
`srsltid`. Functional parameters such as `id`, `q`, `ref` or `v` are kept.

**Popup.** It leads with what was blocked on this page: the count, a
breakdown by list, then each endpoint with its type and list and **Allow 15
min**. Below that: elements hidden on the page, this site's rules with
**Remove**, timed exceptions, and the list versions the build contains. It
follows the system light or dark setting. The toolbar badge shows Chrome's
own per-tab count of blocked requests.

### What it does not do (Chrome)

- **No YouTube or other in-stream video ads.** Those come from the same
  hosts as the video and need script-level filtering. Not attempted, not
  tested.
- **No cosmetic filter lists.** Only elements you pick are hidden. Empty ad
  slots may remain where a blocked ad was.
- **No path-level list filtering.** The lists are domain lists. A tracker
  served from a site's own domain is only blocked if you add an endpoint rule.
- Lists update when you rebuild and reload, not daily on their own. The
  build warns when a list is more than 48 hours old.
- Domain blocking covers subdomains, so a CNAME entry also blocks names below
  it. The proxy matches those CNAME entries exactly.
- Your per-site rules are scoped by the requesting frame's site (DNR
  `initiatorDomains`). On the page's own requests this is the page's site;
  requests made inside a third-party iframe are scoped to that iframe's site.
- The list of blocked endpoints in the popup relies on Chrome's
  `onRuleMatchedDebug`, which exists only for unpacked extensions. A packed
  build would show the count badge only.
- The extension id and `warning.html` are web-accessible, so a site can tell
  that this extension is installed.

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
| 7 | Timed exceptions (allow) |
| 6 | Your allow rules |
| 5 | Your block rules |
| 4 | Ad, tracker and CNAME lists |
| 3 | Continue once (session, one tab, one host) |
| 2 | Malware and phishing lists |
| 1 | Tracking-parameter stripping |

So an exception really wins over every list, and continuing to a flagged site
does not unblock that site's trackers.

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

No `tabs`, `scripting`, `cookies`, `history` or native messaging. There is
no remote code: extension pages allow only their own scripts with
`connect-src 'none'`, and the extension makes no network requests of its
own. List data is compiled into the extension at build time.

## Licences of bundled list data

The extension code is MIT licensed. A Chrome build contains rulesets derived
from HaGeZi DNS Blocklists (GPL-3.0) and the AdGuard CNAME tracker lists
(MIT). The build writes `NOTICE.txt` with each source URL, licence, entry
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
  filter lists, scriptlets or per-site filter syntax.

## Code layout

`browser/core/` has no browser APIs: validation, decisions, the store
(storage injected), picker candidates, and `dnr.js`, which compiles both the
list rulesets (at build time) and your rules (at run time). `background.js`
is the Firefox adapter; `background-chrome.js` is the Chrome service worker.
`content.js`, `popup.*`, `ui.css` are shared; `warning.*` is Chrome-only.
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
URLs and networking calls.

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

Not verified in a real browser: the popup opened from the toolbar (captures
open `popup.html?tab=<id>` in a tab), behaviour after the service worker is
stopped and restarted, the 10-minute continue cap, Firefox dark mode, and any
real website.
