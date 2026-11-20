# Firefox browser companion (experimental)

The proxy sees only the hostname of each connection. It cannot tell
`https://publisher.example/article` from `https://publisher.example/collect`,
and it cannot touch page elements. The companion in `browser/` is a Firefox
extension that can do both, for rules you add yourself. It is unsigned, not
released, and not yet connected to the proxy.

## What it does

- **Blocks endpoints before they are sent.** A request rule names a top-level
  site, one exact destination host, a path pattern, resource types and an
  action. `webRequest.onBeforeRequest` cancels matching requests, so a
  same-origin `/collect` beacon can be refused while the article, login and
  video on that page still load.
- **Hides elements per site, reversibly.** A cosmetic rule names a site and a
  selector. Each hidden element gets a small placeholder with **Show** and
  **Hide again**. **Restore this page** in the popup puts everything back for
  the current page load.
- **Block an element.** From the popup, choose **Block an element…**, then
  click the ad. The companion proposes a specific selector (never a class-only
  one, since sponsored and organic cards often share every class), shows how
  many elements it matches, and saves a site rule only after a real click on
  **Create rule**. **Undo** removes the rule and restores the element.
- **Temporary exceptions.** Each blocked request in the popup has
  **Allow 15 min**. It allows that one exact path, for that site and that
  resource type only, and is removed automatically when it expires. You can
  remove it sooner.
- **Popup.** Lists what was blocked before sending, what is hidden after
  loading, this site's rules, and exceptions with time left. Plain system
  fonts; all page-derived text is set with `textContent`.

## Rules and their limits

The validator (`browser/core/rules.js`, `selectors.js`, `hosts.js`) refuses
anything it is unsure about:

- Site is required and must be a real hostname. IP addresses, single labels
  (`localhost`, `com`) and public suffixes (`co.uk`, `github.io`) are refused.
  The suffix guard is a short built-in list plus a heuristic for country
  registries. A maintained Public Suffix List is future work; until then,
  unlisted suffixes may be accepted, and listed ones are always refused.
- Destination host is exact: no wildcards or subdomain matching.
- Paths start with `/`, match the URL path only (never the query), allow at
  most three `*` wildcards, and must contain real literal text. `/`, `*`,
  `/*`, regular-expression characters, queries and dot segments are refused.
  Matching is a plain glob, never a `RegExp` built from input.
- `main_frame` cannot be blocked, so a rule can never stop navigation.
- Selectors use a small grammar: tag, `#id`, `.class`, attribute tests,
  structural pseudo-classes and `:not()`. `*`, `html`, `body`, `main`, bare
  tags like `div`, pseudo-elements, `:has()`, and anything script-like (`<`,
  `{`, `;`, `url(`, `javascript:`, `on*` attributes) are refused.
- Unknown fields are refused. Rules may carry `expiresAt`; exceptions must.
- When applied, a rule never hides the page body, main content, forms,
  inputs, video, audio or dialogs, or anything that contains them. A rule that
  matches more than 25 elements on a page is skipped and reported.

The site for a request comes only from browser data: the request URL for
navigations, the last `frameAncestors` entry for frames, `documentUrl` for the
top frame, or the tab's last navigation. Page content is never consulted.
If no top-level site is known, the request is allowed.

## Load it temporarily in Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on…** and select `browser/manifest.json`.
3. If Firefox lists host access as optional, allow it in
   `about:addons` → Egress Guard Companion → Permissions.
4. Reload open pages. The add-on and its rules disappear when Firefox quits.

## Permissions and why

| Permission | Why |
| --- | --- |
| `webRequest`, `webRequestBlocking` | Cancel matching requests before they are sent. |
| `http://*/*`, `https://*/*` host access | See requests and run the hiding script on pages. |
| `storage` | Keep rules and exceptions locally. |
| `alarms` | Remove exceptions and rules when they expire. |

No `tabs`, `scripting`, `cookies`, `history` or native messaging. There is no
remote code; extension pages allow only their own scripts and
`connect-src 'none'`. The extension makes no network requests of its own.

## Honest limits

- Hiding happens after load. Hiding an ad does not undo requests it already
  made; add a request rule for that.
- Request blocking is not proof of zero contact. Firefox may resolve DNS,
  preconnect or prefetch before a request reaches the extension. The proxy and
  DNS layers stay responsible for that.
- First-party, server-side processing is out of reach: data the site's server
  already has or forwards stays there.
- A site can change its markup or paths and break a rule. Restore and remove
  the rule if a page breaks.
- In-memory state (blocked list, last navigation per tab) resets when Firefox
  suspends the background script. Rules and exceptions are stored.
- This is a small, rule-at-a-time tool. Use it alongside uBlock Origin, not
  instead of it.

## Code layout and seams

- `browser/core/` is free of browser APIs: `hosts.js`, `selectors.js`,
  `rules.js` (validation), `decide.js` (request decisions and top-level
  resolution), `store.js` (rules, exceptions, expiry; storage injected) and
  `picker.js` (selector candidates).
- `background.js` is the Firefox adapter. A Chrome DNR compiler can translate
  validated rules from the same store into `declarativeNetRequest` rules, and a
  native-messaging adapter can sync the store with the proxy, both without
  changing `core/`.
- Sponsor Skip/Undo from the earlier page-controls candidate is not carried
  over. Its pure timing validator was clean, but its player controls depended
  on YouTube markup and its DOM tests needed Happy DOM, which this repo does
  not install. It can return as its own module later.

## What was verified, and how

Node tests (no dependencies): `node --test 'tests/browser/*.test.cjs'`.
They cover validation, hostile inputs, decisions for every fixture request,
store expiry, the background adapter with a fake `browser` namespace, the
content script and picker on a hand-rolled DOM stub, the popup, and a source
scan for `innerHTML`, `eval`, remote URLs and networking calls.

Real Firefox (160.0.1, headless, throwaway profile, loopback fixture only):
`node tests/browser/firefox-headless.mjs`. It installs a temporary copy with a
test-only file that seeds the fixture rules and opens the picker on `#pick`.
Verified there: the manifest installs; `/collect` reaches the server from an IP
origin (control) but is cancelled on `publisher.example` while the article,
script, stylesheet, session XHR and video media load; only the sponsored card
is hidden; **Show** restores it on a real click; the placeholder's shadow root
is closed to page scripts; real clicks in the picker create a rule hiding only
the picked card, and **Undo** restores it.

Only in Node tests, not yet in a real browser: the popup itself, exceptions and
their expiry, the endpoint-rule form, frame ancestry for subframes, behaviour
after the background script is suspended, dynamic pages, dark mode, and any
real website.
