# Safari on iPhone: feasibility (research, not yet built)

Status, 20 November 2026: research only. The Mac this was checked on has no Xcode
(`xcode-select -p` is `/Library/Developer/CommandLineTools`; `xcodebuild`, `simctl` and
`safari-web-extension-converter` are absent; no iOS simulator runtimes; 0 code-signing
identities; 0 Xcode teams). Nothing below has been run in a simulator or on a phone.

Chrome on iOS cannot run extensions. Safari on iOS runs Safari Web Extensions and native
content blockers, but only when shipped inside an iOS app.

## What Safari supports (iOS mirrors macOS unless noted)

Source for versions: MDN browser-compat-data,
[declarativeNetRequest.json](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/declarativeNetRequest.json),
[webRequest.json](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/webRequest.json),
[storage.json](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/storage.json),
[alarms.json](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/alarms.json),
[manifest/background.json](https://github.com/mdn/browser-compat-data/blob/main/webextensions/manifest/background.json),
[manifest/web_accessible_resources.json](https://github.com/mdn/browser-compat-data/blob/main/webextensions/manifest/web_accessible_resources.json).

| Feature we use | Safari / iOS Safari |
|---|---|
| DNR block, static rulesets | 15 |
| DNR `redirect` (incl. `transform.queryTransform`) | 15.4; compat data lists only `addOrReplaceParams`, not `removeParams` |
| DNR `modifyHeaders` request headers | 16.4; response headers: not supported |
| DNR `requestDomains` / `excludedRequestDomains` | 16.4 |
| DNR `initiatorDomains` | 18.4 |
| DNR dynamic and session rules | 15.4 |
| `onRuleMatchedDebug`, `getDisabledRuleIds`, `updateStaticRules`, `responseHeaders` conditions | not supported |
| `webRequest` | iOS 18, observational only (`BlockingResponse` unsupported; `extraInfoSpec` from 18.4) |
| `storage.session` | 16.4; `storage.sync` does not sync |
| `alarms` | iOS 15 |
| Background | iOS requires non-persistent: `persistent: false` or `service_worker` |
| `web_accessible_resources` `use_dynamic_url` | partial: "The extension's base URL is always dynamic in Safari" |

Rule limits, from an Apple engineer's accepted answer
([forum thread 756931](https://developer.apple.com/forums/thread/756931)): "The rule limit for a
Safari content blocker is 150,000 rules, Safari Web Extension declarativeNetRequest rules are
translated into content blocker rules, and that limit is also 150,000 rules." Plus 100 static
rulesets, 50 enabled, 30,000 dynamic and session rules. Apple does not document a cap on the
number of content-blocker extensions in one app; AdGuard ships six
([AdGuard KB](https://adguard.com/kb/adguard-for-ios/features/safari-protection/)), wBlock five
([wBlock](https://github.com/0xCUB3/wBlock)). AdGuard reports iOS 17 rejecting or crashing on large
compiled lists, sometimes at 40-60k rules
([AdGuard 4.5.1](https://adguard.com/en/blog/adguard-v4-5-1-for-ios.html)).

Native content-blocker JSON
([Apple: Creating a content blocker](https://developer.apple.com/documentation/safariservices/creating-a-content-blocker))
has `block`, `block-cookies`, `css-display-none`, `ignore-previous-rules`, `make-https`; no
redirect and no parameter stripping.

Lifecycle: iOS 17.4-17.6 killed background workers after about 30 seconds on devices, fixed in
17.6.1; on iOS 18 developers still report listeners going deaf after Safari is backgrounded
([758346](https://developer.apple.com/forums/thread/758346),
[756309](https://developer.apple.com/forums/thread/756309)). Design for a background that may
be dead: anything on the blocking path must be declarative.

Permissions: on iOS the user grants access from Safari's extension menu and can choose
"Always Allow on Every Website" (or per site / for one day), or set Allow in Settings > Apps >
Safari > Extensions
([Apple: managing permissions](https://developer.apple.com/documentation/safariservices/managing-safari-web-extension-permissions)).
Private Browsing: "In Safari 17 and later, when you grant access to an extension for a specific
web site, that grants the extension access to the site across all profiles, private browsing,
and browsing without a profile" (same page); the extension itself must also be allowed in
Private Browsing in its settings.

## Architecture this points to

Today's Chrome build ships about 1.5M threat, 257k tracker and 178k CNAME domains as DNR
rules. Safari caps the whole web extension at 150,000 rules, so the split is:

- DNS layer on the phone (separate work): the full hostname lists.
- Web extension (one 150k budget): compact high-confidence threat set with the local warning
  page (URLhaus filter, about 19k lines, plus Phishing Army, about 146k lines, will not both fit
  with anything else; take URLhaus plus the newest Phishing Army entries up to about 100k),
  path-level tracker rules, per-site rules and timed exceptions as dynamic rules (30k cap),
  ad-slot hiding CSS and the picker in the content script.
- Tracking-parameter stripping: DNR `removeParams` is not listed for Safari, so strip in the
  content script (`history.replaceState` on load, rewrite link `href`s on click) and treat DNR
  redirect stripping as a test item.
- Optional native content blockers in the same app, about 100k rules each to stay clear of the
  iOS 17 size failures: top tracker domains ranked by how often their registrable domain occurs
  in the tracker and CNAME lists, three blockers giving about 300k.

Open questions only a build can answer: whether one DNR rule with N `requestDomains` counts as
one rule or N after translation; whether `queryTransform.removeParams` works despite the compat
data; and whether the warning-page redirect to an extension page works for main-frame loads.

## Getting it onto one iPhone

1. Free Apple Account (Personal Team): 7-day provisioning profiles, 3 apps per device, 10 App
   IDs per 7 days, reinstall from Xcode with the phone connected every week; Developer Mode
   must be on ([Apple: membership comparison](https://developer.apple.com/support/compare-memberships/)).
   The app plus its extensions each take an App ID. App Groups support on free teams is
   disputed, so the design avoids App Groups.
2. Apple Developer Program, $99 a year: one-year profiles for own devices, TestFlight (builds
   expire after 90 days), or App Store review.
3. Existing free apps: uBlock Origin Lite (free, open source, MV3 DNR with EasyList,
   EasyPrivacy, Peter Lowe's; iOS 18.5+; no custom rules)
   ([ublockorigin.com/safari](https://ublockorigin.com/safari/)); AdGuard (free Safari content
   blockers with user rules; DNS and advanced features paid); 1Blocker (free tier blocks one
   category); Wipr 2 (about $4.99 one-off, no custom rules).
