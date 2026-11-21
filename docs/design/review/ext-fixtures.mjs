// Fixture states for capturing the real extension pages (browser/*.html) with a stubbed extension API.
// Used by capture.mjs --extension. Strings are real and awkward on purpose: a 70-character hostname, an IDN host in
// punycode, long paths, 9,999+ counts and the longest list names the build ships.
const day = (d) => Date.UTC(2026, 10, d, 9) / 1000;
const sha = (seed) => (seed.repeat(64)).slice(0, 64);

export const LISTS = [
  {id: "threats", label: "Malware and phishing", name: "HaGeZi Threat Intelligence (Medium), URLhaus malware hosts (malware-filter), Phishing Army", domains: 412880, rules: 9, published_at: day(18),
    sources: [{name: "HaGeZi Threat Intelligence (Medium)", sha256: sha("4f1c9a0e"), last_modified: "2026-11-18T06:12:00.000Z"},
      {name: "URLhaus malware hosts (malware-filter)", sha256: sha("a9e2b7d1"), last_modified: "2026-11-19T02:40:00.000Z"},
      {name: "Phishing Army", sha256: sha("0c7f3e55"), last_modified: "2026-11-19T11:05:00.000Z"}]},
  {id: "trackers", label: "Ads and trackers", name: "HaGeZi Multi PRO++", domains: 236117, rules: 5, published_at: day(18),
    sources: [{name: "HaGeZi Multi PRO++", sha256: sha("77d0be12"), last_modified: "2026-11-18T05:00:00.000Z"}]},
  {id: "cname", label: "Disguised trackers", name: "AdGuard CNAME-cloaked trackers", domains: 61204, rules: 2, published_at: day(19),
    sources: [{name: "AdGuard CNAME-cloaked trackers", sha256: sha("e3b0c442"), last_modified: "2026-11-19T08:00:00.000Z"}]},
  {id: "filters", label: "URL filters", name: "EasyPrivacy, AdGuard disguised click-throughs", domains: 0, rules: 4210, updated_at: day(20),
    sources: [{name: "EasyPrivacy", sha256: sha("19ab84c0"), last_modified: "2026-11-20T07:30:00.000Z"},
      {name: "AdGuard disguised click-throughs", sha256: sha("5d2e6f90"), last_modified: "2026-11-20T07:30:00.000Z"}]},
];
const CATEGORIES = {threats: "Malware and phishing", trackers: "Ads and trackers", cname: "Disguised trackers", "fp-trackers": "First-party tracker script",
  easyprivacy: "Tracking request", easylist: "Ad request", replay: "Fingerprinting or session replay", beacons: "Third-party beacon",
  links: "Link tracker unwrapped", surrogates: "Tracker answered by a stub", strict: "Strict mode (third party)", noscript: "Scripts off for this site",
  embeds: "Embed held until clicked", user: "Your rules"};
const TYPES = ["beacon", "ping", "xmlhttprequest", "script", "image", "imageset", "stylesheet", "font", "media", "sub_frame", "object", "csp_report", "other"];

const BLOCKED = [
  {host: "publisher.example", path: "/sgtm/gtm.js", type: "script", list: "fp-trackers", count: 1},
  {host: "publisher.example", path: "/g/collect", type: "image", list: "fp-trackers", count: 3},
  {host: "securepubads.g.doubleclick.net", path: "/pagead/managed/js/gpt/m202611180101/pubads_impl.js", type: "script", list: "trackers", count: 1},
  {host: "tracker-fixture.test", path: "/p.gif", type: "image", list: "trackers", count: 2},
  {host: "publisher.example", path: "/hotjar-123.js", type: "script", list: "replay", count: 1},
];

export const BASE = {
  host: "publisher.example", site: "publisher.example", lists: LISTS, categories: CATEGORIES, types: TYPES, feedback: "debug", blocked: BLOCKED,
  mode: "standard", siteMode: null, defaultMode: "standard", strictAllowed: [], scannedDirect: false, generic: true, rebuilt: false,
  cleaning: {on: true, links: 11, cookies: 0},
  requestRules: [{id: "r1", kind: "request", host: "cdn.segment.com", path: "/v1/t", types: ["beacon", "xmlhttprequest"]}],
  cosmeticRules: [],
  exceptions: [{id: "e1", host: "tracker-fixture.test", path: "/p.gif", type: "image", msLeft: 12 * 60000}],
};
export const PAGE = {site: "publisher.example", paused: false, reason: "", hidden: 2, shown: 0, protectedRules: [], overbroadRules: [],
  generic: {available: true, on: true, wanted: true, slots: 2}};

const LONG_HOST = "accounts.internal-billing-portal.eu-west1.cdn.example-enterprise.co.uk";   // 70 characters
const IDN_HOST = "xn--pypal-4ve.com";
const many = (n) => Array.from({length: n}, (_, i) => ({host: `ads${i}.tracker-network-${i}.example`, path: `/v${i}/pixel/${"a".repeat(i % 7 + 3)}/collect.gif`, type: i % 3 ? "image" : "script", list: i % 4 ? "trackers" : "cname", count: 1 + (i % 3)}));

/** Popup scenarios: [name, state, page status, url, setup JS run after render]. */
export const POPUP = [
  ["main", BASE, PAGE, "https://publisher.example/article/2026/council-plan"],
  ["blocked", BASE, PAGE, null, "tab:blocked"],
  ["blocked-focus", BASE, PAGE, null, "tab:blocked;focusrow:1"],
  ["rules", {...BASE, cosmeticRules: [{id: "c1", kind: "cosmetic", selector: "article.card.teaser[data-ad-slot]"}]}, PAGE, null, "tab:rules"],
  ["rules-add", BASE, PAGE, null, "tab:rules;add"],
  ["settings", BASE, PAGE, null, "tab:settings"],
  ["blocked-empty", {...BASE, host: "docs.python.org", site: "python.org", blocked: [], requestRules: [], exceptions: [], cleaning: {on: true, links: 0, cookies: 0}},
    {...PAGE, hidden: 0, generic: {available: true, on: true, wanted: true, slots: 0}}, null, "tab:blocked"],
  ["rules-empty", {...BASE, host: "docs.python.org", site: "python.org", blocked: [], requestRules: [], exceptions: []}, {...PAGE, hidden: 0}, null, "tab:rules"],
  ["longhost", {...BASE, host: LONG_HOST, site: "example-enterprise.co.uk", mode: "strict",
    blocked: [...many(40), {host: LONG_HOST, path: "/static/js/vendor/analytics/2026-11-20/session-recorder.bundle.min.js", type: "script", list: "replay", count: 9999},
      {host: IDN_HOST, path: "/signin/session/expired/redirect/continue", type: "image", list: "trackers", count: 12}],
    cleaning: {on: true, links: 12480, cookies: 9999}}, {...PAGE, hidden: 10234}, null],
  ["longhost-blocked", null, null, null, "same:longhost;tab:blocked"],
  ["idn", {...BASE, host: IDN_HOST, site: IDN_HOST}, PAGE, null],
  ["threat", {...BASE, blocked: [{host: "cdn.bad-fixture.example", path: "/payload/loader.js", type: "script", list: "threats", count: 1}, ...BLOCKED]}, PAGE, null],
  ["threat-blocked", null, null, null, "same:threat;tab:blocked;focusrow:0"],
  ["packed", {...BASE, feedback: "counts", blocked: [], counts: {threats: 1, trackers: 24, cname: 3, "fp-trackers": 6}}, PAGE, null],
  ["packed-blocked", null, null, null, "same:packed;tab:blocked"],
  ["badge", {...BASE, feedback: "badge", blocked: []}, PAGE, null],
  ["badge-blocked", null, null, null, "same:badge;tab:blocked"],
  ["reduced", {...BASE, rebuilt: true}, PAGE, null],
  ["paused", {...BASE, mode: "relaxed", resumeMode: "standard", paused: Date.UTC(2026, 10, 20, 21, 42)}, {...PAGE, hidden: 0, generic: {available: true, on: false, wanted: false, slots: 0}}, null],
  ["hiding-restored", BASE, {...PAGE, paused: true, reason: "Restored for this page load."}, null, "tab:rules"],
  ["unsupported", {site: null, lists: LISTS}, null, "chrome://newtab/"],
  ["firefox", {host: "publisher.example", site: "publisher.example", requestRules: [], cosmeticRules: [], exceptions: [], blocked: BLOCKED.slice(0, 3), types: TYPES}, PAGE, null],
];

/** The stub installed before the popup's scripts run. */
export function popupStub(state, page, url) {
  return `(() => {
  const state = ${JSON.stringify(state)}, page = ${JSON.stringify(page)}, url = ${JSON.stringify(url || "https://" + ((state && state.host) || "publisher.example") + "/article")};
  window.chrome = {runtime: {id: "capture", sendMessage: async (m) => m.type === "popup-state" ? JSON.parse(JSON.stringify(state)) : {ok: true}},
    tabs: {query: async () => [{id: 1, url}], sendMessage: async () => page ? JSON.parse(JSON.stringify(page)) : null, get: async () => ({id: 1, url})}};
  window.close = () => {};
})();`;
}

export const WARNING_STUB = `window.chrome={runtime:{sendMessage:async(m)=>m.type==="warning-info"?{list:{label:"Malware and phishing",name:"HaGeZi Threat Intelligence (Medium)",published_at:${day(18)}},minutes:10}:{}},tabs:{update:async()=>{}}};`;
export const UNWRAP_STUB = `window.chrome={runtime:{sendMessage:async(m)=>m.type==="unwrap-config"?{scannedDirect:false}:m.type==="check-destination"?{threat:false}:{ok:true}}};`;

const safelinks = (dest) => "https://nam02.safelinks.protection.outlook.com/?url=" + encodeURIComponent(dest) + "&data=05%7C02%7Cj.doe%40contoso.example%7C9f2c%7C0&sdata=kQ3vZ7&reserved=0";
/** Page scenarios: [name, file, query+hash, stub]. */
export const PAGES = [
  ["warning", "warning.html", "?list=threats#https://login-verify.example-phish.test/account/session?continue=%2Fwallet&ref=mail-campaign-2026-11-20", WARNING_STUB],
  ["warning-confirm", "warning.html", "?list=threats#https://login-verify.example-phish.test/account/session?continue=%2Fwallet&ref=mail-campaign-2026-11-20", WARNING_STUB, "document.getElementById('reveal').click()"],
  ["warning-long", "warning.html", `?list=threats#https://${LONG_HOST}/very/long/path/that/keeps/going/and/going/index.php?session=8f2c91d0b7a64e2f9c1d&continue=%2F`, WARNING_STUB],
  ["interstitial", "unwrap.html", "#" + safelinks("https://calendar.partner-workspace.example.com/invite/accept?event=8f2c91d0-quarterly-review&tz=America%2FChicago"), UNWRAP_STUB],
  ["interstitial-idn", "unwrap.html", "#" + safelinks("https://xn--pypal-4ve.com/signin?session=expired"), UNWRAP_STUB],
  ["interstitial-server", "unwrap.html", "#https://protect-eu.mimecast.com/s/AbCdEfGhIjKlMn?domain=calendar.partner-workspace.example.com", UNWRAP_STUB],
  ["unread", "unwrap.html", "#https://www.google.com/url?q=not-a-web-address-Zm9vYmFyLWVuY29kZWQtcGF5bG9hZC10aGF0LWNhbm5vdC1iZS1kZWNvZGVk&sa=D", UNWRAP_STUB],
];
