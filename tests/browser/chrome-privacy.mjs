// Optional real-Chrome check for the URL-level protections. Not part of `node --test`; run it explicitly:
//   node tests/browser/chrome-privacy.mjs [--chrome PATH] [--real-filters] [--shots DIR]
// Builds the extension with the fixture host lists and a small fixture EasyPrivacy-style list (with
// --real-filters, the cached EasyPrivacy and EasyList too, offline), loads it into headless Chrome with a
// throwaway profile over the DevTools pipe, and serves fixture pages from 127.0.0.1. Host resolution maps only
// the fixture names to loopback and everything else to NOTFOUND, with no proxy: nothing external is contacted.
// Checks: first-party tracker paths, the lists' exceptions, fingerprinting and session-replay paths, Relaxed
// sites, Sec-GPC and navigator.globalPrivacyControl, third-party beacons and <a ping>, the Referrer-Policy fix,
// link unwrapping (only from the redirector's own site; refusal of hostile destinations; threat-listed destinations to
// the warning page), the mail-scanner interstitial, surrogates (and their callback stacks), site modes, click-to-load
// embeds (and a clickjacked placeholder), No scripts clearing service workers, tracker cookie lifetimes and the popup.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {build, loadLists, loadFilters, defaultFiltersDir} from "../../scripts/build-browser.mjs";
import {launch, attachWorker, waitFor, sleep, DEFAULT_CHROME} from "./cdp.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const argv = process.argv.slice(2);
const opt = (name, fallback = null) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : fallback; };
const shots = opt("--shots");
fs.mkdirSync(path.join(root, ".cache"), {recursive: true});
const work = fs.mkdtempSync(path.join(root, ".cache", "chrome-privacy-"));
const results = [];
const check = (name, ok, detail = "") => { results.push({name, ok, detail}); console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };

// ---- build ----------------------------------------------------------------------------
const FIXTURE_FILTERS = `[Adblock Plus 2.0]
! Title: EasyPrivacy
! Licence: https://easylist.to/pages/licence.html
/gtm.js
/g/collect?
@@/allowed/gtm.js$domain=publisher.example
||tracker-fixture.test^$third-party
`;
const filters = {easyprivacy: {text: FIXTURE_FILTERS, source: {id: "easyprivacy", name: "EasyPrivacy (fixture)", url: "fixture", license: {name: "fixture", url: "fixture"}, sha256: "-", fetched_at: Math.floor(Date.now() / 1000)}}};
if (argv.includes("--real-filters")) {
  const real = await loadFilters(defaultFiltersDir(), {offline: true, log: (m) => console.log(`note: ${m}`)});
  if (real.easyprivacy) filters.easyprivacy = {...real.easyprivacy, text: `${real.easyprivacy.text}\n${FIXTURE_FILTERS.split("\n").slice(3).join("\n")}`};
  if (real.easylist) filters.easylist = real.easylist;
}
const lists = loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true});
const built = build({out: path.join(work, "dist"), lists, filters});
const ext = path.join(work, "dist", "chrome");
console.log(`built: ${built.staticRules} static rules (${Object.entries(built.rulesets).map(([k, v]) => `${k} ${v}`).join(", ")})`);

// ---- fixture server ---------------------------------------------------------------------
const hits = [];
let port = 0;
const GIF = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");
const pages = {
  "/fp": () => `<!doctype html><title>fp</title><p id="t">first-party trackers</p>
<script>
window.probe = (src) => new Promise((r) => { const s = document.createElement("script"); s.src = src; s.onload = () => r("ok"); s.onerror = () => r("error"); document.head.append(s); });
window.img = (src) => new Promise((r) => { const i = new Image(); i.onload = () => r("ok"); i.onerror = () => r("error"); i.src = src; });
</script>`,
  "/links": () => `<!doctype html><title>links</title><a id="pinglink" href="/landing" ping="/ping-first http://clean-fixture.test:${port}/ping-third">go</a>`,
  "/landing": () => `<!doctype html><title>landing</title><p>landing</p>`,
  "/dest": () => `<!doctype html><title>destination</title><p id="dest">destination</p>`,
  "/refpage": () => `<!doctype html><title>ref</title><img id="r" src="http://clean-fixture.test:${port}/ref.gif">`,
  "/surrogate": () => `<!doctype html><title>s</title><body>
<script>window.stacks = []; window.grab = function () { stacks.push(new Error("probe").stack); };
window.dataLayer = []; window.GoogleAnalyticsObject = "ga"; window.ga = function () { (ga.q = ga.q || []).push(arguments); };</script>
<script src="http://www.google-analytics.com/analytics.js"></script>
<script src="http://www.googletagmanager.com/gtm.js?id=GTM-FIXTURE"></script>
<script src="http://securepubads.g.doubleclick.net/tag/js/gpt.js"></script>
<script>
ga("send", "pageview", {hitCallback: function () { grab(); document.body.dataset.ga = "1"; }});
dataLayer.push({event: "x", eventCallback: function () { grab(); document.body.dataset.gtm = "1"; }});
googletag.cmd.push(function () { grab(); googletag.defineSlot("/1/x", [300, 250], "ad").addService(googletag.pubads()); googletag.enableServices(); document.body.dataset.gpt = "1"; });
</script>`,
  "/embeds": () => `<!doctype html><title>embeds</title><p id="t">article with a video</p>
<iframe id="yt" width="560" height="315" src="http://disqus.com:${port}/embed/comments/?f=fixture" title="comments"></iframe>
<script src="http://cdn-assets.test:${port}/lib.js"></script><script src="/static/own.js"></script><script>window.inline = 1;</script>
<link rel="preconnect" href="http://cdn-assets.test:${port}"><link rel="dns-prefetch" href="//tracker-fixture.test">`,
  "/frameref": () => `<!doctype html><title>frames</title><iframe id="f" src="http://cdn-assets.test:${port}/framepage"></iframe>`,
  "/framepage": () => `<!doctype html><title>frame</title><script>new Image().src = "/report?r=" + encodeURIComponent(document.referrer);</script>`,
  "/cookies": () => `<!doctype html><title>cookies</title><script>document.cookie = "_ga=GA1.1.123.456; max-age=63072000; path=/"; document.cookie = "_fbp=fb.1.2.3; max-age=7776000; path=/"; document.cookie = "prefs=dark; max-age=63072000; path=/";</script>`,
  "/clicks": () => `<!doctype html><title>clicks</title><body>
<a id="tracked" href="http://clean-fixture.test:${port}/dest?utm_source=x&id=3">tracked</a>
<a id="wrapped" href="https://www.google.com/url?q=${encodeURIComponent(`http://clean-fixture.test:${port}/dest?b=2&fbclid=x`)}&sa=U">wrapped</a>
<a id="hijack" href="http://clean-fixture.test:${port}/dest?id=4">hijacked on mousedown</a>
<a id="tco" href="https://t.co/AbCdEf" data-expanded-url="http://clean-fixture.test:${port}/dest?x=1&utm_source=tw">t.co</a>
<a id="plain" href="http://clean-fixture.test:${port}/dest?ref=main&id=5">plain</a>
<script>document.getElementById("hijack").addEventListener("mousedown", function () { this.href = "https://www.google.com/url?q=" + encodeURIComponent("http://clean-fixture.test:${port}/dest?id=4&gclid=hijack"); });</script>`,
  "/results": () => `<!doctype html><title>results</title><body>
<a id="r1" href="http://www.google.com/url?q=${encodeURIComponent(`http://clean-fixture.test:${port}/dest?a=1`)}&usg=X">result</a>
<a id="r2" href="http://www.google.com/url?q=${encodeURIComponent(`http://malware-fixture.test:${port}/payload`)}&usg=Y">bad result</a>`,
  "/url": () => `<!doctype html><title>google redirect notice</title><p id="notice">The page you were on is trying to send you to another site.</p>`,
  "/scanner": () => `<!doctype html><title>scanner</title><p id="scanned">scanner checked it</p>`,
  "/sw.js": () => "",
  "/swpage": () => `<!doctype html><title>sw</title><script>window.swReady = navigator.serviceWorker.register("/sw.js").then(() => navigator.serviceWorker.ready).then(() => caches.keys()).then((k) => k.length);</script>`,
  "/clickjack": () => `<!doctype html><title>clickjack</title><p>article</p><div id="wrap"><iframe id="yt" width="560" height="315" src="http://disqus.com:${port}/embed/comments/?f=cj" title="comments"></iframe></div>`,
  "/dest2": () => `<!doctype html><title>dest2</title><script>history.replaceState(null, "", "/dest2?gclid=zzz&k=1&mc_eid=abc");</script>`,
};
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://fixture");
  const host = (req.headers.host || "").replace(/:\d+$/, "");
  hits.push({host, path: url.pathname, query: url.search, gpc: req.headers["sec-gpc"] || null, referer: req.headers.referer || null, cookie: req.headers.cookie || null, method: req.method});
  const send = (code, type, body, extra = {}) => { res.writeHead(code, {"content-type": type, "cache-control": "no-store", ...extra}); res.end(body); };
  if (url.pathname === "/sw.js") {
    return send(200, "text/javascript", `self.addEventListener("install", (e) => e.waitUntil(caches.open("eg-fixture").then((c) => c.put("/cached.js", new Response("window.fromCache = 1", {headers: {"content-type": "text/javascript"}})))));
self.addEventListener("fetch", (e) => { if (e.request.url.endsWith("/cached.js")) e.respondWith(caches.match("/cached.js")); });`);
  }
  if (host.endsWith("safelinks.protection.outlook.com")) return send(200, "text/html; charset=utf-8", pages["/scanner"]());
  if (pages[url.pathname]) {
    const extra = url.pathname === "/refpage" ? {"referrer-policy": "unsafe-url"} : {};
    return send(200, "text/html; charset=utf-8", pages[url.pathname](), extra);
  }
  if (host === "www.youtube.com" || host === "disqus.com") return send(200, "text/html; charset=utf-8", `<!doctype html><p id="player">player</p>`);
  if (url.pathname === "/set3p.gif") return send(200, "image/gif", GIF, {"set-cookie": "tp=1; Path=/; Max-Age=600"});
  if (/\.js$/.test(url.pathname)) return send(200, "text/javascript", `window.loaded = (window.loaded || []).concat(${JSON.stringify(url.pathname)});`);
  if (/\.(gif|png)$/.test(url.pathname) || req.method === "POST") return send(200, "image/gif", GIF);
  return send(404, "text/plain", "not found");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
port = server.address().port;
const FIXTURE_HOSTS = ["publisher.example", "www.publisher.example", "tracker-fixture.test", "clean-fixture.test", "cdn-assets.test", "www.youtube.com", "disqus.com",
  "www.google.com", "malware-fixture.test", "nam02.safelinks.protection.outlook.com"];
const P = (p) => `http://publisher.example:${port}${p}`;
const hitPaths = () => hits.map((h) => `${h.host}${h.path}`);

// ---- Chrome ---------------------------------------------------------------------------------
const profile = path.join(work, "profile");
fs.mkdirSync(profile);
const browser = launch({bin: opt("--chrome", DEFAULT_CHROME), profile, args: ["--no-proxy-server", `--unsafely-treat-insecure-origin-as-secure=http://publisher.example:${port}`,
  "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,OptimizationHints,MediaRouter,Translate",
  `--host-resolver-rules=${FIXTURE_HOSTS.map((h) => `MAP ${h} 127.0.0.1`).join(", ")}, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`, "--window-size=1280,900"]});
const {cdp, evaluate} = browser;
async function until(session, expression, label, ms = 20000) {
  const ok = await waitFor(async () => Boolean(await evaluate(session, expression)), ms, 150);
  if (!ok) check(label, false, "timed out");
  return ok;
}
async function navigate(session, url) {
  await cdp("Page.navigate", {url}, session);
  await sleep(300);
  await waitFor(async () => (await evaluate(session, "document.readyState")) === "complete", 20000, 150);
}
async function click(session, selector) {
  const box = await evaluate(session, `(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return {x: r.left + r.width / 2, y: r.top + r.height / 2}; })()`);
  for (const type of ["mousePressed", "mouseReleased"]) await cdp("Input.dispatchMouseEvent", {type, x: box.x, y: box.y, button: "left", clickCount: 1}, session);
}
async function screenshot(session, file, width) {
  await cdp("Emulation.setDeviceMetricsOverride", {width, height: 600, deviceScaleFactor: 2, mobile: false}, session);
  await sleep(500);
  const height = await evaluate(session, "Math.ceil(Math.max(document.documentElement.scrollHeight, document.body.scrollHeight))");
  await cdp("Emulation.setDeviceMetricsOverride", {width, height, deviceScaleFactor: 2, mobile: false}, session);
  await sleep(200);
  const {data} = await cdp("Page.captureScreenshot", {format: "png"}, session);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`screenshot ${file}`);
}

try {
  const loaded = await cdp("Extensions.loadUnpacked", {path: ext});
  check("extension loads", loaded.id === built.extensionId, loaded.id);
  const id = loaded.id;
  let sw = await attachWorker(cdp, id);
  const swEval = async (expression) => {
    for (let attempt = 1; ; attempt++) {
      try { return await evaluate(sw.sessionId, expression); } catch (error) {
        if (attempt >= 3) throw error;
        sw = await attachWorker(cdp, id);
      }
    }
  };
  await waitFor(async () => (await swEval("typeof __EGBackground")) === "object", 30000);
  await swEval("__EGBackground.ready.then(() => true)");
  const enabled = await swEval("chrome.declarativeNetRequest.getEnabledRulesets()");
  const want = ["params", "links", "gpc", "referrer", "beacons", "surrogates", "fp-trackers", "easyprivacy", "filter-allow", "replay"];
  check("every new ruleset is enabled", want.every((r) => enabled.includes(r)), enabled.join(","));
  const popupSender = `{id: chrome.runtime.id, url: chrome.runtime.getURL("popup.html")}`;
  const popupState = (tabId, url) => swEval(`__EGBackground.handle({type: "popup-state", tabId: ${tabId}, tabUrl: ${JSON.stringify(url)}}, ${popupSender})`);
  const popupAct = (tabId, url, msg) => swEval(`__EGBackground.handle({...${JSON.stringify(msg)}, tabId: ${tabId}, tabUrl: ${JSON.stringify(url)}}, ${popupSender})`);

  const {targetId} = await cdp("Target.createTarget", {url: "about:blank"});
  const page = (await cdp("Target.attachToTarget", {targetId, flatten: true})).sessionId;
  await cdp("Page.enable", {}, page);
  await cdp("Runtime.enable", {}, page);

  // 1. First-party and proxied trackers by path; the list's own exception; fingerprinting and replay paths.
  hits.length = 0;
  await navigate(page, P("/fp"));
  const fp = await evaluate(page, `Promise.all([probe("/sgtm/gtm.js?id=GTM-ABC"), probe("/allowed/gtm.js"), probe("/static/app.js"), probe("/hotjar-123.js?sv=6"),
    probe("/x/agent?apiKey=AbCdEf123456&version=3&loaderVersion=3.11.6"), img("/g/collect?v=2&tid=G-1")])`);
  await sleep(300);
  check("URL filters: a first-party gtm.js is blocked, the list's @@ exception loads, an ordinary script loads", fp[0] === "error" && fp[1] === "ok" && fp[2] === "ok", fp.join(","));
  check("URL filters: first-party /g/collect never reaches the server", fp[5] === "error" && !hitPaths().includes("publisher.example/g/collect"));
  check("replay: a proxied Hotjar loader and a FingerprintJS Pro agent are blocked", fp[3] === "error" && fp[4] === "error" && !hitPaths().some((p) => /hotjar|agent/.test(p)));
  // 3. GPC on the wire and in the page.
  const pageHit = hits.find((h) => h.path === "/fp");
  check("GPC: the page request carried Sec-GPC: 1", pageHit && pageHit.gpc === "1", JSON.stringify(pageHit && pageHit.gpc));
  check("GPC: subresources carry Sec-GPC: 1", hits.filter((h) => h.path !== "/fp").every((h) => h.gpc === "1"), hits.map((h) => `${h.path}:${h.gpc}`).join(" "));
  check("GPC: navigator.globalPrivacyControl is true in the page", (await evaluate(page, "navigator.globalPrivacyControl")) === true);
  // Beacons: third-party blocked, first-party allowed.
  hits.length = 0;
  await evaluate(page, `navigator.sendBeacon("http://clean-fixture.test:${port}/beacon-third", "x"); navigator.sendBeacon("/beacon-first", "x"); true`);
  await waitFor(() => hitPaths().includes("publisher.example/beacon-first"), 5000);
  await sleep(500);
  check("beacons: a third-party sendBeacon is blocked, a first-party one is sent", hitPaths().includes("publisher.example/beacon-first") && !hitPaths().includes("clean-fixture.test/beacon-third"), hitPaths().join(" "));
  const tabId = await swEval(`chrome.tabs.query({url: "http://publisher.example/*"}).then((t) => t[0].id)`);
  const fpState = await popupState(tabId, P("/fp"));
  const cats = [...new Set(fpState.blocked.map((b) => b.list))].sort();
  check("popup: blocks are attributed to named categories", ["beacons", "fp-trackers", "replay"].every((c) => cats.includes(c)) && fpState.categories["fp-trackers"] === "First-party tracker script", cats.join(","));
  // Relaxed: the escape hatch lifts URL filters on that site only; host lists stay.
  const relaxed = await popupAct(tabId, P("/fp"), {type: "set-mode", mode: "relaxed"});
  await navigate(page, P("/fp"));
  const rel = await evaluate(page, `Promise.all([probe("/sgtm/gtm.js?id=GTM-ABC"), img("http://tracker-fixture.test:${port}/p.gif")])`);
  check("relaxed: URL filters stand down on the site, host-list trackers stay blocked", relaxed.ok && rel[0] === "ok" && rel[1] === "error", rel.join(","));
  await popupAct(tabId, P("/fp"), {type: "set-mode", mode: "default"});

  // <a ping> is removed before it fires (first and third party).
  hits.length = 0;
  await navigate(page, P("/links"));
  await click(page, "#pinglink");
  await until(page, "location.pathname === '/landing'", "ping link navigates");
  await sleep(600);
  check("hyperlink auditing: no ping request was sent", !hits.some((h) => /ping-/.test(h.path)), hitPaths().join(" "));

  // Referrer-Policy: unsafe-url is tightened to Chrome's default.
  hits.length = 0;
  await navigate(page, P("/refpage?secret=1"));
  await waitFor(() => hits.some((h) => h.path === "/ref.gif"), 5000);
  const ref = hits.find((h) => h.path === "/ref.gif");
  check("referrer: a page asking for unsafe-url sends only its origin cross-site", ref && ref.referer === `http://publisher.example:${port}/`, ref && ref.referer);

  // 2. Link unwrapping: from the redirector's own site the redirector is never contacted; hostile destinations are
  // refused; a threat-listed destination lands on the warning page; from anywhere else the redirector keeps its check.
  await navigate(page, `http://www.google.com:${port}/results`);
  hits.length = 0;
  await evaluate(page, "location.href = document.getElementById('r1').href; true");   // a navigation started by Google's page (DNR path, not the click-time cleaner)
  const unwrapped = await until(page, `location.href === "http://clean-fixture.test:${port}/dest?a=1"`, "unwrapped link opens its destination");
  check("links: a google.com/url navigation started on Google goes through the unwrap page to the destination directly; Google is not contacted", unwrapped && hits.some((h) => h.path === "/dest") && !hits.some((h) => h.host === "www.google.com"), await evaluate(page, "location.href"));
  const linkState = await popupState(await swEval(`chrome.tabs.query({url: "http://clean-fixture.test/*"}).then((t) => t[0].id)`), `http://clean-fixture.test:${port}/dest?a=1`);
  check("links: the popup shows the unwrapped link tracker", linkState.blocked.some((b) => b.list === "links" && b.host === "www.google.com"), JSON.stringify({blocked: linkState.blocked, all: await swEval(`chrome.tabs.query({}).then((t) => t.map((x) => [x.id, x.url]))`), logs: await swEval(`chrome.storage.session.get(null).then((s) => Object.keys(s).filter((k) => k.startsWith("log:")).map((k) => [k, s[k].items.map((i) => i.list + ":" + i.host)]))`)}));
  await navigate(page, `chrome-extension://${id}/unwrap.html#https://www.google.com/url?q=${encodeURIComponent("https://user:pw@clean-fixture.test/")}`);
  await sleep(500);
  check("links: a destination with credentials is shown, not opened", (await evaluate(page, "location.protocol")) === "chrome-extension:" && !(await evaluate(page, "document.getElementById('card').hidden")));
  await navigate(page, `chrome-extension://${id}/unwrap.html#https://l.facebook.com/l.php?u=${encodeURIComponent("javascript:document.title='pwned'")}`);
  await sleep(400);
  check("links: a javascript: destination is refused", (await evaluate(page, "document.title")) !== "pwned" && (await evaluate(page, "location.protocol")) === "chrome-extension:");
  await navigate(page, `http://www.google.com/url?q=${encodeURIComponent("javascript:alert(1)")}`);
  await sleep(500);
  check("links: a javascript: destination is never redirected at all", !(await evaluate(page, "location.href")).startsWith(`chrome-extension://${id}/unwrap.html`));
  // The same wrapper arriving from elsewhere (typed, a mail client, another site): Google's own check stays.
  hits.length = 0;
  await navigate(page, `http://www.google.com/url?q=${encodeURIComponent(`http://clean-fixture.test:${port}/dest?typed=1`)}&utm_source=mail`);
  await sleep(800);
  const typedAt = await evaluate(page, "location.href");
  check("links: a google.com/url link typed or opened from another app is not unwrapped (Google's own check stays)",
    !typedAt.startsWith(`chrome-extension://${id}/unwrap.html`) && !hits.some((h) => h.path === "/dest"), typedAt);
  const match = (initiator) => swEval(`chrome.declarativeNetRequest.testMatchOutcome({url: "https://www.google.com/url?q=https%3A%2F%2Fexample.org%2F", type: "main_frame"${initiator ? `, initiator: "${initiator}"` : ""}}).then((r) => r.matchedRules.map((m) => m.rulesetId))`);
  const fromGoogle = await match("https://www.google.com"), fromMail = await match("https://mail.example"), fromNowhere = await match(null);
  check("links: Chrome itself matches the unwrap rule only for navigations started on Google",
    fromGoogle.includes("links") && !fromMail.includes("links") && !fromNowhere.includes("links"), JSON.stringify({fromGoogle, fromMail, fromNowhere}));
  await navigate(page, P("/clicks"));
  const otherSite = await (async () => {
    const box = await evaluate(page, `(() => { const r = document.querySelector("#wrapped").getBoundingClientRect(); return {x: r.left + 4, y: r.top + r.height / 2}; })()`);
    await cdp("Input.dispatchMouseEvent", {type: "mousePressed", x: box.x, y: box.y, button: "right", clickCount: 1}, page);
    await cdp("Input.dispatchMouseEvent", {type: "mouseReleased", x: 5, y: 600, button: "right", clickCount: 1}, page);
    await sleep(150);
    return evaluate(page, "document.querySelector('#wrapped').getAttribute('href')");
  })();
  check("links: the same wrapper on another site keeps its address at click time", otherSite.startsWith("https://www.google.com/url?q="), otherSite);
  // Unwrap -> threat list: the destination is checked before anything opens.
  await navigate(page, `http://www.google.com:${port}/results`);
  hits.length = 0;
  await evaluate(page, "location.href = document.getElementById('r2').href; true");
  const toWarning = await until(page, `location.href.startsWith("chrome-extension://${id}/warning.html") && document.getElementById("host").textContent === "malware-fixture.test"`, "unwrapped threat destination goes to the warning page");
  check("links: an unwrapped destination on the threat list lands on warning.html; the threat host is never contacted",
    toWarning && (await evaluate(page, "document.getElementById('host').textContent")) === "malware-fixture.test" && !hits.some((h) => h.host === "malware-fixture.test"), await evaluate(page, "location.href"));

  // 2b. Mail scanners: the interstitial; nothing opens by itself; Continue goes through the scanner; Open directly is checked.
  const scanUrl = (dest) => `http://nam02.safelinks.protection.outlook.com:${port}/?url=${encodeURIComponent(dest)}&data=05%7C02&sdata=sig&utm_source=x`;
  const scanned = scanUrl(`http://clean-fixture.test:${port}/dest?s=1`);
  hits.length = 0;
  await navigate(page, scanned);
  const onScan = await until(page, `location.href.startsWith("chrome-extension://${id}/unwrap.html") && !document.getElementById("scan").hidden`, "scanner link shows the interstitial");
  await sleep(1500);
  check("scanner: a Safe Links address shows the interstitial with the destination host and stays there; nothing is contacted",
    onScan && (await evaluate(page, "document.getElementById('scan-host').textContent")) === "clean-fixture.test" && (await evaluate(page, "location.protocol")) === "chrome-extension:" && hits.length === 0,
    JSON.stringify({host: await evaluate(page, "document.getElementById('scan-host').textContent"), hits: hitPaths()}));
  check("scanner: Continue through the scanner has the focus; Open directly says it skips the scan",
    (await evaluate(page, "document.activeElement && document.activeElement.id")) === "through" && /skips the mail scan/.test(await evaluate(page, "document.getElementById('direct').getAttribute('aria-label')")));
  const framed = await evaluate(page, `new Promise((r) => { const f = document.createElement("iframe"); f.src = location.href; f.onload = () => { try { r(f.contentDocument ? f.contentDocument.getElementById("scan") && !f.contentDocument.getElementById("scan").hidden : false); } catch (e) { r(false); } }; document.body.append(f); setTimeout(() => r(false), 3000); })`);
  check("scanner: the interstitial does not render inside a frame", framed === false, String(framed));
  await click(page, "#through");
  const through = await until(page, "location.hostname === 'nam02.safelinks.protection.outlook.com'", "Continue reaches the scanner");
  const scanHit = hits.find((h) => h.host === "nam02.safelinks.protection.outlook.com");
  check("scanner: Continue goes through the scanner with its address untouched (signature and every parameter)", through && scanHit && scanHit.query === new URL(scanned).search, JSON.stringify(scanHit));
  await sleep(300);
  const passesLeft = await swEval("chrome.declarativeNetRequest.getSessionRules().then((r) => r.filter((x) => x.id >= 200000 && x.id < 300000).length)");
  hits.length = 0;
  await navigate(page, scanned);
  await until(page, `location.href.startsWith("chrome-extension://${id}/unwrap.html")`, "the pass was for one navigation");
  check("scanner: the pass is used up; the next scanned link shows the interstitial again", passesLeft === 0 && !hits.some((h) => h.host.endsWith("outlook.com") && h.path === "/"), `${passesLeft} ${hitPaths().join(" ")}`);
  // Open directly to a threat-listed destination: warning page, nothing contacted.
  hits.length = 0;
  await navigate(page, scanUrl(`http://malware-fixture.test:${port}/doc`));
  await until(page, "!document.getElementById('scan').hidden", "threat scanner interstitial");
  await click(page, "#direct");
  const directWarn = await until(page, `location.href.startsWith("chrome-extension://${id}/warning.html")`, "Open directly to a listed host goes to the warning page");
  check("scanner: Open directly to a destination on the threat list lands on warning.html", directWarn && !hits.some((h) => h.host === "malware-fixture.test" || h.host.endsWith("outlook.com")), hitPaths().join(" "));
  // The setting (off by default) opens readable scanned links directly, still checked.
  await popupAct(tabId, P("/fp"), {type: "set-scanned-direct", on: true});
  hits.length = 0;
  await navigate(page, scanned);
  const direct = await until(page, `location.href === "http://clean-fixture.test:${port}/dest?s=1"`, "the setting opens scanned links directly");
  check("scanner: with Always open scanned links directly on, the destination opens and the scanner is skipped", direct && !hits.some((h) => h.host.endsWith("outlook.com")), hitPaths().join(" "));
  await popupAct(tabId, P("/fp"), {type: "set-scanned-direct", on: false});

  // 8. Surrogates: page code that calls into blocked trackers keeps working; nothing reaches the trackers.
  await navigate(page, P("/surrogate"));
  const surrogate = await until(page, "document.body.dataset.ga === '1' && document.body.dataset.gtm === '1' && document.body.dataset.gpt === '1'", "surrogates answered");
  check("surrogates: ga() hitCallback, dataLayer eventCallback and googletag.cmd all run with no tracker contacted", surrogate,
    JSON.stringify(await evaluate(page, "({ga: typeof ga, loaded: ga && ga.loaded, gt: typeof googletag, ds: {...document.body.dataset}, entries: performance.getEntriesByType('resource').map((e) => e.name.slice(0, 90))})")));
  const stacks = await evaluate(page, "window.stacks");
  check("surrogates: a page callback's stack shows no extension address", stacks.length >= 3 && stacks.every((st) => !/chrome-extension:/.test(st)), JSON.stringify(stacks));

  // 2 + owner priority: link cleaning at click time (on Google's own page, so its wrappers may be unwrapped), at
  // navigation, in the address bar, Copy clean link, cookies.
  await navigate(page, `http://www.google.com:${port}/clicks`);
  const press = async (selector, button = "left") => {
    const box = await evaluate(page, `(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return {x: r.left + 4, y: r.top + r.height / 2}; })()`);
    await cdp("Input.dispatchMouseEvent", {type: "mousePressed", x: box.x, y: box.y, button, clickCount: 1}, page);
    await cdp("Input.dispatchMouseEvent", {type: "mouseReleased", x: 5, y: 600, button, clickCount: 1}, page);
    await sleep(100);
    return evaluate(page, `document.querySelector(${JSON.stringify(selector)}).getAttribute("href")`);
  };
  const D = (q) => `http://clean-fixture.test:${port}/dest${q}`;
  const tracked = await press("#tracked");
  const wrapped = await press("#wrapped", "right");
  const hijack = await press("#hijack");
  const tco = await press("#tco");
  const plain = await press("#plain");
  check("click time: tracking parameters removed from a link's href on mousedown", tracked === D("?id=3"), tracked);
  check("click time: a Google /url wrapper is replaced by its clean destination on right click (Copy link address)", wrapped === D("?b=2"), wrapped);
  check("click time: a page that swaps the href on mousedown gets the clean destination back", hijack === D("?id=4"), hijack);
  check("click time: a t.co link becomes the clean address the page shows", tco === D("?x=1"), tco);
  check("click time: a functional ref outside the per-site sets survives", plain === D("?ref=main&id=5"), plain);
  hits.length = 0;
  await click(page, "#hijack");
  await until(page, `location.href === ${JSON.stringify(D("?id=4"))}`, "hijacked link navigates to the clean destination");
  check("click time: following the hijacked link reaches the clean destination; the redirector is never contacted", hits.some((h) => h.path === "/dest" && h.query === "?id=4") && !hits.some((h) => /google/.test(h.host)), hitPaths().join(" "));
  // Navigation-time (DNR): a link opened from anywhere arrives clean.
  hits.length = 0;
  await navigate(page, D("?utm_source=a&fbclid=b&id=1&_hsenc=keep&mkt_tok=keep"));
  const navHit = hits.find((h) => h.path === "/dest");
  check("navigation: tracking parameters removed before the request; unsubscribe tokens kept", navHit && navHit.query === "?id=1&_hsenc=keep&mkt_tok=keep", navHit && navHit.query);
  // Address bar: parameters added by a client-side redirect are removed after load.
  await navigate(page, `http://clean-fixture.test:${port}/dest2`);
  const bar = await waitFor(async () => (await evaluate(page, "location.search")) === "?k=1", 6000, 200);
  check("address bar: parameters a page adds with history.replaceState are cleaned after load", bar, await evaluate(page, "location.search"));
  // Copy clean link (context menu handler, through the offscreen document).
  const g9 = `https://www.google.com/url?q=${encodeURIComponent("https://shop.example/p?id=9&utm_campaign=x&gclid=y")}`;
  const copied = await swEval(`__EGBackground.copyClean(${JSON.stringify(g9)}, "https://www.google.com/search?q=x")`);
  check("copy clean link: on Google, the menu handler copies the unwrapped, cleaned address", copied.text === "https://shop.example/p?id=9" && copied.ok === true, JSON.stringify(copied));
  const copiedElsewhere = await swEval(`__EGBackground.copyClean(${JSON.stringify(g9)}, "https://mail.example/inbox")`);
  check("copy clean link: elsewhere, the wrapper is copied as it is (its own check stays)", copiedElsewhere.text === g9, JSON.stringify(copiedElsewhere));
  // Tracking cookies set by page script are removed; a preference cookie stays.
  await navigate(page, `http://clean-fixture.test:${port}/cookies`);
  const gone = await waitFor(async () => !/_ga=|_fbp=/.test(await evaluate(page, "document.cookie")), 5000, 200);
  const jar = await evaluate(page, "document.cookie");
  check("cookies: _ga and _fbp removed as soon as they are set; a preference cookie stays", gone && /prefs=dark/.test(jar), jar);
  const cleanTab = await swEval(`chrome.tabs.query({url: "http://clean-fixture.test/*"}).then((t) => t[0].id)`);
  const cleanState = await popupState(cleanTab, `http://clean-fixture.test:${port}/cookies`);
  check("popup: links cleaned and tracking cookies removed are counted", cleanState.cleaning.links >= 3 && cleanState.cleaning.cookies >= 2, JSON.stringify(cleanState.cleaning));
  // The per-site brake.
  await popupAct(cleanTab, `http://clean-fixture.test:${port}/cookies`, {type: "set-clean", on: false});
  hits.length = 0;
  await navigate(page, D("?utm_source=a&id=2"));
  const braked = hits.find((h) => h.path === "/dest");
  await navigate(page, `http://clean-fixture.test:${port}/cookies`);
  await sleep(1200);
  const kept = await evaluate(page, "document.cookie");
  check("brake: with cleaning off for the site, its links keep their parameters and its cookies stay", braked && braked.query === "?utm_source=a&id=2" && /_ga=/.test(kept), `${braked && braked.query} | ${kept}`);
  await popupAct(cleanTab, `http://clean-fixture.test:${port}/cookies`, {type: "set-clean", on: true});

  // 7. Site modes: Strict, click-to-load, the one-click repair, No scripts.
  await popupAct(tabId, P("/embeds"), {type: "set-mode", mode: "strict"});
  hits.length = 0;
  await navigate(page, P("/embeds"));
  await sleep(800);
  const strictLoaded = await evaluate(page, "window.loaded || []");
  check("strict: a third-party script is blocked, the site's own script and inline code run", !strictLoaded.includes("/lib.js") && strictLoaded.includes("/static/own.js") && (await evaluate(page, "window.inline")) === 1, strictLoaded.join(","));
  check("strict: the YouTube frame is held behind a placeholder and Disqus is not contacted", (await evaluate(page, "document.querySelectorAll('[data-eg-embed=disqus]').length")) === 1 && !hits.some((h) => h.host === "disqus.com"));
  check("strict: third-party connection hints are removed", (await evaluate(page, "document.querySelectorAll('link[rel=preconnect], link[rel=dns-prefetch]').length")) === 0);
  const strictState = await popupState(tabId, P("/embeds"));
  check("strict: the popup attributes the block to Strict mode", strictState.blocked.some((b) => b.list === "strict" && b.host === "cdn-assets.test"), JSON.stringify(strictState.blocked.map((b) => `${b.list}:${b.host}`)));
  // Click the placeholder's button (inside a closed shadow root) with a real mouse event.
  const {root: domRoot} = await cdp("DOM.getDocument", {depth: -1, pierce: true}, page);
  const findButton = (node) => { if (node.nodeName === "BUTTON") return node; for (const c of [...(node.children || []), ...(node.shadowRoots || [])]) { const f = findButton(c); if (f) return f; } return null; };
  const button = findButton(domRoot);
  const quad = button && (await cdp("DOM.getBoxModel", {backendNodeId: button.backendNodeId}, page)).model.content;
  if (quad) for (const type of ["mousePressed", "mouseReleased"]) await cdp("Input.dispatchMouseEvent", {type, x: (quad[0] + quad[4]) / 2, y: (quad[1] + quad[5]) / 2, button: "left", clickCount: 1}, page);
  const embedded = await waitFor(() => hits.some((h) => h.host === "disqus.com" && h.path === "/embed/comments/"), 6000);
  const embedCookie = hits.find((h) => h.host === "disqus.com" && h.path === "/embed/comments/");
  check("click-to-load: one real click loads the held embed for this page", embedded && (await evaluate(page, "getComputedStyle(document.getElementById('yt')).display")) !== "none",
    JSON.stringify({button: Boolean(quad), held: await evaluate(page, "document.querySelectorAll('[data-eg-embed]').length"), frames: await evaluate(page, "[...document.querySelectorAll('iframe')].map((f) => f.src + ' ' + f.style.display)"),
      session: await swEval("chrome.declarativeNetRequest.getSessionRules()"),
      outcome: await swEval(`chrome.declarativeNetRequest.testMatchOutcome({url: "http://www.youtube.com:${port}/embed/fixture", type: "sub_frame", initiator: "http://publisher.example:${port}", tabId: ${tabId}}).then((r) => r.matchedRules)`).catch((e) => String(e))}));
  check("click-to-load: the loaded embed's request carries no cookies (Strict stripping stays above the embed allow)", embedCookie && embedCookie.cookie === null, JSON.stringify(embedCookie));
  const sessionEmbeds = await swEval("chrome.declarativeNetRequest.getSessionRules().then((r) => r.filter((x) => x.id >= 300000 && x.id < 400000).length)");
  await navigate(page, P("/embeds"));
  await sleep(500);
  const afterNav = await swEval("chrome.declarativeNetRequest.getSessionRules().then((r) => r.filter((x) => x.id >= 300000 && x.id < 400000).length)");
  check("click-to-load: the allowance ends when the tab navigates", sessionEmbeds === 1 && afterNav === 0, `${sessionEmbeds} -> ${afterNav}`);
  await popupAct(tabId, P("/embeds"), {type: "strict-allow", host: "cdn-assets.test"});
  await navigate(page, P("/embeds"));
  await sleep(600);
  check("strict: Allow host (the one-click repair) lets that host's script load on this site", (await evaluate(page, "window.loaded || []")).includes("/lib.js"));
  // 9b: third-party frames get no Referer under Strict, and their document.referrer is empty.
  hits.length = 0;
  await navigate(page, P("/frameref?secret=1"));
  await waitFor(() => hits.some((h) => h.path === "/report"), 5000);
  const frameHit = hits.find((h) => h.path === "/framepage");
  const report = hits.find((h) => h.path === "/report");
  check("strict: a third-party frame's request carries no Referer (its server never learns the embedding page)", frameHit && frameHit.referer === null, String(frameHit && frameHit.referer));
  // Known limit, reported not asserted: Chrome still gives the frame's own script the embedder's origin
  // (document.referrer, and location.ancestorOrigins, which no extension can override).
  console.log(`note: inside the frame, document.referrer was ${report ? decodeURIComponent(report.query.slice(3)) || "(empty)" : "(no report)"}`);
  // Clickjacking: the page makes the placeholder's ancestor nearly transparent; a real click on it loads nothing.
  await navigate(page, P("/clickjack"));
  await sleep(900);
  await evaluate(page, "document.getElementById('wrap').style.opacity = '0.02'; true");
  hits.length = 0;
  const cj = await (async () => {
    const {root: r} = await cdp("DOM.getDocument", {depth: -1, pierce: true}, page);
    const b = findButton(r);
    const q = b && (await cdp("DOM.getBoxModel", {backendNodeId: b.backendNodeId}, page)).model.content;
    if (q) for (const type of ["mousePressed", "mouseReleased"]) await cdp("Input.dispatchMouseEvent", {type, x: (q[0] + q[4]) / 2, y: (q[1] + q[5]) / 2, button: "left", clickCount: 1}, page);
    return Boolean(q);
  })();
  await sleep(1200);
  check("click-to-load: a click on a placeholder the page made transparent loads nothing", cj && !hits.some((h) => h.host === "disqus.com") && (await swEval("chrome.declarativeNetRequest.getSessionRules().then((r) => r.filter((x) => x.id >= 300000 && x.id < 400000).length)")) === 0);
  await popupAct(tabId, P("/embeds"), {type: "strict-unallow", host: "cdn-assets.test"});
  // No scripts: a service worker that would serve cached scripts is unregistered and its caches cleared.
  await popupAct(tabId, P("/embeds"), {type: "set-mode", mode: "default"});
  await navigate(page, P("/swpage"));
  const cachesBefore = await evaluate(page, "window.swReady.then((n) => n).catch((e) => 'error: ' + e.message)");
  const regsBefore = await evaluate(page, "navigator.serviceWorker.getRegistrations().then((r) => r.length)");
  const swReply = await popupAct(tabId, P("/swpage"), {type: "set-mode", mode: "noscript"});
  await sleep(800);
  const regsAfter = await evaluate(page, "navigator.serviceWorker.getRegistrations().then((r) => r.length)");
  const cachesAfter = await evaluate(page, "caches.keys().then((k) => k.length)");
  check("no scripts: switching to it unregisters the site's service worker and clears its Cache Storage",
    regsBefore === 1 && cachesBefore === 1 && swReply.cleared && swReply.cleared.ok && regsAfter === 0 && cachesAfter === 0, JSON.stringify({regsBefore, cachesBefore, regsAfter, cachesAfter, cleared: swReply.cleared}));
  await navigate(page, P("/embeds"));
  await sleep(600);
  check("no scripts: the site's own script and inline code do not run", ((await evaluate(page, "window.loaded || []")).length === 0) && (await evaluate(page, "window.inline")) === undefined);
  await popupAct(tabId, P("/embeds"), {type: "set-mode", mode: "default"});

  // 9: fingerprint noise was removed; nothing of it is registered, and GPC's getter looks native.
  const noiseGone = await popupAct(tabId, P("/fp"), {type: "set-noise", on: true});
  const registered = await swEval("chrome.scripting.getRegisteredContentScripts().then((s) => s.length)");
  check("noise: removed (no switch, no registered page scripts)", Boolean(noiseGone.error) && registered === 0, JSON.stringify({noiseGone, registered}));
  await navigate(page, P("/fp"));
  const gpcShape = await evaluate(page, `(() => { const d = Object.getOwnPropertyDescriptor(Navigator.prototype, "globalPrivacyControl"); return {own: Object.prototype.hasOwnProperty.call(navigator, "globalPrivacyControl"), str: Function.prototype.toString.call(d.get), name: d.get.name, proto: "prototype" in d.get, value: navigator.globalPrivacyControl, enumerable: d.enumerable}; })()`);
  check("GPC: the getter sits on Navigator.prototype and reads as native code", !gpcShape.own && /\[native code\]/.test(gpcShape.str) && gpcShape.name === "get globalPrivacyControl" && !gpcShape.proto && gpcShape.value === true, JSON.stringify(gpcShape));

  if (shots) {
    fs.mkdirSync(shots, {recursive: true});
    // The mail-scanner interstitial at desktop and phone widths, light and dark.
    const shot = (await cdp("Target.attachToTarget", {targetId: (await cdp("Target.createTarget", {url: "about:blank"})).targetId, flatten: true})).sessionId;
    await cdp("Page.enable", {}, shot);
    const demo = "https://nam02.safelinks.protection.outlook.com/?url=" + encodeURIComponent("https://payroll.contoso-hr.example/statements/2026-11?id=88213&view=pdf") + "&data=05%7C02%7Cj.doe%40contoso.example%7C9f2c%7C0&sdata=kQ3vZ7&reserved=0";
    for (const scheme of ["light", "dark"]) {
      await cdp("Emulation.setEmulatedMedia", {features: [{name: "prefers-color-scheme", value: scheme}]}, shot);
      for (const [w, tag] of [[1440, "desktop"], [390, "390"]]) {
        await cdp("Emulation.setDeviceMetricsOverride", {width: w, height: 800, deviceScaleFactor: 2, mobile: w < 600}, shot);
        await navigate(shot, `chrome-extension://${id}/unwrap.html#${demo}`);
        await until(shot, "!document.getElementById('scan').hidden", "interstitial rendered");
        await sleep(300);
        await screenshot(shot, path.join(shots, `scanner-interstitial-${tag}-${scheme}.png`), w);
      }
    }
    await navigate(page, P("/fp"));
    await evaluate(page, `Promise.all([probe("/sgtm/gtm.js?id=GTM-ABC"), probe("/hotjar-123.js?sv=6"), img("/g/collect?v=2&tid=G-1"), img("http://tracker-fixture.test:${port}/p.gif")]).then(() => navigator.sendBeacon("http://clean-fixture.test:${port}/b", "x"))`);
    await sleep(800);
    const pop = (await cdp("Target.attachToTarget", {targetId: (await cdp("Target.createTarget", {url: "about:blank"})).targetId, flatten: true})).sessionId;
    await cdp("Page.enable", {}, pop);
    for (const scheme of ["light", "dark"]) {
      await cdp("Emulation.setEmulatedMedia", {features: [{name: "prefers-color-scheme", value: scheme}]}, pop);
      await navigate(pop, `chrome-extension://${id}/popup.html?tab=${tabId}`);
      await until(pop, "Number(document.getElementById('blocked-count').textContent) > 0 && document.querySelectorAll('#modes button').length === 4", "popup rendered");
      await sleep(300);
      await screenshot(pop, path.join(shots, `popup-categories-${scheme}.png`), 360);
    }
  }

  globalThis.__ctx = {page, tabId, popupAct, popupState, swEval, id};
  if (typeof globalThis.__phase2 === "function") await globalThis.__phase2({cdp, evaluate, navigate, click, until, check, hits, hitPaths, P, port, page, tabId, popupAct, popupState, swEval, id, shots, screenshot, sleep, waitFor});

  const external = hits.filter((h) => !FIXTURE_HOSTS.includes(h.host) && h.host !== "127.0.0.1");
  check("no unexpected hosts reached the fixture server", external.length === 0, JSON.stringify(external.slice(0, 5)));
} catch (error) {
  check("harness", false, error.stack || String(error));
} finally {
  await browser.close();
  server.close();
  fs.rmSync(work, {recursive: true, force: true});
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}
