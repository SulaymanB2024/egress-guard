// Optional real-Chrome check for the URL-level protections. Not part of `node --test`; run it explicitly:
//   node tests/browser/chrome-privacy.mjs [--chrome PATH] [--real-filters] [--shots DIR]
// Builds the extension with the fixture host lists and a small fixture EasyPrivacy-style list (with
// --real-filters, the cached EasyPrivacy and EasyList too, offline), loads it into headless Chrome with a
// throwaway profile over the DevTools pipe, and serves fixture pages from 127.0.0.1. Host resolution maps only
// the fixture names to loopback and everything else to NOTFOUND, with no proxy: nothing external is contacted.
// Checks: first-party tracker paths, the lists' exceptions, fingerprinting and session-replay paths, Relaxed
// sites, Sec-GPC and navigator.globalPrivacyControl, third-party beacons and <a ping>, the Referrer-Policy fix,
// link unwrapping (and refusal of hostile destinations), surrogates, site modes, click-to-load embeds, tracker
// cookie lifetimes and the popup's categories.
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
<script>window.dataLayer = []; window.GoogleAnalyticsObject = "ga"; window.ga = function () { (ga.q = ga.q || []).push(arguments); };</script>
<script src="http://www.google-analytics.com/analytics.js"></script>
<script src="http://www.googletagmanager.com/gtm.js?id=GTM-FIXTURE"></script>
<script src="http://securepubads.g.doubleclick.net/tag/js/gpt.js"></script>
<script>
ga("send", "pageview", {hitCallback: function () { document.body.dataset.ga = "1"; }});
dataLayer.push({event: "x", eventCallback: function () { document.body.dataset.gtm = "1"; }});
googletag.cmd.push(function () { googletag.defineSlot("/1/x", [300, 250], "ad").addService(googletag.pubads()); googletag.enableServices(); document.body.dataset.gpt = "1"; });
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
  "/dest2": () => `<!doctype html><title>dest2</title><script>history.replaceState(null, "", "/dest2?gclid=zzz&k=1&mc_eid=abc");</script>`,
  "/noise": () => `<!doctype html><title>noise</title><canvas id="c" width="64" height="32"></canvas><script>
window.canvasHash = () => { const c = document.getElementById("c"); const x = c.getContext("2d"); x.fillStyle = "#c33"; x.fillRect(0, 0, 64, 32); x.fillStyle = "#123"; x.font = "14px sans-serif"; x.fillText("egress", 4, 20);
  const d = x.getImageData(0, 0, 64, 32).data; let h = 0; for (let i = 0; i < d.length; i++) h = (h * 31 + d[i]) >>> 0; return h; };</script>`,
};
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://fixture");
  const host = (req.headers.host || "").replace(/:\d+$/, "");
  hits.push({host, path: url.pathname, query: url.search, gpc: req.headers["sec-gpc"] || null, referer: req.headers.referer || null, cookie: req.headers.cookie || null, method: req.method});
  const send = (code, type, body, extra = {}) => { res.writeHead(code, {"content-type": type, "cache-control": "no-store", ...extra}); res.end(body); };
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
const FIXTURE_HOSTS = ["publisher.example", "www.publisher.example", "tracker-fixture.test", "clean-fixture.test", "cdn-assets.test", "www.youtube.com", "disqus.com"];
const P = (p) => `http://publisher.example:${port}${p}`;
const hitPaths = () => hits.map((h) => `${h.host}${h.path}`);

// ---- Chrome ---------------------------------------------------------------------------------
const profile = path.join(work, "profile");
fs.mkdirSync(profile);
const browser = launch({bin: opt("--chrome", DEFAULT_CHROME), profile, args: ["--no-proxy-server",
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

  // 2. Link unwrapping: the redirector is never contacted; hostile destinations are refused.
  hits.length = 0;
  await navigate(page, `http://www.google.com/url?sa=t&q=${encodeURIComponent(`http://clean-fixture.test:${port}/dest?a=1`)}&usg=X`);
  const unwrapped = await until(page, `location.href === "http://clean-fixture.test:${port}/dest?a=1"`, "unwrapped link opens its destination");
  check("links: google.com/url opens the destination directly", unwrapped && hits.some((h) => h.path === "/dest"), await evaluate(page, "location.href"));
  const linkState = await popupState(await swEval(`chrome.tabs.query({url: "http://clean-fixture.test/*"}).then((t) => t[0].id)`), `http://clean-fixture.test:${port}/dest?a=1`);
  check("links: the popup shows the unwrapped link tracker", linkState.blocked.some((b) => b.list === "links" && b.host === "www.google.com"), JSON.stringify(linkState.blocked));
  await navigate(page, `chrome-extension://${id}/unwrap.html#https://www.google.com/url?q=${encodeURIComponent("https://user:pw@clean-fixture.test/")}`);
  await sleep(500);
  check("links: a destination with credentials is shown, not opened", (await evaluate(page, "location.protocol")) === "chrome-extension:" && !(await evaluate(page, "document.getElementById('card').hidden")));
  await navigate(page, `chrome-extension://${id}/unwrap.html#https://l.facebook.com/l.php?u=${encodeURIComponent("javascript:document.title='pwned'")}`);
  await sleep(400);
  check("links: a javascript: destination is refused", (await evaluate(page, "document.title")) !== "pwned" && (await evaluate(page, "location.protocol")) === "chrome-extension:");
  await navigate(page, `http://www.google.com/url?q=${encodeURIComponent("javascript:alert(1)")}`);
  await sleep(500);
  check("links: a javascript: destination is never redirected at all", !(await evaluate(page, "location.href")).startsWith(`chrome-extension://${id}/unwrap.html`));

  // 8. Surrogates: page code that calls into blocked trackers keeps working; nothing reaches the trackers.
  await navigate(page, P("/surrogate"));
  const surrogate = await until(page, "document.body.dataset.ga === '1' && document.body.dataset.gtm === '1' && document.body.dataset.gpt === '1'", "surrogates answered");
  check("surrogates: ga() hitCallback, dataLayer eventCallback and googletag.cmd all run with no tracker contacted", surrogate,
    JSON.stringify(await evaluate(page, "({ga: typeof ga, loaded: ga && ga.loaded, gt: typeof googletag, ds: {...document.body.dataset}, entries: performance.getEntriesByType('resource').map((e) => e.name.slice(0, 90))})")));

  // 2 + owner priority: link cleaning at click time, at navigation, in the address bar, Copy clean link, cookies.
  await navigate(page, `http://publisher.example:${port}/clicks`);
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
  const copied = await swEval(`__EGBackground.copyClean(${JSON.stringify(`https://www.google.com/url?q=${encodeURIComponent("https://shop.example/p?id=9&utm_campaign=x&gclid=y")}`)})`);
  check("copy clean link: the menu handler copies the unwrapped, cleaned address", copied.text === "https://shop.example/p?id=9" && copied.ok === true, JSON.stringify(copied));
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
  check("click-to-load: one real click loads the held embed for this page", embedded && (await evaluate(page, "getComputedStyle(document.getElementById('yt')).display")) !== "none",
    JSON.stringify({button: Boolean(quad), held: await evaluate(page, "document.querySelectorAll('[data-eg-embed]').length"), frames: await evaluate(page, "[...document.querySelectorAll('iframe')].map((f) => f.src + ' ' + f.style.display)"),
      session: await swEval("chrome.declarativeNetRequest.getSessionRules()"),
      outcome: await swEval(`chrome.declarativeNetRequest.testMatchOutcome({url: "http://www.youtube.com:${port}/embed/fixture", type: "sub_frame", initiator: "http://publisher.example:${port}", tabId: ${tabId}}).then((r) => r.matchedRules)`).catch((e) => String(e))}));
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
  await popupAct(tabId, P("/embeds"), {type: "strict-unallow", host: "cdn-assets.test"});
  await popupAct(tabId, P("/embeds"), {type: "set-mode", mode: "noscript"});
  await navigate(page, P("/embeds"));
  await sleep(600);
  check("no scripts: the site's own script and inline code do not run", ((await evaluate(page, "window.loaded || []")).length === 0) && (await evaluate(page, "window.inline")) === undefined);
  await popupAct(tabId, P("/embeds"), {type: "set-mode", mode: "default"});

  // 9: experimental fingerprint noise, off by default; stable within a site and session, different across sites.
  const hashOn = async (url) => { await navigate(page, url); return evaluate(page, "canvasHash()"); };
  const raw1 = await hashOn(P("/noise"));
  const raw2 = await hashOn(`http://clean-fixture.test:${port}/noise`);
  check("noise: off by default (both sites read the true canvas)", raw1 === raw2, `${raw1} ${raw2}`);
  await popupAct(tabId, P("/noise"), {type: "set-noise", on: true});
  const a1 = await hashOn(P("/noise"));
  const a2 = await hashOn(P("/noise"));
  const b1 = await hashOn(`http://clean-fixture.test:${port}/noise`);
  check("noise: stable within a site and session, different across sites, never the true value", a1 === a2 && a1 !== b1 && a1 !== raw1 && b1 !== raw1, `${a1} ${a2} ${b1} raw ${raw1}`);
  await popupAct(tabId, P("/noise"), {type: "set-noise", on: false});
  const off = await hashOn(P("/noise"));
  check("noise: switching it off restores the true value", off === raw1, `${off}`);

  if (shots) {
    fs.mkdirSync(shots, {recursive: true});
    await navigate(page, P("/fp"));
    await evaluate(page, `Promise.all([probe("/sgtm/gtm.js?id=GTM-ABC"), probe("/hotjar-123.js?sv=6"), img("/g/collect?v=2&tid=G-1"), img("http://tracker-fixture.test:${port}/p.gif")]).then(() => navigator.sendBeacon("http://clean-fixture.test:${port}/b", "x"))`);
    await sleep(800);
    const pop = (await cdp("Target.attachToTarget", {targetId: (await cdp("Target.createTarget", {url: "about:blank"})).targetId, flatten: true})).sessionId;
    await cdp("Page.enable", {}, pop);
    for (const scheme of ["light", "dark"]) {
      await cdp("Emulation.setEmulatedMedia", {features: [{name: "prefers-color-scheme", value: scheme}]}, pop);
      await navigate(pop, `chrome-extension://${id}/popup.html?tab=${tabId}`);
      await until(pop, "Number(document.getElementById('blocked-count').textContent) > 0 && document.querySelectorAll('#modes input').length === 4", "popup rendered");
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
