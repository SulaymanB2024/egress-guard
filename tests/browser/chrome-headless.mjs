// Optional real-Chrome check. Not part of `node --test`; run it explicitly:
//   node tests/browser/chrome-headless.mjs [--chrome PATH] [--feeds DIR] [--shots DIR]
// Builds the Chrome extension into a throwaway folder under .cache/ with the fixture lists in
// tests/browser/fixtures/feeds (plus, with --feeds, the full lists from a proxy feed cache, to prove
// Chrome indexes the real rulesets). Launches headless Chrome with a throwaway --user-data-dir (never
// the user's profile), loads the extension over the DevTools pipe (Extensions.loadUnpacked, because
// branded Chrome ignores --load-extension), and serves the publisher fixture from 127.0.0.1. Host
// resolution maps only the fixture names to loopback and everything else to NOTFOUND, with no proxy,
// so nothing external is contacted. --shots writes popup and warning-page PNGs.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {spawn} from "node:child_process";
import {fileURLToPath} from "node:url";
import {build, loadLists} from "../../scripts/build-browser.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const argv = process.argv.slice(2);
const opt = (name, fallback = null) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : fallback; };
const chromeBin = opt("--chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
const realFeeds = opt("--feeds");
const shots = opt("--shots");
const fixtureDir = path.join(here, "fixtures/publisher");
fs.mkdirSync(path.join(root, ".cache"), {recursive: true});
const work = fs.mkdtempSync(path.join(root, ".cache", "chrome-check-"));
const results = [];
const check = (name, ok, detail = "") => { results.push({name, ok, detail}); console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- extension build ---------------------------------------------------------------
const fixtureLists = loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true});
let lists = fixtureLists;
if (realFeeds) {
  const real = loadLists(path.resolve(realFeeds), {log: (m) => console.log(`note: ${m}`)});
  lists = {};
  for (const kind of Object.keys(real)) {
    lists[kind] = {names: [...real[kind].names, ...fixtureLists[kind].names], sources: real[kind].sources};
  }
}
const t0 = Date.now();
const built = build({out: path.join(work, "dist"), lists});
const ext = path.join(work, "dist", "chrome");
console.log(`built in ${Date.now() - t0} ms: ${Object.entries(built.lists).map(([k, v]) => `${k} ${v.domains}`).join(", ")}`);

// ---- fixture server ------------------------------------------------------------------
const hits = [];
let port = 0;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://fixture");
  const host = (req.headers.host || "").replace(/:\d+$/, "");
  hits.push({host, path: url.pathname, query: url.search});
  const send = (code, type, body) => { res.writeHead(code, {"content-type": type, "cache-control": "no-store"}); res.end(body); };
  if (host === "malware-fixture.test" && url.pathname === "/landing") {
    return send(200, "text/html; charset=utf-8", `<!doctype html><title>Landing</title><p id="landing">landing</p>
<img id="asset" src="/landing-asset.png"><img id="pixel" src="http://pixel.tracker-fixture.test:${port}/landing-pixel.gif">`);
  }
  if (url.pathname === "/article") return send(200, "text/html; charset=utf-8", fs.readFileSync(path.join(fixtureDir, "index.html")));
  if (url.pathname === "/static/app.js") return send(200, "text/javascript", fs.readFileSync(path.join(fixtureDir, "static/app.js")));
  if (url.pathname === "/static/site.css") return send(200, "text/css", fs.readFileSync(path.join(fixtureDir, "static/site.css")));
  if (url.pathname === "/api/session") return send(200, "text/plain", "ok");
  if (url.pathname === "/collect") return send(204, "text/plain", "");
  if (/\.(gif|png)$/.test(url.pathname)) return send(200, "image/gif", Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"));
  return send(404, "text/plain", "not found");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
port = server.address().port;
const FIXTURE_HOSTS = ["publisher.example", "metrics.publisher.example", "tracker-fixture.test", "pixel.tracker-fixture.test",
  "malware-fixture.test", "clean-fixture.test"];

// ---- headless Chrome over the DevTools pipe --------------------------------------------
const profile = path.join(work, "profile");
fs.mkdirSync(profile);
const child = spawn(chromeBin, [
  "--headless", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging", `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
  "--disable-sync", "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--no-pings",
  "--metrics-recording-only", "--disable-breakpad", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain",
  "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,OptimizationHints,MediaRouter,Translate",
  `--host-resolver-rules=${FIXTURE_HOSTS.map((h) => `MAP ${h} 127.0.0.1`).join(", ")}, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`,
  "--window-size=1280,900", "about:blank",
], {stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"], detached: true});
let stderr = "";
child.stderr.on("data", (d) => { stderr += d; });
const toChrome = child.stdio[3], fromChrome = child.stdio[4];
let inbox = Buffer.alloc(0), nextId = 0;
const waiting = new Map();
fromChrome.on("data", (chunk) => {
  inbox = Buffer.concat([inbox, chunk]);
  let end;
  while ((end = inbox.indexOf(0)) >= 0) {
    const msg = JSON.parse(inbox.subarray(0, end).toString("utf8"));
    inbox = inbox.subarray(end + 1);
    if (msg.id && waiting.has(msg.id)) { const w = waiting.get(msg.id); waiting.delete(msg.id); msg.error ? w.reject(new Error(`${msg.error.message} ${msg.error.data || ""}`)) : w.resolve(msg.result); }
  }
});
const cdp = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId;
  const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`${method} timed out`)); }, 60000);
  waiting.set(id, {resolve: (v) => { clearTimeout(timer); resolve(v); }, reject: (e) => { clearTimeout(timer); reject(e); }});
  toChrome.write(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}) + "\0");
});
async function evaluate(sessionId, expression) {
  const r = await cdp("Runtime.evaluate", {expression, awaitPromise: true, returnByValue: true}, sessionId);
  if (r.exceptionDetails) throw new Error(`evaluate: ${r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text}`);
  return r.result.value;
}
async function until(sessionId, expression, label, ms = 25000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { if (await evaluate(sessionId, expression)) return true; } catch {} await sleep(150); }
  check(label, false, "timed out");
  return false;
}
async function navigate(sessionId, url) {
  await cdp("Page.navigate", {url}, sessionId);
  await sleep(300);
  await until(sessionId, "document.readyState === 'complete'", `loaded ${url}`);
}
async function click(sessionId, selector) {
  const box = await evaluate(sessionId, `(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return {x: r.left + r.width / 2, y: r.top + r.height / 2}; })()`);
  for (const type of ["mousePressed", "mouseReleased"]) await cdp("Input.dispatchMouseEvent", {type, x: box.x, y: box.y, button: "left", clickCount: 1}, sessionId);
}
async function screenshot(sessionId, file, width) {
  await cdp("Emulation.setDeviceMetricsOverride", {width, height: 600, deviceScaleFactor: 2, mobile: false}, sessionId);
  await sleep(600);
  const height = await evaluate(sessionId, "Math.ceil(Math.max(document.documentElement.scrollHeight, document.body.scrollHeight))");
  await cdp("Emulation.setDeviceMetricsOverride", {width, height, deviceScaleFactor: 2, mobile: false}, sessionId);
  await sleep(200);
  const {data} = await cdp("Page.captureScreenshot", {format: "png"}, sessionId);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  console.log(`screenshot ${file}`);
}

const PAGE = `http://publisher.example:${port}/article`;
const CONTROL = `http://127.0.0.1:${port}/article`;
const pageReady = "document.getElementById('fixture-status')?.textContent === 'session:ok'";
const shown = (id) => `(() => { const n = document.getElementById('${id}'); return Boolean(n) && getComputedStyle(n).display !== 'none'; })()`;
async function waitFor(fn, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(200); }
  return false;
}
const hitPaths = () => hits.map((h) => `${h.host}${h.path}`);
const loadImages = (sessionId, urls) => evaluate(sessionId, `Promise.all(${JSON.stringify(urls)}.map((u) => new Promise((r) => { const i = new Image(); i.onload = () => r('ok'); i.onerror = () => r('error'); i.src = u; })))`);

let swEval = null;
try {
  const started = Date.now();
  const version = await cdp("Browser.getVersion");
  console.log(`${version.product}, headless, up in ${Date.now() - started} ms`);
  const loaded = await cdp("Extensions.loadUnpacked", {path: ext});
  check("extension loads unpacked over the DevTools pipe with its fixed id", loaded.id === built.extensionId, loaded.id);
  const id = loaded.id;

  // Service worker session. The worker can restart (install, idle); re-attach and retry when it does.
  let sw = null;
  const attachWorker = async () => {
    for (let i = 0; i < 50; i++) {
      const {targetInfos} = await cdp("Target.getTargets");
      const t = targetInfos.find((x) => x.type === "service_worker" && x.url === `chrome-extension://${id}/background.js`);
      if (t) return (await cdp("Target.attachToTarget", {targetId: t.targetId, flatten: true})).sessionId;
      await sleep(200);
    }
    return null;
  };
  swEval = async (expression) => {
    for (let attempt = 1; ; attempt++) {
      try {
        if (!sw) sw = await attachWorker();
        return await evaluate(sw, expression);
      } catch (error) {
        if (attempt >= 3 || !/not found|No session|detached/i.test(error.message)) throw error;
        console.log(`note: service worker call retried (${error.message.split("\n")[0]})`);
        sw = null;
      }
    }
  };
  sw = await attachWorker();
  check("service worker started", Boolean(sw));
  await swEval("__EGBackground.ready.then(() => true)");
  const enabled = await swEval("chrome.declarativeNetRequest.getEnabledRulesets()");
  check("static rulesets enabled: threats, trackers, cname, params", ["threats", "trackers", "cname", "params"].every((r) => enabled.includes(r)), enabled.join(","));
  const available = await swEval("chrome.declarativeNetRequest.getAvailableStaticRuleCount()");
  check("static rule budget left after the lists", available > 0, `${available} rules still available`);
  if (realFeeds) {
    const outcome = await swEval(`Promise.all([
      chrome.declarativeNetRequest.testMatchOutcome({url: "https://${fixtureLists.trackers.names[0]}/x.js", type: "script", initiator: "https://news.example"}),
      chrome.declarativeNetRequest.testMatchOutcome({url: "https://${lists.trackers.names[Math.floor(lists.trackers.names.length / 2)]}/x.js", type: "script", initiator: "https://news.example"}),
      chrome.declarativeNetRequest.testMatchOutcome({url: "https://${lists.threats.names[Math.floor(lists.threats.names.length / 3)]}/", type: "main_frame"}),
    ]).then((r) => r.map((x) => x.matchedRules.map((m) => m.rulesetId).join("+")))`);
    check("real lists: Chrome matches a mid-list tracker and threat domain", outcome[1] === "trackers" && outcome[2] === "threats", JSON.stringify(outcome));
  }

  // Seed the fixture's user rules through the same store API the popup uses.
  const rules = JSON.parse(fs.readFileSync(path.join(fixtureDir, "rules.json"), "utf8")).rules;
  const dynamic = await swEval(`(async () => { for (const r of ${JSON.stringify(rules)}) if (!__EGBackground.store.rules.some((x) => x.id === r.id)) await __EGBackground.store.addRule(r); await __EGBackground.sync(); return (await chrome.declarativeNetRequest.getDynamicRules()).length; })()`);
  check("user request rule compiled to a dynamic rule", dynamic === 1, String(dynamic));

  const {targetId} = await cdp("Target.createTarget", {url: "about:blank"});
  const page = (await cdp("Target.attachToTarget", {targetId, flatten: true})).sessionId;
  await cdp("Page.enable", {}, page);
  await cdp("Runtime.enable", {}, page);

  // Control: on an IP origin the user rule's site does not apply, so /collect is sent.
  hits.length = 0;
  await navigate(page, CONTROL);
  await until(page, pageReady, "control page loaded");
  check("control: /collect reaches the server outside the rule's site", await waitFor(() => hits.some((h) => h.path === "/collect")));

  // Publisher page: user rule blocks /collect; content loads; sponsored card hidden.
  hits.length = 0;
  await navigate(page, PAGE);
  const ready = await until(page, pageReady, "publisher page loaded with session XHR");
  await sleep(800);
  const paths = hits.map((h) => h.path);
  check("publisher: article, script, stylesheet and session XHR load", ready && ["/article", "/static/app.js", "/static/site.css", "/api/session"].every((p) => paths.includes(p)), paths.join(" "));
  check("publisher: /collect beacon never reaches the server (user rule, DNR dynamic)", !paths.includes("/collect"));
  await until(page, `getComputedStyle(document.getElementById('card-sponsored')).display === 'none'`, "sponsored card hidden");
  check("cosmetic: sponsored card hidden, organic cards and login form visible",
    !(await evaluate(page, shown("card-sponsored"))) && (await evaluate(page, shown("card-organic-1"))) && (await evaluate(page, shown("login"))));

  // Built-in lists: tracker and disguised tracker requests never leave; a clean host loads.
  hits.length = 0;
  const outcomes = await loadImages(page, [`http://pixel.tracker-fixture.test:${port}/pixel.gif`, `http://metrics.publisher.example:${port}/m.gif`,
    `http://clean-fixture.test:${port}/ok.gif`]);
  await sleep(300);
  check("lists: listed tracker image is blocked before sending", outcomes[0] === "error" && !hitPaths().includes("pixel.tracker-fixture.test/pixel.gif"), outcomes.join(","));
  check("lists: CNAME-cloaked tracker host is blocked", outcomes[1] === "error" && !hitPaths().includes("metrics.publisher.example/m.gif"));
  check("lists: unlisted host loads (control)", outcomes[2] === "ok" && hitPaths().includes("clean-fixture.test/ok.gif"));

  // What the popup will show for this tab.
  const tabId = await swEval(`chrome.tabs.query({url: "http://publisher.example/*"}).then((t) => t[0].id)`);
  const popupSender = `{id: chrome.runtime.id, url: chrome.runtime.getURL("popup.html")}`;
  const want = ["trackers:pixel.tracker-fixture.test/pixel.gif", "cname:metrics.publisher.example/m.gif", "user:publisher.example/collect"];
  let blockedLists = [];
  const logged = await waitFor(async () => {
    const state = await swEval(`__EGBackground.handle({type: "popup-state", tabId: ${tabId}, tabUrl: ${JSON.stringify(PAGE)}}, ${popupSender})`);
    blockedLists = [...new Set(state.blocked.map((b) => `${b.list}:${b.host}${b.path}`))];
    return want.every((x) => blockedLists.includes(x));
  });
  check("popup state lists blocked requests with their list", logged, blockedLists.join(" "));

  // Exception: allow the tracker pixel on this site for 15 minutes; it must beat the static list.
  const exc = await swEval(`__EGBackground.handle({type: "add-exception", tabId: ${tabId}, tabUrl: ${JSON.stringify(PAGE)}, host: "pixel.tracker-fixture.test", path: "/pixel.gif", resourceType: "image", minutes: 15}, ${popupSender})`);
  check("exception accepted", exc.ok === true, JSON.stringify(exc.error || ""));
  hits.length = 0;
  const after = await loadImages(page, [`http://pixel.tracker-fixture.test:${port}/pixel.gif?again=1`, `http://pixel.tracker-fixture.test:${port}/other.gif`]);
  await sleep(300);
  check("exception: the excepted tracker endpoint now loads (beats the static list by priority)", after[0] === "ok" && hitPaths().includes("pixel.tracker-fixture.test/pixel.gif"), after.join(","));
  check("exception: another path on the same tracker host stays blocked", after[1] === "error" && !hitPaths().includes("pixel.tracker-fixture.test/other.gif"));

  if (shots) {
    fs.mkdirSync(shots, {recursive: true});
    const pop = (await cdp("Target.attachToTarget", {targetId: (await cdp("Target.createTarget", {url: "about:blank"})).targetId, flatten: true})).sessionId;
    await cdp("Page.enable", {}, pop);
    for (const scheme of ["light", "dark"]) {
      await cdp("Emulation.setEmulatedMedia", {features: [{name: "prefers-color-scheme", value: scheme}]}, pop);
      await navigate(pop, `chrome-extension://${id}/popup.html?tab=${tabId}`);
      await until(pop, "Number(document.getElementById('blocked-count').textContent) > 0", "popup rendered blocked items");
      await sleep(300);
      await screenshot(pop, path.join(shots, `popup-${scheme}.png`), 360);
    }
    await cdp("Target.closeTarget", {targetId: (await cdp("Target.getTargets")).targetInfos.find((t) => t.url.includes("popup.html")).targetId});
  }

  // Tracking parameters are stripped from navigations; other parameters stay.
  hits.length = 0;
  await navigate(page, `${PAGE}?utm_source=news&id=7&fbclid=abc&gclid=x`);
  await until(page, pageReady, "page with tracking parameters loaded");
  const articleHit = hits.find((h) => h.path === "/article");
  const href = await evaluate(page, "location.href");
  check("params: utm_*, fbclid and gclid removed before the request; id kept", articleHit && articleHit.query === "?id=7" && href.endsWith("/article?id=7"), `${articleHit && articleHit.query} ${href}`);

  // Threat navigation lands on the local warning page; the site is never contacted.
  hits.length = 0;
  const THREAT = `http://malware-fixture.test:${port}/landing`;
  await navigate(page, THREAT);
  const onWarning = await until(page, `location.href.startsWith("chrome-extension://${id}/warning.html")`, "threat navigation redirected to the warning page");
  await until(page, `document.getElementById('list').textContent.includes('HaGeZi')`, "warning page shows the list");
  const warnText = await evaluate(page, "document.body.innerText");
  check("threat: warning page names the host and the list", onWarning && warnText.includes("malware-fixture.test") && /Malware and phishing/.test(warnText) && /HaGeZi Threat Intelligence/.test(warnText), warnText.split("\n").slice(0, 8).join(" | "));
  check("threat: the flagged site received no request", !hits.some((h) => h.host === "malware-fixture.test"));
  if (shots) {
    for (const scheme of ["light", "dark"]) {
      await cdp("Emulation.setEmulatedMedia", {features: [{name: "prefers-color-scheme", value: scheme}]}, page);
      await screenshot(page, path.join(shots, `warning-${scheme}.png`), 760);
    }
    await screenshot(page, path.join(shots, "warning-dark-390.png"), 390);
    await cdp("Emulation.clearDeviceMetricsOverride", {}, page);
  }

  // "Continue once" needs a deliberate two-step real click; then the site and its own assets load, trackers stay blocked.
  await click(page, "#reveal");
  await sleep(200);
  await click(page, "#continue");
  const continued = await until(page, `location.href === ${JSON.stringify(THREAT)} && document.readyState === 'complete'`, "continue navigates to the site");
  const assets = await waitFor(() => hitPaths().includes("malware-fixture.test/landing") && hitPaths().includes("malware-fixture.test/landing-asset.png"));
  check("continue once: the page and its same-site asset load", continued && assets, hitPaths().join(" "));
  check("continue once: trackers on that page stay blocked", !hitPaths().includes("pixel.tracker-fixture.test/landing-pixel.gif"));
  const sessionCount = () => swEval("chrome.declarativeNetRequest.getSessionRules().then((r) => r.length)");
  const sessionRules = await sessionCount();
  check("continue once: one session rule while on the site", sessionRules === 1, String(sessionRules));

  // Leaving the site ends the exception; coming back shows the warning again.
  await navigate(page, PAGE);
  check("continue once: exception removed after leaving the site", await waitFor(async () => (await sessionCount()) === 0));
  hits.length = 0;
  await navigate(page, THREAT);
  const again = await until(page, `location.href.startsWith("chrome-extension://${id}/warning.html")`, "warning shown again");
  check("continue once: returning later is blocked again", again && !hits.some((h) => h.host === "malware-fixture.test"));

  const external = hits.filter((h) => !FIXTURE_HOSTS.includes(h.host) && h.host !== "127.0.0.1");
  check("no unexpected hosts reached the fixture server", external.length === 0, JSON.stringify(external));
} catch (error) {
  check("harness", false, error.stack || String(error));
} finally {
  try { await cdp("Browser.close"); } catch {}
  await sleep(500);
  try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  server.close();
  fs.rmSync(work, {recursive: true, force: true});
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) console.log(stderr.split("\n").filter((l) => !/cv_display_link|allocator multiple/.test(l)).slice(0, 25).join("\n"));
  process.exit(failed.length ? 1 : 0);
}
