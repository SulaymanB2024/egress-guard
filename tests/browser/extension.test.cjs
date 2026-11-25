"use strict";
// Background adapter, popup and manifest tests with a fake `browser` namespace. No real browser.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {parseHTML, userClick, allText} = require("./dom-stub.cjs");

const root = path.join(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const manifest = JSON.parse(read("browser/manifest.json"));
const fixture = JSON.parse(read("tests/browser/fixtures/publisher/rules.json"));
const requests = JSON.parse(read("tests/browser/fixtures/publisher/requests.json")).requests;
const EXT = "moz-extension://0b5e1c3a-test/";
const START = Date.UTC(2026, 10, 20, 12, 0, 0);
const settle = () => new Promise(setImmediate);
const event = () => { const fns = []; return {addListener: (fn) => fns.push(fn), fns}; };

async function background({stored = fixture, gate = null} = {}) {
  const clock = {now: START};
  const storage = {egressGuard: stored && JSON.parse(JSON.stringify(stored))};
  const alarms = new Map();
  const tabMessages = [];
  const browser = {
    runtime: {id: "browser-companion@egress-guard.invalid", getURL: (p) => EXT + p, onMessage: event()},
    storage: {local: {get: async (key) => { if (gate) await gate; return {[key]: storage[key]}; }, set: async (obj) => Object.assign(storage, JSON.parse(JSON.stringify(obj)))}},
    alarms: {create: (name, info) => alarms.set(name, info), clear: async (name) => alarms.delete(name), onAlarm: event()},
    tabs: {onRemoved: event(), sendMessage: async (tabId, msg) => { tabMessages.push({tabId, msg}); }},
    webRequest: {onBeforeRequest: event()},
  };
  class FakeDate extends Date { static now() { return clock.now; } }
  const ctx = vm.createContext({browser, console, URL, Date: FakeDate, crypto: globalThis.crypto});
  for (const file of manifest.background.scripts) vm.runInContext(read(`browser/${file}`), ctx, {filename: file});
  if (!gate) await ctx.__EGBackground.ready;
  const [listener] = browser.webRequest.onBeforeRequest.fns;
  const request = (details) => listener({tabId: 1, frameId: 0, ...details});
  const fromPopup = (msg) => ctx.__EGBackground.handle(msg, {id: browser.runtime.id, url: `${EXT}popup.html`});
  const fromPage = (msg, url = "https://publisher.example/article", frameId = 0) =>
    ctx.__EGBackground.handle(msg, {id: browser.runtime.id, url, frameId, tab: {id: 1, url}});
  return {ctx, browser, clock, storage, alarms, tabMessages, request, fromPopup, fromPage, api: ctx.__EGBackground};
}

test("manifest: Firefox MV3, minimal permissions, no remote code or extension networking", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.browser_specific_settings.gecko.id);
  assert.deepEqual([...manifest.permissions].sort(), ["alarms", "storage", "webRequest", "webRequestBlocking"]);
  assert.deepEqual(manifest.host_permissions, ["http://*/*", "https://*/*"]);
  assert.equal(manifest.background.service_worker, undefined);
  assert.equal(manifest.content_scripts.length, 1);
  assert.equal(manifest.content_scripts[0].all_frames, false);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  assert.match(manifest.content_security_policy.extension_pages, /connect-src 'none'/);
  const referenced = [...manifest.background.scripts, ...manifest.content_scripts[0].js, manifest.action.default_popup];
  for (const file of referenced) assert.ok(fs.existsSync(path.join(root, "browser", file)), file);
  for (const tag of read("browser/popup.html").matchAll(/<script\b[^>]*>/g)) assert.match(tag[0], /src="[a-z]+\.js"/);
});

test("extension source has no HTML injection, eval or unapproved browser networking APIs", () => {
  const files = [];
  const walk = (dir) => { for (const e of fs.readdirSync(dir, {withFileTypes: true})) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else files.push(p); } };
  walk(path.join(root, "browser"));
  assert.ok(files.length >= 10);
  for (const file of files.filter((f) => /\.(js|html)$/.test(f))) {
    let code = fs.readFileSync(file, "utf8");
    // The one sanctioned read: the Chrome worker loads its own packaged threat ruleset (CSP connect-src 'self').
    // And it asks Chrome how a navigation to a host would match (testMatchOutcome), which sends nothing.
    if (path.basename(file) === "background-chrome.js") code = code.replace("fetch(OWN + file)", "OWN_RULESET").replace('fetch(OWN + "rules/build.json"', "OWN_STAMP(").replace("url: `https://${host}/`", "url: PROBE")
      // After the system proxy refused a page, the worker asks the local guard why, on the reserved name
      // egress-guard.invalid that only the proxy answers (CSP connect-src names exactly that origin).
      .replace("fetch(WHY + encodeURIComponent(host)", "ASK_GUARD(");
    // Ban the network API identifier, not a local option such as includeWebSockets.
    for (const banned of [/innerHTML/, /outerHTML/, /insertAdjacentHTML/, /document\.write/, /\beval\s*\(/, /new Function/, /\bfetch\s*\(/, /XMLHttpRequest/, /\bWebSocket\b/, /sendBeacon/, /importScripts/, /setTimeout\(\s*["'`]/, /\bon[a-z]+\s*=\s*["']/]) {
      assert.doesNotMatch(code, banned, `${path.relative(root, file)} contains ${banned}`);
    }
  }
});

test("acceptance (adapter): fixture requests through the webRequest listener", async () => {
  const bg = await background();
  for (const item of requests) {
    const {name, expect, ...details} = item;
    // Navigations go to another tab so they do not reset tab 1's per-page blocked log.
    const result = await bg.request({...details, tabId: details.type === "main_frame" ? 2 : 1});
    assert.equal(Boolean(result && result.cancel), expect === "block", name);
  }
  const log = bg.api.tabLog.get(1);
  assert.equal(log.length, 1, "one blocked endpoint logged");
  assert.equal(log[0].path, "/collect");
  assert.ok(log[0].count >= 2);
  assert.equal(JSON.stringify(log).includes("pageview"), false, "query strings are not logged");
});

test("requests before storage loads wait for the rules instead of slipping through", async () => {
  let open;
  const bg = await background({gate: new Promise((resolve) => { open = resolve; })});
  const pending = bg.request({url: "https://publisher.example/collect", type: "beacon", documentUrl: "https://publisher.example/a"});
  assert.equal(typeof pending.then, "function", "listener returns a promise while rules load");
  open();
  assert.deepEqual({...await pending}, {cancel: true});
  assert.deepEqual({...await bg.request({url: "https://publisher.example/collect", type: "beacon", tabId: -1})}, {}, "non-tab requests untouched");
});

test("content scripts get only their own site's cosmetic rules; page senders cannot use popup actions", async () => {
  const bg = await background();
  const mine = await bg.fromPage({type: "page-rules"});
  assert.equal(mine.site, "publisher.example");
  assert.deepEqual([...mine.rules.map((r) => r.id)], ["publisher-sponsored-card"]);
  assert.equal((await bg.fromPage({type: "page-rules"}, "https://other.example/")).rules.length, 0);
  assert.equal((await bg.fromPage({type: "page-rules"}, "https://publisher.example/", 3)).rules.length, 0, "subframes get nothing");
  for (const msg of [{type: "remove-rule", id: "publisher-collect"}, {type: "popup-state", tabId: 1}, {type: "add-exception"}]) {
    assert.match((await bg.fromPage(msg)).error, /Not allowed/);
  }
  assert.match((await bg.fromPage({type: "undo-cosmetic", id: "publisher-sponsored-card"}, "https://other.example/")).error, /No such rule/);
  assert.match((await bg.fromPage({type: "undo-cosmetic", id: "publisher-collect"})).error, /No such rule/, "request rules cannot be undone from a page");
  assert.match((await bg.ctx.__EGBackground.handle({type: "page-rules"}, {id: "someone-else", url: "https://publisher.example/", frameId: 0, tab: {id: 1}})).error, /Unknown sender/);
  const added = await bg.fromPage({type: "add-cosmetic", selector: "body"});
  assert.ok(added.error, "hostile selector from the picker path is still validated");
  const ok = await bg.fromPage({type: "add-cosmetic", selector: "aside.promo[data-ad]"}, "https://www.publisher.example/x");
  assert.equal(ok.value.site, "publisher.example", "picker rules are scoped to the registrable site");
  assert.ok(bg.storage.egressGuard.rules.some((r) => r.selector === "aside.promo[data-ad]"), "persisted");
});

test("acceptance (adapter): exception allows one endpoint, expires via alarm, and can be removed", async () => {
  const bg = await background();
  await bg.request({url: "https://publisher.example/article", type: "main_frame"});
  const beacon = {url: "https://publisher.example/collect", type: "beacon", documentUrl: "https://publisher.example/article"};
  assert.equal((await bg.request(beacon)).cancel, true);
  const tabUrl = "https://publisher.example/article";
  const exc = await bg.fromPopup({type: "add-exception", tabId: 1, tabUrl, host: "publisher.example", path: "/collect", resourceType: "beacon", minutes: 15});
  assert.equal(exc.ok, true, exc.error);
  assert.equal(bg.alarms.get("eg-expiry").when, START + 15 * 60000);
  assert.equal((await bg.request(beacon)).cancel, true, "manual block remains authoritative during an ordinary exception");
  assert.equal((await bg.request({...beacon, type: "xmlhttprequest"})).cancel, true, "other type still blocked");
  const state = await bg.fromPopup({type: "popup-state", tabId: 1, tabUrl});
  assert.equal(state.exceptions.length, 1);
  assert.equal(state.exceptions[0].msLeft, 15 * 60000);
  bg.clock.now = START + 15 * 60000;
  assert.equal((await bg.request(beacon)).cancel, true, "blocked again at expiry, before the alarm fires");
  for (const fn of bg.browser.alarms.onAlarm.fns) await fn({name: "eg-expiry"});
  assert.equal(bg.api.store.exceptions.length, 0);
  assert.equal(bg.storage.egressGuard.exceptions.length, 0, "expired exception removed from storage");
  assert.ok(bg.tabMessages.some((m) => m.msg.type === "rules-changed"), "tabs told about the change");
  const again = await bg.fromPopup({type: "add-exception", tabId: 1, tabUrl, host: "publisher.example", path: "/collect", resourceType: "beacon", minutes: 5});
  assert.equal((await bg.fromPopup({type: "remove-exception", id: again.value.id})).ok, true);
  assert.equal((await bg.request(beacon)).cancel, true);
  const wild = await bg.fromPopup({type: "add-exception", tabId: 1, tabUrl, host: "publisher.example", path: "/*", resourceType: "beacon", minutes: 5});
  assert.ok(wild.error);
});

/** Load warning.html with a fake chrome; `framed` puts it inside another page's frame. */
async function warningPage(href, {framed = false} = {}) {
  const doc = parseHTML(read("browser/warning.html"));
  const sent = [];
  const win = {listeners: {}, reloads: 0, replaced: null};
  const location = {href, reload: () => { win.reloads++; }, replace: (u) => { win.replaced = u; }};
  const chrome = {runtime: {sendMessage: async (msg) => { sent.push(msg); return msg.type === "continue-once" ? {ok: true, url: msg.url} : {minutes: 10}; }},
    tabs: {update: async () => {}}};
  const ctx = vm.createContext({document: doc, chrome, console, URL, location, history: {length: 1},
    addEventListener: (type, fn) => { win.listeners[type] = fn; }});
  ctx.top = framed ? {} : ctx;
  ctx.self = ctx;
  for (const file of ["core/psl-data.js", "core/hosts.js", "core/links.js", "core/params.js", "core/dnr.js", "warning.js"]) vm.runInContext(read(`browser/${file}`), ctx, {filename: file});
  await ctx.__EGWarning.ready;
  return {doc, sent, win, location, ctx};
}

test("warning page: Continue sends the address it shows, re-renders if the address changes, and refuses to work in a frame", async () => {
  const WARN = "chrome-extension://danbhmcinakkkkbobacafgidgkfibfmg/warning.html?list=threats#";
  const page = await warningPage(`${WARN}https://login.bad.example/x`);
  assert.equal(allText(page.doc.getElementById("host")), "login.bad.example");
  userClick(page.doc.getElementById("reveal"));
  userClick(page.doc.getElementById("continue"));
  await settle(); await settle();
  assert.equal(JSON.stringify(page.sent.find((m) => m.type === "continue-once")), JSON.stringify({type: "continue-once", url: "https://login.bad.example/x"}));
  // An opener changes only the fragment: the page must not keep showing the old host with a live Continue.
  page.location.href = `${WARN}https://other-bad.example/`;
  assert.equal(typeof page.win.listeners.hashchange, "function");
  page.win.listeners.hashchange();
  assert.equal(page.win.reloads, 1);
  assert.equal(page.doc.getElementById("continue").disabled, true);
  const framed = await warningPage(`${WARN}https://login.bad.example/x`, {framed: true});
  assert.equal(framed.doc.getElementById("reveal").disabled, true);
  assert.equal(framed.doc.getElementById("continue").disabled, true);
  assert.equal(framed.sent.some((m) => m.type === "continue-once"), false);
});

/** Render the popup against a canned popup-state reply. */
async function popupWith(state) {
  const doc = parseHTML(read("browser/popup.html"));
  const sent = [];
  const browser = {
    runtime: {sendMessage: async (msg) => { sent.push(msg); return msg.type === "popup-state" ? JSON.parse(JSON.stringify(state)) : {ok: true}; }},
    tabs: {query: async () => [{id: 1, url: "https://publisher.example/a"}],
      sendMessage: async () => ({site: "publisher.example", paused: false, hidden: 0, shown: 0, protectedRules: [], overbroadRules: []})},
  };
  const ctx = vm.createContext({document: doc, browser, console, close: () => {}});
  vm.runInContext(read("browser/popup.js"), ctx, {filename: "popup.js"});
  await ctx.__EGPopup.ready;
  return {doc, sent, text: (id) => allText(doc.getElementById(id))};
}
const BASE_STATE = {host: "publisher.example", site: "publisher.example", lists: [], requestRules: [], cosmeticRules: [], exceptions: [],
  types: ["beacon", "ping", "xmlhttprequest", "script", "image", "imageset", "stylesheet", "font", "media", "sub_frame", "object", "csp_report", "other"]};

test("popup offers no one-click Allow for malware hosts or for WebSocket-like types", async () => {
  const {doc, text} = await popupWith({...BASE_STATE, feedback: "debug", blocked: [
    {host: "cdn.bad.example", path: "/x.js", type: "script", list: "threats", count: 1},
    {host: "pixel.tracker.test", path: "/socket", type: "websocket", list: "trackers", count: 1},
    {host: "pixel.tracker.test", path: "/p.gif", type: "image", list: "trackers", count: 2},
  ]});
  const buttons = doc.getElementById("blocked").querySelectorAll('button[type="button"]');
  assert.equal(buttons.length, 1, "only the tracker image can be allowed");
  assert.match(buttons[0].getAttribute("aria-label"), /pixel\.tracker\.test\/p\.gif \(image\)/);
  assert.match(text("blocked"), /cdn\.bad\.example\/x\.js/, "the threat request is still listed");
});

test("popup in a packed build shows counts by list and says it cannot name addresses", async () => {
  const {text, doc} = await popupWith({...BASE_STATE, feedback: "counts", counts: {trackers: 5, cname: 2}, blocked: []});
  assert.equal(text("blocked-count"), "7");
  assert.match(text("breakdown"), /5.*2/s);
  assert.equal(doc.getElementById("hero-note").hidden, false);
  assert.match(text("hero-note"), /cannot see which addresses/);
  assert.equal(doc.getElementById("breakdown-group").hidden, false, "counts by reason are listed");
  const badge = await popupWith({...BASE_STATE, feedback: "badge", blocked: []});
  assert.equal(badge.doc.getElementById("blocked-empty").hidden, false);
  assert.match(badge.text("blocked-empty"), /toolbar badge/);
  assert.equal(badge.text("blocked-count"), "–", "no count is invented");
  const debug = await popupWith({...BASE_STATE, feedback: "debug", blocked: []});
  assert.equal(debug.doc.getElementById("hero-note").hidden, true);
});

test("popup renders blocked vs hidden, rules and exceptions with textContent only", async () => {
  const bg = await background();
  const tabUrl = "https://publisher.example/article";
  await bg.request({url: tabUrl, type: "main_frame"});
  await bg.request({url: "https://publisher.example/collect", type: "beacon", documentUrl: tabUrl});
  assert.ok((await bg.fromPopup({type: "add-request-rule", tabUrl, host: "publisher.example", path: "/x<img", types: ["beacon"]})).error);
  const doc = parseHTML(read("browser/popup.html"));
  const tabCalls = [];
  const browser = {
    runtime: {sendMessage: (msg) => bg.fromPopup(msg)},
    tabs: {
      query: async () => [{id: 1, url: tabUrl}],
      sendMessage: async (tabId, msg) => { tabCalls.push(msg.type); return {site: "publisher.example", paused: false, hidden: 1, shown: 0, protectedRules: [], overbroadRules: []}; },
    },
  };
  const ctx = vm.createContext({document: doc, browser, console, close: () => {}});
  vm.runInContext(read("browser/popup.js"), ctx, {filename: "popup.js"});
  await ctx.__EGPopup.ready;
  const text = (id) => allText(doc.getElementById(id));
  assert.match(text("site"), /publisher\.example/);
  assert.match(text("blocked"), /publisher\.example\/collect/);
  assert.match(text("blocked"), /beacon/i);
  assert.match(text("hidden"), /1 element hidden/);
  assert.match(text("rules"), /publisher\.example\/collect.*Always block/s);
  assert.match(text("rules"), /article\.card\.teaser\[data-ad-slot\].*Hidden on this site/s);
  assert.equal(text("exceptions"), "");
  assert.equal(doc.getElementById("exceptions-group").hidden, true, "no exceptions: the group is not shown");
  const allow = doc.getElementById("blocked").querySelector('button[type="button"]');
  assert.ok(allow);
  assert.match(allow.getAttribute("aria-label"), /Allow publisher\.example\/collect \(beacon\) on this site for 15 minutes/);
  userClick(allow);
  await settle(); await settle();
  assert.match(text("exceptions"), /publisher\.example\/collect.*beacon · 15 min left/si);
  assert.equal(doc.getElementById("exceptions-group").hidden, false);
  assert.equal(bg.api.store.exceptions.length, 1);
  // Removing a rule from the popup.
  const before = bg.api.store.rules.length;
  const remove = doc.getElementById("rules").querySelector('button[aria-label^="Remove rule publisher.example/collect"]');
  userClick(remove);
  await settle(); await settle();
  assert.equal(bg.api.store.rules.length, before - 1);
  assert.ok(tabCalls.includes("status"));
});
