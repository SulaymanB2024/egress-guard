"use strict";
// Chrome service-worker adapter with a fake `chrome` namespace. No real browser.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const dnr = require("../../browser/core/dnr.js");
const hosts = require("../../browser/core/hosts.js");

const root = path.join(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const manifest = JSON.parse(read("browser/manifest.chrome.json"));
const fixture = JSON.parse(read("tests/browser/fixtures/publisher/rules.json"));
const ID = dnr.extensionIdFromHex(crypto.createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex"));
const EXT = `chrome-extension://${ID}/`;
const START = Date.UTC(2026, 10, 20, 12, 0, 0);
const WORKER = ["core/psl-data.js", "core/hosts.js", "core/selectors.js", "core/rules.js", "core/store.js", "core/links.js", "core/param-data.js", "core/param-policy.js", "core/params.js", "core/cookies.js", "core/dnr.js", "core/browser-privacy.js", "core/privacy-hardening.js", "background-chrome.js"];
const event = () => { const fns = []; return {addListener: (fn) => fns.push(fn), fns, fire: (...a) => Promise.all(fns.map((f) => f(...a)))}; };
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(setImmediate); };

// Threat-listed names in the fake browser (the real worker asks Chrome's testMatchOutcome, or reads its own ruleset).
const THREATS = ["bad.example", "other-bad.example"];
const isListed = (host) => THREATS.some((d) => host === d || host.endsWith(`.${d}`));

async function worker({stored = fixture, packed = false, extraLocal = {}, extraSession = {}, initialDynamic = [], initialSession = [], now = START, faults = {}, threats = THREATS, why = null, tabUrl = null,
  tabs = [{id: 1, url: "https://publisher.example/article"}]} = {}) {
  const clock = {now};
  const reloads = [];
  const local = {egressGuard: stored && JSON.parse(JSON.stringify(stored)), ...JSON.parse(JSON.stringify(extraLocal))};
  const session = JSON.parse(JSON.stringify(extraSession));
  const fail = (name, detail) => {
    const setting = faults[name];
    if (typeof setting === "function" ? setting(detail) : setting === true || setting > 0) {
      if (typeof setting === "number") faults[name]--;
      throw new Error(`injected ${name} failure`);
    }
  };
  const area = (obj, name) => ({
    get: async (key) => { fail(`${name}Read`, key); return typeof key === "string" ? {[key]: obj[key] && JSON.parse(JSON.stringify(obj[key]))} : {...obj}; },
    set: async (items) => { fail(`${name}Write`, items); Object.assign(obj, JSON.parse(JSON.stringify(items))); },
    remove: async (key) => { for (const k of [].concat(key)) delete obj[k]; },
  });
  let dynamicRules = JSON.parse(JSON.stringify(initialDynamic)), sessionRules = JSON.parse(JSON.stringify(initialSession));
  const dynamicUpdates = [];
  const alarms = new Map();
  const tabMessages = [];
  const chrome = {
    // With use_dynamic_url, getURL returns the per-session origin; the extension's own pages still run at EXT.
    runtime: {id: ID, getURL: (p) => `chrome-extension://4f9e0c2a-dynamic-session/${p}`, onMessage: event(),
      getManifest: () => ({...manifest, ...(packed ? {update_url: "https://clients2.google.com/service/update2/crx"} : {})}), reload: () => { reloads.push(clock.now); }},
    storage: {local: area(local, "local"), session: area(session, "session")},
    alarms: {create: (name, info) => alarms.set(name, info), clear: async (name) => alarms.delete(name), get: async (name) => alarms.get(name), onAlarm: event()},
    tabs: {get: async (id) => ({id, url: tabUrl}), update: async (id, props) => { updates.push({id, ...props}); return {id}; }, onUpdated: event(), onRemoved: event(), sendMessage: async (tabId, msg) => { tabMessages.push({tabId, msg}); }, query: async () => JSON.parse(JSON.stringify(tabs))},
    webNavigation: {onBeforeNavigate: event(), onCommitted: event(), onTabReplaced: event(), onErrorOccurred: event()},
    action: {setBadgeBackgroundColor: async () => {}},
    cookies: {onChanged: event(), remove: async (d) => { cookieCalls.push({op: "remove", ...d}); }, set: async (d) => { cookieCalls.push({op: "set", ...d}); }},
    browsingData: {remove: async (options, types) => { browsingCalls.push(JSON.parse(JSON.stringify({options, types}))); }},
    declarativeNetRequest: {
      getDynamicRules: async () => { fail("dynamicRead", dynamicRules); return dynamicRules.map((r) => ({...r})); },
      updateDynamicRules: async ({removeRuleIds = [], addRules = []}) => { fail("dynamicUpdate", {removeRuleIds, addRules}); dynamicUpdates.push(JSON.parse(JSON.stringify({removeRuleIds, addRules}))); dynamicRules = JSON.parse(JSON.stringify([...dynamicRules.filter((r) => !removeRuleIds.includes(r.id)), ...addRules])); },
      updateSessionRules: async ({removeRuleIds = [], addRules = []}) => { fail("sessionUpdate", {removeRuleIds, addRules}); sessionRules = JSON.parse(JSON.stringify([...sessionRules.filter((r) => !removeRuleIds.includes(r.id)), ...addRules])); },
      getSessionRules: async () => sessionRules.map((r) => ({...r})),
      onRuleMatchedDebug: event(),
      testMatchOutcome: async ({url, type}) => ({matchedRules: type === "main_frame" && threats.some((d) => new URL(url).hostname === d || new URL(url).hostname.endsWith(`.${d}`)) ? [{ruleId: 2, rulesetId: "threats"}] : []}),
      getMatchedRules: async ({tabId}) => ({rulesMatchedInfo: matchedInfo.filter((m) => m.tabId === tabId)}),
      setExtensionActionOptions: async () => {},
    },
  };
  const matchedInfo = [];
  const updates = [];
  const cookieCalls = [], browsingCalls = [];
  const fetched = [];
  if (packed) { delete chrome.declarativeNetRequest.onRuleMatchedDebug; delete chrome.declarativeNetRequest.testMatchOutcome; }
  // Only the worker's own packaged ruleset may be fetched (the CSP allows connect-src 'self' and nothing else).
  const disk = {build: "0".repeat(32)};
  const fetch = async (url) => {
    fetched.push(url);
    if (url.startsWith("http://egress-guard.invalid/why?host=")) {
      if (!why) throw new TypeError("Failed to fetch");
      return {ok: true, json: async () => why(decodeURIComponent(url.split("host=")[1]))};
    }
    if (url === `${EXT}rules/build.json`) return {ok: true, json: async () => ({...disk})};
    if (url !== `${EXT}rules/threats.json`) throw new Error(`unexpected fetch ${url}`);
    return {ok: true, json: async () => [{id: 1, priority: 2, action: {type: "block"}, condition: {requestDomains: threats}}]};
  };
  class FakeDate extends Date { static now() { return clock.now; } }
  const ctx = vm.createContext({chrome, console, URL, URLSearchParams, Date: FakeDate, crypto: globalThis.crypto, setTimeout, clearTimeout, fetch});
  ctx.EGLists = {build: "0".repeat(32), lists: {trackers: {label: "Ads and trackers", name: "HaGeZi Multi PRO++", domains: 4}, threats: {label: "Malware and phishing", name: "HaGeZi Threat Intelligence (Medium)", domains: 2}}};
  for (const file of WORKER) vm.runInContext(read(`browser/${file}`), ctx, {filename: file});
  await ctx.__EGBackground.ready;
  const send = (msg, sender) => new Promise((resolve) => { assert.equal(chrome.runtime.onMessage.fns[0](msg, {id: ID, ...sender}, (r) => resolve(JSON.parse(JSON.stringify(r)))), true); });
  const popup = (msg) => send(msg, {url: `${EXT}popup.html`});
  const page = (msg, url = "https://publisher.example/article", tabId = 1) => send(msg, {url, frameId: 0, tab: {id: tabId, url}});
  const warning = (msg, blocked = "https://login.bad.example/x?y=1", tabId = 4, frameId = 0) => {
    const url = `${EXT}warning.html?list=threats#${blocked}`;
    return send(msg, {url, frameId, tab: {id: tabId, url}});
  };
  // What the warning page sends: the address it is showing.
  const cont = (blocked = "https://login.bad.example/x?y=1", tabId = 4, shown = blocked, frameId = 0) => warning({type: "continue-once", url: shown}, blocked, tabId, frameId);
  const matched = (tabId, url, type, rulesetId, ruleId = 1) => chrome.declarativeNetRequest.onRuleMatchedDebug.fire({request: {tabId, url, type}, rule: {ruleId, rulesetId}});
  const unwrapPage = (msg, link, tabId = 6, frameId = 0) => { const url = `${EXT}unwrap.html#${link}`; return send(msg, {url, frameId, tab: {id: tabId, url}}); };
  return {updates, disk, reloads, ctx, chrome, clock, faults, tabs, local, session, alarms, tabMessages, popup, page, warning, cont, matched, matchedInfo, fetched, api: ctx.__EGBackground, cookieCalls, browsingCalls, unwrapPage, send, dynamicUpdates,
    dynamic: () => dynamicRules, sessionRules: () => sessionRules};
}

test("manifest (Chrome): MV3 service worker, DNR rulesets, minimal permissions, fixed id, no remote code", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "background.js");
  // cookies: tracking cookies removed as they are set; contextMenus + offscreen + clipboardWrite: "Copy clean link".
  assert.deepEqual([...manifest.permissions].sort(), ["alarms", "browsingData", "clipboardWrite", "contextMenus", "cookies", "declarativeNetRequest", "declarativeNetRequestFeedback", "offscreen", "scripting", "storage", "webNavigation"]);
  assert.deepEqual(manifest.host_permissions, ["http://*/*", "https://*/*"]);
  // Rulesets are written by the build (scripts/build-browser.mjs); the source manifest lists none.
  assert.deepEqual(manifest.declarative_net_request.rule_resources, []);
  // Only by a per-session URL, so a site cannot probe the fixed id to learn the extension is installed.
  assert.deepEqual(manifest.web_accessible_resources, [{resources: ["warning.html", "unwrap.html", "surrogates/*.js"], matches: ["<all_urls>"], use_dynamic_url: true}]);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  // The worker may read its own packaged files (the threat ruleset) and nothing else.
  // And it may ask the local guard why the proxy refused a page (a reserved name only the system proxy answers).
  assert.match(manifest.content_security_policy.extension_pages, /connect-src 'self' http:\/\/egress-guard\.invalid(;|$)/);
  assert.match(manifest.content_security_policy.extension_pages, /frame-ancestors 'none'/);
  assert.equal(ID.length, 32);
  // The page-world script only defines navigator.globalPrivacyControl; everything else runs isolated, top frame only.
  assert.equal(manifest.content_scripts[0].world, "MAIN");
  assert.deepEqual(manifest.content_scripts[0].js, ["page-gpc.js"]);
  assert.equal(manifest.content_scripts[1].world, undefined);
  assert.equal(manifest.content_scripts[1].all_frames, false);
  for (const file of [...WORKER, ...manifest.content_scripts[0].js, ...manifest.content_scripts[1].js, "popup.html", "warning.html", "refused.html", "refused.js", "unwrap.html"]) assert.ok(fs.existsSync(path.join(root, "browser", file)), file);
});

test("stored request rules become scoped dynamic DNR rules on start; cosmetic rules do not", async () => {
  const w = await worker();
  const rules = w.dynamic();
  assert.equal(rules.length, 1);
  assert.equal(rules[0].priority, dnr.PRIORITY.userBlock);
  assert.deepEqual(rules[0].condition.topDomains, ["publisher.example"]);
  assert.deepEqual(rules[0].condition.resourceTypes, ["image", "ping", "xmlhttprequest"]);
  assert.equal(w.api.sources[rules[0].id], "publisher-collect");
});

test("blocked log: per tab, labelled by list, no query strings, reset on navigation, params ignored", async () => {
  const w = await worker();
  await w.matched(1, "https://pixel.tracker.test/p.gif?uid=secret", "image", "trackers");
  await w.matched(1, "https://pixel.tracker.test/p.gif?uid=other", "image", "trackers");
  await w.matched(1, "https://metrics.publisher.example/m", "ping", "cname");
  await w.matched(1, "https://publisher.example/collect", "ping", "_dynamic", w.dynamic()[0].id);
  await w.matched(1, "https://publisher.example/article?utm_source=x", "main_frame", "params");
  await w.matched(2, "https://elsewhere.test/x.js", "script", "trackers");
  const state = await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/article"});
  assert.deepEqual(state.blocked.map((b) => [b.list, b.host, b.path, b.type, b.count]), [
    ["trackers", "pixel.tracker.test", "/p.gif", "image", 2],
    ["cname", "metrics.publisher.example", "/m", "ping", 1],
    ["user", "publisher.example", "/collect", "ping", 1],
  ]);
  assert.equal(state.blocked[2].ruleId, "publisher-collect");
  assert.equal(JSON.stringify(state).includes("secret"), false, "query strings are not logged");
  assert.equal(state.lists.find((l) => l.id === "trackers").name, "HaGeZi Multi PRO++");
  await w.chrome.tabs.onUpdated.fire(1, {status: "loading", url: "https://publisher.example/next"}, {});
  await settle();
  assert.equal((await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/next"})).blocked.length, 0);
});

test("acceptance (Chrome adapter): exact endpoint permission is tab-bound, cookieless and removed after scheduled expiry", async () => {
  const w = await worker();
  const tabUrl = "https://publisher.example/article";
  const exc = await w.popup({type: "add-exception", tabId: 1, tabUrl, host: "pixel.tracker.test", path: "/p.gif", resourceType: "image", minutes: 15});
  assert.equal(exc.ok, true, exc.error);
  const rule = w.sessionRules().find((r) => r.priority === dnr.PRIORITY.exception);
  assert.ok(rule, "exception compiled");
  assert.equal(rule.action.type, "allow");
  assert.deepEqual(rule.condition.requestDomains, ["pixel.tracker.test"]);
  assert.deepEqual(rule.condition.topDomains, ["publisher.example"]);
  assert.ok(rule.priority > dnr.PRIORITY.list && rule.priority < dnr.PRIORITY.threat && rule.priority < dnr.PRIORITY.userBlock);
  assert.equal(w.alarms.get("eg-expiry").when, START + 15 * 60000);
  assert.ok((await w.popup({type: "add-exception", tabId: 1, tabUrl, host: "x.test", path: "/", resourceType: "main_frame", minutes: 5})).error);
  await w.matched(1, "https://pixel.tracker.test/p.gif", "image", "_session", rule.id);
  const logged = await w.popup({type: "popup-state", tabId: 1, tabUrl});
  assert.equal(logged.blocked.length, 0, "a match on an allow rule is not reported as blocked");
  w.clock.now = START + 15 * 60000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-expiry"});
  await settle();
  assert.equal(w.sessionRules().some((r) => r.priority === dnr.PRIORITY.exception), false, "removed at expiry");
  assert.equal(w.local.egressGuard.exceptions.length, 0);
});

test("adding and removing a request rule updates dynamic rules and tells tabs", async () => {
  const w = await worker({stored: null});
  const added = await w.popup({type: "add-request-rule", tabId: 1, tabUrl: "https://www.news.example/a", host: "news.example", path: "/beacon", types: ["beacon"]});
  assert.equal(added.ok, true, added.error);
  assert.equal(added.value.site, "news.example");
  assert.equal(w.dynamic().length, 1);
  assert.ok(w.tabMessages.some((m) => m.msg.type === "rules-changed"));
  assert.equal((await w.popup({type: "remove-rule", id: added.value.id})).ok, true);
  assert.equal(w.dynamic().length, 0);
  assert.ok((await w.popup({type: "add-request-rule", tabUrl: "https://news.example/", host: "news.example", path: "/*", types: ["beacon"]})).error, "validation still applies");
});

test("continue once: only the warning page may ask; one tab, one host; ends when the tab leaves the host", async () => {
  const w = await worker();
  assert.match((await w.page({type: "continue-once"})).error, /Not allowed/);
  assert.match((await w.popup({type: "continue-once"})).error, /Not allowed/);
  assert.match((await w.cont("javascript:alert(1)")).error, /Nothing to continue/);
  const ok = await w.cont();
  assert.deepEqual({...ok}, {ok: true, url: "https://login.bad.example/x?y=1"});
  const rules = w.sessionRules();
  assert.equal(rules.length, 2);
  for (const rule of rules) {
    assert.ok(["allow", "modifyHeaders"].includes(rule.action.type), "navigation allow plus sanitation, never allowAllRequests");
    assert.deepEqual(rule.condition.tabIds, [4]);
    assert.deepEqual(rule.condition.requestDomains, ["login.bad.example"]);
    assert.ok([dnr.PRIORITY.continue, dnr.PRIORITY.continueHeaders].includes(rule.priority));
  }
  assert.ok(w.alarms.has("eg-expiry"), "a 10-minute cap is scheduled");
  assert.equal(w.alarms.get("eg-expiry").when, START + 10 * 60000);
  // Moving within the host keeps it; another tab's navigation does not affect it; leaving ends it.
  await w.chrome.tabs.onUpdated.fire(4, {status: "loading", url: "https://login.bad.example/next"}, {});
  await w.chrome.tabs.onUpdated.fire(5, {status: "loading", url: "https://news.example/"}, {});
  await settle();
  assert.equal(w.sessionRules().length, 2);
  await w.chrome.tabs.onUpdated.fire(4, {status: "loading", url: "https://news.example/"}, {});
  await w.api.sync();
  assert.equal(w.sessionRules().length, 0);
  // The cap: expires even if the tab stays.
  await w.cont();
  w.clock.now = START + 10 * 60000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-expiry"});
  await settle();
  assert.equal(w.sessionRules().length, 0);
  const info = await w.warning({type: "warning-info", list: "threats"});
  assert.equal(info.list.name, "HaGeZi Threat Intelligence (Medium)");
});

test("continue once refuses a different host than the page showed, a framed warning page, and unlisted hosts", async () => {
  const w = await worker();
  // The opener swapped only the fragment after the page rendered login.bad.example: the shown URL no longer matches.
  const swapped = await w.cont("https://other-bad.example/", 4, "https://login.bad.example/x?y=1");
  assert.match(swapped.error, /changed/);
  assert.match((await w.warning({type: "continue-once"})).error, /changed/, "a message without the shown URL is refused");
  assert.match((await w.cont(undefined, 4, undefined, 3)).error, /frame/, "a warning page inside a frame cannot continue");
  assert.match((await w.cont("https://news.example/")).error, /not on the malware/, "only a threat-listed host can be continued to");
  assert.equal(w.sessionRules().length, 0);
});

test("continue once: concurrent requests get distinct rule ids", async () => {
  const w = await worker();
  const replies = await Promise.all([w.cont(undefined, 4), w.cont("https://other-bad.example/", 5), w.cont(undefined, 6)]);
  assert.ok(replies.every((r) => r.ok), JSON.stringify(replies));
  const ids = w.sessionRules().map((r) => r.id);
  assert.equal(ids.length, 6);
  assert.equal(new Set(ids).size, 6, ids.join(","));
  assert.equal((await w.api.continues()).length, 3);
});

test("threat-listed requests cannot be allowed from the popup", async () => {
  const w = await worker();
  const reply = await w.popup({type: "add-exception", tabId: 1, tabUrl: "https://publisher.example/article", host: "cdn.bad.example", path: "/x.js", resourceType: "script", minutes: 15});
  assert.match(reply.error, /malware/);
  assert.equal(w.dynamic().some((r) => r.priority === dnr.PRIORITY.exception), false);
});

test("packed build: the threat check reads only the extension's own ruleset", async () => {
  const w = await worker({packed: true});
  assert.match((await w.cont("https://news.example/")).error, /not on the malware/);
  assert.equal((await w.cont()).ok, true);
  assert.deepEqual([...new Set(w.fetched)], [`${EXT}rules/threats.json`]);
});

test("built-in ad-slot hiding is on by default and switches off per site from the popup only", async () => {
  const w = await worker();
  assert.equal((await w.page({type: "page-rules"})).generic, true);
  assert.match((await w.page({type: "set-generic", on: false})).error, /Not allowed/);
  const off = await w.popup({type: "set-generic", tabId: 1, tabUrl: "https://www.publisher.example/a", on: false});
  assert.equal(off.ok, true, off.error);
  assert.equal(off.site, "publisher.example");
  assert.deepEqual(w.local.egressGuardGenericOff, ["publisher.example"]);
  assert.ok(w.tabMessages.some((m) => m.msg.type === "generic" && m.msg.on === false), "open tabs on the site are told at once");
  assert.equal((await w.page({type: "page-rules"})).generic, false);
  assert.equal((await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/a"})).generic, false);
  assert.ok((await w.popup({type: "set-generic", tabId: 1, tabUrl: "https://publisher.example/a", on: "no"})).error);
  await w.popup({type: "set-generic", tabId: 1, tabUrl: "https://publisher.example/a", on: true});
  assert.deepEqual(w.local.egressGuardGenericOff, []);
});

test("packed build: popup gets per-list counts from getMatchedRules and says it cannot name addresses", async () => {
  const w = await worker({packed: true});
  await w.chrome.tabs.onUpdated.fire(1, {status: "loading", url: "https://publisher.example/a"}, {});
  await settle();
  const t = w.clock.now;
  w.matchedInfo.push(
    {tabId: 1, timeStamp: t, rule: {ruleId: 3, rulesetId: "trackers"}}, {tabId: 1, timeStamp: t, rule: {ruleId: 3, rulesetId: "trackers"}},
    {tabId: 1, timeStamp: t, rule: {ruleId: 1, rulesetId: "cname"}}, {tabId: 1, timeStamp: t, rule: {ruleId: 2, rulesetId: "params"}},
    {tabId: 1, timeStamp: t, rule: {ruleId: 100000, rulesetId: "_session"}}, {tabId: 2, timeStamp: t, rule: {ruleId: 3, rulesetId: "trackers"}});
  const state = await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/a"});
  assert.equal(state.feedback, "counts");
  assert.deepEqual({...state.counts}, {trackers: 2, cname: 1});
  assert.equal(state.blocked.length, 0);
  delete w.chrome.declarativeNetRequest.getMatchedRules;
  assert.equal((await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/a"})).feedback, "badge");
  const unpacked = await worker();
  assert.equal((await unpacked.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/a"})).feedback, "debug");
});

test("a rebuilt unpacked folder is noticed on the hourly check and the popup says so; it never reloads itself", async () => {
  const w = await worker();
  await settle();
  assert.equal(w.alarms.get("eg-rebuilt").periodInMinutes, 60);
  const tick = async () => { await w.chrome.alarms.onAlarm.fire({name: "eg-rebuilt"}); await settle(); };
  const state = () => w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/a"});
  await tick();
  assert.equal((await state()).rebuilt, false, "same build on disk");
  w.disk.build = "f".repeat(32);
  await tick();
  assert.equal((await state()).rebuilt, true, "newer build on disk: the popup asks for a reload");
  assert.equal(w.reloads.length, 0, "runtime.reload() left the extension disabled in headless Chrome, so it is never called");
  w.disk.build = "<script>";
  assert.equal(await w.api.reloadIfRebuilt(), "unreadable");
  const packed = await worker({packed: true});
  packed.disk.build = "f".repeat(32);
  assert.equal(await packed.api.reloadIfRebuilt(), "packed");
  assert.equal(packed.reloads.length, 0);
});

test("blocked log keeps at most 256 characters of a path", async () => {
  const w = await worker();
  await w.matched(1, `https://pixel.tracker.test/${"a".repeat(5000)}`, "image", "trackers");
  await w.matched(1, "wss://pixel.tracker.test/socket", "websocket", "trackers");
  const state = await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/article"});
  assert.equal(state.blocked[0].path.length, 256);
  assert.equal(state.blocked[1].type, "websocket", "WebSocket is shown as itself, not as other");
});

test("pages cannot use popup actions; the warning page cannot either; strangers are refused", async () => {
  const w = await worker();
  for (const msg of [{type: "remove-rule", id: "publisher-collect"}, {type: "popup-state", tabId: 1}, {type: "add-exception"}]) {
    assert.match((await w.page(msg)).error, /Not allowed/);
    assert.match((await w.warning(msg)).error, /Not allowed/);
  }
  const page = await w.page({type: "page-rules"});
  assert.deepEqual([...page.rules.map((r) => r.id)], ["publisher-sponsored-card"]);
  assert.equal((await w.page({type: "page-rules"}, "https://publisher.example/", 1)).site, "publisher.example");
  const stranger = await new Promise((resolve) => w.chrome.runtime.onMessage.fns[0]({type: "page-rules"}, {id: "other", url: "https://publisher.example/"}, resolve));
  assert.match(stranger.error, /Unknown sender/);
});

// ---- hardening (review findings 1, 5, 7, 12) ----------------------------------------------------------------------
test("onCookie: vendor-scoped names only on their vendor's domains; opt-out and consent cookies never; DSID on a VPN never", async () => {
  const w = await worker();
  const fire = (cookie) => w.api.onCookie({removed: false, cookie: {path: "/", secure: true, storeId: "0", session: false, ...cookie}});
  await fire({name: "_ga", domain: ".shop.example"});
  await fire({name: "IDE", domain: ".doubleclick.net"});
  await fire({name: "DSID", domain: "vpn.university.example"});
  await fire({name: "DSID", domain: ".doubleclick.net"});
  await fire({name: "test_cookie", domain: "intranet.corp.example"});
  await fire({name: "_hjOptOut", domain: ".shop.example"});
  await fire({name: "taboola_optout", domain: ".taboola.com"});
  await fire({name: "_cs_c", domain: ".shop.example"});
  await fire({name: "uuid2", domain: ".shop.example"});
  await fire({name: "uuid2", domain: ".adnxs.com"});
  const removed = w.cookieCalls.filter((c) => c.op === "remove").map((c) => `${c.name}@${c.url}`);
  assert.deepEqual(removed, ["_ga@https://shop.example/", "IDE@https://doubleclick.net/", "DSID@https://doubleclick.net/", "uuid2@https://adnxs.com/"]);
  // The brake keeps a site's own tracking cookies.
  await w.popup({type: "set-clean", on: false, tabUrl: "https://braked.example/"});
  await fire({name: "_ga", domain: ".braked.example"});
  assert.equal(w.cookieCalls.filter((c) => c.name === "_ga").length, 1);
});

test("unwrap page messages: only the unwrap page in a tab's top frame may check a destination, read the setting or pass a scanner", async () => {
  const w = await worker();
  const scanner = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.org%2Fdoc&data=x";
  assert.deepEqual(await w.unwrapPage({type: "check-destination", url: "https://login.bad.example/x"}, scanner), {ok: true, threat: true});
  assert.deepEqual(await w.unwrapPage({type: "check-destination", url: "https://example.org/doc"}, scanner), {ok: true, threat: false});
  assert.ok((await w.unwrapPage({type: "check-destination", url: "javascript:alert(1)"}, scanner)).error);
  assert.deepEqual(await w.unwrapPage({type: "unwrap-config"}, scanner), {scannedDirect: false});
  // Pages, frames, the warning page and the popup are refused.
  for (const reply of [await w.page({type: "check-destination", url: "https://example.org/"}), await w.page({type: "scanner-continue", url: scanner}),
    await w.unwrapPage({type: "scanner-continue", url: scanner}, scanner, 6, 1), await w.warning({type: "unwrap-config"}),
    await w.popup({type: "scanner-continue", url: scanner})]) assert.ok(reply.error, JSON.stringify(reply));
  // The pass is for the scanner the page shows, in that tab, once.
  assert.match((await w.unwrapPage({type: "scanner-continue", url: scanner + "&changed=1"}, scanner)).error, /changed/);
  assert.deepEqual(await w.unwrapPage({type: "scanner-continue", url: scanner}, scanner, 6), {ok: true});
  const pass = w.sessionRules().find((r) => r.priority === dnr.PRIORITY.scannerPass);
  assert.deepEqual(pass.condition, {requestDomains: ["nam02.safelinks.protection.outlook.com"], resourceTypes: ["main_frame"], tabIds: [6]});
  assert.equal(pass.action.type, "allow");
  // A tracker that led to a scanner: the page shows the scanner link, and that is what may pass.
  const viaGoogle = "https://www.google.com/url?q=" + encodeURIComponent(scanner);
  assert.deepEqual(await w.unwrapPage({type: "scanner-continue", url: scanner}, viaGoogle, 7), {ok: true});
  // Used up when the tab commits the navigation; gone with the tab too.
  await w.chrome.tabs.onUpdated.fire(6, {url: "https://nam02.safelinks.protection.outlook.com/?url=x"}, {});
  await w.api.sync();
  assert.ok(!w.sessionRules().some((r) => r.condition.tabIds && r.condition.tabIds[0] === 6 && r.priority === dnr.PRIORITY.scannerPass));
  await w.chrome.tabs.onRemoved.fire(7);
  await w.api.sync();
  assert.ok(!w.sessionRules().some((r) => r.priority === dnr.PRIORITY.scannerPass));
  // The popup setting, off by default.
  assert.equal((await w.popup({type: "popup-state", tabUrl: "https://publisher.example/"})).scannedDirect, false);
  assert.deepEqual(await w.popup({type: "set-scanned-direct", on: true}), {ok: true, on: true});
  assert.deepEqual(await w.unwrapPage({type: "unwrap-config"}, scanner), {scannedDirect: true});
  assert.ok((await w.popup({type: "set-noise", on: true})).error, "the fingerprint-noise switch is gone");
});

test("No scripts and Strict clear the site's service workers and Cache Storage for the origins the extension can name", async () => {
  const w = await worker();
  const reply = await w.popup({type: "set-mode", mode: "noscript", tabUrl: "https://publisher.example/article"});
  assert.equal(reply.mode, "noscript");
  assert.ok(reply.cleared.ok);
  assert.equal(w.browsingCalls.length, 1);
  assert.deepEqual(w.browsingCalls[0].types, {serviceWorkers: true, cacheStorage: true});
  assert.deepEqual(w.browsingCalls[0].options.origins, ["http://publisher.example", "http://www.publisher.example", "https://publisher.example", "https://www.publisher.example"]);
  await w.popup({type: "set-mode", mode: "strict", tabUrl: "https://publisher.example/article"});
  assert.equal(w.browsingCalls.length, 2);
  const standard = await w.popup({type: "set-mode", mode: "standard", tabUrl: "https://publisher.example/article"});
  assert.equal(standard.cleared, null);
  assert.equal(w.browsingCalls.length, 2);
});

test("Copy clean link: a tracker is unwrapped only from its own site; a scanner link is copied exactly", async () => {
  const w = await worker();
  const g = "https://www.google.com/url?q=" + encodeURIComponent("https://shop.example/p?id=9&utm_campaign=x");
  assert.equal(w.api.cleanLink(g, "www.google.com"), "https://shop.example/p?id=9");
  assert.equal(w.api.cleanLink(g, "mail.example"), g, "from elsewhere: Google's own check stays");
  const scanner = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.org%2F&data=x&utm_source=y";
  assert.equal(w.api.cleanLink(scanner, "outlook.office.com"), scanner);
});

test("offscreen copy: only the extension's own worker may write the clipboard", () => {
  const listeners = [];
  const copies = [];
  const box = {value: "", select() {}};
  const ctx = vm.createContext({chrome: {runtime: {id: ID, onMessage: {addListener: (fn) => listeners.push(fn)}}},
    document: {getElementById: () => box, execCommand: () => { copies.push(box.value); return true; }}});
  vm.runInContext(read("browser/offscreen.js"), ctx);
  const ask = (sender) => { let reply = null; listeners[0]({type: "offscreen-copy", text: "https://example.org/"}, sender, (r) => { reply = JSON.parse(JSON.stringify(r)); }); return reply; };
  assert.equal(ask({id: "other"}), null);
  assert.equal(ask({id: ID, url: "https://evil.example/", tab: {id: 1}}), null, "a content script in a tab");
  assert.equal(ask({id: ID, url: `${EXT}popup.html`, tab: {id: 2}}), null, "an extension page in a tab");
  assert.equal(ask({id: ID, url: "https://evil.example/"}), null, "not the extension's own origin");
  assert.equal(ask({id: ID}), null, "no sender URL");
  assert.deepEqual(ask({id: ID, url: `${EXT}background.js`}), {ok: true});
  assert.deepEqual(copies, ["https://example.org/"]);
});

// ---- timed per-site pause ----------------------------------------------------------------------------------------
const relaxFor = (w, site) => w.dynamic().some((r) => r.priority === dnr.PRIORITY.relax && r.condition.requestDomains.includes(site));
const cleanOffFor = (w, site) => w.dynamic().some((r) => r.priority === dnr.PRIORITY.clean && r.action.type === "allow" && r.condition.requestDomains.includes(site));
const sent = (w, type, tabId = 1) => w.tabMessages.filter((m) => m.tabId === tabId && m.msg.type === type).map((m) => m.msg);

test("pause: the popup pauses a site for 15 minutes (Relaxed, no hiding, no cleaning); it cannot be extended", async () => {
  const w = await worker();
  const tabUrl = "https://www.publisher.example/article";
  assert.ok((await w.page({type: "page-rules"})).rules.length > 0, "cosmetic rules apply before");
  const r = await w.popup({type: "pause-site", tabId: 1, tabUrl, minutes: 600});
  assert.equal(r.ok, true, r.error);
  assert.equal(r.site, "publisher.example", "scoped to the registrable domain");
  assert.equal(r.until, START + 15 * 60000, "fixed length; the message cannot choose it");
  assert.deepEqual({...w.local.egressGuardPauses.items}, {"publisher.example": START + 15 * 60000});
  assert.equal(w.alarms.get("eg-expiry").when, START + 15 * 60000, "an alarm ends it even if the worker sleeps");
  assert.ok(relaxFor(w, "publisher.example") && cleanOffFor(w, "publisher.example"));
  assert.deepEqual({...w.local.egressGuardModes || {sites: {}}}.sites || {}, {}, "the saved level is not changed");
  const state = await w.popup({type: "popup-state", tabId: 1, tabUrl});
  assert.equal(state.paused, START + 15 * 60000);
  assert.equal(state.mode, "relaxed");
  assert.equal(state.resumeMode, "standard", "the level that comes back");
  const pageRules = await w.page({type: "page-rules"});
  assert.deepEqual([...pageRules.rules], []);
  assert.equal(pageRules.generic, false);
  assert.equal((await w.page({type: "guard-config"})).clean, false);
  assert.deepEqual([...sent(w, "rules-changed").pop().rules], [], "open pages show what was hidden");
  assert.equal(sent(w, "generic").pop().on, false);
  assert.equal(sent(w, "clean-enabled").pop().on, false);
  w.clock.now = START + 5 * 60000;
  const again = await w.popup({type: "pause-site", tabId: 1, tabUrl});
  assert.match(again.error, /already paused/);
  assert.equal(w.local.egressGuardPauses.items["publisher.example"], START + 15 * 60000, "not extended");
  // Resume ends it at once.
  assert.equal((await w.popup({type: "resume-site", tabId: 1, tabUrl})).ok, true);
  assert.equal(relaxFor(w, "publisher.example"), false);
  assert.ok((await w.page({type: "page-rules"})).rules.length > 0);
  assert.equal(sent(w, "generic").pop().on, true);
});

test("pause: ends on the alarm and restores the site's own level and settings", async () => {
  const w = await worker();
  const tabUrl = "https://publisher.example/article";
  await w.popup({type: "set-mode", tabId: 1, tabUrl, mode: "strict"});
  await w.popup({type: "pause-site", tabId: 1, tabUrl});
  assert.equal((await w.popup({type: "popup-state", tabId: 1, tabUrl})).resumeMode, "strict");
  w.clock.now = START + 15 * 60000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-expiry"});
  await settle();
  assert.deepEqual({...w.local.egressGuardPauses.items}, {});
  assert.equal(relaxFor(w, "publisher.example"), false);
  assert.equal(cleanOffFor(w, "publisher.example"), false);
  const state = await w.popup({type: "popup-state", tabId: 1, tabUrl});
  assert.equal(state.paused, null);
  assert.equal(state.mode, "strict", "Strict is back");
  assert.equal((await w.page({type: "guard-config"})).clean, true);
  assert.ok(sent(w, "rules-changed").pop().rules.length > 0, "open pages hide again");
});

test("pause: survives a worker restart, and one that expired while the worker slept is lifted on start", async () => {
  const until = START + 10 * 60000;
  const running = await worker({extraLocal: {egressGuardPauses: {schema: 2, scope: "top-level-psl-v2", items: {"publisher.example": until}}}});
  assert.ok(relaxFor(running, "publisher.example"), "a restarted worker keeps the pause");
  assert.equal(running.alarms.get("eg-expiry").when, until);
  assert.deepEqual([...(await running.page({type: "page-rules"})).rules], []);
  const late = await worker({extraLocal: {egressGuardPauses: {schema: 2, scope: "top-level-psl-v2", items: {"publisher.example": until}}}, now: until + 60000});
  assert.equal(relaxFor(late, "publisher.example"), false);
  assert.deepEqual({...late.local.egressGuardPauses.items}, {}, "storage cleared");
  await settle();
  assert.ok(sent(late, "rules-changed").pop().rules.length > 0, "open pages are told to hide again");
  // A stored entry longer than a pause can be (or not a site) is ignored.
  const forged = await worker({extraLocal: {egressGuardPauses: {"publisher.example": START + 24 * 3600000, "www.other.example": START + 60000}}});
  assert.equal(relaxFor(forged, "publisher.example"), false);
  assert.deepEqual({...forged.ctx.__EGBackground.pauses}, {});
});

test("pause: only the popup may start or end it; content scripts and extension pages in tabs are refused", async () => {
  const w = await worker();
  const tabUrl = "https://publisher.example/article";
  for (const msg of [{type: "pause-site", tabUrl}, {type: "resume-site", tabUrl}]) {
    assert.match((await w.page(msg)).error, /Not allowed/, `${msg.type} from a content script`);
    assert.match((await w.warning(msg)).error, /Not allowed/, `${msg.type} from the warning page`);
    assert.match((await w.unwrapPage(msg, "https://www.google.com/url?q=https://example.org/")).error, /Not allowed/, `${msg.type} from the unwrap page`);
  }
  assert.deepEqual(w.local.egressGuardPauses.items, {});
  assert.equal(relaxFor(w, "publisher.example"), false);
  assert.match((await w.popup({type: "pause-site", tabUrl: "chrome://newtab/"})).error, /web page/);
});

const stateOf = (w) => w.popup({type: "popup-state", tabId: 1, tabUrl: "https://publisher.example/article"});
const restartOptions = (w, extra = {}) => ({stored: w.local.egressGuard, extraLocal: w.local, extraSession: w.session,
  initialDynamic: w.dynamic(), initialSession: w.sessionRules(), now: w.clock.now, tabs: w.tabs, ...extra});

test("controller distinguishes saved intent from applied mode after a rejected DNR update and retries", async () => {
  const w = await worker();
  const initial = await stateOf(w);
  assert.equal(initial.policy.state, "applied");
  w.faults.dynamicUpdate = 1;
  const result = await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "strict"});
  assert.match(result.error, /dynamicUpdate/);
  const failed = await stateOf(w);
  assert.equal(failed.mode, "standard");
  assert.equal(failed.requestedMode, "strict");
  assert.equal(failed.policy.state, "degraded");
  assert.equal(w.local.egressGuardModes.sites["publisher.example"], "strict");
  assert.equal((await w.popup({type: "retry-policy"})).ok, true);
  const fixed = await stateOf(w);
  assert.equal(fixed.mode, "strict");
  assert.equal(fixed.policy.state, "applied");
  assert.equal(fixed.policy.desiredRevision, fixed.policy.appliedRevision);
  assert.equal(fixed.policy.expirySemantics, "scheduled");
});

test("a transient startup failure leaves the popup and recovery path usable", async () => {
  const w = await worker({faults: {dynamicUpdate: 1}});
  const failed = await stateOf(w);
  assert.equal(failed.policy.state, "degraded");
  assert.equal(failed.mode, "unknown");
  assert.ok(w.alarms.has("eg-reconcile"));
  await w.chrome.alarms.onAlarm.fire({name: "eg-reconcile"});
  assert.equal((await stateOf(w)).policy.state, "applied");
  assert.equal((await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "strict"})).ok, true);
});

test("failed preference storage rolls back in-memory intent and preserves applied protections", async () => {
  const w = await worker();
  w.faults.localWrite = (items) => Boolean(items.egressGuardModes);
  assert.match((await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "relaxed"})).error, /localWrite/);
  const state = await stateOf(w);
  assert.equal(state.mode, "standard");
  assert.equal(state.requestedMode, "standard");
  assert.equal(relaxFor(w, "publisher.example"), false);
});

test("journal failure after a successful session update rolls the grant back; restart removes interrupted intents", async () => {
  const w = await worker();
  w.faults.sessionWrite = (items) => items.egressGuardGrants?.phase === "applied";
  assert.match((await w.cont()).error, /sessionWrite/);
  assert.equal(w.sessionRules().length, 0, "failed bookkeeping cannot leave an untracked allow");
  assert.equal(w.session.egressGuardGrants.phase, "intent");
  const pending = w.session.egressGuardGrants.entries[0];
  const orphan = dnr.continueRules(pending.id, pending.host, pending.tabId);
  const reboot = await worker(restartOptions(w, {initialSession: orphan, tabs: [{id: 4, url: `${EXT}warning.html?list=threats#https://login.bad.example/`}]}));
  assert.equal(reboot.sessionRules().length, 0, "intent is not restored as consent");
  assert.equal((await reboot.api.continues()).length, 0);
});

test("startup reconciles actual session rules, removes unknown grants and never resurrects missing ones", async () => {
  const w = await worker();
  assert.equal((await w.cont()).ok, true);
  const tabs = [{id: 4, url: "https://login.bad.example/"}];
  const orphan = {id: 999999, priority: 999, action: {type: "allow"}, condition: {requestDomains: ["orphan.example"], resourceTypes: ["script"]}};
  const restored = await worker(restartOptions(w, {initialSession: [...w.sessionRules(), orphan], tabs}));
  assert.equal(restored.sessionRules().length, 2);
  assert.ok(!restored.sessionRules().some((r) => r.id === orphan.id));
  const missing = await worker(restartOptions(w, {initialSession: [], tabs}));
  assert.equal(missing.sessionRules().length, 0);
  assert.equal((await missing.api.continues()).length, 0);
  const expired = await worker(restartOptions(w, {now: START + 11 * 60000, tabs}));
  assert.equal(expired.sessionRules().length, 0);
});

test("threat reclassification revokes stored ordinary exceptions and rejects an embed without false success", async () => {
  const w = await worker();
  const added = await w.popup({type: "add-exception", tabId: 1, tabUrl: "https://publisher.example/", host: "newly-bad.example", path: "/image.gif", resourceType: "image", minutes: 15});
  assert.equal(added.ok, true);
  const reboot = await worker(restartOptions(w, {threats: [...THREATS, "newly-bad.example", "youtube.com"]}));
  assert.equal(reboot.local.egressGuard.exceptions.length, 0);
  assert.ok(!reboot.sessionRules().some((r) => r.priority === dnr.PRIORITY.exception));
  const refused = await reboot.page({type: "load-embed", embed: "youtube"});
  assert.match(refused.error, /refused/);
  assert.ok(!reboot.sessionRules().some((r) => r.priority === dnr.PRIORITY.embed));
});

test("clock rollback revokes temporary grants, persists the high-water mark, and reports expiry as scheduled", async () => {
  const w = await worker();
  assert.equal((await w.cont()).ok, true);
  w.clock.now += 60000;
  await w.api.sync();
  w.clock.now -= 30000;
  await w.api.sync();
  assert.equal(w.sessionRules().length, 0);
  assert.ok((await stateOf(w)).policy.warnings.some((x) => /clock moved backwards/.test(x)));
  assert.equal(w.local.egressGuardController.clockHighWater, START + 60000);
  assert.match((await w.cont()).error, /refused/);
});

test("failed session revocation is reported until actual DNR removal is confirmed", async () => {
  const w = await worker();
  await w.cont();
  w.faults.sessionUpdate = true;
  await w.chrome.tabs.onRemoved.fire(4);
  await w.api.sync().catch(() => {});
  const failed = await stateOf(w);
  assert.equal(failed.policy.state, "degraded");
  assert.equal(failed.policy.grantsPending, true);
  assert.equal(w.sessionRules().length, 2);
  w.faults.sessionUpdate = false;
  await w.popup({type: "retry-policy"});
  assert.equal(w.sessionRules().length, 0);
  assert.equal((await stateOf(w)).policy.grantsPending, false);
});

test("DNR quota preflight preserves the previous applied mode and explains refusal", async () => {
  const w = await worker();
  w.chrome.declarativeNetRequest.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES = 1;
  const result = await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "strict"});
  assert.match(result.error, /capacity/);
  assert.equal((await stateOf(w)).mode, "standard");
  assert.ok(!w.dynamic().some((r) => r.priority === dnr.PRIORITY.mode));
});

test("manual blocks require explicit removal; suffix-wide Strict allowances are refused", async () => {
  const w = await worker();
  assert.match((await w.popup({type: "add-exception", tabId: 1, tabUrl: "https://publisher.example/", host: "publisher.example", path: "/collect", resourceType: "beacon", minutes: 5})).error, /manual block/);
  for (const host of ["ca.us", "k12.ca.us", "uk.com"]) assert.match((await w.popup({type: "strict-allow", tabUrl: "https://publisher.example/", host})).error, /public suffix/);
  assert.equal(manifest.minimum_chrome_version, "145");
});

test("navigation reconciliation cannot publish a mode whose storage commit is still pending", async () => {
  const w = await worker();
  const original = w.chrome.storage.local.set;
  let rejectCommit, announced;
  const started = new Promise((resolve) => { announced = resolve; });
  w.chrome.storage.local.set = async (items) => {
    if (items.egressGuardModes?.sites?.["publisher.example"] === "relaxed") {
      announced();
      return new Promise((resolve, reject) => { rejectCommit = () => reject(new Error("commit interrupted")); });
    }
    return original(items);
  };
  const mutation = w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "relaxed"});
  await started;
  const eventReconcile = w.api.sync();
  assert.equal(relaxFor(w, "publisher.example"), false);
  rejectCommit();
  assert.match((await mutation).error, /commit interrupted/);
  await eventReconcile;
  assert.equal(relaxFor(w, "publisher.example"), false, "the event only observes the rolled-back, saved state");
  assert.equal((await stateOf(w)).mode, "standard");
});

const repair = (w, {tabId = 1, path = "/pixel.gif", minutes = 15} = {}) => w.popup({type: "add-exception", tabId,
  tabUrl: "https://publisher.example/article", host: "pixel.tracker.test", path, resourceType: "image", minutes});

test("a timed repair belongs to its source tab, never another tab showing the same site", async () => {
  const w = await worker({tabs: [{id: 1, url: "https://publisher.example/article"}, {id: 2, url: "https://publisher.example/other"}]});
  const added = await repair(w);
  assert.equal(added.ok, true, added.error);
  assert.equal(added.value.tabId, 1);
  assert.equal(w.local.egressGuard.exceptions[0].tabId, 1);
  assert.ok(w.sessionRules().length === 2 && w.sessionRules().every((r) => JSON.stringify(r.condition.tabIds) === "[1]"));
  assert.equal((await stateOf(w)).exceptions.length, 1);
  assert.equal((await w.popup({type: "popup-state", tabId: 2, tabUrl: "https://publisher.example/other"})).exceptions.length, 0);
  assert.match((await repair(w, {tabId: 88})).error, /source tab changed/);
  const other = await repair(w, {tabId: 2});
  assert.equal(other.ok, true);
  assert.equal(w.local.egressGuard.exceptions.length, 2, "the second tab needs its own explicit consent");
});

test("leaving a repair's PSL site or closing its source tab revokes it and returning cannot revive it", async () => {
  const w = await worker({tabs: [{id: 1, url: "https://publisher.example/article"}, {id: 2, url: "https://publisher.example/other"}]});
  await repair(w);
  w.tabs[0].url = "https://different.example/";
  await w.chrome.tabs.onUpdated.fire(1, {url: w.tabs[0].url}, w.tabs[0]);
  await w.api.sync();
  assert.equal(w.sessionRules().length, 0);
  assert.equal(w.local.egressGuard.exceptions.length, 0);
  w.tabs[0].url = "https://publisher.example/article";
  await w.chrome.tabs.onUpdated.fire(1, {url: w.tabs[0].url}, w.tabs[0]);
  await w.api.sync();
  assert.equal(w.sessionRules().length, 0);
  assert.equal((await repair(w)).ok, true);
  w.tabs.splice(0, 1);
  await w.chrome.tabs.onRemoved.fire(1);
  await w.api.sync();
  assert.equal(w.sessionRules().length, 0);
  assert.deepEqual(w.session.egressGuardGrants.endpoints, []);
});

test("timed endpoint repairs restore only from matching applied journals and complete actual DNR pairs", async () => {
  const w = await worker();
  await repair(w);
  const complete = await worker(restartOptions(w));
  assert.equal(complete.sessionRules().length, 2, "worker restart preserves an actual, journaled source-tab permission");
  assert.equal(complete.local.egressGuard.exceptions.length, 1);
  const missingHeader = await worker(restartOptions(w, {initialSession: w.sessionRules().filter((r) => r.action.type === "allow")}));
  assert.equal(missingHeader.sessionRules().length, 0);
  assert.equal(missingHeader.local.egressGuard.exceptions.length, 0, "missing sanitation invalidates the whole permission");
  const missingAllow = await worker(restartOptions(w, {initialSession: w.sessionRules().filter((r) => r.action.type === "modifyHeaders")}));
  assert.equal(missingAllow.sessionRules().length, 0);
  const freshBrowser = await worker(restartOptions(w, {extraSession: {}, initialSession: []}));
  assert.equal(freshBrowser.sessionRules().length, 0);
  assert.equal(freshBrowser.local.egressGuard.exceptions.length, 0, "local storage alone cannot regenerate a timed permission");
  const absentJournal = await worker(restartOptions(w, {extraSession: {}}));
  assert.equal(absentJournal.sessionRules().length, 0, "untracked actual rules are removed");
  const moved = await worker(restartOptions(w, {tabs: [{id: 2, url: "https://publisher.example/article"}]}));
  assert.equal(moved.sessionRules().length, 0, "same site in a different tab is not the original consent");
});

test("endpoint rule identities remain stable when an earlier permission expires", async () => {
  const w = await worker();
  await repair(w, {path: "/short.gif", minutes: 1});
  const long = await repair(w, {path: "/long.gif", minutes: 15});
  const id = w.session.egressGuardGrants.endpoints.find((g) => g.id === long.value.id).ruleId;
  const reboot = await worker(restartOptions(w, {now: START + 61000}));
  assert.equal(reboot.local.egressGuard.exceptions.length, 1);
  assert.equal(reboot.local.egressGuard.exceptions[0].path, "/long.gif");
  assert.deepEqual(reboot.sessionRules().map((r) => r.id), [id, id + 1]);
});

test("a failed local deletion cannot resurrect a revoked timed permission on restart", async () => {
  const w = await worker();
  const granted = await repair(w);
  w.faults.localWrite = (items) => Boolean(items.egressGuard);
  const removed = await w.popup({type: "remove-exception", id: granted.value.id});
  assert.equal(removed.ok, true, removed.error);
  assert.equal(w.sessionRules().length, 0);
  assert.equal(w.local.egressGuard.exceptions.length, 1, "test keeps the stale local record deliberately");
  assert.deepEqual(w.session.egressGuardGrants.endpoints, []);
  const reboot = await worker(restartOptions(w));
  assert.equal(reboot.sessionRules().length, 0);
  assert.equal(reboot.local.egressGuard.exceptions.length, 0);
});

const strictModes = () => ({schema: 2, scope: "top-level-psl-v2", psl: hosts.psl.sha256, defaultMode: "strict", sites: {}, allowHosts: {}, cleanOff: []});
// Small independent condition model for mode-policy script blocks, not a browser.
function scriptBlockedByMode(all, top, destination = top) {
  const covers = (list, host) => list.some((domain) => hosts.withinScope(host, domain));
  return all.some((rule) => {
    const c = rule.condition;
    return rule.action.type === "block" && rule.priority === dnr.PRIORITY.mode && c.resourceTypes.includes("script") &&
      (!c.topDomains || covers(c.topDomains, top)) && (!c.excludedTopDomains || !covers(c.excludedTopDomains, top)) &&
      (!c.requestDomains || covers(c.requestDomains, destination)) && (!c.excludedRequestDomains || !covers(c.excludedRequestDomains, destination));
  });
}

test("Strict starts with a closed unknown-top hold and releases a prewarmed site only in the full atomic policy", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  const target = "new.example", targetUrl = `https://${target}/first?private=query`;
  assert.equal(scriptBlockedByMode(w.dynamic(), target), true);
  assert.equal(scriptBlockedByMode(w.dynamic(), "publisher.example"), false);
  const before = await w.popup({type: "popup-state", tabId: 2, tabUrl: targetUrl});
  assert.equal(before.preparation.state, "held");
  assert.equal(before.policy.topPartyCoverage, "closed-until-prepared");
  const calls = w.dynamicUpdates.length;
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 1, tabId: 2, url: targetUrl});
  assert.equal(w.dynamicUpdates.length, calls, "a foreign child frame cannot prepare its own policy context");
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 2, url: targetUrl});
  assert.equal(w.dynamicUpdates.length, calls + 1, "one atomic replacement, never an intermediate allow");
  const replacement = w.dynamicUpdates.at(-1).addRules;
  assert.equal(scriptBlockedByMode(replacement, target), false);
  assert.equal(scriptBlockedByMode(replacement, target, "foreign-frame.example"), true, "the named cross-top deny is in the same replacement as the hold exclusion");
  assert.equal(scriptBlockedByMode(replacement, "still-unseen.example"), true);
  assert.equal(replacement.some((r) => ["allow", "allowAllRequests"].includes(r.action.type)), false);
  const state = await w.popup({type: "popup-state", tabId: 2, tabUrl: targetUrl});
  assert.equal(state.preparation.state, "prepared");
  assert.equal(state.preparation.revision, state.policy.dynamicRevision);
  assert.equal(JSON.stringify(w.local.egressGuardController).includes("private=query"), false, "only site names enter the policy receipt");
  assert.deepEqual(w.reloads, [], "no automatic extension or page reload");
});

test("preparation failure retains the old hold; confirmed dynamic policy remains distinct from failed bookkeeping", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  const old = JSON.stringify(w.dynamic());
  w.faults.dynamicUpdate = true;
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 2, url: "https://unready.example/"});
  assert.equal(JSON.stringify(w.dynamic()), old);
  let state = await w.popup({type: "popup-state", tabId: 2, tabUrl: "https://unready.example/"});
  assert.equal(state.policy.state, "degraded");
  assert.equal(state.preparation.state, "held");
  w.faults.dynamicUpdate = false;
  assert.equal((await w.popup({type: "retry-policy"})).ok, true);
  state = await w.popup({type: "popup-state", tabId: 2, tabUrl: "https://unready.example/"});
  assert.equal(state.preparation.state, "prepared");
  w.faults.localWrite = (items) => Boolean(items.egressGuardController);
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 3, url: "https://confirmed.example/"});
  state = await w.popup({type: "popup-state", tabId: 3, tabUrl: "https://confirmed.example/"});
  assert.equal(state.policy.state, "degraded");
  assert.equal(state.policy.appliedRevision, null);
  assert.equal(state.preparation.state, "prepared", "the independently read-back dynamic rules are known even if the final local receipt cannot be written");
  assert.equal(scriptBlockedByMode(w.dynamic(), "confirmed.example"), false);
});

test("failed dynamic readback invalidates the previous preparation receipt until recovery", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  let reads = 0;
  w.faults.dynamicRead = () => ++reads === 2;
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 2, url: "https://unverified.example/"});
  const unknown = await w.popup({type: "popup-state", tabId: 2, tabUrl: "https://unverified.example/"});
  assert.equal(unknown.policy.state, "degraded");
  assert.equal(unknown.policy.dynamicRevision, null);
  assert.equal(unknown.policy.topPartyCoverage, "unknown");
  assert.equal(unknown.preparation.state, "unknown");
  assert.equal(unknown.mode, "unknown", "old policy is not reported as current after a successful mutation with failed readback");
  w.faults.dynamicRead = false;
  await w.popup({type: "retry-policy"});
  assert.equal((await w.popup({type: "popup-state", tabId: 2, tabUrl: "https://unverified.example/"})).preparation.state, "prepared");
});

test("closing the last active context drops automatic preparation and removes its site from the receipt", async () => {
  const tabs = [{id: 1, url: "https://open.example/"}, {id: 2, url: "https://open.example/second"}, {id: 3, url: "https://closed.example/"}];
  const w = await worker({stored: null, tabs, extraLocal: {egressGuardModes: strictModes()}});
  assert.equal(scriptBlockedByMode(w.dynamic(), "closed.example"), false);
  w.tabs.pop();
  await w.chrome.tabs.onRemoved.fire(3);
  await w.api.sync();
  assert.equal(scriptBlockedByMode(w.dynamic(), "closed.example"), true);
  assert.equal(JSON.stringify(w.local.egressGuardController).includes("closed.example"), false);
  w.tabs.shift();
  await w.chrome.tabs.onRemoved.fire(1);
  await w.api.sync();
  assert.equal(scriptBlockedByMode(w.dynamic(), "open.example"), false, "another active tab still needs the site policy");
  w.tabs.pop();
  await w.chrome.tabs.onRemoved.fire(2);
  await w.api.sync();
  assert.equal(scriptBlockedByMode(w.dynamic(), "open.example"), true);
  assert.deepEqual(w.local.egressGuardController.topSites, []);
  assert.deepEqual(w.local.egressGuardController.preparedSites, []);
  assert.equal(w.local.egressGuardController.preparedCache, undefined, "no inactive visit-history cache is stored");
});

test("prewarm candidates expire and never revive from a local receipt after worker restart", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 91, url: "https://prerender.example/"});
  assert.equal(scriptBlockedByMode(w.dynamic(), "prerender.example"), false);
  assert.equal(w.alarms.get("eg-expiry").when, START + 60000);
  const restarted = await worker(restartOptions(w));
  assert.equal(scriptBlockedByMode(restarted.dynamic(), "prerender.example"), true, "matching actual rules and a matching local digest still do not restore an inactive context");
  assert.equal(JSON.stringify(restarted.local.egressGuardController).includes("prerender.example"), false);
  const changedEpoch = JSON.parse(JSON.stringify(w.local));
  changedEpoch.egressGuardController.epoch = "previous-build";
  const upgraded = await worker(restartOptions(w, {extraLocal: changedEpoch}));
  assert.equal(scriptBlockedByMode(upgraded.dynamic(), "prerender.example"), true);
  w.clock.now = START + 61000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-expiry"});
  assert.equal(scriptBlockedByMode(w.dynamic(), "prerender.example"), true, "scheduled pruning reinstates the hold");
  assert.equal(scriptBlockedByMode(w.dynamic(), "publisher.example"), false, "current tabs remain prepared");
  assert.equal(JSON.stringify(w.local.egressGuardController).includes("prerender.example"), false);
});

test("navigation prewarming is bounded and tab-bound, including replacement targets and closed prerenders", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  for (let i = 0; i < 129; i++) await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 1000 + i, url: `https://pending${i}.example/`});
  assert.equal(w.local.egressGuardController.topSites.length, 129, "one active site plus at most 128 transient contexts");
  assert.equal(scriptBlockedByMode(w.dynamic(), "pending0.example"), true, "oldest pending context loses its automatic preparation");
  assert.equal(scriptBlockedByMode(w.dynamic(), "pending128.example"), false);
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 1128, url: "https://replacement.example/"});
  assert.equal(scriptBlockedByMode(w.dynamic(), "pending128.example"), true, "one tab cannot accumulate a history of redirect targets");
  assert.equal(scriptBlockedByMode(w.dynamic(), "replacement.example"), false);
  await w.chrome.tabs.onRemoved.fire(1128);
  await w.api.sync();
  assert.equal(scriptBlockedByMode(w.dynamic(), "replacement.example"), true);
  assert.equal(JSON.stringify(w.local.egressGuardController).includes("replacement.example"), false);
});

test("manual preparation accepts only the popup and the source tab's unchanged URL; it never reloads a page", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  w.tabs[0].url = "https://next.example/form-result";
  const request = {type: "prepare-strict-site", tabId: 1, tabUrl: w.tabs[0].url};
  assert.match((await w.page(request)).error, /Not allowed/);
  assert.match((await w.popup({...request, tabUrl: "https://publisher.example/article"})).error, /tab changed/);
  assert.match((await w.popup({...request, tabId: 100})).error, /tab changed/);
  assert.equal(scriptBlockedByMode(w.dynamic(), "next.example"), true);
  const answer = await w.popup(request);
  assert.equal(answer.ok, true, answer.error);
  assert.equal(answer.preparation.state, "prepared");
  assert.deepEqual(w.reloads, []);
  assert.equal(w.tabs[0].url, request.tabUrl);
  assert.equal(w.tabMessages.some(({msg}) => /reload|replay|resume/.test(msg.type)), false);
});

test("a wildcard registry base stays held without a false prepared receipt for its parent site", async () => {
  const url = "https://af-south-1.airflow.amazonaws.com/";
  const w = await worker({stored: null, tabs: [{id: 1, url}], extraLocal: {egressGuardModes: strictModes()}});
  const state = await w.popup({type: "popup-state", tabId: 1, tabUrl: url});
  assert.equal(state.site, "amazonaws.com");
  assert.equal(state.preparation.state, "held");
  assert.equal(state.preparation.canPrepare, false);
  assert.match(state.preparation.reason, /wildcard-registry/);
  assert.equal(scriptBlockedByMode(w.dynamic(), new URL(url).hostname), true);
  const count = w.dynamicUpdates.length;
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 1, url});
  assert.equal(w.dynamicUpdates.length, count, "no useless prewarm/retry loop for an unrepresentable host");
  assert.match((await w.popup({type: "prepare-strict-site", tabId: 1, tabUrl: url})).error, /cannot be prepared safely/);
});

test("unscopable local HTTP addresses report their Strict hold and never enter permissive domain exclusions", async () => {
  for (const url of ["http://127.0.0.1:8765/", "http://[::1]:8765/", "http://localhost:8765/", "http://intranet/"]) {
    const w = await worker({stored: null, tabs: [{id: 1, url}], extraLocal: {egressGuardModes: strictModes()}});
    const state = await w.popup({type: "popup-state", tabId: 1, tabUrl: url});
    assert.equal(state.site, null);
    assert.equal(state.defaultMode, "strict");
    assert.equal(state.preparation.state, "held", url);
    assert.equal(state.preparation.canPrepare, false);
    assert.match(state.preparation.reason, /IP addresses and single-label/);
    const refused = await w.popup({type: "prepare-strict-site", tabId: 1, tabUrl: url});
    assert.ok(refused.error);
    assert.equal(refused.preparation.state, "held");
    assert.equal(w.dynamic().some((r) => r.condition.excludedTopDomains), false, "no ad-hoc IP or localhost exemption is introduced");
    assert.equal((await w.popup({type: "popup-state", tabId: 1, tabUrl: "chrome://settings/"})).preparation.state, "not-applicable");
  }
});

test("prewarming keeps current source-tab grants scoped and leaves Standard policy unchanged", async () => {
  const standard = await worker({stored: null});
  await standard.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 2, url: "https://new.example/"});
  assert.deepEqual(standard.dynamic(), []);
  assert.equal((await standard.popup({type: "popup-state", tabId: 2, tabUrl: "https://new.example/"})).preparation.state, "not-applicable");
  const strict = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  await repair(strict);
  const original = JSON.stringify(strict.sessionRules());
  await strict.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 1, url: "https://next.example/"});
  assert.equal(JSON.stringify(strict.sessionRules()), original, "a speculative target never widens or transfers existing grants");
  for (const rule of strict.sessionRules()) {
    assert.deepEqual(rule.condition.tabIds, [1]);
    assert.deepEqual(rule.condition.topDomains, ["publisher.example"]);
  }
});

test("privacy controls authenticate the exact top-level settings page and remain usable while DNR is stalled", async () => {
  const w = await worker({stored: null});
  const request = {type: "browser-privacy-apply", selected: ["webrtc"]};
  for (const sender of [
    {url: `${EXT}popup.html`, frameId: 0},
    {url: `${EXT}privacy.html`, frameId: 1},
    {url: `${EXT}privacy.html?forged`, frameId: 0},
    {url: "https://publisher.example/", frameId: 0, tab: {id: 1}},
    {id: "foreign-extension", url: `${EXT}privacy.html`, frameId: 0},
  ]) assert.match((await w.send(request, sender)).error, /only from their settings page/);
  assert.equal(w.local.egressGuardBrowserPrivacy, undefined);
  const originalRead = w.chrome.declarativeNetRequest.getDynamicRules;
  let release;
  const stalled = new Promise((resolve) => { release = resolve; });
  w.chrome.declarativeNetRequest.getDynamicRules = async () => { await stalled; return originalRead(); };
  const changing = w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "strict"});
  await settle();
  let timeout;
  try {
    const reply = await Promise.race([
      w.send(request, {url: `${EXT}privacy.html`, frameId: 0}),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("Privacy recovery was blocked behind DNR")), 1000); }),
    ]);
    assert.equal(reply.schema, 1);
    assert.equal(reply.permission, false, "no profile or permission changes are made by the test");
    assert.deepEqual(w.local.egressGuardBrowserPrivacy.selected, ["webrtc"]);
  } finally { clearTimeout(timeout); release(); await changing; }
});

test("same-document URL changes notify content to re-read its own location without transmitting a URL", async () => {
  const w = await worker({stored: null});
  await w.chrome.tabs.onUpdated.fire(1, {url: "https://publisher.example/new-path?private=value"}, w.tabs[0]);
  assert.ok(w.tabMessages.some((entry) => entry.tabId === 1 && JSON.stringify(entry.msg) === '{"type":"page-location"}'));
});

async function stallReconciliationRead(w) {
  const read = w.chrome.declarativeNetRequest.getDynamicRules;
  let release, entered;
  const gate = new Promise((resolve) => { release = resolve; });
  const started = new Promise((resolve) => { entered = resolve; });
  let first = true;
  w.chrome.declarativeNetRequest.getDynamicRules = async () => {
    if (first) { first = false; entered(); await gate; }
    return read();
  };
  const running = w.api.sync();
  await started;
  return {release, running};
}

test("queued tab retirement defeats a navigation prewarm already waiting behind a stalled reconciliation", async () => {
  const w = await worker({stored: null, tabs: [{id: 1, url: "https://publisher.example/"}, {id: 71, url: "about:blank"}], extraLocal: {egressGuardModes: strictModes()}});
  const stall = await stallReconciliationRead(w);
  const pending = w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 71, url: "https://closed-before-prepare.example/"});
  w.tabs.pop();
  const retired = w.chrome.tabs.onRemoved.fire(71);
  stall.release();
  await Promise.all([stall.running, pending, retired]);
  assert.equal(scriptBlockedByMode(w.dynamic(), "closed-before-prepare.example"), true);
  assert.equal(w.local.egressGuardController.preparedSites.includes("closed-before-prepare.example"), false);
  assert.deepEqual(w.local.egressGuardController.topSites, ["publisher.example"]);
  assert.equal(w.alarms.has("eg-expiry"), false, "the retired prewarm does not receive a fresh expiry window");
});

test("queued tab retirement defeats a pending content sender and cannot resurrect its site after expiry", async () => {
  const closedUrl = "https://closed-sender.example/private/path";
  const w = await worker({stored: null, tabs: [{id: 1, url: "https://publisher.example/"}, {id: 71, url: closedUrl}], extraLocal: {egressGuardModes: strictModes()}});
  const stall = await stallReconciliationRead(w);
  const message = w.page({type: "page-rules"}, closedUrl, 71);
  w.tabs.pop();
  const retired = w.chrome.tabs.onRemoved.fire(71);
  stall.release();
  await Promise.all([stall.running, message, retired]);
  assert.equal(scriptBlockedByMode(w.dynamic(), "closed-sender.example"), true);
  assert.deepEqual(w.local.egressGuardController.topSites, ["publisher.example"]);
  w.clock.now += 60 * 60 * 1000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-reconcile"});
  assert.equal(JSON.stringify(w.local.egressGuardController).includes("closed-sender.example"), false, "the absent-tab fallback cannot retain an old queued sender indefinitely");
  assert.deepEqual(w.local.egressGuardController.preparedSites, ["publisher.example"]);
});

test("tab replacement retires the old sender, prewarm and grants without relying on onRemoved", async () => {
  const w = await worker({stored: null, extraLocal: {egressGuardModes: strictModes()}});
  await w.page({type: "page-rules"});
  await repair(w);
  await w.chrome.webNavigation.onBeforeNavigate.fire({frameId: 0, tabId: 1, url: "https://retired-prewarm.example/"});
  assert.equal(w.sessionRules().length, 2);
  w.tabs.splice(0, w.tabs.length, {id: 2, url: "https://replacement.example/"});
  await w.chrome.webNavigation.onTabReplaced.fire({replacedTabId: 1, tabId: 2});
  assert.deepEqual(w.local.egressGuardController.topSites, ["replacement.example"]);
  assert.deepEqual(w.local.egressGuardController.preparedSites, ["replacement.example"]);
  assert.equal(scriptBlockedByMode(w.dynamic(), "publisher.example"), true);
  assert.equal(scriptBlockedByMode(w.dynamic(), "retired-prewarm.example"), true);
  assert.equal(scriptBlockedByMode(w.dynamic(), "replacement.example"), false);
  assert.equal(w.sessionRules().length, 0);
  assert.deepEqual(w.local.egressGuard.exceptions, []);
});

test("Isolation activation removes cross-site repairs and a prior pause before the named policy is applied", async () => {
  const w = await worker({stored: null});
  const tabUrl = "https://publisher.example/article";
  const cross = await w.popup({type: "add-exception", tabId: 1, tabUrl, host: "collector.example", path: "/resource", resourceType: "image", minutes: 5});
  const own = await w.popup({type: "add-exception", tabId: 1, tabUrl, host: "publisher.example", path: "/resource", resourceType: "image", minutes: 5});
  assert.ok(cross.ok && own.ok);
  assert.equal((await w.page({type: "load-embed", embed: "youtube", cookies: true})).ok, true);
  assert.equal((await w.popup({type: "strict-allow", tabUrl, host: "collector.example"})).ok, true);
  const persistent = await w.api.store.addRule({kind: "request", site: "publisher.example", host: "collector.example", path: "/resource", types: ["image"], action: "allow"});
  const timedAllow = await w.api.store.addRule({kind: "request", site: "publisher.example", host: "collector.example", path: "/temporary", types: ["image"], action: "allow", expiresAt: START + 5 * 60000});
  assert.equal((await w.popup({type: "pause-site", tabUrl})).ok, true);
  const commits = [], sessionsBeforeIsolation = [];
  w.faults.localWrite = (items) => { if (items.egressGuardModes?.sites?.["publisher.example"] === "isolated") commits.push(JSON.parse(JSON.stringify(items))); return false; };
  const update = w.chrome.declarativeNetRequest.updateDynamicRules;
  w.chrome.declarativeNetRequest.updateDynamicRules = async (change) => {
    if (change.addRules?.some((r) => r.priority === dnr.PRIORITY.isolation)) sessionsBeforeIsolation.push(JSON.parse(JSON.stringify(w.sessionRules())));
    return update(change);
  };
  const result = await w.popup({type: "set-mode", tabUrl, mode: "isolated"});
  assert.equal(result.ok, true, result.error);
  assert.equal(result.cleared, null, "Isolation does not delete application or cache storage");
  assert.equal(w.browsingCalls.length, 0);
  assert.equal(w.reloads.length, 0, "no automatic reload or replay");
  assert.equal(commits.length, 1);
  assert.deepEqual(commits[0].egressGuardPauses.items, {}, "mode and pause removal share one saved-intent write");
  assert.equal(sessionsBeforeIsolation.length, 1);
  assert.ok(!sessionsBeforeIsolation[0].some((r) => r.priority === dnr.PRIORITY.exception && r.condition.requestDomains.includes("collector.example")));
  assert.ok(!sessionsBeforeIsolation[0].some((r) => [dnr.PRIORITY.embed, dnr.PRIORITY.embedCookies].includes(r.priority)));
  assert.deepEqual(w.local.egressGuard.exceptions.map((e) => e.id), [own.value.id], "same-site repair remains sanitized and source-tab bound");
  assert.ok(w.local.egressGuard.rules.some((r) => r.id === persistent.id), "persistent explicit intent is retained below the isolation block tier");
  assert.ok(!w.local.egressGuard.rules.some((r) => r.id === timedAllow.id), "expiring saved allows are temporary resource permissions and are revoked too");
  assert.ok(w.dynamic().some((r) => r.priority === dnr.PRIORITY.isolation));
  assert.equal(relaxFor(w, "publisher.example"), false);
  const state = await stateOf(w);
  assert.equal(state.mode, "isolated");
  assert.equal(state.paused, null);
  assert.equal(state.isolation.state, "applied");
  assert.equal(state.isolation.active, true);
  assert.equal(state.isolation.revision, state.policy.dynamicRevision);
  assert.equal(state.isolation.existingConnections, "not-revoked");
  assert.equal(state.isolation.reloadNeeded, true);
  assert.deepEqual(state.isolation.httpHeaders, ["cookie", "authorization", "referer", "x-posthog-distinct-id", "x-posthog-session-id", "x-posthog-window-id", "set-cookie"]);
  assert.equal((await w.page({type: "guard-config"})).mode, "isolated");
});

test("Isolation rejects cross-site repairs and Pause; only an explicit site-mode change relaxes it", async () => {
  const w = await worker({stored: null});
  const tabUrl = "https://publisher.example/article";
  assert.match((await w.page({type: "set-mode", tabUrl, mode: "isolated"})).error, /Not allowed/);
  assert.equal((await w.popup({type: "set-mode", tabUrl, mode: "isolated"})).ok, true);
  for (const msg of [
    {type: "add-exception", tabId: 1, tabUrl, host: "collector.example", path: "/resource", resourceType: "image", minutes: 5},
    {type: "strict-allow", tabUrl, host: "cdn.jsdelivr.net"},
    {type: "pause-site", tabUrl},
  ]) assert.match((await w.popup(msg)).error, /Isolation.*explicitly/, msg.type);
  for (const cookies of [false, true]) assert.match((await w.page({type: "load-embed", embed: "youtube", cookies})).error, /Isolation.*explicitly/);
  assert.equal(w.sessionRules().length, 0);
  assert.equal((await w.popup({type: "set-default-mode", mode: "strict"})).ok, true);
  assert.equal((await stateOf(w)).mode, "isolated", "a default change does not replace an explicit site mode");
  assert.equal((await w.popup({type: "resume-site", tabUrl})).ok, true);
  assert.equal((await stateOf(w)).mode, "isolated");
  assert.equal((await w.popup({type: "set-mode", tabUrl, mode: "standard"})).ok, true);
  assert.equal((await stateOf(w)).isolation, null);
  assert.equal((await w.popup({type: "pause-site", tabUrl})).ok, true, "Pause becomes available after the user changes the site mode");
});

test("Isolation intent and old pause roll back together when preference storage fails", async () => {
  const w = await worker({stored: null});
  const tabUrl = "https://publisher.example/article";
  await w.popup({type: "pause-site", tabUrl});
  const oldRules = JSON.stringify(w.dynamic());
  w.faults.localWrite = (items) => items.egressGuardModes?.sites?.["publisher.example"] === "isolated";
  assert.match((await w.popup({type: "set-mode", tabUrl, mode: "isolated"})).error, /localWrite/);
  const state = await stateOf(w);
  assert.equal(state.requestedMode, "standard");
  assert.equal(state.mode, "relaxed");
  assert.equal(state.isolation, null);
  assert.equal(state.paused, START + 15 * 60000);
  assert.equal(JSON.stringify(w.dynamic()), oldRules, "no unsaved mode reaches Chrome");
  assert.equal(w.local.egressGuardPauses.items["publisher.example"], START + 15 * 60000);
});

test("Isolation receipts distinguish rejected activation, retained applied protection and failed readback", async () => {
  const w = await worker({stored: null});
  const tabUrl = "https://publisher.example/article";
  w.faults.dynamicUpdate = 1;
  assert.match((await w.popup({type: "set-mode", tabUrl, mode: "isolated"})).error, /dynamicUpdate/);
  let state = await stateOf(w);
  assert.equal(state.mode, "standard");
  assert.equal(state.requestedMode, "isolated");
  assert.equal(state.isolation.state, "degraded");
  assert.equal(state.isolation.active, false);
  assert.equal(state.isolation.revision, null);
  assert.match((await w.popup({type: "pause-site", tabUrl})).error, /cannot be paused/);
  assert.equal((await w.popup({type: "retry-policy"})).ok, true);
  state = await stateOf(w);
  assert.equal(state.isolation.state, "applied");
  assert.equal(state.isolation.active, true);
  w.faults.dynamicUpdate = 1;
  assert.match((await w.popup({type: "set-mode", tabUrl, mode: "standard"})).error, /dynamicUpdate/);
  state = await stateOf(w);
  assert.equal(state.requestedMode, "standard");
  assert.equal(state.mode, "isolated");
  assert.equal(state.isolation.state, "degraded");
  assert.equal(state.isolation.active, true, "confirmed old policy remains active after a rejected relaxation");
  assert.match((await w.popup({type: "pause-site", tabUrl})).error, /cannot be paused/);
  assert.equal((await w.popup({type: "retry-policy"})).ok, true);
  assert.equal((await stateOf(w)).isolation, null);

  let reads = 0;
  w.faults.dynamicRead = () => ++reads === 2;
  assert.match((await w.popup({type: "set-mode", tabUrl, mode: "isolated"})).error, /dynamicRead/);
  state = await stateOf(w);
  assert.equal(state.mode, "unknown");
  assert.equal(state.isolation.active, false, "installed but unread rules cannot attest active protection");
  assert.equal(state.isolation.revision, null);
  w.faults.dynamicRead = false;
  w.faults.localWrite = (items) => Boolean(items.egressGuardController);
  assert.match((await w.popup({type: "retry-policy"})).error, /localWrite/);
  state = await stateOf(w);
  assert.equal(state.isolation.state, "degraded");
  assert.equal(state.isolation.active, true, "independent dynamic readback is known despite failed final bookkeeping");
  assert.equal(state.policy.appliedRevision, null);
  assert.equal(state.isolation.revision, state.policy.dynamicRevision);
});

test("Isolation capacity refusal preserves old policy and does not install a reduced fallback", async () => {
  const w = await worker({stored: null});
  const old = JSON.stringify(w.dynamic());
  w.chrome.declarativeNetRequest.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES = 1;
  assert.match((await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "isolated"})).error, /capacity/);
  const state = await stateOf(w);
  assert.equal(state.mode, "standard");
  assert.equal(state.isolation.state, "degraded");
  assert.equal(state.isolation.active, false);
  assert.equal(JSON.stringify(w.dynamic()), old);
});

test("Isolation survives conservative scope migration and defeats stale paused/granted state on restart", async () => {
  const first = await worker({stored: null});
  const tabUrl = "https://publisher.example/article";
  assert.equal((await first.popup({type: "add-exception", tabId: 1, tabUrl, host: "collector.example", path: "/resource", resourceType: "image", minutes: 5})).ok, true);
  assert.equal((await first.page({type: "load-embed", embed: "youtube", cookies: true})).ok, true);
  const revived = await worker(restartOptions(first, {extraLocal: {...first.local,
    egressGuardModes: {...first.local.egressGuardModes, psl: "old-psl-version", sites: {"publisher.example": "isolated", "other.example": "relaxed"}},
    egressGuardPauses: {schema: 2, scope: "top-level-psl-v2", items: {"publisher.example": START + 5 * 60000}},
  }}));
  const state = await stateOf(revived);
  assert.equal(state.mode, "isolated");
  assert.equal(state.isolation.active, true);
  assert.equal(state.paused, null);
  assert.equal(revived.local.egressGuardModes.sites["other.example"], undefined, "permissive migration remains conservative");
  assert.deepEqual(revived.local.egressGuardPauses.items, {});
  assert.deepEqual(revived.local.egressGuard.exceptions, []);
  assert.equal(revived.sessionRules().length, 0, "even matching old journal/rules cannot resurrect a cross-site repair under Isolation");
  const again = await worker(restartOptions(revived, {extraSession: {}, initialSession: []}));
  assert.equal((await stateOf(again)).isolation.active, true, "persistent Isolation does not depend on a session journal");
});

test("Isolation refuses unrepresentable addresses and never attests a parent mode on a wildcard base", async () => {
  const w = await worker({stored: null});
  for (const url of ["http://127.0.0.1:8042/", "http://localhost/", "https://kawasaki.jp/", "https://af-south-1.airflow.amazonaws.com/"]) {
    assert.ok((await w.popup({type: "set-mode", tabUrl: url, mode: "isolated"})).error, url);
  }
  assert.equal((await w.popup({type: "set-mode", tabUrl: "https://amazonaws.com/", mode: "isolated"})).ok, true);
  const unsupported = await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://af-south-1.airflow.amazonaws.com/"});
  assert.equal(unsupported.isolation.state, "unsupported");
  assert.equal(unsupported.isolation.active, false);
  assert.equal(unsupported.mode, "unknown");
  assert.match(unsupported.isolation.reason, /wildcard-registry/);
  const tenant = await w.popup({type: "popup-state", tabId: 1, tabUrl: "https://alice.s3.amazonaws.com/"});
  assert.equal(tenant.mode, "standard");
  assert.equal(tenant.isolation, null, "independent tenant is not the parent's site");
});

// ---- opt-in Client Hints: same authoritative dynamic-rule owner -----------------
const hardening = require("../../browser/core/privacy-hardening.js");
const privacyPage = (w, operation, extra = {}) => w.send({type: `browser-privacy-hardening-${operation}`, ...extra}, {url: `${EXT}privacy.html`, frameId: 0});
const hintRules = w => w.dynamic().filter(rule => hardening.ownsRuleId(rule.id));

test("Client Hints first-use status/retry is read-only, default off and does not claim browser behavior", async () => {
  const w = await worker({stored: null});
  const updates = w.dynamicUpdates.length;
  for (const operation of ["status", "retry"]) {
    const state = await privacyPage(w, operation);
    assert.equal(state.enabled, false); assert.equal(state.saved, false);
    assert.equal(state.state, "inactive"); assert.equal(state.rulesConfirmed, true);
    assert.equal(state.installed, false); assert.equal(state.behaviorVerified, false);
    assert.equal(state.experimental, true); assert.equal(state.evidence, "installed-rules-only");
    assert.equal(state.documentPolicy, "only-when-permissions-policy-is-absent");
    assert.equal(state.workerJavaScript, "not-qualified");
  }
  assert.equal(w.local[hardening.KEY], undefined);
  assert.equal(w.dynamicUpdates.length, updates);
  assert.deepEqual(hintRules(w), []);
});

test("Client Hints apply saves fixed intent before installation; normal policy reconciliation retains it", async () => {
  const w = await worker({stored: null});
  const update = w.chrome.declarativeNetRequest.updateDynamicRules;
  w.chrome.declarativeNetRequest.updateDynamicRules = async request => {
    if (request.addRules.some(rule => hardening.ownsRuleId(rule.id))) assert.equal(w.local[hardening.KEY].enabled, true);
    return update(request);
  };
  const result = await privacyPage(w, "apply", {enabled: true});
  assert.equal(result.state, "installed"); assert.equal(result.installed, true); assert.equal(result.rulesConfirmed, true);
  assert.equal(result.expectedRuleCount, 2); assert.equal(result.verifiedRuleCount, 2);
  assert.equal(result.appliedRevision, result.revision);
  assert.deepEqual(hintRules(w), hardening.compile({enabled: true}));
  assert.equal((await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "relaxed"})).ok, true);
  assert.deepEqual(hintRules(w), hardening.compile({enabled: true}), "Relaxed is not an implicit release of the profile control");
  const restarted = await worker(restartOptions(w));
  assert.equal((await privacyPage(restarted, "status")).state, "installed");
});

test("Client Hints refuses foreign/framed messages, unknown fields and non-Boolean choices without saving", async () => {
  const w = await worker({stored: null});
  const message = {type: "browser-privacy-hardening-apply", enabled: true};
  for (const sender of [
    {url: `${EXT}popup.html`, frameId: 0}, {url: `${EXT}privacy.html`, frameId: 1},
    {url: `${EXT}privacy.html?spoof`, frameId: 0}, {url: "https://publisher.example/", frameId: 0, tab: {id: 1}},
    {id: "foreign", url: `${EXT}privacy.html`, frameId: 0},
  ]) assert.match((await w.send(message, sender)).error, /only from their settings page/);
  for (const enabled of [undefined, null, "true", 1, [], {}]) assert.match((await privacyPage(w, "apply", {enabled})).error, /explicitly/);
  assert.match((await privacyPage(w, "apply", {enabled: true, priority: 999})).error, /fixed control/);
  assert.match((await privacyPage(w, "apply", {enabled: true, headers: ["cookie"]})).error, /fixed control/);
  assert.match((await privacyPage(w, "status", {enabled: true})).error, /fixed control/);
  assert.match((await privacyPage(w, "invented")).error, /Unknown/);
  assert.equal(w.local[hardening.KEY], undefined); assert.deepEqual(hintRules(w), []);
});

test("Client Hints rejected persistence cannot authorize a DNR mutation", async () => {
  const w = await worker({stored: null}); const updates = w.dynamicUpdates.length;
  w.faults.localWrite = patch => Object.hasOwn(patch, hardening.KEY);
  assert.match((await privacyPage(w, "apply", {enabled: true})).error, /localWrite/);
  assert.equal(w.local[hardening.KEY], undefined);
  assert.equal(w.dynamicUpdates.length, updates); assert.deepEqual(hintRules(w), []);
  assert.equal((await privacyPage(w, "status")).enabled, false);
});

test("Client Hints failed rule install remains pending and can recover without inventing behavior proof", async () => {
  const w = await worker({stored: null});
  w.faults.dynamicUpdate = 1;
  const result = await privacyPage(w, "apply", {enabled: true});
  assert.equal(result.enabled, true); assert.equal(result.saved, true);
  assert.equal(result.state, "pending"); assert.equal(result.rulesConfirmed, false); assert.equal(result.installed, false);
  assert.equal(result.appliedRevision, null); assert.match(result.error, /dynamicUpdate/);
  const retry = await privacyPage(w, "retry");
  assert.equal(retry.state, "installed"); assert.equal(retry.rulesConfirmed, true);
  assert.equal(retry.behaviorVerified, false);
});

test("Client Hints rejects quota exhaustion and partial or altered readback", async () => {
  const w = await worker({stored: null});
  w.chrome.declarativeNetRequest.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES = 1;
  assert.equal((await privacyPage(w, "apply", {enabled: true})).state, "pending");
  assert.deepEqual(hintRules(w), []);
  w.chrome.declarativeNetRequest.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES = 5000;
  const originalUpdate = w.chrome.declarativeNetRequest.updateDynamicRules;
  w.chrome.declarativeNetRequest.updateDynamicRules = async request => originalUpdate({...request, addRules: request.addRules.filter(rule => rule.id !== hardening.FIRST_ID + 1)});
  const partial = await privacyPage(w, "retry");
  assert.equal(partial.rulesConfirmed, false); assert.equal(partial.installed, false); assert.equal(partial.verifiedRuleCount, 1);
  assert.equal(partial.state, "pending");
  w.chrome.declarativeNetRequest.updateDynamicRules = originalUpdate;
  assert.equal((await privacyPage(w, "retry")).state, "installed");
  const originalGet = w.chrome.declarativeNetRequest.getDynamicRules;
  w.chrome.declarativeNetRequest.getDynamicRules = async () => (await originalGet()).map(rule => rule.id === hardening.FIRST_ID ? {...rule, priority: 1} : rule);
  const altered = await privacyPage(w, "status");
  assert.equal(altered.rulesConfirmed, false); assert.equal(altered.installed, false); assert.equal(altered.verifiedRuleCount, 1);
});

test("Client Hints unreadable DNR state is unknown, never an installed receipt", async () => {
  const w = await worker({stored: null}); await privacyPage(w, "apply", {enabled: true});
  w.faults.dynamicRead = true;
  const result = await privacyPage(w, "status");
  assert.equal(result.state, "degraded"); assert.equal(result.installed, null);
  assert.equal(result.rulesConfirmed, false); assert.equal(result.observedRuleCount, null); assert.equal(result.appliedRevision, null);
  w.faults.dynamicRead = false;
  assert.equal((await privacyPage(w, "status")).state, "installed");
});

test("Client Hints release preserves other policy and a failed release remains visible across restart", async () => {
  const w = await worker({stored: null});
  assert.equal((await w.popup({type: "set-mode", tabUrl: "https://publisher.example/", mode: "isolated"})).ok, true);
  await privacyPage(w, "apply", {enabled: true});
  const other = JSON.stringify(w.dynamic().filter(rule => !hardening.ownsRuleId(rule.id)));
  w.faults.dynamicUpdate = true;
  const failed = await privacyPage(w, "release");
  assert.equal(failed.enabled, false); assert.equal(failed.state, "release-pending"); assert.equal(failed.installed, true);
  assert.equal(failed.rulesConfirmed, false);
  const restarted = await worker(restartOptions(w, {faults: {dynamicUpdate: true}}));
  assert.equal((await privacyPage(restarted, "status")).state, "release-pending");
  restarted.faults.dynamicUpdate = false;
  const released = await privacyPage(restarted, "retry");
  assert.equal(released.state, "inactive"); assert.equal(released.rulesConfirmed, true); assert.deepEqual(hintRules(restarted), []);
  assert.equal(JSON.stringify(restarted.dynamic()), other);
});

test("corrupt Client Hints intent preserves installed restrictions until explicit recovery", async () => {
  const first = await worker({stored: null}); await privacyPage(first, "apply", {enabled: true});
  const bad = await worker(restartOptions(first, {extraLocal: {...first.local, [hardening.KEY]: {schema: 1, revision: 2, enabled: "yes"}}}));
  assert.deepEqual(hintRules(bad), hardening.compile({enabled: true}));
  const state = await privacyPage(bad, "status");
  assert.equal(state.state, "degraded"); assert.equal(state.rulesConfirmed, false); assert.match(state.error, /invalid/);
  assert.equal((await privacyPage(bad, "release")).state, "inactive"); assert.deepEqual(hintRules(bad), []);
});

test("concurrent Client Hints apply/release shares the policy queue and cannot resurrect the older choice", async () => {
  const w = await worker({stored: null});
  const update = w.chrome.declarativeNetRequest.updateDynamicRules;
  let release; const gate = new Promise(resolve => { release = resolve; });
  w.chrome.declarativeNetRequest.updateDynamicRules = async request => {
    if (request.addRules.some(rule => hardening.ownsRuleId(rule.id))) await gate;
    return update(request);
  };
  const enabling = privacyPage(w, "apply", {enabled: true});
  await settle();
  const releasing = privacyPage(w, "release");
  assert.equal(w.local[hardening.KEY].enabled, true);
  release(); await enabling;
  assert.equal((await releasing).state, "inactive");
  assert.equal(w.local[hardening.KEY].enabled, false); assert.deepEqual(hintRules(w), []);
});

test("a site the proxy refused gets our explanation in place of Chrome's tunnel error", async () => {
  const answers = {
    "ethn.io": {host: "ethn.io", blocked: true, layer: "proxy", source: "tracker-feed", can_allow: true, allow_file: "~/guard/allow.txt"},
    "twitter.com": {host: "twitter.com", blocked: true, layer: "dns-filter", source: null, can_allow: false},
    "fine.example": {host: "fine.example", blocked: false, layer: null, source: "no-match", can_allow: false},
  };
  const fail = (w, url, error = "net::ERR_TUNNEL_CONNECTION_FAILED", frameId = 0) =>
    w.chrome.webNavigation.onErrorOccurred.fire({tabId: 7, frameId, url, error});
  let w = await worker({why: (host) => answers[host] || {blocked: false}, tabUrl: "https://ethn.io/incentives"});
  await fail(w, "https://ethn.io/incentives");
  await settle();
  assert.equal(w.updates.length, 1);
  assert.ok(w.updates[0].url.startsWith(`${EXT}refused.html?`), w.updates[0].url);
  const shown = new URL(w.updates[0].url);
  assert.deepEqual(Object.fromEntries(shown.searchParams), {layer: "proxy", source: "tracker-feed", allow: "1", file: "~/guard/allow.txt"});
  assert.equal(shown.hash.slice(1), "https://ethn.io/incentives");
  assert.ok(w.fetched.includes("http://egress-guard.invalid/why?host=ethn.io"));

  w = await worker({why: (host) => answers[host], tabUrl: "https://twitter.com/home"});
  await fail(w, "https://twitter.com/home");
  await settle();
  assert.deepEqual(Object.fromEntries(new URL(w.updates[0].url).searchParams), {layer: "dns-filter", source: "", allow: "0"});

  // Left alone: other errors, subframes, sites the guard did not refuse, a tab that moved on, and no guard at all.
  w = await worker({why: (host) => answers[host], tabUrl: "https://fine.example/"});
  await fail(w, "https://ethn.io/x", "net::ERR_NAME_NOT_RESOLVED");
  await fail(w, "https://ethn.io/x", undefined, 3);
  await fail(w, "https://fine.example/");
  await fail(w, "https://ethn.io/x");  // the tab now shows fine.example
  await settle();
  assert.equal(w.updates.length, 0);
  w = await worker({tabUrl: "https://ethn.io/x"});
  await fail(w, "https://ethn.io/x");
  await settle();
  assert.equal(w.updates.length, 0);
});
