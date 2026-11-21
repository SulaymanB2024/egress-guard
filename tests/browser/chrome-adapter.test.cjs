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
const WORKER = ["core/psl-data.js", "core/hosts.js", "core/selectors.js", "core/rules.js", "core/store.js", "core/links.js", "core/params.js", "core/cookies.js", "core/dnr.js", "background-chrome.js"];
const event = () => { const fns = []; return {addListener: (fn) => fns.push(fn), fns, fire: (...a) => Promise.all(fns.map((f) => f(...a)))}; };
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(setImmediate); };

// Threat-listed names in the fake browser (the real worker asks Chrome's testMatchOutcome, or reads its own ruleset).
const THREATS = ["bad.example", "other-bad.example"];
const isListed = (host) => THREATS.some((d) => host === d || host.endsWith(`.${d}`));

async function worker({stored = fixture, packed = false, extraLocal = {}, extraSession = {}, initialDynamic = [], initialSession = [], now = START, faults = {}, threats = THREATS,
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
  const alarms = new Map();
  const tabMessages = [];
  const chrome = {
    // With use_dynamic_url, getURL returns the per-session origin; the extension's own pages still run at EXT.
    runtime: {id: ID, getURL: (p) => `chrome-extension://4f9e0c2a-dynamic-session/${p}`, onMessage: event(),
      getManifest: () => ({...manifest, ...(packed ? {update_url: "https://clients2.google.com/service/update2/crx"} : {})}), reload: () => { reloads.push(clock.now); }},
    storage: {local: area(local, "local"), session: area(session, "session")},
    alarms: {create: (name, info) => alarms.set(name, info), clear: async (name) => alarms.delete(name), get: async (name) => alarms.get(name), onAlarm: event()},
    tabs: {onUpdated: event(), onRemoved: event(), sendMessage: async (tabId, msg) => { tabMessages.push({tabId, msg}); }, query: async () => JSON.parse(JSON.stringify(tabs))},
    action: {setBadgeBackgroundColor: async () => {}},
    cookies: {onChanged: event(), remove: async (d) => { cookieCalls.push({op: "remove", ...d}); }, set: async (d) => { cookieCalls.push({op: "set", ...d}); }},
    browsingData: {remove: async (options, types) => { browsingCalls.push(JSON.parse(JSON.stringify({options, types}))); }},
    declarativeNetRequest: {
      getDynamicRules: async () => dynamicRules.map((r) => ({...r})),
      updateDynamicRules: async ({removeRuleIds = [], addRules = []}) => { fail("dynamicUpdate", {removeRuleIds, addRules}); dynamicRules = JSON.parse(JSON.stringify([...dynamicRules.filter((r) => !removeRuleIds.includes(r.id)), ...addRules])); },
      updateSessionRules: async ({removeRuleIds = [], addRules = []}) => { fail("sessionUpdate", {removeRuleIds, addRules}); sessionRules = JSON.parse(JSON.stringify([...sessionRules.filter((r) => !removeRuleIds.includes(r.id)), ...addRules])); },
      getSessionRules: async () => sessionRules.map((r) => ({...r})),
      onRuleMatchedDebug: event(),
      testMatchOutcome: async ({url, type}) => ({matchedRules: type === "main_frame" && threats.some((d) => new URL(url).hostname === d || new URL(url).hostname.endsWith(`.${d}`)) ? [{ruleId: 2, rulesetId: "threats"}] : []}),
      getMatchedRules: async ({tabId}) => ({rulesMatchedInfo: matchedInfo.filter((m) => m.tabId === tabId)}),
      setExtensionActionOptions: async () => {},
    },
  };
  const matchedInfo = [];
  const cookieCalls = [], browsingCalls = [];
  const fetched = [];
  if (packed) { delete chrome.declarativeNetRequest.onRuleMatchedDebug; delete chrome.declarativeNetRequest.testMatchOutcome; }
  // Only the worker's own packaged ruleset may be fetched (the CSP allows connect-src 'self' and nothing else).
  const disk = {build: "0".repeat(32)};
  const fetch = async (url) => {
    fetched.push(url);
    if (url === `${EXT}rules/build.json`) return {ok: true, json: async () => ({...disk})};
    if (url !== `${EXT}rules/threats.json`) throw new Error(`unexpected fetch ${url}`);
    return {ok: true, json: async () => [{id: 1, priority: 2, action: {type: "block"}, condition: {requestDomains: threats}}]};
  };
  class FakeDate extends Date { static now() { return clock.now; } }
  const ctx = vm.createContext({chrome, console, URL, Date: FakeDate, crypto: globalThis.crypto, setTimeout, clearTimeout, fetch});
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
  return {disk, reloads, ctx, chrome, clock, faults, tabs, local, session, alarms, tabMessages, popup, page, warning, cont, matched, matchedInfo, fetched, api: ctx.__EGBackground, cookieCalls, browsingCalls, unwrapPage,
    dynamic: () => dynamicRules, sessionRules: () => sessionRules};
}

test("manifest (Chrome): MV3 service worker, DNR rulesets, minimal permissions, fixed id, no remote code", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "background.js");
  // cookies: tracking cookies removed as they are set; contextMenus + offscreen + clipboardWrite: "Copy clean link".
  assert.deepEqual([...manifest.permissions].sort(), ["alarms", "browsingData", "clipboardWrite", "contextMenus", "cookies", "declarativeNetRequest", "declarativeNetRequestFeedback", "offscreen", "scripting", "storage"]);
  assert.deepEqual(manifest.host_permissions, ["http://*/*", "https://*/*"]);
  // Rulesets are written by the build (scripts/build-browser.mjs); the source manifest lists none.
  assert.deepEqual(manifest.declarative_net_request.rule_resources, []);
  // Only by a per-session URL, so a site cannot probe the fixed id to learn the extension is installed.
  assert.deepEqual(manifest.web_accessible_resources, [{resources: ["warning.html", "unwrap.html", "surrogates/*.js"], matches: ["<all_urls>"], use_dynamic_url: true}]);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  // The worker may read its own packaged files (the threat ruleset) and nothing else.
  assert.match(manifest.content_security_policy.extension_pages, /connect-src 'self'(;|$)/);
  assert.match(manifest.content_security_policy.extension_pages, /frame-ancestors 'none'/);
  assert.equal(ID.length, 32);
  // The page-world script only defines navigator.globalPrivacyControl; everything else runs isolated, top frame only.
  assert.equal(manifest.content_scripts[0].world, "MAIN");
  assert.deepEqual(manifest.content_scripts[0].js, ["page-gpc.js"]);
  assert.equal(manifest.content_scripts[1].world, undefined);
  assert.equal(manifest.content_scripts[1].all_frames, false);
  for (const file of [...WORKER, ...manifest.content_scripts[0].js, ...manifest.content_scripts[1].js, "popup.html", "warning.html", "unwrap.html"]) assert.ok(fs.existsSync(path.join(root, "browser", file)), file);
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
