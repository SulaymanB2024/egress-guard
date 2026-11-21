"use strict";
// Chrome service-worker adapter with a fake `chrome` namespace. No real browser.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const dnr = require("../../browser/core/dnr.js");

const root = path.join(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const manifest = JSON.parse(read("browser/manifest.chrome.json"));
const fixture = JSON.parse(read("tests/browser/fixtures/publisher/rules.json"));
const ID = dnr.extensionIdFromHex(crypto.createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex"));
const EXT = `chrome-extension://${ID}/`;
const START = Date.UTC(2026, 10, 20, 12, 0, 0);
const WORKER = ["core/hosts.js", "core/selectors.js", "core/rules.js", "core/store.js", "core/dnr.js", "background-chrome.js"];
const event = () => { const fns = []; return {addListener: (fn) => fns.push(fn), fns, fire: (...a) => Promise.all(fns.map((f) => f(...a)))}; };
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(setImmediate); };

async function worker({stored = fixture} = {}) {
  const clock = {now: START};
  const local = {egressGuard: stored && JSON.parse(JSON.stringify(stored))};
  const session = {};
  const area = (obj) => ({
    get: async (key) => (typeof key === "string" ? {[key]: obj[key] && JSON.parse(JSON.stringify(obj[key]))} : {...obj}),
    set: async (items) => Object.assign(obj, JSON.parse(JSON.stringify(items))),
    remove: async (key) => { delete obj[key]; },
  });
  let dynamicRules = [], sessionRules = [];
  const alarms = new Map();
  const tabMessages = [];
  const chrome = {
    runtime: {id: ID, getURL: (p) => EXT + p, onMessage: event()},
    storage: {local: area(local), session: area(session)},
    alarms: {create: (name, info) => alarms.set(name, info), clear: async (name) => alarms.delete(name), onAlarm: event()},
    tabs: {onUpdated: event(), onRemoved: event(), sendMessage: async (tabId, msg) => { tabMessages.push({tabId, msg}); }, query: async () => [{id: 1, url: "https://publisher.example/article"}]},
    action: {setBadgeBackgroundColor: async () => {}},
    declarativeNetRequest: {
      getDynamicRules: async () => dynamicRules.map((r) => ({...r})),
      updateDynamicRules: async ({removeRuleIds = [], addRules = []}) => { dynamicRules = JSON.parse(JSON.stringify([...dynamicRules.filter((r) => !removeRuleIds.includes(r.id)), ...addRules])); },
      updateSessionRules: async ({removeRuleIds = [], addRules = []}) => { sessionRules = JSON.parse(JSON.stringify([...sessionRules.filter((r) => !removeRuleIds.includes(r.id)), ...addRules])); },
      onRuleMatchedDebug: event(),
      setExtensionActionOptions: async () => {},
    },
  };
  class FakeDate extends Date { static now() { return clock.now; } }
  const ctx = vm.createContext({chrome, console, URL, Date: FakeDate, crypto: globalThis.crypto, setTimeout, clearTimeout});
  ctx.EGLists = {lists: {trackers: {label: "Ads and trackers", name: "HaGeZi Multi PRO++", domains: 4}, threats: {label: "Malware and phishing", name: "HaGeZi Threat Intelligence (Medium)", domains: 2}}};
  for (const file of WORKER) vm.runInContext(read(`browser/${file}`), ctx, {filename: file});
  await ctx.__EGBackground.ready;
  const send = (msg, sender) => new Promise((resolve) => { assert.equal(chrome.runtime.onMessage.fns[0](msg, {id: ID, ...sender}, (r) => resolve(JSON.parse(JSON.stringify(r)))), true); });
  const popup = (msg) => send(msg, {url: `${EXT}popup.html`});
  const page = (msg, url = "https://publisher.example/article", tabId = 1) => send(msg, {url, frameId: 0, tab: {id: tabId, url}});
  const warning = (msg, blocked = "https://login.bad.example/x?y=1", tabId = 4) => {
    const url = `${EXT}warning.html?list=threats#${blocked}`;
    return send(msg, {url, frameId: 0, tab: {id: tabId, url}});
  };
  const matched = (tabId, url, type, rulesetId, ruleId = 1) => chrome.declarativeNetRequest.onRuleMatchedDebug.fire({request: {tabId, url, type}, rule: {ruleId, rulesetId}});
  return {ctx, chrome, clock, local, session, alarms, tabMessages, popup, page, warning, matched, api: ctx.__EGBackground,
    dynamic: () => dynamicRules, sessionRules: () => sessionRules};
}

test("manifest (Chrome): MV3 service worker, DNR rulesets, minimal permissions, fixed id, no remote code", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "background.js");
  assert.deepEqual([...manifest.permissions].sort(), ["alarms", "declarativeNetRequest", "declarativeNetRequestFeedback", "storage"]);
  assert.deepEqual(manifest.host_permissions, ["http://*/*", "https://*/*"]);
  assert.deepEqual(manifest.declarative_net_request.rule_resources.map((r) => r.id), ["threats", "trackers", "cname", "params"]);
  assert.ok(manifest.declarative_net_request.rule_resources.every((r) => r.enabled));
  assert.deepEqual(manifest.web_accessible_resources, [{resources: ["warning.html"], matches: ["<all_urls>"]}]);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  assert.match(manifest.content_security_policy.extension_pages, /connect-src 'none'/);
  assert.equal(ID.length, 32);
  assert.equal(manifest.content_scripts[0].all_frames, false);
  for (const file of [...WORKER, ...manifest.content_scripts[0].js, "popup.html", "warning.html"]) assert.ok(fs.existsSync(path.join(root, "browser", file)), file);
});

test("stored request rules become scoped dynamic DNR rules on start; cosmetic rules do not", async () => {
  const w = await worker();
  const rules = w.dynamic();
  assert.equal(rules.length, 1);
  assert.equal(rules[0].priority, dnr.PRIORITY.userBlock);
  assert.deepEqual(rules[0].condition.initiatorDomains, ["publisher.example"]);
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

test("acceptance (Chrome adapter): exception beats lists via a priority-7 dynamic rule and expires", async () => {
  const w = await worker();
  const tabUrl = "https://publisher.example/article";
  const exc = await w.popup({type: "add-exception", tabId: 1, tabUrl, host: "pixel.tracker.test", path: "/p.gif", resourceType: "image", minutes: 15});
  assert.equal(exc.ok, true, exc.error);
  const rule = w.dynamic().find((r) => r.priority === dnr.PRIORITY.exception);
  assert.ok(rule, "exception compiled");
  assert.equal(rule.action.type, "allow");
  assert.deepEqual(rule.condition.requestDomains, ["pixel.tracker.test"]);
  assert.deepEqual(rule.condition.initiatorDomains, ["publisher.example"]);
  assert.ok(rule.priority > dnr.PRIORITY.list && rule.priority > dnr.PRIORITY.threat);
  assert.equal(w.alarms.get("eg-expiry").when, START + 15 * 60000);
  assert.ok((await w.popup({type: "add-exception", tabId: 1, tabUrl, host: "x.test", path: "/", resourceType: "main_frame", minutes: 5})).error);
  await w.matched(1, "https://pixel.tracker.test/p.gif", "image", "_dynamic", rule.id);
  const logged = await w.popup({type: "popup-state", tabId: 1, tabUrl});
  assert.equal(logged.blocked.length, 0, "a match on an allow rule is not reported as blocked");
  w.clock.now = START + 15 * 60000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-expiry"});
  await settle();
  assert.equal(w.dynamic().some((r) => r.priority === dnr.PRIORITY.exception), false, "removed at expiry");
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
  assert.match((await w.warning({type: "continue-once"}, "javascript:alert(1)")).error, /Nothing to continue/);
  const ok = await w.warning({type: "continue-once"});
  assert.deepEqual({...ok}, {ok: true, url: "https://login.bad.example/x?y=1"});
  const [rule] = w.sessionRules();
  assert.equal(rule.action.type, "allowAllRequests");
  assert.deepEqual(rule.condition.tabIds, [4]);
  assert.deepEqual(rule.condition.requestDomains, ["login.bad.example"]);
  assert.equal(rule.priority, dnr.PRIORITY.continue);
  assert.ok(w.alarms.has("eg-expiry"), "a 10-minute cap is scheduled");
  // Moving within the host keeps it; another tab's navigation does not affect it; leaving ends it.
  await w.chrome.tabs.onUpdated.fire(4, {status: "loading", url: "https://login.bad.example/next"}, {});
  await w.chrome.tabs.onUpdated.fire(5, {status: "loading", url: "https://news.example/"}, {});
  await settle();
  assert.equal(w.sessionRules().length, 1);
  await w.chrome.tabs.onUpdated.fire(4, {status: "loading", url: "https://news.example/"}, {});
  await settle();
  assert.equal(w.sessionRules().length, 0);
  // The cap: expires even if the tab stays.
  await w.warning({type: "continue-once"});
  w.clock.now = START + 10 * 60000;
  await w.chrome.alarms.onAlarm.fire({name: "eg-expiry"});
  await settle();
  assert.equal(w.sessionRules().length, 0);
  const info = await w.warning({type: "warning-info", list: "threats"});
  assert.equal(info.list.name, "HaGeZi Threat Intelligence (Medium)");
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
