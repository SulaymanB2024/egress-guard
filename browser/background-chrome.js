/* Chrome adapter (MV3 service worker). Chrome has no blocking webRequest, so every decision is a
 * declarativeNetRequest rule: built-in lists ship as static rulesets (compiled at build time),
 * user rules and exceptions are compiled by core/dnr.js into dynamic rules, and "continue once"
 * from the warning page is a session rule. This file only translates browser data.
 * The service worker can stop at any time; anything needed later lives in chrome.storage. */
(function (root) {
  "use strict";
  const C = root.chrome;
  const {RuleStore} = root.EGStore;
  const dnr = root.EGDnr;
  const hosts = root.EGHosts;
  const rulesApi = root.EGRules;
  const LISTS = root.EGLists || {lists: {}};
  const KEY = "egressGuard";
  const ALARM = "eg-expiry";
  const MAX_LOG = 100;
  const CONTINUE_MINUTES = 10;
  const CONTINUE_BASE = 100000;   // session rule ids for "continue once"
  const EXCEPTION_MINUTES_MAX = rulesApi.MAX_EXCEPTION_MINUTES;

  const store = new RuleStore({persist: {
    load: async () => (await C.storage.local.get(KEY))[KEY],
    save: (value) => C.storage.local.set({[KEY]: value}),
  }});
  let sources = {};                 // dynamic rule id -> store id
  const ready = store.load().then(async () => {
    for (const msg of store.rejected) console.warn("Egress Guard dropped a stored entry:", msg);
    await sync();
  });

  // ---- dynamic rules --------------------------------------------------------------
  let syncing = Promise.resolve();
  function sync() {
    syncing = syncing.catch(() => {}).then(async () => {
      store.pruneSync();
      const compiled = dnr.compileUserState(store.rules, store.exceptions, Date.now());
      const existing = await C.declarativeNetRequest.getDynamicRules();
      await C.declarativeNetRequest.updateDynamicRules({removeRuleIds: existing.map((r) => r.id), addRules: compiled.rules});
      sources = compiled.sources;
      await schedule();
    });
    return syncing;
  }

  async function schedule() {
    await C.alarms.clear(ALARM);
    const times = [store.nextExpiry(), ...(await continues()).map((c) => c.expiresAt)].filter((t) => t !== null);
    if (times.length) C.alarms.create(ALARM, {when: Math.max(Math.min(...times), Date.now() + 1000)});
  }

  // ---- "continue once" session rules --------------------------------------------
  async function continues() { return (await C.storage.session.get("continues")).continues || []; }
  async function saveContinues(list) { await C.storage.session.set({continues: list}); }

  async function addContinue(host, tabId) {
    const list = (await continues()).filter((c) => !(c.host === host && c.tabId === tabId));
    const used = new Set(list.map((c) => c.id));
    let id = CONTINUE_BASE;
    while (used.has(id)) id++;
    const rule = dnr.continueRule(id, host, tabId);
    await C.declarativeNetRequest.updateSessionRules({removeRuleIds: [id], addRules: [rule]});
    list.push({id, host, tabId, expiresAt: Date.now() + CONTINUE_MINUTES * 60000});
    await saveContinues(list);
    await schedule();
    return list[list.length - 1];
  }

  async function dropContinues(test) {
    const list = await continues();
    const gone = list.filter(test);
    if (!gone.length) return;
    await C.declarativeNetRequest.updateSessionRules({removeRuleIds: gone.map((c) => c.id)});
    await saveContinues(list.filter((c) => !gone.includes(c)));
  }

  // ---- per-tab blocked log (unpacked builds report matches through onRuleMatchedDebug) ----
  const logs = new Map();           // tabId -> Promise<{items: [...]}>, mirrored to storage.session
  let flushTimer = null;
  function tabLog(tabId) {
    // Cache the promise, not the value, so concurrent matches for one tab share a single log.
    if (!logs.has(tabId)) logs.set(tabId, C.storage.session.get(`log:${tabId}`).then((r) => r[`log:${tabId}`] || {items: []}, () => ({items: []})));
    return logs.get(tabId);
  }
  function flushSoon() {
    if (flushTimer) return;
    flushTimer = setTimeout(async () => {
      flushTimer = null;
      const data = {};
      for (const [tabId, log] of logs) data[`log:${tabId}`] = await log;
      C.storage.session.set(data).catch(() => {});
    }, 200);
  }

  function listOf(rule) {
    if (rule.rulesetId === "_dynamic") return {list: "user", ruleId: sources[rule.ruleId] || null};
    if (rule.rulesetId === "_session") return null;
    return {list: rule.rulesetId};
  }

  async function onMatched(info) {
    const {request, rule} = info;
    if (!request || request.tabId === undefined || request.tabId < 0) return;
    const source = listOf(rule);
    if (!source || source.list === "params") return;
    let parsed;
    try { parsed = new URL(request.url); } catch { return; }
    const host = hosts.normalizeHost(parsed.hostname);
    if (!host) return;
    const type = request.type === "main_frame" ? "main_frame" : (dnr.CHROME_TO_CORE[request.type] || "other");
    const log = await tabLog(request.tabId);
    const path = parsed.pathname || "/";
    const prior = log.items.find((x) => x.host === host && x.path === path && x.type === type && x.list === source.list);
    if (prior) prior.count++;
    else if (log.items.length < MAX_LOG) log.items.push({host, path, type, list: source.list, ruleId: source.ruleId || null, count: 1});
    flushSoon();
  }

  async function resetTab(tabId) {
    logs.set(tabId, Promise.resolve({items: []}));
    await C.storage.session.remove(`log:${tabId}`);
  }

  // ---- events (registered synchronously so they wake the worker) ----------------
  if (C.declarativeNetRequest.onRuleMatchedDebug) C.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => { onMatched(info).catch(() => {}); });
  if (C.declarativeNetRequest.setExtensionActionOptions) C.declarativeNetRequest.setExtensionActionOptions({displayActionCountAsBadgeText: true}).catch(() => {});
  if (C.action && C.action.setBadgeBackgroundColor) C.action.setBadgeBackgroundColor({color: "#19382e"}).catch(() => {});

  C.tabs.onUpdated.addListener((tabId, info) => {
    if (info.status === "loading") resetTab(tabId).catch(() => {});
    if (typeof info.url === "string" && !info.url.startsWith(C.runtime.getURL(""))) {
      // A "continue once" exception ends when the tab leaves the host it was granted for.
      const host = hosts.hostOfUrl(info.url);
      dropContinues((c) => c.tabId === tabId && !(host && hosts.withinScope(host, c.host))).catch(() => {});
    }
  });
  C.tabs.onRemoved.addListener((tabId) => {
    logs.delete(tabId);
    C.storage.session.remove(`log:${tabId}`).catch(() => {});
    dropContinues((c) => c.tabId === tabId).catch(() => {});
  });
  C.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name !== ALARM) return;
    await ready;
    const now = Date.now();
    await dropContinues((c) => c.expiresAt <= now);
    if (await store.prune()) { await sync(); await broadcast(); } else await schedule();
  });

  // ---- messaging -------------------------------------------------------------------
  const extensionUrl = (sender, page) => typeof sender.url === "string" && sender.url.startsWith(C.runtime.getURL(page));
  // The popup normally has no tab; opened as popup.html?tab=<id> (development captures) it does.
  const fromPopup = (sender) => extensionUrl(sender, "popup.html");
  const fromWarning = (sender) => sender.tab && Number.isInteger(sender.tab.id) && extensionUrl(sender, "warning.html");
  const senderTopHost = (sender) => (sender.tab && sender.frameId === 0 && !extensionUrl(sender, "") ? hosts.hostOfUrl(sender.url || sender.tab.url) : null);
  const plain = (rule) => ({...rule, ...(rule.types ? {types: [...rule.types]} : {})});

  function broadcastTab(tabId, host) {
    C.tabs.sendMessage(tabId, {type: "rules-changed", rules: store.activeFor(host).cosmeticRules.map(plain)}).catch(() => {});
  }
  async function broadcast() {
    const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
    for (const tab of tabs) { const host = hosts.hostOfUrl(tab.url); if (host) broadcastTab(tab.id, host); }
  }

  function listsSummary() {
    return Object.entries(LISTS.lists || {}).map(([id, meta]) => ({id, ...meta}));
  }

  async function handle(message, sender) {
    await ready;
    if (!message || typeof message !== "object") return {error: "Bad message."};
    if (sender.id !== C.runtime.id) return {error: "Unknown sender."};
    const pageHost = senderTopHost(sender);
    switch (message.type) {
      case "page-rules":
        if (!pageHost) return {rules: []};
        return {site: hosts.siteOf(pageHost), rules: store.activeFor(pageHost).cosmeticRules.map(plain)};
      case "add-cosmetic": {
        if (!pageHost) return {error: "Not a page."};
        const result = await attempt(() => store.addRule({kind: "cosmetic", site: hosts.siteOf(pageHost), selector: message.selector, note: "Added with Block this element"}));
        if (!result.error) await afterChange();
        return result;
      }
      case "undo-cosmetic": {
        const rule = store.rules.find((r) => r.id === message.id);
        if (!pageHost || !rule || rule.kind !== "cosmetic" || !hosts.withinScope(pageHost, rule.site)) return {error: "No such rule."};
        await store.removeRule(rule.id); await afterChange();
        return {ok: true};
      }
      case "warning-info": {
        if (!fromWarning(sender)) return {error: "Not allowed from a page."};
        const meta = (LISTS.lists || {})[message.list] || null;
        return {list: meta, minutes: CONTINUE_MINUTES};
      }
      case "continue-once": {
        if (!fromWarning(sender)) return {error: "Not allowed from a page."};
        const target = dnr.parseWarning(sender.url);
        if (!target) return {error: "Nothing to continue to."};
        await addContinue(target.host, sender.tab.id);
        return {ok: true, url: target.url};
      }
    }
    if (!fromPopup(sender)) return {error: "Not allowed from a page."};
    switch (message.type) {
      case "popup-state": {
        const host = hosts.hostOfUrl(message.tabUrl);
        const lists = listsSummary();
        if (!host) return {site: null, lists};
        const now = Date.now();
        const active = store.activeFor(host);
        const log = Number.isInteger(message.tabId) ? await tabLog(message.tabId) : {items: []};
        return {
          host, site: hosts.siteOf(host), lists, feedback: Boolean(C.declarativeNetRequest.onRuleMatchedDebug),
          requestRules: active.requestRules.map(plain), cosmeticRules: active.cosmeticRules.map(plain),
          exceptions: active.exceptions.map((e) => ({...e, msLeft: Math.max(0, e.expiresAt - now)})),
          blocked: log.items.map((x) => ({...x})), types: rulesApi.RESOURCE_TYPES,
        };
      }
      case "add-request-rule": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        const result = await attempt(() => store.addRule({kind: "request", site: hosts.siteOf(host), host: message.host, path: message.path, types: message.types, action: "block"}));
        if (!result.error) await afterChange();
        return result;
      }
      case "remove-rule": { const ok = await store.removeRule(message.id); if (ok) await afterChange(); return {ok}; }
      case "add-exception": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        if (message.resourceType === "main_frame") return {error: "Navigations are allowed with Continue on the warning page."};
        const minutes = Math.min(message.minutes, EXCEPTION_MINUTES_MAX);
        const result = await attempt(() => store.addException({site: hosts.siteOf(host), host: message.host, path: message.path, type: message.resourceType, minutes}));
        if (!result.error) await afterChange();
        return result;
      }
      case "remove-exception": { const ok = await store.removeException(message.id); if (ok) await afterChange(); return {ok}; }
      default: return {error: "Unknown message."};
    }
  }

  async function attempt(fn) {
    try { const value = await fn(); return {ok: true, value: plain(value)}; } catch (error) {
      if (error instanceof rulesApi.RuleError) return {error: error.message};
      throw error;
    }
  }

  async function afterChange() { await sync(); await broadcast(); }

  // Chrome's onMessage needs sendResponse + `return true` for async replies.
  C.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handle(message, sender).then(sendResponse, (error) => sendResponse({error: String(error && error.message || error)}));
    return true;
  });
  root.__EGBackground = Object.freeze({store, ready, handle, sync, onMatched, tabLog, continues, get sources() { return sources; }});
})(globalThis);
