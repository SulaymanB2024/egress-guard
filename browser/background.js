/* Firefox adapter: wires webRequest, storage, alarms and messaging to the pure decision core.
 * Everything that decides lives in core/; this file only translates browser data. */
(function (root) {
  "use strict";
  const B = root.browser;
  const {RuleStore} = root.EGStore;
  const {decide, topLevelUrl} = root.EGDecide;
  const hosts = root.EGHosts;
  const rulesApi = root.EGRules;
  const KEY = "egressGuard";
  const MAX_LOG = 100;
  const ALARM = "eg-expiry";

  const store = new RuleStore({persist: {
    load: async () => (await B.storage.local.get(KEY))[KEY],
    save: (value) => B.storage.local.set({[KEY]: value}),
  }});
  const tabTop = new Map();   // tabId -> last main_frame URL (browser data, never page data)
  const tabLog = new Map();   // tabId -> [{host, path, type, ruleId, count}]
  let loaded = false;
  const ready = store.load().then(() => { loaded = true; for (const msg of store.rejected) console.warn("Egress Guard dropped a stored entry:", msg); return schedule(); });

  async function schedule() {
    await B.alarms.clear(ALARM);
    const next = store.nextExpiry();
    if (next !== null) B.alarms.create(ALARM, {when: Math.max(next, Date.now() + 1000)});
  }

  function onRequest(details) {
    if (details.tabId === undefined || details.tabId < 0) return {}; // browser-internal or extension requests
    if (details.type === "main_frame") { tabTop.set(details.tabId, details.url); tabLog.delete(details.tabId); return {}; }
    const topUrl = topLevelUrl(details, tabTop.get(details.tabId));
    const topHost = hosts.hostOfUrl(topUrl);
    if (!topHost) return {};
    const {requestRules, exceptions} = store.activeFor(topHost);
    if (!requestRules.length) return {};
    const result = decide({url: details.url, type: details.type, topUrl}, requestRules, exceptions, Date.now());
    if (result.action !== "block") return {};
    record(details.tabId, result);
    return {cancel: true};
  }

  function record(tabId, result) {
    const log = tabLog.get(tabId) || [];
    const {host, path, type} = result.req;
    const prior = log.find((x) => x.host === host && x.path === path && x.type === type);
    if (prior) prior.count++;
    else if (log.length < MAX_LOG) log.push({host, path, type, ruleId: result.id, count: 1});
    tabLog.set(tabId, log);
  }

  B.webRequest.onBeforeRequest.addListener(
    (details) => (loaded ? onRequest(details) : ready.then(() => onRequest(details))),
    {urls: ["http://*/*", "https://*/*"]},
    ["blocking"],
  );
  B.tabs.onRemoved.addListener((tabId) => { tabTop.delete(tabId); tabLog.delete(tabId); });
  B.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name !== ALARM) return;
    if (await store.prune()) await broadcast();
    await schedule();
  });

  const fromExtensionPage = (sender) => !sender.tab && typeof sender.url === "string" && sender.url.startsWith(B.runtime.getURL(""));
  // Content scripts run in the top frame only; their site comes from the browser's sender data.
  const senderTopHost = (sender) => (sender.tab && sender.frameId === 0 ? hosts.hostOfUrl(sender.url || sender.tab.url) : null);
  const siteScope = (host) => hosts.siteOf(host);
  const plain = (rule) => ({...rule, ...(rule.types ? {types: [...rule.types]} : {})});

  async function broadcast() {
    for (const [tabId, url] of tabTop) {
      const host = hosts.hostOfUrl(url);
      if (!host) continue;
      B.tabs.sendMessage(tabId, {type: "rules-changed", rules: store.activeFor(host).cosmeticRules.map(plain)}).catch(() => {});
    }
  }

  async function handle(message, sender) {
    await ready;
    if (!message || typeof message !== "object") return {error: "Bad message."};
    if (sender.id !== B.runtime.id) return {error: "Unknown sender."};
    const pageHost = senderTopHost(sender);
    switch (message.type) {
      case "page-rules":
        if (!pageHost) return {rules: []};
        return {site: siteScope(pageHost), rules: store.activeFor(pageHost).cosmeticRules.map(plain)};
      case "add-cosmetic": {
        if (!pageHost) return {error: "Not a page."};
        const result = await attempt(() => store.addRule({kind: "cosmetic", site: siteScope(pageHost), selector: message.selector, note: "Added with Block this element"}));
        if (!result.error) await afterChange();
        return result;
      }
      case "undo-cosmetic": {
        // A page's content script may only undo a cosmetic rule scoped to its own site.
        const rule = store.rules.find((r) => r.id === message.id);
        if (!pageHost || !rule || rule.kind !== "cosmetic" || !hosts.withinScope(pageHost, rule.site)) return {error: "No such rule."};
        await store.removeRule(rule.id); await afterChange();
        return {ok: true};
      }
    }
    if (!fromExtensionPage(sender)) return {error: "Not allowed from a page."};
    switch (message.type) {
      case "popup-state": {
        const url = tabTop.get(message.tabId) || message.tabUrl;
        const host = hosts.hostOfUrl(url);
        if (!host) return {site: null};
        const now = Date.now();
        const active = store.activeFor(host);
        return {
          host, site: siteScope(host),
          requestRules: active.requestRules.map(plain), cosmeticRules: active.cosmeticRules.map(plain),
          exceptions: active.exceptions.map((e) => ({...e, msLeft: Math.max(0, e.expiresAt - now)})),
          blocked: (tabTop.get(message.tabId) === url ? tabLog.get(message.tabId) : null) || [],
          types: rulesApi.RESOURCE_TYPES,
        };
      }
      case "add-request-rule": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        const result = await attempt(() => store.addRule({kind: "request", site: siteScope(host), host: message.host, path: message.path, types: message.types, action: "block"}));
        if (!result.error) await afterChange();
        return result;
      }
      case "remove-rule": { const ok = await store.removeRule(message.id); if (ok) await afterChange(); return {ok}; }
      case "add-exception": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        const result = await attempt(() => store.addException({site: siteScope(host), host: message.host, path: message.path, type: message.resourceType, minutes: message.minutes}));
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

  async function afterChange() { await schedule(); await broadcast(); }

  B.runtime.onMessage.addListener((message, sender) => handle(message, sender));
  root.__EGBackground = Object.freeze({store, ready, onRequest, handle, tabTop, tabLog});
})(globalThis);
