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
  const MAX_PATH = 256;             // characters of a blocked request's path kept in the per-tab log
  const CONTINUE_MINUTES = 10;
  const CONTINUE_BASE = 100000;   // session rule ids for "continue once"
  // The extension's own origin. Not runtime.getURL(): with use_dynamic_url (warning.html is web-accessible only by a
  // per-session URL, so sites cannot detect the extension) getURL returns that dynamic origin, while our own pages
  // (popup, warning page after the DNR redirect) still run at the fixed-id origin.
  const OWN = `chrome-extension://${C.runtime.id}/`;
  const EXCEPTION_MINUTES_MAX = rulesApi.MAX_EXCEPTION_MINUTES;

  const store = new RuleStore({persist: {
    load: async () => (await C.storage.local.get(KEY))[KEY],
    save: (value) => C.storage.local.set({[KEY]: value}),
  }});
  let sources = {};                 // dynamic rule id -> store id
  let allowIds = new Set();         // dynamic rule ids whose action is allow
  // Sites where the built-in ad-slot hiding is switched off (popup). Only validated site names are kept.
  const GENERIC_KEY = "egressGuardGenericOff";
  const MAX_GENERIC_OFF = 500;
  let genericOff = new Set();
  async function loadGenericOff() {
    const stored = (await C.storage.local.get(GENERIC_KEY))[GENERIC_KEY];
    genericOff = new Set((Array.isArray(stored) ? stored : []).map((s) => hosts.siteOf(s)).filter(Boolean).slice(0, MAX_GENERIC_OFF));
  }
  // Site modes (Relaxed / Standard / Strict / No scripts) and the hosts allowed under Strict, per site. Validated on
  // load and on every change; compiled into dynamic rules by dnr.compileModes.
  const MODES_KEY = "egressGuardModes";
  const MAX_MODE_SITES = 2000, MAX_ALLOWED_HOSTS = 50;
  let modes = {defaultMode: "standard", sites: {}, allowHosts: {}, cleanOff: [], scannedDirect: false};
  let modeKinds = {};               // dynamic rule id -> popup category (or null)
  function cleanModes(value) {
    const out = {defaultMode: value && value.defaultMode === "strict" ? "strict" : "standard", sites: {}, allowHosts: {}, cleanOff: [], scannedDirect: false};
    // "Always open scanned links directly": off unless the user switched it on.
    out.scannedDirect = Boolean(value && value.scannedDirect === true);
    const off = value && Array.isArray(value.cleanOff) ? value.cleanOff : [];
    out.cleanOff = [...new Set(off.filter((s) => hosts.siteOf(s) === s))].slice(0, MAX_MODE_SITES).sort();
    const sites = value && typeof value.sites === "object" && value.sites ? value.sites : {};
    for (const [site, mode] of Object.entries(sites).slice(0, MAX_MODE_SITES)) {
      if (hosts.siteOf(site) === site && dnr.SITE_MODES.includes(mode)) out.sites[site] = mode;
    }
    const allow = value && typeof value.allowHosts === "object" && value.allowHosts ? value.allowHosts : {};
    for (const [site, list] of Object.entries(allow).slice(0, MAX_MODE_SITES)) {
      if (hosts.siteOf(site) !== site || !Array.isArray(list)) continue;
      const names = [...new Set(list.map((h) => hosts.normalizeHost(h)).filter(Boolean))].slice(0, MAX_ALLOWED_HOSTS).sort();
      if (names.length) out.allowHosts[site] = names;
    }
    return out;
  }
  async function loadModes() { modes = cleanModes((await C.storage.local.get(MODES_KEY))[MODES_KEY]); }
  async function saveModes() { await C.storage.local.set({[MODES_KEY]: modes}); }
  const modeFor = (site) => (site && modes.sites[site]) || modes.defaultMode;
  const cleaningOn = (site) => !(site && modes.cleanOff.includes(site));

  // ---- retired: experimental fingerprint noise ----------------------------------------------------------------
  // Removed in 0.3.1: keyed by the frame's own site, it gave third-party frames a stable cross-site value, and its key
  // was reachable by page script. Installs that had it on still hold persistent registrations; they are removed here.
  async function retireNoise() {
    if (!C.scripting || !C.scripting.getRegisteredContentScripts) return;
    const existing = await C.scripting.getRegisteredContentScripts({ids: ["eg-noise", "eg-noise-key"]}).catch(() => []);
    if (existing.length) await C.scripting.unregisterContentScripts({ids: existing.map((x) => x.id)});
  }

  // ---- click-to-load embeds: a session allow for one provider in one tab, ended when the tab navigates ----------
  const EMBED_BASE = 300000;
  function loadEmbed(embedId, tabId, withCookies = false) {
    return serial(async () => {
      const list = (await C.storage.session.get("embeds")).embeds || [];
      const prior = list.find((e) => e.tabId === tabId && e.embed === embedId);
      if (prior && (prior.withCookies || !withCookies)) return prior;
      const used = new Set(list.map((e) => e.id));
      let id = prior ? prior.id : EMBED_BASE;
      while (!prior && used.has(id)) id++;
      await C.declarativeNetRequest.updateSessionRules({removeRuleIds: [id], addRules: [dnr.embedRule(id, embedId, tabId, {withCookies})]});
      const entry = {id, tabId, embed: embedId, withCookies};
      await C.storage.session.set({embeds: [...list.filter((e) => e !== prior), entry]});
      return entry;
    });
  }

  // ---- "Continue through the scanner": one session allow for one scanner host in one tab ------------------------
  const PASS_BASE = 200000;
  const PASS_MS = 60000;
  function addScannerPass(host, tabId) {
    return serial(async () => {
      const list = (await C.storage.session.get("passes")).passes || [];
      const kept = list.filter((p) => !(p.tabId === tabId));
      const used = new Set(kept.map((p) => p.id));
      let id = PASS_BASE;
      while (used.has(id)) id++;
      await C.declarativeNetRequest.updateSessionRules({removeRuleIds: [...list.filter((p) => p.tabId === tabId).map((p) => p.id), id], addRules: [dnr.scannerPassRule(id, host, tabId)]});
      const entry = {id, tabId, host, expiresAt: Date.now() + PASS_MS};
      await C.storage.session.set({passes: [...kept, entry]});
      return entry;
    });
  }
  function dropPasses(test) {
    return serial(async () => {
      const list = (await C.storage.session.get("passes")).passes || [];
      const gone = list.filter(test);
      if (!gone.length) return;
      await C.declarativeNetRequest.updateSessionRules({removeRuleIds: gone.map((p) => p.id)});
      await C.storage.session.set({passes: list.filter((p) => !gone.includes(p))});
    });
  }

  // ---- No scripts / Strict: a site's service workers could serve cached pages and scripts that no rule sees ------
  // Switching a site to No scripts or Strict unregisters its service workers and clears its Cache Storage for the
  // origins we can name: the site, www., and every origin of that site open in a tab. Other subdomains that are not
  // open keep theirs until they are visited with the site open, and the popup says so.
  async function clearWorkers(site) {
    if (!C.browsingData || !C.browsingData.remove) return {ok: false, origins: []};
    const origins = new Set(["https:", "http:"].flatMap((scheme) => [`${scheme}//${site}`, `${scheme}//www.${site}`]));
    const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]}).catch(() => []);
    for (const t of tabs) {
      let u;
      try { u = new URL(t.url); } catch { continue; }
      if (hosts.siteOf(u.hostname) === site) origins.add(u.origin);
    }
    const list = [...origins].sort();
    await C.browsingData.remove({origins: list}, {serviceWorkers: true, cacheStorage: true});
    return {ok: true, origins: list};
  }
  function dropEmbeds(tabId) {
    return serial(async () => {
      const list = (await C.storage.session.get("embeds")).embeds || [];
      const gone = list.filter((e) => e.tabId === tabId);
      if (!gone.length) return;
      await C.declarativeNetRequest.updateSessionRules({removeRuleIds: gone.map((e) => e.id)});
      await C.storage.session.set({embeds: list.filter((e) => e.tabId !== tabId)});
    });
  }

  // ---- link and cookie cleaning counts (per tab for links, per site for cookies; session storage) ----------
  const counts = {links: new Map(), cookies: new Map()};
  let countTimer = null;
  function bump(kind, key, n = 1) {
    if (key === null || key === undefined) return;
    counts[kind].set(key, (counts[kind].get(key) || 0) + n);
    if (countTimer) return;
    countTimer = setTimeout(() => {
      countTimer = null;
      C.storage.session.set({counts: {links: [...counts.links], cookies: [...counts.cookies].slice(-500)}}).catch(() => {});
    }, 300);
  }
  const countsReady = C.storage.session.get("counts").then((r) => {
    const saved = r.counts || {};
    for (const kind of ["links", "cookies"]) for (const [k, v] of Array.isArray(saved[kind]) ? saved[kind] : []) if (Number.isFinite(v)) counts[kind].set(k, (counts[kind].get(k) || 0) + v);
  }).catch(() => {});

  // ---- tracking cookies (core/cookies.js): removed, or cut to the session, the moment they are set --------------
  const cookieRules = root.EGCookies;
  const cookieUrl = (c) => `http${c.secure ? "s" : ""}:\/\/${c.domain.replace(/^\./, "")}${c.path || "/"}`;
  async function onCookie(change) {
    if (!change || change.removed || !change.cookie || !cookieRules) return;
    const c = change.cookie;
    const action = cookieRules.classify(c.name, c.domain);
    if (!action) return;
    const site = hosts.siteOf(c.domain.replace(/^\./, ""));
    await ready;
    if (!cleaningOn(site)) return;
    const target = {url: cookieUrl(c), name: c.name, storeId: c.storeId, ...(c.partitionKey ? {partitionKey: c.partitionKey} : {})};
    if (action === "remove") {
      await C.cookies.remove(target);
      bump("cookies", site);
    } else if (action === "session" && !c.session) {
      const {expirationDate, hostOnly, session, ...keep} = c;
      await C.cookies.set({...keep, url: target.url, ...(hostOnly ? {domain: undefined} : {})});
      bump("cookies", site);
    }
  }
  if (C.cookies && C.cookies.onChanged) C.cookies.onChanged.addListener((change) => { onCookie(change).catch(() => {}); });

  // ---- "Copy clean link" (context menu) through an offscreen document, so the page never sees the copy ----------
  const MENU = "eg-copy-clean";
  /** The clean form of a link on a page at `fromHost`: a tracker is unwrapped only where the page is that tracker's own
   * site (core/links.js allowedFrom); a mail scanner's link is never changed, not even its parameters. */
  function cleanLink(href, fromHost = null) {
    const L = root.EGLinks;
    if (L && L.scannerOf(href)) return href;
    let out = href;
    if (L && L.wrapperOf(out)) { const r = L.unwrap(out, {from: fromHost}); if (r.url) out = r.url; }
    if (L && L.scannerOf(out)) return out;
    return root.EGParams ? root.EGParams.clean(out).url : out;
  }
  async function copyText(text) {
    if (!C.offscreen) return {ok: false};
    const has = C.runtime.getContexts ? (await C.runtime.getContexts({contextTypes: ["OFFSCREEN_DOCUMENT"]})).length > 0 : false;
    if (!has) await C.offscreen.createDocument({url: "offscreen.html", reasons: ["CLIPBOARD"], justification: "Copy a cleaned link to the clipboard."});
    try { return await C.runtime.sendMessage({type: "offscreen-copy", text}); } finally { C.offscreen.closeDocument().catch(() => {}); }
  }
  async function copyClean(linkUrl, pageUrl = null) {
    if (typeof linkUrl !== "string" || !/^https?:/i.test(linkUrl)) return {ok: false};
    const text = cleanLink(linkUrl, hosts.hostOfUrl(pageUrl || ""));
    const result = await copyText(text);
    return {ok: Boolean(result && result.ok), text};
  }
  if (C.contextMenus) {
    C.runtime.onInstalled.addListener(() => {
      C.contextMenus.removeAll(() => C.contextMenus.create({id: MENU, title: "Copy clean link", contexts: ["link"]}));
    });
    C.contextMenus.onClicked.addListener((info) => { if (info.menuItemId === MENU) copyClean(info.linkUrl, info.frameUrl || info.pageUrl).catch(() => {}); });
  }

  const ready = Promise.all([store.load(), loadGenericOff(), loadModes(), retireNoise().catch(() => {})]).then(async () => {
    for (const msg of store.rejected) console.warn("Egress Guard dropped a stored entry:", msg);
    await sync();
  });

  // ---- dynamic rules --------------------------------------------------------------
  let syncing = Promise.resolve();
  function sync() {
    syncing = syncing.catch(() => {}).then(async () => {
      store.pruneSync();
      const compiled = dnr.compileUserState(store.rules, store.exceptions, Date.now());
      const siteModes = dnr.compileModes(modes);
      const existing = await C.declarativeNetRequest.getDynamicRules();
      await C.declarativeNetRequest.updateDynamicRules({removeRuleIds: existing.map((r) => r.id), addRules: [...compiled.rules, ...siteModes.rules]});
      sources = compiled.sources;
      modeKinds = siteModes.kinds;
      allowIds = new Set(compiled.rules.filter((r) => r.action.type !== "block").map((r) => r.id));
      await schedule();
    });
    return syncing;
  }

  async function schedule() {
    await C.alarms.clear(ALARM);
    const passes = (await C.storage.session.get("passes")).passes || [];
    const times = [store.nextExpiry(), ...(await continues()).map((c) => c.expiresAt), ...passes.map((x) => x.expiresAt)].filter((t) => t !== null && t !== undefined);
    if (times.length) C.alarms.create(ALARM, {when: Math.max(Math.min(...times), Date.now() + 1000)});
  }

  // ---- "continue once" session rules --------------------------------------------
  async function continues() { return (await C.storage.session.get("continues")).continues || []; }
  async function saveContinues(list) { await C.storage.session.set({continues: list}); }
  const ruleIds = (c) => [c.id, c.id + 1];       // each continue is two session rules (dnr.continueRules)

  // Read-modify-write of the continue list is serialised, so two clicks never pick the same rule id.
  let continuing = Promise.resolve();
  function serial(fn) {
    const run = continuing.catch(() => {}).then(fn);
    continuing = run;
    return run;
  }

  function addContinue(host, tabId) {
    return serial(async () => {
      const list = await continues();
      const replaced = list.filter((c) => c.host === host && c.tabId === tabId);
      const kept = list.filter((c) => !replaced.includes(c));
      const used = new Set(kept.flatMap(ruleIds));
      let id = CONTINUE_BASE;
      while (used.has(id) || used.has(id + 1)) id += 2;
      await C.declarativeNetRequest.updateSessionRules({removeRuleIds: [...replaced.flatMap(ruleIds), id, id + 1], addRules: dnr.continueRules(id, host, tabId)});
      const entry = {id, host, tabId, expiresAt: Date.now() + CONTINUE_MINUTES * 60000};
      await saveContinues([...kept, entry]);
      await schedule();
      return entry;
    });
  }

  function dropContinues(test) {
    return serial(async () => {
      const list = await continues();
      const gone = list.filter(test);
      if (!gone.length) return;
      await C.declarativeNetRequest.updateSessionRules({removeRuleIds: gone.flatMap(ruleIds)});
      await saveContinues(list.filter((c) => !gone.includes(c)));
    });
  }

  // ---- is a host on the bundled malware and phishing list? ---------------------------------
  // Unpacked builds ask Chrome itself (testMatchOutcome). Packed builds lack that API, so the worker reads its own
  // packaged threat ruleset once (the CSP allows connect-src 'self' and nothing else).
  let threatNames = null;
  async function isThreat(host) {
    const D = C.declarativeNetRequest;
    if (D.testMatchOutcome) {
      try {
        const outcome = await D.testMatchOutcome({url: `https://${host}/`, type: "main_frame"});
        return outcome.matchedRules.some((m) => listKind(m.rulesetId) === "threats");
      } catch { /* fall through to the packaged list */ }
    }
    if (!threatNames) {
      const files = ((LISTS.lists || {}).threats || {}).files || ["rules/threats.json"];
      threatNames = Promise.all(files.filter((f) => /^rules\/threats(-[0-9]+)?\.json$/.test(f)).map((file) => fetch(OWN + file).then((r) => r.json())))
        .then((sets) => new Set(sets.flat().filter((r) => r.action.type === "block").flatMap((r) => r.condition.requestDomains || [])));
      threatNames.catch(() => { threatNames = null; });
    }
    const names = await threatNames;
    for (let name = host; name.includes("."); name = name.slice(name.indexOf(".") + 1)) if (names.has(name)) return true;
    return false;
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

  // A large list is split across rulesets "threats", "threats-2", …; they are one list to the user.
  function listKind(rulesetId) { return typeof rulesetId === "string" ? rulesetId.replace(/-[0-9]+$/, "") : rulesetId; }

  function listOf(rule) {
    // Allow rules (your allow rules, timed exceptions, the lists' own exceptions, Relaxed sites) and header changes
    // also report matches; they blocked nothing.
    if (rule.rulesetId === "_dynamic") {
      if (Object.prototype.hasOwnProperty.call(modeKinds, rule.ruleId)) return modeKinds[rule.ruleId] ? {list: modeKinds[rule.ruleId]} : null;
      return allowIds.has(rule.ruleId) ? null : {list: "user", ruleId: sources[rule.ruleId] || null};
    }
    if (rule.rulesetId === "_session") return null;
    const list = dnr.categoryOf(rule.rulesetId);
    return list ? {list} : null;
  }

  async function onMatched(info) {
    const {request, rule} = info;
    if (!request || request.tabId === undefined || request.tabId < 0) return;
    // A cleaned navigation (parameters removed or a redirector unwrapped) counts as a cleaned link.
    if (rule.rulesetId === "params" || rule.rulesetId === "links") bump("links", request.tabId);
    const source = listOf(rule);
    if (!source) return;
    let parsed;
    try { parsed = new URL(request.url); } catch { return; }
    const host = hosts.normalizeHost(parsed.hostname);
    if (!host) return;
    const type = request.type === "main_frame" ? "main_frame" : (dnr.CHROME_TO_CORE[request.type] || "other");
    const log = await tabLog(request.tabId);
    const path = (parsed.pathname || "/").slice(0, MAX_PATH);
    const prior = log.items.find((x) => x.host === host && x.path === path && x.type === type && x.list === source.list);
    if (prior) prior.count++;
    else if (log.items.length < MAX_LOG) log.items.push({host, path, type, list: source.list, ruleId: source.ruleId || null, count: 1});
    // An unwrapped link is matched on the navigation that the page load then resets; carry it into the new log.
    if (type === "main_frame") carried.set(request.tabId, {at: Date.now(), item: {host, path, type, list: source.list, ruleId: null, count: 1}});
    flushSoon();
  }

  const carried = new Map();        // tabId -> the navigation-level match that led to this page load
  async function resetTab(tabId, url) {
    const carry = carried.get(tabId);
    // The unwrap page itself is a stop on the way: the match is carried on to the page it opens.
    if (!(typeof url === "string" && url.startsWith(OWN))) carried.delete(tabId);
    const keep = carry && Date.now() - carry.at < 15000 ? [carry.item] : [];
    logs.set(tabId, Promise.resolve({items: keep}));
    await C.storage.session.remove(`log:${tabId}`);
    await C.storage.session.set({[`nav:${tabId}`]: Date.now()});
  }

  /**
   * What the popup can honestly show about blocked requests on a tab:
   *   "debug"  (unpacked builds) every blocked endpoint, from onRuleMatchedDebug;
   *   "counts" (packed builds) per-list counts from getMatchedRules, which reports rules, never addresses;
   *   "badge"  when neither is available (or Chrome's getMatchedRules quota is spent): the toolbar badge only.
   */
  async function blockedReport(tabId) {
    const D = C.declarativeNetRequest;
    if (!Number.isInteger(tabId)) return {feedback: D.onRuleMatchedDebug ? "debug" : "badge", blocked: []};
    if (D.onRuleMatchedDebug) return {feedback: "debug", blocked: (await tabLog(tabId)).items.map((x) => ({...x}))};
    if (!D.getMatchedRules) return {feedback: "badge", blocked: []};
    try {
      const since = (await C.storage.session.get(`nav:${tabId}`))[`nav:${tabId}`];
      const {rulesMatchedInfo = []} = await D.getMatchedRules({tabId, ...(Number.isFinite(since) ? {minTimeStamp: since} : {})});
      const counts = {};
      for (const info of rulesMatchedInfo) {
        const source = listOf(info.rule);
        if (!source) continue;
        counts[source.list] = (counts[source.list] || 0) + 1;
      }
      return {feedback: "counts", blocked: [], counts};
    } catch {
      return {feedback: "badge", blocked: []};
    }
  }

  // ---- events (registered synchronously so they wake the worker) ----------------
  if (C.declarativeNetRequest.onRuleMatchedDebug) C.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => { onMatched(info).catch(() => {}); });
  if (C.declarativeNetRequest.setExtensionActionOptions) C.declarativeNetRequest.setExtensionActionOptions({displayActionCountAsBadgeText: true}).catch(() => {});
  if (C.action && C.action.setBadgeBackgroundColor) C.action.setBadgeBackgroundColor({color: "#19382e"}).catch(() => {});

  C.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (info.status === "loading") resetTab(tabId, (tab && tab.url) || info.url).catch(() => {});
    // A loaded embed is for that page only.
    if (info.status === "loading") dropEmbeds(tabId).catch(() => {});
    if (typeof info.url === "string" && !info.url.startsWith(OWN)) {
      // A "continue once" exception ends when the tab leaves the host it was granted for.
      const host = hosts.hostOfUrl(info.url);
      dropContinues((c) => c.tabId === tabId && !(host && hosts.withinScope(host, c.host))).catch(() => {});
      // A scanner pass is for one navigation: once the tab commits any web address (the scanner itself, normally), it is used.
      dropPasses((x) => x.tabId === tabId).catch(() => {});
    }
  });
  C.tabs.onRemoved.addListener((tabId) => {
    logs.delete(tabId);
    carried.delete(tabId);
    counts.links.delete(tabId);
    C.storage.session.remove([`log:${tabId}`, `nav:${tabId}`]).catch(() => {});
    dropContinues((c) => c.tabId === tabId).catch(() => {});
    dropEmbeds(tabId).catch(() => {});
    dropPasses((x) => x.tabId === tabId).catch(() => {});
  });
  // ---- noticing a rebuilt extension folder ---------------------------------------------------
  // An unpacked extension's files are read from its folder live. When `node scripts/build-browser.mjs` rewrites that
  // folder, rules/build.json changes; the worker notices on its hourly check and the popup asks the user to press
  // the reload arrow. It does NOT call runtime.reload(): in headless Chrome 157 an unpacked extension that reloaded
  // itself came back disabled (developer mode on or off), which would silently switch all protection off.
  // No network: the only read is the extension's own file (connect-src 'self'). Packed builds skip this.
  const REFRESH_ALARM = "eg-rebuilt";
  const REFRESH_MINUTES = 60;
  async function reloadIfRebuilt() {
    if (!LISTS.build || (C.runtime.getManifest && C.runtime.getManifest().update_url)) return "packed";
    let onDisk;
    try { onDisk = await fetch(OWN + "rules/build.json", {cache: "no-store"}).then((r) => r.json()); } catch { return "unreadable"; }
    if (!onDisk || typeof onDisk.build !== "string" || !/^[0-9a-f]{32}$/.test(onDisk.build)) return "unreadable";
    const stale = onDisk.build !== LISTS.build;
    await C.storage.session.set({rebuilt: stale ? {at: Number(onDisk.built_at) || null} : null});
    return stale ? "rebuilt" : "current";
  }
  C.alarms.get(REFRESH_ALARM).then((existing) => {
    if (!existing) C.alarms.create(REFRESH_ALARM, {delayInMinutes: 1, periodInMinutes: REFRESH_MINUTES});
  }).catch(() => {});

  C.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === REFRESH_ALARM) { await reloadIfRebuilt(); return; }
    if (alarm.name !== ALARM) return;
    await ready;
    const now = Date.now();
    await dropContinues((c) => c.expiresAt <= now);
    await dropPasses((x) => x.expiresAt <= now);
    if (await store.prune()) { await sync(); await broadcast(); } else await schedule();
  });

  // ---- messaging -------------------------------------------------------------------
  const extensionUrl = (sender, page) => typeof sender.url === "string" && sender.url.startsWith(OWN + page);
  // The popup normally has no tab; opened as popup.html?tab=<id> (development captures) it does.
  const fromPopup = (sender) => extensionUrl(sender, "popup.html");
  const fromWarning = (sender) => sender.tab && Number.isInteger(sender.tab.id) && extensionUrl(sender, "warning.html");
  const fromUnwrap = (sender) => sender.tab && Number.isInteger(sender.tab.id) && sender.frameId === 0 && extensionUrl(sender, "unwrap.html");
  /** The scanner link the unwrap page in `sender` shows: its own link, or the scanner a link tracker led to. */
  function scannerShownBy(sender) {
    let hash;
    try { hash = new URL(sender.url).hash.slice(1); } catch { return null; }
    const L = root.EGLinks;
    if (L.scannerOf(hash)) return hash;
    const first = L.wrapperOf(hash);
    const r = L.unwrap(hash, {from: first && !first.open ? first.sites[0] : null});
    return r.url && L.scannerOf(r.url) ? r.url : null;
  }
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
        return {site: hosts.siteOf(pageHost), rules: store.activeFor(pageHost).cosmeticRules.map(plain), generic: !genericOff.has(hosts.siteOf(pageHost))};
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
      case "guard-config": {
        if (!pageHost) return {clean: false};
        const mode = modeFor(hosts.siteOf(pageHost));
        return {clean: cleaningOn(hosts.siteOf(pageHost)), mode, embeds: mode === "strict" || mode === "noscript" ? dnr.EMBEDS.map((e) => ({id: e.id, name: e.name, domains: [...e.domains]})) : []};
      }
      case "load-embed": {
        if (!pageHost || !sender.tab || !Number.isInteger(sender.tab.id)) return {error: "Not a page."};
        if (!dnr.EMBEDS.some((e) => e.id === message.embed)) return {error: "Bad message."};
        await loadEmbed(message.embed, sender.tab.id, message.cookies === true);
        return {ok: true};
      }
      case "unwrap-config": {
        if (!fromUnwrap(sender)) return {error: "Not allowed from a page."};
        return {scannedDirect: modes.scannedDirect};
      }
      case "check-destination": {
        // The unwrap page asks before it opens anything: a destination on the malware and phishing list goes to the
        // warning page, whether it came from a link tracker or from "Open directly".
        if (!fromUnwrap(sender)) return {error: "Not allowed from a page."};
        const url = root.EGLinks.safeDestination(message.url);
        const host = url && hosts.hostOfUrl(url);
        if (!host) return {error: "Not a web address."};
        const threat = await isThreat(host);
        // The page that opens next shows the link tracker it skipped (the DNR match itself may land in the log of the
        // page the click came from, depending on event timing).
        const shown = hosts.hostOfUrl(new URL(sender.url).hash.slice(1));
        if (shown && !threat) {
          let path = "/";
          try { path = new URL(new URL(sender.url).hash.slice(1)).pathname.slice(0, MAX_PATH); } catch { /* keep "/" */ }
          carried.set(sender.tab.id, {at: Date.now(), item: {host: shown, path, type: "main_frame", list: "links", ruleId: null, count: 1}});
        }
        return {ok: true, threat};
      }
      case "scanner-continue": {
        if (!fromUnwrap(sender)) return {error: "Not allowed from a page."};
        const shown = scannerShownBy(sender);
        // The page names the link it showed; if the address changed since, the user agreed to something else.
        if (!shown || message.url !== shown) return {error: "The address changed after this page loaded. Reload it and read it again."};
        const host = hosts.hostOfUrl(shown);
        if (!host) return {error: "Bad message."};
        await addScannerPass(host, sender.tab.id);
        await schedule();
        return {ok: true};
      }
      case "links-cleaned": {
        const n = Number(message.count);
        if (!pageHost || !Number.isInteger(n) || n < 1 || n > 100) return {error: "Bad message."};
        bump("links", sender.tab.id, n);
        return {ok: true};
      }
      case "warning-info": {
        if (!fromWarning(sender)) return {error: "Not allowed from a page."};
        const meta = (LISTS.lists || {})[message.list] || null;
        return {list: meta, minutes: CONTINUE_MINUTES};
      }
      case "continue-once": {
        if (!fromWarning(sender)) return {error: "Not allowed from a page."};
        if (sender.frameId !== 0) return {error: "The warning page cannot continue from inside a frame."};
        const target = dnr.parseWarning(sender.url);
        if (!target) return {error: "Nothing to continue to."};
        // The page names the address it showed; if the fragment changed since, the user agreed to something else.
        if (message.url !== target.url) return {error: "The address changed after this page loaded. Reload it and read it again."};
        if (!(await isThreat(target.host))) return {error: "That site is not on the malware and phishing list."};
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
        const report = await blockedReport(message.tabId);
        return {
          host, site: hosts.siteOf(host), lists, ...report, generic: !genericOff.has(hosts.siteOf(host)),
          rebuilt: Boolean((await C.storage.session.get("rebuilt")).rebuilt),
          requestRules: active.requestRules.map(plain), cosmeticRules: active.cosmeticRules.map(plain),
          exceptions: active.exceptions.map((e) => ({...e, msLeft: Math.max(0, e.expiresAt - now)})),
          types: rulesApi.RESOURCE_TYPES,
          categories: Object.fromEntries(Object.entries(dnr.CATEGORIES).filter(([, v]) => v.label).map(([k, v]) => [k, v.label])),
          mode: modeFor(hosts.siteOf(host)), siteMode: modes.sites[hosts.siteOf(host)] || null, defaultMode: modes.defaultMode,
          strictAllowed: [...(modes.allowHosts[hosts.siteOf(host)] || [])],
          scannedDirect: modes.scannedDirect,
          cleaning: {on: cleaningOn(hosts.siteOf(host)), links: await countsReady.then(() => counts.links.get(message.tabId) || 0),
            cookies: counts.cookies.get(hosts.siteOf(host)) || 0},
        };
      }
      case "set-clean": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        if (!site || typeof message.on !== "boolean") return {error: "Bad message."};
        const off = new Set(modes.cleanOff);
        if (message.on) off.delete(site); else if (off.size < MAX_MODE_SITES) off.add(site); else return {error: "Too many sites."};
        modes.cleanOff = [...off].sort();
        await saveModes(); await sync();
        const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
        for (const t of tabs) if (hosts.siteOf(hosts.hostOfUrl(t.url) || "") === site) C.tabs.sendMessage(t.id, {type: "clean-enabled", on: message.on}).catch(() => {});
        return {ok: true, on: message.on};
      }
      case "copy-clean": return copyClean(message.url, message.tabUrl);
      case "set-scanned-direct": {
        if (typeof message.on !== "boolean") return {error: "Bad message."};
        modes.scannedDirect = message.on;
        await saveModes();
        return {ok: true, on: modes.scannedDirect};
      }
      case "set-mode": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        if (!site) return {error: "Open a web page first."};
        if (message.mode !== "default" && !dnr.SITE_MODES.includes(message.mode)) return {error: "Bad message."};
        if (message.mode === "default") delete modes.sites[site];
        else if (Object.keys(modes.sites).length >= MAX_MODE_SITES && !modes.sites[site]) return {error: "Too many sites have their own mode."};
        else modes.sites[site] = message.mode;
        await saveModes(); await sync();
        // Rules cannot see what a service worker answers from its cache: clear the site's workers and caches.
        const mode = modeFor(site);
        const cleared = mode === "noscript" || mode === "strict" ? await clearWorkers(site).catch(() => ({ok: false, origins: []})) : null;
        return {ok: true, site, mode, cleared};
      }
      case "set-default-mode": {
        if (message.mode !== "standard" && message.mode !== "strict") return {error: "Bad message."};
        modes.defaultMode = message.mode;
        await saveModes(); await sync();
        return {ok: true, defaultMode: modes.defaultMode};
      }
      case "strict-allow": case "strict-unallow": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        const target = hosts.normalizeHost(message.host);
        if (!site || !target) return {error: "Bad message."};
        if (message.type === "strict-allow" && await isThreat(target)) return {error: "This host is on the malware and phishing list; it cannot be allowed from here."};
        const list = new Set(modes.allowHosts[site] || []);
        if (message.type === "strict-allow") { if (list.size >= MAX_ALLOWED_HOSTS) return {error: "Too many allowed hosts for this site."}; list.add(target); }
        else list.delete(target);
        if (list.size) modes.allowHosts[site] = [...list].sort(); else delete modes.allowHosts[site];
        await saveModes(); await sync();
        return {ok: true};
      }
      case "add-request-rule": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        const result = await attempt(() => store.addRule({kind: "request", site: hosts.siteOf(host), host: message.host, path: message.path, types: message.types, action: "block"}));
        if (!result.error) await afterChange();
        return result;
      }
      case "remove-rule": { const ok = await store.removeRule(message.id); if (ok) await afterChange(); return {ok}; }
      case "set-generic": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        if (!site) return {error: "Open a web page first."};
        if (typeof message.on !== "boolean") return {error: "Bad message."};
        if (message.on) genericOff.delete(site);
        else if (genericOff.size < MAX_GENERIC_OFF) genericOff.add(site);
        else return {error: "Too many sites have ad-slot hiding switched off."};
        await C.storage.local.set({[GENERIC_KEY]: [...genericOff].sort()});
        const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
        for (const tab of tabs) {
          if (hosts.siteOf(hosts.hostOfUrl(tab.url) || "") === site) C.tabs.sendMessage(tab.id, {type: "generic", on: message.on}).catch(() => {});
        }
        return {ok: true, site, on: message.on};
      }
      case "add-exception": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        if (message.resourceType === "main_frame") return {error: "Navigations are allowed with Continue on the warning page."};
        const target = hosts.normalizeHost(message.host);
        if (target && await isThreat(target)) return {error: "This host is on the malware and phishing list; it cannot be allowed from here."};
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
  root.__EGBackground = Object.freeze({store, ready, handle, sync, onMatched, tabLog, continues, reloadIfRebuilt, onCookie, copyClean, cleanLink, counts, get sources() { return sources; }});
})(globalThis);
