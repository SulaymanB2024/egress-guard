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
  // Optional profile controls have their own saved-intent/readback controller.
  // They must remain recoverable when the unrelated DNR queue is stalled.
  const browserPrivacy = root.EGBrowserPrivacy ? root.EGBrowserPrivacy.createController(C) : null;
  if (browserPrivacy) browserPrivacy.ready.catch(() => {});
  const hardeningApi = root.EGPrivacyHardening || null;

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
    genericOff = new Set((Array.isArray(stored) ? stored : []).filter((s) => hosts.siteOf(s) === s).slice(0, MAX_GENERIC_OFF));
  }
  // Site modes (Relaxed / Standard / Strict / No scripts / Isolation) and the hosts allowed under Strict. Validated on
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
    out.cleanOff = [...new Set(off.filter((s) => hosts.siteOf(s) === s && hosts.canScopeSite(s)))].slice(0, MAX_MODE_SITES).sort();
    const sites = value && typeof value.sites === "object" && value.sites ? value.sites : {};
    for (const [site, mode] of Object.entries(sites).slice(0, MAX_MODE_SITES)) {
      if (hosts.siteOf(site) === site && hosts.canScopeSite(site) && dnr.SITE_MODES.includes(mode)) out.sites[site] = mode;
    }
    const allow = value && typeof value.allowHosts === "object" && value.allowHosts ? value.allowHosts : {};
    for (const [site, list] of Object.entries(allow).slice(0, MAX_MODE_SITES)) {
      if (hosts.siteOf(site) !== site || !hosts.canScopeSite(site) || !Array.isArray(list)) continue;
      const names = [...new Set(list.map((h) => hosts.normalizeHost(h)).filter((h) => h && !hosts.isSuffixLike(h)))].slice(0, MAX_ALLOWED_HOSTS).sort();
      if (names.length) out.allowHosts[site] = names;
    }
    return out;
  }
  let savedModes = JSON.parse(JSON.stringify(modes));
  async function loadModes() {
    const raw = (await C.storage.local.get(MODES_KEY))[MODES_KEY];
    modes = cleanModes(raw);
    if (raw && (raw.schema !== 2 || raw.scope !== "top-level-psl-v2" || raw.psl !== hosts.psl.sha256)) {
      modes.sites = Object.fromEntries(Object.entries(modes.sites).filter(([, mode]) => ["strict", "noscript", "isolated"].includes(mode)));
      modes.allowHosts = {}; modes.cleanOff = [];
      policy.warnings.push("Legacy relaxed modes, cleaning exemptions and host permissions were revoked for the PSL/top-level scope migration.");
    }
    savedModes = clone(modes);
  }
  async function saveModes({clearPauseSite = null} = {}) {
    const next = cleanModes(modes);
    const nextPauses = clearPauseSite ? {...pauses} : null;
    if (nextPauses) delete nextPauses[clearPauseSite];
    try {
      // One saved-intent write for activation and its pause removal. Independently,
      // effectiveModes never permits a pause to replace Isolation, even if old or
      // inconsistent storage contains both entries after recovery.
      await C.storage.local.set({[MODES_KEY]: {...next, schema: 2, scope: "top-level-psl-v2", psl: hosts.psl.sha256},
        ...(nextPauses ? {[PAUSE_KEY]: {schema: 2, scope: "top-level-psl-v2", items: nextPauses}} : {})});
      modes = next; savedModes = clone(next);
      if (nextPauses) { pauses = nextPauses; savedPauses = clone(nextPauses); }
    } catch (error) { modes = clone(savedModes); if (nextPauses) pauses = clone(savedPauses); noteError(error); throw error; }
  }

  // ---- timed per-site pause (popup only) ------------------------------------------------------------------------
  // Pause: for PAUSE_MINUTES the site (registrable domain) runs at Relaxed, with no element hiding and no link or
  // cookie cleaning. It is an overlay on the saved settings, never a change to them, so when it ends (alarm, Resume,
  // or a worker or browser restart after the expiry) the site's own level and settings simply apply again. The threat
  // list, the warning page and the user's block rules are untouched (they sit above Relaxed). Only the popup can start
  // or end it; a running pause cannot be extended. Stored in storage.local as {site: expiresAt}.
  const PAUSE_KEY = "egressGuardPauses";
  const PAUSE_MINUTES = 15, MAX_PAUSES = 50;
  let pauses = {}, savedPauses = {};
  /** Load stored pauses, dropping anything malformed or expired. Returns the sites whose pause ended while asleep. */
  async function loadPauses() {
    const stored = (await C.storage.local.get(PAUSE_KEY))[PAUSE_KEY];
    const now = Date.now();
    const ended = [];
    pauses = {};
    const entries = stored && stored.schema === 2 && stored.scope === "top-level-psl-v2" && stored.items && typeof stored.items === "object" ? stored.items : {};
    for (const [site, until] of Object.entries(entries).slice(0, MAX_PAUSES)) {
      if (hosts.siteOf(site) !== site || !hosts.canScopeSite(site) || !Number.isFinite(until) || until > now + PAUSE_MINUTES * 60000) continue;
      if (until > now) pauses[site] = until; else ended.push(site);
    }
    savedPauses = clone(pauses);
    return ended;
  }
  async function savePauses() {
    try {
      await C.storage.local.set({[PAUSE_KEY]: {schema: 2, scope: "top-level-psl-v2", items: pauses}});
      savedPauses = clone(pauses);
    } catch (error) { pauses = clone(savedPauses); noteError(error); throw error; }
  }
  const requestedPausedUntil = (site) => (site && modes.sites[site] !== "isolated" && pauses[site] > Date.now() ? pauses[site] : null);
  // Applied pauses stay visible until the actual allow is removed, even if its
  // scheduled deadline passed while Chrome slept or rejected a rule update.
  const pausedUntil = (site) => (site && applied && applied.effectiveModes.sites[site] !== "isolated" && applied.pauses[site]) || null;
  /** End pauses whose time has come; returns their sites. */
  async function endPauses(now = Date.now()) {
    const ended = Object.keys(pauses).filter((site) => pauses[site] <= now);
    for (const site of ended) delete pauses[site];
    if (ended.length) await savePauses();
    return ended;
  }
  /** The saved modes with every running pause laid over them: Relaxed, and cleaning off. */
  function effectiveModes() {
    const live = Object.keys(pauses).filter((site) => requestedPausedUntil(site));
    if (!live.length) return modes;
    return {...modes, sites: {...modes.sites, ...Object.fromEntries(live.map((site) => [site, "relaxed"]))},
      cleanOff: [...new Set([...modes.cleanOff, ...live])].sort()};
  }
  const savedModeFor = (site) => (site && modes.sites[site]) || modes.defaultMode;
  const modeFor = (site, topHost = site) => {
    const mode = applied ? ((site && applied.effectiveModes.sites[site]) || applied.effectiveModes.defaultMode) : "unknown";
    return mode === "isolated" && !preparedHostScope(site, topHost) ? "unknown" : mode;
  };
  const cleaningOn = (site) => !(site && applied && applied.effectiveModes.cleanOff.includes(site));
  const isolationSelected = (site, includeApplied = true) => {
    const key = hosts.siteOf(site);
    return Boolean(key && (modes.sites[key] === "isolated" || includeApplied && applied && applied.effectiveModes.sites[key] === "isolated"));
  };
  const crossesIsolation = (site, target, includeApplied = true) => isolationSelected(site, includeApplied) && hosts.isThirdParty(target, site);
  const ISOLATION_REPAIR_ERROR = "Isolation blocks cross-site resources and has no repair exceptions. Choose another site mode explicitly before allowing this resource.";

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
  function loadEmbed(embedId, tabId, withCookies = false, site = null) {
    return changeGrantsNow((list) => {
      const prior = list.find((e) => e.kind === "embed" && e.tabId === tabId && e.embed === embedId && e.site === site && e.expiresAt > Date.now());
      if (prior && (prior.withCookies || !withCookies)) return list;
      const kept = list.filter((e) => e !== prior);
      return [...kept, {kind: "embed", id: prior ? prior.id : nextGrantId(kept, EMBED_BASE), tabId, embed: embedId,
        withCookies, site, createdAt: Date.now(), expiresAt: Date.now() + EMBED_MS}];
    });
  }

  // ---- "Continue through the scanner": one session allow for one scanner host in one tab ------------------------
  const PASS_BASE = 200000;
  const PASS_MS = 60000;
  function addScannerPass(host, tabId) {
    return changeGrantsNow((list) => {
      const kept = list.filter((e) => !(e.kind === "pass" && e.tabId === tabId));
      return [...kept, {kind: "pass", id: nextGrantId(kept, PASS_BASE), tabId, host, createdAt: Date.now(), expiresAt: Date.now() + PASS_MS}];
    });
  }
  function dropPasses(test) { return changeGrants((list) => list.filter((e) => e.kind !== "pass" || !test(e))); }

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
  function dropEmbeds(tabId) { return changeGrants((list) => list.filter((e) => e.kind !== "embed" || e.tabId !== tabId)); }

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

  // ---- reconciled browser policy -----------------------------------------------------------
  // A saved preference is intent. Only read-back from DNR makes it an applied receipt.
  // Dynamic and session updates are individually atomic, not a transaction together.
  // Revoke session permissions first, install denies, then add journaled permissions.
  const CONTROLLER_KEY = "egressGuardController";
  const GRANT_KEY = "egressGuardGrants";
  const RECOVERY_ALARM = "eg-reconcile";
  const ENDPOINT_BASE = 400000;
  const PERSISTENT_ALLOW_BASE = 600000;
  const MAX_GRANTS = 500;
  // Bounded, in-memory navigation prewarming, never a persistent visit history.
  // The registered dynamic policy/receipt can retain a site until reconciliation;
  // these transient contexts themselves are never restored after worker restart.
  const MAX_PREWARM_CONTEXTS = 128, PREWARM_MS = 60000;
  const EMBED_MS = 60 * 60000;
  const EPOCH = `${C.runtime.getManifest ? C.runtime.getManifest().version : "0.8"}:${LISTS.build || "source"}:${hosts.psl.sha256}`;
  let loaded = false, restoredSessions = false;
  let endedWhileAsleep = [];
  let grants = [], journal = null, savedReceipt = null, applied = null;
  let endpointIds = {};
  let lastWall = Date.now();
  const knownTabs = new Map();
  const prewarmContexts = new Map(); // source tab id -> {site, expiresAt}
  const policy = {state: "pending", desiredRevision: null, savedRevision: null, appliedRevision: null,
    error: null, grantsPending: false, expirySemantics: "scheduled", warnings: [], topPartyCoverage: "unknown"};
  let hardening = {schema: 1, revision: 0, enabled: false};
  let hardeningLoaded = false, hardeningSaved = false, hardeningError = "";
  let syncing = Promise.resolve();
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const canonical = (v) => JSON.stringify(v, function (key, value) {
    if (value && typeof value === "object" && !Array.isArray(value)) return Object.fromEntries(Object.keys(value).sort().map((k) => [k, value[k]]));
    return value;
  });
  const sameRules = (a, b) => canonical([...a].sort((x, y) => x.id - y.id)) === canonical([...b].sort((x, y) => x.id - y.id));
  async function digest(value) {
    const bytes = Uint8Array.from(unescape(encodeURIComponent(canonical(value))), (c) => c.charCodeAt(0));
    return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 24);
  }
  const noteError = (error) => { policy.state = "degraded"; policy.error = String(error && error.message || error); };
  function forgetDynamicReceipt() {
    applied = null;
    policy.dynamicRevision = null; policy.appliedRevision = null;
    policy.topPartyCoverage = "unknown";
  }
  function serial(fn) {
    const run = syncing.catch(() => {}).then(fn);
    syncing = run;
    return run;
  }

  async function loadHardening() {
    if (hardeningLoaded || !hardeningApi) return;
    try {
      const raw = (await C.storage.local.get(hardeningApi.KEY))[hardeningApi.KEY];
      if (raw !== undefined) { hardening = hardeningApi.validateState(raw); hardeningSaved = true; }
      hardeningLoaded = true; hardeningError = "";
    } catch (error) {
      hardeningError = String(error && error.message || error).slice(0, 300);
      // Do not silently remove a previously installed restriction when its saved
      // intent cannot be read. The normal policy failure path keeps last rules.
      throw error;
    }
  }

  async function hardeningStatus() {
    if (!hardeningApi) return {error: "Client Hints control is unavailable in this build."};
    await loadHardening().catch(() => {});
    let observed = null, readError = "";
    try { observed = (await C.declarativeNetRequest.getDynamicRules()).filter(rule => hardeningApi.ownsRuleId(rule.id)); }
    catch (error) { readError = String(error && error.message || error).slice(0, 300); }
    const enabledRules = hardeningApi.compile({enabled: true, priority: dnr.PRIORITY.clientHints});
    const wanted = hardening.enabled ? enabledRules : [];
    const rulesConfirmed = Boolean(!hardeningError && observed && sameRules(observed, wanted));
    const installed = observed === null ? null : sameRules(observed, enabledRules);
    const state = hardeningError || readError ? "degraded" : hardening.enabled
      ? (installed ? "installed" : "pending") : observed.length ? "release-pending" : "inactive";
    return {schema: 1, control: "high-entropy-client-hints", ...hardeningApi.CAPABILITIES,
      saved: hardeningSaved, enabled: hardening.enabled, revision: hardening.revision,
      appliedRevision: rulesConfirmed ? hardening.revision : null, state, rulesConfirmed, installed,
      expectedRuleCount: wanted.length, observedRuleCount: observed === null ? null : observed.length,
      verifiedRuleCount: observed === null ? null : enabledRules.filter(rule => observed.some(actual => canonical(actual) === canonical(rule))).length,
      ruleIds: enabledRules.map(rule => rule.id), requestHeaders: [...hardeningApi.REQUEST_HEADERS],
      error: hardeningError || readError || (!rulesConfirmed ? policy.error || "The requested Client Hints rules have not been confirmed." : ""),
      policyState: policy.state, policyError: policy.error || ""};
  }

  async function setHardeningNow(enabled) {
    if (!hardeningApi) return {error: "Client Hints control is unavailable in this build."};
    hardeningApi.validateEnabled(enabled);
    await loadHardening().catch(() => {}); // an explicit choice can replace corrupt saved intent
    const replacement = {schema: 1, revision: Number.isSafeInteger(hardening.revision + 1) ? hardening.revision + 1 : 1, enabled};
    await C.storage.local.set({[hardeningApi.KEY]: replacement});
    hardening = replacement; hardeningSaved = hardeningLoaded = true; hardeningError = "";
    // This runs ONLY inside the shared DNR queue. No second owner races the main
    // reconciler; a saved checkbox cannot claim a successful rule installation.
    await apply().catch(() => {});
    return hardeningStatus();
  }

  async function retryHardeningNow() {
    await loadHardening().catch(() => {});
    if (hardeningSaved && !hardeningError) await apply().catch(() => {});
    return hardeningStatus();
  }

  const safelyScopedSite = (site) => hosts.siteOf(site) === site && hosts.canScopeSite(site);
  // Wildcard registry bases are conservatively excluded with their descendants:
  // DNR topDomains cannot express "all child tenants except the base hostname".
  const preparedHostScope = (site, host) => Boolean(site && safelyScopedSite(site) && hosts.inSiteScope(host, site) &&
    !hosts.scopeExclusions(site).some((boundary) => hosts.withinScope(host, boundary)));
  function preparationFor(site, topHost = site) {
    const revision = applied && applied.revision || null;
    const canPrepare = preparedHostScope(site, topHost);
    const base = {site, revision, canPrepare};
    if (!topHost) return {...base, state: "not-applicable"};
    if (!applied) return {...base, state: "unknown"};
    const mode = ((site && applied.effectiveModes.sites[site]) || applied.effectiveModes.defaultMode);
    if (mode !== "strict") return {...base, state: "not-applicable"};
    if (applied.preparationSchema !== 1 || !Array.isArray(applied.preparedSites)) return {...base, state: "unknown"};
    return {...base, state: canPrepare && applied.preparedSites.includes(site) ? "prepared" : applied.preparationHold ? "held" : "unknown",
      ...(!canPrepare ? {reason: hosts.normalizeHost(topHost)
        ? "This public-suffix or wildcard-registry address cannot be prepared safely with Chrome's domain conditions."
        : "IP addresses and single-label hosts cannot be prepared safely with Chrome's domain conditions. Default Strict still holds their active resources."} : {})};
  }
  function preparationForUrl(url) {
    let parsed;
    try { parsed = new URL(url); } catch { return preparationFor(null); }
    if (!["http:", "https:"].includes(parsed.protocol)) return preparationFor(null);
    const host = hosts.hostOfUrl(url);
    // Raw HTTP(S) hostnames are used only for an honest unsupported-address
    // receipt. They never become a DNR exclusion, permission or prepared scope.
    return preparationFor(host && hosts.siteOf(host), host || parsed.hostname);
  }

  function isolationFor(site, topHost = site) {
    const requested = site && modes.sites[site] === "isolated";
    const recorded = Boolean(site && applied && applied.effectiveModes.sites[site] === "isolated");
    if (!requested && !recorded) return null;
    const supported = preparedHostScope(site, topHost);
    const active = supported && recorded;
    return {state: !supported ? "unsupported" : policy.state === "degraded" ? "degraded" : requested && active && policy.state === "applied" ? "applied" : "pending",
      active, requested: Boolean(requested), revision: active ? applied.revision : null,
      resourceScope: "cross-top-site-subresources", httpHeaders: [...dnr.ISOLATION_REQUEST_HEADERS, "set-cookie"],
      navigationScope: "destination-site-headers", existingConnections: "not-revoked", reloadNeeded: true,
      ...(!supported ? {reason: "This public-suffix or wildcard-registry address cannot be isolated safely with Chrome's domain conditions."} : {})};
  }

  function preparationCandidates(activeSites, requestedModes, now) {
    for (const [tabId, entry] of prewarmContexts) if (entry.expiresAt <= now || entry.expiresAt > now + PREWARM_MS) prewarmContexts.delete(tabId);
    if (requestedModes.defaultMode !== "strict") prewarmContexts.clear();
    return [...new Set([...activeSites, ...[...prewarmContexts.values()].map((entry) => entry.site)])].sort();
  }

  function prewarm(url, tabId) {
    const host = hosts.hostOfUrl(url || ""), site = hosts.siteOf(host);
    if (!preparedHostScope(site, host)) return Promise.resolve();
    return serial(async () => {
      if (!loaded) await loadState();
      if (modes.defaultMode !== "strict") return;
      prewarmContexts.delete(tabId); prewarmContexts.set(tabId, {site, expiresAt: Date.now() + PREWARM_MS});
      while (prewarmContexts.size > MAX_PREWARM_CONTEXTS) prewarmContexts.delete(prewarmContexts.keys().next().value);
      await apply();
    });
  }

  async function loadState() {
    await Promise.all([store.load(), loadGenericOff(), loadModes(), loadHardening(), loadPauses().then((ended) => { endedWhileAsleep = ended; }), retireNoise().catch(() => {})]);
    const [session, local] = await Promise.all([C.storage.session.get(GRANT_KEY), C.storage.local.get(CONTROLLER_KEY)]);
    journal = session[GRANT_KEY]; savedReceipt = local[CONTROLLER_KEY];
    if (savedReceipt && savedReceipt.schema === 2 && Number.isFinite(savedReceipt.observedAt)) lastWall = Math.max(savedReceipt.observedAt, Number(savedReceipt.clockHighWater) || 0);
    for (const msg of store.rejected) if (!policy.warnings.includes(msg)) policy.warnings.push(msg);
    if (savedReceipt && savedReceipt.epoch !== EPOCH) {
      store.exceptions = []; pauses = {};
      policy.warnings.push("Temporary permissions were revoked after an extension or policy-bundle update.");
    }
    for (const site of Object.keys(pauses)) if (modes.sites[site] === "isolated") delete pauses[site];
    // Complete the conservative migration before any newly compiled permissions.
    await Promise.all([store.save(), saveModes(), savePauses()]);
    loaded = true;
  }

  function rulesForGrant(entry) {
    if (entry.kind === "continue") return dnr.continueRules(entry.id, entry.host, entry.tabId);
    if (entry.kind === "pass") return [dnr.scannerPassRule(entry.id, entry.host, entry.tabId)];
    if (entry.kind === "embed") return [dnr.embedRule(entry.id, entry.embed, entry.tabId, {withCookies: entry.withCookies, topSite: entry.site})];
    throw new Error("Unknown permission kind.");
  }

  function validGrant(entry, now) {
    if (!entry || typeof entry !== "object" || !Number.isInteger(entry.id) || !Number.isInteger(entry.tabId) || entry.tabId < 0 ||
        !Number.isFinite(entry.createdAt) || !Number.isFinite(entry.expiresAt) || entry.createdAt > now || entry.expiresAt <= now) return false;
    const limits = {continue: CONTINUE_MINUTES * 60000, pass: PASS_MS, embed: EMBED_MS};
    if (!limits[entry.kind] || entry.expiresAt - entry.createdAt > limits[entry.kind] || entry.expiresAt <= entry.createdAt) return false;
    const ranges = {continue: [CONTINUE_BASE, PASS_BASE], pass: [PASS_BASE, EMBED_BASE], embed: [EMBED_BASE, ENDPOINT_BASE]};
    if (entry.id < ranges[entry.kind][0] || entry.id + 1 >= ranges[entry.kind][1]) return false;
    if (entry.kind === "embed" && (hosts.siteOf(entry.site) !== entry.site || typeof entry.withCookies !== "boolean")) return false;
    if (entry.kind !== "embed" && hosts.normalizeHost(entry.host) !== entry.host) return false;
    try { rulesForGrant(entry); return true; } catch { return false; }
  }

  async function eligibleGrant(entry, tabs, now) {
    if (!validGrant(entry, now)) return false;
    const tab = tabs.find((t) => t.id === entry.tabId);
    if (!tab) return false;
    const host = hosts.hostOfUrl(tab.url || "");
    if (entry.kind === "embed") {
      if (hosts.siteOf(host) !== entry.site) return false;
      if (dnr.EMBEDS.find((e) => e.id === entry.embed).domains.some((name) => crossesIsolation(entry.site, name, false))) return false;
      // Any provider that has become a listed threat loses ordinary load/cookie grants.
      for (const name of dnr.EMBEDS.find((e) => e.id === entry.embed).domains) if (await isThreat(name)) return false;
    } else if (entry.kind === "pass") {
      if (await isThreat(entry.host)) return false;
      // A pass is consumed at the first committed web navigation. Only the interstitial may keep it.
      if (!String(tab.url || "").startsWith(OWN + "unwrap.html")) return false;
    } else {
      if (host !== entry.host) {
        const target = String(tab.url || "").startsWith(OWN + "warning.html") && dnr.parseWarning(tab.url);
        if (!target || target.host !== entry.host) return false;
      }
      if (!(await isThreat(entry.host))) return false;
    }
    return true;
  }

  async function readTabs() {
    const tabs = await C.tabs.query({});
    // A trusted sender can be more recent than tabs.query during navigation. It is
    // never restored across worker lifetimes; removal/navigation events clear it.
    for (const [id, tab] of knownTabs) if (!tabs.some((t) => t.id === id)) tabs.push(tab);
    return tabs;
  }

  function checkQuota(dynamicRules, sessionRules) {
    const D = C.declarativeNetRequest;
    const unsafe = dynamicRules.filter((r) => !["block", "allow", "allowAllRequests", "upgradeScheme"].includes(r.action.type)).length;
    if (dynamicRules.length > (D.MAX_NUMBER_OF_DYNAMIC_RULES || 30000) || unsafe > (D.MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES || 5000)) throw new Error("Policy exceeds Chrome's dynamic-rule capacity. Reduce site overrides; the previous applied rules remain active.");
    if (sessionRules.length > (D.MAX_NUMBER_OF_SESSION_RULES || 5000)) throw new Error("Policy exceeds Chrome's session-rule capacity. Revoke an unused permission first.");
    for (const list of [dynamicRules, sessionRules]) if (list.filter((r) => r.condition.regexFilter).length > (D.MAX_NUMBER_OF_REGEX_RULES || 1000)) throw new Error("Policy exceeds Chrome's regular-expression rule capacity.");
  }

  async function revokeSessionOnFailure() {
    // A rejected metadata write must never leave a successful, untracked allow.
    grants = []; endpointIds = {};
    const hadEndpoints = store.exceptions.length > 0;
    store.exceptions = [];
    policy.sessionRevision = null; policy.appliedRevision = null;
    if (applied) delete applied.sessionDigest;
    try {
      const current = await C.declarativeNetRequest.getSessionRules();
      if (current.length) await C.declarativeNetRequest.updateSessionRules({removeRuleIds: current.map((r) => r.id)});
      policy.grantsPending = (await C.declarativeNetRequest.getSessionRules()).length > 0;
    } catch { policy.grantsPending = true; }
    if (hadEndpoints) await store.save().catch(() => {});
  }

  function eligibleEndpoint(exc, tabs) {
    if (!Number.isInteger(exc.tabId) || exc.tabId < 0) return false;
    const tab = tabs.find((t) => t.id === exc.tabId);
    const top = tab && hosts.hostOfUrl(tab.url || "");
    return Boolean(top && hosts.inSiteScope(top, exc.site));
  }

  async function saveEndpointRevocations(kept) {
    if (kept.length === store.exceptions.length) return;
    store.exceptions = kept;
    await store.save().catch((error) => { policy.warnings.push(`Local endpoint deletion failed: ${String(error.message || error)}. Consult the policy receipt for browser revocation status.`); });
  }

  async function revalidatePermissions(now, rollback, tabs) {
    const keepRules = [], keepExceptions = [];
    for (const rule of store.rules) {
      if (rule.expiresAt !== undefined && rule.expiresAt <= now) continue;
      if (rule.action === "allow" && (rollback || rule.expiresAt !== undefined && crossesIsolation(rule.site, rule.host, false) || await isThreat(rule.host))) continue;
      keepRules.push(rule);
    }
    for (const exc of store.exceptions) {
      if (!eligibleEndpoint(exc, tabs) || crossesIsolation(exc.site, exc.host, false) || rollback || exc.expiresAt <= now || (exc.createdAt !== undefined && exc.createdAt > now) || await isThreat(exc.host)) continue;
      keepExceptions.push(exc);
    }
    if (keepRules.length !== store.rules.length || keepExceptions.length !== store.exceptions.length) {
      // Revocation takes effect even if persistence fails. Startup revalidates again.
      store.rules = keepRules; store.exceptions = keepExceptions;
      await store.save().catch((error) => { policy.warnings.push(`Revocations could not be saved: ${String(error.message || error)}`); });
    }
    const nextModes = clone(modes);
    let changed = false;
    for (const [site, names] of Object.entries(nextModes.allowHosts)) {
      const keep = [];
      for (const name of names) if (!(await isThreat(name))) keep.push(name);
      if (keep.length !== names.length) { changed = true; if (keep.length) nextModes.allowHosts[site] = keep; else delete nextModes.allowHosts[site]; }
    }
    if (changed) {
      modes = nextModes;
      await saveModes().catch((error) => { modes = nextModes; policy.warnings.push(`Threat reclassification could not be saved: ${String(error.message || error)}`); });
    }
    if (rollback) {
      grants = []; pauses = {}; prewarmContexts.clear();
      policy.warnings.push("The system clock moved backwards; temporary permissions were revoked.");
      await savePauses().catch(() => { pauses = {}; });
    }
    let expiredPause = false;
    for (const [site, until] of Object.entries(pauses)) if (until <= now || modes.sites[site] === "isolated") { delete pauses[site]; expiredPause = true; }
    if (expiredPause) {
      const desired = clone(pauses);
      await savePauses().catch((error) => { pauses = desired; policy.warnings.push(`Expired pauses could not be saved: ${String(error.message || error)}`); });
    }
  }

  async function reconcile() {
    const D = C.declarativeNetRequest;
    const now = Date.now(), rollback = now < lastWall - 1000;
    lastWall = Math.max(lastWall, now);
    policy.state = "pending"; policy.error = null;
    const [tabs, currentDynamic, currentSession] = await Promise.all([readTabs(), D.getDynamicRules(), D.getSessionRules()]);
    const currentDigest = await digest(currentDynamic);
    if (applied && applied.dynamicDigest !== currentDigest) forgetDynamicReceipt();
    if (!applied && savedReceipt && savedReceipt.schema === 2 && savedReceipt.epoch === EPOCH &&
        savedReceipt.dynamicDigest === currentDigest) {
      applied = savedReceipt;
      policy.dynamicRevision = applied.revision;
      policy.topPartyCoverage = applied.preparationSchema === 1 ? (applied.preparationHold ? "closed-until-prepared" : "explicit-top-sites") : "unknown";
    }
    await revalidatePermissions(now, rollback, tabs);
    const validJournal = journal && journal.schema === 2 && journal.epoch === EPOCH && journal.phase === "applied" && !rollback &&
      Number.isFinite(journal.observedAt) && journal.observedAt <= now + 1000;
    if (!restoredSessions) {
      grants = []; endpointIds = {};
      const restored = [], usedEndpointIds = new Set();
      const groups = validJournal && Array.isArray(journal.endpoints) ? journal.endpoints : [];
      for (const exc of store.exceptions) {
        const group = groups.find((g) => g && g.id === exc.id && canonical(g.exception) === canonical(exc));
        if (!group || !Number.isInteger(group.ruleId) || group.ruleId < ENDPOINT_BASE || group.ruleId + 1 >= dnr.MODE_BASE ||
            group.ruleId % 2 !== 0 || usedEndpointIds.has(group.ruleId) || usedEndpointIds.has(group.ruleId + 1)) continue;
        const expected = dnr.compileUserState([], [exc], now, {firstId: group.ruleId}).rules;
        if (expected.length !== 2 || !expected.every((r) => currentSession.some((actual) => canonical(actual) === canonical(r)))) continue;
        restored.push(exc); endpointIds[exc.id] = group.ruleId;
        usedEndpointIds.add(group.ruleId); usedEndpointIds.add(group.ruleId + 1);
      }
      // No journal (fresh browser session), an interrupted intent, a missing rule
      // or a missing sanitation pair all require a fresh explicit repair action.
      await saveEndpointRevocations(restored);
      if (validJournal && Array.isArray(journal.entries)) {
        const ids = new Set();
        for (const entry of journal.entries.slice(0, MAX_GRANTS)) {
          if (!(await eligibleGrant(entry, tabs, now))) continue;
          const wanted = rulesForGrant(entry);
          if (wanted.some((r) => ids.has(r.id))) continue;
          // Never resurrect a missing/revoked grant from stale metadata. In-flight
          // intents and partially installed groups are discarded on worker restart.
          if (!wanted.every((r) => currentSession.some((actual) => canonical(actual) === canonical(r)))) continue;
          grants.push(entry); wanted.forEach((r) => ids.add(r.id));
        }
      }
      restoredSessions = true;
    } else {
      const keep = [];
      for (const entry of grants) if (await eligibleGrant(entry, tabs, now)) keep.push(entry);
      grants = keep;
    }
    const tabIdsBySite = {};
    for (const tab of tabs) {
      const host = hosts.hostOfUrl(tab.url || "");
      if (host && Number.isInteger(tab.id) && tab.id >= 0) (tabIdsBySite[host] ||= []).push(tab.id);
    }
    const activeSites = [...new Set(Object.keys(tabIdsBySite).map((h) => hosts.siteOf(h)).filter((site) => site && safelyScopedSite(site)))].sort();
    const requestedModes = clone(effectiveModes());
    const topSites = preparationCandidates(activeSites, requestedModes, now);
    const compiled = dnr.compileUserState(store.rules.filter((r) => r.action !== "allow"), [], now);
    const persistent = dnr.compileUserState(store.rules.filter((r) => r.action === "allow"), [], now, {firstId: PERSISTENT_ALLOW_BASE, tabIdsBySite});
    endpointIds = Object.fromEntries(store.exceptions.filter((exc) => Number.isInteger(endpointIds[exc.id])).map((exc) => [exc.id, endpointIds[exc.id]]));
    const usedEndpoints = new Set(Object.values(endpointIds).flatMap((id) => [id, id + 1]));
    const endpointRules = [], endpointGroups = [];
    for (const exc of store.exceptions) {
      if (!endpointIds[exc.id]) {
        let id = ENDPOINT_BASE;
        while (usedEndpoints.has(id) || usedEndpoints.has(id + 1)) id += 2;
        endpointIds[exc.id] = id; usedEndpoints.add(id); usedEndpoints.add(id + 1);
      }
      const ruleId = endpointIds[exc.id];
      const pair = dnr.compileUserState([], [exc], now, {firstId: ruleId, tabIdsBySite}).rules;
      if (pair.length !== 2) throw new Error("The source tab no longer matches the endpoint permission.");
      endpointRules.push(...pair);
      endpointGroups.push({id: exc.id, ruleId, exception: clone(exc)});
    }
    const siteModes = dnr.compileModes(requestedModes, {topSites});
    const hardeningRules = hardeningApi ? hardeningApi.compile({enabled: hardening.enabled, priority: dnr.PRIORITY.clientHints}) : [];
    const wantedDynamic = [...compiled.rules, ...siteModes.rules, ...hardeningRules];
    const wantedSession = [...grants.flatMap(rulesForGrant), ...persistent.rules, ...endpointRules];
    const snapshot = {schema: 2, epoch: EPOCH, modes: clone(modes), effectiveModes: requestedModes, pauses: clone(pauses), rules: store.snapshot(), topSites,
      preparationSchema: 1, preparationHold: siteModes.preparationHold, preparedSites: siteModes.preparedSites, privacyHardening: clone(hardening)};
    const revision = await digest({...snapshot, grants, dynamic: wantedDynamic, session: wantedSession});
    policy.desiredRevision = revision;
    checkQuota(wantedDynamic, wantedSession);

    // Revocations precede permission additions and dynamic changes. Unknown rules,
    // including rules from older extension versions, are removed unconditionally.
    const remove = currentSession.filter((old) => !wantedSession.some((r) => canonical(r) === canonical(old))).map((r) => r.id);
    if (remove.length) await D.updateSessionRules({removeRuleIds: remove});
    if (!sameRules(currentDynamic, wantedDynamic)) {
      await D.updateDynamicRules({removeRuleIds: currentDynamic.map((r) => r.id), addRules: wantedDynamic});
      // A successful mutation invalidates the old receipt immediately. If the
      // readback fails, neither old nor requested policy is attested as current.
      forgetDynamicReceipt();
    }
    const checkedDynamic = await D.getDynamicRules();
    if (!sameRules(checkedDynamic, wantedDynamic)) throw new Error("Chrome did not confirm the requested dynamic policy.");
    // Dynamic modes are independently confirmed even if a later session/storage step fails.
    applied = {...snapshot, revision, dynamicDigest: await digest(checkedDynamic), observedAt: now, clockHighWater: lastWall};
    policy.dynamicRevision = revision; policy.appliedRevision = null;
    policy.topPartyCoverage = siteModes.preparationHold ? "closed-until-prepared" : "explicit-top-sites";
    sources = compiled.sources; modeKinds = {...siteModes.kinds, ...Object.fromEntries(hardeningRules.map(rule => [rule.id, "client-hints"]))};
    allowIds = new Set(compiled.rules.filter((r) => r.action.type !== "block").map((r) => r.id));

    const intent = {schema: 2, epoch: EPOCH, phase: "intent", revision, observedAt: now, entries: clone(grants), endpoints: endpointGroups};
    await C.storage.session.set({[GRANT_KEY]: intent});
    policy.savedRevision = revision;
    const beforeAdd = await D.getSessionRules();
    if (!sameRules(beforeAdd, wantedSession)) await D.updateSessionRules({removeRuleIds: beforeAdd.map((r) => r.id), addRules: wantedSession});
    const checkedSession = await D.getSessionRules();
    if (!sameRules(checkedSession, wantedSession)) throw new Error("Chrome did not confirm the requested session permissions.");
    journal = {...intent, phase: "applied"};
    await C.storage.session.set({[GRANT_KEY]: journal});
    await C.storage.session.remove(["continues", "passes", "embeds"]); // superseded, never trusted for restoration
    applied = {...applied, sessionDigest: await digest(checkedSession)};
    await C.storage.local.set({[CONTROLLER_KEY]: applied});
    policy.appliedRevision = revision; policy.sessionRevision = revision; policy.state = "applied"; policy.error = null; policy.grantsPending = false;
    policy.warnings = [...new Set(policy.warnings)].slice(-20);
    await schedule();
  }

  async function apply() {
    try {
      if (!loaded) await loadState();
      await reconcile();
      for (const site of endedWhileAsleep.splice(0)) await broadcastSite(site);
    } catch (error) {
      noteError(error);
      await revokeSessionOnFailure();
      // If even loading preferences failed, strip legacy permissive dynamic rules;
      // retain blocks/headers. No unknown stored permission is trusted by default.
      if (!loaded) {
        try {
          const current = await C.declarativeNetRequest.getDynamicRules();
          const permissive = current.filter((r) => ["allow", "allowAllRequests"].includes(r.action.type));
          if (permissive.length) await C.declarativeNetRequest.updateDynamicRules({removeRuleIds: permissive.map((r) => r.id)});
        } catch { policy.grantsPending = true; }
      }
      await C.alarms.create(RECOVERY_ALARM, {delayInMinutes: 1, periodInMinutes: 1});
      throw error;
    }
  }
  function sync() { return serial(apply); }
  // Initialization never permanently poisons the message handlers. A recovery
  // alarm and the popup's Retry run the same idempotent reconciliation again.
  const ready = sync().catch(() => undefined);

  async function schedule() {
    await C.alarms.clear(ALARM);
    const now = Date.now();
    const times = [...store.rules, ...store.exceptions, ...grants].map((x) => x.expiresAt)
      .concat(Object.values(pauses), [...prewarmContexts.values()].map((entry) => entry.expiresAt)).filter((t) => Number.isFinite(t) && t > now);
    if (times.length) await C.alarms.create(ALARM, {when: Math.max(Math.min(...times), now + 1000)});
    await C.alarms.create(RECOVERY_ALARM, {delayInMinutes: 1, periodInMinutes: 1});
  }

  async function continues() { return grants.filter((entry) => entry.kind === "continue").map(clone); }
  const ruleIds = (entry) => rulesForGrant(entry).map((r) => r.id);
  async function changeGrantsNow(change) {
      if (!loaded) await loadState();
      const before = grants.map(clone);
      const next = change(before);
      const requested = next.filter((entry) => !before.some((old) => canonical(old) === canonical(entry)));
      if (next.length > MAX_GRANTS) throw new Error("Too many active temporary permissions.");
      grants = next;
      await apply();
      if (requested.some((entry) => !grants.some((actual) => canonical(actual) === canonical(entry)))) {
        throw new Error("The permission was refused: its tab or site mode changed, its deadline passed, or the provider is now a threat. Reload the page and review the request.");
      }
  }
  function changeGrants(change) { return serial(() => changeGrantsNow(change)); }
  async function dropEndpointsNow(test) {
    const kept = store.exceptions.filter((exc) => !test(exc));
    const changed = kept.length !== store.exceptions.length;
    if (!changed) return false;
    await saveEndpointRevocations(kept);
    await apply();
    return true;
  }
  function dropEndpoints(test) { return serial(() => dropEndpointsNow(test)); }

  const nextGrantId = (list, base, width = 1) => {
    const used = new Set(list.flatMap(ruleIds));
    let id = base;
    while (Array.from({length: width}, (_, i) => id + i).some((n) => used.has(n))) id += width;
    return id;
  };
  function addContinue(host, tabId) {
    return changeGrantsNow((list) => {
      const kept = list.filter((e) => !(e.kind === "continue" && e.tabId === tabId));
      return [...kept, {kind: "continue", id: nextGrantId(kept, CONTINUE_BASE, 2), host, tabId,
        createdAt: Date.now(), expiresAt: Date.now() + CONTINUE_MINUTES * 60000}];
    });
  }
  function dropContinues(test) { return changeGrants((list) => list.filter((e) => e.kind !== "continue" || !test(e))); }

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

  function retireTab(tabId) {
    if (!Number.isInteger(tabId) || tabId < 0) return Promise.resolve();
    // A page message or prewarm may already be waiting behind a slow rule API.
    // Final deletion must run after those earlier writers, in their same queue;
    // deleting synchronously in onRemoved lets them resurrect a retired context.
    return serial(async () => {
      knownTabs.delete(tabId);
      prewarmContexts.delete(tabId);
      logs.delete(tabId); carried.delete(tabId); counts.links.delete(tabId);
      await C.storage.session.remove([`log:${tabId}`, `nav:${tabId}`]).catch(() => {});
      await saveEndpointRevocations(store.exceptions.filter((entry) => entry.tabId !== tabId));
      grants = grants.filter((entry) => entry.tabId !== tabId);
      await apply();
    });
  }

  // ---- events (registered synchronously so they wake the worker) ----------------
  if (C.declarativeNetRequest.onRuleMatchedDebug) C.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => { onMatched(info).catch(() => {}); });
  if (C.declarativeNetRequest.setExtensionActionOptions) C.declarativeNetRequest.setExtensionActionOptions({displayActionCountAsBadgeText: true}).catch(() => {});
  if (C.action && C.action.setBadgeBackgroundColor) C.action.setBadgeBackgroundColor({color: "#19382e"}).catch(() => {});

  // Navigation events only prewarm named policy; they are not a network barrier.
  // The already-installed preparation hold handles requests that arrive first.
  // Prerender targets need not be visible to tabs.query for safe site preparation.
  if (C.webNavigation) {
    const prepareNavigation = (details) => {
      if (details && details.frameId === 0 && Number.isInteger(details.tabId) && details.tabId >= 0) return prewarm(details.url, details.tabId).catch(() => {});
    };
    for (const event of [C.webNavigation.onBeforeNavigate, C.webNavigation.onCommitted]) if (event) event.addListener(prepareNavigation, {url: [{schemes: ["http", "https"]}]});
    if (C.webNavigation.onTabReplaced) C.webNavigation.onTabReplaced.addListener((details) => {
      // The retired id is explicit; do not depend on a separate onRemoved event.
      if (details && Number.isInteger(details.replacedTabId) && details.replacedTabId >= 0) return retireTab(details.replacedTabId).catch(() => {});
      return sync().catch(() => {});
    });
  }

  C.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (typeof info.url === "string") {
      knownTabs.set(tabId, {id: tabId, url: info.url});
      const top = hosts.hostOfUrl(info.url);
      dropEndpoints((exc) => exc.tabId === tabId && !(top && hosts.inSiteScope(top, exc.site))).catch(() => {});
      // Same-document navigation need not change the DOM. The content script
      // re-reads its own location; no page-controlled URL is sent as authority.
      C.tabs.sendMessage(tabId, {type: "page-location"}).catch(() => {});
    }
    else if (tab && typeof tab.url === "string") knownTabs.set(tabId, {id: tabId, url: tab.url});
    if (info.status === "loading") resetTab(tabId, (tab && tab.url) || info.url).catch(() => {});
    // A loaded embed is for that page only.
    if (info.status === "loading") dropEmbeds(tabId).catch(() => {});
    if (typeof info.url === "string" && !info.url.startsWith(OWN)) {
      // A "continue once" exception ends when the tab leaves the host it was granted for.
      const host = hosts.hostOfUrl(info.url);
      dropContinues((c) => c.tabId === tabId && host !== c.host).catch(() => {});
      // A scanner pass is for one navigation: once the tab commits any web address (the scanner itself, normally), it is used.
      dropPasses((x) => x.tabId === tabId).catch(() => {});
    }
    if (typeof info.url === "string" || info.status === "loading") sync().catch(() => {});
  });
  C.tabs.onRemoved.addListener((tabId) => retireTab(tabId).catch(() => {}));
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
    if (alarm.name !== ALARM && alarm.name !== RECOVERY_ALARM) return;
    await ready;
    const before = applied ? Object.keys(applied.pauses) : [];
    await sync().catch(() => {});
    if (policy.state === "applied") {
      for (const site of before) if (!pausedUntil(site)) await broadcastSite(site);
      await broadcast();
    }
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
    // A paused site gets no cosmetic rules (its hidden elements come back); its rules return when the pause ends.
    C.tabs.sendMessage(tabId, {type: "rules-changed", rules: pausedUntil(hosts.siteOf(host)) ? [] : store.activeFor(host).cosmeticRules.map(plain)}).catch(() => {});
  }
  /** A pause started or ended: that site's open pages update hiding, ad-slot hiding and link cleaning at once. */
  async function broadcastSite(site) {
    const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
    for (const tab of tabs) {
      const host = hosts.hostOfUrl(tab.url);
      if (!host || hosts.siteOf(host) !== site) continue;
      broadcastTab(tab.id, host);
      C.tabs.sendMessage(tab.id, {type: "generic", on: !genericOff.has(site) && !pausedUntil(site)}).catch(() => {});
      C.tabs.sendMessage(tab.id, {type: "clean-enabled", on: cleaningOn(site)}).catch(() => {});
    }
  }
  async function broadcast() {
    const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
    for (const tab of tabs) { const host = hosts.hostOfUrl(tab.url); if (host) broadcastTab(tab.id, host); }
  }

  function listsSummary() {
    return Object.entries(LISTS.lists || {}).map(([id, meta]) => ({id, ...meta}));
  }

  async function handleMessage(message, sender) {
    await ready;
    if (!message || typeof message !== "object") return {error: "Bad message."};
    if (sender.id !== C.runtime.id) return {error: "Unknown sender."};
    if ((!loaded || !restoredSessions) && message.type !== "popup-state" && message.type !== "retry-policy") await apply();
    if (sender.tab && Number.isInteger(sender.tab.id) && sender.frameId === 0 && typeof sender.url === "string") knownTabs.set(sender.tab.id, {id: sender.tab.id, url: sender.url});
    const pageHost = senderTopHost(sender);
    switch (message.type) {
      case "page-rules":
        if (!pageHost) return {rules: []};
        if (pausedUntil(hosts.siteOf(pageHost))) return {site: hosts.siteOf(pageHost), rules: [], generic: false};
        return {site: hosts.siteOf(pageHost), rules: store.activeFor(pageHost).cosmeticRules.map(plain), generic: !genericOff.has(hosts.siteOf(pageHost))};
      case "add-cosmetic": {
        if (!pageHost) return {error: "Not a page."};
        const result = await attempt(() => store.addRule({kind: "cosmetic", site: hosts.siteOf(pageHost), selector: message.selector, note: "Added with Block this element"}));
        if (!result.error) await afterChange();
        return result;
      }
      case "undo-cosmetic": {
        const rule = store.rules.find((r) => r.id === message.id);
        if (!pageHost || !rule || rule.kind !== "cosmetic" || !hosts.inSiteScope(pageHost, rule.site)) return {error: "No such rule."};
        await store.removeRule(rule.id); await afterChange();
        return {ok: true};
      }
      case "guard-config": {
        if (!pageHost) return {clean: false};
        const mode = modeFor(hosts.siteOf(pageHost), pageHost);
        return {clean: cleaningOn(hosts.siteOf(pageHost)), mode, embeds: mode === "strict" || mode === "noscript" ? dnr.EMBEDS.map((e) => ({id: e.id, name: e.name, domains: [...e.domains]})) : []};
      }
      case "cosmetic-style": {
        if (!pageHost || typeof message.on !== "boolean" || !C.scripting || !root.EGCosmeticList) return {error: "Cosmetic stylesheet is unavailable."};
        const details = {target: {tabId: sender.tab.id, frameIds: [0]}, css: root.EGCosmeticList.stylesheet(), origin: "USER"};
        if (message.on) await C.scripting.insertCSS(details); else await C.scripting.removeCSS(details);
        return {ok: true, on: message.on};
      }
      case "load-embed": {
        if (!pageHost || !sender.tab || !Number.isInteger(sender.tab.id)) return {error: "Not a page."};
        const provider = dnr.EMBEDS.find((e) => e.id === message.embed);
        if (!provider) return {error: "Bad message."};
        if (provider.domains.some((name) => crossesIsolation(hosts.siteOf(pageHost), name))) return {error: ISOLATION_REPAIR_ERROR};
        await loadEmbed(message.embed, sender.tab.id, message.cookies === true, hosts.siteOf(pageHost));
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
      case "retry-policy": {
        await apply(); await broadcast();
        return {ok: true, policy: {...policy}, coverage: LISTS.coverage || {complete: false, missing: ["build metadata"]}};
      }
      case "prepare-strict-site": {
        if (!Number.isInteger(message.tabId) || message.tabId < 0 || typeof message.tabUrl !== "string") return {error: "Open a web page first."};
        const tab = (await readTabs()).find((entry) => entry.id === message.tabId);
        if (!tab || tab.url !== message.tabUrl) return {error: "The tab changed. Reopen the popup before preparing this site."};
        const host = hosts.hostOfUrl(tab.url), site = hosts.siteOf(host);
        if (!preparedHostScope(site, host)) return {error: "This address cannot be prepared safely with Chrome's domain conditions.", preparation: preparationForUrl(tab.url)};
        // The actual open tab is already an authoritative preparation context;
        // this manual action creates no persistent or inactive-site permission.
        await apply();
        const preparation = preparationFor(site, host);
        if (preparation.state !== "prepared") return {error: "Strict site policy was not confirmed. Consult the policy receipt.", preparation};
        return {ok: true, preparation};
      }
      case "popup-state": {
        const host = hosts.hostOfUrl(message.tabUrl);
        const lists = listsSummary();
        if (!host) return {site: null, lists, policy: {...policy}, preparation: preparationForUrl(message.tabUrl), coverage: LISTS.coverage || {complete: false, missing: ["build metadata"]},
          mode: modeFor(null), siteMode: null, defaultMode: applied ? applied.modes.defaultMode : "unknown", requestedMode: modes.defaultMode, requestedDefaultMode: modes.defaultMode};
        const now = Date.now();
        const active = store.activeFor(host);
        const report = await blockedReport(message.tabId);
        return {
          host, site: hosts.siteOf(host), lists, ...report, generic: !genericOff.has(hosts.siteOf(host)),
          rebuilt: Boolean((await C.storage.session.get("rebuilt").catch(() => ({}))).rebuilt),
          requestRules: active.requestRules.map(plain), cosmeticRules: active.cosmeticRules.map(plain),
          exceptions: active.exceptions.filter((e) => e.tabId === message.tabId).map((e) => ({...e, msLeft: Math.max(0, e.expiresAt - now)})),
          types: rulesApi.RESOURCE_TYPES,
          categories: Object.fromEntries(Object.entries(dnr.CATEGORIES).filter(([, v]) => v.label).map(([k, v]) => [k, v.label])),
          policy: {...policy}, coverage: LISTS.coverage || {complete: false, missing: ["build metadata"]},
          preparation: preparationFor(hosts.siteOf(host), host),
          isolation: isolationFor(hosts.siteOf(host), host),
          mode: modeFor(hosts.siteOf(host), host), siteMode: applied ? applied.modes.sites[hosts.siteOf(host)] || null : null, defaultMode: applied ? applied.modes.defaultMode : "unknown",
          requestedMode: savedModeFor(hosts.siteOf(host)), requestedDefaultMode: modes.defaultMode,
          paused: pausedUntil(hosts.siteOf(host)), resumeMode: savedModeFor(hosts.siteOf(host)),
          strictAllowed: [...(applied && applied.modes.allowHosts[hosts.siteOf(host)] || [])],
          scannedDirect: modes.scannedDirect,
          cleaning: {on: cleaningOn(hosts.siteOf(host)), links: await countsReady.then(() => counts.links.get(message.tabId) || 0),
            cookies: counts.cookies.get(hosts.siteOf(host)) || 0},
        };
      }
      case "set-clean": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        if (!site || !hosts.canScopeSite(site) || typeof message.on !== "boolean") return {error: "Bad message."};
        const off = new Set(modes.cleanOff);
        if (message.on) off.delete(site); else if (off.size < MAX_MODE_SITES) off.add(site); else return {error: "Too many sites."};
        modes.cleanOff = [...off].sort();
        await saveModes(); await apply();
        const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
        for (const t of tabs) if (hosts.siteOf(hosts.hostOfUrl(t.url) || "") === site) C.tabs.sendMessage(t.id, {type: "clean-enabled", on: message.on}).catch(() => {});
        return {ok: true, on: message.on};
      }
      case "copy-clean": return copyClean(message.url, message.tabUrl);
      case "pause-site": case "resume-site": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        if (!site || !hosts.canScopeSite(site)) return {error: "Open a web page with a safely scoped registrable site first."};
        if (message.type === "pause-site") {
          if (isolationSelected(site)) return {error: "Isolation cannot be paused. Choose another site mode explicitly to relax it."};
          // Fixed length; a running pause is not extended (Resume, then Pause again, starts a new one).
          if (requestedPausedUntil(site)) return {error: "This site is already paused.", until: requestedPausedUntil(site)};
          await endPauses();
          if (Object.keys(pauses).length >= MAX_PAUSES) return {error: "Too many sites are paused."};
          pauses[site] = Date.now() + PAUSE_MINUTES * 60000;
        } else {
          if (!(site in pauses)) return {ok: true, site, until: null};
          delete pauses[site];
        }
        await savePauses(); await apply(); await broadcastSite(site);
        return {ok: true, site, until: pausedUntil(site)};
      }
      case "set-scanned-direct": {
        if (typeof message.on !== "boolean") return {error: "Bad message."};
        modes.scannedDirect = message.on;
        await saveModes(); await apply();
        return {ok: true, on: modes.scannedDirect};
      }
      case "set-mode": {
        const host = hosts.hostOfUrl(message.tabUrl), site = hosts.siteOf(host || "");
        if (!site || !hosts.canScopeSite(site)) return {error: "Open a web page with a safely scoped registrable site first."};
        if (message.mode !== "default" && !dnr.SITE_MODES.includes(message.mode)) return {error: "Bad message."};
        if (message.mode === "isolated" && !preparedHostScope(site, host)) return {error: "This address cannot be isolated safely with Chrome's domain conditions."};
        if (message.mode === "default") delete modes.sites[site];
        else if (Object.keys(modes.sites).length >= MAX_MODE_SITES && !modes.sites[site]) return {error: "Too many sites have their own mode."};
        else modes.sites[site] = message.mode;
        await saveModes({clearPauseSite: message.mode === "isolated" ? site : null}); await apply();
        // Rules cannot see what a service worker answers from its cache: clear the site's workers and caches.
        const mode = modeFor(site);
        const cleared = mode === "noscript" || mode === "strict" ? await clearWorkers(site).catch(() => ({ok: false, origins: []})) : null;
        await broadcastSite(site);
        return {ok: true, site, mode, cleared, isolation: isolationFor(site, host)};
      }
      case "set-default-mode": {
        if (message.mode !== "standard" && message.mode !== "strict") return {error: "Bad message."};
        modes.defaultMode = message.mode;
        await saveModes(); await apply();
        return {ok: true, defaultMode: modes.defaultMode};
      }
      case "strict-allow": case "strict-unallow": {
        const site = hosts.siteOf(hosts.hostOfUrl(message.tabUrl) || "");
        const target = hosts.normalizeHost(message.host);
        if (!site || !hosts.canScopeSite(site) || !target || hosts.isSuffixLike(target)) return {error: "Choose a hostname below a public suffix."};
        if (message.type === "strict-allow" && crossesIsolation(site, target)) return {error: ISOLATION_REPAIR_ERROR};
        if (message.type === "strict-allow" && !modes.allowHosts[site] && Object.keys(modes.allowHosts).length >= MAX_MODE_SITES) return {error: "Too many sites have allowed hosts."};
        if (message.type === "strict-allow" && await isThreat(target)) return {error: "This host is on the malware and phishing list; it cannot be allowed from here."};
        const list = new Set(modes.allowHosts[site] || []);
        if (message.type === "strict-allow") { if (list.size >= MAX_ALLOWED_HOSTS) return {error: "Too many allowed hosts for this site."}; list.add(target); }
        else list.delete(target);
        if (list.size) modes.allowHosts[site] = [...list].sort(); else delete modes.allowHosts[site];
        await saveModes(); await apply();
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
        if (!site || !hosts.canScopeSite(site)) return {error: "Open a web page with a safely scoped registrable site first."};
        if (typeof message.on !== "boolean") return {error: "Bad message."};
        const next = new Set(genericOff);
        if (message.on) next.delete(site);
        else if (next.size < MAX_GENERIC_OFF) next.add(site);
        else return {error: "Too many sites have ad-slot hiding switched off."};
        await C.storage.local.set({[GENERIC_KEY]: [...next].sort()});
        genericOff = next;
        const tabs = await C.tabs.query({url: ["http://*/*", "https://*/*"]});
        for (const tab of tabs) {
          if (hosts.siteOf(hosts.hostOfUrl(tab.url) || "") === site) C.tabs.sendMessage(tab.id, {type: "generic", on: message.on}).catch(() => {});
        }
        return {ok: true, site, on: message.on};
      }
      case "add-exception": {
        const host = hosts.hostOfUrl(message.tabUrl);
        if (!host) return {error: "Open a web page first."};
        if (!Number.isInteger(message.tabId) || message.tabId < 0) return {error: "An endpoint repair needs its source tab."};
        const source = (await readTabs()).find((tab) => tab.id === message.tabId);
        if (!source || !hosts.inSiteScope(hosts.hostOfUrl(source.url || ""), hosts.siteOf(host))) return {error: "The source tab changed. Reload the popup before allowing this resource."};
        if (message.resourceType === "main_frame") return {error: "Navigations are allowed with Continue on the warning page."};
        const target = hosts.normalizeHost(message.host);
        if (target && await isThreat(target)) return {error: "This host is on the malware and phishing list; it cannot be allowed from here."};
        const site = hosts.siteOf(host);
        if (target && crossesIsolation(site, target)) return {error: ISOLATION_REPAIR_ERROR};
        const manual = store.rules.find((r) => r.kind === "request" && r.action === "block" && r.host === target && hosts.inSiteScope(host, r.site) &&
          r.types.some((type) => (dnr.TYPE_MAP[type] || []).some((mapped) => (dnr.EXCEPTION_TYPE_MAP[message.resourceType] || []).includes(mapped))) &&
          new RegExp(dnr.endpointRegex(r.host, r.path)).test(`https://${target}${message.path}`) &&
          (r.party === "any" || !r.party || (r.party === "third") === hosts.isThirdParty(target, site)));
        if (manual) return {error: "Your manual block still denies this endpoint. Remove that block explicitly before allowing the resource."};
        const minutes = Math.min(message.minutes, EXCEPTION_MINUTES_MAX);
        const result = await attempt(() => store.addException({site: hosts.siteOf(host), host: message.host, path: message.path, type: message.resourceType, minutes, tabId: message.tabId}));
        if (!result.error) {
          await afterChange();
          if (!store.exceptions.some((exc) => exc.id === result.value.id)) return {error: "The source tab changed or the permission was revoked before it could be applied."};
        }
        return result;
      }
      case "remove-exception": { const ok = await dropEndpointsNow((exc) => exc.id === message.id); if (ok) await broadcast(); return {ok}; }
      default: return {error: "Unknown message."};
    }
  }

  async function handlePrivacy(message, sender) {
    if (!sender || sender.id !== C.runtime.id || sender.url !== `${OWN}privacy.html` || sender.frameId !== 0) return {error: "Browser privacy controls are available only from their settings page."};
    if (message.type.startsWith("browser-privacy-hardening-")) {
      const allowedKeys = message.type === "browser-privacy-hardening-apply" ? ["type", "enabled"] : ["type"];
      if (Object.keys(message).some(key => !allowedKeys.includes(key))) return {error: "Client Hints messages accept only their fixed control choice."};
      switch (message.type) {
        case "browser-privacy-hardening-status": return serial(hardeningStatus);
        case "browser-privacy-hardening-apply": return serial(() => setHardeningNow(message.enabled));
        case "browser-privacy-hardening-retry": return serial(retryHardeningNow);
        case "browser-privacy-hardening-release": return serial(() => setHardeningNow(false));
        default: return {error: "Unknown Client Hints message."};
      }
    }
    if (!browserPrivacy) return {error: "Browser privacy controls are unavailable."};
    switch (message.type) {
      case "browser-privacy-status": return browserPrivacy.status();
      case "browser-privacy-apply": return browserPrivacy.apply(message.selected);
      case "browser-privacy-retry": return browserPrivacy.retry();
      case "browser-privacy-release": return browserPrivacy.release();
      default: return {error: "Unknown browser privacy message."};
    }
  }

  function handle(message, sender) {
    // Separate authority and queue: DNR/storage recovery cannot block the exact
    // extension-owned privacy page's independent profile-control receipt.
    if (message && typeof message.type === "string" && message.type.startsWith("browser-privacy-")) return handlePrivacy(message, sender);
    // One queue owns all intent mutations and reconciliation. An event cannot
    // publish a half-saved message preference or overwrite a simultaneous edit.
    return serial(() => handleMessage(message, sender));
  }

  async function attempt(fn) {
    try { const value = await fn(); return {ok: true, value: plain(value)}; } catch (error) {
      if (error instanceof rulesApi.RuleError) return {error: error.message};
      throw error;
    }
  }

  async function afterChange() { await apply(); await broadcast(); }

  // Chrome's onMessage needs sendResponse + `return true` for async replies.
  C.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handle(message, sender).then(sendResponse, (error) => sendResponse({error: String(error && error.message || error)}));
    return true;
  });
  root.__EGBackground = Object.freeze({store, ready, handle, sync, onMatched, tabLog, continues, reloadIfRebuilt, onCookie, copyClean, cleanLink, counts, get sources() { return sources; }, get pauses() { return {...pauses}; }, get policy() { return {...policy}; }, get grants() { return grants.map(clone); }});
})(globalThis);
