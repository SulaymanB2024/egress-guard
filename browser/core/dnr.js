/* Chrome declarativeNetRequest compiler. Pure: no browser APIs.
 *
 * Two jobs, one priority ladder:
 *   - compileList(): build-time. Turns verified domain lists into static rulesets.
 *   - compileUserState(): run time. Turns validated user rules and exceptions into dynamic rules.
 *
 * Priority ladder (higher wins; within one extension allow beats block at equal priority):
 *   1 params        strip tracking parameters from navigations (redirect)
 *   2 threat        malware/phishing: navigation -> local warning page, everything else blocked
 *   3 continue      "continue once" from the warning page: session `allow` rules for one tab and one host, its
 *                   navigation and its own requests. Never allowAllRequests, which would lift every lower-priority
 *                   rule (other threat hosts included) for the whole frame tree.
 *   4 list          ad/tracker and CNAME-cloaked tracker lists
 *   5 user block    endpoint rules added in the popup
 *   6 user allow    endpoint allow rules
 *   7 exception     timed exceptions; beat every list and rule above
 * "continue" sits below "list" on purpose: continuing to a flagged site does not unblock its trackers. */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;
  const hosts = isNode ? require("./hosts.js") : root.EGHosts;

  const PRIORITY = Object.freeze({params: 1, threat: 2, continue: 3, list: 4, userBlock: 5, userAllow: 6, exception: 7});

  // Every Chrome resource type except main_frame. Lists never stop a top-level navigation;
  // threat navigations are redirected to the warning page instead.
  const SUBRESOURCE_TYPES = Object.freeze(["sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest",
    "ping", "csp_report", "media", "websocket", "webtransport", "webbundle", "other"]);

  // Core (Firefox webRequest) type -> Chrome DNR types. Chrome reports beacons as "ping".
  const TYPE_MAP = Object.freeze({
    beacon: ["ping"], ping: ["ping"], xmlhttprequest: ["xmlhttprequest"], script: ["script"], image: ["image"],
    imageset: ["image"], stylesheet: ["stylesheet"], font: ["font"], media: ["media"], sub_frame: ["sub_frame"],
    object: ["object"], csp_report: ["csp_report"], other: ["other", "websocket", "webtransport", "webbundle"],
  });
  // Chrome type -> type shown in the popup. Web sockets, web transport and web bundles keep their own names: they are not
  // rule types, so the popup offers no exception for them, and an "other" exception never covers them.
  const CHROME_TO_CORE = Object.freeze({ping: "ping", xmlhttprequest: "xmlhttprequest", script: "script", image: "image",
    stylesheet: "stylesheet", font: "font", media: "media", sub_frame: "sub_frame", object: "object", csp_report: "csp_report",
    websocket: "websocket", webtransport: "webtransport", webbundle: "webbundle", other: "other"});
  // Exceptions open exactly the type that was shown.
  const EXCEPTION_TYPE_MAP = Object.freeze({...TYPE_MAP, other: ["other"]});

  // Click and campaign identifiers that carry no page content. Exact names only: DNR removeParams has no wildcards.
  // Kept on purpose: mkt_tok (Marketo), _hsenc and _hsmi (HubSpot), which unsubscribe and preference links need.
  const TRACKING_PARAMS = Object.freeze([
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id", "utm_name", "utm_cid",
    "utm_reader", "utm_referrer", "utm_social", "utm_social-type", "utm_brand", "utm_place", "utm_pubreferrer", "utm_swu",
    "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "twclid", "ttclid", "igshid",
    "li_fat_id", "mc_eid", "oly_anon_id", "oly_enc_id", "vero_id", "rb_clickid",
    "s_cid", "wickedid", "epik", "_openstat", "srsltid",
  ]);

  const LIST_KINDS = Object.freeze({
    threats: {label: "Malware and phishing", priority: PRIORITY.threat},
    trackers: {label: "Ads and trackers", priority: PRIORITY.list},
    cname: {label: "Disguised trackers", priority: PRIORITY.list},
  });
  const DEFAULT_CHUNK = 25000;

  const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  /** Glob path ("*" = any run of characters) -> anchored URL regex for one exact host. */
  function endpointRegex(host, pathPattern) {
    const path = pathPattern.split("*").map(escapeRegex).join("[^?#]*");
    return `^https?://${escapeRegex(host)}(?::[0-9]+)?${path}(?:[?#].*)?$`;
  }

  /** Drop any domain whose parent domain is also listed: DNR requestDomains already covers subdomains. */
  function minimize(domains) {
    const set = new Set(domains);
    const out = [];
    for (const name of set) {
      const labels = name.split(".");
      let covered = false;
      for (let i = 1; i < labels.length - 1 && !covered; i++) covered = set.has(labels.slice(i).join("."));
      if (!covered) out.push(name);
    }
    return out.sort();
  }

  function chunks(items, size) {
    const out = [];
    for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
    return out;
  }

  /**
   * Static ruleset for one list. `warningUrl` (chrome-extension://<id>/warning.html) is required for threats:
   * a threat navigation is redirected there with the blocked URL after "#".
   */
  function compileList(kind, domains, {chunk = DEFAULT_CHUNK, warningUrl = null} = {}) {
    const info = LIST_KINDS[kind];
    if (!info) throw new Error(`unknown list ${kind}`);
    if (!Number.isInteger(chunk) || chunk < 1) throw new Error("chunk must be a positive integer");
    const names = minimize(domains);
    const rules = [];
    let id = 1;
    for (const part of chunks(names, chunk)) {
      rules.push({id: id++, priority: info.priority, action: {type: "block"},
        condition: {requestDomains: part, resourceTypes: [...SUBRESOURCE_TYPES]}});
      if (kind === "threats") {
        if (!/^chrome-extension:\/\/[a-p]{32}\/warning\.html$/.test(warningUrl || "")) throw new Error("threats need the extension's warning page URL");
        rules.push({id: id++, priority: info.priority,
          action: {type: "redirect", redirect: {regexSubstitution: `${warningUrl}?list=${kind}#\\0`}},
          condition: {requestDomains: part, regexFilter: "^https?://.*$", resourceTypes: ["main_frame"]}});
      }
    }
    return {rules, domains: names.length};
  }

  /**
   * Static ruleset that strips tracking parameters from page and frame navigations. One plain urlFilter
   * rule per parameter ("?name=" and "&name="), each removing the whole set: a single regex with every
   * name exceeds Chrome's compiled-regex size limit and is silently dropped.
   */
  function compileParams() {
    const action = {type: "redirect", redirect: {transform: {queryTransform: {removeParams: [...TRACKING_PARAMS]}}}};
    const out = [];
    let id = 1;
    for (const name of TRACKING_PARAMS) {
      for (const sep of ["?", "&"]) {
        out.push({id: id++, priority: PRIORITY.params, action,
          condition: {urlFilter: `${sep}${name}=`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame", "sub_frame"]}});
      }
    }
    return out;
  }

  const live = (item, now) => item.expiresAt === undefined || item.expiresAt > now;
  const chromeTypes = (types, map = TYPE_MAP) => [...new Set(types.flatMap((t) => map[t] || []))].sort();

  /**
   * Dynamic rules for the user's request rules and live exceptions.
   * Returns {rules, sources}: `sources` maps each DNR id to the store id it came from (for the popup log).
   */
  function compileUserState(rules, exceptions, now, {firstId = 1} = {}) {
    const out = [];
    const sources = {};
    let id = firstId;
    const push = (sourceId, priority, actionType, site, host, path, types, party, map) => {
      const condition = {regexFilter: endpointRegex(host, path), isUrlFilterCaseSensitive: true, requestDomains: [host],
        initiatorDomains: [site], resourceTypes: chromeTypes(types, map)};
      if (party === "first") condition.domainType = "firstParty";
      if (party === "third") condition.domainType = "thirdParty";
      sources[id] = sourceId;
      out.push({id: id++, priority, action: {type: actionType}, condition});
    };
    for (const rule of rules) {
      if (rule.kind !== "request" || !live(rule, now)) continue;
      const allow = rule.action === "allow";
      push(rule.id, allow ? PRIORITY.userAllow : PRIORITY.userBlock, allow ? "allow" : "block", rule.site, rule.host, rule.path, rule.types, rule.party);
    }
    for (const exc of exceptions) {
      if (!live(exc, now)) continue;
      push(exc.id, PRIORITY.exception, "allow", exc.site, exc.host, exc.path, [exc.type], undefined, EXCEPTION_TYPE_MAP);
    }
    return {rules: out, sources};
  }

  /**
   * Session rules for "continue once" (ids `id` and `id + 1`), below the tracker lists: in one tab, the navigation to
   * one host, and requests to that host made by that host itself. Plain `allow`, so other threat-listed hosts the page
   * pulls in stay blocked.
   */
  function continueRules(id, host, tabId) {
    const name = hosts.normalizeHost(host);
    if (!name || !Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(id) || id < 1) throw new Error("continue needs a host and a tab");
    return [
      {id, priority: PRIORITY.continue, action: {type: "allow"},
        condition: {requestDomains: [name], resourceTypes: ["main_frame"], tabIds: [tabId]}},
      {id: id + 1, priority: PRIORITY.continue, action: {type: "allow"},
        condition: {requestDomains: [name], initiatorDomains: [name], resourceTypes: [...SUBRESOURCE_TYPES], tabIds: [tabId]}},
    ];
  }

  /** Parse the warning page's location (…/warning.html?list=threats#<blocked URL>). */
  function parseWarning(href) {
    let url;
    try { url = new URL(href); } catch { return null; }
    const list = url.searchParams.get("list");
    const blocked = url.hash.slice(1);
    let target;
    try { target = new URL(blocked); } catch { return null; }
    if (target.protocol !== "http:" && target.protocol !== "https:") return null;
    const host = hosts.normalizeHost(target.hostname);
    if (!host) return null;
    return {list: LIST_KINDS[list] ? list : "threats", url: target.href, host};
  }

  /** Chrome extension id for a manifest "key" (base64 DER public key): sha256 -> first 32 hex -> a..p. */
  function extensionIdFromHex(sha256Hex) {
    return [...sha256Hex.slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  }

  const api = Object.freeze({PRIORITY, SUBRESOURCE_TYPES, TYPE_MAP, CHROME_TO_CORE, EXCEPTION_TYPE_MAP, TRACKING_PARAMS, LIST_KINDS, DEFAULT_CHUNK,
    endpointRegex, minimize, compileList, compileParams, compileUserState, continueRules, parseWarning, extensionIdFromHex});
  if (isNode) module.exports = api;
  else root.EGDnr = api;
})(globalThis);
