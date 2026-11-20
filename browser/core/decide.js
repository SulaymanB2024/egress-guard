/* Request decisions. Pure: no browser APIs.
 *
 * Input is the trusted request description an adapter builds from browser data
 * (Firefox webRequest details today; a Chrome DNR compiler or native-messaging
 * adapter later). Page content never reaches this module. */
(function (root) {
  "use strict";
  const hosts = typeof module !== "undefined" && module.exports ? require("./hosts.js") : root.EGHosts;

  /** Glob match where "*" matches any run of characters. Two-pointer algorithm, no RegExp; inputs are bounded. */
  function pathMatches(pattern, path) {
    let p = 0, s = 0, star = -1, mark = 0;
    while (s < path.length) {
      if (p < pattern.length && pattern[p] !== "*" && pattern[p] === path[s]) { p++; s++; }
      else if (p < pattern.length && pattern[p] === "*") { star = p++; mark = s; }
      else if (star >= 0) { p = star + 1; s = ++mark; }
      else return false;
    }
    while (p < pattern.length && pattern[p] === "*") p++;
    return p === pattern.length;
  }

  /**
   * Top-level page URL from trusted Firefox webRequest fields, in priority order.
   * `tabTopUrl` is the adapter's record of the tab's last main_frame request (also browser data).
   */
  function topLevelUrl(details, tabTopUrl) {
    if (details.type === "main_frame") return details.url;
    if (Array.isArray(details.frameAncestors) && details.frameAncestors.length) {
      return details.frameAncestors[details.frameAncestors.length - 1].url;
    }
    if (details.frameId === 0 && typeof details.documentUrl === "string") return details.documentUrl;
    return typeof tabTopUrl === "string" ? tabTopUrl : null;
  }

  /** Normalize a request into {host, path, type, topHost, thirdParty} or null when out of scope. */
  function describe({url, type, topUrl}) {
    let parsed;
    try { parsed = new URL(url); } catch { return null; }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:" && parsed.protocol !== "ws:" && parsed.protocol !== "wss:") return null;
    const host = hosts.normalizeHost(parsed.hostname);
    if (!host) return null;
    const topHost = hosts.hostOfUrl(topUrl);
    return {host, path: parsed.pathname || "/", type, topHost, thirdParty: topHost ? hosts.isThirdParty(host, topHost) : null};
  }

  const live = (item, now) => item.expiresAt === undefined || item.expiresAt > now;

  function ruleMatches(rule, req) {
    if (rule.kind !== "request" || !hosts.withinScope(req.topHost, rule.site)) return false;
    if (rule.host !== req.host || !rule.types.includes(req.type) || !pathMatches(rule.path, req.path)) return false;
    if (rule.party === "first" && req.thirdParty) return false;
    if (rule.party === "third" && !req.thirdParty) return false;
    return true;
  }

  function exceptionMatches(exc, req) {
    return hosts.withinScope(req.topHost, exc.site) && exc.host === req.host && exc.type === req.type && exc.path === req.path;
  }

  /**
   * Decide one request. Order: out of scope -> allow; navigation -> allow; unknown top-level -> allow;
   * live exception -> allow; allow rule -> allow; block rule -> block; otherwise allow.
   * Returns {action, reason, id?, req?}.
   */
  function decide(request, rules, exceptions, now) {
    if (request.type === "main_frame") return {action: "allow", reason: "navigation"};
    const req = describe(request);
    if (!req) return {action: "allow", reason: "out-of-scope"};
    if (!req.topHost) return {action: "allow", reason: "no-top-level-site", req};
    const exc = exceptions.find((item) => live(item, now) && exceptionMatches(item, req));
    if (exc) return {action: "allow", reason: "exception", id: exc.id, req};
    const matching = rules.filter((rule) => live(rule, now) && ruleMatches(rule, req));
    const allow = matching.find((rule) => rule.action === "allow");
    if (allow) return {action: "allow", reason: "allow-rule", id: allow.id, req};
    const block = matching.find((rule) => rule.action === "block");
    if (block) return {action: "block", reason: "block-rule", id: block.id, req};
    return {action: "allow", reason: "no-rule", req};
  }

  const api = Object.freeze({pathMatches, topLevelUrl, describe, decide});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGDecide = api;
})(globalThis);
