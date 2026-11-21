/* Hostname and site boundaries using the complete, packaged Public Suffix List.
 * Pure: no browser APIs or network. Exact, wildcard and exception rules include
 * both ICANN registries and private hosting platforms. */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;
  const psl = isNode ? require("./psl-data.js") : root.EGPSL;
  if (!psl || !psl.rules || !psl.metadata) throw new Error("The packaged Public Suffix List is missing.");
  const exact = new Set(), wildcard = new Set(), exceptions = new Set();
  for (const rule of psl.rules.split("\n")) {
    if (rule.startsWith("!")) exceptions.add(rule.slice(1));
    else if (rule.startsWith("*.")) wildcard.add(rule.slice(2));
    else exact.add(rule);
  }
  const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

  /** Lowercased ASCII hostname, or null. IP literals and single labels are refused. */
  function normalizeHost(value) {
    if (typeof value !== "string") return null;
    let host = value.trim().toLowerCase();
    if (host.endsWith(".")) host = host.slice(0, -1);
    if (!host || host.length > 253) return null;
    const labels = host.split(".");
    if (labels.length < 2 || !labels.every((label) => LABEL.test(label))) return null;
    if (/^[0-9]+$/.test(labels[labels.length - 1])) return null;
    return host;
  }

  /** Length of the prevailing PSL rule; the implicit '*' covers unknown TLDs. */
  function suffixLength(labels) {
    let length = 1;
    for (let i = 0; i < labels.length; i++) {
      const tail = labels.slice(i).join(".");
      if (exceptions.has(tail)) return labels.length - i - 1;
      if (exact.has(tail)) length = Math.max(length, labels.length - i);
      if (i > 0 && wildcard.has(tail)) length = Math.max(length, labels.length - i + 1);
    }
    return length;
  }

  function publicSuffix(host) {
    const normal = normalizeHost(host);
    if (!normal) return null;
    const labels = normal.split(".");
    return labels.slice(-suffixLength(labels)).join(".");
  }

  /** Public suffixes cannot be permission scopes; malformed scopes are refused. */
  function isSuffixLike(host) {
    const normal = normalizeHost(host);
    return !normal || publicSuffix(normal) === normal;
  }

  /** Registrable domain (eTLD+1), or null for an invalid host or public suffix. */
  function siteOf(host) {
    const normal = normalizeHost(host);
    if (!normal) return null;
    const labels = normal.split(".");
    const take = suffixLength(labels) + 1;
    return labels.length >= take ? labels.slice(-take).join(".") : null;
  }

  function hostOfUrl(url) {
    if (typeof url !== "string") return null;
    let parsed;
    try { parsed = new URL(url); } catch { return null; }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return normalizeHost(parsed.hostname);
  }

  function withinScope(host, scope) {
    return typeof host === "string" && typeof scope === "string" && (host === scope || host.endsWith(`.${scope}`));
  }

  // A permission on a registrable domain must not include independent tenants
  // under a nested private suffix. DNR domain lists otherwise match all descendants.
  const exclusionCache = new Map();
  function scopeExclusions(scope) {
    if (!exclusionCache.has(scope)) {
      const list = [...exact, ...wildcard].filter((suffix) => suffix !== scope && withinScope(suffix, scope));
      exclusionCache.set(scope, Object.freeze([...new Set(list)].sort()));
    }
    return [...exclusionCache.get(scope)];
  }
  function canScopeSite(scope) {
    return !isSuffixLike(scope) && !wildcard.has(scope);
  }
  function inSiteScope(host, scope) {
    return withinScope(host, scope) && siteOf(host) === siteOf(scope);
  }

  function isThirdParty(requestHost, topHost) {
    const a = siteOf(requestHost), b = siteOf(topHost);
    return !a || !b || a !== b;
  }

  const api = Object.freeze({normalizeHost, isSuffixLike, publicSuffix, siteOf, hostOfUrl, withinScope, inSiteScope, scopeExclusions, canScopeSite, isThirdParty, psl: psl.metadata});
  if (isNode) module.exports = api;
  else root.EGHosts = api;
})(globalThis);
