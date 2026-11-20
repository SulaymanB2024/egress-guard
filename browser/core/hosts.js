/* Hostname parsing, a small conservative public-suffix guard and site comparison.
 * Pure: no browser APIs. Loaded as a classic script (global EGHosts) or via require().
 * The suffix list is deliberately short. A maintained Public Suffix List is future work;
 * until then anything that looks like a suffix is refused rather than guessed. */
(function (root) {
  "use strict";
  // Single labels such as "com" or "localhost" are refused separately.
  const MULTI_LABEL_SUFFIXES = new Set([
    // Common second-level registries.
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.br", "net.br", "org.br", "gov.br", "co.in", "net.in", "org.in", "gov.in", "co.za", "org.za",
    "com.mx", "com.ar", "com.tr", "com.tw", "com.hk", "com.sg", "com.my", "co.id", "co.il", "com.ua",
    // Shared hosting where every customer is a separate site.
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "herokuapp.com",
    "appspot.com", "blogspot.com", "cloudfront.net", "azurewebsites.net", "firebaseapp.com", "web.app",
    "s3.amazonaws.com", "fly.dev", "onrender.com", "glitch.me", "surge.sh", "wordpress.com", "tumblr.com",
  ]);
  const SECOND_LEVEL_WORDS = new Set(["co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go", "ltd", "plc", "mil"]);
  const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

  /** Lowercased ASCII hostname, or null. IP literals and single labels are refused. */
  function normalizeHost(value) {
    if (typeof value !== "string") return null;
    let host = value.trim().toLowerCase();
    if (host.endsWith(".")) host = host.slice(0, -1);
    if (!host || host.length > 253) return null;
    const labels = host.split(".");
    if (labels.length < 2 || !labels.every((label) => LABEL.test(label))) return null;
    if (/^[0-9]+$/.test(labels[labels.length - 1])) return null; // IPv4-like
    return host;
  }

  /** True when the host is, or may be, a public suffix (refused as a rule scope). */
  function isSuffixLike(host) {
    const labels = host.split(".");
    if (labels.length < 2) return true;
    if (MULTI_LABEL_SUFFIXES.has(host)) return true;
    // Heuristic for unlisted country registries such as "com.pe" or "co.th".
    return labels.length === 2 && labels[1].length === 2 && SECOND_LEVEL_WORDS.has(labels[0]);
  }

  /** Approximate registrable domain ("site") for party comparisons. */
  function siteOf(host) {
    const normal = normalizeHost(host);
    if (!normal) return null;
    const labels = normal.split(".");
    for (let take = 2; take <= labels.length; take++) {
      const tail = labels.slice(-take).join(".");
      if (!isSuffixLike(tail)) return tail;
    }
    return null;
  }

  /** Hostname of an http(s) URL, or null for anything else. */
  function hostOfUrl(url) {
    if (typeof url !== "string") return null;
    let parsed;
    try { parsed = new URL(url); } catch { return null; }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return normalizeHost(parsed.hostname);
  }

  /** True when `host` is `scope` or a subdomain of it. */
  function withinScope(host, scope) {
    return host === scope || host.endsWith(`.${scope}`);
  }

  function isThirdParty(requestHost, topHost) {
    const a = siteOf(requestHost), b = siteOf(topHost);
    return !a || !b || a !== b;
  }

  const api = Object.freeze({normalizeHost, isSuffixLike, siteOf, hostOfUrl, withinScope, isThirdParty});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGHosts = api;
})(globalThis);
