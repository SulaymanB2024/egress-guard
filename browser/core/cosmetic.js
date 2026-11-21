/* Generic ad-slot hiding: a small first-party selector set, applied as one stylesheet (no per-element
 * script work), on by default and switchable off per site from the popup. Pure data and a CSS builder.
 *
 * Rules for adding a selector: it must name an ad container by a convention that ad servers or ad
 * frameworks themselves use (AdSense, Google Publisher Tag, Prebid, AMP, Taboola, Outbrain) or an
 * explicit "advertisement" label; never a word that ordinary content uses ("sponsored", "promo",
 * "banner"). Prefer class, id-prefix or tag-qualified attribute selectors: Chrome matches those from
 * a bucket, so the cost scales with matching elements, not with the whole page. No :has(), no
 * universal attribute selectors. MAX_SELECTORS caps the set; tests enforce both. */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;
  const hosts = isNode ? require("./hosts.js") : root.EGHosts;
  const selectors = isNode ? require("./cosmetic-selectors.js") : root.EGCosmeticSelectors;
  const MAX_IMPORTED_RULES = 30000, MAX_SCOPE_NAMES = 128;
  const MAX_EXCEPTION_STEPS = 250000;

  const GENERIC_SELECTORS = Object.freeze([
    // Google AdSense and Publisher Tag (GPT) slots.
    "ins.adsbygoogle",
    "div[id^=\"div-gpt-ad\"]",
    "div[id^=\"google_ads_iframe\"]",
    "iframe[id^=\"google_ads_iframe\"]",
    "div[data-google-query-id]",
    "div[data-ad-slot]",
    // Ad-server frames whose host the lists already block: the frame is empty, so hide the box.
    "iframe[src*=\"googlesyndication.com\"]",
    "iframe[src*=\"doubleclick.net\"]",
    "iframe[src*=\"amazon-adsystem.com\"]",
    "iframe[src*=\"adnxs.com\"]",
    // AMP ad elements.
    "amp-ad", "amp-sticky-ad", "amp-embed[type=\"taboola\"]", "amp-embed[type=\"outbrain\"]",
    // Content-recommendation ad widgets.
    "div.OUTBRAIN", "div.trc_related_container", "div[id^=\"taboola-\"]",
    // Explicitly labelled ad containers.
    "aside[aria-label=\"Advertisement\"]", "div[aria-label=\"Advertisement\"]", "section[aria-label=\"Advertisement\"]",
    "div[aria-label=\"advertisement\"]",
    // Common ad-slot class names (also on EasyList's generic list for years).
    ".ad-slot", ".ad-slot-container", ".ad-container", ".ad-wrapper", ".ad-unit", ".adunit", ".ad-placeholder",
    ".ad-banner", ".dfp-ad", ".gpt-ad", ".advertisement", ".ad-label", ".ad__slot", ".ad-slot__label",
  ]);
  const MAX_SELECTORS = 80;

  /** One stylesheet. Each selector is its own rule so a selector Chrome rejects cannot void the others. */
  function stylesheet(selectors = GENERIC_SELECTORS) {
    return selectors.slice(0, MAX_SELECTORS).map((s) => `${s}{display:none!important}`).join("\n");
  }

  // Entity scopes are cosmetic syntax, not an assertion of common ownership and
  // never a network permission. The complete PSL determines the suffix boundary,
  // including independent private tenants and wildcard/exception rules.
  function normalizeScope(value, allowSuffix = false) {
    if (!hosts || typeof value !== "string") return null;
    if (value.endsWith(".*")) {
      const stem = value.slice(0, -2);
      const checked = hosts.normalizeHost(`${stem}.example`);
      return checked && checked.endsWith(".example") ? `${checked.slice(0, -8)}.*` : null;
    }
    const h = hosts.normalizeHost(value);
    return h && (allowSuffix || !hosts.isSuffixLike(h)) ? h : null;
  }
  function matchesScope(host, scope) {
    const h = hosts && hosts.normalizeHost(host);
    if (!h || typeof scope !== "string") return false;
    if (!scope.endsWith(".*")) return h === scope || h.endsWith(`.${scope}`);
    const suffix = hosts.publicSuffix(h);
    if (!suffix || suffix === h) return false;
    const stem = h.slice(0, -suffix.length - 1), wanted = scope.slice(0, -2);
    return stem === wanted || stem.endsWith(`.${wanted}`);
  }
  const validScopes = (r, allowSuffix = false) => r && Array.isArray(r.include) && Array.isArray(r.exclude) &&
    r.include.length + r.exclude.length <= MAX_SCOPE_NAMES &&
    [...r.include, ...r.exclude].every((s) => normalizeScope(s, allowSuffix) === s);
  const applies = (host, r) => (!r.include.length || r.include.some((d) => matchesScope(host, d))) && !r.exclude.some((d) => matchesScope(host, d));

  // ABP-style exception patterns are a bounded literal/glob language. The
  // matcher advances a finite set of positions; repeated wildcards cannot cause
  // regular-expression backtracking on a hostile URL.
  function patternProgram(pattern) {
    if (typeof pattern !== "string" || pattern.length > 512 || /[^\x20-\x7e]/.test(pattern) ||
        (pattern.startsWith("/") && pattern.endsWith("/")) || (pattern.match(/\*/g) || []).length > 8) return null;
    let anchor = "any", rest = pattern, end = false;
    if (rest.startsWith("||")) { anchor = "domain"; rest = rest.slice(2); }
    else if (rest.startsWith("|")) { anchor = "start"; rest = rest.slice(1); }
    if (rest.endsWith("|")) { rest = rest.slice(0, -1); end = true; }
    if (rest.includes("|")) return null;
    return {anchor, end, tokens: [...rest.toLowerCase().replace(/\*+/g, "*")]};
  }
  function matchesPattern(program, page, budget = {remaining: MAX_EXCEPTION_STEPS, exhausted: false}) {
    if (!program || typeof page !== "string" || page.length > 8192) return true; // fail toward the exemption
    const charge = (steps) => {
      if (!Number.isFinite(budget.remaining) || budget.remaining < steps) { budget.remaining = 0; budget.exhausted = true; return false; }
      budget.remaining -= steps; return true;
    };
    const text = page.toLowerCase(), length = text.length;
    let positions;
    if (program.anchor === "start") { if (!charge(1)) return true; positions = [0]; }
    else if (program.anchor === "domain") {
      const start = text.indexOf("://") + 3;
      if (start < 3) return false;
      const end = text.indexOf("/", start);
      if (!charge((end < 0 ? length : end) - start + 1)) return true;
      positions = [start];
      for (let i = start; i < (end < 0 ? length : end); i++) if (text[i] === ".") positions.push(i + 1);
    } else { if (!charge(length + 1)) return true; positions = Array.from({length: length + 1}, (_, i) => i); }
    for (const token of program.tokens) {
      if (!positions.length) return false;
      if (token === "*") {
        const count = length - positions[0] + 1;
        if (!charge(count)) return true;
        positions = Array.from({length: count}, (_, i) => positions[0] + i); continue;
      }
      if (!charge(positions.length)) return true;
      const next = [];
      for (const pos of positions) {
        const atEnd = pos === length;
        const matched = token === "^" ? atEnd || /[^a-z0-9_.%\-]/.test(text[pos]) : !atEnd && text[pos] === token;
        const value = atEnd ? pos : pos + 1;
        if (matched && next[next.length - 1] !== value) next.push(value);
      }
      positions = next;
    }
    return program.end ? positions.includes(length) : positions.length > 0;
  }
  function parseHideException(line) {
    if (typeof line !== "string" || !line.startsWith("@@")) return null;
    const at = line.lastIndexOf("$");
    if (at < 2) return null;
    const kinds = {generichide: "generic", ghide: "generic", specifichide: "scoped", shide: "scoped", elemhide: "all", ehide: "all"};
    const options = line.slice(at + 1).toLowerCase().split(","), selected = options.filter((o) => kinds[o]);
    const mentioned = options.map((o) => o.split("=", 1)[0].replace(/^~/, "")).filter((o) => kinds[o]);
    if (!mentioned.length) return null;
    const kind = mentioned.length === 1 ? kinds[mentioned[0]] : "all";
    const fail = (error) => ({ok: false, kind, error});
    if (selected.length !== 1 || options.some((o) => !kinds[o] && !o.startsWith("domain="))) return fail("unsupported-hide-exception-option");
    if (options.filter((o) => o.startsWith("domain=")).length > 1) return fail("unsupported-hide-exception-scope");
    const include = [], exclude = [];
    const domains = options.find((o) => o.startsWith("domain="));
    if (domains) {
      const values = domains.slice(7).split("|");
      if (!values.length || values.length > MAX_SCOPE_NAMES) return fail("unsupported-hide-exception-scope");
      for (let value of values) {
        const negative = value.startsWith("~");
        if (negative) value = value.slice(1);
        const name = normalizeScope(value, true);
        if (!name) return fail("unsupported-hide-exception-scope");
        (negative ? exclude : include).push(name);
      }
    }
    const pattern = line.slice(2, at);
    if ((!pattern && !domains) || !patternProgram(pattern)) return fail("unsupported-hide-exception-pattern");
    return {ok: true, value: {kind, pattern, include: [...new Set(include)].sort(), exclude: [...new Set(exclude)].sort()}};
  }

  function importPolicy(host, href = "", data = root.EGCosmeticData) {
    const h = hosts && hosts.normalizeHost(host);
    const policy = {host: h, generic: true, scoped: true, excepted: new Set(), reasons: [], sourceExemptions: [], degradedFamilies: [], exceptionSteps: 0, exceptionBudgetExhausted: false};
    const disable = (kind, reason, sourceException = false) => {
      if (kind === "generic" || kind === "all") policy.generic = false;
      if (kind === "scoped" || kind === "all") policy.scoped = false;
      const causes = sourceException ? policy.sourceExemptions : policy.degradedFamilies;
      for (const family of kind === "all" ? ["generic", "scoped"] : [kind]) if (!causes.includes(family)) causes.push(family);
      if (reason && !policy.reasons.includes(reason)) policy.reasons.push(reason);
    };
    if (!h || !hosts.siteOf(h) || !selectors || !data || data.schema !== 1 || !Array.isArray(data.rules) || !Array.isArray(data.exceptions) || data.rules.length > MAX_IMPORTED_RULES) {
      disable("all", "Imported cosmetic data or a registrable page host is unavailable."); return policy;
    }
    const fallback = data.fallback || {};
    if (fallback.generic === true) disable("generic", "A source generic-hiding exception could not be represented.");
    if (fallback.scoped === true) disable("scoped", "A source scoped-hiding exception could not be represented.");
    if (fallback.selectors !== undefined && (!Array.isArray(fallback.selectors) || fallback.selectors.length > MAX_IMPORTED_RULES)) disable("all", "Malformed cosmetic exception fallback.");
    for (const selector of Array.isArray(fallback.selectors) ? fallback.selectors.slice(0, MAX_IMPORTED_RULES) : []) {
      if (selectors.validateSelector(selector).ok) policy.excepted.add(selector);
    }
    if (data.exceptions.length > MAX_IMPORTED_RULES) { disable("all", "Cosmetic exception budget exceeded."); return policy; }
    for (const r of data.exceptions) {
      if (!validScopes(r, true) || typeof r.selector !== "string") { disable("all", "Malformed cosmetic exception scope."); continue; }
      if (selectors.validateSelector(r.selector).ok && applies(h, r)) policy.excepted.add(r.selector);
    }
    let page = "";
    try { const u = new URL(href || `https://${h}/`); if (/^https?:$/.test(u.protocol) && u.hostname === h) page = `${u.protocol}//${u.host}${u.pathname}${u.search}`; } catch { /* keep empty */ }
    const exceptions = data.hideExceptions === undefined ? [] : data.hideExceptions;
    if (!Array.isArray(exceptions) || exceptions.length > 2000) { disable("all", "Malformed cosmetic page exceptions."); return policy; }
    const budget = {remaining: MAX_EXCEPTION_STEPS, exhausted: false};
    for (const r of exceptions) {
      if (!validScopes(r, true) || !["generic", "scoped", "all"].includes(r.kind)) { disable("all", "Malformed cosmetic page exception."); continue; }
      const pattern = patternProgram(r.pattern);
      if (!pattern) { disable(r.kind, "Unsupported cosmetic page exception pattern."); continue; }
      if (!applies(h, r) || (r.kind === "generic" && !policy.generic) || (r.kind === "scoped" && !policy.scoped) || (!policy.generic && !policy.scoped)) continue;
      // Without a usable current URL no path exception can be disproved safely.
      const match = !page || matchesPattern(pattern, page, budget);
      if (budget.exhausted) disable(r.kind, "Cosmetic exception work budget exhausted; the affected imported family is disabled.");
      else if (match) disable(r.kind, `A source ${r.kind}-hiding exception applies to this page.`, true);
    }
    policy.exceptionSteps = MAX_EXCEPTION_STEPS - budget.remaining;
    policy.exceptionBudgetExhausted = budget.exhausted;
    return policy;
  }

  function scopedRules(host, data = root.EGCosmeticData, limit = 200, href = "", policy = importPolicy(host, href, data)) {
    if (!policy.scoped) return [];
    const seen = new Set(), out = [];
    for (const r of data.rules) {
      if (!validScopes(r) || !r.include.length || !applies(policy.host, r) || policy.excepted.has(r.selector) || seen.has(r.selector)) continue;
      const validation = selectors.validateSelector(r.selector);
      if (!validation.ok) continue;
      seen.add(r.selector);
      out.push({id: `scoped-${out.length}`, kind: "cosmetic", selector: r.selector, source: "scoped", relational: validation.relational === true});
      if (out.length >= Math.max(1, Math.min(limit, 200))) break;
    }
    return out;
  }

  function genericIndex(host, href = "", data = root.EGCosmeticData) {
    const policy = importPolicy(host, href, data);
    const index = {ids: new Map(), classes: new Map(), rules: new Map(), policy};
    if (!policy.generic) return index;
    const list = data.genericRules === undefined ? [] : data.genericRules;
    if (!Array.isArray(list) || list.length > MAX_IMPORTED_RULES) { policy.generic = false; policy.degradedFamilies.push("generic"); policy.reasons.push("Generic cosmetic rule budget or data shape is invalid."); return index; }
    const seen = new Set();
    for (let i = 0; i < list.length; i++) {
      const r = list[i];
      if (!validScopes(r) || r.include.length || !applies(policy.host, r) || policy.excepted.has(r.selector) || seen.has(r.selector)) continue;
      const token = selectors.simpleToken(r.selector);
      if (!token) continue;
      seen.add(r.selector);
      const rule = {id: `generic-${i}`, kind: "cosmetic", selector: r.selector, source: "generic"};
      index.rules.set(rule.id, rule);
      (token.kind === "id" ? index.ids : index.classes).set(token.value, rule);
    }
    return index;
  }
  function genericMatches(index, id, classes) {
    const out = [], seen = new Set();
    const take = (rule) => { if (rule && !seen.has(rule.id)) { out.push(rule); seen.add(rule.id); } };
    if (!index || !index.policy.generic) return out;
    take(index.ids.get(id));
    let count = 0;
    for (const name of classes || []) { if (count++ >= 32) break; take(index.classes.get(name)); }
    return out;
  }

  const api = Object.freeze({GENERIC_SELECTORS, MAX_SELECTORS, MAX_IMPORTED_RULES, MAX_SCOPE_NAMES, MAX_EXCEPTION_STEPS, stylesheet,
    normalizeScope, matchesScope, patternProgram, matchesPattern, parseHideException, importPolicy, scopedRules, genericIndex, genericMatches});
  if (isNode) module.exports = api;
  else root.EGCosmeticList = api;
})(globalThis);
