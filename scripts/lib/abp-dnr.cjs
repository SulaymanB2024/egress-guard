"use strict";
/* Build-time compiler: Adblock Plus network filters (EasyPrivacy, EasyList) -> Chrome declarativeNetRequest rules.
 * Pure: no I/O. Never shipped in the extension; the build writes its output as static rulesets.
 *
 * What converts: URL patterns (`||`, `|`, `^`, `*`), bounded regular-expression filters, `$third-party`
 * and first-party, resource types (positive and negated), `domain=`/`from=` (initiator), `to=`/`denyallow=`
 * (request domain), `method=`, `match-case`, `important`, exceptions (`@@`) and `badfilter`. Everything else is
 * dropped and counted by reason. Cosmetic filters are not network filters and are not counted. Pure `||host^` filters
 * with the same options are folded into one rule with `requestDomains`, which costs one rule however many hosts it
 * holds.
 *
 * Exceptions and `$important` filters are trusted only when anchored to a concrete host: a `||host…` pattern whose
 * host is a real registrable name (not a public suffix, no wildcard), a `to=` host, or a `domain=` restriction.
 * Anything else (`@@||*^$document`, `@@^$document`, `@@|http$document`, `@@/./$document`, `@@|https://$all`, …)
 * would let one hostile or broken upstream line allow, or block, everything: it is dropped and counted in
 * `stats.suspicious`, which the build caps. `$document` exceptions never become `allowAllRequests`: they compile to
 * a plain `allow` for requests made by that host's pages, at the list's own exception priority, so they lift only that
 * list's filters. `$all` exceptions allow requests to the host, nothing more. */
const hosts = require("../../browser/core/hosts.js");

const TYPES = Object.freeze({
  script: ["script"], image: ["image"], stylesheet: ["stylesheet"], css: ["stylesheet"], object: ["object"],
  "object-subrequest": ["object"], xmlhttprequest: ["xmlhttprequest"], xhr: ["xmlhttprequest"], subdocument: ["sub_frame"],
  frame: ["sub_frame"], ping: ["ping"], beacon: ["ping"], media: ["media"], font: ["font"], websocket: ["websocket"],
  other: ["other"], webtransport: ["webtransport"], webbundle: ["webbundle"],
});
const ALL_SUB = Object.freeze(["sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping",
  "csp_report", "media", "websocket", "webtransport", "webbundle", "other"]);
const METHODS = new Set(["connect", "delete", "get", "head", "options", "patch", "post", "put"]);
// Modifiers that only concern cosmetic filtering. An exception carrying only these blocks nothing and allows nothing.
const COSMETIC_EXCEPTIONS = new Set(["elemhide", "ehide", "generichide", "ghide", "specifichide", "shide", "genericblock", "content"]);
// Modifiers DNR cannot express. The filter is dropped (and counted) rather than converted into something broader.
const UNSUPPORTED = new Set(["csp", "removeparam", "queryprune", "header", "permissions", "replace", "urltransform", "rewrite",
  "sitekey", "cname", "strict1p", "strict3p", "strict-first-party", "strict-third-party", "empty", "mp4", "inline-script",
  "inline-font", "popunder", "app", "network", "ipaddress", "redirect-rule", "webrtc", "jsonprune", "uritransform", "urlskip",
  "reason", "requestheader", "responseheader", "doc"]);

const ASCII = /^[\x20-\x7e]*$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// Counted repetitions can exceed Chrome's 2 KiB RE2 budget in a 30-character
// source. This conservative supported-subset bound counts expanded byte-range
// atoms, not source bytes. It is not a substitute for the artifact's real RE2
// audit: other constructs and the actual engine version still affect memory.
const MAX_COUNTED_REPEAT_COST = 64;
const MAX_ALTERNATIVE_BRANCHES = 32;

/** Is `line` a cosmetic, scriptlet or HTML filter (not a network filter)? */
function isCosmetic(line) {
  return /#[@?$%]{0,2}#|#\+js|\$\$|\$@\$/.test(line) && !/^\/.*\/(\$|$)/.test(line);
}

/** Split "pattern$opt,opt" at the options separator (the last "$" that starts a plausible option list). */
function splitOptions(body) {
  const at = body.lastIndexOf("$");
  if (at < 0) return [body, null];
  const opts = body.slice(at + 1);
  if (!/^~?[a-z0-9_-]+(?:=|,|$)/i.test(opts)) return [body, null];
  return [body.slice(0, at), opts];
}

/** Split an option list on commas that are not inside a `/regex/` value. */
function splitList(opts) {
  const out = [];
  let cur = "", inRe = false;
  for (let i = 0; i < opts.length; i++) {
    const c = opts[i];
    if (c === "/" && (cur.endsWith("=") || inRe)) inRe = !inRe;
    if (c === "," && !inRe) { out.push(cur); cur = ""; } else cur += c;
  }
  out.push(cur);
  return out;
}

/** "a.com|~b.com" -> {include, exclude, dropped}; entity (`site.*`), wildcard and regex entries cannot be expressed. */
function domainList(value) {
  const include = [], exclude = [];
  let dropped = 0, droppedInclude = 0, droppedExclude = 0;
  for (let entry of value.split("|")) {
    entry = entry.trim().toLowerCase();
    if (!entry) continue;
    const neg = entry.startsWith("~");
    if (neg) entry = entry.slice(1);
    if (!DOMAIN.test(entry)) { dropped++; if (neg) droppedExclude++; else droppedInclude++; continue; }
    (neg ? exclude : include).push(entry);
  }
  return {include, exclude, dropped, droppedInclude, droppedExclude};
}

/** RE2 (Chrome's regex engine) refuses look-around and back-references. */
function re2Compatible(source) {
  if (/\(\?[=!<]|\\[1-9]|\(\?[a-z]*[:)]?/i.test(source.replace(/\(\?:/g, ""))) return false;
  try { new RegExp(source); } catch { return false; }
  return source.length <= 300;
}

/** Conservative expansion cost of counted atoms/groups; no regex is rewritten here. */
function countedRepeatCost(source, caseSensitive = false) {
  let offset = 0;
  const capped = (n) => Math.min(n, 1000000);
  function byteRanges(atom) {
    const re = new RegExp("^(?:" + atom + ")$", caseSensitive ? "" : "i");
    const present = Array.from({length: 256}, (_, n) => re.test(String.fromCharCode(n)));
    // RE2 can encode the matching ASCII case pair in one folded range.
    if (!caseSensitive) for (let n = 65; n <= 90; n++) if (present[n] && present[n + 32]) present[n] = false;
    let ranges = 0;
    for (let n = 0; n < present.length; n++) if (present[n] && !present[n - 1]) ranges++;
    return Math.max(1, ranges);
  }
  function sequence() {
    let weight = 0, counted = 0;
    while (offset < source.length && source[offset] !== ")") {
      let atom = 0, childCounted = 0;
      const ch = source[offset++];
      if (ch === "(") {
        if (source.slice(offset, offset + 2) === "?:") offset += 2;
        const child = sequence(); atom = child.weight; childCounted = child.counted;
        if (source[offset] === ")") offset++;
      } else if (ch === "[") {
        const start = offset - 1;
        while (offset < source.length) {
          const next = source[offset++];
          if (next === "\\") offset++;
          else if (next === "]") break;
        }
        atom = byteRanges(source.slice(start, offset));
      } else if (ch === "\\") {
        const next = source[offset++];
        if (/[dDsSwW]/.test(next || "")) atom = byteRanges("\\" + next);
        else if (next === "b" || next === "B") atom = 0;
        else {
          atom = 1;
          if (next === "x" && /^[0-9a-f]{2}/i.test(source.slice(offset))) offset += 2;
          else if (next === "u" && /^[0-9a-f]{4}/i.test(source.slice(offset))) offset += 4;
        }
      } else atom = ch === "^" || ch === "$" ? 0 : ch === "." ? 2 : 1;
      counted = capped(counted + childCounted);
      const repeat = /^\{(\d+)(?:,(\d*))?\}/.exec(source.slice(offset));
      if (repeat) {
        const copies = repeat[2] === undefined ? Number(repeat[1]) : repeat[2] === "" ? Number(repeat[1]) + 1 : Number(repeat[2]);
        atom = capped(atom * copies); counted = capped(counted + atom); offset += repeat[0].length;
        if (source[offset] === "?") offset++;
      } else if (/[?*+]/.test(source[offset] || "")) {
        atom++; offset++;
        if (source[offset] === "?") offset++;
      }
      weight = capped(weight + atom);
    }
    return {weight, counted};
  }
  return sequence().counted;
}

/** Exact disjunction of a flat, top-level, unquantified literal-alternative group.
 * A quantified group is never split: (a|b)+ includes mixed strings that a+|b+
 * would lose. The bodies have no backreferences and carry no substitution.
 */
function splitRegexAlternatives(source) {
  const stack = [];
  let best = null;
  for (let i = 0; i < source.length; i++) {
    if (source[i] === "\\") { i++; continue; }
    if (source[i] === "[") {
      while (++i < source.length) { if (source[i] === "\\") i++; else if (source[i] === "]") break; }
      continue;
    }
    if (source[i] === "(") {
      if (stack.length) stack[stack.length - 1].nested = true;
      stack.push({start: i, nested: false});
    } else if (source[i] === ")") {
      const group = stack.pop();
      if (!group || stack.length || group.nested || /[?*+{]/.test(source[i + 1] || "")) continue;
      const body = source.slice(group.start + 1, i).replace(/^\?:/, "");
      const branches = [...new Set(body.split("|"))];
      if (branches.length < 8 || branches.length > MAX_ALTERNATIVE_BRANCHES || !branches.every((b) => /^[A-Za-z0-9_-]+\$?$/.test(b))) continue;
      if (!best || branches.length > best.branches.length) best = {start: group.start, end: i + 1, branches};
    }
  }
  return best ? best.branches.map((branch) => source.slice(0, best.start) + "(?:" + branch + ")" + source.slice(best.end)) : [source];
}

/** Normalise an ABP URL pattern for DNR urlFilter. Returns {urlFilter} | {domain} | {error}. */
function convertPattern(pattern) {
  if (!ASCII.test(pattern)) return {error: "non-ASCII pattern"};
  let p = pattern;
  // A leading or trailing "*" is implied by substring matching.
  while (p.startsWith("*")) p = p.slice(1);
  if (!p.endsWith("|")) while (p.endsWith("*")) p = p.slice(0, -1);
  if (p === "" || p === "|" || p === "||") return {urlFilter: null};
  if (p.startsWith("||*")) p = p.slice(2);
  const host = /^\|\|([a-z0-9.-]+)\^?\|?$/i.exec(p);
  // The trailing | is an end-of-URL constraint, not part of a whole-host rule.
  // Folding ||host^| into requestDomains would broaden both blocks and allows.
  if (host && DOMAIN.test(host[1].toLowerCase()) && host[1].includes(".") && p.endsWith("^")) return {domain: host[1].toLowerCase()};
  return {urlFilter: p};
}

/**
 * Parse one filter line. Returns null (not a network filter), {drop: reason}, or
 * {exception, important, badfilter, key, condition, document, domain?}.
 */
function parseLine(raw) {
  const line = raw.trim();
  if (!line || line.startsWith("!") || line.startsWith("[")) return null;
  if (isCosmetic(line)) return null;
  const exception = line.startsWith("@@");
  const body = exception ? line.slice(2) : line;
  const [pattern, opts] = splitOptions(body);
  const condition = {};
  let important = false, badfilter = false, document = false, cosmeticOnly = false, all = false;
  const include = new Set(), exclude = new Set();
  let explicitTypes = false, popupOnly = false;
  if (opts !== null) {
    let cosmeticFlags = 0, total = 0;
    for (const item of splitList(opts)) {
      total++;
      const eq = item.indexOf("=");
      let name = (eq < 0 ? item : item.slice(0, eq)).trim().toLowerCase();
      const value = eq < 0 ? null : item.slice(eq + 1);
      const neg = name.startsWith("~");
      if (neg) name = name.slice(1);
      if (name === "_" || name === "") continue;
      if (COSMETIC_EXCEPTIONS.has(name)) { cosmeticFlags++; continue; }
      if (TYPES[name]) { explicitTypes = true; for (const t of TYPES[name]) (neg ? exclude : include).add(t); continue; }
      switch (name) {
        case "third-party": case "3p": condition.domainType = neg ? "firstParty" : "thirdParty"; continue;
        case "first-party": case "1p": condition.domainType = neg ? "thirdParty" : "firstParty"; continue;
        case "match-case": condition.isUrlFilterCaseSensitive = !neg; continue;
        case "important": important = true; continue;
        case "badfilter": badfilter = true; continue;
        case "document": if (neg) return {drop: "negated $document"}; document = true; explicitTypes = true; continue;
        case "popup": explicitTypes = true; popupOnly = true; continue;
        case "all": explicitTypes = true; for (const t of ALL_SUB) include.add(t); document = true; all = true; continue;
        case "domain": case "from": {
          if (value === null) return {drop: "domain= without a value"};
          const d = domainList(value);
          // Dropping an excluded entry, or every included one, would widen the filter: drop the filter instead.
          // Dropping some included entries only narrows it.
          if (d.droppedExclude || (d.droppedInclude && !d.include.length)) return {drop: "domain= entries DNR cannot express (entity or regex)"};
          if (d.include.length) condition.initiatorDomains = d.include;
          if (d.exclude.length) condition.excludedInitiatorDomains = d.exclude;
          continue;
        }
        case "to": case "denyallow": {
          if (value === null) return {drop: `${name}= without a value`};
          const d = domainList(value);
          if (d.dropped) return {drop: `${name}= entries DNR cannot express`};
          if (name === "denyallow") { if (d.exclude.length) return {drop: "negated denyallow entry"}; condition.excludedRequestDomains = d.include; continue; }
          if (d.include.length) condition.requestDomains = d.include;
          if (d.exclude.length) condition.excludedRequestDomains = d.exclude;
          continue;
        }
        case "method": {
          if (value === null) return {drop: "method= without a value"};
          const yes = [], no = [];
          for (let m of value.toLowerCase().split("|")) {
            const n = m.startsWith("~"); if (n) m = m.slice(1);
            if (!METHODS.has(m)) return {drop: "unsupported request method"};
            (n ? no : yes).push(m);
          }
          if (yes.length) condition.requestMethods = yes;
          if (no.length) condition.excludedRequestMethods = no;
          continue;
        }
        case "redirect": if (exception) return {drop: "redirect exception"}; continue;  // implies block; the block is kept
      }
      if (UNSUPPORTED.has(name)) return {drop: `$${name}`};
      return {drop: `unknown option $${name}`};
    }
    if (cosmeticFlags && cosmeticFlags === total) cosmeticOnly = true;
  }
  if (cosmeticOnly) return {drop: exception ? "cosmetic-only exception ($elemhide, $generichide…)" : "cosmetic-only modifier"};
  if (popupOnly && !include.size && !document) return {drop: "$popup only"};
  // Resource types.
  if (document && !exception) {
    if (!include.size) return {drop: "$document block (top-level navigations are never blocked)"};
    document = false;
  }
  if (include.size) condition.resourceTypes = [...include].filter((t) => !exclude.has(t)).sort();
  if (exclude.size && !include.size) condition.excludedResourceTypes = [...exclude].sort();
  if (explicitTypes && !document && condition.resourceTypes && !condition.resourceTypes.length) return {drop: "no resource type DNR can match"};
  if (document) condition.resourceTypes = ["main_frame", "sub_frame"];
  // Pattern.
  let domain = null;
  if (!ASCII.test(pattern)) return {drop: "non-ASCII pattern"};
  if (pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/")) {
    const source = pattern.slice(1, -1);
    if (!re2Compatible(source)) return {drop: "regular expression RE2 cannot run (or longer than 300 characters)"};
    condition.regexFilter = source;
  } else {
    const p = convertPattern(pattern);
    if (p.error) return {drop: p.error};
    if (p.domain) domain = p.domain;
    else if (p.urlFilter) condition.urlFilter = p.urlFilter;
  }
  if (!domain && !condition.urlFilter && !condition.regexFilter && !condition.initiatorDomains && !condition.requestDomains) {
    return {drop: "matches every request (no pattern and no domain)", suspicious: exception || important};
  }
  if (condition.isUrlFilterCaseSensitive === undefined && (condition.urlFilter || condition.regexFilter)) condition.isUrlFilterCaseSensitive = false;
  if (exception || important) {
    // Only real registrable names count as anchors; a public suffix in domain= (or to=) is dropped from the list.
    for (const key of ["initiatorDomains", "requestDomains"]) {
      if (!condition[key]) continue;
      condition[key] = condition[key].filter((d) => hosts.siteOf(d));
      if (!condition[key].length) return {drop: `${exception ? "exception" : "$important filter"} scoped only to public suffixes`, suspicious: true};
    }
    const anchor = domain || anchoredHost(condition.urlFilter);
    const anchored = (anchor && hosts.siteOf(anchor)) || condition.initiatorDomains || condition.requestDomains;
    if (!anchored) return {drop: `${exception ? "exception" : "$important filter"} not anchored to a host`, suspicious: true};
  }
  if (exception && document) {
    // Never allowAllRequests. "Allow on pages of this host" becomes a plain allow for the host's own requests;
    // $all becomes a plain allow for requests to the host.
    const host = domain || anchoredHost(condition.urlFilter);
    if (!host || !hosts.siteOf(host) || condition.regexFilter || (condition.urlFilter &&
      (condition.urlFilter.endsWith("|") || condition.urlFilter.replace(/\^$/, "") !== `||${host}`))) {
      return {drop: "$document exception that is not a whole host", suspicious: true};
    }
    delete condition.resourceTypes;
    delete condition.urlFilter;
    delete condition.isUrlFilterCaseSensitive;
    if (all) return {exception, important, badfilter, document: false, domain: host, condition, regex: false};
    condition.initiatorDomains = [...new Set([...(condition.initiatorDomains || []), host])].filter((d) => d === host || d.endsWith(`.${host}`));
    return {exception, important, badfilter, document: false, domain: null, condition, regex: false};
  }
  return {exception, important, badfilter, document, domain, condition, regex: Boolean(condition.regexFilter)};
}

/** The host a `||host…` urlFilter is anchored to, when it is a plain host name followed by a separator. */
function anchoredHost(urlFilter) {
  if (typeof urlFilter !== "string") return null;
  const m = /^\|\|([a-z0-9.-]+)(?:[\^/:|?]|$)/i.exec(urlFilter);
  if (!m) return null;
  const host = m[1].toLowerCase().replace(/\.$/, "");
  return DOMAIN.test(host) && host.includes(".") ? host : null;
}

/** Text identity used by $badfilter: the line without its badfilter option. */
function badKey(line) {
  const [pattern, opts] = splitOptions(line.trim());
  if (opts === null) return line.trim();
  const kept = splitList(opts).filter((o) => o.trim().toLowerCase() !== "badfilter").sort();
  return kept.length ? `${pattern}$${kept.join(",")}` : pattern;
}

/**
 * Compile a filter list. Returns {block, important, allow, stats} where each array holds DNR rule bodies without id
 * or priority (the build assigns them). stats: {lines, network, converted, rules, regex, dropped: {reason: n}}.
 */
function compileFilters(text, {maxRegex = Infinity} = {}) {
  const lines = String(text).split(/\r?\n/);
  const stats = {lines: lines.length, network: 0, converted: 0, rules: 0, regex: 0, regexSplitFilters: 0, regexSplitRules: 0,
    countedRepeatBudget: MAX_COUNTED_REPEAT_COST, folded: 0, dropped: {}, suspicious: 0, suspiciousLines: [], exceptions: 0};
  const drop = (reason) => { stats.dropped[reason] = (stats.dropped[reason] || 0) + 1; };
  const parsed = [];
  const bad = new Set();
  for (const line of lines) {
    const p = parseLine(line);
    if (p === null) continue;
    stats.network++;
    if (p.drop) { drop(p.drop); if (p.suspicious) { stats.suspicious++; stats.suspiciousLines.push(line.trim().slice(0, 200)); } continue; }
    if (p.badfilter) { bad.add(badKey(line)); stats.converted++; continue; }
    parsed.push({line: line.trim(), ...p});
  }
  const out = {block: [], important: [], allow: []};
  const groups = new Map();
  let regexUsed = 0;
  for (const p of parsed) {
    if (bad.has(badKey(p.line))) { drop("disabled by $badfilter"); continue; }
    let conditions = [p.condition];
    if (p.regex) {
      const cost = countedRepeatCost(p.condition.regexFilter, p.condition.isUrlFilterCaseSensitive);
      if (cost > MAX_COUNTED_REPEAT_COST) {
        const reason = "regular expression exceeds supported counted-repetition expansion budget";
        if (p.exception) throw new Error("Cannot omit a protecting regex exception: " + reason + ": " + p.line);
        drop(reason); continue;
      }
      const patterns = splitRegexAlternatives(p.condition.regexFilter);
      if (regexUsed + patterns.length > maxRegex) {
        if (p.exception) throw new Error("Cannot omit a protecting regex exception: over the regular-expression rule budget: " + p.line);
        drop("over the regular-expression rule budget"); continue;
      }
      regexUsed += patterns.length;
      if (patterns.length > 1) { stats.regexSplitFilters++; stats.regexSplitRules += patterns.length - 1; }
      conditions = patterns.map((regexFilter) => ({...p.condition, regexFilter}));
    }
    stats.converted++;
    const bucket = p.exception ? "allow" : p.important ? "important" : "block";
    if (p.exception) stats.exceptions++;
    const action = {type: p.exception ? "allow" : "block"};   // never allowAllRequests (see the header)
    if (p.domain && !p.condition.requestDomains) {
      // Fold `||host^` filters that share every other condition into one requestDomains rule.
      const key = `${bucket}|${action.type}|${JSON.stringify(p.condition)}`;
      if (!groups.has(key)) { const rule = {action, condition: {...p.condition, requestDomains: []}}; groups.set(key, rule); out[bucket].push(rule); }
      groups.get(key).condition.requestDomains.push(p.domain);
      stats.folded++;
      continue;
    }
    for (const original of conditions) {
      const condition = {...original};
      if (p.domain) condition.urlFilter = `||${p.domain}^`;
      out[bucket].push({action, condition});
    }
  }
  for (const rule of groups.values()) rule.condition.requestDomains = [...new Set(rule.condition.requestDomains)].sort();
  stats.regex = regexUsed;
  stats.rules = out.block.length + out.important.length + out.allow.length;
  return {...out, stats};
}

/** Read the `! Version:`, `! Last modified:`, `! Title:` and `! Licence:` header lines. */
function header(text) {
  const out = {};
  for (const line of String(text).split(/\r?\n/, 40)) {
    const m = /^!\s*(Version|Last modified|Title|Licence|License|Expires):\s*(.+)$/i.exec(line);
    if (m) out[m[1].toLowerCase().replace(" ", "_").replace("license", "licence")] = m[2].trim();
  }
  return out;
}

module.exports = Object.freeze({TYPES, ALL_SUB, parseLine, compileFilters, convertPattern, splitOptions, re2Compatible,
  countedRepeatCost, splitRegexAlternatives, MAX_COUNTED_REPEAT_COST, header, badKey, isCosmetic});
