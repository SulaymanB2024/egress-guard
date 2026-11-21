"use strict";
/* Constrained build-time cosmetics: indexed tokens and scoped native CSS only.
 * Input licenses and provenance are carried by the build NOTICE/manifest. */
const cosmetic = require("../../browser/core/cosmetic.js");
const selectors = require("../../browser/core/cosmetic-selectors.js");
const MAX_RULES = 30000;
const MAX_DOMAINS = 128;
function canonicalSelector(raw) {
  return raw.trim().replace(/\[([a-z][a-z0-9_:-]*)([~^$*|]?=)([-a-zA-Z0-9_]+)\]/g,
    (_, name, op, value) => "[" + name + op + '"' + value + '"]');
}
function scopes(raw, exception = false) {
  const include = [], exclude = [];
  if (!raw) return {include, exclude};
  const values = raw.split(",");
  if (values.length > MAX_DOMAINS) return null;
  for (let value of values) {
    const negative = value.startsWith("~");
    if (negative) value = value.slice(1);
    const host = cosmetic.normalizeScope(value, exception);
    // Dropping one bad exclusion could widen a rule; reject the line.
    if (!host) return null;
    (negative ? exclude : include).push(host);
  }
  return {include: [...new Set(include)].sort(), exclude: [...new Set(exclude)].sort()};
}
function compileCosmetics(inputs, {maxRules = MAX_RULES} = {}) {
  const rules = [], genericRules = [], exceptions = [], hideExceptions = [], seen = new Set();
  const fallback = {generic: false, scoped: false, selectors: []};
  const stats = {lines: 0, accepted: 0, generic: 0, relational: 0, entityScoped: 0, exceptions: 0, hideExceptions: 0, duplicate: 0, dropped: {}, fallbacks: {}};
  const drop = reason => { stats.dropped[reason] = (stats.dropped[reason] || 0) + 1; };
  const fallbackFor = (kind, reason) => {
    if (kind === "generic" || kind === "all") fallback.generic = true;
    if (kind === "scoped" || kind === "all") fallback.scoped = true;
    stats.fallbacks[reason] = (stats.fallbacks[reason] || 0) + 1;
  };
  const reserve = () => { if (rules.length + genericRules.length + exceptions.length + hideExceptions.length + fallback.selectors.length >= maxRules) throw new Error("Cosmetic rule budget exceeded; review the source list."); };
  for (const input of inputs || []) {
    if (typeof input !== "string") throw new TypeError("Cosmetic list must be text.");
    for (const raw of input.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("!") || line.startsWith("[")) continue;
      const pageException = cosmetic.parseHideException(line);
      if (pageException) {
        stats.lines++;
        if (!pageException.ok) { drop(pageException.error); fallbackFor(pageException.kind, "disable-imported-family"); continue; }
        const key = JSON.stringify(["page-exception", pageException.value]);
        if (seen.has(key)) { stats.duplicate++; continue; }
        if (hideExceptions.length >= 2000) throw new Error("Cosmetic page-exception budget exceeded; review the source list.");
        reserve(); seen.add(key); hideExceptions.push(pageException.value); stats.hideExceptions++; continue;
      }
      if (!/#[@?$%]{0,2}#|#\+js|\$\$|\$@\$/u.test(line)) continue;
      stats.lines++;
      const match = /^([^#]*?)(#@#|##)(.+)$/.exec(line);
      if (!match) { drop("procedural-or-scriptlet"); continue; }
      const exception = match[2] === "#@#";
      const selector = canonicalSelector(match[3]);
      if (/^\+js\(/.test(selector)) { drop("procedural-or-scriptlet"); continue; }
      const validation = selectors.validateSelector(selector);
      if (!validation.ok) { drop("unsupported-selector"); continue; }
      const scope = scopes(match[1], exception);
      if (!scope) {
        drop("unsupported-domain-scope");
        // An unusable exception scope must not activate an otherwise accepted
        // selector. Quarantine that exact selector across imported rules only.
        if (exception && !fallback.selectors.includes(selector)) {
          reserve();
          fallback.selectors.push(selector);
          stats.fallbacks["suppress-excepted-selector"] = (stats.fallbacks["suppress-excepted-selector"] || 0) + 1;
        }
        continue;
      }
      const generic = !exception && !scope.include.length;
      if (generic && !selectors.simpleToken(selector)) { drop("unsupported-generic-selector"); continue; }
      const entry = {...scope, selector};
      const key = JSON.stringify([exception, entry]);
      if (seen.has(key)) { stats.duplicate++; continue; }
      reserve();
      seen.add(key);
      (exception ? exceptions : generic ? genericRules : rules).push(entry);
      if (exception) stats.exceptions++;
      else if (generic) stats.generic++;
      else { stats.accepted++; if (validation.relational) stats.relational++; }
      if ([...scope.include, ...scope.exclude].some((s) => s.endsWith(".*"))) stats.entityScoped++;
    }
  }
  return {schema: 1, rules, genericRules, exceptions, hideExceptions, fallback, stats};
}
module.exports = {compileCosmetics, canonicalSelector, MAX_RULES};
