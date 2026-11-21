"use strict";
/* Constrained build-time cosmetics: scoped CSS only, no executable bodies.
 * Input licenses and provenance are carried by the build NOTICE/manifest. */
const hosts = require("../../browser/core/hosts.js");
const selectors = require("../../browser/core/selectors.js");
const MAX_RULES = 30000;
const MAX_DOMAINS = 128;
function canonicalSelector(raw) {
  return raw.trim().replace(/\[([a-z][a-z0-9_:-]*)([~^$*|]?=)([-a-zA-Z0-9_]+)\]/g,
    (_, name, op, value) => "[" + name + op + '"' + value + '"]');
}
function scopes(raw) {
  const include = [], exclude = [];
  if (!raw) return {include, exclude};
  const values = raw.split(",");
  if (values.length > MAX_DOMAINS) return null;
  for (let value of values) {
    const negative = value.startsWith("~");
    if (negative) value = value.slice(1);
    const host = hosts.normalizeHost(value);
    // Dropping one bad exclusion could widen a rule; reject the line.
    if (!host || hosts.isSuffixLike(host)) return null;
    (negative ? exclude : include).push(host);
  }
  return {include: [...new Set(include)].sort(), exclude: [...new Set(exclude)].sort()};
}
function compileCosmetics(inputs, {maxRules = MAX_RULES} = {}) {
  const rules = [], exceptions = [], seen = new Set();
  const stats = {lines: 0, accepted: 0, exceptions: 0, duplicate: 0, dropped: {}};
  const drop = reason => { stats.dropped[reason] = (stats.dropped[reason] || 0) + 1; };
  for (const input of inputs || []) {
    if (typeof input !== "string") throw new TypeError("Cosmetic list must be text.");
    for (const raw of input.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith("!") || line.startsWith("[")) continue;
      if (!/#[@?$%]{0,2}#|#\+js|\$\$|\$@\$/u.test(line)) continue;
      stats.lines++;
      const match = /^([^#]*?)(#@#|##)(.+)$/.exec(line);
      if (!match) { drop("procedural-or-scriptlet"); continue; }
      const scope = scopes(match[1]);
      if (!scope) { drop("unsupported-domain-scope"); continue; }
      const exception = match[2] === "#@#";
      if (!exception && !scope.include.length) { drop("unscoped-hide"); continue; }
      const selector = canonicalSelector(match[3]);
      if (!selectors.validateSelector(selector).ok) { drop("unsupported-selector"); continue; }
      const entry = {...scope, selector};
      const key = JSON.stringify([exception, entry]);
      if (seen.has(key)) { stats.duplicate++; continue; }
      if (rules.length + exceptions.length >= maxRules) throw new Error("Cosmetic rule budget exceeded; review the source list.");
      seen.add(key);
      (exception ? exceptions : rules).push(entry);
      if (exception) stats.exceptions++; else stats.accepted++;
    }
  }
  return {schema: 1, rules, exceptions, stats};
}
module.exports = {compileCosmetics, canonicalSelector, MAX_RULES};
