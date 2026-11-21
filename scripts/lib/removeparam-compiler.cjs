/* Compile a deliberately bounded removeparam dialect into data plus Chrome DNR.
 * Upstream exceptions restrict the combined legacy/import policy. They never
 * become network allow rules. See docs/parameters-0.9.md for the exact dialect. */
"use strict";

const params = require("../../browser/core/params.js");
const policy = require("../../browser/core/param-policy.js");
const hosts = require("../../browser/core/hosts.js");
const MAX_ROWS = 12000, MAX_LINE = 20000, MAX_REGEX_RULES = 900;
const MAX_REGEX_SOURCE = 1400, PRESENCE_CHUNK = 70;
const NATIVE_NAME = /^[A-Za-z0-9_!\x27()*\.~-]{1,64}$/;
const TYPES = new Set(["doc", "document", "all", "image", "script", "stylesheet", "css", "font", "media", "object", "subdocument", "frame", "xhr", "xmlhttprequest", "websocket", "ping", "other", "webrtc"]);
const KEPT = new Set(params.KEPT);
const sorted = (xs) => [...new Set(xs)].sort();
const covers = policy.covers;
const escapeRE = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const hostOK = (s) => policy.HOST.test(s) && s.includes(".") && !/^\d+(?:\.\d+){3}$/.test(s);

function optionsOf(text) {
  const out = []; let start = 0, regex = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (escaped) { escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (ch === "/") {
      if (regex) regex = false;
      else if (/^(?:removeparam|queryprune)=~?$/.test(text.slice(start, i))) regex = true;
    }
    if (ch === "," && !regex) { out.push(text.slice(start, i)); start = i + 1; }
  }
  out.push(text.slice(start));
  return out;
}

function parseLine(line) {
  const exception = line.startsWith("@@"), body = exception ? line.slice(2) : line;
  for (let pos = body.indexOf("$"); pos >= 0; pos = body.indexOf("$", pos + 1)) {
    if (!/^[a-zA-Z~][a-zA-Z0-9~-]*(?:=|,|$)/.test(body.slice(pos + 1))) continue;
    const options = optionsOf(body.slice(pos + 1));
    const remove = options.filter((o) => o === "removeparam" || o.startsWith("removeparam="));
    if (!remove.length) continue;
    const rawName = remove.length === 1 && remove[0].startsWith("removeparam=") ? remove[0].slice(12) : null;
    const name = rawName !== null && policy.NAME.test(rawName) && !rawName.startsWith("~") ? rawName : null;
    return {line, exception, pattern: body.slice(0, pos), options, rawName, name, all: remove.length === 1 && remove[0] === "removeparam", malformed: remove.length !== 1};
  }
  return null;
}

function badKey(row) {
  return (row.exception ? "@@" : "") + row.pattern + "$" + row.options.filter((o) => o !== "badfilter").sort().join(",");
}

function evaluateCondition(text) {
  if (text.length > 256) throw Error("conditional-too-long");
  const tokens = text.match(/&&|\|\||[!()]|[A-Za-z_][A-Za-z_0-9]*/g) || [];
  if (tokens.join("") !== text.replace(/\s/g, "")) throw Error("conditional-syntax");
  const env = {ext_ubol: true, env_chromium: true, env_mv3: true, env_firefox: false};
  let i = 0;
  function atom() {
    const t = tokens[i++];
    if (t === "!") return !atom();
    if (t === "(") { const value = or(); if (tokens[i++] !== ")") throw Error("conditional-syntax"); return value; }
    if (!Object.hasOwn(env, t)) throw Error("unknown-conditional");
    return env[t];
  }
  function and() { let value = atom(); while (tokens[i] === "&&") { i++; const next = atom(); value = value && next; } return value; }
  function or() { let value = and(); while (tokens[i] === "||") { i++; const next = and(); value = value || next; } return value; }
  const value = or();
  if (i !== tokens.length) throw Error("conditional-syntax");
  return value;
}

function destinationList(value) {
  if (!value || value.length > 16000) return null;
  const include = [], exclude = [];
  for (let item of value.split("|")) {
    const negative = item.startsWith("~"); if (negative) item = item.slice(1);
    item = item.toLowerCase();
    if (!hostOK(item)) return null; // Drop the whole predicate, never just an invalid arm.
    (negative ? exclude : include).push(item);
  }
  return {include: sorted(include), exclude: sorted(exclude)};
}

function typeScope(row) {
  const positive = row.options.filter((o) => TYPES.has(o));
  if (row.options.some((o) => ["~doc", "~document", "~all"].includes(o))) return false;
  return !positive.length || positive.some((o) => ["doc", "document", "all"].includes(o));
}

function hostAnchor(pattern, allowPath) {
  if (!pattern || pattern === "*") return {include: [], exclude: [], excludeLabels: [], exact: true};
  const match = /^\|\|([^/^?*|]+)(.*)$/.exec(pattern);
  if (match && hostOK(match[1].toLowerCase()) && (allowPath ? /^[\^/]|^\|$/.test(match[2]) : match[2] === "^"))
    return {include: [match[1].toLowerCase()], exclude: [], excludeLabels: [], exact: match[2] === "^"};
  // An entity exemption is conservatively widened to every hostname containing
  // the entity label. This cannot remove a parameter the source would preserve.
  if (allowPath) {
    const entity = /^\|\|(?:[a-z0-9-]+\.)*([a-z0-9-]+)\.\*(?:[\^/|?]|$)/.exec(pattern);
    if (entity && policy.LABEL.test(entity[1])) return {include: [], exclude: [], excludeLabels: [entity[1]], exact: false};
  }
  return null;
}

function mergeInclude(a, b) {
  if (!a.length) return b;
  if (!b.length) return a;
  const out = [];
  for (const x of a) for (const y of b) {
    if (covers(x, [y])) out.push(x);
    else if (covers(y, [x])) out.push(y);
  }
  return sorted(out);
}

// Long exact-label complements exceed Chrome's 2 KiB RE2 program budget. Widen
// entity exemptions to three-character DNS-label prefixes, and emit a compact
// regular language that cannot cross a hostname's dot or first path slash.
function labelPrefixComplement(words) {
  const tree = {end: false, children: new Map()};
  for (const word of sorted(words)) {
    let node = tree;
    for (const ch of word) {
      if (!node.children.has(ch)) node.children.set(ch, {end: false, children: new Map()});
      node = node.children.get(ch);
    }
    node.end = true;
  }
  function emit(node, depth) {
    const alternatives = depth ? [""] : [];
    const excluded = [...node.children.keys()].map((ch) => ch === "-" ? "\\-" : ch).join("");
    alternatives.push("[^./" + excluded + "][^./]*");
    for (const [ch, child] of node.children) if (!child.end) alternatives.push(escapeRE(ch) + emit(child, depth + 1));
    return "(?:" + alternatives.join("|") + ")";
  }
  return emit(tree, 0);
}

function presentRegex(names, labels = []) {
  let prefix = "^https?://[^?#]*";
  if (labels.length) {
    const allowed = labelPrefixComplement(labels);
    // Port punctuation is consumed inside the final label alternative. A
    // forbidden prefix still cannot cross the label boundary before that port.
    prefix = "^https?://(?:" + allowed + "\\.)*" + allowed + "\\.?/[^?#]*";
  }
  return prefix + "\\?(?:[^&#]*&)*(?:" + names.map(escapeRE).join("|") + ")(?:=|&|$)";
}

function chunks(names) {
  const out = []; let group = [], size = 0;
  for (const name of names) {
    const n = escapeRE(name).length + 1;
    if (group.length && size + n > PRESENCE_CHUNK) { out.push(group); group = []; size = 0; }
    group.push(name); size += n;
  }
  if (group.length) out.push(group);
  return out;
}

// Turn overlapping host predicates into disjoint destination regions. Rules in
// one region remove its entire family in one transform; present-key chunks do
// not cause extra redirects because they share that complete action.
function partition(groups) {
  const boundaries = sorted(groups.flatMap((g) => [...g.include, ...g.exclude]));
  if (boundaries.length > 4000) throw Error("destination-boundary-budget");
  const value = (host) => sorted(groups.filter((g) => (!g.include.length || !!host && covers(host, g.include)) && (!host || !covers(host, g.exclude))).flatMap((g) => g.names));
  const root = {host: "", names: value(""), children: []}, nodes = new Map([["", root]]);
  const ordered = [...boundaries].sort((a, b) => a.split(".").length - b.split(".").length || a.localeCompare(b));
  for (const host of ordered) {
    let suffix = host, parent = root;
    while (suffix.includes(".")) { suffix = suffix.slice(suffix.indexOf(".") + 1); if (nodes.has(suffix)) { parent = nodes.get(suffix); break; } }
    const names = value(host);
    // Redundant boundaries do not split an otherwise identical action.
    if (names.join("\n") === parent.names.join("\n")) continue;
    const node = {host, names, children: []}; parent.children.push(node); nodes.set(host, node);
  }
  const regions = [];
  for (const node of nodes.values()) if (node.names.length) regions.push({include: node.host ? [node.host] : [], exclude: node.children.map((child) => child.host), names: node.names});
  const merged = [];
  for (const region of regions) {
    const key = region.names.join("\n");
    const target = merged.find((old) => old.key === key && old.include.length && region.include.length &&
      !old.include.some((h) => covers(h, region.exclude)) && !region.include.some((h) => covers(h, old.exclude)));
    if (target) { target.include.push(...region.include); target.exclude.push(...region.exclude); }
    else merged.push({...region, key});
  }
  return merged;
}

function rulesFor(data, priority) {
  if (data.disabled) return [];
  const rules = [], families = new Map();
  // Unconditional/global, conditional/global and scoped policies get separate
  // passes. Splitting by label exemptions avoids weakening another key's guard.
  const commonExclusions = JSON.stringify(data.pathExcludedHosts);
  for (const original of data.groups) {
    const labels = original.excludeLabelPrefixes || [], names = original.names.filter((name) => NATIVE_NAME.test(name) && (!labels.length || name.length <= 12));
    if (!names.length) continue;
    const group = {...original, names};
    const kind = group.include.length ? "scoped" : JSON.stringify(group.exclude) === commonExclusions ? "common" : "conditional";
    const key = kind + ":" + labels.join(",");
    if (!families.has(key)) families.set(key, {groups: [], labels});
    families.get(key).groups.push(group);
  }
  for (const {groups, labels} of families.values()) for (const region of partition(groups)) for (const someNames of labels.length ? region.names.map((name) => [name]) : chunks(region.names)) {
    const regexFilter = presentRegex(someNames, labels);
    if (regexFilter.length > MAX_REGEX_SOURCE) throw Error("regex-source-budget");
    const condition = {regexFilter, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame"], requestMethods: ["get"]};
    if (region.include.length) condition.requestDomains = sorted(region.include);
    if (region.exclude.length) condition.excludedRequestDomains = sorted(region.exclude);
    rules.push({priority, action: {type: "redirect", redirect: {transform: {queryTransform: {removeParams: region.names}}}}, condition});
  }
  const pathExcludedHosts = sorted([...data.pathExcludedHosts, ...params.EXCLUDED_HOSTS]);
  const pathDomains = params.AMAZON.filter((domain) => !covers(domain, pathExcludedHosts) &&
    !data.pathExcludedLabelPrefixes.some((prefix) => domain.split(".").some((label) => label.startsWith(prefix))));
  if (pathDomains.length) {
    const label = data.pathExcludedLabelPrefixes.length ? labelPrefixComplement(data.pathExcludedLabelPrefixes) : null;
    const authority = label ? "(?:" + label + "\\.)*" + label + "\\.?" : "[^/?#]+";
    const regexFilter = "^(https?://" + authority + "(?:/[^?#]*?)?)/ref=[^/?#]*(.*)$";
    if (regexFilter.length > MAX_REGEX_SOURCE) throw Error("regex-source-budget");
    rules.push({priority, action: {type: "redirect", redirect: {regexSubstitution: "\\1\\2"}}, condition: {
      regexFilter,
      isUrlFilterCaseSensitive: true, requestDomains: pathDomains, excludedRequestDomains: pathExcludedHosts,
      resourceTypes: ["main_frame"], requestMethods: ["get"]}});
  }
  // Fixed code-owned brakes alone can emit allow. Source exemptions above only
  // shrink redirect predicates. Higher-priority header sanitation still applies.
  for (const regexFilter of params.PRESERVE_URL_REGEXES) rules.push({priority, action: {type: "allow"}, condition: {
    regexFilter, isUrlFilterCaseSensitive: false, excludedRequestDomains: [...params.EXCLUDED_HOSTS],
    resourceTypes: ["main_frame"], requestMethods: ["get"]}});
  if (rules.length > MAX_REGEX_RULES) throw Error("regex-rule-budget");
  return rules.map((rule, i) => ({id: i + 1, ...rule}));
}

function compileRemoveParams(textOrEmpty, {priority = 9, allowReduced = false} = {}) {
  if (typeof textOrEmpty !== "string") throw TypeError("Parameter source must be text");
  if (textOrEmpty.length > 4 * 1024 * 1024) throw RangeError("Parameter source exceeds the bounded compiler size");
  if (!Number.isSafeInteger(priority) || priority < 1) throw TypeError("Invalid parameter priority");
  const available = !!textOrEmpty.trim(), stats = {sourceRows: 0, removeparamRows: 0, importedRules: 0, exceptionRows: 0,
    effectiveNames: 0, rules: 0, unsupported: 0, ignoredNonRemoval: 0, inactiveRows: 0, badfiltered: 0, keptRows: 0,
    coarsenedExceptions: 0, compatibilityExclusions: 0, quarantined: 0, coarsenedEntityPrefixes: [], prefixGroupFallbacks: 0,
    explicitlyDisabledNames: [], nativeEffectiveNames: 0, reasons: {}};
  const reasons = (reason, count = 1) => { stats.reasons[reason] = (stats.reasons[reason] || 0) + count; };
  const unsafe = [], quarantine = new Set(), rows = [], inactive = [], stack = [];
  let active = true;
  for (const [index, raw] of textOrEmpty.split(/\r?\n/).entries()) {
    const line = raw.trim(); if (!line) continue;
    if (line.startsWith("!#")) {
      try {
        if (line.startsWith("!#if ")) {
          if (stack.length >= 8) throw Error("conditional-depth");
          const condition = evaluateCondition(line.slice(5)); stack.push({parent: active, condition, elseSeen: false}); active = active && condition;
        } else if (line === "!#else") {
          const top = stack[stack.length - 1]; if (!top || top.elseSeen) throw Error("conditional-else"); top.elseSeen = true; active = top.parent && !top.condition;
        } else if (line === "!#endif") {
          const top = stack.pop(); if (!top) throw Error("conditional-endif"); active = top.parent;
        } else throw Error("unsupported-directive");
      } catch (error) { unsafe.push({line: index + 1, reason: error.message}); }
      continue;
    }
    if (line.startsWith("!") || /^\[Adblock.*\]$/.test(line)) continue;
    stats.sourceRows++;
    if (stats.sourceRows > MAX_ROWS || line.length > MAX_LINE) { unsafe.push({line: index + 1, reason: "source-budget"}); continue; }
    const row = parseLine(line);
    if (!row) {
      if (line.startsWith("@@") && /(?:\$|,)removeparam(?:=|,|$)/.test(line)) unsafe.push({line: index + 1, reason: "malformed-parameter-exception"});
      else stats.ignoredNonRemoval++;
      continue;
    }
    row.number = index + 1; stats.removeparamRows++;
    if (!active) { stats.inactiveRows++; inactive.push(row); continue; }
    rows.push(row);
  }
  if (stack.length) unsafe.push({reason: "unclosed-conditional"});
  const disabledKeys = new Set(rows.filter((r) => r.options.includes("badfilter")).map(badKey));
  const live = rows.filter((row) => {
    if (row.options.includes("badfilter") || disabledKeys.has(badKey(row))) { stats.badfiltered++; return false; }
    return true;
  });
  const exceptions = new Map(), allHosts = new Set(params.EXCLUDED_HOSTS), allLabels = new Set(), explicitlyDisabledNames = new Set();
  function exempt(name, scope, reason) {
    if (!scope) {
      if (name) { quarantine.add(name); reasons(reason || "unrepresented-named-exception"); }
      else unsafe.push({reason: reason || "unbounded-all-parameter-exception"});
      return;
    }
    if (!name) {
      if (!scope.include.length && !scope.excludeLabels.length) { unsafe.push({reason: "unbounded-all-parameter-exception"}); return; }
      for (const host of scope.include) allHosts.add(host);
      for (const label of scope.excludeLabels) allLabels.add(label);
      return;
    }
    if (!exceptions.has(name)) exceptions.set(name, {hosts: new Set(), labels: new Set()});
    const item = exceptions.get(name);
    if (!scope.include.length && !scope.excludeLabels.length) { quarantine.add(name); return; }
    for (const host of scope.include) item.hosts.add(host);
    for (const label of scope.excludeLabels) item.labels.add(label);
  }
  function exceptionScope(row) {
    const scope = hostAnchor(row.pattern, true);
    if (scope && (scope.include.length || scope.excludeLabels.length)) return scope;
    const to = row.options.find((o) => o.startsWith("to="));
    if (to) {
      const parsed = destinationList(to.slice(3));
      if (parsed && parsed.include.length) return {...parsed, excludeLabels: [], exact: false};
    }
    // First-party-only + finite positive initiator sites bounds the destination
    // too. Widen to each registrable site, including the pinned private PSL.
    const domain = row.options.find((o) => o.startsWith("domain=") || o.startsWith("from="));
    if (domain && row.options.some((o) => ["~3p", "~third-party", "1p", "first-party"].includes(o))) {
      const parsed = destinationList(domain.slice(domain.indexOf("=") + 1));
      if (parsed && parsed.include.length && !parsed.exclude.length) {
        const sites = parsed.include.map((host) => hosts.siteOf(host));
        if (sites.every(hostOK)) return {include: sorted(sites), exclude: [], excludeLabels: [], exact: false};
      }
    }
    return null;
  }
  // A matching legacy remover must not recreate a literal rule explicitly
  // disabled by the maintained source. Contextual disables conservatively
  // preserve more destinations, never remove more query information.
  for (const row of rows.filter((r) => !r.exception && r.options.includes("badfilter") && r.name && typeScope(r))) {
    const scope = exceptionScope(row);
    if (scope) exempt(row.name, scope);
    else if (!row.pattern || row.pattern === "*") explicitlyDisabledNames.add(row.name);
    else exempt(row.name, null, "unrepresented-badfilter-scope");
  }
  for (const row of live.filter((r) => r.exception)) {
    stats.exceptionRows++;
    if (!typeScope(row)) { reasons("exception-outside-main-frame"); continue; }
    if (row.malformed || !row.all && !row.name) { unsafe.push({line: row.number, reason: "unbounded-parameter-exception"}); continue; }
    const scope = exceptionScope(row);
    if (scope && (!scope.exact || row.options.some((o) => /^(domain|from|to)=|^(?:~?3p|~?third-party|1p|first-party)$/.test(o)))) stats.coarsenedExceptions++;
    exempt(row.name, scope);
  }
  // A compatibility branch explicitly omitted for MV3 must not be recreated by
  // a legacy name set. Its literal names become conservative scoped exemptions.
  for (const row of inactive) if (!row.exception && row.name) {
    exempt(row.name, exceptionScope(row), "inactive-compatibility-name"); stats.compatibilityExclusions++;
  }
  const removers = [];
  for (const row of live.filter((r) => !r.exception)) {
    if (!typeScope(row)) { reasons("remover-outside-main-frame"); continue; }
    if (row.malformed || !row.name) { stats.unsupported++; reasons(row.all ? "remove-all-unsupported" : "nonliteral-name"); continue; }
    if (KEPT.has(row.name)) { stats.keptRows++; continue; }
    let scope = hostAnchor(row.pattern, false), unsupported = null;
    if (!scope) unsupported = "url-pattern-unsupported";
    for (const option of row.options) {
      if (option.startsWith("removeparam=") || TYPES.has(option) || option.startsWith("~") && TYPES.has(option.slice(1))) continue;
      if (option === "match-case" && row.pattern === row.pattern.toLowerCase()) continue;
      if (option.startsWith("to=")) {
        const to = destinationList(option.slice(3));
        if (!to) { unsupported = "destination-scope-unsupported"; continue; }
        // Explicit exclusions veto legacy overlap as well as this source row.
        if (to.exclude.length) exempt(row.name, {include: to.exclude, excludeLabels: []});
        if (scope) {
          const include = mergeInclude(scope.include, to.include);
          if (scope.include.length && to.include.length && !include.length) { unsupported = "empty-destination-intersection"; continue; }
          scope = {...scope, include, exclude: sorted([...scope.exclude, ...to.exclude])};
        }
      } else unsupported = option.startsWith("domain=") || option.startsWith("from=") ? "initiator-scope-unsupported" : "modifier-unsupported";
    }
    if (unsupported) { stats.unsupported++; reasons(unsupported); continue; }
    removers.push({...scope, names: [row.name], imported: true});
  }
  const baseline = [{names: [...params.GLOBAL], include: [], exclude: [], excludeLabels: [], imported: false},
    ...params.SCOPED.map((g) => ({names: g.params, include: g.domains, exclude: [], excludeLabels: [], imported: false}))];
  const entityLabels = sorted([...allLabels, ...[...exceptions.values()].flatMap((x) => [...x.labels])]);
  stats.coarsenedEntityPrefixes = entityLabels.map((label) => ({label, prefix: label.slice(0, 3)}));
  const pathExcludedHosts = sorted(allHosts), pathExcludedLabelPrefixes = sorted([...allLabels].map((label) => label.slice(0, 3))), grouped = new Map();
  for (const row of [...baseline, ...removers]) for (const name of row.names) {
    if (KEPT.has(name) || quarantine.has(name) || explicitlyDisabledNames.has(name)) continue;
    const exception = exceptions.get(name), exclude = sorted([...pathExcludedHosts, ...row.exclude, ...(exception ? exception.hosts : [])]);
    let excludeLabelPrefixes = sorted([...pathExcludedLabelPrefixes, ...row.excludeLabels.map((label) => label.slice(0, 3)), ...(exception ? [...exception.labels].map((label) => label.slice(0, 3)) : [])]);
    // Several unrelated entity exemptions can make even a short complement too
    // large. First-character prefixes are a further conservative narrowing.
    if (excludeLabelPrefixes.length > 1) { excludeLabelPrefixes = sorted(excludeLabelPrefixes.map((prefix) => prefix[0])); stats.prefixGroupFallbacks++; }
    const include = sorted(row.include).filter((host) => !covers(host, exclude) && !excludeLabelPrefixes.some((prefix) => host.split(".").some((label) => label.startsWith(prefix))));
    if (row.include.length && !include.length) continue;
    const key = JSON.stringify([include, exclude, excludeLabelPrefixes]);
    if (!grouped.has(key)) grouped.set(key, {names: new Set(), include, exclude, excludeLabelPrefixes});
    grouped.get(key).names.add(name);
    if (row.imported) stats.importedRules++;
  }
  stats.quarantined = quarantine.size;
  stats.explicitlyDisabledNames = sorted(explicitlyDisabledNames);
  const coverage = {available, reduced: unsafe.length > 0 || quarantine.size > 0, disabled: unsafe.length > 0,
    quarantined: sorted(quarantine), supportedSyntax: "literal-query-names-v1", mainFrameGetOnly: true, unsafe: unsafe.slice(0, 20)};
  if (coverage.reduced && !allowReduced) throw Object.assign(new Error("Parameter policy requires an explicit reduced build: " +
    [...unsafe.map((x) => x.reason), ...[...quarantine].map((name) => "quarantined:" + name)].slice(0, 10).join(", ")), {coverage, stats});
  const data = {schema: 1, generated: true, available, disabled: coverage.disabled,
    groups: coverage.disabled ? [] : [...grouped.values()].map((g) => ({...g, names: sorted(g.names)})),
    pathExcludedHosts, pathExcludedLabelPrefixes, quarantined: coverage.quarantined, coverage};
  if (!policy.prepare(data)) throw Error("Generated parameter policy failed validation");
  let rules;
  try { rules = rulesFor(data, priority); }
  catch (error) {
    if (!allowReduced) throw error;
    coverage.reduced = true; coverage.disabled = true; coverage.unsafe.push({reason: error.message}); data.disabled = true; data.groups = []; rules = [];
  }
  stats.rules = rules.length;
  stats.effectiveNames = new Set(data.groups.flatMap((g) => g.names)).size;
  stats.nativeEffectiveNames = new Set(rules.flatMap((r) => r.action.redirect && r.action.redirect.transform ? r.action.redirect.transform.queryTransform.removeParams : [])).size;
  coverage.nativeDeferredNames = sorted(data.groups.flatMap((g) => g.names.filter((name) => !NATIVE_NAME.test(name) || g.excludeLabelPrefixes.length && name.length > 12)));
  if (data.disabled) stats.importedRules = 0;
  return {data, rules, stats, coverage};
}

module.exports = {compileRemoveParams, parseLine, optionsOf, presentRegex, labelPrefixComplement, partition, rulesFor, MAX_REGEX_RULES};
