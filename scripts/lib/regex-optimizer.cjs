"use strict";
/* Optional build-time optimization. The verifier is supplied by the build;
 * this module never spawns a process, installs an engine, or opens a browser.
 *
 * Proof envelope: replace rules with the SAME complete action, priority, and
 * every non-regex field by one predicate equal to their disjunction. Thus the
 * set of eligible (priority, action) pairs is unchanged for every request.
 * Rule ids/debug matches may change. Undocumented same-priority tie-breaking
 * between different redirect actions is not made deterministic by this pass.
 * Capture substitution and modifyHeaders are excluded: captures, match ranges,
 * and repeated header operations are not Boolean-action semantics.
 */
const {unionPatterns} = require("./regex-language.cjs");
const MAX_OPERANDS = 8;
const MAX_CHECKS = 10000;

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
}

function identity(rule) {
  if (!rule || !rule.condition || typeof rule.condition.regexFilter !== "string" ||
      !["allow", "block", "redirect"].includes(rule.action?.type) ||
      (rule.action.type === "redirect" && (!rule.action.redirect || "regexSubstitution" in rule.action.redirect)) ||
      (rule.condition.isUrlFilterCaseSensitive !== undefined && typeof rule.condition.isUrlFilterCaseSensitive !== "boolean")) return null;
  const {id, condition: {regexFilter, ...condition}, ...rest} = rule;
  return JSON.stringify(stable({...rest, condition}));
}

/** verifyRegex({regex, isCaseSensitive, requireCapturing:false}) must return
 * a Boolean resource approval from the selected RE2 verifier, using max_mem
 * 2048 and Latin1 for Chrome. No verifier means no transformation. A verifier
 * error aborts this optional pass rather than claiming an unchecked result.
 */
async function optimizeRegexRules(rules, {verifyRegex, maxOperands = MAX_OPERANDS, maxChecks = MAX_CHECKS} = {}) {
  if (!Array.isArray(rules)) throw TypeError("Rules must be an array");
  if (!Number.isInteger(maxOperands) || maxOperands < 2 || maxOperands > MAX_OPERANDS ||
      !Number.isInteger(maxChecks) || maxChecks < 1 || maxChecks > MAX_CHECKS) throw RangeError("Invalid bounded optimizer budget");
  const stats = {schema: 1, algorithm: "exact-action-regex-union-v1", inputRegexRules: rules.filter((r) => typeof r?.condition?.regexFilter === "string").length,
    outputRegexRules: 0, saved: 0, mergedGroups: 0, candidateAttempts: 0, resourceChecks: 0, rejectedChecks: 0, syntaxRefusals: 0,
    checkBudgetExhausted: false, verifierSupplied: typeof verifyRegex === "function", nativeChrome: false};
  if (!stats.verifierSupplied) { stats.outputRegexRules = stats.inputRegexRules; return {rules: [...rules], merges: [], stats}; }
  const groups = new Map();
  for (let index = 0; index < rules.length; index++) {
    const key = identity(rules[index]);
    if (key === null) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(index);
  }
  const replacements = new Map(), removed = new Set(), merges = [], checked = new Map();
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const batches = [];
    // First-fit in stable source-length order is deterministic, bounded, and
    // makes no claim to find a globally minimal number of regex rules.
    for (const index of [...members].sort((a, b) => rules[a].condition.regexFilter.length - rules[b].condition.regexFilter.length || a - b)) {
      let placed = false;
      for (const batch of batches) {
        if (batch.indices.length >= maxOperands || stats.candidateAttempts >= maxChecks) continue;
        stats.candidateAttempts++;
        const indices = [...batch.indices, index];
        const regex = unionPatterns(indices.map((i) => rules[i].condition.regexFilter));
        if (regex === null) { stats.syntaxRefusals++; continue; }
        const isCaseSensitive = rules[index].condition.isUrlFilterCaseSensitive ?? false;
        const key = JSON.stringify([isCaseSensitive, regex]);
        let supported = checked.get(key);
        if (supported === undefined) {
          stats.resourceChecks++;
          supported = await verifyRegex({regex, isCaseSensitive, requireCapturing: false});
          if (typeof supported !== "boolean") throw TypeError("Regex verifier must return a Boolean");
          checked.set(key, supported);
          if (!supported) stats.rejectedChecks++;
        }
        if (!supported) continue;
        batch.indices.push(index); batch.regex = regex; placed = true; break;
      }
      if (!placed) batches.push({indices: [index], regex: rules[index].condition.regexFilter});
    }
    for (const batch of batches) {
      if (batch.indices.length < 2) continue;
      const indices = [...batch.indices].sort((a, b) => a - b), first = indices[0];
      replacements.set(first, {...rules[first], condition: {...rules[first].condition, regexFilter: batch.regex}});
      for (const index of indices.slice(1)) removed.add(index);
      merges.push({intoIndex: first, fromIndices: indices, sourceIds: indices.map((i) => rules[i].id ?? null)});
    }
  }
  const output = rules.flatMap((rule, index) => removed.has(index) ? [] : [replacements.get(index) || rule]);
  stats.outputRegexRules = stats.inputRegexRules - removed.size;
  stats.saved = removed.size; stats.mergedGroups = merges.length;
  stats.checkBudgetExhausted = stats.candidateAttempts >= maxChecks;
  return {rules: output, merges: merges.sort((a, b) => a.intoIndex - b.intoIndex), stats};
}

module.exports = Object.freeze({optimizeRegexRules, MAX_OPERANDS, MAX_CHECKS});
