"use strict";
const crypto = require("node:crypto");
const {unionPatterns} = require("./regex-language.cjs");

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
}
const encoded = (value) => JSON.stringify(stable(value));
const digest = (value) => crypto.createHash("sha256").update(encoded(value)).digest("hex");
function withoutPredicate(rule) {
  const {id, condition: {regexFilter, ...condition}, ...rest} = rule;
  return {...rest, condition};
}

/** A replayable proof record contains indices and hashes, not whole domain
 * lists or raw regex dumps. Verification reconstructs every changed rule and
 * ensures every untouched rule remains byte-for-byte equal as JSON data.
 */
function makePlan(rulesets, results, sources) {
  const entries = {};
  for (const [name, before] of Object.entries(rulesets)) {
    const result = results[name], after = result.rules;
    entries[name] = {beforeSha256: digest(before), afterSha256: digest(after), beforeRules: before.length, afterRules: after.length,
      stats: result.stats, merges: result.merges.map((merge) => ({...merge,
        invariantSha256: digest(withoutPredicate(before[merge.intoIndex])),
        inputPatternSha256: merge.fromIndices.map((index) => digest(before[index].condition.regexFilter)),
        outputPatternSha256: digest(unionPatterns(merge.fromIndices.map((index) => before[index].condition.regexFilter)))}))};
  }
  return {schema: 1, algorithm: "exact-action-regex-union-v1", equivalence: "eligible-priority-action-pairs",
    nativeChrome: false, sources, beforeSha256: digest(rulesets), afterSha256: digest(Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.rules]))),
    rulesets: entries};
}

function validatePlan(rulesets, optimized, plan) {
  const fail = () => { throw Error("Regex optimization proof record is incomplete or inconsistent"); };
  if (!plan || plan.schema !== 1 || plan.algorithm !== "exact-action-regex-union-v1" || plan.nativeChrome !== false ||
      plan.equivalence !== "eligible-priority-action-pairs" || plan.beforeSha256 !== digest(rulesets) || plan.afterSha256 !== digest(optimized) ||
      encoded(Object.keys(rulesets).sort()) !== encoded(Object.keys(optimized || {}).sort()) ||
      encoded(Object.keys(rulesets).sort()) !== encoded(Object.keys(plan.rulesets || {}).sort())) fail();
  for (const [name, before] of Object.entries(rulesets)) {
    const after = optimized[name], entry = plan.rulesets[name];
    if (!Array.isArray(before) || !Array.isArray(after) || !entry || entry.beforeSha256 !== digest(before) ||
        entry.afterSha256 !== digest(after) || entry.beforeRules !== before.length || entry.afterRules !== after.length || !Array.isArray(entry.merges)) fail();
    const replaced = new Map(), removed = new Set(), used = new Set();
    for (const merge of entry.merges) {
      if (!merge || !Array.isArray(merge.fromIndices) || merge.fromIndices.length < 2 || merge.fromIndices.length > 8 ||
          merge.fromIndices.some((index, offset) => !Number.isInteger(index) || index < 0 || index >= before.length ||
            used.has(index) || (offset && index <= merge.fromIndices[offset - 1])) || merge.intoIndex !== merge.fromIndices[0]) fail();
      const original = before[merge.intoIndex];
      if (!original?.condition || typeof original.condition.regexFilter !== "string" || !["allow", "block", "redirect"].includes(original.action?.type) ||
          (original.action.type === "redirect" && (!original.action.redirect || "regexSubstitution" in original.action.redirect))) fail();
      const invariant = digest(withoutPredicate(original));
      if (merge.invariantSha256 !== invariant || encoded(merge.sourceIds) !== encoded(merge.fromIndices.map((index) => before[index].id ?? null)) ||
          encoded(merge.inputPatternSha256) !== encoded(merge.fromIndices.map((index) => digest(before[index].condition?.regexFilter)))) fail();
      for (const index of merge.fromIndices) {
        if (!before[index]?.condition || typeof before[index].condition.regexFilter !== "string" || digest(withoutPredicate(before[index])) !== invariant) fail();
        used.add(index);
      }
      const regexFilter = unionPatterns(merge.fromIndices.map((index) => before[index].condition.regexFilter));
      if (regexFilter === null || merge.outputPatternSha256 !== digest(regexFilter)) fail();
      replaced.set(merge.intoIndex, {...original, condition: {...original.condition, regexFilter}});
      for (const index of merge.fromIndices.slice(1)) removed.add(index);
    }
    const replay = before.flatMap((rule, index) => removed.has(index) ? [] : [replaced.get(index) || rule]);
    if (encoded(replay) !== encoded(after) || entry.stats?.saved !== removed.size || entry.stats?.mergedGroups !== entry.merges.length ||
        entry.stats?.inputRegexRules !== before.filter((rule) => typeof rule.condition?.regexFilter === "string").length ||
        entry.stats?.outputRegexRules !== after.filter((rule) => typeof rule.condition?.regexFilter === "string").length) fail();
  }
  return true;
}

module.exports = Object.freeze({digest, canonicalJSON: encoded, makePlan, validatePlan});
