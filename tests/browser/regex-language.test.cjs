"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {lowerToUrlFilters, unionPatterns} = require("../../scripts/lib/regex-language.cjs");
const {optimizeRegexRules} = require("../../scripts/lib/regex-optimizer.cjs");
const abp = require("../../scripts/lib/abp-dnr.cjs");
const {urlFilterRegex} = require("../../scripts/lib/dnr-benchmark.cjs");

function languageMatches(patterns, value, sensitive = true) {
  return patterns.some((pattern) => new RegExp(pattern, sensitive ? "" : "i").test(value));
}
function checkLowered(source, values, sensitive = true) {
  const filters = lowerToUrlFilters(source);
  assert.ok(filters, source);
  for (const value of values) assert.equal(languageMatches(filters.map(urlFilterRegex), value, sensitive),
    languageMatches([source], value, sensitive), `${source}: ${JSON.stringify(value)}`);
  return filters;
}
function words(alphabet, length) {
  const out = [""]; let current = [""];
  for (let i = 0; i < length; i++) { current = current.flatMap((prefix) => alphabet.map((char) => prefix + char)); out.push(...current); }
  return out;
}

test("finite URL-filter lowering preserves anchors, exact protocols, ports, encodings and fragments", () => {
  const source = "^https?://collector\\.example(:8443)?/(?:pixel|events)\\?id=(?:A|B)%2F.*$";
  const values = [];
  for (const scheme of ["http", "https", "httpx", "ws", "ftp"]) for (const authority of ["collector.example", "collector.example:8443",
    "collector.example:443", "collector.example.evil", "user@collector.example", "xn--collector-9za.example"])
    for (const path of ["/pixel", "/events", "/pixels", "/Pixel"]) for (const query of ["?id=A%2Fabc", "?id=B%2fabc", "?id=A/abc", "?id=AB%2Fabc", "?id=A%2Fabc#fragment"])
      values.push(`${scheme}://${authority}${path}${query}`);
  values.push("https://safe.example/?next=https://collector.example/pixel?id=A%2Fabc");
  assert.equal(checkLowered(source, values).length, 16);
  checkLowered(source, values, false);
  const tlds = "^https?:\\/\\/.*\\.(club|news|live|online)\\/.*";
  checkLowered(tlds, ["https://ads.club/a", "http://ads.news/", "wss://ads.live/", "https://ads.online:443/a",
    "https://safe.example/path/ads.club/a", "https://safe.example/#https://ads.club/a", "https://ads.club.evil/a", "https://ads.club", "HTTPS://ADS.CLUB/A"], false);
});

test("finite expansion agrees on an exhaustive small ASCII language and never invents separator semantics", () => {
  const values = words(["a", "b", "/", "?", "%", "&"], 5);
  for (const source of ["a", "^a", "a$", "^a$", "a.*b", "^(a|b)/", "(a|b){2}", "^a?b$", "a(?:/b)?", "^a(?:|b)/", "a\\?b", "%2F", "^a.*?b$"])
    checkLowered(source, values);
  assert.deepEqual(lowerToUrlFilters("^https?://a\\.example/"), ["|http://a.example/", "|https://a.example/"]);
  assert.ok(lowerToUrlFilters("a.*b").every((filter) => !filter.includes("^") && !filter.startsWith("||")));
});

test("unrepresentable atoms, broad empty alternatives and expansion overflow retain their regex", () => {
  for (const source of ["[ab]", "a+", "a*", ".+", ".", "\\d+", "\\bword\\b", "\\x41", "\\Qliteral\\E", "(?i)abc",
    "(?i:abc)", "a\\*b", "a\\^b", "a\\|b", "a\\\\b", "a^b", "a$b", "(?:a|)", "a?", ".*", "^$", "é", "a\nb", "a b", "a{65}",
    "^(a|b)(a|b)(a|b)(a|b)(a|b)(a|b)(a|b)(a|b)$", "(".repeat(34) + "a" + ")".repeat(34)]) assert.equal(lowerToUrlFilters(source), null, source);
  assert.equal(lowerToUrlFilters("a|b", {maxFilters: 1}), null);
  assert.equal(lowerToUrlFilters("abc", {maxFilterLength: 2}), null);
  assert.equal(lowerToUrlFilters("a", {maxFilters: 1000000}), null);
  assert.equal(abp.compileFilters("/a+b/$script").block[0].condition.regexFilter, "a+b");
});

test("ABP lowering retains every non-pattern condition, source authority, case flag and badfilter", () => {
  const pattern = "/^https?:\\/\\/collector\\.example\\/(pixel|events)\\?id=(A|B)%2F.*$/";
  const options = "$script,third-party,domain=publisher.example|~account.publisher.example,to=collector.example,method=get,match-case";
  for (const prefix of ["", "@@"]) {
    const original = abp.parseLine(prefix + pattern + options), compiled = abp.compileFilters(prefix + pattern + options, {maxRegex: 0});
    const rules = prefix ? compiled.allow : compiled.block;
    const {regexFilter, ...other} = original.condition;
    assert.equal(compiled.stats.converted, 1);
    assert.equal(compiled.stats.regexLoweredFilters, 1);
    assert.equal(compiled.stats.regexLoweredRules, 8);
    assert.equal(compiled.stats.regexLoweredSlots, 1);
    assert.equal(compiled.stats.regex, 0);
    for (const rule of rules) {
      const {urlFilter, ...condition} = rule.condition;
      assert.deepEqual(condition, other);
      assert.equal(rule.action.type, prefix ? "allow" : "block");
      assert.ok(urlFilter.startsWith("|http"));
    }
    const disabled = abp.compileFilters(prefix + pattern + options + "\n" + prefix + pattern + options + ",badfilter");
    assert.equal(disabled.stats.regexLoweredRules, 0);
    assert.equal(disabled.block.length + disabled.allow.length, 0);
  }
  assert.equal(abp.compileFilters("@@/^https?:\\/\\/collector\\.example\\/pixel$/").allow.length, 0,
    "lowering does not newly authorize a source exception that failed concrete-scope validation");
  const ordinary = abp.compileFilters("/pixel\\?id=ABC/$script").block[0];
  assert.equal(ordinary.condition.isUrlFilterCaseSensitive, false);
});

test("source-row accounting is separate from expanded URL-filter and eliminated regex counts", () => {
  const source = "/^https?:\\/\\/.*\\.(a|b|c|d|e|f|g|h|i)\\/.*$/";
  const compiled = abp.compileFilters(source + "$script");
  assert.equal(compiled.stats.converted, 1);
  assert.equal(compiled.stats.regexLoweredFilters, 1);
  assert.equal(compiled.stats.regexLoweredRules, 18);
  assert.equal(compiled.stats.regexLoweredSlots, 3);
  assert.equal(compiled.stats.regexSplitFilters, 0);
});

test("structural factoring preserves alternatives, assertions, optionality and mixed quantified branches", () => {
  const values = words(["a", "b", "c", "d", "?", "/"], 5);
  const families = [["^abc$", "^adc$"], ["^a(?:b|c)+d$", "^a(?:a|b)+c$"], ["^a?b$", "^a?c$"],
    ["a|", "b"], ["a\\?b", "a\\?c"], ["^[ab]b$", "^[ab]c$"], ["\\ba\\b", "\\bb\\b"], ["^a{1,3}b$", "^a{1,3}c$"]];
  for (const family of families) {
    const merged = unionPatterns(family);
    assert.ok(merged);
    for (const value of values) assert.equal(languageMatches([merged], value), languageMatches(family, value), `${family}: ${JSON.stringify(value)}`);
  }
  assert.equal(unionPatterns(["(?i)a", "b"]), null, "inline flag scope is outside the parser's proof envelope");
  assert.equal(unionPatterns(["(a)\\1", "b"]), null);
  assert.equal(unionPatterns(["\\Q(a|b)\\E", "b"]), null);
  assert.equal(unionPatterns(["[[:alpha:]]", "b"]), null);
});

const rule = (id, regexFilter, extra = {}) => ({id, priority: 9, action: {type: "redirect", redirect: {transform: {queryTransform: {removeParams: ["click_id"]}}}},
  condition: {regexFilter, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame"], requestMethods: ["get"], excludedRequestDomains: ["account.example"]}, ...extra});
const accepts = async ({regex, isCaseSensitive, requireCapturing}) => {
  assert.equal(requireCapturing, false); assert.equal(typeof isCaseSensitive, "boolean");
  new RegExp(regex, isCaseSensitive ? "" : "i"); return true;
};

test("verified OR keeps exact redirect transforms, scope, priority and case semantics", async () => {
  const base = [rule(5, "^https://a\\.example/\\?click_id="), rule(8, "^https://b\\.example/\\?click_id=")];
  const snapshot = structuredClone(base);
  const result = await optimizeRegexRules(base, {verifyRegex: accepts});
  assert.equal(result.stats.saved, 1);
  assert.equal(result.rules[0].id, 5);
  const {regexFilter, ...condition} = result.rules[0].condition;
  const {regexFilter: original, ...expected} = base[0].condition;
  assert.deepEqual(condition, expected); assert.deepEqual(result.rules[0].action, base[0].action);
  assert.deepEqual(result.merges, [{intoIndex: 0, fromIndices: [0, 1], sourceIds: [5, 8]}]);
  assert.deepEqual(base, snapshot, "optimization does not mutate its input");
  for (const url of ["https://a.example/?click_id=1", "https://b.example/?click_id=2", "https://c.example/?click_id=1", "https://a.example/?Click_id=1"])
    assert.equal(languageMatches([regexFilter], url), languageMatches(base.map((r) => r.condition.regexFilter), url));

  const variations = [
    {priority: 10}, {action: {type: "block"}}, {action: {type: "allow"}},
    {action: {type: "redirect", redirect: {transform: {queryTransform: {removeParams: ["other_id"]}}}}},
    {condition: {...base[1].condition, isUrlFilterCaseSensitive: false}},
    {condition: {...base[1].condition, excludedRequestDomains: ["another.example"]}},
    {condition: {...base[1].condition, requestDomains: ["collector.example"]}},
    {condition: {...base[1].condition, resourceTypes: ["sub_frame"]}},
    {condition: {...base[1].condition, requestMethods: ["post"]}},
    {condition: {...base[1].condition, topDomains: ["publisher.example"]}},
    {condition: {...base[1].condition, domainType: "thirdParty"}},
    {condition: {...base[1].condition, responseHeaders: [{header: "x-policy", values: ["yes"]}]}},
  ];
  for (const variation of variations) {
    const result = await optimizeRegexRules([base[0], {...base[1], ...variation}], {verifyRegex: accepts});
    assert.equal(result.stats.saved, 0, JSON.stringify(variation));
    assert.equal(result.stats.resourceChecks, 0);
  }
});

test("capture substitutions, repeated header effects and frame allows cannot enter Boolean OR optimization", async () => {
  for (const action of [{type: "redirect", redirect: {regexSubstitution: "https://warning.example/?url=\\0"}},
    {type: "modifyHeaders", requestHeaders: [{header: "x-value", operation: "append", value: "v"}]}, {type: "allowAllRequests"}]) {
    const rows = [rule(1, "a", {action}), rule(2, "b", {action})];
    const result = await optimizeRegexRules(rows, {verifyRegex: accepts});
    assert.deepEqual(result.rules, rows); assert.equal(result.stats.resourceChecks, 0);
  }
});

test("verifier absence, rejection, failure and bounded attempts never silently emit unchecked predicates", async () => {
  const rows = [rule(1, "a"), rule(2, "b"), rule(3, "c")];
  assert.deepEqual((await optimizeRegexRules(rows)).rules, rows);
  const refused = await optimizeRegexRules(rows, {verifyRegex: async () => false});
  assert.deepEqual(refused.rules, rows); assert.ok(refused.stats.rejectedChecks > 0);
  await assert.rejects(optimizeRegexRules(rows, {verifyRegex: async () => { throw Error("engine unavailable"); }}), /engine unavailable/);
  await assert.rejects(optimizeRegexRules(rows, {verifyRegex: async () => ({isSupported: true})}), /Boolean/);
  const bounded = await optimizeRegexRules(rows, {verifyRegex: accepts, maxChecks: 1});
  assert.equal(bounded.stats.saved, 1); assert.equal(bounded.stats.candidateAttempts, 1); assert.equal(bounded.stats.checkBudgetExhausted, true);
  const invalidSyntax = await optimizeRegexRules([rule(1, "(?i)a"), rule(2, "(?i)b"), rule(3, "(?i)c")], {verifyRegex: accepts, maxChecks: 1});
  assert.deepEqual(invalidSyntax.rules.map((r) => r.id), [1, 2, 3]); assert.equal(invalidSyntax.stats.candidateAttempts, 1);
});
