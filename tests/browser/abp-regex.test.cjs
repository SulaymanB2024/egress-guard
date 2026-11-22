"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const abp = require("../../scripts/lib/abp-dnr.cjs");

const HEAVY_REASON = "regular expression exceeds supported counted-repetition expansion budget";
const SUFFIXES = "php|jx|jsx|1ph|jsf|jz|jsm|j$";
const SUFFIX_PATTERN = "^https?:\\/\\/.*\\/[a-z0-9A-Z_]{2,15}\\.(" + SUFFIXES + ")";

test("counted repetitions are bounded by expansion rather than short source length", () => {
  const heavy = ["https?:\\/\\/104\\.154\\..{100,}", "https?:\\/\\/\\w{30,}\\.example/\\w{30,}",
    "^https://cdn.example/npm/[-a-z_]{4,22}@latest/dist/script\\.min\\.js$"];
  for (const pattern of heavy) {
    assert.ok(pattern.length < 100);
    assert.ok(abp.countedRepeatCost(pattern, false) > abp.MAX_COUNTED_REPEAT_COST, pattern);
  }
  const supported = "\\/[0-9a-f]{32}\\/invoke\\.js";
  assert.equal(abp.countedRepeatCost(supported, false), 64, "a qualifying fixed hex repetition is retained");
  assert.equal(abp.countedRepeatCost("\\{100,\\}", false), 0, "escaped braces are literals");
  assert.equal(abp.countedRepeatCost("[{}]", false), 0, "braces inside classes are literals");
  assert.ok(abp.countedRepeatCost("(?:a{12}b){12}", false) > abp.MAX_COUNTED_REPEAT_COST);
  const result = abp.compileFilters([...heavy, supported].map((pattern) => "/" + pattern + "/$script").join("\n"));
  assert.equal(result.stats.dropped[HEAVY_REASON], 3);
  assert.equal(result.stats.converted, 1);
  assert.equal(result.stats.regex, 1);
  assert.equal(result.block[0].condition.regexFilter, supported);
});

test("flat regex alternatives pack into small exact groups while retaining every non-pattern condition", () => {
  const line = "/" + SUFFIX_PATTERN + "/$script,third-party,domain=publisher.example|~account.publisher.example,method=get";
  const original = abp.parseLine(line), result = abp.compileFilters(line);
  assert.equal(result.block.length, 2);
  assert.equal(result.stats.converted, 1, "converted counts original source rows");
  assert.equal(result.stats.regexSplitFilters, 1);
  assert.equal(result.stats.regexSplitRules, 1, "split rules count additional outputs, without wasting one slot per literal");
  assert.equal(result.stats.regex, 2);
  const {regexFilter, ...other} = original.condition;
  for (const rule of result.block) {
    const {regexFilter: split, ...rest} = rule.condition;
    assert.deepEqual(rest, other);
    assert.equal(rule.action.type, "block");
    assert.notEqual(split, regexFilter);
  }
  const source = new RegExp(regexFilter, "i"), parts = result.block.map((rule) => new RegExp(rule.condition.regexFilter, "i"));
  for (const stem of ["a", "ab", "A_B", "a".repeat(15), "a".repeat(16)]) {
    for (const suffix of ["php", "PHP", "php_extra", "jx", "jsx", "1ph", "jsf", "jz", "jsm", "j", "js", "png"]) {
      for (const tail of ["", "?v=1", "/next", "#part"]) {
        const url = `https://cdn.example/${stem}.${suffix}${tail}`;
        assert.equal(parts.some((re) => re.test(url)), source.test(url), url);
      }
    }
  }
  for (const pattern of ["^(a|b|c|d|e|f|g|h)+$", "^(a|b|c|d|e|f|g|h)?$", "^(?:(a|b|c|d|e|f|g|h))$",
    "^[a|b|c|d|e|f|g|h]$", "^(a|b|c|d|e|f|g|)$"]) {
    assert.deepEqual(abp.splitRegexAlternatives(pattern), [pattern], "quantified, nested, class and empty alternatives are not approximated");
  }
});

test("regex expansion cannot silently discard a protecting exception or a partial branch set", () => {
  const line = "/" + SUFFIX_PATTERN + "/$script,domain=publisher.example";
  const omitted = abp.compileFilters(line, {maxRegex: 1});
  assert.equal(omitted.block.length, 0);
  assert.equal(omitted.stats.regex, 0);
  assert.equal(omitted.stats.dropped["over the regular-expression rule budget"], 1);
  assert.throws(() => abp.compileFilters("@@" + line, {maxRegex: 1}), /Cannot omit a protecting regex exception/);
  const exception = abp.compileFilters("@@" + line, {maxRegex: 2});
  assert.equal(exception.allow.length, 2);
  assert.equal(exception.stats.exceptions, 1);
  const heavy = "@@/https?:\\/\\/collector\\.example/.{100,}/$script,domain=publisher.example";
  assert.throws(() => abp.compileFilters(heavy), /Cannot omit a protecting regex exception.*counted-repetition/);
  assert.equal(abp.compileFilters(heavy + "\n" + heavy + ",badfilter").allow.length, 0, "$badfilter runs before expansion checks");
  assert.equal(abp.compileFilters(line + "\n" + line + ",badfilter").block.length, 0, "$badfilter removes every would-be branch");
});

test("packed alternatives retain every remainder branch and end anchor", () => {
  for (const count of [9, 14, 25, 31]) {
    const words = Array.from({length: count}, (_, i) => `item${i}`);
    const pattern = "^(?:" + words.join("|") + ")$";
    const packed = abp.splitRegexAlternatives(pattern);
    assert.equal(packed.length, Math.ceil(count / 4));
    const original = new RegExp(pattern), parts = packed.map(value => new RegExp(value));
    for (const word of [...words, "", "item", "item999", "item0suffix", "prefixitem0", ...words.map(value => value + "\n")]) {
      assert.equal(parts.some(part => part.test(word)), original.test(word), `${count}: ${JSON.stringify(word)}`);
    }
  }
});

test("end-anchored host patterns retain their URL constraint and cannot become document-wide exceptions", () => {
  assert.deepEqual(abp.convertPattern("||collector.example^"), {domain: "collector.example"});
  for (const pattern of ["||collector.example^|", "||collector.example|"]) {
    assert.deepEqual(abp.convertPattern(pattern), {urlFilter: pattern});
    const block = abp.compileFilters(pattern).block[0];
    const allow = abp.compileFilters("@@" + pattern).allow[0];
    for (const rule of [block, allow]) {
      assert.equal(rule.condition.urlFilter, pattern);
      assert.equal(rule.condition.requestDomains, undefined, "native end anchors must not become whole-domain predicates");
    }
    assert.match(abp.parseLine("@@" + pattern + "$document").drop, /not a whole host/);
    assert.match(abp.parseLine("@@" + pattern + "$all").drop, /not a whole host/);
  }
  assert.equal(abp.compileFilters("@@||collector.example^$document").allow.length, 1, "whole-host document behavior is unchanged");
});
