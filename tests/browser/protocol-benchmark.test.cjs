"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const model = require("../../scripts/lib/dnr-benchmark.cjs");
const hosts = require("../../browser/core/hosts.js");
const corpusPath = path.join(__dirname, "fixtures/protocols-v1.json");
const corpus = JSON.parse(fs.readFileSync(corpusPath));
const baseline = require("../../docs/benchmarks/protocols-v1-baseline-0.9.json");
const rule = (id, action, priority, condition = {}) => ({id, ruleset: "test", priority, action: typeof action === "string" ? {type: action} : action, condition});
const evaluate = (rules, request) => model.evaluateRequest(rules.map((r) => model.compileRule(r, hosts.siteOf)), {url: "https://publisher.example/a", type: "script", initiator: "https://publisher.example/", topUrl: "https://publisher.example/", tabId: 7, ...request});

test("protocol challenge corpus is frozen independently of implementation", () => {
  assert.equal(model.sha256(fs.readFileSync(corpusPath)), "074d616ba05c929adb76007048b644dd1cc9ebf3fb5ac39ecd9f588061852423");
  assert.equal(baseline.corpusSha256, model.sha256(fs.readFileSync(corpusPath)));
  assert.equal(corpus.families.length, 9);
  assert.equal(corpus.fixtures.filter((f) => f.label === "tracking").length, 34);
  assert.equal(corpus.fixtures.filter((f) => f.label === "functional").length, 34);
  assert.equal(new Set(corpus.fixtures.map((f) => f.id)).size, corpus.fixtures.length);
  for (const fixture of corpus.fixtures) assert.ok(corpus.sources[fixture.source]?.urls.length, fixture.id);
  assert.deepEqual(baseline.summary, model.summarize(corpus, baseline.results));
  assert.equal(baseline.summary.escaped, 21);
  assert.deepEqual(baseline.summary.functionalPrevented, ["meta-nested-value", "posthog-nested-value", "prebid-path-suffix"]);
  const stage1Bytes = fs.readFileSync(path.join(__dirname, "../../docs/benchmarks/protocols-v1-stage1-0.10.json"));
  assert.equal(model.sha256(stage1Bytes), "3a7d7f6e8882ec22da1ebcd16a98964115de43f0dc2d783b355528ee4a68aa86", "retain the exact intermediate result, including the missed target");
  const stage1 = JSON.parse(stage1Bytes);
  assert.equal(stage1.summary.escaped, 11);
  assert.equal(stage1.comparison.metThirtyPercentTarget, false);
  assert.deepEqual(stage1.comparison, model.compare(baseline, stage1));
  const final = require("../../docs/benchmarks/protocols-v1-candidate-0.10.json");
  assert.equal(final.corpusSha256, baseline.corpusSha256);
  assert.equal(final.summary.escaped, 9);
  assert.deepEqual(final.comparison, model.compare(baseline, final));
  const errataBytes = fs.readFileSync(path.join(__dirname, "../../docs/benchmarks/protocols-v1-errata.json"));
  const sensitivity = require("../../docs/benchmarks/protocols-v1-errata-sensitivity.json");
  assert.equal(sensitivity.errataSha256, model.sha256(errataBytes));
  assert.equal(sensitivity.corpusSha256, baseline.corpusSha256);
  assert.equal(sensitivity.baselineArtifactSha256, baseline.artifact.sha256);
  assert.equal(sensitivity.candidateArtifactSha256, final.artifact.sha256);
  assert.equal(sensitivity.decisionsUnchanged, true);
  assert.deepEqual(sensitivity.originalComparison, final.comparison);
  assert.deepEqual(sensitivity.sensitivityComparison, final.comparison);
});

test("URL-filter model preserves host anchors, separators, end anchors and case", () => {
  const covered = (filter, url, sensitive = false) => evaluate([rule(1, "block", 1, {urlFilter: filter, isUrlFilterCaseSensitive: sensitive})], {url}).prevented;
  assert.equal(covered("||a.example^", "https://sub.a.example/script"), true);
  assert.equal(covered("||a.example^", "https://a.example.evil.test/script"), false);
  assert.equal(covered("||a.example^", "https://elsewhere.example/?q=https://a.example/a"), false);
  assert.equal(covered("|https://a.example/end|", "https://a.example/end"), true);
  assert.equal(covered("|https://a.example/end|", "https://a.example/end?x=1"), false);
  assert.equal(covered("/A*pixel^", "https://a.example/a/b/pixel?x=1"), true);
  assert.equal(covered("/A*pixel^", "https://a.example/a/b/pixel?x=1", true), false);
  assert.equal(covered("/a.b", "https://a.example/aXb"), false);
});

test("pre-request scoring honors allow precedence and never credits header sanitation", () => {
  const block = rule(1, "block", 6), allow = rule(2, "allow", 6);
  assert.equal(evaluate([block, allow]).prevented, false);
  assert.equal(evaluate([allow, {...block, priority: 7}]).prevented, true);
  assert.equal(evaluate([rule(3, {type: "modifyHeaders", requestHeaders: [{header: "Cookie", operation: "remove"}]}, 50)]).prevented, false);
  assert.equal(evaluate([rule(4, "block", 20, {responseHeaders: [{header: "x-tracker"}]})]).prevented, false, "post-send block cannot prevent initial delivery");
  assert.equal(evaluate([rule(5, {type: "redirect", redirect: {extensionPath: "/surrogates/local.js"}}, 18)]).prevented, true);
  assert.equal(evaluate([rule(6, {type: "redirect", redirect: {url: "https://collector.example/new"}}, 18)]).prevented, false, "moving a request is not sufficient evidence of prevention");
  assert.equal(evaluate([block], {type: "main_frame"}).prevented, false, "implicit resource scope excludes main-frame navigation");
  assert.throws(() => model.compileRule(rule(7, "allowAllRequests", 50), hosts.siteOf), /inheritance/);
  assert.throws(() => model.compileRule(rule(8, "block", 1, {futureCondition: true}), hosts.siteOf), /Unmodeled/);
  for (const condition of [{domainType: "sameSite"}, {resourceTypes: "script"}, {resourceTypes: ["futureType"]}, {requestMethods: ["POST"]}, {requestDomains: [1]}, {regexFilter: {}}, {isUrlFilterCaseSensitive: "false"}, {tabIds: [1.5]}]) {
    assert.throws(() => model.compileRule(rule(9, "block", 1, condition), hosts.siteOf), /Malformed|Unmodeled/);
  }
});

test("party and frame scope use public-suffix boundaries and distinct top/initiator", () => {
  assert.equal(evaluate([rule(1, "block", 1, {domainType: "thirdParty"})], {url: "https://b.github.io/a", initiator: "https://a.github.io/"}).prevented, true);
  assert.equal(evaluate([rule(1, "block", 1, {domainType: "thirdParty"})], {url: "https://cdn.publisher.example/a"}).prevented, false);
  const scoped = rule(2, "block", 1, {topDomains: ["publisher.example"], initiatorDomains: ["frame.example"], requestMethods: ["post"], resourceTypes: ["ping"]});
  assert.equal(evaluate([scoped], {url: "https://frame.example/a", initiator: "https://frame.example/", type: "ping", method: "post"}).prevented, true);
  assert.equal(evaluate([scoped], {url: "https://frame.example/a", initiator: "https://frame.example/", topUrl: "https://different.example/", type: "ping", method: "post"}).prevented, false);
});

test("equal-family/mechanism weights do not turn permutations into prevalence", () => {
  const tiny = {families: ["a", "b"], fixtures: [
    {id: "a1", family: "a", mechanism: "query", label: "tracking"},
    {id: "a2", family: "a", mechanism: "query", label: "tracking"},
    {id: "a3", family: "a", mechanism: "opaque", label: "tracking"},
    {id: "b1", family: "b", mechanism: "query", label: "tracking"}
  ]};
  const rows = tiny.fixtures.map((f) => ({...f, prevented: f.id !== "a3"}));
  assert.equal(model.summarize(tiny, rows).equalFamilyEscapeRate, .25);
  tiny.fixtures.push({id: "a4", family: "a", mechanism: "query", label: "tracking"});
  rows.push({...tiny.fixtures.at(-1), prevented: true});
  assert.equal(model.summarize(tiny, rows).equalFamilyEscapeRate, .25);
});

test("comparison rejects corpus/feed drift and new functional blocks invalidate target", () => {
  assert.throws(() => model.compare(baseline, {...baseline, corpusSha256: "different"}), /Corpus changed/);
  assert.throws(() => model.compare(baseline, {...baseline, artifact: {...baseline.artifact, inputsSha256: "different"}}), /snapshots differ/);
  const candidate = structuredClone(baseline);
  candidate.summary.equalFamilyEscapeRate = .1;
  const control = candidate.results.find((r) => r.label === "functional" && !r.prevented);
  control.prevented = true;
  const comparison = model.compare(baseline, candidate);
  assert.equal(comparison.metThirtyPercentTarget, false);
  assert.deepEqual(comparison.newFalsePositives, [control.id]);
});
