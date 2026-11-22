"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const {spawnSync} = require("node:child_process");
const {optimizeRegexRules} = require("../../scripts/lib/regex-optimizer.cjs");
const {makePlan, validatePlan, digest} = require("../../scripts/lib/regex-optimization-plan.cjs");
const root = path.resolve(__dirname, "../..");
const example = (id, regexFilter) => ({id, priority: 5, action: {type: "block"},
  condition: {regexFilter, isUrlFilterCaseSensitive: false, resourceTypes: ["script"], initiatorDomains: ["publisher.example"]}});
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const temporary = () => fs.mkdtempSync(path.join(os.tmpdir(), "egress-regex-build-"));

test("merge proof replays every changed and unchanged rule and detects authority or ancestry changes", async () => {
  const before = {example: [example(1, "^https://a\\.example/(a|b)$"), example(2, "^https://b\\.example/(a|b)$"),
    {...example(3, "independent"), priority: 15}]};
  const result = await optimizeRegexRules(before.example, {verifyRegex: async () => true});
  const after = {example: result.rules}, plan = makePlan(before, {example: result}, {fixture: "source-digest"});
  assert.equal(validatePlan(before, after, plan), true);
  const mutated = structuredClone(after); mutated.example[0].action = {type: "allow"};
  const rewrittenHashes = structuredClone(plan);
  rewrittenHashes.afterSha256 = digest(mutated); rewrittenHashes.rulesets.example.afterSha256 = digest(mutated.example);
  assert.throws(() => validatePlan(before, mutated, rewrittenHashes), /incomplete or inconsistent/);
  const omitted = {example: after.example.slice(0, 1)}, omittedPlan = structuredClone(plan);
  omittedPlan.afterSha256 = digest(omitted); omittedPlan.rulesets.example.afterSha256 = digest(omitted.example);
  omittedPlan.rulesets.example.afterRules = omitted.example.length;
  assert.throws(() => validatePlan(before, omitted, omittedPlan), /incomplete or inconsistent/);
  for (const mutate of [
    (value) => { value.rulesets.example.merges[0].fromIndices = [0, 0]; },
    (value) => { value.rulesets.example.merges[0].sourceIds = [1, 999]; },
    (value) => { value.rulesets.example.merges[0].outputPatternSha256 = "0".repeat(64); },
    (value) => { value.rulesets.example.merges = []; },
    (value) => { delete value.rulesets.example; },
    (value) => { value.nativeChrome = true; },
  ]) {
    const value = structuredClone(plan); mutate(value);
    assert.throws(() => validatePlan(before, after, value), /incomplete or inconsistent/);
  }
});

test("optional optimizer failure leaves the previous published build intact", async () => {
  const {build} = await import(path.join(root, "scripts/build-browser.mjs"));
  const out = temporary();
  try {
    const ordinary = build({out});
    assert.deepEqual(ordinary.regexOptimization, {enabled: false, nativeChrome: false});
    const identity = read(path.join(out, "chrome/rules/build.json")).build;
    const chrome = fs.readFileSync(path.join(out, "chrome/background.js"));
    assert.throws(() => build({out, optimizeRegex: true, re2Python: path.join(out, "no-such-interpreter")}), /could not complete/);
    assert.equal(read(path.join(out, "chrome/rules/build.json")).build, identity);
    assert.deepEqual(fs.readFileSync(path.join(out, "chrome/background.js")), chrome);
    assert.deepEqual(fs.readdirSync(out).sort(), ["chrome", "firefox"]);
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("a verifier reporting a different package version cannot authorize optimization", async () => {
  const dir = temporary();
  try {
    const fake = path.join(dir, "wrong-version");
    fs.writeFileSync(fake, "#!" + process.execPath + "\nconsole.log(JSON.stringify({ready:true,packageVersion:'9.9.9'}));\n", {mode: 0o700});
    const run = spawnSync(process.execPath, [path.join(root, "scripts/optimize-browser-regex.cjs")], {
      input: JSON.stringify({schema: 1, python: fake, rulesets: {example: [example(1, "a"), example(2, "b")]}}),
      encoding: "utf8", timeout: 10000,
    });
    assert.equal(run.status, 1); assert.equal(run.stdout, "");
    assert.match(run.stderr, /google-re2==1\.1\.20251105/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("RE2 interpreter selection is rejected unless optimization was explicitly requested", () => {
  const run = spawnSync(process.execPath, [path.join(root, "scripts/build-browser.mjs"), "--re2-python", "python3"],
    {encoding: "utf8", timeout: 10000});
  assert.equal(run.status, 1); assert.match(run.stderr, /requires --optimize-regex/);
});
