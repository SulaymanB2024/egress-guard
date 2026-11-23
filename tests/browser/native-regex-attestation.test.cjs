"use strict";
// Injected extension APIs test the attestation contract, not Chrome behavior.
// No native browser, proxy or network listener is started by this suite.
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const crypto = require("node:crypto"), vm = require("node:vm");
const helper = import("./native-regex-attestation.mjs");
const rule = (id, regexFilter, extra = {}) => ({id, action: {type: "block"}, condition: {regexFilter}, ...extra});
async function fixture(work) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "egress-regex-attestation-"));
  fs.mkdirSync(path.join(directory, "rules"));
  const manifest = {manifest_version: 3, declarative_net_request: {rule_resources: [
    {id: "active", path: "rules/active.json", enabled: true}, {id: "disabled", path: "rules/disabled.json", enabled: false}]}};
  fs.writeFileSync(path.join(directory, "manifest.json"), JSON.stringify(manifest));
  const active = [rule(1, "alpha"), rule(2, "beta", {condition: {regexFilter: "beta", isUrlFilterCaseSensitive: true}}),
    rule(3, "(gamma)", {action: {type: "redirect", redirect: {regexSubstitution: "https://example.test/\\1"}}}),
    {id: 4, action: {type: "block"}, condition: {urlFilter: "literal"}}];
  const disabled = [rule(1, "(Delta)", {condition: {regexFilter: "(Delta)", isUrlFilterCaseSensitive: true},
    action: {type: "redirect", redirect: {regexSubstitution: "https://example.test/\\1"}}}), rule(2, "alpha")];
  fs.writeFileSync(path.join(directory, "rules/active.json"), JSON.stringify(active));
  fs.writeFileSync(path.join(directory, "rules/disabled.json"), JSON.stringify(disabled));
  try { return await work(directory, {manifest, active, disabled}, await helper); }
  finally { fs.rmSync(directory, {recursive: true, force: true}); }
}

function evaluator(directory, {native = async () => ({isSupported: true}), mutateAnswer, mutateAsset} = {}) {
  const calls = [], fetches = [];
  const context = vm.createContext({URL, TextEncoder, Uint8Array, crypto: crypto.webcrypto,
    chrome: {runtime: {getURL: value => "chrome-extension://fixture/" + value.replace(/^\//, "")},
      declarativeNetRequest: native === null ? {} : {isRegexSupported: async options => { calls.push(structuredClone(options)); return native(options); }}},
    fetch: async (url, options) => {
      const parsed = new URL(url); assert.equal(parsed.protocol, "chrome-extension:"); assert.equal(parsed.hostname, "fixture");
      assert.equal(options.redirect, "error"); assert.equal(options.credentials, "omit"); fetches.push(parsed.pathname);
      const raw = fs.readFileSync(path.join(directory, parsed.pathname));
      return new Response(mutateAsset ? mutateAsset(parsed.pathname, raw) : raw);
    }});
  const evaluate = async expression => {
    const response = await vm.runInContext(expression, context, {timeout: 1000});
    const result = JSON.parse(JSON.stringify(response));
    return mutateAnswer && expression.includes("async function browserBatch") ? mutateAnswer(result) : result;
  };
  return {evaluate, calls, fetches};
}

test("inventory includes disabled rulesets and duplicate patterns with explicit native case/capture flags", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory);
  assert.equal(inventory.rules, 6); assert.equal(inventory.regexes, 5);
  assert.deepEqual(inventory.rulesets.map(row => [row.id, row.enabled, row.regexes]), [["active", true, 3], ["disabled", false, 2]]);
  assert.deepEqual(inventory.rows.map(row => [row.options.isCaseSensitive, row.options.requireCapturing]), [[false, false], [true, false], [false, true], [true, true], [false, false]]);
  assert.equal(inventory.rows[0].optionsSha256, inventory.rows[4].optionsSha256, "equal input is still inventoried twice");
  assert.notEqual(inventory.rows[0].ordinal, inventory.rows[4].ordinal);
  const publicJson = JSON.stringify(api.publicRegexInventory(inventory));
  for (const pattern of ["alpha", "beta", "gamma", "Delta"]) assert(!publicJson.includes(pattern));
  assert(Object.isFrozen(inventory.rows[0].options));
}));

test("adapter calls Chrome once for every actual input and proves exact packaged bytes and coverage", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory), mock = evaluator(directory);
  const receipt = await api.attestNativeRegexes({inventory, evaluate: mock.evaluate,
    recheck: () => api.artifactRegexesUnchanged(directory, inventory), browserProduct: "model-only"});
  assert.equal(receipt.status, "PASS"); assert.equal(receipt.complete, true);
  assert.equal(receipt.expected, 5); assert.equal(receipt.attempted, 5); assert.equal(receipt.checked, 5);
  assert.equal(receipt.passed, 5); assert.equal(receipt.rejected, 0); assert.equal(receipt.unavailable, 0);
  // Calls within one bounded batch may start in any digest-completion order;
  // preserve multiplicity and both flags when comparing the complete inputs.
  assert.deepEqual(mock.calls.map(value => JSON.stringify(value)).sort(),
    inventory.rows.map(row => JSON.stringify(row.options)).sort());
  assert.equal(receipt.expectedInputsSha256, receipt.checkedInputsSha256);
  assert.equal(receipt.packagedFilesVerified, true); assert.equal(receipt.artifactUnchanged, true);
  assert.deepEqual(mock.fetches, ["/manifest.json", "/rules/active.json", "/rules/disabled.json"]);
  assert.deepEqual(receipt.rulesets.map(row => [row.id, row.checked, row.unavailable]), [["active", 3, 0], ["disabled", 2, 0]]);
}));

test("missing native API cannot be replaced by source RE2 or a passing empty result", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory), mock = evaluator(directory, {native: null});
  const receipt = await api.attestNativeRegexes({inventory, evaluate: mock.evaluate, recheck: () => true});
  assert.equal(receipt.status, "NOT COVERED"); assert.equal(receipt.complete, false);
  assert.equal(receipt.attempted, 0); assert.equal(receipt.checked, 0); assert.equal(receipt.unavailable, 5);
  assert.equal(mock.calls.length, 0);
}));

test("native rejection preserves full coverage but fails acceptance without echoing regex source", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory);
  const mock = evaluator(directory, {native: async options => options.regex === "(gamma)" ? {isSupported: false, reason: "memoryLimitExceeded"} : {isSupported: true}});
  const receipt = await api.attestNativeRegexes({inventory, evaluate: mock.evaluate, recheck: () => true});
  assert.equal(receipt.status, "FAIL"); assert.equal(receipt.complete, true);
  assert.equal(receipt.checked, 5); assert.equal(receipt.rejected, 1); assert.equal(receipt.passed, 4);
  assert.deepEqual(receipt.errors, [{code: "memoryLimitExceeded", ruleset: "active", id: 3}]);
  assert(!JSON.stringify(receipt).includes("gamma"));
}));

test("malformed API booleans, contradictory reasons and thrown errors never count as checked", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory);
  for (const value of [true, {}, {isSupported: "true"}, {isSupported: true, reason: "syntaxError"}, {isSupported: false}, {isSupported: false, reason: "unknown"}, {isSupported: true, extra: 1}]) {
    const mock = evaluator(directory, {native: async () => value});
    const receipt = await api.attestNativeRegexes({inventory, evaluate: mock.evaluate, recheck: () => true});
    assert.equal(receipt.status, "NOT COVERED"); assert.equal(receipt.checked, 0); assert.equal(receipt.unavailable, 5);
  }
  const mock = evaluator(directory, {native: async () => { throw new Error("private-regex-and-path"); }});
  const receipt = await api.attestNativeRegexes({inventory, evaluate: mock.evaluate, recheck: () => true});
  assert.equal(receipt.status, "NOT COVERED"); assert(!JSON.stringify(receipt).includes("private-regex-and-path"));
}));

test("dropped, duplicate, reordered or wrong-option acknowledgements cannot claim complete input coverage", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory);
  for (const mutateAnswer of [
    reply => ({...reply, results: reply.results.slice(1)}),
    reply => ({...reply, results: reply.results.map(() => reply.results[0])}),
    reply => ({...reply, results: [...reply.results].reverse()}),
    reply => ({...reply, results: reply.results.map(row => ({...row, optionsSha256: "0".repeat(64)}))}),
  ]) {
    const mock = evaluator(directory, {mutateAnswer});
    const receipt = await api.attestNativeRegexes({inventory, evaluate: mock.evaluate, recheck: () => true});
    assert.equal(receipt.status, "NOT COVERED"); assert.equal(receipt.complete, false); assert(receipt.checked < 5);
  }
}));

test("packaged artifact mismatch or post-attestation edit prevents a successful receipt", () => fixture(async (directory, _data, api) => {
  const inventory = api.readArtifactRegexInventory(directory);
  const mismatch = evaluator(directory, {mutateAsset: (name, raw) => name.endsWith("active.json") ? Buffer.concat([raw, Buffer.from(" ")]) : raw});
  const first = await api.attestNativeRegexes({inventory, evaluate: mismatch.evaluate, recheck: () => true});
  assert.equal(first.status, "FAIL"); assert.equal(first.checked, 0); assert.equal(mismatch.calls.length, 0);
  const ordinary = evaluator(directory);
  const second = await api.attestNativeRegexes({inventory, evaluate: ordinary.evaluate, recheck: () => {
    fs.appendFileSync(path.join(directory, "rules/active.json"), " "); return api.artifactRegexesUnchanged(directory, inventory);
  }});
  assert.equal(second.status, "FAIL"); assert.equal(second.checked, 5); assert.equal(second.artifactUnchanged, false);
  assert.equal(second.complete, false);
}));

test("unsafe declarations, duplicate JSON keys, non-Boolean flags and duplicate rule IDs are rejected", () => fixture(async (directory, data, api) => {
  const manifestPath = path.join(directory, "manifest.json"), rulePath = path.join(directory, "rules/active.json");
  for (const unsafe of ["../outside.json", "/outside.json", "rules/../outside.json", "rules\\outside.json", "https://example.test/rules", "rules/%2e%2e/file", "rules/active.json?x"]) {
    const manifest = structuredClone(data.manifest); manifest.declarative_net_request.rule_resources[0].path = unsafe;
    fs.writeFileSync(manifestPath, JSON.stringify(manifest)); assert.throws(() => api.readArtifactRegexInventory(directory), /unsafe-artifact-path/);
  }
  fs.writeFileSync(manifestPath, JSON.stringify(data.manifest));
  for (const raw of [
    '[{"id":1,"id":2,"action":{"type":"block"},"condition":{"regexFilter":"private-pattern"}}]',
    '[{"id":1,"action":{"type":"block"},"condition":{"regexFilter":"a","r\\u0065gexFilter":"private-pattern"}}]',
    '[{"id":1,"action":{"type":"block"},"condition":{"regexFilter":"private-pattern","isUrlFilterCaseSensitive":null}}]',
    JSON.stringify([rule(1, "a"), rule(1, "b")]),
    '[{"private-pattern":BROKEN}]',
  ]) {
    fs.writeFileSync(rulePath, raw);
    assert.throws(() => api.readArtifactRegexInventory(directory), error => !error.message.includes("private-pattern"));
  }
}));

test("linked, escaped and nonregular resources and oversized input cannot enter an inventory", () => fixture(async (directory, _data, api) => {
  const file = path.join(directory, "rules/active.json"), backup = path.join(directory, "source.json");
  fs.renameSync(file, backup); fs.symlinkSync(backup, file);
  assert.throws(() => api.readArtifactRegexInventory(directory)); fs.unlinkSync(file);
  fs.linkSync(backup, file); assert.throws(() => api.readArtifactRegexInventory(directory), /independent-regular/); fs.unlinkSync(file);
  fs.mkdirSync(file); assert.throws(() => api.readArtifactRegexInventory(directory), /independent-regular/); fs.rmdirSync(file);
  fs.copyFileSync(backup, file); fs.truncateSync(file, api.LIMITS.rulesetBytes + 1);
  assert.throws(() => api.readArtifactRegexInventory(directory), /artifact-byte-limit/);
  const link = path.join(directory, "linked-root"); fs.symlinkSync(directory, link);
  assert.throws(() => api.readArtifactRegexInventory(link + path.sep), /artifact-directory/);
}));

test("linked ancestors and a directory swapped during open are rejected before resource bytes are read", () => fixture(async (directory, _data, api) => {
  const rules = path.join(directory, "rules"), original = path.join(directory, "original-rules"), outside = path.join(directory, "outside");
  fs.mkdirSync(outside); fs.writeFileSync(path.join(outside, "active.json"), JSON.stringify([rule(1, "private-outside-pattern")]));
  fs.renameSync(rules, original); fs.symlinkSync(outside, rules);
  assert.throws(() => api.readArtifactRegexInventory(directory), /unsafe-artifact-directory/);
  fs.unlinkSync(rules); fs.renameSync(original, rules);
  const open = fs.openSync, read = fs.readSync; let swapped = false, outsideFd = null, outsideReads = 0;
  fs.openSync = (name, ...args) => {
    if (name === path.join(rules, "active.json") && !swapped) {
      swapped = true; fs.renameSync(rules, original); fs.symlinkSync(outside, rules);
      outsideFd = open(name, ...args); return outsideFd;
    }
    return open(name, ...args);
  };
  fs.readSync = (fd, ...args) => { if (fd === outsideFd) outsideReads++; return read(fd, ...args); };
  try { assert.throws(() => api.readArtifactRegexInventory(directory), /artifact-path-changed/); }
  finally { fs.openSync = open; fs.readSync = read; }
  assert.equal(swapped, true); assert.equal(outsideReads, 0);
}));

test("native work is bounded into complete batches and a lost middle batch cannot receive coverage credit", () => fixture(async (directory, _data, api) => {
  const entries = Array.from({length: api.LIMITS.batch * 2 + 1}, (_, index) => rule(index + 1, "same-pattern"));
  fs.writeFileSync(path.join(directory, "rules/active.json"), JSON.stringify(entries));
  const inventory = api.readArtifactRegexInventory(directory), mock = evaluator(directory);
  let batches = 0;
  const evaluate = async expression => {
    if (expression.includes("async function browserBatch")) {
      batches++;
      if (batches === 2) throw new Error("lost-native-transport");
    }
    return mock.evaluate(expression);
  };
  const receipt = await api.attestNativeRegexes({inventory, evaluate, recheck: () => true});
  assert.equal(batches, 3); assert.equal(receipt.expected, 35);
  assert.equal(receipt.checked, 19); assert.equal(receipt.unavailable, 16); assert.equal(mock.calls.length, 19);
  assert.equal(receipt.status, "NOT COVERED"); assert.equal(receipt.complete, false);
  assert.notEqual(receipt.expectedInputsSha256, receipt.checkedInputsSha256);
}));

test("zero regexes receive no vacuous native pass and case/action changes alter the inventory hash", () => fixture(async (directory, data, api) => {
  const before = api.readArtifactRegexInventory(directory);
  data.active[0].condition.isUrlFilterCaseSensitive = true;
  fs.writeFileSync(path.join(directory, "rules/active.json"), JSON.stringify(data.active));
  const changed = api.readArtifactRegexInventory(directory);
  assert.notEqual(before.inputsSha256, changed.inputsSha256); assert.notEqual(before.inventorySha256, changed.inventorySha256);
  for (const name of ["active", "disabled"]) fs.writeFileSync(path.join(directory, `rules/${name}.json`), "[]");
  const empty = api.readArtifactRegexInventory(directory), mock = evaluator(directory);
  const receipt = await api.attestNativeRegexes({inventory: empty, evaluate: mock.evaluate, recheck: () => true});
  assert.equal(receipt.status, "NOT COVERED"); assert.equal(receipt.complete, false); assert.equal(mock.calls.length, 0);
}));
