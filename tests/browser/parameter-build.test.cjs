"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const vm = require("node:vm");
const load = () => import("../../scripts/build-browser.mjs");
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "eg-parameter-build-"));
const source = {id: "url-tracking", name: "AdGuard/uBO – URL Tracking Protection", url: "fixture", license: {name: "GPL-3.0", url: "fixture"},
  sha256: "a".repeat(64), fetched_at: Date.now() / 1000, stale: false};

test("tracking source uses its own exact identity and never invents a date from its template", async () => {
  const {FILTER_LISTS, checkFilterBody} = await load();
  const spec = FILTER_LISTS.find(item => item.id === "url-tracking");
  const body = `! Title: ${spec.name}\n! License: ${spec.license.url}\n! Homepage: https://github.com/uBlockOrigin/uAssets\n! Last modified: %timestamp%\n` +
    "$removeparam=fixture_tracking\n".repeat(spec.minimum);
  const receipt = checkFilterBody(spec, Buffer.from(body));
  assert.equal(receipt.last_modified, null);
  assert.equal(receipt.version, null);
  assert.equal(receipt.filters, spec.minimum);
  for (const changed of [body.replace(spec.name, "Wrong source"), body.replace(spec.license.url, "https://elsewhere.example/license"),
    body + `! Title: ${spec.name}\n`, body.trimEnd(), body.replaceAll("$removeparam=fixture_tracking", "||unrelated.example^")]) {
    assert.throws(() => checkFilterBody(spec, Buffer.from(changed)));
  }
  assert.equal(checkFilterBody(spec, Buffer.from(body + "example.test##.fixture-ad\n")).filters, spec.minimum + 1,
    "incidental non-parameter data is bounded and left to the separate compiler");
});

test("built worker and content receive the same exception-aware parameter policy and hash", async () => {
  const {build} = await load(), out = temp();
  try {
    const text = "$removeparam=fixture_tracking\n$removeparam=utm_source\n@@||safe.example^$removeparam=utm_source\n";
    const summary = build({out, filters: {"url-tracking": {text, source}}});
    const chrome = path.join(out, "chrome"), worker = fs.readFileSync(path.join(chrome, "background.js"), "utf8");
    const generated = fs.readFileSync(path.join(chrome, "core/param-data.js"), "utf8");
    assert.ok(worker.includes(generated), "worker must use generated policy, never the source placeholder");
    const stamp = JSON.parse(fs.readFileSync(path.join(chrome, "rules/build.json")));
    assert.equal(stamp.parameter_policy_sha256, crypto.createHash("sha256").update(generated).digest("hex"));
    assert.equal(summary.coverage.parameters.available, true);
    assert.ok(summary.parameters.importedRules > 0);
    const content = vm.createContext({URL});
    for (const file of ["core/param-data.js", "core/param-policy.js", "core/params.js"]) vm.runInContext(fs.readFileSync(path.join(chrome, file), "utf8"), content);
    const background = vm.createContext({URL, TextEncoder, crypto: crypto.webcrypto});
    vm.runInContext(worker.split("// ---- background-chrome.js")[0], background);
    const protectedUrl = "https://safe.example/read?utm_source=keep&fixture_tracking=remove&q=a%2Bb";
    const ordinaryUrl = "https://news.example/read?utm_source=remove&fixture_tracking=remove&q=a%2Bb";
    for (const context of [content, background]) {
      assert.equal(context.EGParams.clean(protectedUrl).url, "https://safe.example/read?utm_source=keep&q=a%2Bb");
      assert.equal(context.EGParams.clean(ordinaryUrl).url, "https://news.example/read?q=a%2Bb");
    }
    const manifest = JSON.parse(fs.readFileSync(path.join(chrome, "manifest.json")));
    const scripts = manifest.content_scripts.find(item => item.js.includes("core/params.js")).js;
    assert.ok(scripts.indexOf("core/param-data.js") < scripts.indexOf("core/param-policy.js"));
    assert.ok(scripts.indexOf("core/param-policy.js") < scripts.indexOf("core/params.js"));
    const rules = JSON.parse(fs.readFileSync(path.join(chrome, "rules/params.json")));
    for (const rule of rules) {
      assert.equal(rule.priority, 9);
      assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]);
      assert.deepEqual(rule.condition.requestMethods, ["get"]);
    }
    assert.match(fs.readFileSync(path.join(chrome, "NOTICE.txt"), "utf8"), /AdGuard\/uBO[\s\S]*GPL-3\.0/);
    assert.doesNotMatch(fs.readFileSync(path.join(out, "firefox/core/param-data.js"), "utf8"), /fixture_tracking/);
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("a quarantined parameter receipt remains reduced and full publication preserves last-good output", async () => {
  const {build} = await load(), out = temp();
  const filters = {"url-tracking": {source, text: "$removeparam=fixture_tracking\n@@/unrepresentable*path$removeparam=fixture_tracking\n$removeparam=another_tracking\n"}};
  try {
    fs.mkdirSync(path.join(out, "chrome")); fs.writeFileSync(path.join(out, "chrome/last-good"), "unchanged");
    assert.throws(() => build({out, filters, requireComplete: true}));
    assert.equal(fs.readFileSync(path.join(out, "chrome/last-good"), "utf8"), "unchanged");
    const reduced = build({out, filters});
    assert.equal(reduced.coverage.complete, false);
    assert.equal(reduced.coverage.parameters.reduced, true);
    assert.ok(reduced.coverage.parameters.quarantined.includes("fixture_tracking"));
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("a named quarantine acknowledgment preserves every other complete-build gate", async () => {
  const {build, feedSpecs, FILTER_LISTS} = await load(), out = temp();
  const lists = Object.fromEntries(Object.entries(feedSpecs("pro.plus")).map(([kind, specs]) => [kind, {
    names: ["fixture.example"], required: specs.map(spec => spec.id), sources: specs.map(spec => ({...spec,
      updated_at: Date.now() / 1000, sha256: "b".repeat(64)})),
  }]));
  const filters = Object.fromEntries(FILTER_LISTS.map(spec => [spec.id, {source: {...source, ...spec},
    text: spec.kind === "parameters" ? "$removeparam=fixture_tracking\n@@/unrepresentable*path$removeparam=fixture_tracking\n$removeparam=another_tracking\n"
      : spec.kind === "domains" ? "link.fixture.example\n" : "||tracker.example^\n"}]));
  try {
    assert.throws(() => build({out, lists, filters, requireComplete: true}), /allow-parameter-quarantine/);
    const accepted = build({out, lists, filters, requireComplete: true, allowParameterQuarantine: ["fixture_tracking"]});
    assert.equal(accepted.coverage.complete, false, "review never relabels a reduced source as complete");
    assert.deepEqual(accepted.coverage.parameters.reviewedQuarantined, ["fixture_tracking"]);
    assert.deepEqual(accepted.coverage.missing, []);
    fs.writeFileSync(path.join(out, "chrome/last-good"), "unchanged");
    assert.throws(() => build({out, lists, filters, requireComplete: true, allowParameterQuarantine: ["wrong_name"]}), /Incomplete browser coverage/);
    const missing = {...filters}; delete missing.easyprivacy;
    assert.throws(() => build({out, lists, filters: missing, requireComplete: true, allowParameterQuarantine: ["fixture_tracking"]}), /easyprivacy/);
    const unsafe = {...filters, "url-tracking": {...filters["url-tracking"], text: filters["url-tracking"].text + "@@*$removeparam\n"}};
    assert.throws(() => build({out, lists, filters: unsafe, requireComplete: true, allowParameterQuarantine: ["fixture_tracking"]}), /Incomplete browser coverage/);
    const otherQuarantine = {...filters, "url-tracking": {...filters["url-tracking"], text: filters["url-tracking"].text + "@@/another*pattern$removeparam=another_tracking\n"}};
    assert.throws(() => build({out, lists, filters: otherQuarantine, requireComplete: true, allowParameterQuarantine: ["fixture_tracking"]}), /Incomplete browser coverage/);
    assert.equal(fs.readFileSync(path.join(out, "chrome/last-good"), "utf8"), "unchanged");
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});
