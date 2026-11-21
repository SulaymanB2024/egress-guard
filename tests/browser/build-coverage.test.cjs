"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const load = () => import("../../scripts/build-browser.mjs");
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "eg-build-receipts-"));

test("a medium fallback never acknowledges requested full threat coverage", async () => {
  const {buildCoverage, feedSpecs, FILTER_LISTS} = await load();
  const lists = Object.fromEntries(Object.entries(feedSpecs("pro.plus")).map(([kind, specs]) => [kind, {
    required: specs.map(spec => spec.id), sources: specs.map(spec => ({id: spec.id, updated_at: Date.now() / 1000}))
  }]));
  const filters = Object.fromEntries(FILTER_LISTS.map(spec => [spec.id, {source: {stale: false}}]));
  assert.equal(buildCoverage(lists, filters).complete, true);
  lists.threats.sources.find(source => source.id === "hagezi-threat-intel-full").id = "hagezi-threat-intel";
  assert.equal(buildCoverage(lists, filters).complete, false);
  assert.ok(buildCoverage(lists, filters).missing.includes("hagezi-threat-intel-full"));
  lists.threats.required = feedSpecs("pro.plus", "medium").threats.map(spec => spec.id);
  assert.equal(buildCoverage(lists, filters).complete, true, "explicitly selected medium is complete for that selection");
});

test("uncompilable required filters and disabled production size checks cannot report complete", async () => {
  const {buildCoverage, compileFilterRulesets, feedSpecs, FILTER_LISTS} = await load();
  const lists = Object.fromEntries(Object.entries(feedSpecs("pro.plus")).map(([kind, specs]) => [kind, {
    required: specs.map(spec => spec.id), sources: specs.map(spec => ({id: spec.id, updated_at: Date.now() / 1000}))
  }]));
  const filters = Object.fromEntries(FILTER_LISTS.map(spec => [spec.id, {source: {stale: false}, text: "||tracker.example^$unsupported-option\n"}]));
  const compiled = compileFilterRulesets(filters);
  const receipt = buildCoverage(lists, filters, compiled.stats);
  assert.equal(receipt.complete, false);
  assert.deepEqual(receipt.ineffective, ["easyprivacy", "easylist"]);
  assert.equal(receipt.filterSyntax, "supported-subset");
  lists.trackers.development = true;
  assert.equal(buildCoverage(lists, filters).complete, false);
  assert.equal(buildCoverage(lists, filters).development, true);
});

test("a complete build refuses missing coverage before replacing any last-good output", async () => {
  const {build, buildCoverage} = await load();
  const out = temp();
  try {
    fs.mkdirSync(path.join(out, "chrome"));
    fs.writeFileSync(path.join(out, "chrome/last-good"), "unchanged");
    assert.throws(() => build({out, requireComplete: true}), /Incomplete browser coverage/);
    assert.equal(fs.readFileSync(path.join(out, "chrome/last-good"), "utf8"), "unchanged");
    const receipt = buildCoverage(null, null);
    assert.equal(receipt.complete, false);
    for (const name of ["urlhaus-filter", "phishing-army", "hagezi-threat-intel-full", "hagezi-pro.plus", "adguard-cname-ads", "adguard-cname-trackers", "easylist", "easyprivacy", "adguard-clickthroughs"]) assert.ok(receipt.missing.includes(name), name);
    const reduced = build({out});
    const stamp = JSON.parse(fs.readFileSync(path.join(out, "chrome/rules/build.json")));
    assert.deepEqual(stamp.coverage, reduced.coverage);
    assert.equal(stamp.coverage.complete, false);
    assert.match(stamp.psl_sha256, /^[a-f0-9]{64}$/);
    assert.ok(fs.existsSync(path.join(out, "chrome/vendor/public_suffix_list.dat")));
    assert.ok(fs.existsSync(path.join(out, "chrome/semantic.html")));
    assert.ok(fs.existsSync(path.join(out, "chrome/privacy.html")));
    assert.ok(fs.existsSync(path.join(out, "chrome/core/cosmetic-selectors.js")));
    assert.ok(fs.existsSync(path.join(out, "chrome/core/browser-privacy.js")));
    const manifest = JSON.parse(fs.readFileSync(path.join(out, "chrome/manifest.json")));
    assert.ok(manifest.optional_permissions.includes("privacy"));
    assert.ok(manifest.permissions.includes("webNavigation"));
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("unsupported cosmetic exemptions are visible and cannot report complete coverage", async () => {
  const {buildCoverage, feedSpecs, FILTER_LISTS, build} = await load();
  const {compileCosmetics} = require("../../scripts/lib/cosmetic-compiler.cjs");
  const lists = Object.fromEntries(Object.entries(feedSpecs("pro.plus")).map(([kind, specs]) => [kind, {
    required: specs.map(spec => spec.id), sources: specs.map(spec => ({id: spec.id, updated_at: Date.now() / 1000})), domains: [],
  }]));
  const filters = Object.fromEntries(FILTER_LISTS.map(spec => [spec.id, {source: {stale: false}, text: "||tracker.example^\n##.adunit\n@@||example.com^$generichide,unknown-option"}]));
  const data = compileCosmetics([filters.easylist.text]);
  const receipt = buildCoverage(lists, filters, null, data);
  assert.equal(receipt.complete, false); assert.equal(receipt.cosmetics.reduced, true);
  assert.deepEqual(receipt.cosmetics.disabledFamilies, ["generic"]);
  assert.equal(receipt.cosmetics.genericRules, 1);
  const out = temp();
  try {
    fs.mkdirSync(path.join(out, "chrome")); fs.writeFileSync(path.join(out, "chrome", "last-good"), "unchanged");
    assert.throws(() => build({out, lists, filters, requireComplete: true}), /cosmetic coverage was reduced/);
    assert.equal(fs.readFileSync(path.join(out, "chrome", "last-good"), "utf8"), "unchanged");
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("second output publication failure restores both last-good folders", async () => {
  const {publishBuild} = await load();
  const out = temp();
  const stage = path.join(out, "stage"); fs.mkdirSync(stage);
  for (const name of ["chrome", "firefox"]) {
    fs.mkdirSync(path.join(out, name)); fs.writeFileSync(path.join(out, name, "version"), "old-" + name);
    fs.mkdirSync(path.join(stage, name)); fs.writeFileSync(path.join(stage, name, "version"), "new-" + name);
  }
  try {
    const rename = (a, b) => { if (a === path.join(stage, "firefox")) throw new Error("disk failure"); fs.renameSync(a, b); };
    assert.throws(() => publishBuild(stage, out, rename), /disk failure/);
    for (const name of ["chrome", "firefox"]) assert.equal(fs.readFileSync(path.join(out, name, "version"), "utf8"), "old-" + name);
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("filter download without Content-Length is canceled at the byte bound and never cached", async () => {
  const {loadFilters, FILTER_LISTS} = await load();
  const dir = temp(); const notes = []; let canceled = 0, chunks = 0;
  const fetchImpl = async (url, options) => {
    assert.equal(options.redirect, "error");
    const body = new ReadableStream({
      pull(controller) { chunks++; controller.enqueue(new Uint8Array(1024 * 1024)); },
      cancel() { canceled++; },
    });
    const response = new Response(body);
    Object.defineProperty(response, "url", {value: url});
    return response;
  };
  try {
    const result = await loadFilters(dir, {fetchImpl, allowMissing: true, log: note => notes.push(note)});
    assert.deepEqual(result, {});
    assert.equal(canceled, FILTER_LISTS.length);
    assert.ok(chunks <= FILTER_LISTS.length * 19, "no unbounded buffering after rejection");
    assert.ok(notes.some(note => /size limit|too large|exceeds/.test(note)), notes.join("\n"));
    for (const spec of FILTER_LISTS) assert.equal(fs.existsSync(path.join(dir, spec.id + ".txt")), false);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
