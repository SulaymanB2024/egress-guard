"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {spawnSync} = require("node:child_process");
const {SDK_IDS, validateSourceManifest, reviewSourcePins, MAX_FILE_BYTES} = require("../../scripts/lib/sdk-source-review.cjs");
const project = path.resolve(__dirname, "../..");
const cli = path.join(project, "scripts/compare-sdk-wire-drift.mjs");
const published = JSON.parse(fs.readFileSync(path.join(project, "tests/fixtures/sdk_drift/manifest.json"), "utf8"));
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const blob = bytes => crypto.createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
const fixtureBytes = Buffer.from("synthetic source-verifier fixture; this is not vendor SDK code\n");

function fixture() {
  // A synthetic inventory tests evidence boundaries without downloading,
  // interpreting or executing any third-party code.
  const doc = "https://example.test/source-review-fixture";
  return {schema: 1, id: "synthetic-source-unit-fixture", reviewed_on: "2026-11-22",
    evidence_level: "manual-source-review", not_covered: [...published.not_covered],
    sdks: SDK_IDS.map(id => ({id, name: id + " synthetic fixture",
      source_kind: id === "posthog" ? "sdk-source" : "unacquired-sdk",
      repository: id === "posthog" ? "example/test-fixture" : null,
      revision: id === "posthog" ? "1".repeat(40) : null,
      source_directory: id === "posthog" ? id : null,
      reviewed_files: id === "posthog" ? [{path: "fixture.txt", bytes: fixtureBytes.length,
        sha256: sha(fixtureBytes), git_blob_sha1: blob(fixtureBytes), acquired_on: "2026-11-22",
        source_url: `https://raw.githubusercontent.com/example/test-fixture/${"1".repeat(40)}/fixture.txt`}] : [],
      documents: [{url: doc, review: "primary-reviewed"}],
      claims: [{id: "synthetic-claim", tier: id === "posthog" ? "reviewed-source" : "reviewed-primary-doc",
        statement: "Synthetic validator input; no vendor claim is tested here.",
        files: id === "posthog" ? ["fixture.txt"] : [], documents: [doc],
        limitations: ["Not an SDK or browser execution."]}]}))};
}
function sourceRow(m) { return m.sdks.find(s => s.id === "posthog"); }
function temp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-sdk source-"));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const root = path.join(dir, "source root"), sdk = path.join(root, "posthog");
  fs.mkdirSync(sdk, {recursive: true}); fs.writeFileSync(path.join(sdk, "fixture.txt"), fixtureBytes);
  const manifest = path.join(dir, "manifest.json"); fs.writeFileSync(manifest, JSON.stringify(fixture()));
  return {dir, root, sdk, manifest};
}
function run(manifest, root, extra = []) {
  return spawnSync(process.execPath, [cli, "--source-manifest", manifest, "--source-root", root, ...extra],
    {encoding: "utf8", timeout: 10000, maxBuffer: 256 * 1024});
}

test("source inventory retains all requested families and separates proprietary, server and integration evidence", () => {
  const before = JSON.stringify(published);
  assert.equal(validateSourceManifest(published), published);
  assert.equal(JSON.stringify(published), before, "validation is read-only");
  assert.deepEqual(published.sdks.map(s => s.id), SDK_IDS);
  assert.deepEqual(published.sdks.filter(s => s.source_kind === "unacquired-sdk").map(s => s.id),
    ["ga4", "gtm", "meta-pixel"]);
  assert.equal(published.sdks.find(s => s.id === "prebid").source_kind, "server-source");
  assert.equal(published.sdks.find(s => s.id === "fingerprint-pro").source_kind, "integration-documentation");
  assert.equal(published.sdks.reduce((sum, s) => sum + s.reviewed_files.length, 0), 11);
  assert.equal(published.sdks.find(s => s.id === "meta-pixel").claims.filter(c => c.tier === "unverified-primary").length, 2);
});

test("source validation rejects missing denominators, invented authority, paths and unsupported evidence", () => {
  for (const mutate of [
    m => m.sdks.pop(), m => { m.sdks[0].id = "posthog"; },
    m => { m.vendor_sdk_execution = "VERIFIED"; }, m => m.not_covered.pop(),
    m => { m.evidence_level = "native-chrome-proxy"; },
    m => { m.sdks[0].revision = "1".repeat(40); },
    m => { sourceRow(m).source_directory = "../posthog"; },
    m => { sourceRow(m).reviewed_files[0].path = "../secret"; },
    m => { sourceRow(m).reviewed_files[0].path = "/absolute"; },
    m => { sourceRow(m).reviewed_files[0].path = "nested\\escape"; },
    m => { sourceRow(m).reviewed_files.push({...sourceRow(m).reviewed_files[0]}); },
    m => { sourceRow(m).reviewed_files[0].bytes = MAX_FILE_BYTES + 1; },
    m => { sourceRow(m).reviewed_files[0].source_url = "https://raw.githubusercontent.com/example/test-fixture/main/fixture.txt"; },
    m => { sourceRow(m).reviewed_files[0].acquired_on = "2026-02-30"; },
    m => { sourceRow(m).claims[0].files = ["unreviewed.ts"]; },
    m => { sourceRow(m).claims[0].limitations = []; },
    m => { sourceRow(m).claims[0].id = false; },
    m => { m.sdks[0].claims[0].tier = "reviewed-source"; },
    m => { m.sdks[0].documents[0].review = "primary-inaccessible"; },
    m => { m.sdks[0].documents[0].url = "https://user:secret@example.test/"; },
  ]) {
    const manifest = fixture(); mutate(manifest);
    assert.throws(() => validateSourceManifest(manifest));
  }
});

test("matching source bytes never create SDK, receiver or native-enforcement evidence", () => {
  const result = reviewSourcePins(fixture(), () => fixtureBytes);
  assert.equal(result.status, "SOURCE PINS VERIFIED");
  assert.equal(result.inventory_families, 7);
  assert.equal(result.families_with_verified_files, 1);
  assert.equal(result.vendor_sdk_execution, "NOT COVERED");
  assert.equal(result.native_browser_enforcement, "NOT COVERED");
  assert.equal(result.receiver_bytes, "NOT COVERED");
  assert.equal(result.families.filter(s => s.source_status === "NOT COVERED").length, 6);
  assert.ok(result.families.every(s => s.claim_review.includes("NOT REVALIDATED")));
});

test("changed source bytes, Git blob mismatch and missing sources cannot receive a verified pin status", () => {
  const changed = reviewSourcePins(fixture(), () => Buffer.from("changed source"));
  assert.equal(changed.status, "SOURCE DRIFT");
  assert.equal(changed.files[0].status, "MISMATCH");
  const wrongBlob = fixture(); sourceRow(wrongBlob).reviewed_files[0].git_blob_sha1 = "a".repeat(40);
  assert.equal(reviewSourcePins(wrongBlob, () => fixtureBytes).status, "SOURCE DRIFT");
  for (const [reader, expected] of [
    [() => { throw Object.assign(new Error("do not disclose local path"), {code: "ENOENT"}); }, "MISSING"],
    [() => { throw new Error("do not disclose local path"); }, "UNREADABLE"],
    [() => Buffer.alloc(MAX_FILE_BYTES + 1), "UNREADABLE"],
    [() => "not raw bytes", "UNREADABLE"]
  ]) {
    const result = reviewSourcePins(fixture(), reader);
    assert.equal(result.status, "NOT COVERED"); assert.equal(result.files[0].status, expected);
    assert.ok(!JSON.stringify(result).includes("do not disclose"));
  }
});

test("real Node source-review CLI hashes local bytes, pins its manifest and refuses overwrites", t => {
  const f = temp(t), output = path.join(f.dir, "source receipt.json");
  const result = run(f.manifest, f.root, ["--out", output]);
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(fs.readFileSync(output, "utf8"));
  assert.equal(receipt.manifest_sha256, sha(fs.readFileSync(f.manifest)));
  assert.equal(receipt.verifier_sha256.entrypoint, sha(fs.readFileSync(cli)));
  assert.equal(receipt.files[0].observed_sha256, sha(fixtureBytes));
  assert.equal(receipt.native_browser_enforcement, "NOT COVERED");
  const first = fs.readFileSync(output);
  assert.equal(run(f.manifest, f.root, ["--out", output]).status, 1);
  assert.deepEqual(fs.readFileSync(output), first);
});

test("source CLI emits a failing receipt for missing, modified, linked and non-regular files", t => {
  const f = temp(t), file = path.join(f.sdk, "fixture.txt");
  fs.writeFileSync(file, "modified");
  let result = run(f.manifest, f.root);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "SOURCE DRIFT");
  fs.unlinkSync(file);
  result = run(f.manifest, f.root);
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).files[0].status, "MISSING");
  const outside = path.join(f.dir, "outside.txt"); fs.writeFileSync(outside, fixtureBytes);
  fs.symlinkSync(outside, file);
  result = run(f.manifest, f.root);
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).files[0].status, "UNREADABLE");
  fs.unlinkSync(file); fs.mkdirSync(file);
  result = run(f.manifest, f.root);
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).files[0].status, "UNREADABLE");
});

test("source CLI refuses mixed wire/source authority and missing mode inputs", t => {
  const f = temp(t);
  assert.equal(run(f.manifest, f.root, ["--before", f.manifest]).status, 1);
  const result = spawnSync(process.execPath, [cli, "--source-manifest", f.manifest], {encoding: "utf8"});
  assert.equal(result.status, 1); assert.equal(result.stdout, "");
});
