"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {spawnSync} = require("node:child_process");
const {validateReceipt, compareReceipts} = require("../../scripts/lib/sdk-wire-drift.cjs");
const cli = path.resolve(__dirname, "../../scripts/compare-sdk-wire-drift.mjs");
const digest = value => crypto.createHash("sha256").update(value).digest("hex");
const a = "a".repeat(64), b = "b".repeat(64), c = "c".repeat(64);
const rev1 = "1".repeat(40), rev2 = "2".repeat(40);
function receipt(revision, values = {}) {
  const source = revision === rev1 ? "controlled-sdk-release-one" : "controlled-sdk-release-two";
  const r = {
    schema: 1, sdk: {name: "matomo", revision, bundle_sha256: digest(source)},
    setup: {fixture_sha256: a, policy_sha256: b, extension_sha256: c, execution: "native-chrome-proxy"},
    evidence: {sender_completed: true, origin_tls_collector: true, proxy_route_verified: true,
      origin_meter_valid: true, positive_control_bytes: 53, positive_control_events: 1},
    cases: [
      {id: "query", kind: "tracking", transport: "GET/image", context_completed: true,
        received_canary_events: 0, received_application_bytes: 0, functional_succeeded: null},
      {id: "opaque", kind: "tracking", transport: "POST/xhr", context_completed: true,
        received_canary_events: 0, received_application_bytes: 0, functional_succeeded: null},
      {id: "checkout", kind: "functional", transport: "POST/xhr", context_completed: true,
        received_canary_events: 0, received_application_bytes: 53, functional_succeeded: true}
    ]
  };
  if (values.tracking) Object.assign(r.cases[0], values.tracking);
  if (values.opaque) Object.assign(r.cases[1], values.opaque);
  if (values.functional) Object.assign(r.cases[2], values.functional);
  if (values.setup) Object.assign(r.setup, values.setup);
  if (values.evidence) Object.assign(r.evidence, values.evidence);
  return r;
}
test("new canary deliveries are regressions; persistent and stopped escapes are explicit", () => {
  const before = receipt(rev1, {tracking: {received_canary_events: 2, received_application_bytes: 40}});
  const after = receipt(rev2, {opaque: {received_canary_events: 1, received_application_bytes: 10}});
  const out = compareReceipts(before, after);
  assert.equal(out.status, "REGRESSION");
  assert.deepEqual(out.new_canary_escapes, ["opaque"]);
  assert.deepEqual(out.stopped_canary_escapes, ["query"]);
  assert.equal(out.cases_compared, 3);
  const still = receipt(rev2, {tracking: {received_canary_events: 1, received_application_bytes: 20}});
  assert.deepEqual(compareReceipts(before, still).persistent_canary_escapes, ["query"]);
});
test("unattributed positive first-party bytes do not earn zero-leak credit", () => {
  const out = compareReceipts(receipt(rev1), receipt(rev2, {opaque: {received_application_bytes: 80}}));
  assert.equal(out.status, "NOT COVERED");
  assert.deepEqual(out.unattributed_tracking_bytes, ["opaque"]);
  assert.equal(compareReceipts(receipt(rev1), receipt(rev2)).status, "NO NEW OBSERVED CANARY ESCAPE");
});
test("functional control failure and missing delivery are both regressions", () => {
  for (const values of [{functional: {functional_succeeded: false}},
    {functional: {received_application_bytes: 0}}]) {
    const out = compareReceipts(receipt(rev1), receipt(rev2, values));
    assert.equal(out.status, "REGRESSION");
    assert.deepEqual(out.functional_regressions, ["checkout"]);
  }
  const invalidBase = receipt(rev1, {functional: {functional_succeeded: false}});
  assert.equal(compareReceipts(invalidBase, receipt(rev2)).status, "NOT COVERED");
});
test("persistent canary volume increase is a real observed regression", () => {
  const before = receipt(rev1, {tracking: {received_canary_events: 1, received_application_bytes: 10}});
  const after = receipt(rev2, {tracking: {received_canary_events: 3, received_application_bytes: 30}});
  const out = compareReceipts(before, after);
  assert.equal(out.status, "REGRESSION");
  assert.deepEqual(out.increased_canary_event_counts, [{id: "query", before: 1, after: 3}]);
  assert.deepEqual(out.increased_tracking_bytes, [{id: "query", before: 10, after: 30}]);
  assert.deepEqual(out.persistent_canary_escapes, ["query"]);
  assert.deepEqual(out.new_canary_escapes, []);
});
test("same canary volume with additional received tracking bytes cannot be credited clean", () => {
  const before = receipt(rev1, {tracking: {received_canary_events: 1, received_application_bytes: 10}});
  const after = receipt(rev2, {tracking: {received_canary_events: 1, received_application_bytes: 100}});
  const out = compareReceipts(before, after);
  assert.equal(out.status, "NOT COVERED");
  assert.deepEqual(out.increased_canary_event_counts, []);
  assert.deepEqual(out.increased_tracking_bytes, [{id: "query", before: 10, after: 100}]);
  assert.deepEqual(out.unattributed_tracking_bytes, []);
});
test("unchanged SDK bytes are not accepted as evidence of source drift", () => {
  const identical = receipt(rev1);
  assert.throws(() => compareReceipts(identical, receipt(rev1)), /source bytes/);
  const relabel = receipt(rev2); relabel.sdk.bundle_sha256 = identical.sdk.bundle_sha256;
  assert.throws(() => compareReceipts(identical, relabel), /source bytes/);
});
test("CLI entrypoint executes when installed in a directory containing spaces", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-sdk spaced-"));
  try {
    const cloned = path.join(dir, "scripts", "compare-sdk-wire-drift.mjs");
    const lib = path.join(dir, "scripts", "lib", "sdk-wire-drift.cjs");
    fs.mkdirSync(path.dirname(lib), {recursive: true});
    fs.copyFileSync(cli, cloned);
    fs.copyFileSync(path.resolve(__dirname, "../../scripts/lib/sdk-wire-drift.cjs"), lib);
    const p = spawnSync(process.execPath, [cloned, "--not-valid"], {encoding: "utf8", timeout: 10000});
    assert.notEqual(p.status, 0, "CLI must reject invalid input, not silently exit 0");
    assert.match(p.stderr, /sdk-wire-drift: invalid input/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
test("routing, positive controls, sender completion and native declaration are required", () => {
  const good = receipt(rev1);
  for (const evidence of [{origin_meter_valid: false}, {sender_completed: false},
    {proxy_route_verified: false}, {positive_control_bytes: 0},
    {positive_control_events: 0}, {origin_tls_collector: false}])
    assert.equal(compareReceipts(good, receipt(rev2, {evidence})).status, "NOT COVERED");
  assert.equal(compareReceipts(receipt(rev1, {setup: {execution: "source-only"}}),
    receipt(rev2, {setup: {execution: "source-only"}})).status, "NOT COVERED");
});
test("policy/artifact/fixture and denominator drift are rejected", () => {
  const base = receipt(rev1);
  for (const key of ["policy_sha256", "fixture_sha256", "extension_sha256"]) {
    const altered = receipt(rev2, {setup: {[key]: "0".repeat(64)}});
    assert.throws(() => compareReceipts(base, altered), /changed/);
  }
  const missing = receipt(rev2); missing.cases.pop();
  assert.throws(() => compareReceipts(base, missing), /denominator/);
  const renamed = receipt(rev2); renamed.cases[0].id = "renamed";
  assert.throws(() => compareReceipts(base, renamed), /identity/);
  const changedTransport = receipt(rev2); changedTransport.cases[0].transport = "POST/xhr";
  assert.throws(() => compareReceipts(base, changedTransport), /transport/);
});
test("rejects raw URLs, duplicate IDs, invalid bytes, forged canary and unknown evidence", () => {
  const invalid = [
    r => {r.cases[0].url = "https://tracker.test?secret=123";},
    r => {r.cases[0].id = "checkout";},
    r => {r.cases[0].received_application_bytes = -1;},
    r => {r.cases[0].received_canary_events = 1;},
    r => {r.cases[1].received_application_bytes = 0.5;},
    r => {r.evidence.raw_identifier = "secret";},
    r => {r.sdk.bundle_sha256 = "unverified";},
    r => {r.cases[2].received_canary_events = 1;},
  ];
  for (const mutate of invalid) {
    const r = receipt(rev1); mutate(r);
    assert.throws(() => validateReceipt(r));
  }
});
test("offline CLI checks exact local bundle hashes, creates private exclusive output, never launches Chrome", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eg-sdk-wire-"));
  try {
    const files = Object.fromEntries(["before", "after"].map(x => [x, path.join(dir, x + ".json")]));
    const bundles = Object.fromEntries(["before", "after"].map(x => [x, path.join(dir, x + ".js")]));
    const out = path.join(dir, "report.json");
    fs.writeFileSync(bundles.before, "controlled-sdk-release-one");
    fs.writeFileSync(bundles.after, "controlled-sdk-release-two");
    fs.writeFileSync(files.before, JSON.stringify(receipt(rev1)));
    fs.writeFileSync(files.after, JSON.stringify(receipt(rev2)));
    const args = [cli, "--before", files.before, "--after", files.after,
      "--before-bundle", bundles.before, "--after-bundle", bundles.after, "--out", out];
    let proc = spawnSync(process.execPath, args, {encoding: "utf8", timeout: 10000});
    assert.equal(proc.status, 0, proc.stderr);
    assert.equal(proc.stdout, "");
    const report = JSON.parse(fs.readFileSync(out, "utf8"));
    assert.equal(report.status, "NO NEW OBSERVED CANARY ESCAPE");
    assert.match(report.scope, /not independently prove/);
    assert.equal(fs.statSync(out).mode & 0o777, 0o600);
    proc = spawnSync(process.execPath, args, {encoding: "utf8", timeout: 10000});
    assert.notEqual(proc.status, 0, "No overwriting prior evidence");
    const originalReport = fs.readFileSync(out, "utf8");
    fs.writeFileSync(bundles.after, "tampered-sdk");
    const other = path.join(dir, "other.json");
    proc = spawnSync(process.execPath, [...args.slice(0, -2), "--out", other], {encoding: "utf8", timeout: 10000});
    assert.notEqual(proc.status, 0, "Changed source must fail pin");
    assert.equal(fs.existsSync(other), false);
    assert.equal(fs.readFileSync(out, "utf8"), originalReport);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
