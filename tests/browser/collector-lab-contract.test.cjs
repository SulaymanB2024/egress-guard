"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const runner = import("./chrome-collector-lab.mjs");
const root = path.resolve(__dirname, "../..");

test("--check performs source-only validation and cannot enter native work", async () => {
  const {main} = await runner;
  const receipt = await main(["--check", "--chrome", "/does-not-exist", "--python", "/does-not-exist"], () => { throw new Error("native path reached"); });
  assert.equal(receipt.qualification, "NOT COVERED");
  assert.equal(receipt.nativeExecuted, false);
  assert.equal(receipt.startedProcesses, 0);
  assert.equal(receipt.openedSockets, 0);
  assert.match(receipt.fixtureSha256, /^[a-f0-9]{64}$/);
});

test("native mode requires explicit executables, artifact and new receipt; no profile/trust escape option", async () => {
  const {parseOptions} = await runner;
  for (const args of [[], ["--chrome", "/x"], ["--profile", "/existing"], ["--ignore-certificate-errors"], ["--check", "--check"], ["--check", "--subjects", "1"], ["--check", "--subjects", "9"], ["--check", "--timeout", "Infinity"]]) assert.throws(() => parseOptions(args));
  const valid = parseOptions(["--chrome", "/chrome", "--python", "/python", "--extension", "/artifact", "--out", "/new.json"]);
  assert.equal(valid.subjects, 4); assert.equal(valid.timeout, 600000);
});

test("browser routing uses actual proxy and exact SPKI trust; external DNS fails", async () => {
  const {browserArguments, HOSTS, validateMetadata} = await runner;
  const meta = {schema: 1, hosts: [...HOSTS], proxy_port: 18080, origin_port: 18443, origin_certificate_sha256: "a".repeat(64), origin_spki: Buffer.alloc(32, 1).toString("base64"), proxy: {ready: true, revision: "synthetic"}, history: "none", mitmproxy: "12.3.1"};
  const args = browserArguments(meta);
  assert(args.includes("--proxy-server=http://127.0.0.1:18080"));
  assert(args.includes("--proxy-bypass-list=<-loopback>"));
  assert(args.includes(`--ignore-certificate-errors-spki-list=${meta.origin_spki}`));
  assert(!args.includes("--ignore-certificate-errors"));
  assert(args.includes("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"));
  assert.throws(() => validateMetadata({...meta, hosts: ["publisher.lab.test", "shop.lab.test", ...HOSTS.slice(2)]}));
  assert.throws(() => validateMetadata({...meta, proxy_port: 0}));
});

test("native certificate receipt compares actual DER bytes, not just a configured trust flag", async () => {
  const {certificateReceipt} = await runner;
  const certificate = new crypto.X509Certificate(require("node:tls").rootCertificates[0]);
  const expected = crypto.createHash("sha256").update(certificate.raw).digest("hex");
  assert.equal(certificateReceipt({tableNames: [certificate.raw.toString("base64")]}, expected).status, "PASS");
  assert.equal(certificateReceipt({tableNames: [certificate.raw.toString("base64")]}, "0".repeat(64)).status, "FAIL");
  for (const result of [undefined, {}, {tableNames: []}, {tableNames: ["not-DER"]}]) assert.equal(certificateReceipt(result, expected).status, "NOT COVERED");
});

test("cohort truth is separate from observed IDs, uses two registrable sites and stable Python-compatible tokens", async () => {
  const {makeVisits, HOSTS} = await runner;
  const a = makeVisits("baseline", 4), b = makeVisits("protected", 4);
  assert.equal(a.rows.length, 8);
  const expected = "eglab-id-" + crypto.createHash("sha256").update("egress-guard-lab-subject-0").digest("hex").slice(0, 24);
  assert.equal(a.rows[0].identifier, expected);
  for (let i = 0; i < a.rows.length; i++) {
    assert.match(a.rows[i].visit, /^[a-f0-9]{24}$/);
    assert.notEqual(a.rows[i].visit, b.rows[i].visit);
    assert.equal(a.rows[i].identifier, b.rows[i].identifier);
    assert.deepEqual(Object.keys(a.visits[a.rows[i].visit]).sort(), ["site", "subject"]);
  }
  assert.deepEqual([...new Set(a.rows.map(row => row.site))], HOSTS.slice(0, 2));
  assert.equal(new Set(a.rows.map(row => row.identifier)).size, 4);
});

function arms(CHANNELS, EXPECTED_BLOCKED) {
  const baseline = {channels: {}, scores: {}, routeCorrelated: true, connectionsClosed: true, rawApplicationBytesDelta: 2000, trackerHostApplicationBytes: 800};
  const score = channel => ({channel, subjects: 4, positive_pairs: 4, negative_pairs: 12, true_matches: 4, false_matches: 0,
    true_match_rate: 1, false_match_rate: 0, threshold: 1, threshold_chosen_from_ground_truth: false});
  for (const key of CHANNELS) {
    baseline.channels[key] = {receivedVisits: 8, events: key === "cart" ? 16 : 8, completedContexts: key === "cart" ? 16 : 8,
      actionWindows: {measuredWindows: key === "cart" ? 16 : 8, zeroByteWindows: 0,
        positiveByteWindows: key === "cart" ? 16 : 8, totalTargetOriginApplicationBytes: 800}};
    baseline.scores[key] = score(key);
  }
  baseline.scores.all = score("all");
  const protectedArm = structuredClone(baseline); protectedArm.trackerHostApplicationBytes = 0;
  for (const key of EXPECTED_BLOCKED) protectedArm.channels[key].receivedVisits = protectedArm.channels[key].events = 0;
  protectedArm.channels.ga4.actionWindows = {measuredWindows: 8, zeroByteWindows: 8, positiveByteWindows: 0,
    totalTargetOriginApplicationBytes: 0};
  return {baseline, protectedArm};
}

test("missing/anonymous baseline or uncompleted worker cannot earn blocking credit", async () => {
  const {assessDelivery, CHANNELS, EXPECTED_BLOCKED} = await runner;
  for (const variant of ["missing", "anonymous", "timeout"]) {
    const {baseline, protectedArm} = arms(CHANNELS, EXPECTED_BLOCKED);
    if (variant === "missing") baseline.channels.worker.receivedVisits = 0;
    if (variant === "anonymous") baseline.scores.worker.true_match_rate = 0;
    if (variant === "timeout") protectedArm.channels.worker.completedContexts = 7;
    assert.equal(assessDelivery(baseline, protectedArm, 8).find(row => row.name === "collector:worker").status, "NOT COVERED");
  }
});

test("opaque first-party residual and functional controls are mandatory, not removed from denominator", async () => {
  const {assessDelivery, CHANNELS, EXPECTED_BLOCKED} = await runner;
  const {baseline, protectedArm} = arms(CHANNELS, EXPECTED_BLOCKED);
  assert(assessDelivery(baseline, protectedArm, 8).every(row => row.status === "PASS"));
  protectedArm.channels.opaque.receivedVisits = 0;
  assert.equal(assessDelivery(baseline, protectedArm, 8).find(row => row.name.startsWith("opaque")).status, "FAIL");
  protectedArm.channels.cart.events = 15;
  assert.equal(assessDelivery(baseline, protectedArm, 8).find(row => row.name.startsWith("functional")).status, "FAIL");
  protectedArm.trackerHostApplicationBytes = 1;
  assert.equal(assessDelivery(baseline, protectedArm, 8).find(row => row.name.startsWith("tracker host")).status, "FAIL");
});

test("a common token on every subject fails opaque and aggregate identification despite TPR 1", async () => {
  const {assessDelivery, CHANNELS, EXPECTED_BLOCKED} = await runner;
  for (const armName of ["baseline", "protectedArm"]) for (const channel of ["opaque", "all"]) {
    const pair = arms(CHANNELS, EXPECTED_BLOCKED);
    Object.assign(pair[armName].scores[channel], {false_matches: 12, false_match_rate: 1});
    const check = assessDelivery(pair.baseline, pair.protectedArm, 8).find(row => row.name.startsWith("opaque"));
    assert.equal(check.status, "FAIL", `${armName}/${channel}: common token must not establish identity`);
  }
});

test("residual identification requires complete valid pair counts, rates and independent threshold", async () => {
  const {assessDelivery, CHANNELS, EXPECTED_BLOCKED} = await runner;
  for (const channel of ["opaque", "all"]) for (const change of [
    {positive_pairs: 0}, {negative_pairs: 0}, {positive_pairs: 3}, {negative_pairs: 11},
    {true_matches: 3}, {false_matches: 1}, {true_match_rate: 0}, {false_match_rate: 0.1},
    {subjects: 3}, {threshold_chosen_from_ground_truth: true}, {threshold: 2},
  ]) {
    const {baseline, protectedArm} = arms(CHANNELS, EXPECTED_BLOCKED);
    Object.assign(protectedArm.scores[channel], change);
    assert.equal(assessDelivery(baseline, protectedArm, 8).find(row => row.name.startsWith("opaque")).status, "FAIL");
  }
  const {baseline, protectedArm} = arms(CHANNELS, EXPECTED_BLOCKED);
  delete protectedArm.scores.all;
  assert.equal(assessDelivery(baseline, protectedArm, 8).find(row => row.name.startsWith("opaque")).status, "FAIL");
});

test("collector errors, overflow or uncorrelated partial bytes invalidate evidence", async () => {
  const {summarizeArm} = await runner;
  const before = {connections: [], decrypted_origin_application_bytes: 0, transport_disconnects: 0, handler_errors: 0, overflow: false};
  const base = {connections: [{host: "publisher.test", peer_port: 12345, application_bytes: 4, closed: true, proxy_route_observed: true}], events: [], decrypted_origin_application_bytes: 4, transport_disconnects: 0, overflow: false, handler_errors: 0};
  for (const change of [{handler_errors: 1}, {overflow: true}, {decrypted_origin_application_bytes: -1}, {connections: [{...base.connections[0], proxy_route_observed: false}]}]) assert.throws(() => summarizeArm({...base, ...change}, before, {}, []));
  const summary = summarizeArm(base, before, {}, []);
  assert.equal(summary.rawApplicationBytesDelta, 4);
  assert.equal(summary.channels.ga4.receivedVisits, 0);
  assert.equal(summary.channels.ga4.completedContexts, 0);
});

test("reused TCP source port remains a new metered connection; byte sizes are not invented wire totals", async () => {
  const {summarizeArm} = await runner;
  const row = {host: "tracker.test", peer_port: 12345, application_bytes: 100, closed: true, proxy_route_observed: true};
  const before = {connections: [row], decrypted_origin_application_bytes: 100, transport_disconnects: 0, handler_errors: 0, overflow: false};
  const after = {connections: [row, {...row, application_bytes: 3}], decrypted_origin_application_bytes: 103, transport_disconnects: 0, events: [], overflow: false, handler_errors: 0};
  const summary = summarizeArm(after, before, {}, []);
  assert.equal(summary.connections, 1);
  assert.equal(summary.trackerHostApplicationBytes, 3);
  assert.equal(summary.rawApplicationBytesDelta, 3);
});

test("source retains real sender, received-byte path, exclusive output and explicit native omissions", () => {
  const source = fs.readFileSync(path.join(__dirname, "chrome-collector-lab.mjs"), "utf8");
  assert(source.includes("chrome.runtime.sendMessage("));
  assert(source.includes("/privacy.html`"));
  assert(source.includes('fs.openSync(options.out, "wx", 0o600)'));
  assert(source.includes('env.PYTHONPATH = path.join(ROOT, "src")'));
  assert(!source.includes("testMatchOutcome"));
  assert(!source.includes("Browser.setGlobalPrivacyControl"));
  assert(source.includes('"WSS live revocation"'));
  assert(source.includes("HTML ping auditing (--no-pings helper baseline)"));
  assert(fs.readFileSync(path.join(root, "tests/privacy_lab.py"), "utf8").includes("same = visits[left]"));
});

test("existing output is refused before any fixture or browser attempt", async () => {
  const {runNative} = await runner;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "egress-guard-lab-contract-")), out = path.join(dir, "receipt.json");
  try {
    fs.writeFileSync(out, "keep this prior receipt\n");
    const report = await runNative({chrome: process.execPath, python: process.execPath, extension: "/missing-artifact", out, subjects: 4, timeout: 60000});
    assert.equal(report.qualification, "FAIL");
    assert.equal(report.nativeAttempted, false);
    assert.equal(report.nativeExecuted, false);
    assert.equal(fs.readFileSync(out, "utf8"), "keep this prior receipt\n");
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("sampled first-party zero-byte credit requires a positive baseline and all protected windows", async () => {
  const {assessDelivery, CHANNELS, EXPECTED_BLOCKED} = await runner;
  const pair = arms(CHANNELS, EXPECTED_BLOCKED);
  const find = () => assessDelivery(pair.baseline, pair.protectedArm, 8).find(row => row.name.startsWith("sampled first-party"));
  assert.equal(find().status, "PASS");
  pair.protectedArm.channels.ga4.actionWindows = {measuredWindows: 8, zeroByteWindows: 7, positiveByteWindows: 1,
    totalTargetOriginApplicationBytes: 11};
  assert.equal(find().status, "NOT COVERED");
  pair.protectedArm.channels.ga4.actionWindows = {measuredWindows: 8, zeroByteWindows: 8, positiveByteWindows: 0,
    totalTargetOriginApplicationBytes: 0};
  pair.baseline.channels.ga4.actionWindows.totalTargetOriginApplicationBytes = 0;
  assert.equal(find().status, "NOT COVERED");
});

test("tracker bytes on a preexisting routed TLS connection cannot be credited as zero", async () => {
  const {summarizeArm, assessDelivery, CHANNELS, EXPECTED_BLOCKED} = await runner;
  const row = {host: "tracker.test", peer_port: 29100, application_bytes: 21, closed: true, proxy_route_observed: true};
  const before = {connections: [row], decrypted_origin_application_bytes: 21,
    transport_disconnects: 0, handler_errors: 0, overflow: false};
  const after = {...before, connections: [{...row, application_bytes: 28}],
    decrypted_origin_application_bytes: 28, events: []};
  const summary = summarizeArm(after, before, {}, []);
  assert.equal(summary.connections, 0, "No new TCP connection was opened");
  assert.equal(summary.rawApplicationBytesDelta, 7);
  assert.equal(summary.trackerHostApplicationBytes, 7, "Existing tunnel traffic must be counted");
  const pair = arms(CHANNELS, EXPECTED_BLOCKED);
  pair.protectedArm.trackerHostApplicationBytes = summary.trackerHostApplicationBytes;
  assert.equal(assessDelivery(pair.baseline, pair.protectedArm, 8)
    .find(check => check.name === "tracker host received zero application bytes").status, "FAIL");

  const open = {...after, connections: [{...row, application_bytes: 28, closed: false}]};
  assert.equal(summarizeArm(open, before, {}, []).connectionsClosed, false);
  const unrouted = {...after, connections: [{...row, application_bytes: 28, proxy_route_observed: false}]};
  assert.throws(() => summarizeArm(unrouted, before, {}, []), /Unrouted/);
  const rewound = {...after, connections: [{...row, application_bytes: 18}],
    decrypted_origin_application_bytes: 18};
  assert.throws(() => summarizeArm(rewound, before, {}, []));
});

test("all-arm tracker-byte deltas include both old and newly opened same-port connections", async () => {
  const {summarizeArm} = await runner;
  const initial = {host: "tracker.test", peer_port: 35000, application_bytes: 100,
    closed: true, proxy_route_observed: true};
  const before = {connections: [initial], decrypted_origin_application_bytes: 100,
    transport_disconnects: 0, handler_errors: 0, overflow: false};
  const after = {...before, connections: [{...initial, application_bytes: 106},
    {...initial, application_bytes: 9}], decrypted_origin_application_bytes: 115, events: []};
  const summary = summarizeArm(after, before, {}, []);
  assert.equal(summary.connections, 1);
  assert.equal(summary.trackerHostApplicationBytes, 15);
  assert.equal(summary.rawApplicationBytesDelta, 15);
});
