"use strict";
// Build script: snapshot verification, feed metadata kept in sync with the proxy, and build output.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "../..");
const FEEDS = path.join(__dirname, "fixtures/feeds");
const load = () => import(path.join(root, "scripts/build-browser.mjs"));
const tmp = () => { fs.mkdirSync(path.join(root, ".cache"), {recursive: true}); return fs.mkdtempSync(path.join(root, ".cache", "build-test-")); };

test("feed URLs, names and minimums match the proxy's src/egress_guard/feeds.py", async () => {
  const {feedSpecs, TIERS} = await load();
  const py = fs.readFileSync(path.join(root, "src/egress_guard/feeds.py"), "utf8");
  for (const tier of Object.keys(TIERS)) {
    assert.match(py, new RegExp(`\\("${tier.replace(".", "\\.")}", "${TIERS[tier].name.replace(/\+/g, "\\+")}", ${TIERS[tier].minimum.toLocaleString("en-US").replace(/,/g, "_")}\\)`), tier);
  }
  const specs = feedSpecs("pro.plus");
  assert.match(py, /"HaGeZi Threat Intelligence \(Medium\)",\s+HAGEZI \+ "tif\.medium-onlydomains\.txt",\s+100_000/);
  assert.ok(specs.threats[0].url.endsWith("tif.medium-onlydomains.txt"));
  assert.match(py, /\("ads", 1_000\), \("trackers", 20_000\)/);
  assert.deepEqual(specs.cname.map((s) => s.minimum), [1000, 20000]);
  assert.match(py, /HAGEZI = "https:\/\/raw\.githubusercontent\.com\/hagezi\/dns-blocklists\/main\/wildcard\/"/);
  assert.ok(specs.trackers[0].url.startsWith("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"));
});

test("snapshots are re-verified: tampering, bad names, wrong counts and small lists are refused", async () => {
  const {readSnapshot, dnsName} = await load();
  const good = path.join(FEEDS, "blocklists/hagezi-pro.plus.txt");
  assert.equal(readSnapshot(good).names.length, 4);
  assert.throws(() => readSnapshot(good, {minimum: 50000}), /fewer than/);
  const dir = tmp();
  try {
    const original = fs.readFileSync(good, "utf8");
    const write = (text) => { const f = path.join(dir, "x.txt"); fs.writeFileSync(f, text); return f; };
    assert.throws(() => readSnapshot(write(original.replace("adserver.example", "adserver.exampla"))), /SHA-256/);
    assert.throws(() => readSnapshot(write(original.split("\n").slice(1).join("\n"))), /header/);
    const [header, ...rest] = original.split("\n");
    const meta = JSON.parse(header.slice(2));
    assert.throws(() => readSnapshot(write(`# ${JSON.stringify({...meta, entries: 9})}\n${rest.join("\n")}`)), /count/);
    const crypto = require("node:crypto");
    const body = "evil..example\n";
    assert.throws(() => readSnapshot(write(`# ${JSON.stringify({entries: 1, sha256: crypto.createHash("sha256").update(body).digest("hex")})}\n${body}`)), /invalid hostname/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
  for (const bad of ["localhost", "1.2.3.4", "a..b", "-a.example", "A.example", "x.example."]) assert.equal(dnsName(bad), null, bad);
  assert.equal(dnsName("xn--bcher-kva.example"), "xn--bcher-kva.example");
});

test("build emits Chrome and Firefox from shared sources; Chrome gets rulesets, a bundled worker and a notice", async () => {
  const {build, loadLists} = await load();
  const out = tmp();
  try {
    const notes = [];
    const lists = loadLists(FEEDS, {allowSmall: true, log: (m) => notes.push(m)});
    assert.deepEqual(notes, ["missing adguard-cname-ads.exact: cname list will be empty"]);
    const summary = build({out, lists});
    assert.equal(summary.extensionId, "danbhmcinakkkkbobacafgidgkfibfmg");
    const chrome = path.join(out, "chrome"), firefox = path.join(out, "firefox");
    const cm = JSON.parse(fs.readFileSync(path.join(chrome, "manifest.json"), "utf8"));
    assert.equal(cm.background.service_worker, "background.js");
    for (const r of cm.declarative_net_request.rule_resources) assert.ok(Array.isArray(JSON.parse(fs.readFileSync(path.join(chrome, r.path), "utf8"))), r.path);
    for (const f of [...cm.content_scripts[0].js, "popup.html", "popup.js", "ui.css", "warning.html", "warning.js", "core/hosts.js", "core/dnr.js"]) assert.ok(fs.existsSync(path.join(chrome, f)), f);
    const threats = JSON.parse(fs.readFileSync(path.join(chrome, "rules/threats.json"), "utf8"));
    assert.deepEqual(threats.flatMap((r) => r.condition.requestDomains).sort(), ["malware-fixture.test", "malware-fixture.test", "phish.example", "phish.example"]);
    const trackers = JSON.parse(fs.readFileSync(path.join(chrome, "rules/trackers.json"), "utf8"));
    assert.deepEqual(trackers[0].condition.requestDomains, ["adserver.example", "tracker-fixture.test"], "subdomains folded into parents");
    const worker = fs.readFileSync(path.join(chrome, "background.js"), "utf8");
    assert.doesNotMatch(worker, /importScripts|\bfetch\s*\(/);
    assert.match(worker, /globalThis\.EGLists = /);
    assert.match(worker, /HaGeZi Multi PRO\+\+/);
    const notice = fs.readFileSync(path.join(chrome, "NOTICE.txt"), "utf8");
    assert.match(notice, /GPL-3\.0/);
    assert.match(notice, /tif\.medium-onlydomains\.txt/);
    assert.match(notice, /AdGuard CNAME-cloaked trackers/);
    const fm = JSON.parse(fs.readFileSync(path.join(firefox, "manifest.json"), "utf8"));
    assert.deepEqual(fm, JSON.parse(fs.readFileSync(path.join(root, "browser/manifest.json"), "utf8")));
    for (const f of [...fm.background.scripts, ...fm.content_scripts[0].js, "popup.html", "ui.css"]) assert.ok(fs.existsSync(path.join(firefox, f)), f);
    assert.equal(fs.existsSync(path.join(firefox, "warning.html")), false);
    assert.equal(fs.existsSync(path.join(firefox, "rules")), false);
    // No lists: valid empty rulesets, parameter stripping still on.
    build({out, lists: null});
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(chrome, "rules/trackers.json"), "utf8")), []);
    assert.ok(JSON.parse(fs.readFileSync(path.join(chrome, "rules/params.json"), "utf8")).length > 0);
    assert.deepEqual(fs.readdirSync(out).sort(), ["chrome", "firefox"], "staging folder cleaned up");
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});
