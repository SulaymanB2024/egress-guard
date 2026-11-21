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
  assert.match(py, /Feed\("hagezi-threat-intel-full", "HaGeZi Threat Intelligence \(Full\)",\s+HAGEZI \+ "tif-onlydomains\.txt", 500_000/);
  assert.match(py, /PHISHING = Feed\("phishing-army", "Phishing Army", PHISHING_ARMY, 20_000/);
  assert.match(py, /MALWARE = Feed\("urlhaus-filter", "URLhaus malware hosts \(malware-filter\)", URLHAUS_FILTER, 1_000/);
  const byId = Object.fromEntries(specs.threats.map((s) => [s.id, s]));
  assert.deepEqual(Object.keys(byId), ["urlhaus-filter", "phishing-army", "hagezi-threat-intel-full"], "the proxy's threat group, default full tier");
  assert.ok(py.includes(`PHISHING_ARMY = "${byId["phishing-army"].url}"`));
  assert.ok(py.includes(`URLHAUS_FILTER = "${byId["urlhaus-filter"].url}"`));
  assert.ok(byId["hagezi-threat-intel-full"].url.endsWith("tif-onlydomains.txt"));
  assert.ok(byId["hagezi-threat-intel-full"].fallback.url.endsWith("tif.medium-onlydomains.txt"));
  assert.ok(feedSpecs("pro.plus", "medium").threats[2].url.endsWith("tif.medium-onlydomains.txt"));
  assert.match(py, /MAX_FEED_BYTES = 64 \* 1024 \* 1024/);
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

test("a missing threat feed is fatal unless explicitly allowed; links, non-files and oversize snapshots are refused unread", async () => {
  const {loadLists, readSnapshot} = await load();
  const dir = tmp();
  try {
    fs.mkdirSync(path.join(dir, "blocklists"));
    fs.copyFileSync(path.join(FEEDS, "blocklists/hagezi-pro.plus.txt"), path.join(dir, "blocklists/hagezi-pro.plus.txt"));
    assert.throws(() => loadLists(dir, {allowSmall: true}), /threat.*missing|missing.*threat/i);
    const notes = [];
    const lists = loadLists(dir, {allowSmall: true, allowMissing: true, log: (m) => notes.push(m)});
    assert.equal(lists.threats.names.length, 0);
    assert.ok(notes.some((n) => /hagezi-threat-intel/.test(n)));
    const real = path.join(FEEDS, "blocklists/hagezi-threat-intel.txt");
    const link = path.join(dir, "blocklists/hagezi-threat-intel.txt");
    fs.symlinkSync(real, link);
    assert.throws(() => readSnapshot(link), /regular file/);
    assert.throws(() => loadLists(dir, {allowSmall: true}), /regular file/);
    assert.throws(() => readSnapshot(path.join(dir, "blocklists")), /regular file/);
    const big = path.join(dir, "big.txt");
    fs.writeFileSync(big, "");
    fs.truncateSync(big, 65 * 1024 * 1024);
    assert.throws(() => readSnapshot(big), /size limit/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("a list too large for one Chrome ruleset file is split, and the manifest and worker know every part", async () => {
  const {build, loadLists, splitRules} = await load();
  assert.deepEqual(splitRules([]), [[]]);
  const out = tmp();
  try {
    const lists = loadLists(FEEDS, {allowSmall: true});
    lists.threats.names = Array.from({length: 30}, (_, i) => `bad${i}.example`);
    const summary = build({out, lists, chunk: 4, maxRulesetBytes: 600});
    assert.ok(summary.lists.threats.files > 1, JSON.stringify(summary.lists.threats));
    const chrome = path.join(out, "chrome");
    const cm = JSON.parse(fs.readFileSync(path.join(chrome, "manifest.json"), "utf8"));
    const ids = cm.declarative_net_request.rule_resources.map((r) => r.id);
    assert.equal(ids.filter((id) => /^threats(-\d+)?$/.test(id)).length, summary.lists.threats.files);
    assert.ok(ids.includes("params") && ids.includes("links") && ids.includes("gpc"));
    const names = ids.filter((id) => /^threats/.test(id)).flatMap((id) => JSON.parse(fs.readFileSync(path.join(chrome, `rules/${id}.json`), "utf8")))
      .filter((r) => r.action.type === "block").flatMap((r) => r.condition.requestDomains);
    assert.equal(new Set(names).size, 30, "every name lands in exactly one part");
    for (const r of cm.declarative_net_request.rule_resources.filter((x) => /^(threats|trackers|cname)/.test(x.id))) assert.ok(fs.statSync(path.join(chrome, r.path)).size <= 600 || JSON.parse(fs.readFileSync(path.join(chrome, r.path))).length === 1, r.path);
    const worker = fs.readFileSync(path.join(chrome, "background.js"), "utf8");
    assert.ok(worker.includes('"rules/threats-2.json"'), "the worker can read every threat part");
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("threat list merges URLhaus, Phishing Army and HaGeZi; IP literals are kept out of Chrome rules", async () => {
  const {loadLists, readSnapshot} = await load();
  const crypto = require("node:crypto");
  const dir = tmp();
  const snap = (name, entries) => {
    const body = entries.join("\n") + "\n";
    fs.writeFileSync(path.join(dir, "blocklists", name), `# ${JSON.stringify({entries: entries.length, sha256: crypto.createHash("sha256").update(body).digest("hex")})}\n${body}`);
  };
  try {
    fs.mkdirSync(path.join(dir, "blocklists"));
    for (const f of ["hagezi-pro.plus.txt", "hagezi-threat-intel.txt"]) fs.copyFileSync(path.join(FEEDS, "blocklists", f), path.join(dir, "blocklists", f));
    snap("urlhaus-filter.txt", ["192.0.2.7", "2001:db8::1", "malware-host.example"]);
    snap("phishing-army.txt", ["phish.example", "login-phish.example"]);
    snap("hagezi-threat-intel-full.txt", ["malware-fixture.test", "full-only.example"]);
    assert.throws(() => readSnapshot(path.join(dir, "blocklists/urlhaus-filter.txt")), /invalid hostname/, "IPs only where the proxy allows them");
    const notes = [];
    const lists = loadLists(dir, {allowSmall: true, log: (m) => notes.push(m)});
    assert.deepEqual([...new Set(lists.threats.names)].sort(), ["full-only.example", "login-phish.example", "malware-fixture.test", "malware-host.example", "phish.example"]);
    assert.deepEqual(lists.threats.sources.map((s) => s.id), ["urlhaus-filter", "phishing-army", "hagezi-threat-intel-full"]);
    assert.ok(notes.some((n) => /2 IP addresses not used/.test(n)));
    const medium = loadLists(dir, {allowSmall: true, threatTier: "medium"});
    assert.ok(!medium.threats.names.includes("full-only.example"));
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("build emits Chrome and Firefox from shared sources; Chrome gets rulesets, a bundled worker and a notice", async () => {
  const {build, loadLists} = await load();
  const out = tmp();
  try {
    const notes = [];
    const lists = loadLists(FEEDS, {allowSmall: true, log: (m) => notes.push(m)});
    assert.deepEqual(notes, [
      "missing urlhaus-filter.txt: threats list will not include URLhaus malware hosts (malware-filter)",
      "missing phishing-army.txt: threats list will not include Phishing Army",
      "hagezi-threat-intel-full.txt not cached; using HaGeZi Threat Intelligence (Medium)",
      "missing adguard-cname-ads.exact: cname list will not include AdGuard CNAME-cloaked ads",
    ]);
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
    assert.doesNotMatch(worker, /importScripts/);
    assert.deepEqual(worker.match(/\bfetch\s*\([^)]*\)/g), ["fetch(OWN + file)", 'fetch(OWN + "rules/build.json", {cache: "no-store"})'],
      "the worker reads only its own packaged files: the threat ruleset and the build stamp");
    const stamp = JSON.parse(fs.readFileSync(path.join(chrome, "rules/build.json"), "utf8"));
    assert.match(stamp.build, /^[0-9a-f]{32}$/);
    assert.ok(worker.includes(`"build":"${stamp.build}"`), "the worker knows which build it is");
    assert.match(worker, /\^rules\\\/threats\(-\[0-9\]\+\)\?\\\.json\$/, "and only files named like a threat ruleset");
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
