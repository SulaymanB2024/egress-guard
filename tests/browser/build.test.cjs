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
    assert.throws(() => loadLists(dir, {allowSmall: true, allowMissing: true}), /regular file/);
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
    const lists = loadLists(FEEDS, {allowSmall: true, allowMissing: true});
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
    const lists = loadLists(dir, {allowSmall: true, allowMissing: true, log: (m) => notes.push(m)});
    assert.deepEqual([...new Set(lists.threats.names)].sort(), ["full-only.example", "login-phish.example", "malware-fixture.test", "malware-host.example", "phish.example"]);
    assert.deepEqual(lists.threats.sources.map((s) => s.id), ["urlhaus-filter", "phishing-army", "hagezi-threat-intel-full"]);
    assert.ok(notes.some((n) => /2 IP addresses not used/.test(n)));
    const medium = loadLists(dir, {allowSmall: true, allowMissing: true, threatTier: "medium"});
    assert.ok(!medium.threats.names.includes("full-only.example"));
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("build emits Chrome and Firefox from shared sources; Chrome gets rulesets, a bundled worker and a notice", async () => {
  const {build, loadLists} = await load();
  const out = tmp();
  try {
    const notes = [];
    const lists = loadLists(FEEDS, {allowSmall: true, allowMissing: true, log: (m) => notes.push(m)});
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
    assert.deepEqual(worker.match(/\bfetch\s*\([^)]*\)/g), ["fetch(OWN + file)", 'fetch(OWN + "rules/build.json", {cache: "no-store"})', "fetch(WHY + encodeURIComponent(host)"],
      "the worker reads only its own packaged files (the threat ruleset and the build stamp) and asks the local guard why it refused a page");
    const stamp = JSON.parse(fs.readFileSync(path.join(chrome, "rules/build.json"), "utf8"));
    assert.match(stamp.build, /^[0-9a-f]{32}$/);
    const protocolBody = fs.readFileSync(path.join(chrome, "tracking-protocols.json"));
    const protocolCatalog = JSON.parse(protocolBody);
    assert.equal(stamp.tracking_protocols_sha256, require("node:crypto").createHash("sha256").update(protocolBody).digest("hex"));
    assert.deepEqual(stamp.tracking_protocols, protocolCatalog.stats);
    assert.ok(protocolCatalog.stats.regexRules > 0 && protocolCatalog.catalog.length > 0);
    assert.equal(protocolCatalog.compiler_sha256, require("node:crypto").createHash("sha256")
      .update(fs.readFileSync(path.join(chrome, "core/tracking-protocols.js"))).digest("hex"));
    const firstParty = JSON.parse(fs.readFileSync(path.join(chrome, "rules/fp-trackers.json"), "utf8"));
    assert.equal(new Set(firstParty.map(rule => rule.id)).size, firstParty.length, "protocol additions cannot collide with hand or imported rule IDs");
    const protocolProbe = "https://publisher.example/renamed?tid=G-ABC1234567&extra=1&v=2";
    assert.ok(firstParty.some(rule => rule.action.type === "block" && rule.priority === 6 && rule.condition.regexFilter &&
      new RegExp(rule.condition.regexFilter, rule.condition.isUrlFilterCaseSensitive ? "" : "i").test(protocolProbe)), "the published artifact contains the first-party protocol defense at the hand-filter tier");
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
    assert.equal(fs.existsSync(path.join(firefox, "tracking-protocols.json")), false, "Firefox's manual-rule adapter does not claim the Chrome protocol catalog");
    // No lists: valid empty rulesets, parameter stripping still on.
    build({out, lists: null});
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(chrome, "rules/trackers.json"), "utf8")), []);
    assert.ok(JSON.parse(fs.readFileSync(path.join(chrome, "rules/params.json"), "utf8")).length > 0);
    assert.deepEqual(fs.readdirSync(out).sort(), ["chrome", "firefox"], "staging folder cleaned up");
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});

test("URL filter lists: downloaded once a day into the build's own cache, verified, hash-recorded; tampering and wrong files refused", async () => {
  const {loadFilters, readCachedFilter, compileFilterRulesets, FILTER_LISTS, build} = await load();
  const dir = tmp();
  const body = (title) => `[Adblock Plus 2.0]\n! Version: 202611210000\n! Title: ${title}\n! Licence: https://easylist.to/pages/licence.html\n` +
    Array.from({length: 20001}, (_, i) => `||t${i}.example^`).join("\n") + "\n/g/collect?\n@@||ok.example/g/collect?\n||ads.example^\n";
  const domains = Array.from({length: 6000}, (_, i) => `c${i}.click.example`).concat(["mkt_vis.example"]).join("\n") + "\n";
  const textFor = (url) => { const spec = FILTER_LISTS.find((f) => f.url === url); return spec.kind === "domains" ? domains : spec.kind === "parameters"
    ? `! Title: ${spec.name}\n! License: ${spec.license.url}\n! Homepage: https://github.com/uBlockOrigin/uAssets\n! Last modified: %timestamp%\n` + "$removeparam=fixture_tracking\n".repeat(spec.minimum + 1) : body(spec.name); };
  const reply = (url, text) => { const result = new Response(text); Object.defineProperty(result, "url", {value: url}); return result; };
  let calls = 0;
  const fetchImpl = async (url) => { calls++; return reply(url, textFor(url)); };
  try {
    const first = await loadFilters(dir, {fetchImpl});
    assert.equal(calls, FILTER_LISTS.length);
    assert.deepEqual(Object.keys(first).sort(), FILTER_LISTS.map((f) => f.id).sort());
    const cached = readCachedFilter(dir, FILTER_LISTS.find(spec => spec.id === "easyprivacy"));
    const meta = cached.meta;
    assert.equal(meta.sha256, require("node:crypto").createHash("sha256").update(cached.body).digest("hex"));
    assert.equal(meta.version, "202611210000");
    await loadFilters(dir, {fetchImpl});
    assert.equal(calls, FILTER_LISTS.length, "a fresh cache is not downloaded again");
    await loadFilters(dir, {fetchImpl, now: Date.now() / 1000 + 2 * 86400});
    assert.equal(calls, 2 * FILTER_LISTS.length, "a day-old cache is refreshed");
    // Tampering with the cached body is refused; offline, nothing replaces it.
    fs.appendFileSync(path.join(dir, "easylist.snapshot"), "@@||evil-allow.example^\n");
    const logs = [];
    await assert.rejects(loadFilters(dir, {offline: true}), /Required filter EasyList/);
    const offline = await loadFilters(dir, {offline: true, allowMissing: true, log: (m) => logs.push(m)});
    assert.ok(!offline.easylist && logs.some((m) => /SHA-256/.test(m)));
    // A wrong file (no header, wrong title, licence line gone) is never cached.
    for (const text of ["<html>not a list</html>", body("Something"), body("EasyList").replace(/! Licence:.*\n/, "")]) {
      const bad = tmp();
      const got = await loadFilters(bad, {allowMissing: true, fetchImpl: async (url) => reply(url, url.endsWith("/easylist.txt") ? text : textFor(url)), log: () => {}});
      assert.ok(!got.easylist && !fs.existsSync(path.join(bad, "easylist.snapshot")));
      fs.rmSync(bad, {recursive: true, force: true});
    }
    // Placement: path filters on any host -> fp-trackers, exceptions -> filter-allow, host-only -> trackerDomains.
    const compiled = compileFilterRulesets(first);
    assert.ok(compiled.rulesets["fp-trackers"].some((r) => r.condition.urlFilter === "/g/collect?"));
    assert.ok(compiled.rulesets["filter-allow"].length >= 2);
    assert.ok(compiled.trackerDomains.includes("ads.example"));
    const out = tmp();
    const summary = build({out, filters: first});
    const notice = fs.readFileSync(path.join(out, "chrome/NOTICE.txt"), "utf8");
    assert.match(notice, /EasyPrivacy[\s\S]*GPL-3\.0 or CC BY-SA 3\.0[\s\S]*sha256: [0-9a-f]{64}/);
    assert.match(notice, /AdGuard disguised click-throughs[\s\S]*MIT/);
    assert.ok(summary.staticRules <= 30000 && summary.regexRules <= 1000);
    const bounce = JSON.parse(fs.readFileSync(path.join(out, "chrome/rules/bounce.json"), "utf8")).flatMap((r) => r.condition.requestDomains);
    assert.ok(bounce.includes("c1.click.example") && !bounce.includes("mkt_vis.example"), "invalid host names are left out");
    fs.rmSync(out, {recursive: true, force: true});
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("unpinned lists: a fresh copy whose size, entries or exceptions moved by more than the cap fails the build until accepted", async () => {
  const {loadFilters, readCachedFilter, FILTER_LISTS, LIST_CHANGE_FACTOR} = await load();
  const dir = tmp();
  const body = (title, exceptions) => `[Adblock Plus 2.0]\n! Version: 202611210000\n! Title: ${title}\n! Licence: https://easylist.to/pages/licence.html\n` +
    Array.from({length: 20001}, (_, i) => `||t${i}.example^`).join("\n") + "\n" + Array.from({length: exceptions}, (_, i) => `@@||ok${i}.example/x`).join("\n") + "\n";
  const domains = (n) => Array.from({length: n}, (_, i) => `c${i}.click.example`).join("\n") + "\n";
  let exceptions = 100, names = 6000;
  const textFor = (url) => { const spec = FILTER_LISTS.find((f) => f.url === url); return spec.kind === "domains" ? domains(names) : spec.kind === "parameters"
    ? `! Title: ${spec.name}\n! License: ${spec.license.url}\n! Homepage: https://github.com/uBlockOrigin/uAssets\n! Last modified: %timestamp%\n` + "$removeparam=fixture_tracking\n".repeat(spec.minimum + 1) : body(spec.name, spec.id === "easylist" ? exceptions : 100); };
  const fetchImpl = async (url) => { const result = new Response(textFor(url)); Object.defineProperty(result, "url", {value: url}); return result; };
  const day = Date.now() / 1000 + 2 * 86400;
  try {
    await loadFilters(dir, {fetchImpl});
    const spec = FILTER_LISTS.find(item => item.id === "easylist");
    const meta = readCachedFilter(dir, spec).meta;
    assert.equal(meta.exceptions, 100, "the counts are recorded beside the hash");
    assert.ok(meta.entries > 20000 && meta.bytes > 0);
    // Exceptions tripled overnight: refused, and the cached copy is kept as it was.
    exceptions = 100 * (LIST_CHANGE_FACTOR + 1);
    await assert.rejects(loadFilters(dir, {fetchImpl, now: day}), /EasyList: exceptions changed from 100 to 300.*--accept-list-change easylist/);
    assert.equal(readCachedFilter(dir, spec).meta.sha256, meta.sha256);
    // Accepted on purpose: cached, and the new counts become the reference.
    const accepted = await loadFilters(dir, {fetchImpl, now: day, acceptChange: ["easylist"]});
    assert.ok(accepted.easylist);
    assert.equal(readCachedFilter(dir, spec).meta.exceptions, 300);
    // The click-through domain list has the same cap (it feeds cookie stripping on navigations).
    names = 6000 * 3;
    await assert.rejects(loadFilters(dir, {fetchImpl, now: day + 3 * 86400}), /AdGuard disguised click-throughs: (bytes|entries) changed/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("hostile list lines: more unanchored exceptions than the cap stop the build; the bypass lines never become allow rules", async () => {
  const {compileFilterRulesets, MAX_SUSPICIOUS, build} = await load();
  const source = (id, name) => ({id, name, url: "fixture", license: {name: "fixture", url: "fixture"}, sha256: "a".repeat(64), fetched_at: 1795000000, version: "1", last_modified: "21 Nov 2026 05:15 UTC"});
  const lines = ["@@||*^$document", "@@^$document", "@@|http$document", "@@/./$document", "@@|https://$all"];
  const ok = {easylist: {text: ["/banner.png", ...lines, "@@||fine.example/banner.png"].join("\n"), source: source("easylist", "EasyList")}};
  const compiled = compileFilterRulesets(ok);
  assert.equal(compiled.stats.easylist.suspicious, lines.length);
  assert.deepEqual(compiled.rulesets["filter-allow"].map((r) => r.action.type), ["allow"]);
  assert.equal(compiled.rulesets["filter-allow"][0].priority, 2, "EasyList's own exception tier");
  const flood = {easylist: {text: Array.from({length: MAX_SUSPICIOUS + 1}, (_, i) => `@@/path${i}/x.js`).join("\n"), source: source("easylist", "EasyList")}};
  assert.throws(() => compileFilterRulesets(flood), /not anchored to a host/);
  // The popup footer and NOTICE.txt carry each list's SHA-256 and last-modified date.
  const out = tmp();
  try {
    build({out, filters: ok});
    const worker = fs.readFileSync(path.join(out, "chrome/background.js"), "utf8");
    const lists = JSON.parse(/globalThis\.EGLists = Object\.freeze\((.*)\);\n/.exec(worker)[1]).lists;
    assert.deepEqual(lists.filters.sources.map((s) => [s.name, s.sha256, s.last_modified]), [["EasyList", "a".repeat(64), "21 Nov 2026 05:15 UTC"]]);
    const notice = fs.readFileSync(path.join(out, "chrome/NOTICE.txt"), "utf8");
    assert.match(notice, /last modified: 21 Nov 2026 05:15 UTC.*sha256: a{64}/);
    assert.match(fs.readFileSync(path.join(root, "browser/popup.js"), "utf8"), /s\.sha256/);
  } finally { fs.rmSync(out, {recursive: true, force: true}); }
});
