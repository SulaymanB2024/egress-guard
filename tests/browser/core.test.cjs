"use strict";
// Decision-core tests: hosts, selector grammar, rule validation, request decisions, store and expiry.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const hosts = require("../../browser/core/hosts.js");
const sel = require("../../browser/core/selectors.js");
const rules = require("../../browser/core/rules.js");
const {decide, pathMatches, topLevelUrl} = require("../../browser/core/decide.js");
const {RuleStore} = require("../../browser/core/store.js");

const fixtureDir = path.join(__dirname, "fixtures/publisher");
const fixtureRules = JSON.parse(fs.readFileSync(path.join(fixtureDir, "rules.json"), "utf8"));
const fixtureRequests = JSON.parse(fs.readFileSync(path.join(fixtureDir, "requests.json"), "utf8"));
const NOW = Date.UTC(2026, 10, 20, 12, 0, 0);
const blockRule = (over = {}) => ({id: "r1", kind: "request", site: "publisher.example", host: "publisher.example", path: "/collect", types: ["beacon"], action: "block", ...over});
const memory = () => { let saved; return {load: async () => saved && JSON.parse(JSON.stringify(saved)), save: async (v) => { saved = v; }, peek: () => saved}; };

// ---- hosts ------------------------------------------------------------------
test("hostnames are normalized and malformed ones refused", () => {
  assert.equal(hosts.normalizeHost("Publisher.Example."), "publisher.example");
  for (const bad of ["", "localhost", "com", "127.0.0.1", "10.0.0.1", "[::1]", "a..b", "-a.example", "a-.example", "ex ample.com",
    "publisher.example:8080", "publisher.example/path", "*.publisher.example", "pub_lisher.example", "ünï.example", "a".repeat(64) + ".example", null, 42]) {
    assert.equal(hosts.normalizeHost(bad), null, String(bad));
  }
  assert.equal(hosts.normalizeHost("xn--nxasmq6b.example"), "xn--nxasmq6b.example");
});

test("conservative suffix guard and site comparison", () => {
  for (const suffix of ["co.uk", "com.au", "github.io", "com.pe", "co.th", "pages.dev"]) assert.equal(hosts.isSuffixLike(suffix), true, suffix);
  for (const site of ["publisher.example", "bbc.co.uk", "user.github.io", "example.com"]) assert.equal(hosts.isSuffixLike(site), false, site);
  assert.equal(hosts.siteOf("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(hosts.siteOf("cdn.publisher.example"), "publisher.example");
  assert.equal(hosts.siteOf("alice.github.io"), "alice.github.io");
  assert.equal(hosts.isThirdParty("cdn.publisher.example", "www.publisher.example"), false);
  assert.equal(hosts.isThirdParty("alice.github.io", "bob.github.io"), true);
  assert.equal(hosts.withinScope("www.publisher.example", "publisher.example"), true);
  assert.equal(hosts.withinScope("evilpublisher.example", "publisher.example"), false);
  assert.equal(hosts.withinScope("publisher.example.evil.test", "publisher.example"), false);
});

// ---- selectors --------------------------------------------------------------
test("specific selectors parse", () => {
  for (const ok of ["article.card.teaser[data-ad-slot]", "#sidebar-ad", ".promo", 'div[data-testid="ad-unit"]', "#feed > article:nth-of-type(2)",
    "section.feed article.card:not(.organic)", ".a, .b", "li.item:first-child", 'aside[aria-label^="Advert"]']) {
    assert.equal(sel.validateSelector(ok).ok, true, ok);
  }
});

test("broad, structural and script-like selectors are rejected", () => {
  for (const bad of ["*", "body", "html", "div", "main", "article", "div span", "*.ad", "body > div", "html .x > body", ":root", "head .x",
    "div:has(.ad)", ".ad::before", "a[href]", "[class]", "[id]", ".x, div", ".a,.b,.c,.d,.e", ".x {display:block}", ".x; color:red",
    "@import 'x'", ".x\\61", "<script>", "javascript:alert(1)", '[data-x="javascript:alert(1)"]', '[onclick="x"]', "[onload]", '[style*="x"]',
    ".x /* c */", "url(x)", ".x:hover", "iframe.ad", "script.ad", "", " ", "a".repeat(301), "a b c d e f g.x", ".x >", ".x ,", "[data-x='y']",
    "a.b c.d e.f g.h i.j k.l m.n", "#", ".", "[data-x", '[data-x="y]', ":not(.a .b)", ".x:not()", ".x:nth-child(foo)", null, 3]) {
    assert.equal(sel.validateSelector(bad).ok, false, String(bad));
  }
});

// ---- rule validation --------------------------------------------------------
test("fixture rules validate", () => {
  for (const rule of fixtureRules.rules) assert.equal(rules.tryRule(rule).ok, true, rule.id);
});

test("request rules: exact host, bounded path, allowed types and required site", () => {
  const ok = rules.validateRule(blockRule({types: ["beacon", "ping", "beacon"]}));
  assert.deepEqual([...ok.types], ["beacon", "ping"]);
  assert.equal(ok.party, "any");
  assert.equal(Object.isFrozen(ok), true);
  const bad = {
    noSite: {site: undefined}, suffixSite: {site: "co.uk"}, tldSite: {site: "com"}, githubSite: {site: "github.io"}, ipSite: {site: "127.0.0.1"},
    wildHost: {host: "*.publisher.example"}, ipHost: {host: "10.0.0.1"}, portHost: {host: "publisher.example:443"}, urlHost: {host: "https://publisher.example"},
    barePath: {path: "/"}, starPath: {path: "*"}, slashStar: {path: "/*"}, starsOnly: {path: "/*/*"}, onechar: {path: "/a*"}, noSlash: {path: "collect"},
    query: {path: "/collect?x=1"}, regex: {path: "/coll(ect|ector)$"}, regex2: {path: "/collect.+"}, space: {path: "/col lect"}, dots: {path: "/a/../collect"},
    stars: {path: "/a*b*c*d*e"}, doubleStar: {path: "/col**lect"}, longPath: {path: "/" + "a".repeat(300)}, hash: {path: "/collect#x"},
    mainFrame: {types: ["main_frame"]}, unknownType: {types: ["dns"]}, noTypes: {types: []}, typeString: {types: "beacon"},
    action: {action: "redirect"}, party: {party: "both"}, extra: {regex: ".*"}, script: {note: "<script>alert(1)</script>"},
    expired: {expiresAt: NOW - 1}, badExpiry: {expiresAt: "tomorrow"}, id: {id: "R 1"}, kind: {kind: "dnr"},
  };
  for (const [name, over] of Object.entries(bad)) assert.equal(rules.tryRule(blockRule(over), {now: NOW}).ok, false, name);
  assert.equal(rules.tryRule(Object.assign(Object.create({kind: "request"}), blockRule())).ok, false, "prototype objects refused");
  assert.equal(rules.tryRule([blockRule()]).ok, false);
  assert.equal(rules.tryRule(JSON.parse('{"__proto__": {"x": 1}, "id": "a", "kind": "request"}')).ok, false);
});

test("cosmetic rules require a site and a specific selector; unknown fields refused", () => {
  const base = {id: "c1", kind: "cosmetic", site: "publisher.example", selector: ".promo"};
  assert.equal(rules.tryRule(base).ok, true);
  for (const over of [{selector: "body"}, {selector: "*"}, {selector: "div"}, {site: "example"}, {site: undefined}, {host: "publisher.example"}, {selector: ".x{}"}, {selector: "<img src=x onerror=alert(1)>"}]) {
    assert.equal(rules.tryRule({...base, ...over}).ok, false, JSON.stringify(over));
  }
});

test("exceptions: exact path, one type, must expire within 24 hours", () => {
  const exc = {id: "e1", site: "publisher.example", host: "publisher.example", path: "/collect", type: "beacon", expiresAt: NOW + 60000};
  assert.equal(rules.tryException(exc, {now: NOW}).ok, true);
  for (const over of [{path: "/col*"}, {type: "main_frame"}, {expiresAt: undefined}, {expiresAt: NOW - 1}, {expiresAt: NOW + 25 * 3600000}, {site: "co.uk"}, {types: ["beacon"]}]) {
    assert.equal(rules.tryException({...exc, ...over}, {now: NOW}).ok, false, JSON.stringify(over));
  }
});

// ---- path matching and top-level resolution ----------------------------------
test("path globs match path only, without regex semantics", () => {
  assert.equal(pathMatches("/collect", "/collect"), true);
  assert.equal(pathMatches("/collect", "/collect/"), false);
  assert.equal(pathMatches("/collect", "/collection"), false);
  assert.equal(pathMatches("/api/*/track", "/api/v2/track"), true);
  assert.equal(pathMatches("/api/*/track", "/api/v2/other"), false);
  assert.equal(pathMatches("/c.llect", "/collect"), false);
  assert.equal(pathMatches("/px*", "/px.gif"), true);
  assert.equal(pathMatches("/a*b*c", "/" + "a".repeat(5000) + "x"), false);
});

test("top-level site comes from trusted request fields in priority order", () => {
  assert.equal(topLevelUrl({type: "main_frame", url: "https://a.example/"}), "https://a.example/");
  assert.equal(topLevelUrl({type: "beacon", frameId: 5, documentUrl: "https://frame.example/", frameAncestors: [{url: "https://mid.example/"}, {url: "https://top.example/"}]}), "https://top.example/");
  assert.equal(topLevelUrl({type: "beacon", frameId: 0, documentUrl: "https://top.example/a", frameAncestors: []}), "https://top.example/a");
  assert.equal(topLevelUrl({type: "beacon", frameId: 5, documentUrl: "https://frame.example/"}, "https://tab.example/"), "https://tab.example/");
  assert.equal(topLevelUrl({type: "beacon", frameId: 5, documentUrl: "https://frame.example/"}), null);
});

// ---- acceptance: publisher fixture decisions ---------------------------------
test("acceptance: collector is blocked while article, login and video requests are allowed", () => {
  const ruleSet = fixtureRules.rules.map((r) => rules.validateRule(r));
  for (const item of fixtureRequests.requests) {
    const result = decide({url: item.url, type: item.type, topUrl: topLevelUrl(item)}, ruleSet, [], NOW);
    assert.equal(result.action, item.expect, `${item.name}: ${result.reason}`);
  }
});

test("decision order: unknown top-level and navigation allow; allow rules beat block rules; party filters", () => {
  const block = rules.validateRule(blockRule({types: ["beacon", "xmlhttprequest"]}));
  const req = {url: "https://publisher.example/collect", type: "beacon", topUrl: "https://publisher.example/"};
  assert.equal(decide(req, [block], [], NOW).action, "block");
  assert.equal(decide({...req, topUrl: null}, [block], [], NOW).reason, "no-top-level-site");
  assert.equal(decide({...req, type: "main_frame"}, [block], [], NOW).action, "allow");
  assert.equal(decide({...req, url: "data:text/plain,x"}, [block], [], NOW).reason, "out-of-scope");
  assert.equal(decide({...req, url: "https://PUBLISHER.example./collect"}, [block], [], NOW).action, "block");
  assert.equal(decide({...req, topUrl: "https://www.publisher.example/a"}, [block], [], NOW).action, "block", "subdomain top-level is in scope");
  assert.equal(decide({...req, url: "https://cdn.publisher.example/collect"}, [block], [], NOW).action, "allow", "exact host only");
  const allow = rules.validateRule(blockRule({id: "a1", action: "allow"}));
  assert.equal(decide(req, [block, allow], [], NOW).reason, "allow-rule");
  const third = rules.validateRule(blockRule({id: "t1", site: "news.example", host: "tracker.example", path: "/px*", types: ["image"], party: "third"}));
  assert.equal(decide({url: "https://tracker.example/px.gif", type: "image", topUrl: "https://news.example/"}, [third], [], NOW).action, "block");
  const first = rules.validateRule({...blockRule(), id: "f1", party: "first"});
  assert.equal(decide({...req, topUrl: "https://publisher.example/"}, [first], [], NOW).action, "block");
  const expired = {...block, expiresAt: NOW - 1};
  assert.equal(decide(req, [expired], [], NOW).action, "allow", "expired rule ignored even before pruning");
});

// ---- store, exceptions, expiry ------------------------------------------------
test("acceptance: an exception permits exactly one endpoint, then expires", async () => {
  let clock = NOW;
  const persist = memory();
  const store = new RuleStore({persist, now: () => clock});
  await store.addRule(blockRule({types: ["beacon", "xmlhttprequest"]}));
  await store.addRule(blockRule({id: "r2", path: "/metrics"}));
  const exc = await store.addException({site: "publisher.example", host: "publisher.example", path: "/collect", type: "beacon", minutes: 10});
  const run = (url, type = "beacon", topUrl = "https://publisher.example/article") => {
    const {requestRules, exceptions} = store.activeFor("publisher.example");
    return decide({url, type, topUrl}, requestRules, exceptions, clock);
  };
  assert.equal(run("https://publisher.example/collect").reason, "exception");
  assert.equal(run("https://publisher.example/collect", "xmlhttprequest").action, "block", "other type still blocked");
  assert.equal(run("https://publisher.example/metrics").action, "block", "other path still blocked");
  assert.equal(run("https://publisher.example/collect", "beacon", "https://other.example/").action, "allow");
  assert.equal(decide({url: "https://publisher.example/collect", type: "beacon", topUrl: "https://other.example/"}, store.rules, store.exceptions, clock).reason, "no-rule", "exception and rules stay site-scoped");
  assert.equal(store.nextExpiry(), exc.expiresAt);
  clock = exc.expiresAt; // expiry instant: no longer live even before prune
  assert.equal(run("https://publisher.example/collect").action, "block");
  assert.equal(await store.prune(), true);
  assert.equal(store.exceptions.length, 0);
  assert.equal(persist.peek().exceptions.length, 0, "removal persisted");
});

test("exceptions can be removed by hand and replace an identical earlier one", async () => {
  const store = new RuleStore({now: () => NOW});
  const a = await store.addException({site: "publisher.example", host: "publisher.example", path: "/collect", type: "beacon", minutes: 5});
  const b = await store.addException({site: "publisher.example", host: "publisher.example", path: "/collect", type: "beacon", minutes: 30});
  assert.equal(store.exceptions.length, 1);
  assert.equal(store.exceptions[0].id, b.id);
  assert.notEqual(a.id, b.id);
  assert.equal(await store.removeException(b.id), true);
  assert.equal(store.exceptions.length, 0);
  for (const minutes of [0, -1, 1.5, 1441, "10", undefined]) {
    await assert.rejects(store.addException({site: "publisher.example", host: "publisher.example", path: "/collect", type: "beacon", minutes}));
  }
  await assert.rejects(store.addException({site: "publisher.example", host: "publisher.example", path: "/col*", type: "beacon", minutes: 5}));
});

test("store persists, reloads only valid unexpired entries, refuses duplicates and expires rules", async () => {
  let clock = NOW;
  const persist = memory();
  const store = new RuleStore({persist, now: () => clock});
  const temp = await store.addRule({kind: "cosmetic", site: "publisher.example", selector: ".promo", expiresAt: NOW + 1000});
  assert.match(temp.id, /^hide-[0-9a-f]{12}$/);
  await assert.rejects(store.addRule({kind: "cosmetic", site: "publisher.example", selector: ".promo"}), /identical/);
  await assert.rejects(store.addRule({kind: "cosmetic", site: "publisher.example", selector: "body"}));
  const raw = persist.peek();
  raw.rules.push({id: "evil", kind: "cosmetic", site: "com", selector: "*"}, {id: "x", kind: "request", site: "a.example", host: "a.example", path: "/", types: ["beacon"], action: "block"});
  raw.exceptions.push({id: "old", site: "publisher.example", host: "publisher.example", path: "/collect", type: "beacon", expiresAt: NOW - 1});
  const again = await new RuleStore({persist: {load: async () => raw, save: async () => {}}, now: () => clock}).load();
  assert.equal(again.rules.length, 1);
  assert.equal(again.exceptions.length, 0);
  assert.equal(again.rejected.length, 3);
  assert.equal((await new RuleStore({persist: {load: async () => ({schema: 99, rules: [blockRule()]}), save: async () => {}}}).load()).rules.length, 0, "unknown schema ignored");
  assert.equal(store.activeFor("www.publisher.example").cosmeticRules.length, 1);
  assert.equal(store.activeFor("evil.example").cosmeticRules.length, 0);
  clock = NOW + 1000;
  assert.equal(store.activeFor("publisher.example").cosmeticRules.length, 0);
  assert.equal(await store.prune(), true);
  assert.equal(store.rules.length, 0);
});

test("acceptance: hostile rule inputs are rejected", async () => {
  const store = new RuleStore({now: () => NOW});
  const hostile = [
    {kind: "cosmetic", site: "publisher.example", selector: "*"},
    {kind: "cosmetic", site: "publisher.example", selector: "body"},
    {kind: "cosmetic", site: "publisher.example", selector: "html"},
    {kind: "cosmetic", site: "publisher.example", selector: "div"},
    {kind: "cosmetic", site: "co.uk", selector: ".ad"},
    {kind: "cosmetic", site: "publisher.example", selector: "</style><script>alert(1)</script>"},
    {kind: "cosmetic", site: "publisher.example", selector: ".ad", script: "alert(1)"},
    {kind: "request", site: "publisher.example", host: "publisher.example", path: "/", types: ["beacon"], action: "block"},
    {kind: "request", site: "publisher.example", host: "publisher.example", path: "*", types: ["beacon"], action: "block"},
    {kind: "request", site: "publisher.example", host: "publisher.example", path: "/(.*)", types: ["beacon"], action: "block"},
    {kind: "request", site: "publisher.example", host: "*.example", path: "/collect", types: ["beacon"], action: "block"},
    {kind: "request", site: "publisher.example", host: "pub lisher.example", path: "/collect", types: ["beacon"], action: "block"},
    {kind: "request", host: "publisher.example", path: "/collect", types: ["beacon"], action: "block"},
    {kind: "request", site: "publisher.example", host: "publisher.example", path: "/collect", types: ["main_frame"], action: "block"},
    {kind: "request", site: "publisher.example", host: "publisher.example", path: "/collect", types: ["beacon"], action: "redirect", redirect: "https://evil.example/"},
    "javascript:alert(1)", null, [], 7,
  ];
  for (const input of hostile) await assert.rejects(store.addRule(input), rules.RuleError, JSON.stringify(input));
  assert.equal(store.rules.length, 0);
});
