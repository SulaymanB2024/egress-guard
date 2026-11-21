"use strict";
// Chrome DNR compiler: list rulesets, priority ladder, exceptions, parameter stripping.
const test = require("node:test");
const assert = require("node:assert/strict");
const dnr = require("../../browser/core/dnr.js");
const rules = require("../../browser/core/rules.js");
const {pathMatches} = require("../../browser/core/decide.js");

const WARN = "chrome-extension://danbhmcinakkkkbobacafgidgkfibfmg/warning.html";
const NOW = Date.UTC(2026, 10, 20, 12);

/** Minimal model of Chrome's documented matching for the rule shapes we emit (enough to check intent). */
function matches(rule, req) {
  const c = rule.condition;
  const url = new URL(req.url);
  const host = url.hostname;
  const covers = (list, name) => list.some((d) => name === d || name.endsWith(`.${d}`));
  if (c.resourceTypes && !c.resourceTypes.includes(req.type)) return false;
  if (c.requestDomains && !covers(c.requestDomains, host)) return false;
  if (c.initiatorDomains && !(req.initiator && covers(c.initiatorDomains, req.initiator))) return false;
  if (c.tabIds && !c.tabIds.includes(req.tabId)) return false;
  if (c.regexFilter && !new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive ? "" : "i").test(req.url)) return false;
  return true;
}
/** Highest priority wins; at equal priority allow/allowAllRequests > block > redirect (same extension). */
function outcome(all, req) {
  const rank = {allow: 3, allowAllRequests: 3, block: 2, redirect: 1};
  const hit = all.filter((r) => matches(r, req)).sort((a, b) => b.priority - a.priority || rank[b.action.type] - rank[a.action.type]);
  return hit.length ? hit[0].action.type : "none";
}

test("priority ladder: exceptions > user rules > lists > continue-once > threats > params", () => {
  const p = dnr.PRIORITY;
  assert.ok(p.exception > p.userAllow && p.userAllow > p.userBlock && p.userBlock > p.list && p.list > p.continue && p.continue > p.threat && p.threat > p.params);
});

test("list compiler chunks requestDomains, minimizes subdomains and never blocks navigation for ads/trackers", () => {
  const names = ["b.example", "x.b.example", "a.example", ...Array.from({length: 5}, (_, i) => `t${i}.example`)];
  const {rules: out, domains} = dnr.compileList("trackers", names, {chunk: 3});
  assert.equal(domains, 7, "x.b.example is covered by b.example");
  assert.equal(out.length, 3);
  assert.deepEqual(out.map((r) => r.id), [1, 2, 3]);
  for (const r of out) {
    assert.equal(r.action.type, "block");
    assert.equal(r.priority, dnr.PRIORITY.list);
    assert.ok(!r.condition.resourceTypes.includes("main_frame"));
    assert.ok(r.condition.requestDomains.length <= 3);
  }
  assert.deepEqual(dnr.compileList("trackers", []).rules, [], "empty list -> empty ruleset");
  assert.throws(() => dnr.compileList("bogus", names));
});

test("threat lists block every subresource and redirect navigations to the local warning page", () => {
  assert.throws(() => dnr.compileList("threats", ["bad.example"]), /warning page/);
  assert.throws(() => dnr.compileList("threats", ["bad.example"], {warningUrl: "https://evil.example/warning.html"}), /warning page/);
  const {rules: out} = dnr.compileList("threats", ["bad.example"], {warningUrl: WARN});
  assert.equal(out.length, 2);
  const nav = out.find((r) => r.action.type === "redirect");
  assert.deepEqual(nav.condition.resourceTypes, ["main_frame"]);
  assert.equal(nav.action.redirect.regexSubstitution, `${WARN}?list=threats#\\0`);
  const url = "https://login.bad.example/a?b=1";
  const redirected = url.replace(new RegExp(nav.condition.regexFilter), (m) => nav.action.redirect.regexSubstitution.replace("\\0", () => m));
  assert.deepEqual(dnr.parseWarning(redirected), {list: "threats", url, host: "login.bad.example"});
  assert.equal(outcome(out, {url: "https://cdn.bad.example/x.js", type: "script", initiator: "news.example"}), "block");
});

test("parseWarning refuses anything but an http(s) target", () => {
  for (const bad of [`${WARN}`, `${WARN}#javascript:alert(1)`, `${WARN}#data:text/html,hi`, `${WARN}#chrome://settings`, `${WARN}#https://127.0.0.1/`, "nope"]) {
    assert.equal(dnr.parseWarning(bad), null, bad);
  }
  assert.equal(dnr.parseWarning(`${WARN}?list=evil#https://bad.example/`).list, "threats", "unknown list names are not echoed");
});

test("endpoint regex matches exactly like the core glob: exact host, path only, any port, any query", () => {
  const cases = [
    ["publisher.example", "/collect", "https://publisher.example/collect", true],
    ["publisher.example", "/collect", "http://publisher.example:8080/collect?x=1#y", true],
    ["publisher.example", "/collect", "https://publisher.example/collect/more", false],
    ["publisher.example", "/collect", "https://www.publisher.example/collect", false],
    ["publisher.example", "/collect", "https://publisher.example.evil.test/collect", false],
    ["publisher.example", "/collect", "https://evil.test/?u=https://publisher.example/collect", false],
    ["publisher.example", "/api/*/track", "https://publisher.example/api/v2/x/track", true],
    ["publisher.example", "/api/*/track", "https://publisher.example/api/v2/track?/api/a/track", true],
    ["a.example", "/p.v1(x)", "https://a.example/p.v1(x)", true],
    ["a.example", "/p.v1(x)", "https://a.example/pXv1(x)", false],
  ];
  for (const [host, path, url, expected] of cases) {
    assert.equal(new RegExp(dnr.endpointRegex(host, path)).test(url), expected, `${host}${path} vs ${url}`);
    const u = new URL(url);
    if (u.hostname === host) assert.equal(pathMatches(path, u.pathname), expected, `core agrees for ${url}`);
  }
});

function userRule(overrides) {
  return rules.validateRule({id: "r1", kind: "request", site: "publisher.example", host: "publisher.example", path: "/collect", types: ["beacon", "xmlhttprequest"], action: "block", ...overrides});
}
function exception(overrides) {
  return rules.validateException({id: "e1", site: "publisher.example", host: "pixel.tracker.test", path: "/p.gif", type: "image", expiresAt: NOW + 60000, ...overrides});
}

test("user rules compile to scoped, case-sensitive dynamic rules with mapped types", () => {
  const {rules: out, sources} = dnr.compileUserState([userRule(), userRule({id: "r2", action: "allow", path: "/ok", party: "third"}),
    rules.validateRule({id: "h1", kind: "cosmetic", site: "publisher.example", selector: "div.ad"})], [], NOW);
  assert.equal(out.length, 2, "cosmetic rules are not network rules");
  const [block, allow] = out;
  assert.equal(block.action.type, "block");
  assert.equal(block.priority, dnr.PRIORITY.userBlock);
  assert.deepEqual(block.condition.resourceTypes, ["ping", "xmlhttprequest"], "beacon maps to Chrome's ping");
  assert.deepEqual(block.condition.initiatorDomains, ["publisher.example"]);
  assert.equal(block.condition.isUrlFilterCaseSensitive, true);
  assert.equal(allow.action.type, "allow");
  assert.equal(allow.priority, dnr.PRIORITY.userAllow);
  assert.equal(allow.condition.domainType, "thirdParty");
  assert.deepEqual(sources, {1: "r1", 2: "r2"});
  assert.equal(dnr.compileUserState([userRule({expiresAt: NOW - 1})], [], NOW).rules.length, 0, "expired rules dropped");
  assert.equal(dnr.compileUserState([], [exception({expiresAt: NOW})], NOW).rules.length, 0, "expired exceptions dropped");
});

test("acceptance: an exception beats the tracker list and threat list, only for its endpoint, site and type", () => {
  const lists = dnr.compileList("trackers", ["tracker.test"]).rules.map((r) => ({...r, id: 1000 + r.id}));
  const threats = dnr.compileList("threats", ["bad.example"], {warningUrl: WARN}).rules.map((r) => ({...r, id: 2000 + r.id}));
  const {rules: user} = dnr.compileUserState([userRule()], [exception(), exception({id: "e2", host: "cdn.bad.example", path: "/lib.js", type: "script"})], NOW);
  const all = [...lists, ...threats, ...user];
  const req = (url, type = "image", initiator = "publisher.example") => ({url, type, initiator, tabId: 1});
  assert.equal(outcome(all, req("https://pixel.tracker.test/p.gif")), "allow");
  assert.equal(outcome(all, req("https://pixel.tracker.test/p.gif", "script")), "block", "other type");
  assert.equal(outcome(all, req("https://pixel.tracker.test/q.gif")), "block", "other path");
  assert.equal(outcome(all, req("https://pixel.tracker.test/p.gif", "image", "other.example")), "block", "other site");
  assert.equal(outcome(all, req("https://cdn.bad.example/lib.js", "script")), "allow", "threat subresource exception");
  assert.equal(outcome(all, req("https://publisher.example/collect", "ping")), "block", "user rule");
  assert.equal(outcome(all, req("https://publisher.example/article", "main_frame", null)), "none");
});

test("continue-once allows the flagged site in one tab but not its trackers", () => {
  const threats = dnr.compileList("threats", ["bad.example"], {warningUrl: WARN}).rules;
  const trackers = dnr.compileList("trackers", ["tracker.test"]).rules.map((r) => ({...r, id: 100 + r.id}));
  const cont = dnr.continueRule(100000, "bad.example", 7);
  assert.equal(cont.priority, dnr.PRIORITY.continue);
  assert.equal(cont.action.type, "allowAllRequests");
  const all = [...threats, ...trackers, cont];
  assert.equal(outcome(all, {url: "https://bad.example/", type: "main_frame", tabId: 7}), "allowAllRequests");
  assert.equal(outcome(all, {url: "https://bad.example/", type: "main_frame", tabId: 8}), "redirect", "other tabs still warned");
  // allowAllRequests at priority 3 lifts lower-priority rules for that frame (threat=2) but not trackers (4).
  assert.ok(dnr.PRIORITY.threat < cont.priority && dnr.PRIORITY.list > cont.priority);
  assert.throws(() => dnr.continueRule(1, "127.0.0.1", 7));
  assert.throws(() => dnr.continueRule(1, "bad.example", -1));
});

test("tracking parameter stripping: exact names, navigations only, only when one is present", () => {
  const out = dnr.compileParams();
  assert.equal(out.length, dnr.TRACKING_PARAMS.length * 2);
  assert.equal(new Set(out.map((r) => r.id)).size, out.length);
  const removed = out[0].action.redirect.transform.queryTransform.removeParams;
  for (const rule of out) {
    assert.equal(rule.priority, dnr.PRIORITY.params);
    assert.deepEqual(rule.condition.resourceTypes, ["main_frame", "sub_frame"]);
    assert.equal(rule.condition.regexFilter, undefined, "no regex: Chrome caps compiled regex size");
    assert.deepEqual(rule.action.redirect.transform.queryTransform.removeParams, removed);
  }
  for (const name of ["utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid", "msclkid", "dclid", "gbraid", "wbraid", "mc_eid", "igshid"]) assert.ok(removed.includes(name), name);
  for (const name of ["id", "q", "page", "ref", "v", "t"]) assert.ok(!removed.includes(name), `${name} is functional and kept`);
  // urlFilter without wildcards or anchors is a plain substring test.
  const triggers = (url) => out.some((r) => url.includes(r.condition.urlFilter));
  assert.ok(triggers("https://news.example/a?id=1&utm_source=x"));
  assert.ok(triggers("https://news.example/a?fbclid=abc"));
  assert.ok(!triggers("https://news.example/a?id=1"));
  assert.ok(!triggers("https://news.example/a?xutm_source=1"));
  // Applying the transform (as Chrome does) keeps functional parameters in order.
  const url = new URL("https://news.example/a?utm_source=x&id=7&fbclid=b&gclid=c");
  for (const name of removed) url.searchParams.delete(name);
  assert.equal(url.href, "https://news.example/a?id=7");
});

test("extension id derivation matches Chrome's documented a-p mapping", () => {
  assert.equal(dnr.extensionIdFromHex("0123456789abcdef0123456789abcdef00"), "abcdefghijklmnopabcdefghijklmnop");
});
