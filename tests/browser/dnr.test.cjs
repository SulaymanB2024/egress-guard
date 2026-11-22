"use strict";
// Chrome DNR compiler: list rulesets, priority ladder, exceptions, parameter stripping.
const test = require("node:test");
const assert = require("node:assert/strict");
const dnr = require("../../browser/core/dnr.js");
const rules = require("../../browser/core/rules.js");
const hosts = require("../../browser/core/hosts.js");
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
  if (c.requestMethods && !c.requestMethods.includes(req.method || "get")) return false;
  if (c.requestDomains && !covers(c.requestDomains, host)) return false;
  if (c.excludedRequestDomains && covers(c.excludedRequestDomains, host)) return false;
  const top = req.top || req.initiator; // Chrome fallback when no associated top frame exists.
  if (c.topDomains && !(top && covers(c.topDomains, top))) return false;
  if (c.excludedTopDomains && top && covers(c.excludedTopDomains, top)) return false;
  if (c.domainType === "thirdParty" && req.initiator && !hosts.isThirdParty(host, req.initiator)) return false;
  if (c.domainType === "firstParty" && (!req.initiator || hosts.isThirdParty(host, req.initiator))) return false;
  if (c.initiatorDomains && !(req.initiator && covers(c.initiatorDomains, req.initiator))) return false;
  if (c.tabIds && !c.tabIds.includes(req.tabId)) return false;
  if (c.regexFilter && !new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive ? "" : "i").test(req.url)) return false;
  return true;
}
/**
 * Highest priority wins; at equal priority allow/allowAllRequests > block > redirect (same extension).
 * Frame-tree inheritance: when `req.frame` (the navigation request that created the requesting frame) is
 * matched by an allowAllRequests rule of priority P, every request from that frame is allowed unless a rule
 * with priority above P matches it. This is how Chrome documents allowAllRequests.
 */
const RANK = {allow: 3, allowAllRequests: 3, block: 2, redirect: 1};
function best(all, req) {
  return all.filter((r) => r.action.type !== "modifyHeaders" && matches(r, req)).sort((a, b) => b.priority - a.priority || RANK[b.action.type] - RANK[a.action.type])[0] || null;
}
function outcome(all, req) {
  const hit = best(all, req);
  if (req.frame) {
    const frameRule = best(all, req.frame);
    if (frameRule && frameRule.action.type === "allowAllRequests" && (!hit || hit.priority <= frameRule.priority)) return "allow";
  }
  return hit ? hit.action.type : "none";
}

test("priority ladder preserves threat/manual denies and independent credential consent", () => {
  const p = dnr.PRIORITY;
  assert.ok(p.userBlock > p.continueHeaders && p.continueHeaders > p.continue && p.continue > p.threat && p.threat > p.grantHeaders && p.grantHeaders > p.exception && p.exception > p.userAllow && p.userAllow > p.list);
  assert.ok(p.gpc > p.exception, "no allow rule can switch Sec-GPC off");
  assert.ok(p.surrogate > p.list && p.surrogate < p.userBlock, "a stub beats the list block, your own block beats the stub");
  assert.ok(p.relax > p.embedCookies && p.embedCookies > p.scannerPass && p.scannerPass > p.scanner && p.scanner > p.clean && p.modeHeaders > p.userBlock,
    "Relaxed lifts cleaning; a scanner pass lifts only the scanner redirect and cleaning");
  assert.ok(p.clean > p.embed && p.embed > p.mode && p.mode > p.hand, "a loaded embed lifts Strict's blocks, not its cookie stripping");
  assert.ok(p.threat > p.isolation && p.isolation > p.grantHeaders && p.isolationHeaders > p.continueHeaders && p.gpc > p.isolationHeaders,
    "Isolation cannot be repaired below threats; navigation consent never restores credentials");
  assert.ok(p.clean > p.params && p.params > p.mode, "parameter preservation stays below sanitation and has no frame scope");
  assert.ok(p.hand > p.filterImportant && p.filterImportant > p.easyprivacyAllow && p.easyprivacyAllow > p.easyprivacy && p.easyprivacy > p.easylistAllow && p.easylistAllow > p.easylist,
    "each list's exceptions sit directly above its own blocks; hand-written filters and every cleaning rule sit above all list exceptions");
  assert.deepEqual(dnr.FILTER_PRIORITY.easylist, {block: p.easylist, allow: p.easylistAllow});
  assert.deepEqual(dnr.FILTER_PRIORITY.easyprivacy, {block: p.easyprivacy, allow: p.easyprivacyAllow});
  assert.equal(new Set(Object.values(p)).size, Object.keys(p).length, "one tier per priority");
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
  const {rules: out, sources} = dnr.compileUserState([userRule(), userRule({id: "r2", action: "allow", host: "tracker.example", path: "/ok", party: "third"}),
    rules.validateRule({id: "h1", kind: "cosmetic", site: "publisher.example", selector: "div.ad"})], [], NOW);
  assert.equal(out.length, 3, "cosmetic rules are not network rules; allows include a sanitation pair");
  const [block, allow] = out;
  assert.equal(block.action.type, "block");
  assert.equal(block.priority, dnr.PRIORITY.userBlock);
  assert.deepEqual(block.condition.resourceTypes, ["ping", "xmlhttprequest"], "beacon maps to Chrome's ping");
  assert.deepEqual(block.condition.topDomains, ["publisher.example"]);
  assert.equal(block.condition.isUrlFilterCaseSensitive, true);
  assert.equal(allow.action.type, "allow");
  assert.equal(allow.priority, dnr.PRIORITY.userAllow);
  assert.equal(allow.condition.domainType, undefined, "party comparison is against the known top site, not the nested initiator");
  assert.deepEqual(sources, {1: "r1", 2: "r2", 3: "r2"});
  assert.equal(dnr.compileUserState([userRule({expiresAt: NOW - 1})], [], NOW).rules.length, 0, "expired rules dropped");
  assert.equal(dnr.compileUserState([], [exception({expiresAt: NOW})], NOW).rules.length, 0, "expired exceptions dropped");
});

test("acceptance: an exception lifts tracker lists for its endpoint/site/type but cannot override a threat", () => {
  const lists = dnr.compileList("trackers", ["tracker.test"]).rules.map((r) => ({...r, id: 1000 + r.id}));
  const threats = dnr.compileList("threats", ["bad.example"], {warningUrl: WARN}).rules.map((r) => ({...r, id: 2000 + r.id}));
  const {rules: user} = dnr.compileUserState([userRule()], [exception(), exception({id: "e2", host: "cdn.bad.example", path: "/lib.js", type: "script"})], NOW);
  const all = [...lists, ...threats, ...user];
  const req = (url, type = "image", initiator = "publisher.example") => ({url, type, initiator, tabId: 1});
  assert.equal(outcome(all, req("https://pixel.tracker.test/p.gif")), "allow");
  assert.equal(outcome(all, req("https://pixel.tracker.test/p.gif", "script")), "block", "other type");
  assert.equal(outcome(all, req("https://pixel.tracker.test/q.gif")), "block", "other path");
  assert.equal(outcome(all, req("https://pixel.tracker.test/p.gif", "image", "other.example")), "block", "other site");
  assert.equal(outcome(all, req("https://cdn.bad.example/lib.js", "script")), "block", "threats always outrank ordinary exceptions");
  assert.equal(outcome(all, req("https://publisher.example/collect", "ping")), "block", "user rule");
  assert.equal(outcome(all, req("https://publisher.example/article", "main_frame", null)), "none");
});

test("frame-tree model: allowAllRequests lifts lower-priority rules for every request of the frame", () => {
  const threats = dnr.compileList("threats", ["bad.example", "other-bad.example"], {warningUrl: WARN}).rules;
  const wide = {id: 9, priority: dnr.PRIORITY.continue, action: {type: "allowAllRequests"}, condition: {requestDomains: ["bad.example"], resourceTypes: ["main_frame"], tabIds: [7]}};
  const frame = {url: "https://bad.example/", type: "main_frame", tabId: 7};
  assert.equal(outcome([...threats, wide], {url: "https://other-bad.example/x.js", type: "script", initiator: "bad.example", tabId: 7, frame}), "allow",
    "the model reproduces why allowAllRequests is too wide");
});

test("continue-once allows the flagged site in one tab, not its trackers, not other threat hosts", () => {
  const threats = dnr.compileList("threats", ["bad.example", "other-bad.example"], {warningUrl: WARN}).rules;
  const trackers = dnr.compileList("trackers", ["tracker.test"]).rules.map((r) => ({...r, id: 100 + r.id}));
  const cont = dnr.continueRules(100000, "bad.example", 7);
  assert.deepEqual(cont.map((r) => r.id), [100000, 100001]);
  for (const rule of cont) {
    assert.ok(["allow", "modifyHeaders"].includes(rule.action.type), "navigation allow plus sanitation, never allowAllRequests");
    assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]);
    assert.deepEqual(rule.condition.tabIds, [7]);
  }
  const all = [...threats, ...trackers, ...cont];
  const frame = {url: "https://bad.example/", type: "main_frame", tabId: 7};
  assert.equal(outcome(all, frame), "allow");
  assert.equal(outcome(all, {...frame, tabId: 8}), "redirect", "other tabs still warned");
  assert.equal(outcome(all, {url: "https://bad.example/app.js", type: "script", initiator: "bad.example", tabId: 7, frame}), "block", "own resources keep their threat block");
  assert.equal(outcome(all, {url: "https://cdn.bad.example/app.js", type: "script", initiator: "bad.example", tabId: 7, frame}), "block", "subdomain resources keep their threat block");
  assert.equal(outcome(all, {url: "https://other-bad.example/x.js", type: "script", initiator: "bad.example", tabId: 7, frame}), "block", "other threat hosts stay blocked");
  assert.equal(outcome(all, {url: "https://other-bad.example/", type: "sub_frame", initiator: "bad.example", tabId: 7, frame}), "block");
  assert.equal(outcome(all, {url: "https://pixel.tracker.test/p.gif", type: "image", initiator: "bad.example", tabId: 7, frame}), "block", "trackers stay blocked");
  assert.equal(outcome(all, {url: "https://bad.example/app.js", type: "script", initiator: "news.example", tabId: 7}), "block", "other sites cannot load it");
  assert.equal(outcome(all, {...frame, url: "https://login.bad.example/"}), "redirect", "permission is exact-host, not all descendant hosts");
  assert.ok(dnr.PRIORITY.threat < dnr.PRIORITY.continue && dnr.PRIORITY.continue < dnr.PRIORITY.userBlock);
  assert.throws(() => dnr.continueRules(1, "127.0.0.1", 7));
  assert.throws(() => dnr.continueRules(1, "bad.example", -1));
});

test("an exception shown as \"other\" does not also allow WebSocket, WebTransport or Web Bundles", () => {
  const {rules: out} = dnr.compileUserState([], [exception({type: "other"})], NOW);
  assert.deepEqual(out[0].condition.resourceTypes, ["other"]);
  assert.equal(dnr.CHROME_TO_CORE.websocket, "websocket", "logged under its own type");
  assert.ok(!rules.RESOURCE_TYPES.includes(dnr.CHROME_TO_CORE.websocket), "so no exception can be made for it");
  const blocked = dnr.compileUserState([userRule({types: ["other"]})], [], NOW).rules[0];
  assert.ok(blocked.condition.resourceTypes.includes("websocket"), "a block rule for other still covers them");
});

test("tracking parameter stripping: exact names, navigations only, only when one is present", () => {
  const all = dnr.compileParams();
  const params = require("../../browser/core/params.js");
  const preserveCount = (params.PRESERVE_URL_REGEXES || [params.PRESERVE_REGEX]).length;
  const scopedCount = dnr.SCOPED_PARAMS.reduce((n, s) => n + s.params.length * 2, 0);
  assert.equal(all.length, dnr.TRACKING_PARAMS.length * 2 + scopedCount + params.PATH_RULES.length + preserveCount, "parameter, path and fixed preservation rules are distinct");
  assert.equal(new Set(all.map((r) => r.id)).size, all.length);
  assert.equal(new Set(dnr.TRACKING_PARAMS).size, dnr.TRACKING_PARAMS.length, "no duplicate names");
  const preserve = all.filter((r) => r.action.type === "allow");
  assert.equal(preserve.length, preserveCount);
  for (const rule of preserve) {
    assert.equal(rule.priority, dnr.PRIORITY.params, "an allow at the redirect's own priority beats it");
    assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]);
    assert.deepEqual(rule.condition.requestMethods, ["get"]);
  }
  const redirects = all.filter((r) => r.action.type === "redirect");
  const out = redirects.filter((r) => !r.condition.requestDomains && !r.condition.regexFilter);
  const removed = out[0].action.redirect.transform.queryTransform.removeParams;
  for (const rule of redirects) {
    assert.equal(rule.priority, dnr.PRIORITY.params);
    assert.deepEqual(rule.condition.requestMethods, ["get"], "POST bodies are never replayed through parameter redirects");
    assert.ok(rule.condition.excludedRequestDomains.includes("accounts.google.com") && rule.condition.excludedRequestDomains.includes("ads.google.com"), "sign-in and consoles excluded");
    if (rule.action.redirect.regexSubstitution) { assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]); continue; }
    assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]);
    assert.equal(rule.condition.regexFilter, undefined, "no regex: Chrome caps compiled regex size");
    for (const kept of dnr.KEPT_PARAMS) assert.ok(!rule.action.redirect.transform.queryTransform.removeParams.includes(kept));
  }
  for (const rule of out) assert.deepEqual(rule.action.redirect.transform.queryTransform.removeParams, removed);
  // Generic names are removed only on the sites that use them for share tracking.
  const youtube = all.find((r) => r.condition.requestDomains && r.condition.requestDomains.includes("youtube.com"));
  assert.ok(youtube.action.redirect.transform.queryTransform.removeParams.includes("si"));
  assert.ok(!removed.includes("si") && !removed.includes("s") && !removed.includes("trk"));
  for (const name of ["_gl", "gad_source", "mc_cid", "vgo_ee", "__hstc", "pk_campaign", "mtm_source", "ttclid", "twclid", "li_fat_id", "s_cid", "vero_id", "oly_enc_id", "__s", "yclid", "dclid"]) assert.ok(removed.includes(name), name);
  for (const name of ["utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid", "msclkid", "dclid", "gbraid", "wbraid", "mc_eid", "igshid"]) assert.ok(removed.includes(name), name);
  for (const name of ["id", "q", "page", "ref", "v", "t"]) assert.ok(!removed.includes(name), `${name} is functional and kept`);
  for (const name of ["mkt_tok", "_hsenc", "_hsmi"]) assert.ok(!removed.includes(name), `${name} is kept: unsubscribe and preference links need it`);
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

test("manual other denies match WebSocket handshakes without expanding old allows", () => {
  const entry = userRule({host: "collector.example", path: "/stream*", types: ["other"]});
  const deny = dnr.compileUserState([entry], [], NOW).rules;
  const allow = dnr.compileUserState([{...entry, action: "allow"}], [], NOW).rules;
  const repair = dnr.compileUserState([], [exception({host: "collector.example", path: "/stream", type: "other", tabId: 1})], NOW).rules;
  for (const url of ["ws://collector.example/stream", "wss://collector.example:8443/stream/events?user=sample"]) {
    const req = {url, type: "websocket", top: "publisher.example", initiator: "foreign-frame.example", tabId: 1};
    assert.equal(outcome(deny, req), "block", url);
    assert.equal(outcome(allow, req), "none", "HTTP-only saved allows gain no socket capability");
    assert.equal(outcome(repair, req), "none", "ordinary other repairs remain exact-type");
    assert.equal(outcome(deny, {...req, top: "other.example"}), "none");
    assert.equal(outcome(deny, {...req, url: url.replace("collector.example", "sub.collector.example")}), "none", "exact destination only");
  }
  assert.ok(new RegExp(deny[0].condition.regexFilter).test("wss://collector.example./stream"), "regex retains the existing optional trailing dot; browser domain normalization is separately qualified");
  assert.equal(deny[0].condition.requestMethods, undefined, "positive HTTP method filters do not match Chrome WebSocket handshakes");
  assert.equal(outcome(deny, {url: "https://collector.example/stream", type: "webtransport", top: "publisher.example"}), "block");
  assert.equal(outcome(deny, {url: "https://collector.example/other", type: "other", top: "publisher.example"}), "none");
});

test("Isolation blocks every cross-top-site subresource despite ordinary repair and compatibility allowances", () => {
  const isolated = dnr.compileModes({sites: {"publisher.example": "isolated"}, allowHosts: {"publisher.example": ["cdn.vendor.example"]}, cleanOff: ["publisher.example"]});
  const allow = dnr.compileUserState([userRule({host: "cdn.vendor.example", path: "/resource", types: [...rules.RESOURCE_TYPES], action: "allow"})], [], NOW).rules;
  const repair = dnr.compileUserState([], [exception({host: "cdn.vendor.example", path: "/resource", type: "image", tabId: 1})], NOW).rules;
  const dynamic = [...isolated.rules, ...allow, ...repair, dnr.embedRule(300000, "youtube", 1, {topSite: "publisher.example", withCookies: true})];
  for (const type of dnr.SUBRESOURCE_TYPES) {
    const req = {url: `${type === "websocket" ? "wss" : "https"}://cdn.vendor.example/resource`, type, top: "publisher.example", initiator: "cdn.vendor.example", tabId: 1};
    assert.equal(outcome(dynamic, req), "block", type);
    assert.equal(best(dynamic, req).priority, dnr.PRIORITY.isolation, type);
    assert.equal(outcome(isolated.rules, {...req, url: "https://publisher.example/resource"}), "none", "own resources remain enabled");
    assert.equal(outcome(isolated.rules, {...req, top: "elsewhere.example"}), "none", "unrelated top sites retain their own policy");
  }
  for (const host of [...dnr.FUNCTIONAL_HOSTS, "www.youtube.com"]) assert.equal(outcome(dynamic, {
    url: `https://${host}/resource`, type: "sub_frame", top: "publisher.example", initiator: host, tabId: 1}), "block", host);
  assert.equal(outcome(dynamic, {url: "https://outside.example/", type: "main_frame", top: "publisher.example"}), "none", "this is not an outbound navigation firewall");
  assert.ok(isolated.rules.filter((r) => r.action.type === "block").every((r) => !r.condition.requestMethods && !r.condition.domainType));
});

test("Isolation uses PSL site ownership for top scopes, destinations and cold initial navigation sanitation", () => {
  const all = dnr.compileModes({defaultMode: "strict", sites: {"amazonaws.com": "isolated"}}).rules;
  const req = {url: "https://alice.s3.amazonaws.com/resource", type: "image", top: "amazonaws.com", initiator: "alice.s3.amazonaws.com"};
  assert.equal(outcome(all, req), "block", "nested private tenant is not part of its hosting company's first party");
  assert.equal(best(all, req).priority, dnr.PRIORITY.isolation);
  assert.equal(outcome(all, {...req, url: "https://www.amazonaws.com/resource"}), "none");
  assert.equal(outcome(all, {...req, url: "https://amazonaws.com/app.js", type: "script", top: "amazonaws.com"}), "none", "default Strict's cold hold does not hold an explicit isolated site's own scripts");
  const isolationRules = all.filter((r) => [dnr.PRIORITY.isolation, dnr.PRIORITY.isolationHeaders].includes(r.priority));
  assert.equal(outcome(isolationRules, {...req, top: "alice.s3.amazonaws.com"}), "none", "parent's mode does not apply inside independent tenant pages");
  const headers = (request) => isolationRules.filter((r) => r.action.type === "modifyHeaders" && matches(r, request));
  assert.equal(headers({url: "https://www.amazonaws.com/", type: "main_frame"}).length, 1, "first omnibox visit is sanitized before worker navigation events");
  assert.equal(headers({url: "https://alice.s3.amazonaws.com/", type: "main_frame"}).length, 0, "parent destination sanitation does not strip a tenant's sign-in");
  assert.equal(headers({url: "https://af-south-1.airflow.amazonaws.com/", type: "main_frame"}).length, 0, "unrepresentable wildcard bases are explicitly unsupported");
  assert.equal(headers({...req, top: undefined, initiator: "amazonaws.com"}).length, 1, "Chrome's no-top fallback is initiator-scoped, not attributed to some tab");
  assert.equal(headers({...req, top: undefined, initiator: "alice.s3.amazonaws.com"}).length, 0);
  const ownRepair = dnr.compileUserState([], [exception({site: "amazonaws.com", host: "amazonaws.com", path: "/resource", type: "image", tabId: 1})], NOW).rules;
  const own = {url: "https://amazonaws.com/resource", type: "image", top: "amazonaws.com", tabId: 1};
  const sanitizer = headers(own).find((r) => r.priority > best(ownRepair, own).priority);
  assert.deepEqual(sanitizer.action.requestHeaders.map((h) => h.header).sort(), ["authorization", "cookie", "referer", "x-posthog-distinct-id", "x-posthog-session-id", "x-posthog-window-id"]);
  assert.deepEqual(sanitizer.action.responseHeaders, [{header: "set-cookie", operation: "remove"}]);
  assert.ok(sanitizer.action.requestHeaders.every((h) => h.operation === "remove"));
});

test("Isolation preserves threat/manual precedence and strips credentials after explicit threat navigation consent", () => {
  const isolated = dnr.compileModes({sites: {"bad.example": "isolated"}}).rules;
  const threat = dnr.compileList("threats", ["bad.example", "other-bad.example"], {warningUrl: WARN}).rules;
  const continued = dnr.continueRules(100000, "bad.example", 1);
  const all = [...isolated, ...threat, ...continued];
  const nav = {url: "https://bad.example/", type: "main_frame", tabId: 1};
  assert.equal(outcome(all, nav), "allow", "the warning page can still give explicit navigation consent");
  assert.ok(isolated.some((r) => r.action.type === "modifyHeaders" && r.priority > best(all, nav).priority && matches(r, nav) && r.action.requestHeaders.some((h) => h.header === "authorization")));
  const cross = {url: "https://other-bad.example/resource", type: "image", top: "bad.example", tabId: 1};
  assert.equal(best(all, cross).priority, dnr.PRIORITY.threat);
  const manual = dnr.compileUserState([userRule({site: "bad.example", host: "other-bad.example", path: "/resource", types: ["image"]})], [], NOW).rules;
  assert.equal(best([...all, ...manual], cross).priority, dnr.PRIORITY.userBlock);
  assert.equal(outcome(all, {...cross, url: "https://bad.example/resource"}), "block", "Continue never releases threat subresources");
});

test("Isolation removes source-verified analytics headers on ordinary same-site API calls above repair grants", () => {
  const trackingHeaders = ["x-posthog-distinct-id", "x-posthog-session-id", "x-posthog-window-id"];
  const req = {url: "https://shop.example/api/cart", type: "xmlhttprequest", method: "post", top: "shop.example", tabId: 1};
  const repair = dnr.compileUserState([], [exception({site: "shop.example", host: "shop.example", path: "/api/cart", type: "xmlhttprequest", tabId: 1})], NOW).rules;
  const removed = (all, request) => {
    const winner = best(all, request);
    return all.filter(rule => rule.action.type === "modifyHeaders" && matches(rule, request) &&
      (!winner || rule.priority > winner.priority)).flatMap(rule => (rule.action.requestHeaders || [])
        .filter(header => header.operation === "remove").map(header => header.header));
  };
  const isolated = [...dnr.compileModes({sites: {"shop.example": "isolated"}}).rules, ...repair];
  assert.equal(outcome(isolated, req), "allow", "the functional same-site operation remains admitted");
  for (const header of trackingHeaders) assert.ok(removed(isolated, req).includes(header), header);
  for (const header of trackingHeaders) assert.ok(removed(isolated, {url: "https://shop.example/", type: "main_frame"}).includes(header), header);
  assert.equal(removed(isolated, {...req, top: "unrelated.example"}).length, 0, "the opt-in site scope is retained");
  for (const mode of ["standard", "strict", "relaxed"]) {
    const headers = removed(dnr.compileModes({sites: {"shop.example": mode}}).rules, req);
    assert.ok(trackingHeaders.every(header => !headers.includes(header)), mode);
  }
  assert.ok(!removed(isolated, req).includes("traceparent"), "generic application tracing is not guessed to be this vendor protocol");
});

test("extension id derivation matches Chrome's documented a-p mapping", () => {
  assert.equal(dnr.extensionIdFromHex("0123456789abcdef0123456789abcdef00"), "abcdefghijklmnopabcdefghijklmnop");
});

test("topDomains binds manual rules to the outer page even across foreign iframe initiators", () => {
  const all = dnr.compileUserState([userRule()], [], NOW).rules;
  const request = {url: "https://publisher.example/collect", type: "ping", top: "publisher.example", initiator: "foreign-frame.example"};
  assert.equal(outcome(all, request), "block");
  assert.equal(outcome(all, {...request, top: "other.example", initiator: "publisher.example"}), "none");
});

test("ordinary endpoint grants are tab-bound, remain cookieless and never lift explicit denies", () => {
  const exc = exception({tabId: 1});
  const permit = dnr.compileUserState([], [exc], NOW, {tabIdsBySite: {"publisher.example": [1, 2], "other.example": [2]}}).rules;
  assert.equal(permit.length, 2);
  const req = {url: "https://pixel.tracker.test/p.gif", type: "image", top: "publisher.example", initiator: "foreign-frame.example", tabId: 1};
  assert.equal(outcome(permit, req), "allow");
  assert.equal(outcome(permit, {...req, tabId: -1, top: undefined, initiator: "publisher.example"}), "none", "background workers receive no tab-scoped permission");
  assert.equal(outcome(permit, {...req, tabId: 2}), "none");
  const allow = best(permit, req);
  const sanitation = permit.filter((r) => r.action.type === "modifyHeaders" && r.priority > allow.priority && matches(r, req));
  assert.ok(sanitation.some((r) => r.action.requestHeaders.some((h) => h.header === "cookie" && h.operation === "remove")));
  assert.ok(sanitation.some((r) => r.action.responseHeaders.some((h) => h.header === "set-cookie" && h.operation === "remove")));
  const manual = dnr.compileUserState([userRule({host: exc.host, path: exc.path, types: [exc.type]})], [], NOW).rules;
  assert.equal(outcome([...permit, ...manual], req), "block");
  assert.deepEqual(dnr.compileUserState([], [exc], NOW, {tabIdsBySite: {}}).rules, []);
});

test("Strict uses top-site party boundaries, including separately hosted tenants below a parent domain", () => {
  const strict = dnr.compileModes({sites: {"publisher.example": "strict"}, allowHosts: {"publisher.example": ["cdn.vendor.example"]}}).rules;
  const nested = {url: "https://frame.vendor.example/worker.js", type: "script", top: "publisher.example", initiator: "frame.vendor.example"};
  assert.equal(outcome(strict, nested), "block", "iframe cannot make cross-top requests first-party by initiating them itself");
  assert.equal(outcome(strict, {...nested, top: "unrelated.example"}), "none");
  const allowed = {...nested, url: "https://cdn.vendor.example/worker.js"};
  assert.equal(outcome(strict, allowed), "none", "explicit Strict resource permission works");
  assert.ok(strict.some((r) => r.action.type === "modifyHeaders" && matches(r, allowed) && r.action.requestHeaders.some((h) => h.header === "cookie")), "Strict resource permission retains cookie stripping");
  const parent = dnr.compileModes({sites: {"amazonaws.com": "strict"}}).rules;
  const tenant = {url: "https://alice.s3.amazonaws.com/app.js", type: "script", top: "amazonaws.com", initiator: "alice.s3.amazonaws.com"};
  assert.equal(outcome(parent, tenant), "block", "nested private tenants are third-party to their hosting company's own site");
  assert.equal(outcome(parent, {...tenant, top: "alice.s3.amazonaws.com"}), "none", "parent's scope does not cover independently hosted tenant pages");
  assert.ok(parent.some((r) => r.action.type === "modifyHeaders" && matches(r, tenant) && r.action.requestHeaders.some((h) => h.header === "cookie")));
});

test("default Strict holds unseen top sites before preparation, including same-origin requests from foreign frames", () => {
  const req = {url: "https://frame.vendor.example/app.js", type: "script", top: "new.example", initiator: "frame.vendor.example"};
  const pending = dnr.compileModes({defaultMode: "strict"});
  const ready = dnr.compileModes({defaultMode: "strict"}, {topSites: ["new.example"]});
  assert.equal(outcome(pending.rules, req), "block");
  assert.equal(outcome(ready.rules, req), "block");
  assert.equal(outcome(pending.rules, {...req, url: "https://new.example/app.js", initiator: "new.example"}), "block", "own scripts can be held too; preparation is not claimed to be transparent");
  assert.equal(outcome(ready.rules, {...req, url: "https://new.example/app.js", initiator: "new.example"}), "none");
  assert.equal(pending.kinds[best(pending.rules, req).id], "preparation", "a preparation block is not labelled a third-party tracker");
  assert.ok(pending.rules.every((r) => !r.condition.domainType));
  assert.ok(ready.rules.every((r) => !["allow", "allowAllRequests"].includes(r.action.type)), "release never uses a permissive override");
  assert.equal(outcome(pending.rules, {...req, type: "main_frame"}), "none", "navigation and POST replay are outside the hold");
  for (const type of ["image", "xmlhttprequest", "websocket", "ping"]) {
    const headers = pending.rules.filter((r) => r.action.type === "modifyHeaders" && matches(r, {...req, type}));
    assert.ok(headers.some((r) => r.action.requestHeaders.some((h) => h.header === "cookie" && h.operation === "remove")), type);
    assert.ok(headers.some((r) => r.action.requestHeaders.some((h) => h.header === "referer" && h.operation === "remove")), type);
    assert.ok(headers.some((r) => r.action.responseHeaders.some((h) => h.header === "set-cookie" && h.operation === "remove")), type);
  }
  assert.equal(outcome(pending.rules, {...req, top: undefined}), "block", "no associated top frame falls back to initiator; unknown worker contexts remain held");
  assert.equal(outcome(ready.rules, {...req, url: "https://new.example/worker.js", top: undefined, initiator: "new.example"}), "none");
});

test("preparation exclusions preserve private tenants under prepared or non-Strict parent sites", () => {
  const topSites = ["amazonaws.com", "bob.s3.amazonaws.com", "publisher.example"];
  const compiled = dnr.compileModes({defaultMode: "strict"}, {topSites});
  const own = (host) => ({url: `https://${host}/app.js`, type: "script", top: host, initiator: host});
  for (const host of ["publisher.example", "www.amazonaws.com", "bob.s3.amazonaws.com", "cdn.bob.s3.amazonaws.com"]) assert.equal(outcome(compiled.rules, own(host)), "none", host);
  for (const host of ["alice.s3.amazonaws.com", "widget.alice.s3.amazonaws.com", "never-seen.example"]) assert.equal(outcome(compiled.rules, own(host)), "block", host);
  const holds = compiled.rules.filter((r) => compiled.kinds[r.id] === "preparation");
  assert.equal(holds.length, 3, "583 nested PSL boundaries share two recovery conditions plus the global unknown scope");
  assert.deepEqual(compiled.rules, dnr.compileModes({defaultMode: "strict"}, {topSites: [...topSites].reverse()}).rules, "rule identity/order is deterministic");
  for (const mode of ["standard", "relaxed", "noscript"]) {
    const ruleset = dnr.compileModes({defaultMode: "strict", sites: {"amazonaws.com": mode}}).rules;
    const tenant = own("alice.s3.amazonaws.com");
    assert.equal(outcome(ruleset, tenant), "block", `${mode} on the hosting company does not exempt an independent tenant`);
    if (mode !== "noscript") assert.equal(outcome(ruleset, {...own("amazonaws.com"), frame: {url: "https://amazonaws.com/", type: "main_frame"}}), mode === "relaxed" ? "allow" : "none");
  }
});

test("grouped preparation scopes agree with PSL ownership across nested boundary samples", () => {
  const prepared = ["amazonaws.com", "fastly.net", "bob.s3.amazonaws.com", "city.kawasaki.jp", "xn--bcher-kva.example"];
  const compiled = dnr.compileModes({defaultMode: "strict"}, {topSites: prepared});
  const holds = compiled.rules.filter((r) => compiled.kinds[r.id] === "preparation");
  const samples = new Set(["unlisted.example", ...prepared, ...prepared.map((s) => `cdn.${s}`),
    ...prepared.flatMap((site) => hosts.scopeExclusions(site).flatMap((boundary) => [boundary, `tenant.${boundary}`, `cdn.tenant.${boundary}`]))]);
  assert.ok(samples.size > 1500, "exercise the packaged private suffix hierarchy, not just one synthetic domain");
  for (const top of samples) {
    const owned = prepared.some((site) => hosts.inSiteScope(top, site));
    const held = holds.some((r) => matches(r, {url: "https://unknown-vendor.example/a.js", type: "script", top, initiator: top}));
    if (!owned) assert.equal(held, true, `${top}: an independent tenant must never escape the hold`);
    else if (held) assert.ok(prepared.some((site) => hosts.inSiteScope(top, site) && hosts.scopeExclusions(site).includes(top)),
      `${top}: only a conservative wildcard base may remain held within an otherwise prepared site`);
  }
  const base = "af-south-1.airflow.amazonaws.com";
  assert.equal(hosts.siteOf(base), "amazonaws.com");
  assert.ok(holds.some((r) => matches(r, {url: `https://${base}/a.js`, type: "script", top: base, initiator: base})), "a wildcard base stays held because topDomains also matches its independent descendants");
  assert.throws(() => dnr.compileModes({defaultMode: "strict"}, {topSites: Array.from({length: 4097}, (_, i) => `s${i}.example`)}), /Too many sites to prepare/);
});

test("preparation preserves tab-grant sanitation and threat/manual precedence", () => {
  const held = dnr.compileModes({defaultMode: "strict"}).rules;
  const exc = exception({tabId: 1, type: "script"});
  const pair = dnr.compileUserState([], [exc], NOW).rules;
  const req = {url: `https://${exc.host}${exc.path}`, type: "script", top: exc.site, initiator: exc.host, tabId: 1};
  assert.equal(outcome([...held, ...pair], req), "allow");
  assert.equal(outcome([...held, ...pair], {...req, tabId: 2}), "block");
  const allow = best(pair, req);
  const sanitation = pair.find((r) => r.action.type === "modifyHeaders" && r.priority > allow.priority && matches(r, req));
  assert.ok(sanitation.action.requestHeaders.some((h) => h.header === "cookie" && h.operation === "remove"));
  const threat = dnr.compileList("threats", [exc.host], {warningUrl: WARN}).rules;
  assert.equal(outcome([...held, ...pair, ...threat], req), "block");
  const manual = dnr.compileUserState([userRule({host: exc.host, path: exc.path, types: ["script"]})], [], NOW).rules;
  assert.equal(outcome([...held, ...pair, ...manual], req), "block");
});

test("an embed permission cannot follow its tab into an independent private tenant before revocation", () => {
  const held = dnr.compileModes({defaultMode: "strict"}, {topSites: ["amazonaws.com"]}).rules;
  for (const withCookies of [false, true]) {
    const grant = dnr.embedRule(300000, "youtube", 1, {topSite: "amazonaws.com", withCookies});
    const req = {url: "https://www.youtube.com/embed/demo", type: "sub_frame", top: "amazonaws.com", initiator: "amazonaws.com", tabId: 1};
    assert.equal(outcome([...held, grant], req), "allow");
    assert.equal(outcome([...held, grant], {...req, top: "alice.s3.amazonaws.com", initiator: "alice.s3.amazonaws.com"}), "block");
    assert.equal(matches(grant, {...req, tabId: 2}), false);
  }
  assert.throws(() => dnr.embedRule(300000, "youtube", 1, {topSite: "kawasaki.jp"}), /safely scoped/);
});
