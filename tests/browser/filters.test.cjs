"use strict";
// URL filters (EasyPrivacy/EasyList conversion), link unwrapping, privacy rules, site modes and surrogates.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const dnr = require("../../browser/core/dnr.js");
const links = require("../../browser/core/links.js");
const hosts = require("../../browser/core/hosts.js");
const abp = require("../../scripts/lib/abp-dnr.cjs");

const root = path.resolve(__dirname, "../..");
const UNWRAP = "chrome-extension://danbhmcinakkkkbobacafgidgkfibfmg/unwrap.html";

// ---- a model of Chrome's documented matching, enough for the rule shapes the build emits ----
function urlFilterRegex(filter) {
  let re = "";
  let i = 0;
  if (filter.startsWith("||")) { re = "^[a-z][a-z0-9+.-]*://([^/?#]*\\.)?"; i = 2; } else if (filter.startsWith("|")) { re = "^"; i = 1; }
  for (; i < filter.length; i++) {
    const c = filter[i];
    if (c === "*") re += ".*";
    else if (c === "^") re += "(?:[^A-Za-z0-9_.%-]|$)";
    else if (c === "|" && i === filter.length - 1) re += "$";
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return re;
}
const covers = (list, name) => list.some((d) => name === d || name.endsWith(`.${d}`));
function matches(rule, req) {
  const c = rule.condition;
  const url = new URL(req.url);
  const host = url.hostname;
  const types = c.resourceTypes || dnr.SUBRESOURCE_TYPES.filter((t) => !(c.excludedResourceTypes || []).includes(t));
  if (!types.includes(req.type)) return false;
  if (c.requestDomains && !covers(c.requestDomains, host)) return false;
  if (c.excludedRequestDomains && covers(c.excludedRequestDomains, host)) return false;
  if (c.initiatorDomains && !(req.initiator && covers(c.initiatorDomains, req.initiator))) return false;
  if (c.excludedInitiatorDomains && req.initiator && covers(c.excludedInitiatorDomains, req.initiator)) return false;
  if (c.tabIds && !c.tabIds.includes(req.tabId)) return false;
  if (c.domainType) {
    const third = !req.initiator || hosts.siteOf(req.initiator) !== hosts.siteOf(host);
    if ((c.domainType === "thirdParty") !== third) return false;
  }
  const flags = c.isUrlFilterCaseSensitive ? "" : "i";
  if (c.urlFilter && !new RegExp(urlFilterRegex(c.urlFilter), flags).test(req.url)) return false;
  if (c.regexFilter && !new RegExp(c.regexFilter, flags).test(req.url)) return false;
  return true;
}
const RANK = {allow: 4, allowAllRequests: 4, block: 3, upgradeScheme: 2, redirect: 1};
function outcome(all, req) {
  const hits = all.filter((r) => r.action.type !== "modifyHeaders" && matches(r, req))
    .sort((a, b) => b.priority - a.priority || RANK[b.action.type] - RANK[a.action.type]);
  let hit = hits[0] || null;
  if (req.frame) {
    const frameHits = all.filter((r) => r.action.type === "allowAllRequests" && matches(r, req.frame));
    const top = frameHits.sort((a, b) => b.priority - a.priority)[0];
    if (top && (!hit || hit.priority <= top.priority)) return "allow";
  }
  return hit ? (hit.action.type === "allowAllRequests" ? "allow" : hit.action.type) : "none";
}
function headerRules(all, req) {
  const allows = all.filter((r) => /^allow/.test(r.action.type) && matches(r, req)).map((r) => r.priority);
  if (req.frame) allows.push(...all.filter((r) => r.action.type === "allowAllRequests" && matches(r, req.frame)).map((r) => r.priority));
  const ceiling = allows.length ? Math.max(...allows) : -Infinity;
  return all.filter((r) => r.action.type === "modifyHeaders" && r.priority > ceiling && matches(r, req));
}
const withPriority = (rules, priority) => rules.map((r, i) => ({id: i + 1, priority, ...r}));
function compileText(text) {
  const c = abp.compileFilters(text);
  return [...withPriority(c.block, dnr.PRIORITY.filter), ...withPriority(c.important, dnr.PRIORITY.filterImportant), ...withPriority(c.allow, dnr.PRIORITY.filterAllow)];
}

// ---- ABP -> DNR conversion ----
test("filter conversion: patterns, options, types and party map onto DNR conditions", () => {
  const p = (line) => abp.parseLine(line);
  assert.deepEqual(p("/g/collect?").condition, {urlFilter: "/g/collect?", isUrlFilterCaseSensitive: false});
  assert.equal(p("||tracker.example^").domain, "tracker.example");
  assert.deepEqual(p("||cdn.example/px.gif$image,third-party").condition,
    {resourceTypes: ["image"], domainType: "thirdParty", urlFilter: "||cdn.example/px.gif", isUrlFilterCaseSensitive: false});
  assert.deepEqual(p("/stats.js$~third-party,script").condition.domainType, "firstParty");
  assert.deepEqual(p("/ads/$domain=a.example|~b.a.example").condition.initiatorDomains, ["a.example"]);
  assert.deepEqual(p("/ads/$domain=a.example|~b.a.example").condition.excludedInitiatorDomains, ["b.a.example"]);
  assert.deepEqual(p("/x.js$~script").condition.excludedResourceTypes, ["script"]);
  assert.deepEqual(p("/x$xhr,subdocument,beacon").condition.resourceTypes, ["ping", "sub_frame", "xmlhttprequest"]);
  assert.deepEqual(p("/x$method=post|~get").condition.requestMethods, ["post"]);
  assert.equal(p("/Track$match-case").condition.isUrlFilterCaseSensitive, true);
  assert.equal(p("/x$important").important, true);
  assert.equal(p("**/pixel*").condition.urlFilter, "/pixel");
  // Regular expressions: kept when RE2 can run them, refused otherwise.
  assert.equal(p("/^https?:\\/\\/[a-z]+\\.example\\/t\\.js/$script").condition.regexFilter, "^https?:\\/\\/[a-z]+\\.example\\/t\\.js");
  assert.match(p("/(?=lookahead)x/").drop, /RE2/);
  // Not network filters at all.
  for (const line of ["! comment", "[Adblock Plus 2.0]", "example.com##.ad", "##.banner", "example.com#@#.ad", "example.com#?#div:-abp-has(.ad)", "example.com#$#abort-on-property-read x", "example.com##+js(nobab)"]) {
    assert.equal(p(line), null, line);
  }
});

test("filter conversion: what DNR cannot express is dropped with a reason, never broadened", () => {
  const p = (line) => abp.parseLine(line);
  assert.match(p("||site.example^$document").drop, /navigations are never blocked/);
  assert.match(p("/ad.js$popup").drop, /popup/);
  assert.match(p("||x.example^$csp=script-src 'none'").drop, /csp/);
  assert.match(p("||x.example^$removeparam=utm").drop, /removeparam/);
  assert.match(p("/ads$domain=example.*").drop, /entity/);
  assert.match(p("/ads$frobnicate").drop, /unknown option/);
  assert.match(p("@@||x.example^$elemhide").drop, /cosmetic-only/);
  assert.match(p("$third-party").drop, /every request/);
  assert.match(p("/ünïcode/").drop, /non-ASCII/);
  // A domain list with a usable entry and an entity entry keeps the usable one only if that cannot widen it.
  assert.deepEqual(p("/ads$domain=a.example|b.*").condition.initiatorDomains, ["a.example"], "narrower is fine");
  assert.match(p("/ads$domain=a.example|~b.*").drop, /entity/, "losing an exclusion would widen it");
  assert.match(p("/ads$domain=~b.*").drop, /entity/);
});

test("filter conversion: host-only filters fold into requestDomains, exceptions become allow / allowAllRequests, $badfilter removes", () => {
  const text = ["||a.example^", "||b.example^", "||c.example^$third-party", "/collect?v=", "@@||ok.example/collect?v=", "@@||news.example^$document",
    "/drop-me.js", "/drop-me.js$badfilter", "||e.example^$script,important"].join("\n");
  const c = abp.compileFilters(text);
  const folded = c.block.find((r) => r.condition.requestDomains && !r.condition.domainType);
  assert.deepEqual(folded.condition.requestDomains, ["a.example", "b.example"]);
  assert.ok(c.block.find((r) => r.condition.domainType === "thirdParty" && r.condition.requestDomains[0] === "c.example"));
  assert.ok(!c.block.some((r) => r.condition.urlFilter === "/drop-me.js"), "$badfilter disables its twin");
  assert.equal(c.stats.dropped["disabled by $badfilter"], 1);
  assert.deepEqual(c.allow.map((r) => r.action.type).sort(), ["allow", "allowAllRequests"]);
  assert.deepEqual(c.allow.find((r) => r.action.type === "allowAllRequests").condition.resourceTypes, ["main_frame", "sub_frame"]);
  assert.equal(c.important.length, 1);
  assert.equal(c.stats.network, 9);
});

test("exception precedence: a list's @@ lifts its own filters, never $important, host lists, threats, or your rules", () => {
  const filters = compileText(["/collect?v=", "@@||shop.example/collect?v=", "||ads.example/banner$important", "@@||ads.example/banner", "@@||news.example^$document",
    "@@||evil.example^", "@@||listed.example^"].join("\n"));
  const threat = dnr.compileList("threats", ["evil.example"], {warningUrl: "chrome-extension://danbhmcinakkkkbobacafgidgkfibfmg/warning.html"}).rules;
  const list = dnr.compileList("trackers", ["listed.example"]).rules;
  const user = dnr.compileUserState([{id: "u", kind: "request", action: "block", site: "shop.example", host: "shop.example", path: "/collect", types: ["xmlhttprequest"]}], [], 0).rules;
  const all = [...filters, ...threat, ...list, ...user];
  const req = (url, initiator, type = "xmlhttprequest", extra = {}) => ({url, initiator, type, ...extra});
  assert.equal(outcome(all, req("https://blog.example/collect?v=2&tid=1", "blog.example")), "block");
  assert.equal(outcome(all, req("https://shop.example/collect?v=2", "shop.example", "image")), "allow", "the list's own exception");
  assert.equal(outcome(all, req("https://shop.example/collect?v=2", "shop.example")), "block", "your block rule beats the list's exception");
  assert.equal(outcome(all, req("https://ads.example/banner", "x.example", "image")), "block", "$important beats @@");
  assert.equal(outcome(all, req("https://evil.example/x.js", "x.example", "script")), "block", "@@ never unblocks a threat host");
  assert.equal(outcome(all, req("https://listed.example/x.js", "x.example", "script")), "block", "@@ never unblocks a host-list entry");
  // $document exceptions lift URL filters for the page, not the host lists or threats.
  const frame = req("https://news.example/", undefined, "main_frame");
  assert.equal(outcome(all, req("https://news.example/collect?v=1", "news.example", "ping", {frame})), "allow");
  assert.equal(outcome(all, req("https://listed.example/p.gif", "news.example", "image", {frame})), "block");
  assert.equal(outcome(all, req("https://evil.example/p.gif", "news.example", "image", {frame})), "block");
});

test("timed exceptions and Relaxed sites win over URL filters; the threat list is not overridable by either", () => {
  const filters = compileText("/collect?v=\n/fp/tags.js");
  const threat = dnr.compileList("threats", ["evil.example"], {warningUrl: "chrome-extension://danbhmcinakkkkbobacafgidgkfibfmg/warning.html"}).rules;
  const exc = dnr.compileUserState([], [{id: "e", site: "shop.example", host: "shop.example", path: "/collect", type: "xmlhttprequest", expiresAt: Date.now() + 60000}], Date.now()).rules;
  const relaxed = dnr.compileModes({sites: {"bank.example": "relaxed"}}).rules;
  const all = [...filters, ...threat, ...exc, ...relaxed];
  assert.equal(outcome(all, {url: "https://shop.example/collect?v=2", initiator: "shop.example", type: "xmlhttprequest"}), "allow");
  const frame = {url: "https://www.bank.example/login", type: "main_frame"};
  assert.equal(outcome(all, {url: "https://www.bank.example/fp/tags.js?org_id=1", initiator: "www.bank.example", type: "script", frame}), "allow");
  assert.equal(outcome(all, {url: "https://evil.example/x.js", initiator: "www.bank.example", type: "script", frame}), "block");
  assert.equal(outcome(all, {url: "https://other.example/fp/tags.js", initiator: "other.example", type: "script"}), "block");
});

test("hand-written fingerprinting, session-replay and first-party tracker filters hit vendor paths, not ordinary assets", () => {
  const rules = [...dnr.compileHand("replay"), ...dnr.compileHand("fp-trackers")];
  const hit = (url, type = "script") => outcome(rules, {url, initiator: "shop.example", type}) === "block";
  for (const url of ["https://metrics.shop.example/web/v3/abc?apiKey=AbCdEf123456&version=3&loaderVersion=3.11.0", "https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@4/dist/fp.min.js",
    "https://shop.example/hotjar-123456.js?sv=7", "https://shop.example/s/fs.js", "https://shop.example/static/array.js", "https://sgtm.shop.example/x7.js?id=GTM-ABC123",
    "https://shop.example/events.js?sdkid=C1&lib=ttq"]) assert.ok(hit(url), url);
  assert.ok(hit("https://shop.example/fp/tags?org_id=abc&session_id=1", "image"));
  assert.ok(hit("https://shop.example/tr/?id=1234567890&ev=PageView", "image"));
  for (const url of ["https://shop.example/static/app.js", "https://shop.example/s/fonts.js", "https://shop.example/api/event", "https://shop.example/tracking/order?id=1"]) assert.ok(!hit(url), url);
  for (const rule of rules) assert.equal(rule.priority, dnr.PRIORITY.filter);
});

// ---- link unwrapping ----
test("link unwrapping: known redirectors yield their destination", () => {
  const cases = [
    ["https://www.google.com/url?sa=t&url=https%3A%2F%2Fexample.org%2Fa%3Fb%3D1&usg=X", "https://example.org/a?b=1"],
    ["https://www.google.co.uk/url?q=https://example.org/&sa=U", "https://example.org/"],
    ["https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2Fp&h=AT0", "https://example.org/p"],
    ["https://l.instagram.com/?u=https%3A%2F%2Fexample.org&e=x", "https://example.org/"],
    ["https://out.reddit.com/t3_abc?url=https%3A%2F%2Fexample.org%2Fx&token=t", "https://example.org/x"],
    ["https://t.umblr.com/redirect?z=https%3A%2F%2Fexample.org&t=1", "https://example.org/"],
    ["https://away.vk.com/away.php?to=https%3A%2F%2Fexample.org&cc_key=", "https://example.org/"],
    ["https://www.youtube.com/redirect?event=video_description&redir_token=x&q=https%3A%2F%2Fexample.org%2Fv", "https://example.org/v"],
    ["https://slack-redir.net/link?url=https%3A%2F%2Fexample.org", "https://example.org/"],
    ["https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fexample.org&urlhash=x", "https://example.org/"],
    ["https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2F&rut=x", "https://example.org/"],
    ["https://disq.us/url?url=https%3A%2F%2Fexample.org%2Fa%3AAbCdEfGhIjKl&cuid=1", "https://example.org/a"],
    ["https://go.redirectingat.com/?id=1&url=https%3A%2F%2Fshop.example%2Fp", "https://shop.example/p"],
    ["https://www.bing.com/ck/a?!&&p=abc&u=a1" + Buffer.from("https://example.org/b?x=1").toString("base64url") + "&ntb=1", "https://example.org/b?x=1"],
    ["https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.org%2Fdoc%3Fid%3D3&data=05%7C01&sdata=x&reserved=0", "https://example.org/doc?id=3"],
    ["https://urldefense.proofpoint.com/v2/url?u=https-3A__example.org_path_page-3Fa-3D1&d=DwMF&c=x", "https://example.org/path/page?a=1"],
    ["https://urldefense.com/v3/__https://example.org/a/b__;!!ABC!def$", "https://example.org/a/b"],
    ["https://r.search.yahoo.com/_ylt=Aw/RV=2/RE=1/RO=10/RU=https%3a%2f%2fexample.org%2fy/RK=2/RS=x-", "https://example.org/y"],
    ["https://www.google.com/amp/s/example.org/news/story.amp", "https://example.org/news/story.amp"],
    ["https://l.messenger.com/l.php?u=https%3A%2F%2Fexample.org%2Fm&h=x", "https://example.org/m"],
    ["https://href.li/?https://example.org/h", "https://example.org/h"],
    ["https://mandrillapp.com/track/click/123/example.org?p=" + Buffer.from(JSON.stringify({p: JSON.stringify({u: 1, v: 1, url: "https://example.org/md", id: "x"})})).toString("base64url"), "https://example.org/md"],
    // IDN destination, a fragment, a double-encoded destination decoded exactly once
    ["https://www.google.com/url?q=https%3A%2F%2Fb%C3%BCcher.example%2F%23top", "https://xn--bcher-kva.example/#top"],
    ["https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Fsearch%3Fq%3Da%252Fb", "https://example.org/search?q=a%2Fb"],
    // repeated parameter: the first usable value wins
    ["https://www.google.com/url?q=&q=https%3A%2F%2Fexample.org%2Ffirst&q=https%3A%2F%2Fevil.example", "https://example.org/first"],
  ];
  for (const [input, want] of cases) assert.deepEqual(links.unwrap(input).url, want, input);
  // Nested wrappers are unwrapped all the way.
  const nested = "https://www.google.com/url?q=" + encodeURIComponent("https://l.facebook.com/l.php?u=" + encodeURIComponent("https://example.org/deep"));
  assert.deepEqual(links.unwrap(nested), {url: "https://example.org/deep", via: ["google", "facebook"]});
});

test("link unwrapping refuses anything but an absolute http(s) destination, at any depth", () => {
  const bad = ["javascript:alert(1)", "javascript%3Aalert(1)", "data:text/html,<script>alert(1)</script>", "chrome-extension://danbhmcinakkkkbobacafgidgkfibfmg/popup.html",
    "file:///etc/passwd", "//example.org/x", "/relative", "https://user:pw@example.org/", "https://", " https://example.org", "https://exa\tmple.org", "https://ex\nample.org", "vbscript:x", "HTTPS:example.org"];
  for (const dest of bad) {
    for (const wrap of [(d) => `https://www.google.com/url?q=${encodeURIComponent(d)}`, (d) => `https://l.facebook.com/l.php?u=${encodeURIComponent(d)}`]) {
      const r = links.unwrap(wrap(dest));
      assert.ok(r.error, `${dest} -> ${JSON.stringify(r)}`);
    }
  }
  // A good outer layer around a hostile inner one fails as a whole (no partial unwrap that would loop).
  const inner = "https://l.facebook.com/l.php?u=" + encodeURIComponent("javascript:alert(1)");
  assert.ok(links.unwrap("https://www.google.com/url?q=" + encodeURIComponent(inner)).error);
  // Too deep.
  let deep = "https://example.org/";
  for (let i = 0; i < 6; i++) deep = "https://www.google.com/url?q=" + encodeURIComponent(deep);
  assert.match(links.unwrap(deep).error, /too many/);
  // Not a wrapper, lookalike hosts, malformed input.
  for (const href of ["https://example.org/url?q=https://x.example", "https://www.google.com.evil.example/url?q=https://x.example", "https://evilgoogle.com/url?q=https://x.example",
    "https://www.google.com/search?q=https://x.example", "not a url", "", null, "https://www.bing.com/ck/a?u=a1!!!", "https://www.bing.com/ck/a?u=a1" + Buffer.from("javascript:alert(1)").toString("base64url")]) {
    assert.ok(links.unwrap(href).error, String(href));
  }
  for (const r of [links.unwrap("https://www.google.com/url?q=https%3A%2F%2Fexample.org%2F%23frag")]) assert.equal(r.url, "https://example.org/#frag");
});

test("link unwrapping DNR rules: main frame only, redirect to the unwrap page, RE2-safe, and the same patterns as the page", () => {
  const rules = dnr.compileLinks(UNWRAP);
  assert.equal(rules.length, links.WRAPPERS.length);
  assert.throws(() => dnr.compileLinks("https://example.org/unwrap.html"));
  for (const r of rules) {
    assert.deepEqual(r.condition.resourceTypes, ["main_frame"]);
    assert.equal(r.action.redirect.regexSubstitution, `${UNWRAP}#\\0`);
    assert.ok(abp.re2Compatible(r.condition.regexFilter), r.condition.regexFilter);
    assert.ok(r.condition.regexFilter.length < 400);
  }
  const fires = (url) => rules.some((r) => matches(r, {url, type: "main_frame"}));
  assert.ok(fires("https://www.google.com/url?q=https%3A%2F%2Fexample.org"));
  assert.ok(!fires("https://www.google.com/url?q=javascript%3Aalert(1)"), "a non-http destination is never even redirected");
  assert.ok(!fires("https://www.google.com/search?q=https%3A%2F%2Fexample.org"));
  assert.ok(!rules.some((r) => matches(r, {url: "https://www.google.com/url?q=https%3A%2F%2Fexample.org", type: "sub_frame"})));
  // Mail security rewriters are unwrapped at the owner's request (documented: it skips the employer's click-time scan).
  assert.ok(fires("https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.org&data=x"));
  assert.ok(fires("https://urldefense.proofpoint.com/v2/url?u=https-3A__example.org_a&d=x"));
  // Mimecast links are opaque: never a rule, never an unwrap.
  assert.ok(!fires("https://protect-eu.mimecast.com/s/AbCdEf?domain=example.org") && links.unwrap("https://protect-eu.mimecast.com/s/AbCdEf?domain=example.org").error);
});

// ---- link cleaning (query parameters) ----
test("link cleaner: global names everywhere, ambiguous names only on their sites, the rest of the address untouched", () => {
  const params = require("../../browser/core/params.js");
  const c = (u) => params.clean(u).url;
  assert.equal(c("https://news.example/a?utm_source=x&id=7&fbclid=b&gclid=c#top"), "https://news.example/a?id=7#top");
  assert.equal(c("https://news.example/a?q=a+b%20c&utm_medium=&page=2"), "https://news.example/a?q=a+b%20c&page=2", "encoding and order kept, empty values removed");
  assert.equal(c("https://news.example/?fbclid=1&fbclid=2"), "https://news.example/", "repeated names all go; no dangling ?");
  assert.equal(c("https://github.com/o/r/compare?ref=main&utm_campaign=x"), "https://github.com/o/r/compare?ref=main", "a legitimate ref outside the per-site sets survives");
  assert.equal(c("https://www.amazon.com/dp/B000/ref=sr_1_1?tag=aff-20&keywords=kettle&psc=1&th=1"), "https://www.amazon.com/dp/B000?keywords=kettle&th=1");
  assert.equal(c("https://www.youtube.com/watch?v=abc&si=XYZ&t=42"), "https://www.youtube.com/watch?v=abc&t=42", "si is share tracking on YouTube; t (timestamp) stays");
  assert.equal(c("https://x.com/u/status/1?s=20&t=abc"), "https://x.com/u/status/1");
  assert.equal(c("https://shop.example/p?s=20&t=abc&tag=red"), "https://shop.example/p?s=20&t=abc&tag=red", "generic names elsewhere are content");
  assert.equal(c("https://www.google.com/search?q=kettle&ei=abc&ved=0ah&oq=ket&sxsrf=x&start=10"), "https://www.google.com/search?q=kettle&start=10");
  assert.equal(c("https://app.example/cb?code=abc&state=xyz&utm_source=mail"), "https://app.example/cb?code=abc&state=xyz", "OAuth parameters stay");
  assert.equal(c("https://mail.example/unsub?mkt_tok=abc&_hsenc=1&_hsmi=2&utm_source=x"), "https://mail.example/unsub?mkt_tok=abc&_hsenc=1&_hsmi=2");
  assert.equal(c("https://bücher.example/?gclid=1&a=1"), "https://xn--bcher-kva.example/?a=1");
  assert.equal(c("https://news.example/a?UTM_SOURCE=x"), "https://news.example/a?UTM_SOURCE=x", "names are exact (DNR is case-sensitive here too)");
  assert.equal(c("https://news.example/a?utm%5Fsource=x&b=1"), "https://news.example/a?b=1", "an encoded name is still that name");
  for (const odd of ["javascript:alert(1)?utm_source=x", "mailto:a@b.example?utm_source=x", "not a url", ""]) assert.equal(c(odd), odd);
  assert.deepEqual(params.clean("https://news.example/a?id=1").removed, []);
  // Coverage the owner asked for.
  const g = new Set(params.GLOBAL);
  for (const n of ["utm_source", "mc_cid", "mc_eid", "pk_campaign", "piwik_campaign", "mtm_source", "hsa_cam", "oly_enc_id", "vero_id", "_openstat", "yclid", "ysclid",
    "gclid", "gclsrc", "gbraid", "wbraid", "dclid", "gad_source", "gad_campaignid", "fbclid", "msclkid", "twclid", "ttclid", "li_fat_id", "igshid", "igsh", "epik", "sccid",
    "rdt_cid", "irclickid", "srsltid", "_gl", "s_kwcid", "ef_id", "cmpid"]) assert.ok(g.has(n), n);
  for (const n of ["ref", "source", "src", "tag", "cid", "si", "s", "t", "id", "code", "state", "token", "session", "q", "page"]) assert.ok(!g.has(n), `${n} is not global`);
  for (const k of params.KEPT) for (const scope of params.SCOPED) assert.ok(!params.namesFor(scope.domains[0]).has(k), `${k} kept on ${scope.domains[0]}`);
});

test("link cleaner and DNR rules agree: every name the page cleaner removes has a navigation rule on the same sites", () => {
  const params = require("../../browser/core/params.js");
  const rules = dnr.compileParams();
  const fires = (url) => rules.some((r) => matches(r, {url, type: "main_frame"}));
  for (const name of params.GLOBAL) assert.ok(fires(`https://news.example/a?x=1&${encodeURIComponent(name).replace(/%5B/g, "[").replace(/%5D/g, "]")}=1`) || name.includes("["), name);
  for (const scope of params.SCOPED) for (const name of scope.params) {
    assert.ok(fires(`https://www.${scope.domains[0]}/p?${name}=1`), `${name} on ${scope.domains[0]}`);
  }
  assert.ok(!fires("https://github.com/o/r?ref=main"));
  assert.ok(fires("https://www.amazon.com/dp/B000/ref=sr_1_1"));
  const path = rules.find((r) => r.action.redirect.regexSubstitution);
  const out = "https://www.amazon.com/dp/B000/ref=sr_1_1?k=v".replace(new RegExp(path.condition.regexFilter), path.action.redirect.regexSubstitution.replace(/\\(\d)/g, "$$$1"));
  assert.equal(out, "https://www.amazon.com/dp/B000?k=v");
});

test("tracking cookies: analytics, ad and click-id cookies are removed; logins, carts, consent and preferences are not", () => {
  const cookies = require("../../browser/core/cookies.js");
  for (const name of ["_ga", "_ga_ABC123XYZ", "_gid", "_gat_UA-1", "_gcl_au", "_gcl_aw", "_gac_UA-1", "_fbp", "_fbc", "_uetsid", "_uetvid", "_uetmsclkid", "_ttp", "_scid",
    "_pin_unauth", "_hjSessionUser_123", "_hjid", "ajs_anonymous_id", "ajs_user_id", "mp_0123abcd_mixpanel", "amplitude_id_abc", "_clck", "_clsk", "li_fat_id",
    "IDE", "test_cookie", "_rdt_uuid", "_pk_id.1.abcd", "hubspotutk", "__hstc", "_epik", "__utma"]) assert.equal(cookies.classify(name), "remove", name);
  assert.equal(cookies.classify("MUID"), "session");
  for (const name of ["sessionid", "session", "csrftoken", "XSRF-TOKEN", "cart", "user_session", "_gh_sess", "OptanonConsent", "euconsent-v2", "CookieConsent", "theme",
    "prefs", "SID", "HSID", "__Secure-3PSID", "_gaz", "ga", "_g", "lang", "_shopify_y", "", null]) assert.equal(cookies.classify(name), null, String(name));
});

test("cookie and bounce rules: third-party tracker hosts and opaque redirectors lose cookies; the per-site brake lifts only cleaning", () => {
  const {cookies, bounce} = dnr.compilePrivacy({trackerDomains: ["metrics.vendor.example"], bounceDomains: ["click.shop.example"]});
  const brake = dnr.compileModes({cleanOff: ["braked.example"]}).rules;
  const filters = compileText("/collect?v=");
  const all = [...cookies, ...bounce, ...brake, ...filters, ...dnr.compileParams(), ...dnr.compileLinks(UNWRAP)];
  const strips = (req) => headerRules(all, req).some((r) => r.action.requestHeaders && r.action.requestHeaders[0].header === "cookie");
  assert.ok(strips({url: "https://www.facebook.com/plugins/like.php", initiator: "news.example", type: "sub_frame"}));
  assert.ok(strips({url: "https://metrics.vendor.example/p.js", initiator: "news.example", type: "script"}));
  assert.ok(!strips({url: "https://www.facebook.com/x", initiator: "www.facebook.com", type: "xmlhttprequest"}), "first party keeps its cookies");
  assert.ok(!strips({url: "https://accounts.google.com/gsi/iframe", initiator: "news.example", type: "sub_frame"}), "sign-in keeps its cookies");
  assert.ok(strips({url: "https://t.co/AbC", type: "main_frame"}), "bounce: t.co");
  assert.ok(strips({url: "https://click.shop.example/aff?id=1", type: "main_frame"}), "bounce: disguised click-through");
  assert.ok(!strips({url: "https://www.facebook.com/plugins/like.php", initiator: "braked.example", type: "sub_frame"}), "brake: cookies kept on that site");
  assert.equal(outcome(all, {url: "https://braked.example/a?utm_source=x", type: "main_frame"}), "allow", "brake: no parameter stripping on navigations to it");
  assert.equal(outcome(all, {url: "https://braked.example/collect?v=1", initiator: "braked.example", type: "ping"}), "block", "brake: URL filters still apply");
  assert.equal(outcome(all, {url: "https://other.example/a?utm_source=x", type: "main_frame"}), "redirect");
});

// ---- privacy signals ----
test("privacy rules: Sec-GPC everywhere above every allow; third-party beacons; Referrer-Policy only tightened", () => {
  const {gpc, referrer, beacons} = dnr.compilePrivacy();
  assert.equal(gpc[0].priority, dnr.PRIORITY.gpc);
  assert.deepEqual(gpc[0].action.requestHeaders, [{header: "sec-gpc", operation: "set", value: "1"}]);
  assert.ok(gpc[0].condition.resourceTypes.includes("main_frame"));
  const exc = dnr.compileUserState([], [{id: "e", site: "a.example", host: "a.example", path: "/x", type: "script", expiresAt: Date.now() + 60000}], Date.now()).rules;
  assert.equal(headerRules([...gpc, ...exc], {url: "https://a.example/x", initiator: "a.example", type: "script"}).length, 1, "an exception does not switch GPC off");
  const b = [...beacons];
  assert.equal(outcome(b, {url: "https://collector.example/e", initiator: "news.example", type: "ping"}), "block");
  assert.equal(outcome(b, {url: "https://news.example/e", initiator: "www.news.example", type: "ping"}), "none", "first-party beacons are left to the filters");
  const values = referrer[0].condition.responseHeaders[0].values;
  const re = (v) => new RegExp(`^${v.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`, "i");
  const fires = (header) => values.some((v) => re(v).test(header));
  for (const weak of ["unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin", "no-referrer, unsafe-url"]) assert.ok(fires(weak), weak);
  for (const strong of ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url, no-referrer", "origin"]) assert.ok(!fires(strong), strong);
});

// ---- site modes ----
test("site modes: Strict blocks third-party scripts, frames and fonts except functional providers; strips third-party cookies", () => {
  const {rules, kinds} = dnr.compileModes({sites: {"news.example": "strict"}, allowHosts: {"news.example": ["cdn.newsassets.example"]}});
  const req = (url, type, initiator = "www.news.example") => ({url, initiator, type});
  assert.equal(outcome(rules, req("https://widgets.vendor.example/w.js", "script")), "block");
  assert.equal(outcome(rules, req("https://embed.vendor.example/", "sub_frame")), "block");
  assert.equal(outcome(rules, req("https://fonts.vendor.example/a.woff2", "font")), "block");
  assert.equal(outcome(rules, req("https://img.vendor.example/a.png", "image")), "none", "images are not Strict's business");
  assert.equal(outcome(rules, req("https://static.news.example/app.js", "script")), "none", "first party");
  assert.equal(outcome(rules, req("https://cdn.newsassets.example/app.js", "script")), "none", "a host you allowed");
  for (const ok of ["https://js.stripe.com/v3/", "https://www.paypal.com/sdk/js", "https://challenges.cloudflare.com/turnstile/v0/api.js", "https://cdnjs.cloudflare.com/ajax/libs/x.js", "https://accounts.google.com/gsi/client"]) {
    assert.equal(outcome(rules, req(ok, "script")), "none", ok);
  }
  assert.equal(outcome(rules, req("https://widgets.vendor.example/w.js", "script", "other.example")), "none", "other sites stay Standard");
  const cookie = headerRules(rules, req("https://img.vendor.example/a.png", "image"));
  assert.ok(cookie.some((r) => r.action.requestHeaders && r.action.requestHeaders[0].header === "cookie"));
  assert.ok(!headerRules(rules, req("https://js.stripe.com/v3/", "script")).length, "payment providers keep their cookies");
  for (const id of Object.keys(kinds)) assert.ok(rules.some((r) => String(r.id) === id));
  assert.ok(Object.values(kinds).includes("strict"));
});

test("site modes: No scripts blocks every script of the site and adds script-src 'none'; Strict as default spares sites set otherwise", () => {
  const {rules} = dnr.compileModes({defaultMode: "strict", sites: {"reader.example": "noscript", "app.example": "standard"}});
  assert.equal(outcome(rules, {url: "https://reader.example/app.js", initiator: "reader.example", type: "script"}), "block");
  assert.ok(rules.some((r) => r.action.type === "modifyHeaders" && r.action.responseHeaders && r.action.responseHeaders[0].value === "script-src 'none'" && r.condition.requestDomains.includes("reader.example")));
  assert.equal(outcome(rules, {url: "https://vendor.example/w.js", initiator: "any.example", type: "script"}), "block", "Strict by default");
  assert.equal(outcome(rules, {url: "https://vendor.example/w.js", initiator: "app.example", type: "script"}), "none", "a site set to Standard");
  assert.equal(outcome(rules, {url: "https://m.stripe.network/inner.js", initiator: "js.stripe.com", type: "script"}), "none", "functional providers' own frames are not held to Strict");
  for (const r of rules) assert.ok(r.priority === dnr.PRIORITY.mode || r.priority === dnr.PRIORITY.relax);
  assert.deepEqual(dnr.compileModes({sites: {"co.uk": "noscript", "x.example": "bogus"}}).rules, [], "invalid sites and modes compile to nothing");
});

test("click-to-load: a held embed loads for one tab after a click; the session rule beats Strict only", () => {
  const {rules} = dnr.compileModes({sites: {"news.example": "strict"}});
  const allow = dnr.embedRule(300000, "youtube", 7);
  const all = [...rules, allow];
  const req = (tabId) => ({url: "https://www.youtube.com/embed/abc", initiator: "www.news.example", type: "sub_frame", tabId});
  assert.equal(outcome(all, req(7)), "allow");
  assert.equal(outcome(all, req(8)), "block");
  assert.ok(allow.priority < dnr.PRIORITY.threat);
  assert.throws(() => dnr.embedRule(1, "nope", 1));
});

// ---- surrogates ----
test("surrogates: known tracker scripts redirect to bundled stubs that exist and make no requests", () => {
  const rules = dnr.compileSurrogates();
  const list = dnr.compileList("trackers", ["google-analytics.com", "googletagmanager.com"]).rules;
  const all = [...rules, ...list];
  assert.equal(outcome(all, {url: "https://www.google-analytics.com/analytics.js", initiator: "a.example", type: "script"}), "redirect");
  assert.equal(outcome(all, {url: "https://www.google-analytics.com/g/collect?v=2", initiator: "a.example", type: "ping"}), "block");
  for (const s of dnr.SURROGATES) {
    const code = fs.readFileSync(path.join(root, "browser/surrogates", s.file), "utf8");
    assert.doesNotMatch(code, /fetch|XMLHttpRequest|sendBeacon|WebSocket|Image\(|createElement|document\.cookie|localStorage|https?:/, s.file);
  }
});

test("surrogates run: the APIs pages call exist, callbacks fire, queued commands drain", async () => {
  const vm = require("node:vm");
  const run = (file, window) => { const ctx = vm.createContext({window, setTimeout, Array, Object}); window.window = window; vm.runInContext(`with (window) {${fs.readFileSync(path.join(root, "browser/surrogates", file), "utf8")}}`, ctx); return window; };
  const tick = () => new Promise((r) => setTimeout(r, 5));
  let called = 0;
  const w1 = run("google-tag-manager.js", {dataLayer: [{event: "x", eventCallback: () => called++}]});
  w1.dataLayer.push({event: "click", eventCallback: () => called++});
  w1.gtag("event", "purchase", {event_callback: () => called++});
  await tick();
  assert.equal(called, 3);
  const w2 = run("google-analytics.js", {ga: Object.assign(() => {}, {q: [["send", "pageview", {hitCallback: () => called++}]]})});
  w2.ga("send", "event", {hitCallback: () => called++});
  await tick();
  assert.equal(called, 5);
  const w3 = run("google-publisher-tag.js", {googletag: {cmd: [() => called++]}});
  w3.googletag.cmd.push(() => { called++; w3.googletag.defineSlot("/1/x", [300, 250], "div-1").addService(w3.googletag.pubads()).setTargeting("a", "b"); w3.googletag.enableServices(); w3.googletag.display("div-1"); });
  assert.equal(called, 7);
  const w4 = run("segment.js", {analytics: [["track", "x"]]});
  w4.analytics.ready(() => called++);
  w4.analytics.track("y", {}, () => called++);
  await tick();
  assert.equal(called, 9);
  const w5 = run("meta-pixel.js", {});
  w5.fbq("track", "PageView");
  const w6 = run("adobe-launch.js", {});
  w6._satellite.track("x");
  assert.equal(typeof w6.s_gi("x").t, "function");
});

test("categories: every block-capable ruleset has a popup label; header and allow rulesets are quiet", () => {
  for (const id of ["threats", "threats-2", "trackers", "cname", "fp-trackers", "easyprivacy", "easylist", "replay", "beacons", "links", "surrogates"]) {
    const cat = dnr.categoryOf(id);
    assert.ok(cat && dnr.CATEGORIES[cat].label, id);
  }
  for (const id of ["params", "gpc", "referrer", "filter-allow"]) assert.equal(dnr.categoryOf(id), null, id);
});
