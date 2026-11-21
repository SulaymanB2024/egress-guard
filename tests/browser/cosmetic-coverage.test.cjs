"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const compiler = require("../../scripts/lib/cosmetic-compiler.cjs");
const C = require("../../browser/core/cosmetic.js");
const S = require("../../browser/core/cosmetic-selectors.js");
const manual = require("../../browser/core/selectors.js");
const H = require("./content-harness.cjs");
const build = (...lines) => compiler.compileCosmetics([lines.join("\n")]);
const genericPage = (options) => H.content({generic: true, semantic: false, ...options});
const mutate = (p, target, type = "attributes", more = {}) => { p.t.emit([{type, target, ...more}]); p.t.flush(); };

test("imported native relations stay bounded and cannot change manual-rule grammar", () => {
  for (const selector of [
    ".ad-shell:has(> .ad-marker)", ".ad-shell:has(+ .ad-marker)",
    '.ad-shell:not(.organic):has(.ad-marker, a[href^="/paid/"])',
    ".ad-shell:has(.one):has(.two)",
  ]) {
    assert.equal(S.validateSelector(selector).ok, true, selector);
    assert.equal(S.validateSelector(selector).relational, true);
    assert.equal(manual.validateSelector(selector).ok, false, "manual rules did not gain :has authority");
  }
  for (const selector of [
    "div:has(.ad-marker)", "body:has(.ad-marker)", ".ad:has(.a:has(.b))",
    ".ad:not(:has(.organic))", ".ad:has(.a):has(.b):has(.c)",
    ".ad:has(.a .b .c .d)", ".ad:has(.a,.b,.c)", ".ad:has-text(Sponsored)",
    ".ad:has(.a){display:none}", ".ad:has(.a),body", ".ad:has(script[src])",
    '.ad:has([style="display:none"])', ".ad:has(.a):remove()", ".ad:has(> )",
  ]) assert.equal(S.validateSelector(selector).ok, false, selector);
});

test("cosmetic entity scopes use prevailing PSL boundaries, not string substrings", () => {
  for (const host of ["google.com", "www.google.co.uk", "images.google.com.br"]) assert.equal(C.matchesScope(host, "google.*"), true, host);
  assert.equal(C.matchesScope("www.google.co.uk", "www.google.*"), true);
  for (const host of ["google.evil.biz", "evilgoogle.com", "www.google.com.evil.biz", "google.computer"]) {
    assert.equal(C.matchesScope(host, "www.google.*"), false, host);
  }
  assert.equal(C.matchesScope("tenant.github.io", "github.*"), false, "private suffix is not an entity prefix");
  assert.equal(C.matchesScope("tenant.s3.amazonaws.com", "amazonaws.*"), false);
  assert.equal(C.matchesScope("tenant.github.io", "tenant.*"), true, "an explicit lexical entity can match a private tenant; it grants no network authority");
  assert.equal(C.matchesScope("city.kawasaki.jp", "city.*"), true, "PSL exception");
  assert.equal(C.matchesScope("foo.bar.kawasaki.jp", "foo.*"), true, "PSL wildcard");
  const data = build("google.*,~accounts.google.*##.ad-card");
  assert.equal(C.scopedRules("www.google.co.uk", data).length, 1);
  assert.equal(C.scopedRules("accounts.google.co.uk", data).length, 0);
  assert.equal(C.scopedRules("google.evil.biz", data).length, 0);
});

test("simple generic indices honor identical-selector and negative-scope exceptions", () => {
  const data = build("##.ad-card", "##.global-ad", "#@#.global-ad", "publisher.example#@#.ad-card", "~safe.example##.promo-card", "##.unsupported > .child");
  assert.equal(data.stats.generic, 3);
  assert.equal(data.stats.dropped["unsupported-generic-selector"], 1);
  const pub = C.genericIndex("publisher.example", "https://publisher.example/", data);
  assert.deepEqual(C.genericMatches(pub, "", ["ad-card", "global-ad", "promo-card"]).map((r) => r.selector), [".promo-card"]);
  const safe = C.genericIndex("safe.example", "https://safe.example/", data);
  assert.deepEqual(C.genericMatches(safe, "", ["ad-card", "global-ad", "promo-card"]).map((r) => r.selector), [".ad-card"]);
  assert.equal(C.genericMatches(safe, "", ["not-ad-card"]).length, 0);
});

test("page compatibility exemptions use bounded URL syntax and never grant a network allow", () => {
  const data = build("##.generic-ad", "publisher.example##.specific-ad", "@@||publisher.example/private*$generichide", "@@||publisher.example/account^$elemhide");
  const privatePage = C.genericIndex("publisher.example", "https://publisher.example/private/settings", data);
  assert.equal(privatePage.rules.size, 0);
  assert.deepEqual(privatePage.policy.sourceExemptions, ["generic"]);
  assert.deepEqual(privatePage.policy.degradedFamilies, [], "a source compatibility exception is not an application failure");
  assert.equal(C.scopedRules("publisher.example", data, 200, "https://publisher.example/private/settings").length, 1);
  assert.equal(C.scopedRules("publisher.example", data, 200, "https://publisher.example/account/home").length, 0);
  assert.equal(C.genericIndex("publisher.example", "https://publisher.example/articles", data).rules.size, 1);
  const host = C.patternProgram("||example.com^");
  assert.equal(C.matchesPattern(host, "https://sub.example.com:8443/page"), true);
  assert.equal(C.matchesPattern(host, "https://example.com.evil.test/page"), false);
  assert.equal(C.matchesPattern(host, "https://evil.test/example.com/page"), false);
  assert.equal(C.matchesPattern(C.patternProgram("||www.google.*/search?"), "https://www.google.co.uk/search?q=private"), true);
  assert.equal(C.matchesPattern(C.patternProgram("|https://example.com/exact|"), "https://example.com/exact?x=1"), false);
  assert.equal(C.matchesPattern(C.patternProgram("*a".repeat(8) + "z"), "a".repeat(4096)), false, "wildcard failure is finite-state, not regex backtracking");
  assert.equal(C.matchesPattern(host, "https://example.org/" + "x".repeat(8192)), true, "oversized URLs retain the exemption conservatively");
  assert.equal(C.patternProgram("/(a+)+$/"), null);
  assert.equal(C.patternProgram("*".repeat(9)), null);
  assert.ok(data.hideExceptions.every((r) => !r.action && !r.requestDomains), "cosmetic exemptions cannot become DNR permissions");
});

test("unsupported exceptions conservatively quarantine the selector or imported family", () => {
  const selectorData = build("##.ad-card", "publisher.example##.ad-card", "bad.*.scope#@#.ad-card", "##.other-ad");
  assert.deepEqual(selectorData.fallback.selectors, [".ad-card"]);
  assert.equal(selectorData.stats.fallbacks["suppress-excepted-selector"], 1);
  assert.equal(C.genericIndex("publisher.example", "https://publisher.example/", selectorData).rules.size, 1);
  assert.equal(C.scopedRules("publisher.example", selectorData).length, 0);
  const familyData = build("##.generic-ad", "publisher.example##.specific-ad", "@@||publisher.example^$generichide,third-party");
  assert.equal(familyData.fallback.generic, true);
  assert.equal(familyData.fallback.scoped, false);
  assert.equal(C.genericIndex("publisher.example", "https://publisher.example/", familyData).rules.size, 0);
  assert.equal(C.scopedRules("publisher.example", familyData).length, 1);
  assert.equal(build("@@||publisher.example^$generichide=unknown").fallback.generic, true);
  const suffixException = build("##.ad-card", "gov.uk#@#.ad-card");
  assert.equal(C.genericIndex("service.gov.uk", "https://service.gov.uk/", suffixException).rules.size, 0, "public suffixes can narrow hiding through an exemption only");
  assert.equal(build("gov.uk##.ad-card").rules.length, 0);
});

test("URL exception matching shares a hard operation budget across the page policy", () => {
  const expensive = Array.from({length: 12}, (_, i) => `@@||publisher.example/${"*a".repeat(8)}z${i}$generichide`);
  const data = build("##.generic-ad", "publisher.example##.site-ad", ...expensive);
  const url = "https://publisher.example/" + "a".repeat(4000);
  const policy = C.importPolicy("publisher.example", url, data);
  assert.equal(policy.exceptionBudgetExhausted, true);
  assert.ok(policy.exceptionSteps <= C.MAX_EXCEPTION_STEPS);
  assert.equal(policy.generic, false, "an unproved exemption disables its family");
  assert.deepEqual(policy.degradedFamilies, ["generic"]);
  assert.equal(policy.scoped, true, "unaffected scoped rules remain available");
  assert.match(policy.reasons.join(" "), /work budget exhausted/);
  assert.equal(C.scopedRules("publisher.example", data, 200, url, policy).length, 1);
});

test("13,000 generic rules are token lookups, not per-selector DOM queries", async () => {
  const data = build(...Array.from({length: 13000}, (_, i) => `##.indexed-ad-${i}`));
  const p = await genericPage({data, markup: '<div id="target" class="indexed-ad-12999">Paid placement</div><article id="organic" class="indexed-ad-12999-ish">Ordinary article</article>'});
  assert.equal(p.api.status().imported.genericRules, 13000);
  assert.equal(p.hidden("target"), true);
  assert.equal(p.hidden("organic"), false);
  let indexedQueries = 0;
  const query = p.doc.querySelectorAll;
  p.doc.querySelectorAll = function (selector) { if (selector.includes("indexed-ad-")) indexedQueries++; return query.call(this, selector); };
  const late = p.doc.createElement("div"); late.id = "late"; late.className = "indexed-ad-12345"; late.textContent = "Advertisement"; p.doc.body.append(late);
  mutate(p, p.doc.body, "childList", {addedNodes: [late]});
  assert.equal(p.hidden("late"), true);
  assert.equal(indexedQueries, 0);
  assert.ok(p.api.status().imported.visited < 100, "discovery scales with fixture nodes, not rule count");
});

test("generic matching protects form/editor ancestry and revalidates existing nodes", async () => {
  const data = build("##.indexed-ad");
  const p = await genericPage({data, markup: '<div id="ad" class="indexed-ad">Ad</div><form><div id="form-label" class="indexed-ad">Required field instructions</div></form><div contenteditable="true"><span id="edit" class="indexed-ad">Draft</span></div><div id="player" class="indexed-ad"><video></video></div>'});
  assert.equal(p.hidden("ad"), true);
  for (const id of ["form-label", "edit", "player"]) assert.equal(p.hidden(id), false, id);
  const ad = p.doc.getElementById("ad"); ad.className = "organic"; mutate(p, ad);
  assert.equal(p.hidden("ad"), false);
  ad.className = "indexed-ad"; mutate(p, ad); assert.equal(p.hidden("ad"), true);
  const input = p.doc.createElement("input"); ad.append(input); mutate(p, ad, "childList", {addedNodes: [input]});
  assert.equal(p.hidden("ad"), false, "a new protected descendant releases a prior generic hide");
});

test("generic traversal yields, finishes later and keeps independent per-selector bounds", async () => {
  const data = build("##.indexed-ad", "##.later-ad");
  const markup = Array.from({length: 400}, (_, i) => `<div id="row-${i}" class="${i < 30 ? "indexed-ad" : "ordinary"}">row</div>`).join("") + '<div id="late" class="later-ad">Paid placement</div>';
  const p = await genericPage({data, markup});
  assert.equal(p.api.status().workPending, true);
  assert.equal(p.hidden("late"), false, "later DOM is not traversed in the initial bounded task");
  p.t.flush();
  assert.equal(p.hidden("late"), true);
  assert.equal(p.api.status().hidden, 26, "25 records for one selector do not stop another selector");
  assert.ok(p.api.status().imported.limits.includes("per-selector-records"));
  assert.equal(p.api.status().workPending, false);
  for (let i = 0; i < 100; i++) mutate(p, p.doc.body, "childList");
  assert.equal(p.hidden("row-0"), true, "busy-page limits do not restore existing hides");
});

test("generic Show, Pause, Restore and resumed discovery preserve reversible controls", async () => {
  const p = await genericPage({data: build("##.indexed-ad"), markup: '<div id="ad" class="indexed-ad" style="display:grid!important">Placement</div>'});
  const placeholder = H.walk(p.doc, (n) => n.localName === "egress-guard-hidden")[0];
  const button = H.walk(placeholder.shadowRoot, (n) => n.localName === "button")[0];
  H.userClick(button);
  assert.equal(p.doc.getElementById("ad").style.getPropertyValue("display"), "grid");
  mutate(p, p.doc.body, "childList"); assert.equal(p.hidden("ad"), false, "Show survives later scans");
  await p.send({type: "restore-page"}); await p.send({type: "resume"}); p.t.flush();
  assert.equal(p.hidden("ad"), true);
  await p.send({type: "generic", on: false}); assert.equal(p.hidden("ad"), false);
  await p.send({type: "generic", on: true}); p.t.flush(); assert.equal(p.hidden("ad"), true);
});

test("SPA URL exceptions release imported records and reapply only after the exception ends", async () => {
  const p = await genericPage({data: build("##.indexed-ad", "publisher.example##.site-ad", "@@||publisher.example/private*$generichide"), markup: '<div id="generic" class="indexed-ad">Ad</div><div id="specific" class="site-ad">Site ad</div>'});
  assert.equal(p.hidden("generic"), true); assert.equal(p.hidden("specific"), true);
  p.ctx.location.href = "https://publisher.example/private/inbox";
  await p.send({type: "page-location"}); p.t.flush();
  assert.equal(p.hidden("generic"), false); assert.equal(p.hidden("specific"), true);
  assert.equal(p.api.status().imported.genericEnabled, false);
  p.ctx.location.href = "https://publisher.example/articles";
  await p.send({type: "page-location"}); p.t.flush();
  assert.equal(p.hidden("generic"), true);
});

test("a semantic scan cannot consume an SPA URL change before cosmetic exceptions refresh", async () => {
  const p = await H.content({generic: true, semantic: true,
    data: build("##.indexed-ad", "@@||publisher.example/ad-free$generichide"),
    markup: '<div id="ad" class="indexed-ad">An advertising placement</div><div class="ordinary">An ordinary article</div>'});
  assert.equal(p.hidden("ad"), true);
  p.ctx.location.href = "https://publisher.example/ad-free";
  const batch = p.api.semanticCandidates();
  assert.equal(batch.ok, true);
  assert.equal(batch.disabledReason, undefined, "use a public route that the sensitive-page gate does not exclude");
  await p.send({type: "page-location"}); p.t.flush();
  assert.equal(p.hidden("ad"), false);
  assert.equal(p.api.status().imported.genericEnabled, false);
  assert.deepEqual(Array.from(p.api.status().imported.sourceExemptions), ["generic"]);
});

test("native relational fixtures update outer targets after deep descendants change", async () => {
  const selector = '.ad-shell:has(.ad-disclosure[data-paid="yes"])';
  const oracle = (node) => node.classList.includes("ad-shell") && H.walk(node, (n) => n.classList.includes("ad-disclosure") && n.getAttribute("data-paid") === "yes").length > 0;
  const p = await genericPage({data: build(`publisher.example##${selector}`), nativeSelectors: {[selector]: oracle}, markup: '<section id="shell" class="ad-shell"><div><div><div><span id="label" class="ad-disclosure" data-paid="no">Sponsored</span></div></div></div></section>'});
  assert.equal(p.hidden("shell"), false);
  assert.ok(p.t.observers.some((o) => o.options.attributeFilter.includes("data-paid")));
  const label = p.doc.getElementById("label"); label.setAttribute("data-paid", "yes"); mutate(p, label);
  assert.equal(p.hidden("shell"), true, "an outer target outside the immediate dirty subtree is reevaluated");
  label.setAttribute("data-paid", "no"); mutate(p, label);
  assert.equal(p.hidden("shell"), false);
});

test("native sibling relations and protected insertions are rechecked", async () => {
  const selector = ".ad-shell:has(+ .ad-note)";
  const oracle = (node) => { const siblings = node.parentElement ? node.parentElement.children : []; return node.classList.includes("ad-shell") && Boolean(siblings[siblings.indexOf(node) + 1]?.classList.includes("ad-note")); };
  const p = await genericPage({data: build(`publisher.example##${selector}`), nativeSelectors: {[selector]: oracle}, markup: '<div id="shell" class="ad-shell">Ad</div><span id="note" class="ordinary">Disclosure</span>'});
  const note = p.doc.getElementById("note"); note.className = "ad-note"; mutate(p, note); assert.equal(p.hidden("shell"), true);
  const form = p.doc.createElement("form"), shell = p.doc.getElementById("shell"); shell.append(form); mutate(p, shell, "childList", {addedNodes: [form]});
  assert.equal(p.hidden("shell"), false);
});

test("generic depth and per-node token bounds are explicit, not silent global shutdowns", async () => {
  const classes = Array.from({length: 32}, (_, i) => `ordinary-${i}`).concat("indexed-ad").join(" ");
  const deep = "<div>".repeat(70) + '<div id="deep" class="indexed-ad">Deep ad</div>' + "</div>".repeat(70);
  const p = await genericPage({data: build("##.indexed-ad"), markup: `<div id="many" class="${classes}">Many tokens</div>${deep}<div id="normal" class="indexed-ad">Ad</div>`});
  p.t.flush();
  assert.equal(p.hidden("many"), false); assert.equal(p.hidden("deep"), false); assert.equal(p.hidden("normal"), true);
  assert.ok(p.api.status().imported.limits.includes("class-tokens"));
  assert.ok(p.api.status().imported.limits.includes("subtree-depth"));
  assert.equal(p.api.status().paused, false);
});
