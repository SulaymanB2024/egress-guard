"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const {content, guard, event, walk, settle, read, vm} = require("./content-harness.cjs");
const cosmetic = require("../../browser/core/cosmetic.js"), semantic = require("../../browser/core/semantic.js");
const rule = (selector) => ({id: "custom", kind: "cosmetic", site: "publisher.example", selector});
const feed = `<section id="feed"><article id="paid" class="card"><span>Sponsored</span><a href="/product">A useful product from a paid advertiser</a></article><article id="organic" class="card"><h2>Sponsored content explained</h2><a href="/article">An ordinary article about online advertising</a></article></section>`;

test("busy unrelated mutations keep hides and settle without manual Resume", async () => {
  const p = await content({markup: '<div id="ad" class="paid-card">Ad</div><span id="ticker">0</span>', rules: [rule(".paid-card")]});
  for (let i = 0; i < 100; i++) {
    p.doc.getElementById("ticker").className = `tick-${i}`;
    p.t.emit([{type: "attributes", target: p.doc.getElementById("ticker"), attributeName: "class"}]); p.t.advance(175);
    assert.equal(p.hidden("ad"), true);
    assert.equal(p.api.status().paused, false);
  }
  p.t.flush(); assert.equal(p.api.status().workPending, false);
  const fresh = p.doc.createElement("div"); fresh.id = "new"; fresh.className = "paid-card"; p.doc.body.append(fresh);
  p.t.emit([{type: "childList", target: p.doc.body, addedNodes: [fresh]}]); p.t.flush();
  assert.equal(p.hidden("new"), true);
});

test("hidden nodes are released on protected content, editability, and focus changes", async () => {
  for (const change of ["form", "editable", "focus"]) {
    const p = await content({markup: '<div id="ad" class="paid-card">Ad</div>', rules: [rule(".paid-card")]});
    const n = p.doc.getElementById("ad"); assert.equal(p.hidden("ad"), true);
    if (change === "form") n.append(p.doc.createElement("form"));
    if (change === "editable") n.setAttribute("contenteditable", "true");
    if (change === "focus") { n.focus(); n.dispatchEvent(event("focusin")); }
    p.t.emit([{type: "attributes", target: n, attributeName: "contenteditable"}]); p.t.flush();
    assert.equal(p.hidden("ad"), false, change);
  }
});

test("picker uses the selected card and refuses a shared-attribute generalization", async () => {
  const p = await content({markup: '<div id="chosen" class="card" data-kind="sponsored">Ad</div><div class="card" data-kind="organic">Organic</div>'});
  assert.equal(p.api.proposal(p.doc.getElementById("chosen")).count, 1);
  p.doc.getElementById("chosen").removeAttribute("id");
  const chosen = p.doc.body.children[0];
  assert.equal(p.api.proposal(chosen).selector, 'div.card[data-kind="sponsored"]');
  chosen.setAttribute("data-kind", ""); p.doc.body.children[1].setAttribute("data-kind", "");
  assert.equal(p.api.proposal(chosen, {positional: false}), null);
});

test("deterministic native-ad recognition hides disclosed cards, keeps an article about ads, and supports undo", async () => {
  const p = await content({markup: feed, generic: true}); p.t.flush();
  assert.equal(p.hidden("paid"), true);
  assert.equal(p.hidden("organic"), false);
  assert.equal(p.api.status().semantic.hidden, 1);
  p.api.semanticRestore(); assert.equal(p.hidden("paid"), false);
  p.t.emit([{type: "childList", target: p.doc.body, addedNodes: []}]); p.t.flush();
  assert.equal(p.hidden("paid"), false, "undo prevents automatic rediscovery this page load");
});

test("the built-in hiding switch used by site Pause releases native semantic records", async () => {
  const p = await content({markup: feed, generic: true}); p.t.flush();
  assert.equal(p.hidden("paid"), true);
  p.api.setGeneric(false); p.t.flush(); assert.equal(p.hidden("paid"), false);
  p.api.setGeneric(true); p.t.flush(); assert.equal(p.hidden("paid"), true);
});

test("an exact Sponsored word nested inside a headline is not a paid disclosure", async () => {
  const markup = '<section><article id="headline" class="card"><div><h2><span>Sponsored</span></h2></div><a href="/story">An article about the advertising industry</a></article><article id="other" class="card"><a href="/other">A second ordinary news story</a></article></section>';
  const p = await content({markup, generic: true}); p.t.flush();
  assert.equal(p.hidden("headline"), false); assert.equal(p.hidden("other"), false);
});

test("a mixed sponsored/organic column is never the semantic hide unit", async () => {
  const markup = '<section><div class="column" id="mixed"><article class="card" id="paid"><span>Sponsored</span><a href="/offer">The paid advertiser offer</a></article><article class="card" id="organic"><a href="/news">The ordinary editorial article</a></article></div><div class="column" id="other"><a href="/more">Another ordinary editorial column</a></div></section>';
  const p = await content({markup, generic: true}); p.t.flush();
  assert.equal(p.hidden("mixed"), false); assert.equal(p.hidden("organic"), false); assert.equal(p.hidden("other"), false); assert.equal(p.hidden("paid"), true);
  const review = await content({markup});
  const cards = review.api.semanticCandidates().candidates;
  assert.ok(cards.every((c) => c.structure.nestedCards === 0));
});

test("candidate IDs bind explicit labels to one snapshot and current safe nodes", async () => {
  const p = await content({markup: feed});
  const snapshot = p.api.semanticCandidates();
  assert.equal(snapshot.candidates.length, 2);
  const paid = snapshot.candidates.find((c) => c.classification === "paid-placement"); assert.ok(paid);
  assert.ok(!JSON.stringify(snapshot).includes("https://"), "no page or destination URL values exported");
  let applied = p.api.semanticApply({...snapshot, labels: [{id: paid.id, category: "paid-placement", selector: "body"}]});
  assert.equal(applied.ok, false); assert.equal(p.hidden("paid"), false);
  applied = p.api.semanticApply({...snapshot, labels: [{id: paid.id, category: "paid-placement"}]});
  assert.equal(applied.applied, 1); assert.equal(p.hidden("organic"), false);
  p.api.semanticRestore(); assert.equal(p.hidden("paid"), false);
  assert.equal(p.api.semanticApply({...snapshot, labels: [{id: paid.id, category: "paid-placement"}]}).ok, false);
});

test("semantic hides survive unrelated siblings but release changed structure even with identical text", async () => {
  const p = await content({markup: feed});
  const s = p.api.semanticCandidates(), paid = s.candidates.find((c) => c.classification === "paid-placement");
  p.api.semanticApply({...s, labels: [{id: paid.id, category: "paid-placement"}]});
  const sibling = p.doc.createElement("article"); sibling.className = "card"; sibling.textContent = "A new ordinary card";
  p.doc.getElementById("feed").append(sibling);
  p.t.emit([{type: "childList", target: p.doc.getElementById("feed"), addedNodes: [sibling]}]); p.t.flush();
  assert.equal(p.hidden("paid"), true);
  const card = p.doc.getElementById("paid"), label = card.children[0], headline = p.doc.createElement("h2"); headline.textContent = label.textContent;
  label.before(headline); label.remove();
  p.t.emit([{type: "childList", target: card, addedNodes: [headline], removedNodes: [label]}]); p.t.flush();
  assert.equal(p.hidden("paid"), false);
});

test("stale semantic cards, navigation, unknown IDs and protected commerce cannot be hidden", async () => {
  const p = await content({markup: feed});
  let s = p.api.semanticCandidates(), c = s.candidates[0];
  p.doc.getElementById("paid").append(p.doc.createElement("form"));
  let r = p.api.semanticApply({...s, labels: [{id: c.id, category: "paid-placement"}]});
  assert.equal(r.applied, 0); assert.equal(p.hidden("paid"), false);
  r = p.api.semanticApply({...s, labels: [{id: "invented", category: "paid-placement"}]});
  assert.equal(r.applied, 0);
  s = p.api.semanticCandidates(); c = s.candidates.find((v) => v.classification === "essential-commerce"); assert.ok(c); assert.equal("text" in c, false);
  r = p.api.semanticApply({...s, labels: [{id: c.id, category: "paid-placement"}]}); assert.equal(r.applied, 0);
  p.ctx.location.href = "https://publisher.example/another-page";
  r = p.api.semanticApply({...s, labels: [{id: s.candidates[1].id, category: "paid-placement"}]}); assert.equal(r.applied, 0);
  const sensitive = await content({markup: feed, href: "https://publisher.example/inbox"});
  assert.equal(sensitive.api.semanticCandidates().candidates.length, 0);
  assert.ok(sensitive.api.semanticCandidates().disabledReason);
});

test("semantic structure requires disclosure, linked repeated cards and protected-content precedence", () => {
  const c = {disclosures: ["Sponsored"], structure: {hasLink: true, repeatedPeers: 2, textLength: 80}};
  assert.equal(semantic.classify(c).category, "paid-placement");
  assert.equal(semantic.classify({...c, disclosures: ["This article explains sponsored posts"]}).category, "uncertain");
  assert.equal(semantic.classify({...c, protected: true}).category, "essential-commerce");
  assert.equal(semantic.classify({...c, structure: {...c.structure, repeatedPeers: 0}}).category, "uncertain");
});

test("medical and patient paths refuse candidate extraction; private-app gates and redaction are conservative", async () => {
  for (const pathname of ["/patient/results", "/patients/1", "/medical/summary", "/health-records/record", "/healthrecord/123", "/patient-portal/home", "/prescriptions", "/appointments/next"]) {
    const p = await content({markup: feed, generic: true, href: `https://publisher.example${pathname}`});
    assert.ok(p.api.semanticCandidates().disabledReason, pathname);
    assert.equal(p.hidden("paid"), false, "automatic semantic detection also stands down");
  }
  assert.equal(semantic.sensitiveLocation("https://workspace.slack.com/client/channels"), true);
  const redacted = semantic.sanitizeText("Write to person@example.org or https://example.org/token/1234 with abcdef0123456789abcdef0123456789abcd");
  assert.ok(!redacted.includes("person@example.org")); assert.ok(!redacted.includes("https://")); assert.ok(!redacted.includes("abcdef0123"));
});

test("domain cosmetic data respects identical exceptions and refuses partial invalid scopes", async () => {
  const r = {include: ["publisher.example"], exclude: [], selector: ".slot"};
  const data = {schema: 1, rules: [r, {...r, selector: ".other", include: ["publisher.example", "not a domain"]}], exceptions: []};
  assert.equal(cosmetic.scopedRules("publisher.example", data).length, 1);
  assert.equal(cosmetic.scopedRules("elsewhere.example", data).length, 0);
  assert.equal(cosmetic.scopedRules("publisher.example", {...data, exceptions: [{...r, include: []}]}).length, 0);
  const p = await content({markup: '<div id="slot" class="slot">Ad</div><div id="protected" class="slot"><form>Keep checkout</form></div>', generic: true, data});
  p.t.flush(); assert.equal(p.hidden("slot"), true); assert.equal(p.hidden("protected"), false);
  p.api.setGeneric(false); p.t.flush(); assert.equal(p.hidden("slot"), false);
});

test("Chrome generic styles use a fixed worker operation without a DOM-visible stylesheet", async () => {
  const p = await content({markup: "<p>Article</p>", generic: true, chrome: true});
  assert.equal(p.doc.querySelectorAll("style[data-eg-page-ui]").length, 0);
  assert.deepEqual(p.messages.filter((m) => m.type === "cosmetic-style").map((m) => ({...m})), [{type: "cosmetic-style", on: true}]);
  assert.equal(p.api.status().generic.on, true);
  p.api.setGeneric(false); await settle(); assert.equal(p.api.status().generic.on, false);
});

test("a failed Chrome stylesheet receipt is retried by a later policy broadcast", async () => {
  const p = await content({markup: "<p>Article</p>", generic: true, chrome: true, styleFailures: 1});
  assert.equal(p.api.status().generic.on, false); assert.ok(p.api.status().generic.error);
  p.api.setRules([]); await settle();
  assert.equal(p.api.status().generic.on, true); assert.equal(p.api.status().generic.error, null); assert.equal(p.api.status().generic.pending, false);
});

test("late scripted embeds get a load control, and retried scripts retain security and execution attributes", async () => {
  const g = await guard("<p>Initial page</p>");
  const block = g.doc.createElement("blockquote"); block.className = "twitter-tweet"; g.doc.body.append(block);
  const script = g.doc.createElement("script");
  for (const [k, v] of Object.entries({src: "https://platform.twitter.com/widgets.js", integrity: "sha384-fixture", crossorigin: "anonymous", referrerpolicy: "no-referrer", type: "module", nonce: "fixture-nonce"})) script.setAttribute(k, v);
  script.async = false; g.doc.head.append(script);
  g.t.emit([{type: "childList", target: g.doc.body, addedNodes: [block]}, {type: "childList", target: g.doc.head, addedNodes: [script]}]); g.t.flush();
  const box = g.doc.querySelector("[data-eg-embed]"); assert.ok(box);
  walk(box.shadowRoot, (n) => n.localName === "button")[0].dispatchEvent(event("click")); await settle();
  const replacement = g.doc.querySelector("script[src]"); assert.notEqual(replacement, script);
  for (const name of ["integrity", "crossorigin", "referrerpolicy", "type", "nonce"]) assert.equal(replacement.getAttribute(name), script.getAttribute(name), name);
  assert.equal(replacement.async, false);
  assert.equal(g.messages.filter((m) => m.type === "load-embed").length, 1);
});

test("changed held script and frame sources do not activate stale resources", async () => {
  const g = await guard('<blockquote class="twitter-tweet">Tweet</blockquote><script src="https://platform.twitter.com/widgets.js" integrity="sha384-original"></script>');
  const oldBox = g.doc.querySelector("[data-eg-embed]"); assert.ok(oldBox);
  g.doc.querySelector("script[src]").setAttribute("integrity", "sha384-changed");
  walk(oldBox.shadowRoot, (n) => n.localName === "button")[0].dispatchEvent(event("click")); await settle();
  assert.equal(g.messages.filter((m) => m.type === "load-embed").length, 0);
  const f = await guard('<iframe id="frame" src="https://www.youtube.com/embed/one" style="display:grid"></iframe>', {id: "youtube", name: "YouTube", domains: ["youtube.com"]});
  const frame = f.doc.getElementById("frame"), prior = f.doc.querySelector("[data-eg-embed]"); assert.ok(prior);
  frame.setAttribute("src", "https://www.youtube.com/embed/two");
  f.t.emit([{type: "attributes", target: frame, attributeName: "src"}]); f.t.flush();
  assert.notEqual(f.doc.querySelector("[data-eg-embed]"), prior);
  assert.equal(f.doc.querySelectorAll("[data-eg-embed]").length, 1);
});

test("GTM renamed queues complete pending/future callbacks without touching unsafe global names", async () => {
  let called = 0;
  const window = {customLayer: [{event: "ready", eventCallback: () => called++}]};
  const ctx = vm.createContext({window, setTimeout, Array, Object, document: {currentScript: {src: "https://www.googletagmanager.com/gtm.js?id=GTM-TEST&l=customLayer"}}});
  vm.runInContext(read("browser/surrogates/google-tag-manager.js"), ctx);
  window.customLayer.push({event: "next", eventCallback: () => called++});
  await new Promise((resolve) => setTimeout(resolve, 20)); assert.equal(called, 2); assert.equal(window.dataLayer, undefined);
  let accessed = 0; const hostile = {};
  Object.defineProperty(hostile, "secret", {get() { accessed++; return []; }});
  vm.runInNewContext(read("browser/surrogates/google-tag-manager.js"), {window: hostile, Object, Array, setTimeout, document: {currentScript: {src: "https://www.googletagmanager.com/gtm.js?l=secret"}}});
  assert.equal(accessed, 0);
  vm.runInNewContext(read("browser/surrogates/google-tag-manager.js"), {window: hostile, Object, Array, setTimeout, document: {currentScript: {src: "https://www.googletagmanager.com/gtm.js?l=__proto__"}}});
  assert.equal(Object.getPrototypeOf(hostile), Object.prototype);
});
