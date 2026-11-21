"use strict";
// Content-script tests on the publisher fixture using the hand-rolled DOM stub.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {parseHTML, userClick, scriptClick, event, allText} = require("./dom-stub.cjs");
const {RuleStore} = require("../../browser/core/store.js");
const picker = require("../../browser/core/picker.js");

const root = path.join(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const html = read("tests/browser/fixtures/publisher/index.html");
const fixture = JSON.parse(read("tests/browser/fixtures/publisher/rules.json"));
const cosmetic = fixture.rules.find((r) => r.kind === "cosmetic");
const settle = () => new Promise(setImmediate);

async function page({rules = [cosmetic], markup = html, generic = undefined} = {}) {
  const doc = parseHTML(markup);
  const store = new RuleStore();
  for (const r of rules) await store.addRule(r);
  const sent = [];
  let listener = null;
  const browser = {runtime: {
    sendMessage: async (msg) => {
      sent.push(msg);
      if (msg.type === "page-rules") return {site: "publisher.example", rules: store.activeFor("publisher.example").cosmeticRules, ...(generic === undefined ? {} : {generic: generic.on})};
      if (msg.type === "add-cosmetic") {
        try { return {ok: true, value: await store.addRule({kind: "cosmetic", site: "publisher.example", selector: msg.selector})}; } catch (e) { return {error: e.message}; }
      }
      if (msg.type === "undo-cosmetic") return {ok: await store.removeRule(msg.id)};
      return {error: "unexpected"};
    },
    onMessage: {addListener: (fn) => { listener = fn; }},
  }};
  const ctx = vm.createContext({document: doc, browser, setTimeout, clearTimeout, console, Date});
  const files = ["browser/core/selectors.js", "browser/core/picker.js", ...(generic ? ["browser/core/cosmetic.js"] : []), "browser/content.js"];
  for (const file of files) vm.runInContext(read(file), ctx, {filename: file});
  await ctx.__EGCosmetic.ready;
  const $ = (id) => doc.getElementById(id);
  const hidden = (id) => $(id).style.getPropertyValue("display") === "none" && $(id).style.getPropertyPriority("display") === "important";
  const ui = (tag) => doc.querySelectorAll(`${tag}[data-eg-page-ui]`);
  return {doc, api: ctx.__EGCosmetic, store, sent, send: (m) => listener(m), $, hidden, ui};
}

const button = (host, label) => {
  const find = (n) => { if (n.localName === "button" && n.textContent === label) return n; for (const c of n.childNodes) { const hit = find(c); if (hit) return hit; } return null; };
  return find(host.shadowRoot);
};

test("built-in ad-slot stylesheet: one style element, switchable per site, lifted by Restore page, absent in Firefox", async () => {
  const styles = (p) => {
    const out = [];
    const walk = (n) => { if (n.localName === "style" && n.hasAttribute("data-eg-page-ui")) out.push(n); for (const c of n.childNodes || []) walk(c); };
    walk(p.doc);
    return out;
  };
  const on = await page({generic: {on: true}});
  assert.equal(styles(on).length, 1);
  assert.match(styles(on)[0].textContent, /ins\.adsbygoogle\{display:none!important\}/);
  assert.equal(on.api.status().generic.on, true);
  await on.send({type: "generic", on: false});
  assert.equal(styles(on).length, 0, "switched off for the site: removed at once");
  await on.send({type: "generic", on: true});
  assert.equal(styles(on).length, 1);
  await on.send({type: "restore-page"});
  assert.equal(styles(on).length, 0, "Restore this page also lifts it");
  await on.send({type: "resume"});
  assert.equal(styles(on).length, 1);
  const off = await page({generic: {on: false}});
  assert.equal(styles(off).length, 0, "a site switched off gets no stylesheet");
  const firefox = await page();
  assert.equal(styles(firefox).length, 0);
  assert.equal(firefox.api.status().generic.available, false);
});

test("generic selector set stays small, specific and cheap", () => {
  const list = require("../../browser/core/cosmetic.js");
  assert.ok(list.GENERIC_SELECTORS.length <= list.MAX_SELECTORS);
  for (const s of list.GENERIC_SELECTORS) {
    assert.doesNotMatch(s, /:has\(|^\[|^\*|,|\s|sponsor|promo/i, s);
    assert.ok(/^[a-z-]+[.#\[]|^[a-z-]+$|^\.[A-Za-z_]/.test(s), `${s} is tag-qualified or a class`);
  }
  assert.equal(new Set(list.GENERIC_SELECTORS).size, list.GENERIC_SELECTORS.length);
  assert.equal(list.stylesheet().split("\n").length, list.GENERIC_SELECTORS.length);
});

test("acceptance: only the sponsored card is hidden; Show restores it; Restore page undoes everything", async () => {
  const p = await page();
  assert.equal(p.hidden("card-sponsored"), true);
  for (const id of ["card-organic-1", "card-organic-2", "story", "clip", "player", "login", "content", "feed"]) assert.equal(p.hidden(id), false, id);
  assert.deepEqual(p.api.status().hidden, 1);
  const [placeholder] = p.ui("egress-guard-hidden");
  assert.ok(placeholder, "a placeholder marks the hidden element");
  assert.equal(placeholder.parentNode, p.$("feed"));
  assert.match(allText(placeholder), /Hidden by your rule/);
  userClick(button(placeholder, "Show"));
  assert.equal(p.hidden("card-sponsored"), false, "Show restores the card");
  assert.equal(p.api.status().shown, 1);
  userClick(button(placeholder, "Hide again"));
  assert.equal(p.hidden("card-sponsored"), true);
  // Restore page: everything back, placeholders gone, pre-existing inline display preserved.
  p.api.restorePage();
  assert.equal(p.hidden("card-sponsored"), false);
  assert.equal(p.ui("egress-guard-hidden").length, 0);
  assert.equal(p.api.status().paused, true);
  p.api.resume();
  assert.equal(p.hidden("card-sponsored"), true);
});

test("an author's own inline display value survives hide and restore", async () => {
  const p = await page({markup: html.replace('data-ad-slot="feed-2"', 'data-ad-slot="feed-2" style="display: grid"')});
  assert.equal(p.hidden("card-sponsored"), true);
  p.api.restorePage();
  assert.equal(p.$("card-sponsored").style.getPropertyValue("display"), "grid");
});

test("removing the rule (rules-changed) releases the element", async () => {
  const p = await page();
  await p.send({type: "rules-changed", rules: []});
  assert.equal(p.hidden("card-sponsored"), false);
  assert.equal(p.ui("egress-guard-hidden").length, 0);
});

test("rules never hide the article, video, login form or anything containing them", async () => {
  const rules = [
    {id: "story", kind: "cosmetic", site: "publisher.example", selector: "article.story"},
    {id: "player", kind: "cosmetic", site: "publisher.example", selector: "#player"},
    {id: "login", kind: "cosmetic", site: "publisher.example", selector: "form.card.login"},
    {id: "feed", kind: "cosmetic", site: "publisher.example", selector: "#content"},
    {id: "email", kind: "cosmetic", site: "publisher.example", selector: 'input[name="email"]'},
  ];
  const p = await page({rules});
  for (const id of ["story", "player", "login", "content"]) assert.equal(p.hidden(id), false, id);
  assert.deepEqual(new Set(p.api.status().protectedRules), new Set(["story", "player", "login", "feed", "email"]));
});

test("a rule matching more than 25 elements is skipped as too broad", async () => {
  const many = Array.from({length: 30}, (_, i) => `<div class="tile">${i}</div>`).join("");
  const p = await page({rules: [{id: "tiles", kind: "cosmetic", site: "publisher.example", selector: ".tile"}], markup: html.replace("</main>", `${many}</main>`)});
  assert.equal(p.api.status().hidden, 0);
  assert.deepEqual([...p.api.status().overbroadRules], ["tiles"]);
});

test("picker candidates never propose class-only selectors", () => {
  const base = {tag: "article", id: "", classes: ["card", "teaser"], attrs: [], ancestry: [{tag: "article", id: "", index: 2}, {tag: "section", id: "feed", index: 1}]};
  assert.deepEqual(picker.candidates(base), ["#feed > article:nth-of-type(2)"]);
  assert.deepEqual(picker.candidates({...base, attrs: [{name: "data-ad-slot", value: "feed-2"}]}).slice(0, 2),
    ['article.card.teaser[data-ad-slot="feed-2"]', "article.card.teaser[data-ad-slot]"]);
  const hostile = picker.candidates({...base, ancestry: [], attrs: [{name: "data-x", value: '"><img src=x onerror=alert(1)>'}, {name: "onclick", value: "x"}]});
  assert.deepEqual(hostile, ["article.card.teaser[data-x]"]);
  assert.deepEqual(picker.candidates({tag: "div", id: "", classes: [], attrs: [], ancestry: []}), []);
});

test("acceptance: 'Block this element' creates a validated site rule only on a trusted click, with Undo", async () => {
  const p = await page({rules: []});
  assert.equal(p.hidden("card-sponsored"), false);
  p.api.startPicker();
  const [panel] = p.ui("egress-guard-picker");
  assert.ok(panel);
  // A page script cannot drive the picker.
  scriptClick(p.$("card-sponsored"));
  assert.equal(button(panel, "Create rule").hidden, true);
  // A real click on the sponsored card's heading proposes a selector that matches only sponsored cards.
  userClick(p.$("card-sponsored").children[0]);
  assert.equal(button(panel, "Create rule").hidden, false);
  assert.match(allText(panel), /#card-sponsored/);
  scriptClick(button(panel, "Create rule"));
  await settle();
  assert.equal(p.store.rules.length, 0, "scripted Create is ignored");
  userClick(button(panel, "Create rule"));
  await settle();
  assert.equal(p.store.rules.length, 1);
  assert.equal(p.store.rules[0].site, "publisher.example");
  assert.equal(p.store.rules[0].selector, "#card-sponsored");
  assert.equal(p.hidden("card-sponsored"), true);
  for (const id of ["card-organic-1", "card-organic-2"]) assert.equal(p.hidden(id), false);
  assert.equal(p.ui("egress-guard-picker").length, 0, "picker closes");
  const [toast] = p.ui("egress-guard-toast");
  userClick(button(toast, "Undo"));
  await settle();
  assert.equal(p.store.rules.length, 0, "Undo removes the stored rule");
  assert.equal(p.hidden("card-sponsored"), false, "Undo restores the card");
});

test("picker refuses the login form, the video and the article", async () => {
  const p = await page({rules: []});
  for (const id of ["login", "clip", "story"]) {
    p.api.startPicker();
    const [panel] = p.ui("egress-guard-picker");
    userClick(p.$(id));
    assert.equal(button(panel, "Create rule").hidden, true, id);
    assert.match(allText(panel), /No specific, safe rule/);
    p.$("story").dispatchEvent(event("keydown", {key: "Escape"}));
    assert.equal(p.ui("egress-guard-picker").length, 0, "Escape cancels");
  }
});

test("picker on an organic card proposes only that card", async () => {
  const p = await page({rules: []});
  p.api.startPicker();
  userClick(p.$("card-organic-1"));
  const [panel] = p.ui("egress-guard-picker");
  assert.match(allText(panel), /#card-organic-1/);
  userClick(button(panel, "Create rule"));
  await settle();
  assert.equal(p.hidden("card-organic-1"), true);
  for (const id of ["card-organic-2", "card-sponsored"]) assert.equal(p.hidden(id), false);
});
