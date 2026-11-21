"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {parseHTML, event, allText} = require("./dom-stub.cjs");
const model = require("../../browser/core/local-model.js");
const read = name => fs.readFileSync(path.join(__dirname, "../../browser", name), "utf8");
const snapshot = () => ({ok: true, documentId: "doc-1", domGeneration: 2, candidates: [
  {id: "candidate-1", classification: "uncertain", accessibleLabel: "<script>untrusted</script>", text: "Sponsored card", disclosures: ["Sponsored"]},
  {id: "candidate-2", classification: "essential-commerce", accessibleLabel: "Cart", text: "Checkout"},
]});
async function ui(analyze) {
  const doc = parseHTML(read("semantic.html")), messages = [], updates = [];
  let runs = 0;
  const chrome = {tabs: {
    get: async () => ({id: 7, url: "https://publisher.example/article"}),
    sendMessage: async (id, message, scope) => {
      messages.push({id, message, scope});
      if (message.type === "semantic-candidates") return snapshot();
      if (message.type === "semantic-apply") return {ok: true, applied: 1, rejected: 0};
      return {ok: true};
    },
    onUpdated: {addListener: callback => updates.push(callback)}, onRemoved: {addListener() {}},
  }};
  const ctx = vm.createContext({document: doc, chrome, location: {search: "?tab=7"}, URL, AbortController,
    addEventListener() {}, EGLocalModel: {...model, availability: async () => "available", analyze: async (...args) => {
      runs++; return analyze ? analyze(...args) : {labels: [{id: "candidate-1", category: "paid-placement"}]};
    }}});
  vm.runInContext(read("semantic.js"), ctx);
  await ctx.__EGSemanticUI.ready;
  return {doc, messages, updates, api: ctx.__EGSemanticUI, runs: () => runs, $: id => doc.getElementById(id)};
}
test("semantic review requires explicit scan, analysis and selection, sends only IDs to the source frame", async () => {
  const view = await ui();
  assert.equal(view.messages.length, 0);
  assert.equal(view.runs(), 0);
  assert.equal(view.$("scan").disabled, true);
  await view.api.scan(); assert.equal(view.messages.length, 0);
  view.$("public-page").checked = true;
  view.$("public-page").dispatchEvent(event("change"));
  await view.api.scan();
  assert.equal(view.runs(), 0);
  assert.equal(view.$("apply").disabled, true);
  assert.ok(allText(view.$("candidates")).includes("<script>untrusted</script>"), "page text remains literal text: " + allText(view.$("error")) + "; " + allText(view.$("candidates")));
  const tags = node => [node.localName, ...node.childNodes.flatMap(tags)];
  assert.equal(tags(view.$("candidates")).includes("script"), false);
  await view.api.analyze();
  assert.equal(view.runs(), 1);
  assert.equal(view.messages.some(entry => entry.message.type === "semantic-apply"), false);
  const descendants = node => [node, ...node.childNodes.flatMap(descendants)];
  const boxes = descendants(view.$("candidates")).filter(node => node.localName === "input");
  assert.equal(boxes[0].checked, false, "model does not preselect actions");
  assert.equal(boxes[1].disabled, true, "protected commerce cannot be selected");
  boxes[0].checked = true; boxes[0].dispatchEvent(event("change"));
  await view.api.apply();
  const applied = view.messages.find(entry => entry.message.type === "semantic-apply");
  assert.equal(applied.id, 7); assert.equal(applied.scope.frameId, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(applied.message)), {type: "semantic-apply", documentId: "doc-1", domGeneration: 2, labels: [{id: "candidate-1", category: "paid-placement"}]});
  assert.equal(view.api.batch, null, "applied snapshot cannot be reused");
  await view.api.restore();
  assert.equal(view.messages.at(-1).message.type, "semantic-restore");
});
test("navigation cancels local inference and discards late results and displayed snippets", async () => {
  let finish, signal;
  const view = await ui((input, options) => { signal = options.signal; return new Promise(resolve => { finish = resolve; }); });
  view.$("public-page").checked = true;
  await view.api.scan();
  const running = view.api.analyze();
  view.updates[0](7, {url: "https://publisher.example/account"});
  assert.equal(signal.aborted, true);
  finish({labels: [{id: "candidate-1", category: "paid-placement"}]});
  await running;
  assert.equal(view.api.batch, null);
  assert.equal(allText(view.$("candidates")), "");
  assert.equal(view.$("apply").disabled, true);
  assert.equal(view.$("public-page").checked, false);
  assert.equal(view.$("restore").disabled, true);
  const before = view.messages.length;
  await view.api.restore();
  assert.equal(view.messages.length, before, "old review cannot restore a new document");
  assert.equal(view.messages.some(entry => entry.message.type === "semantic-apply"), false);
});
