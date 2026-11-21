"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const {parseHTML, event, allText} = require("./dom-stub.cjs");
const privacy = require("../../browser/core/browser-privacy.js");
const read = file => fs.readFileSync(path.join(__dirname, "../../browser", file), "utf8");
function receipt(selected = [], extra = {}) {
  return {schema: 1, permission: false, scope: "regular", saved: false, revision: 0, selected,
    state: "inactive", complete: false, error: "", rows: privacy.CATALOG.map(spec => ({id: spec.id, selected: selected.includes(spec.id),
      target: spec.value, supported: false, value: null, levelOfControl: null, effective: false, owned: false, state: "permission-required", error: ""})), ...extra};
}
async function ui({granted = true, initial = receipt()} = {}) {
  const doc = parseHTML(read("privacy.html")), messages = [], requests = [];
  let current = initial;
  const chrome = {runtime: {sendMessage: async message => {
    messages.push(message);
    if (message.type === "browser-privacy-apply") {
      current = receipt([...message.selected], {permission: true, saved: true, revision: 1, state: "degraded"});
    } else if (message.type === "browser-privacy-release") current = receipt([], {permission: true, saved: true, revision: 2, state: "inactive", complete: true});
    return JSON.parse(JSON.stringify(current));
  }}, permissions: {request: async request => { requests.push(request); return granted; }}};
  const ctx = vm.createContext({document: doc, chrome, EGBrowserPrivacy: privacy, addEventListener() {}});
  vm.runInContext(read("privacy.js"), ctx); await ctx.__EGPrivacyUI.ready;
  return {doc, api: ctx.__EGPrivacyUI, messages, requests, $: id => doc.getElementById(id), setReceipt: value => { current = value; }};
}
test("privacy review does not request permission or apply choices on opening", async () => {
  const view = await ui();
  assert.equal(view.messages.length, 1); assert.equal(view.messages[0].type, "browser-privacy-status");
  assert.equal(view.requests.length, 0); assert.equal(view.$("apply").disabled, false);
  for (const spec of privacy.CATALOG) assert.equal(view.$(`control-${spec.id}`).checked, true);
  assert.match(allText(view.$("status")), /No privacy controls are selected/);
});
test("declined permission leaves saved choices and browser mutation requests untouched", async () => {
  const view = await ui({granted: false}); await view.api.apply();
  assert.deepEqual(JSON.parse(JSON.stringify(view.requests)), [{permissions: ["privacy"]}]);
  assert.equal(view.messages.some(message => message.type === "browser-privacy-apply"), false);
  assert.match(allText(view.$("error")), /did not grant/); assert.equal(view.api.state.saved, false);
});
test("explicit apply sends only selected catalog IDs and reports incomplete protection", async () => {
  const view = await ui();
  for (const spec of privacy.CATALOG) view.$(`control-${spec.id}`).checked = spec.id === "webrtc";
  await view.api.apply();
  const applied = view.messages.find(message => message.type === "browser-privacy-apply");
  assert.deepEqual(JSON.parse(JSON.stringify(applied)), {type: "browser-privacy-apply", selected: ["webrtc"]});
  assert.equal(view.requests.length, 1); assert.match(allText(view.$("status")), /0 of 1 selected protections verified/);
  assert.match(allText(view.$("status")), /attention/); assert.equal(view.$("retry").disabled, false);
  await view.api.release(); assert.equal(view.messages.at(-1).type, "browser-privacy-release");
  for (const spec of privacy.CATALOG) assert.equal(view.$(`control-${spec.id}`).checked, false);
  assert.equal(view.requests.length, 1, "release does not ask for new authority");
});
test("refresh preserves unsaved choices and treats error text as text", async () => {
  const view = await ui(); view.$("control-webrtc").checked = false; view.$("control-webrtc").dispatchEvent(event("change"));
  const next = receipt(["webrtc"], {permission: true, saved: true, state: "degraded", error: "<img src=x onerror=alert(1)>"});
  view.setReceipt(next); await view.api.refresh();
  assert.equal(view.$("control-webrtc").checked, false);
  assert.equal(allText(view.$("error")), "<img src=x onerror=alert(1)>");
  const tags = node => [node.localName, ...node.childNodes.flatMap(tags)]; assert.equal(tags(view.$("error")).includes("img"), false);
});
