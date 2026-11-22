"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const privacy = require("../../browser/core/browser-privacy.js");
const copy = value => JSON.parse(JSON.stringify(value));

function browser({permission = true, state} = {}) {
  const data = state === undefined ? {} : {[privacy.KEY]: copy(state)};
  const calls = [], controls = new Map();
  const failures = {save: false, read: false};
  const C = {privacy: {network: {}, services: {}, websites: {}}, permissions: {contains: async () => permission},
    storage: {local: {
      get: async () => { if (failures.read) throw new Error("storage read failed"); return copy(data); },
      set: async patch => { calls.push(["save", copy(patch)]); if (failures.save) throw new Error("storage write failed"); Object.assign(data, copy(patch)); },
    }}};
  for (const spec of privacy.CATALOG) {
    const control = {base: spec.id === "webrtc" ? "default" : true, own: undefined, other: undefined, policy: undefined,
      failGet: false, failSet: false, failClear: false, invalid: null, setGate: null};
    const layer = () => control.policy !== undefined ? [control.policy, "not_controllable"] : control.other !== undefined ? [control.other, "controlled_by_other_extensions"] :
      control.own !== undefined ? [control.own, "controlled_by_this_extension"] : [control.base, "controllable_by_this_extension"];
    control.api = {
      get: async scope => { calls.push(["get", spec.id, scope]); if (control.failGet) throw new Error("get failed"); if (control.invalid) return control.invalid; const [value, levelOfControl] = layer(); return {value, levelOfControl}; },
      set: async request => { calls.push(["set", spec.id, request]); if (control.setGate) await control.setGate; if (control.failSet) throw new Error("set failed"); control.own = request.value; },
      clear: async request => { calls.push(["clear", spec.id, request]); if (control.failClear) throw new Error("clear failed"); control.own = undefined; },
    };
    controls.set(spec.id, control); C.privacy[spec.path[0]][spec.path[1]] = control.api;
  }
  return {C, data, calls, controls, failures, setPermission: value => { permission = value; },
    remove: id => { const spec = privacy.CATALOG.find(item => item.id === id); delete C.privacy[spec.path[0]][spec.path[1]]; }};
}
const row = (receipt, id) => receipt.rows.find(item => item.id === id);
const mutations = fake => fake.calls.filter(call => ["set", "clear"].includes(call[0]));

test("opening status without saved intent never changes browser settings or requests permission", async () => {
  const fake = browser({permission: false}), controller = privacy.createController(fake.C);
  const initial = await controller.ready, receipt = await controller.status();
  assert.equal(initial.state, "inactive"); assert.equal(receipt.permission, false); assert.equal(receipt.complete, false);
  assert.deepEqual(receipt.selected, []); assert.deepEqual(mutations(fake), []); assert.deepEqual(fake.data, {});
});
test("fixed controls persist intent before mutation and report actual values and owners", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; fake.calls.length = 0;
  const receipt = await controller.apply(["webrtc", "prediction", "ad-measurement"]);
  assert.equal(fake.calls[0][0], "save"); assert.equal(receipt.complete, true); assert.equal(receipt.state, "applied");
  for (const id of receipt.selected) { assert.equal(row(receipt, id).owned, true); assert.equal(row(receipt, id).effective, true); }
  assert.equal(fake.controls.get("webrtc").own, "disable_non_proxied_udp");
  for (const call of mutations(fake)) assert.equal(call[2].scope, "regular");
  assert.equal(fake.calls.some(call => /safeBrowsing|password|autofill/i.test(String(call[1]))), false);
});
test("storage failure cannot authorize any browser mutation", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; fake.calls.length = 0; fake.failures.save = true;
  await assert.rejects(controller.apply(["webrtc"]), /storage write failed/);
  assert.deepEqual(mutations(fake), []); assert.deepEqual((await controller.status()).selected, []);
});
test("retry without a saved choice never clears settings even when privacy permission exists", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; fake.calls.length = 0;
  const receipt = await controller.retry();
  assert.equal(receipt.saved, false); assert.deepEqual(mutations(fake), []); assert.equal(fake.calls.some(call => call[0] === "save"), false);
});
test("unsupported, policy-controlled and other-extension controls are never falsely applied", async () => {
  const fake = browser(); fake.remove("topics"); fake.controls.get("prediction").policy = true; fake.controls.get("webrtc").other = "default";
  const controller = privacy.createController(fake.C); await controller.ready; fake.calls.length = 0;
  const receipt = await controller.apply(["topics", "prediction", "webrtc"]);
  assert.equal(receipt.state, "degraded"); assert.equal(receipt.complete, false);
  assert.equal(row(receipt, "topics").state, "unavailable"); assert.equal(row(receipt, "prediction").state, "overridden");
  assert.equal(row(receipt, "webrtc").state, "overridden"); assert.equal(fake.calls.some(call => call[0] === "set"), false);
  fake.controls.get("prediction").policy = false;
  const refreshed = await controller.status(); assert.equal(row(refreshed, "prediction").state, "effective-elsewhere"); assert.equal(row(refreshed, "prediction").owned, false);
});
test("successful API response with a concurrently overriding value remains degraded", async () => {
  const fake = browser(); const control = fake.controls.get("auditing"), original = control.api.set;
  control.api.set = async value => { await original(value); control.other = true; };
  const controller = privacy.createController(fake.C); await controller.ready;
  const receipt = await controller.apply(["auditing"]);
  assert.equal(receipt.state, "degraded"); assert.equal(row(receipt, "auditing").effective, false); assert.equal(row(receipt, "auditing").levelOfControl, "controlled_by_other_extensions");
});
test("release clears our hidden layer without overwriting changed user or extension settings", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready;
  await controller.apply(["prediction", "webrtc"]);
  fake.controls.get("prediction").base = false;
  fake.controls.get("webrtc").other = "default_public_interface_only"; fake.calls.length = 0;
  const receipt = await controller.release();
  assert.equal(receipt.state, "inactive"); assert.equal(receipt.complete, true);
  assert.equal(fake.controls.get("prediction").base, false); assert.equal(fake.controls.get("prediction").own, undefined);
  assert.equal(fake.controls.get("webrtc").own, undefined); assert.equal(row(receipt, "webrtc").value, "default_public_interface_only");
  assert.equal(fake.calls.some(call => call[0] === "set"), false);
  fake.controls.get("webrtc").other = undefined;
  assert.equal(row(await controller.status(), "webrtc").value, "default");
});
test("failed clear under another extension stays pending until retry succeeds", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; await controller.apply(["webrtc"]);
  const control = fake.controls.get("webrtc"); control.other = "default"; control.failClear = true;
  const receipt = await controller.release();
  assert.equal(receipt.state, "degraded"); assert.equal(receipt.complete, false); assert.equal(row(receipt, "webrtc").state, "release-pending");
  control.failClear = false;
  assert.equal((await controller.retry()).state, "inactive"); assert.equal(control.own, undefined);
});
test("failed release beneath another extension remains pending across worker restart", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; await controller.apply(["webrtc"]);
  const control = fake.controls.get("webrtc"); control.other = "default"; control.failClear = true;
  await controller.release();
  const restarted = privacy.createController(fake.C);
  assert.equal(row(await restarted.ready, "webrtc").state, "release-pending");
  assert.deepEqual(fake.data[privacy.KEY].selected, []);
  control.failClear = false; assert.equal((await restarted.retry()).state, "inactive");
  control.other = undefined; assert.equal(row(await restarted.status(), "webrtc").value, "default");
});
test("an unreadable current value after clear is not a complete readback receipt", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; await controller.apply(["webrtc"]);
  fake.controls.get("webrtc").failGet = true;
  const receipt = await controller.release();
  assert.equal(fake.controls.get("webrtc").own, undefined);
  assert.equal(receipt.state, "degraded"); assert.equal(receipt.complete, false); assert.equal(row(receipt, "webrtc").state, "unknown");
});
test("partial application is recoverable and startup reconciles persisted choices", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready; fake.controls.get("webrtc").failSet = true;
  const partial = await controller.apply(["webrtc", "prediction"]);
  assert.equal(partial.complete, false); assert.equal(row(partial, "prediction").state, "applied"); assert.equal(row(partial, "webrtc").state, "pending");
  fake.controls.get("webrtc").failSet = false;
  const restarted = privacy.createController(fake.C); assert.equal((await restarted.ready).complete, true);
  fake.setPermission(false); const denied = await restarted.status(); assert.equal(denied.state, "permission-required"); assert.equal(denied.complete, false);
});
test("malformed stored choices and invented write paths are refused, explicit release recovers", async () => {
  const fake = browser({state: {schema: 1, revision: 1, selected: ["safeBrowsingEnabled"]}}), controller = privacy.createController(fake.C);
  assert.equal((await controller.ready).state, "degraded"); assert.deepEqual(mutations(fake), []);
  for (const selection of [["__proto__"], ["webrtc", "webrtc"], ["network.webRTCIPHandlingPolicy"], "webrtc", [false]]) {
    await assert.rejects(controller.apply(selection), /listed browser privacy controls/);
  }
  assert.deepEqual(mutations(fake), []); assert.equal((await controller.release()).state, "inactive");
});
test("malformed setting receipts cannot establish effective protection", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready;
  fake.controls.get("prediction").invalid = {value: "false", levelOfControl: "controlled_by_this_extension"};
  const receipt = await controller.apply(["prediction"]);
  assert.equal(receipt.complete, false); assert.equal(row(receipt, "prediction").state, "unknown"); assert.equal(row(receipt, "prediction").effective, false);
  fake.controls.get("prediction").invalid = {value: false, levelOfControl: "controlled_by_this_extension", incognitoSpecific: true};
  assert.equal(row(await controller.status(), "prediction").state, "unknown", "an incognito-specific value cannot attest the regular profile");
});
test("concurrent apply and release retain order and cannot resurrect stale choices", async () => {
  const fake = browser(), controller = privacy.createController(fake.C); await controller.ready;
  let unblock; fake.controls.get("webrtc").setGate = new Promise(resolve => { unblock = resolve; });
  const applying = controller.apply(["webrtc"]), releasing = controller.release();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(fake.data[privacy.KEY].selected.includes("webrtc"), true);
  unblock(); await applying; const final = await releasing;
  assert.equal(final.state, "inactive"); assert.equal(fake.controls.get("webrtc").own, undefined); assert.deepEqual(fake.data[privacy.KEY].selected, []);
});

test("retired advertising preferences remain supported and releasable without counting as current protections", async () => {
  const legacy = ["topics", "ad-auctions", "ad-measurement"];
  for (const spec of privacy.CATALOG) assert.equal(spec.recommended, !legacy.includes(spec.id));
  const fake = browser({state: {schema: 1, revision: 8, selected: [...legacy, "webrtc"]}});
  const controller = privacy.createController(fake.C);
  const receipt = await controller.ready;
  assert.equal(receipt.complete, true);
  assert.deepEqual(receipt.selected, [...legacy, "webrtc"].sort());
  assert.deepEqual(receipt.counts, {active: {selected: 1, confirmed: 1}, legacy: {selected: 3, confirmed: 3}});
  assert.equal(receipt.evidence, "chrome-setting-readback"); assert.equal(receipt.behaviorVerified, false);
  for (const id of legacy) assert.equal(fake.controls.get(id).own, false, "previously authorized intent is retained");
  await controller.release();
  for (const id of legacy) assert.equal(fake.controls.get(id).own, undefined);
});

test("browser privacy catalog has no write authority over DNT or fingerprint/device APIs", () => {
  assert.equal(privacy.CATALOG.some(spec => /doNotTrack|sensor|camera|microphone|userAgent|clientHints/i.test(spec.path.join("."))), false);
  assert.throws(() => privacy.validateSelection(["doNotTrackEnabled"]), /listed browser privacy/);
});
