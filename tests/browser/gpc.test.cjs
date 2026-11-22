"use strict";
// Document-realm regression tests, not a Chrome wire/worker qualification.
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../../browser/page-gpc.js"), "utf8");
function realm(setup = "") {
  const ctx = vm.createContext({});
  vm.runInContext("class Navigator {}\nglobalThis.Navigator = Navigator; globalThis.navigator = new Navigator();\n" + setup, ctx);
  return ctx;
}
const evaluate = (ctx, code) => vm.runInContext(code, ctx);

test("GPC supplies a document fallback without changing unrelated navigator values", () => {
  const ctx = realm("navigator.doNotTrack = '1'; navigator.hardwareConcurrency = 8;");
  evaluate(ctx, source);
  assert.equal(evaluate(ctx, "navigator.globalPrivacyControl"), true);
  assert.equal(evaluate(ctx, "navigator.doNotTrack"), "1");
  assert.equal(evaluate(ctx, "navigator.hardwareConcurrency"), 8);
  assert.equal(evaluate(ctx, "Object.hasOwn(navigator, 'globalPrivacyControl')"), false);
  assert.equal(evaluate(ctx, "Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').enumerable"), true);
  assert.equal(evaluate(ctx, "Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').set"), undefined);
});

test("GPC preserves both true and false native/inherited properties without invoking their getter", () => {
  for (const value of [true, false]) {
    const ctx = realm(`globalThis.reads = 0; Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', {get() { reads++; return ${value}; }, configurable: true}); globalThis.original = Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').get;`);
    evaluate(ctx, source);
    assert.equal(evaluate(ctx, "reads"), 0);
    assert.equal(evaluate(ctx, "Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').get === original"), true);
    assert.equal(evaluate(ctx, "navigator.globalPrivacyControl"), value);
  }
});

test("an existing navigator own property is preserved without adding a misleading prototype fallback", () => {
  const ctx = realm("Object.defineProperty(navigator, 'globalPrivacyControl', {value: false, configurable: false});");
  evaluate(ctx, source);
  assert.equal(evaluate(ctx, "navigator.globalPrivacyControl"), false);
  assert.equal(evaluate(ctx, "Object.hasOwn(Navigator.prototype, 'globalPrivacyControl')"), false);
});

test("frozen prototypes, missing document Navigator and re-injection fail safely", () => {
  const frozen = realm("Object.freeze(Navigator.prototype);");
  assert.doesNotThrow(() => evaluate(frozen, source));
  assert.equal(evaluate(frozen, "'globalPrivacyControl' in navigator"), false);
  const worker = vm.createContext({});
  evaluate(worker, "class WorkerNavigator {} globalThis.WorkerNavigator = WorkerNavigator; globalThis.navigator = new WorkerNavigator();");
  assert.doesNotThrow(() => evaluate(worker, source));
  assert.equal(evaluate(worker, "'globalPrivacyControl' in navigator"), false, "a document script must not claim worker coverage");
  const twice = realm(); evaluate(twice, source);
  evaluate(twice, "globalThis.first = Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').get;");
  evaluate(twice, source);
  assert.equal(evaluate(twice, "Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').get === first"), true);
});

test("GPC fallback remains explicitly distinguishable from a native branded accessor", () => {
  const ctx = realm(); evaluate(ctx, source);
  assert.equal(evaluate(ctx, "Object.getOwnPropertyDescriptor(Navigator.prototype, 'globalPrivacyControl').get.call({})"), true,
    "this known WebIDL-brand difference must not be described as native stealth or full conformance");
});
