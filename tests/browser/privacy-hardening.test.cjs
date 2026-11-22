"use strict";
// Deterministic source/condition tests. This is not native Chrome qualification.
const test = require("node:test"), assert = require("node:assert/strict");
const hardening = require("../../browser/core/privacy-hardening.js");
const dnr = require("../../browser/core/dnr.js");

function response(headers, type = "main_frame", url = "https://publisher.example/") {
  const rule = hardening.compile({enabled: true})[1];
  const matches = url.startsWith("http") && rule.condition.resourceTypes.includes(type) &&
    !rule.condition.excludedResponseHeaders.some(condition => headers.some(([name]) => name.toLowerCase() === condition.header));
  return matches ? [...headers, ["permissions-policy", rule.action.responseHeaders[0].value]] : [...headers];
}

test("Client Hints is off without an explicit Boolean choice; invalid saved authority is rejected", () => {
  assert.deepEqual(hardening.compile(), []);
  assert.deepEqual(hardening.compile({enabled: false}), []);
  for (const enabled of [1, "true", null, {}, []]) assert.throws(() => hardening.compile({enabled}), /explicitly/);
  for (const state of [null, [], {}, {schema: 1, revision: 0, enabled: true}, {schema: 1, revision: 1, enabled: "true"},
    {schema: 1, revision: 1, enabled: true, headers: ["cookie"]}, {schema: 2, revision: 1, enabled: true}]) {
    assert.throws(() => hardening.validateState(state), /invalid/);
  }
  assert.deepEqual(hardening.validateState({schema: 1, revision: 9, enabled: false}), {schema: 1, revision: 9, enabled: false});
});

test("two fixed rules have separate request/response stages and cannot grant a request", () => {
  const rules = hardening.compile({enabled: true});
  assert.equal(rules.length, 2);
  assert.deepEqual(rules.map(rule => rule.id), [hardening.FIRST_ID, hardening.FIRST_ID + 1]);
  for (const rule of rules) {
    assert.equal(rule.action.type, "modifyHeaders");
    assert.equal(rule.condition.regexFilter, undefined);
    assert.equal(rule.priority, dnr.PRIORITY.clientHints);
    assert.ok(rule.priority > dnr.PRIORITY.exception && rule.priority > dnr.PRIORITY.continue);
    assert.ok(rule.priority > dnr.PRIORITY.isolationHeaders && rule.priority < dnr.PRIORITY.gpc);
  }
  assert.equal(rules[0].condition.responseHeaders, undefined);
  assert.equal(rules[0].condition.excludedResponseHeaders, undefined, "outgoing sanitation must happen before a response exists");
  assert.equal(rules[1].action.requestHeaders, undefined);
  assert.deepEqual(rules[1].condition.resourceTypes, ["main_frame", "sub_frame"]);
  assert.equal(rules[0].condition.resourceTypes.includes("main_frame"), true);
  assert.equal(rules[0].condition.resourceTypes.includes("xmlhttprequest"), true);
});

test("request action removes only eight detailed UA headers and retains ordinary identity/functional headers", () => {
  const headers = new Map([
    ...hardening.REQUEST_HEADERS.map(name => [name.toUpperCase(), "synthetic-detailed-value"]),
    ["Sec-CH-UA", '"Chromium";v="145"'], ["Sec-CH-UA-Mobile", "?0"], ["Sec-CH-UA-Platform", '"Linux"'],
    ["User-Agent", "synthetic-browser"], ["DNT", "1"], ["Sec-GPC", "1"], ["Authorization", "synthetic"],
    ["Content-Type", "application/json"], ["Device-Memory", "synthetic"], ["X-App-Version", "synthetic"],
  ]);
  for (const operation of hardening.compile({enabled: true})[0].action.requestHeaders) {
    assert.equal(operation.operation, "remove");
    for (const name of headers.keys()) if (name.toLowerCase() === operation.header) headers.delete(name);
  }
  assert.equal(hardening.REQUEST_HEADERS.length, 8);
  assert.equal(headers.size, 10);
  for (const name of ["Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "User-Agent", "DNT", "Sec-GPC", "Authorization", "Content-Type", "Device-Memory", "X-App-Version"]) assert.ok(headers.has(name), name);
});

test("absent policy gains only empty UA allowlists; Accept-CH, Critical-CH and site security headers remain intact", () => {
  const original = [["Content-Security-Policy", "default-src 'self'"], ["Accept-CH", "Sec-CH-UA-Model, DPR"], ["Critical-CH", "DPR"]];
  const changed = response(original);
  assert.deepEqual(changed.slice(0, original.length), original);
  assert.equal(changed.length, original.length + 1);
  assert.equal(changed.at(-1)[1], hardening.POLICY);
  assert.ok(hardening.DIRECTIVES.includes("ch-ua-high-entropy-values"));
  assert.ok(hardening.DIRECTIVES.every(name => /^ch-ua-/.test(name)));
  assert.ok(hardening.POLICY.split(", ").every(value => value.endsWith("=()")));
  assert.deepEqual(response(original, "script"), original, "worker script policy support is not inferred from document support");
  assert.deepEqual(response(original, "xmlhttprequest"), original);
  assert.deepEqual(response(original, "main_frame", "chrome-extension://fixed/privacy.html"), original);
});

test("every existing policy, including empty, conflicting, duplicate, malformed and oversized values, stands down unchanged", () => {
  const samples = [
    [["Permissions-Policy", "camera=(), microphone=()"]],
    [["pErMiSsIoNs-PoLiCy", ""]],
    [["permissions-policy", "ch-ua-high-entropy-values=*"]],
    [["permissions-policy", "ch-ua-high-entropy-values=(), ch-ua-high-entropy-values=*"]],
    [["permissions-policy", "geolocation=()"], ["Permissions-Policy", "camera=(self)"]],
    [["permissions-policy", 'camera=("unclosed)']],
    [["permissions-policy", "camera=(), " + "x".repeat(65500)]],
    [["permissions-policy", "x".repeat(70000)]],
  ];
  for (const headers of samples) {
    assert.deepEqual(response(headers), headers);
    assert.deepEqual(response(headers, "sub_frame"), headers);
  }
});

test("compilation returns fresh rule objects and immutable authority constants", () => {
  const rules = hardening.compile({enabled: true});
  rules[0].action.requestHeaders[0].header = "cookie";
  rules[1].condition.excludedResponseHeaders.length = 0;
  assert.equal(hardening.compile({enabled: true})[0].action.requestHeaders[0].header, "sec-ch-ua-arch");
  assert.equal(hardening.compile({enabled: true})[1].condition.excludedResponseHeaders.length, 1);
  assert.throws(() => hardening.REQUEST_HEADERS.push("cookie"), TypeError);
  assert.equal(hardening.CAPABILITIES.behaviorVerified, false);
  assert.equal(hardening.CAPABILITIES.experimental, true);
  for (const firstId of [0, -1, 1.5, 2147483647]) assert.throws(() => hardening.compile({enabled: true, firstId}), /allocation/);
});
