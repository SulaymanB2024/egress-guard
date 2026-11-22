"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {measureActionWindow, summarizeActionWindows, assessFirstPartyActionWindows} = require("./collector-byte-windows.cjs");
const row = (host, port, bytes, routed = true) => ({host, peer_port: port, application_bytes: bytes, proxy_route_observed: routed, closed: false});
const snap = connections => ({connections, decrypted_origin_application_bytes: connections.reduce((s, r) => s + r.application_bytes, 0), handler_errors: 0, overflow: false});

test("samples existing, new and source-port-reused connections without losing bytes", () => {
  const before = snap([row("publisher.test", 28001, 13), row("shop.test", 28002, 5)]);
  const after = snap([row("publisher.test", 28001, 31), row("shop.test", 28002, 7), row("publisher.test", 28001, 4)]);
  const result = measureActionWindow(before, after, "publisher.test");
  assert.equal(result.targetOriginApplicationBytes, 22);
  assert.equal(result.otherOriginApplicationBytes, 2);
  assert.equal(result.targetOriginApplicationBytes + result.otherOriginApplicationBytes, 24);
});
test("zero means no newly received bytes, not only absence of an HTTP event", () => {
  const start = snap([row("publisher.test", 30000, 400)]);
  const end = snap([row("publisher.test", 30000, 400), row("tracker.test", 30001, 0)]);
  assert.equal(measureActionWindow(start, end, "publisher.test").targetOriginApplicationBytes, 0);
});
test("positive shared-origin bytes cannot be assigned to a tracking request", () => {
  const result = measureActionWindow(snap([row("publisher.test", 30000, 0)]),
    snap([row("publisher.test", 30000, 99)]), "publisher.test");
  assert.equal(result.targetOriginApplicationBytes, 99);
  assert.match(result.scope, /cannot be assigned to this request/);
});
test("rejects forged routes, corrupt counters, rollbacks and overflowing evidence", () => {
  const start = snap([row("publisher.test", 30000, 1)]);
  for (const end of [snap([row("publisher.test", 30000, 2, false)]),
    snap([row("publisher.test", 30000, 0)]), snap([row("shop.test", 30000, 2)]),
    {...snap([row("publisher.test", 30000, 2)]), decrypted_origin_application_bytes: 0},
    {...snap([row("publisher.test", 30000, 2)]), overflow: true},
    {...snap([row("publisher.test", 30000, 2)]), handler_errors: 1}, snap([])])
    assert.throws(() => measureActionWindow(start, end, "publisher.test"));
});
test("rejects unapproved origins and invalid floating, missing or negative counters", () => {
  const initial = snap([]);
  for (const host of ["https://publisher.test", "publisher.com", "127.0.0.1", "tracker.test:443", "evil.test", null])
    assert.throws(() => measureActionWindow(initial, initial, host));
  for (const bad of [row("publisher.test", 0, 1), row("publisher.test", 3000, 0.2),
    row("publisher.test", 3000, -1), row("publisher.test", 3000, 1, false)])
    assert.throws(() => measureActionWindow(initial, snap([bad]), "publisher.test"));
});
test("positive receiver baseline and all protected zero-byte windows are mandatory", () => {
  const outcome = (kind, bytes) => ({kind, byteWindow: {status: "MEASURED", targetOriginApplicationBytes: bytes, otherOriginApplicationBytes: 0}});
  const base = summarizeActionWindows([outcome("ga4", 12), outcome("ga4", 9), outcome("cart", 44)], "ga4");
  const active = summarizeActionWindows([outcome("ga4", 0), outcome("ga4", 0)], "ga4");
  assert.equal(assessFirstPartyActionWindows(base, active, 2).status, "PASS");
  assert.equal(assessFirstPartyActionWindows(base, {...active, zeroByteWindows: 1,
    positiveByteWindows: 1, totalTargetOriginApplicationBytes: 1}, 2).status, "NOT COVERED");
  assert.equal(assessFirstPartyActionWindows({...base, positiveByteWindows: 1}, active, 2).status, "NOT COVERED");
  assert.equal(assessFirstPartyActionWindows(base, active, 3).status, "NOT COVERED");
  assert.throws(() => summarizeActionWindows([{kind: "ga4"}], "ga4"));
});
