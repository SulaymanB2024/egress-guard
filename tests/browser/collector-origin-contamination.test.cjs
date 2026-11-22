"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {measureActionWindow, summarizeActionWindows, assessFirstPartyActionWindows} = require("./collector-byte-windows.cjs");
const row = (host, port, bytes) => ({host, peer_port: port, application_bytes: bytes, proxy_route_observed: true});
const snap = connections => ({connections, decrypted_origin_application_bytes: connections.reduce((sum, r) => sum + r.application_bytes, 0), handler_errors: 0, overflow: false});
const window = (target, nonTarget, port) => ({kind: "ga4", byteWindow: measureActionWindow(snap([]),
  snap([...target ? [row("publisher.test", port, target)] : [], ...nonTarget ? [row("tracker.test", port + 100, nonTarget)] : []]), "publisher.test")});
const total = values => summarizeActionWindows(values.map(([target, other], index) => window(target, other, 29000 + index)), "ga4");

test("isolated protected window with tracker-host receiver bytes cannot PASS", () => {
  const before = total([[20, 0], [25, 0]]);
  const after = total([[0, 15], [0, 18]]);
  assert.equal(after.totalTargetOriginApplicationBytes, 0);
  assert.equal(after.totalOtherOriginApplicationBytes, 33);
  assert.equal(after.positiveOtherOriginWindows, 2);
  assert.equal(assessFirstPartyActionWindows(before, after, 2).status, "NOT COVERED");
});
test("unrelated bytes in baseline make the isolated comparison ambiguous", () => {
  const before = total([[20, 9], [25, 0]]);
  const after = total([[0, 0], [0, 0]]);
  assert.equal(assessFirstPartyActionWindows(before, after, 2).status, "NOT COVERED");
});
test("isolated baseline deliveries and protected zero receivers still pass the bounded gate", () => {
  const before = total([[20, 0], [25, 0]]);
  const after = total([[0, 0], [0, 0]]);
  assert.equal(assessFirstPartyActionWindows(before, after, 2).status, "PASS");
});
test("other-origin evidence is mandatory and bounded, not silently treated as zero", () => {
  for (const otherOriginApplicationBytes of [undefined, -1, 0.1, Number.POSITIVE_INFINITY]) {
    assert.throws(() => summarizeActionWindows([{kind: "ga4", byteWindow: {
      status: "MEASURED", targetOriginApplicationBytes: 0, otherOriginApplicationBytes}}], "ga4"));
  }
  const max = Number.MAX_SAFE_INTEGER;
  assert.throws(() => summarizeActionWindows([
    {kind: "ga4", byteWindow: {status: "MEASURED", targetOriginApplicationBytes: 0, otherOriginApplicationBytes: max}},
    {kind: "ga4", byteWindow: {status: "MEASURED", targetOriginApplicationBytes: 0, otherOriginApplicationBytes: 1}}
  ], "ga4"), /overflow/);
});

test("mislabeled tracker-host receiver windows cannot certify first-party GA4", () => {
  const falseOrigin = {kind: "ga4", byteWindow: measureActionWindow(
    snap([]), snap([row("tracker.test", 31000, 41)]), "tracker.test")};
  assert.throws(() => summarizeActionWindows([falseOrigin], "ga4"), /first-party publisher/);
});
