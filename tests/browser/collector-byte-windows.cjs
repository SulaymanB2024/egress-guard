"use strict";
// Receiver-side decrypted-byte deltas for controlled, sequential test actions.
// A zero covers only the sampled window; shared-origin positive bytes and later
// asynchronous requests cannot be attributed to one action.
const fixtureHosts = new Set(["publisher.test", "shop.test", "tracker.test", "alias.test", "allowed.test", "blocked.test"]);
function measureActionWindow(before, after, host) {
  if (!fixtureHosts.has(host)) throw new Error("Unknown controlled origin");
  function validate(snapshot) {
    if (!snapshot || !Array.isArray(snapshot.connections) || snapshot.overflow ||
        snapshot.handler_errors !== 0) throw new Error("Invalid collector evidence");
    let total = 0;
    for (const row of snapshot.connections) {
      if (!row || !fixtureHosts.has(row.host) || !Number.isSafeInteger(row.application_bytes) ||
          row.application_bytes < 0 || !Number.isInteger(row.peer_port) ||
          row.peer_port < 1 || row.peer_port > 65535) throw new Error("Invalid connection evidence");
      total += row.application_bytes;
      if (!Number.isSafeInteger(total)) throw new Error("Meter overflow");
    }
    if (snapshot.decrypted_origin_application_bytes !== total) throw new Error("Meter sum mismatch");
    return total;
  }
  const start = validate(before), finish = validate(after);
  if (finish < start || after.connections.length < before.connections.length) throw new Error("Meter rollback");
  let hostBytes = 0, otherBytes = 0;
  for (const [index, row] of after.connections.entries()) {
    const prior = before.connections[index];
    if (prior && (prior.host !== row.host || prior.peer_port !== row.peer_port ||
      row.application_bytes < prior.application_bytes)) throw new Error("Connection mutation");
    const delta = row.application_bytes - (prior?.application_bytes ?? 0);
    if (delta > 0 && row.proxy_route_observed !== true) throw new Error("Unrouted received bytes");
    if (row.host === host) hostBytes += delta;
    else otherBytes += delta;
  }
  if (hostBytes + otherBytes !== finish - start) throw new Error("Unconserved receiver bytes");
  return {status: "MEASURED", targetHost: host, targetOriginApplicationBytes: hostBytes,
    otherOriginApplicationBytes: otherBytes,
    scope: "Receiver bytes inside sampled window; positive shared-origin bytes and later arrivals cannot be assigned to this request."};
}
function summarizeActionWindows(outcomes, kind) {
  const windows = outcomes.filter(row => row.kind === kind).map(row => row.byteWindow);
  if (windows.some(row => row?.status !== "MEASURED" ||
      !Number.isSafeInteger(row.targetOriginApplicationBytes) ||
      row.targetOriginApplicationBytes < 0 ||
      !Number.isSafeInteger(row.otherOriginApplicationBytes) ||
      row.otherOriginApplicationBytes < 0)) throw new Error("Missing action-byte observation");
  const targetBytes = windows.reduce((sum, row) => sum + row.targetOriginApplicationBytes, 0);
  const otherBytes = windows.reduce((sum, row) => sum + row.otherOriginApplicationBytes, 0);
  if (!Number.isSafeInteger(targetBytes) || !Number.isSafeInteger(otherBytes))
    throw new Error("Action-byte summary overflow");
  return {measuredWindows: windows.length,
    zeroByteWindows: windows.filter(row => row.targetOriginApplicationBytes === 0).length,
    positiveByteWindows: windows.filter(row => row.targetOriginApplicationBytes > 0).length,
    positiveOtherOriginWindows: windows.filter(row => row.otherOriginApplicationBytes > 0).length,
    totalTargetOriginApplicationBytes: targetBytes,
    totalOtherOriginApplicationBytes: otherBytes};
}
function assessFirstPartyActionWindows(baseline, protectedArm, expected) {
  const baseOK = baseline && baseline.measuredWindows === expected &&
    baseline.positiveByteWindows === expected && baseline.zeroByteWindows === 0 &&
    baseline.totalTargetOriginApplicationBytes > 0 &&
    baseline.positiveOtherOriginWindows === 0 && baseline.totalOtherOriginApplicationBytes === 0;
  const protectedOK = protectedArm && protectedArm.measuredWindows === expected &&
    protectedArm.zeroByteWindows === expected && protectedArm.positiveByteWindows === 0 &&
    protectedArm.totalTargetOriginApplicationBytes === 0 &&
    protectedArm.positiveOtherOriginWindows === 0 && protectedArm.totalOtherOriginApplicationBytes === 0;
  return {status: Number.isSafeInteger(expected) && expected >= 2 && baseOK && protectedOK ? "PASS" : "NOT COVERED",
    detail: {baseline, protected: protectedArm, expected,
      scope: "Only isolated sampled origin intervals. Non-target origin bytes invalidate a zero-leakage claim; shared-origin and delayed bytes remain unattributed."}};
}

// A controlled deferred request is scheduled after the page action returns. Its
// completion marker is observed before taking the final bounded receiver snapshot.
// The marker proves only that this specific synthetic action completed, not that
// arbitrary timers or requests from a real SDK have stopped forever.
function measureDeferredFirstParty(before, scheduled, settled, host) {
  const immediate = measureActionWindow(before, scheduled, host);
  const delayed = measureActionWindow(scheduled, settled, host);
  const total = measureActionWindow(before, settled, host);
  if (immediate.targetOriginApplicationBytes + delayed.targetOriginApplicationBytes !== total.targetOriginApplicationBytes ||
      immediate.otherOriginApplicationBytes + delayed.otherOriginApplicationBytes !== total.otherOriginApplicationBytes) {
    throw new Error("Deferred receiver bytes were not conserved");
  }
  return {
    status: "MEASURED", targetHost: host,
    immediateTargetOriginApplicationBytes: immediate.targetOriginApplicationBytes,
    lateTargetOriginApplicationBytes: delayed.targetOriginApplicationBytes,
    totalTargetOriginApplicationBytes: total.targetOriginApplicationBytes,
    totalOtherOriginApplicationBytes: total.otherOriginApplicationBytes,
    scope: "Controlled timer completion plus bounded receiver drain only; arbitrary future traffic and positive shared-origin attribution remain unqualified."
  };
}
function assessDeferredFirstParty(baseline, protectedArm) {
  const valid = row => row && row.status === "MEASURED" && row.scheduled === true &&
    row.timerFinished === true && row.attempted === true && row.targetHost === "publisher.test" &&
    ["immediateTargetOriginApplicationBytes", "lateTargetOriginApplicationBytes",
      "totalTargetOriginApplicationBytes", "totalOtherOriginApplicationBytes", "receivedEvents"]
      .every(key => Number.isSafeInteger(row[key]) && row[key] >= 0) &&
    row.immediateTargetOriginApplicationBytes + row.lateTargetOriginApplicationBytes === row.totalTargetOriginApplicationBytes &&
    row.totalOtherOriginApplicationBytes === 0;
  let status = "NOT COVERED";
  if (valid(baseline) && valid(protectedArm) && baseline.totalTargetOriginApplicationBytes > 0 && baseline.receivedEvents === 1) {
    status = protectedArm.totalTargetOriginApplicationBytes > 0 || protectedArm.receivedEvents > 0 ? "FAIL" : "PASS";
  }
  return {status, detail: {baseline, protected: protectedArm,
    scope: "One isolated synthetic deferred first-party GA4 GET after timer completion and a bounded 300 ms drain, not a lifetime or real-SDK guarantee."}};
}
module.exports = {measureActionWindow, summarizeActionWindows, assessFirstPartyActionWindows,
  measureDeferredFirstParty, assessDeferredFirstParty};
