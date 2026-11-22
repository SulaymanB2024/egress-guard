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
      row.targetOriginApplicationBytes < 0)) throw new Error("Missing action-byte observation");
  return {measuredWindows: windows.length,
    zeroByteWindows: windows.filter(row => row.targetOriginApplicationBytes === 0).length,
    positiveByteWindows: windows.filter(row => row.targetOriginApplicationBytes > 0).length,
    totalTargetOriginApplicationBytes: windows.reduce((sum, row) => sum + row.targetOriginApplicationBytes, 0)};
}
function assessFirstPartyActionWindows(baseline, protectedArm, expected) {
  const baseOK = baseline && baseline.measuredWindows === expected &&
    baseline.positiveByteWindows === expected && baseline.zeroByteWindows === 0 &&
    baseline.totalTargetOriginApplicationBytes > 0;
  const protectedOK = protectedArm && protectedArm.measuredWindows === expected &&
    protectedArm.zeroByteWindows === expected && protectedArm.positiveByteWindows === 0 &&
    protectedArm.totalTargetOriginApplicationBytes === 0;
  return {status: Number.isSafeInteger(expected) && expected >= 2 && baseOK && protectedOK ? "PASS" : "NOT COVERED",
    detail: {baseline, protected: protectedArm, expected,
      scope: "Only sampled controlled origin intervals; shared-origin or delayed bytes are not individually attributable."}};
}
module.exports = {measureActionWindow, summarizeActionWindows, assessFirstPartyActionWindows};
