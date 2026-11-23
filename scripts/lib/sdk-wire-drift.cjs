"use strict";
// Offline comparison of controlled SDK collector receipts. No I/O, browser API,
// allow/block authority or automatic promotion. Never accepts raw URLs or PII.
const HEX64 = /^[0-9a-f]{64}$/;
const HEXREV = /^[0-9a-f]{40}$/;
const ID = /^[a-z][a-z0-9_-]{0,63}$/;
const NAME = /^[a-z][a-z0-9-]{0,47}$/;
const TRANSPORT = /^(GET|POST)\/(image|script|ping|xhr|sub_frame)$/;
const MAX_CASES = 256;
function keys(obj, expected, label) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj) ||
      Object.keys(obj).sort().join("|") !== [...expected].sort().join("|"))
    throw new Error("Invalid " + label + " structure");
}
function natural(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid " + label);
}
function validateReceipt(r) {
  keys(r, ["schema", "sdk", "setup", "evidence", "cases"], "receipt");
  if (r.schema !== 1) throw new Error("Unsupported receipt schema");
  keys(r.sdk, ["name", "revision", "bundle_sha256"], "SDK pin");
  if (!NAME.test(r.sdk.name) || !HEXREV.test(r.sdk.revision) ||
      !HEX64.test(r.sdk.bundle_sha256)) throw new Error("Missing exact SDK source pin");
  keys(r.setup, ["fixture_sha256", "policy_sha256", "extension_sha256", "execution"], "setup");
  for (const k of ["fixture_sha256", "policy_sha256", "extension_sha256"])
    if (!HEX64.test(r.setup[k])) throw new Error("Invalid setup pin");
  if (!["native-chrome-proxy", "source-only", "simulated-lifecycle"].includes(r.setup.execution))
    throw new Error("Unknown execution mode");
  keys(r.evidence, ["sender_completed", "origin_tls_collector", "proxy_route_verified",
    "origin_meter_valid", "positive_control_bytes", "positive_control_events"], "evidence");
  for (const k of ["sender_completed", "origin_tls_collector", "proxy_route_verified", "origin_meter_valid"])
    if (typeof r.evidence[k] !== "boolean") throw new Error("Invalid evidence state");
  natural(r.evidence.positive_control_bytes, "control bytes");
  natural(r.evidence.positive_control_events, "control events");
  if (!Array.isArray(r.cases) || r.cases.length < 2 || r.cases.length > MAX_CASES)
    throw new Error("Invalid case count");
  const seen = new Set(); let tracking = 0, functional = 0;
  for (const row of r.cases) {
    keys(row, ["id", "kind", "transport", "context_completed",
      "received_canary_events", "received_application_bytes", "functional_succeeded"], "case");
    if (typeof row.id !== "string" || !ID.test(row.id) || seen.has(row.id))
      throw new Error("Invalid or duplicate case ID");
    seen.add(row.id);
    if (!["tracking", "functional"].includes(row.kind) || !TRANSPORT.test(row.transport) ||
        typeof row.context_completed !== "boolean") throw new Error("Invalid case identity");
    natural(row.received_canary_events, "canary events");
    natural(row.received_application_bytes, "origin bytes");
    if (row.received_canary_events > 0 && row.received_application_bytes === 0)
      throw new Error("Canary event without received bytes");
    if (row.kind === "tracking") {
      tracking++;
      if (row.functional_succeeded !== null) throw new Error("Tracking case cannot assert function");
    } else {
      functional++;
      if (typeof row.functional_succeeded !== "boolean" || row.received_canary_events !== 0)
        throw new Error("Invalid functional control");
    }
  }
  if (!tracking || !functional) throw new Error("Tracking and functional denominators required");
  return r;
}
function compareReceipts(beforeRaw, afterRaw) {
  const before = validateReceipt(beforeRaw), after = validateReceipt(afterRaw);
  if (before.sdk.name !== after.sdk.name) throw new Error("SDK identity changed");
  // A different revision label with identical source bytes cannot establish
  // SDK code drift; apparent traffic differences need a separate cause.
  if (before.sdk.bundle_sha256 === after.sdk.bundle_sha256)
    throw new Error("Identical SDK source bytes; no source drift to compare");
  const dimensions = ["fixture_sha256", "policy_sha256", "extension_sha256", "execution"];
  if (dimensions.some(k => before.setup[k] !== after.setup[k]))
    throw new Error("Environment, policy or fixture changed; not SDK-only drift");
  const oldCases = new Map(before.cases.map(row => [row.id, row]));
  if (oldCases.size !== after.cases.length) throw new Error("Changed case denominator");
  const newer = [], stopped = [], persistent = [], functionalRegressions = [], ambiguous = [];
  const increasedCanaryCounts = [], increasedTrackingBytes = [];
  for (const row of after.cases) {
    const old = oldCases.get(row.id);
    if (!old || row.kind !== old.kind || row.transport !== old.transport)
      throw new Error("Changed case identity or transport");
    if (row.kind === "tracking") {
      if (old.received_canary_events === 0 && row.received_canary_events > 0) newer.push(row.id);
      if (old.received_canary_events > 0 && row.received_canary_events === 0) stopped.push(row.id);
      if (row.received_canary_events > 0 && old.received_canary_events > 0) persistent.push(row.id);
      // A previously escaping channel can become materially noisier without
      // adding a new escaping case. Count increases are observed regressions.
      if (old.received_canary_events > 0 && row.received_canary_events > old.received_canary_events)
        increasedCanaryCounts.push({id: row.id, before: old.received_canary_events,
          after: row.received_canary_events});
      // Payload growth alone does not prove more tracking: compression, SDK
      // framing and unrelated bytes can explain it. Refuse a clean outcome.
      if (row.received_application_bytes > old.received_application_bytes)
        increasedTrackingBytes.push({id: row.id, before: old.received_application_bytes,
          after: row.received_application_bytes});
      // A body can be opaque to the synthetic canary parser. Never award a
      // zero-leak result when unexplained tracking-case bytes reached the sink.
      if (row.received_canary_events === 0 && row.received_application_bytes > 0) ambiguous.push(row.id);
    } else if (old.functional_succeeded &&
        (!row.functional_succeeded || row.received_application_bytes === 0))
      functionalRegressions.push(row.id);
  }
  const complete = [before, after].every(r =>
    r.setup.execution === "native-chrome-proxy" &&
    r.evidence.sender_completed && r.evidence.origin_tls_collector &&
    r.evidence.proxy_route_verified && r.evidence.origin_meter_valid &&
    r.evidence.positive_control_bytes > 0 && r.evidence.positive_control_events > 0 &&
    r.cases.every(row => row.context_completed)) &&
    before.cases.filter(row => row.kind === "functional").every(row =>
      row.functional_succeeded && row.received_application_bytes > 0);
  const status = !complete ? "NOT COVERED" :
    newer.length || increasedCanaryCounts.length || functionalRegressions.length ?
    "REGRESSION" : ambiguous.length || increasedTrackingBytes.length ?
    "NOT COVERED" : "NO NEW OBSERVED CANARY ESCAPE";
  return {
    schema: 1, status,
    qualification: "Input-declared controlled receiver evidence; no browser or proxy is launched by this tool.",
    sdk: before.sdk.name,
    before_revision: before.sdk.revision, after_revision: after.sdk.revision,
    before_bundle_sha256: before.sdk.bundle_sha256, after_bundle_sha256: after.sdk.bundle_sha256,
    pinned_setup: {...before.setup},
    cases_compared: after.cases.length,
    new_canary_escapes: newer.sort(), stopped_canary_escapes: stopped.sort(),
    persistent_canary_escapes: persistent.sort(), functional_regressions: functionalRegressions.sort(),
    increased_canary_event_counts: increasedCanaryCounts.sort((a, b) => a.id.localeCompare(b.id)),
    increased_tracking_bytes: increasedTrackingBytes.sort((a, b) => a.id.localeCompare(b.id)),
    unattributed_tracking_bytes: ambiguous.sort(),
    scope: "Exact locally pinned bundles and controlled cases only. Source pins and declared execution do not independently prove native enforcement. Positive opaque first-party bytes, unexplained tracking-byte growth and untested future sends remain unresolved."
  };
}
module.exports = {validateReceipt, compareReceipts};
