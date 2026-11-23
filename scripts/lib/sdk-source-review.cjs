"use strict";
// Offline source evidence, deliberately separate from SDK receiver receipts.
// Hash equality checks reviewed bytes. It cannot execute or interpret an SDK,
// authenticate a publisher, or promote source review into native enforcement.
const crypto = require("node:crypto");
const SDK_IDS = Object.freeze(["ga4", "gtm", "meta-pixel", "matomo", "posthog", "prebid", "fingerprint-pro"]);
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const ID = /^[a-z][a-z0-9-]{0,63}$/;
const REPOSITORY = /^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 32;
const NOT_COVERED = Object.freeze(["vendor-sdk-execution", "native-browser-enforcement", "receiver-bytes", "future-releases"]);

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join("|") !== [...expected].sort().join("|"))
    throw new Error("Invalid " + label + " structure");
}
function text(value, limit, label) {
  if (typeof value !== "string" || !value.trim() || value.length > limit || /[\u0000-\u001f]/.test(value))
    throw new Error("Invalid " + label);
}
function sourcePath(value) {
  text(value, 512, "source path");
  if (value.includes("\\") || value.includes(":")) throw new Error("Unsafe source path");
  const parts = value.split("/");
  if (parts.some(p => !p || p === "." || p === ".." || !/^[A-Za-z0-9_.@+-]+$/.test(p)))
    throw new Error("Unsafe source path");
  return value;
}
function date(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value) ||
      !Number.isFinite(Date.parse(value + "T00:00:00Z")) ||
      new Date(value + "T00:00:00Z").toISOString().slice(0, 10) !== value)
    throw new Error("Invalid " + label);
}
function documentURL(value) {
  text(value, 2048, "document URL");
  let url;
  try { url = new URL(value); } catch { throw new Error("Invalid document URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.port)
    throw new Error("Invalid document URL");
  return value;
}
function uniqueStrings(value, limit, label) {
  if (!Array.isArray(value) || value.length > limit || new Set(value).size !== value.length ||
      value.some(v => typeof v !== "string")) throw new Error("Invalid " + label);
  return value;
}
function validateSourceManifest(manifest) {
  exactKeys(manifest, ["schema", "id", "reviewed_on", "evidence_level", "not_covered", "sdks"], "source manifest");
  if (manifest.schema !== 1 || typeof manifest.id !== "string" || !ID.test(manifest.id) ||
      manifest.evidence_level !== "manual-source-review") throw new Error("Invalid source manifest identity");
  date(manifest.reviewed_on, "source review date");
  if ([...uniqueStrings(manifest.not_covered, NOT_COVERED.length, "uncovered scope")].sort().join("|") !==
      [...NOT_COVERED].sort().join("|")) throw new Error("Source review cannot assert runtime evidence");
  if (!Array.isArray(manifest.sdks) || manifest.sdks.length !== SDK_IDS.length)
    throw new Error("The seven-family source inventory is required");
  const sdkIds = new Set(); let fileCount = 0, totalBytes = 0;
  for (const sdk of manifest.sdks) {
    exactKeys(sdk, ["id", "name", "source_kind", "repository", "revision", "source_directory",
      "reviewed_files", "documents", "claims"], "SDK source inventory");
    if (!SDK_IDS.includes(sdk.id) || sdkIds.has(sdk.id)) throw new Error("Invalid SDK inventory denominator");
    sdkIds.add(sdk.id);
    text(sdk.name, 80, "SDK name");
    if (!["unacquired-sdk", "sdk-source", "server-source", "integration-documentation"].includes(sdk.source_kind))
      throw new Error("Unknown source evidence kind");
    if (!Array.isArray(sdk.reviewed_files) || sdk.reviewed_files.length > MAX_FILES)
      throw new Error("Invalid reviewed source files");
    const acquired = sdk.source_kind !== "unacquired-sdk";
    if (acquired ? !sdk.reviewed_files.length || !REPOSITORY.test(sdk.repository) ||
        !HEX40.test(sdk.revision) || sdk.source_directory !== sdk.id :
        sdk.reviewed_files.length || sdk.repository !== null || sdk.revision !== null || sdk.source_directory !== null)
      throw new Error("Inconsistent source acquisition evidence");
    const files = new Set();
    for (const file of sdk.reviewed_files) {
      exactKeys(file, ["path", "bytes", "sha256", "git_blob_sha1", "source_url", "acquired_on"], "source file pin");
      sourcePath(file.path);
      date(file.acquired_on, "source acquisition date");
      if (file.source_url !== `https://raw.githubusercontent.com/${sdk.repository}/${sdk.revision}/${file.path}`)
        throw new Error("Source URL does not match its pinned repository, revision and path");
      if (files.has(file.path) || !Number.isSafeInteger(file.bytes) || file.bytes < 1 ||
          file.bytes > MAX_FILE_BYTES || !HEX64.test(file.sha256) || !HEX40.test(file.git_blob_sha1))
        throw new Error("Invalid source file pin");
      files.add(file.path); fileCount++; totalBytes += file.bytes;
    }
    if (fileCount > MAX_FILES || totalBytes > MAX_TOTAL_BYTES) throw new Error("Source inventory exceeds bounds");
    if (!Array.isArray(sdk.documents) || sdk.documents.length > 12) throw new Error("Invalid source documents");
    const documents = new Map();
    for (const doc of sdk.documents) {
      exactKeys(doc, ["url", "review"], "source document");
      documentURL(doc.url);
      if (documents.has(doc.url) || !["primary-reviewed", "primary-inaccessible"].includes(doc.review))
        throw new Error("Invalid document review evidence");
      documents.set(doc.url, doc.review);
    }
    if (!Array.isArray(sdk.claims) || !sdk.claims.length || sdk.claims.length > 12)
      throw new Error("Invalid source claims");
    const claims = new Set();
    for (const claim of sdk.claims) {
      exactKeys(claim, ["id", "tier", "statement", "files", "documents", "limitations"], "source claim");
      if (typeof claim.id !== "string" || !ID.test(claim.id) || claims.has(claim.id) ||
          !["reviewed-source", "reviewed-primary-doc", "unverified-primary"].includes(claim.tier))
        throw new Error("Invalid claim evidence tier");
      claims.add(claim.id); text(claim.statement, 1200, "claim statement");
      uniqueStrings(claim.files, MAX_FILES, "claim files");
      uniqueStrings(claim.documents, 12, "claim documents");
      uniqueStrings(claim.limitations, 8, "claim limitations");
      if (!claim.limitations.length) throw new Error("Claim visibility limit is required");
      claim.limitations.forEach(v => text(v, 800, "claim limitation"));
      if (claim.files.some(p => !files.has(p)) || claim.documents.some(u => !documents.has(u)))
        throw new Error("Claim references unreviewed evidence");
      if (claim.tier === "reviewed-source" && !claim.files.length ||
          claim.tier === "reviewed-primary-doc" && (!claim.documents.length ||
            claim.documents.some(u => documents.get(u) !== "primary-reviewed")) ||
          claim.tier === "unverified-primary" && (claim.files.length || !claim.documents.length ||
            claim.documents.some(u => documents.get(u) !== "primary-inaccessible")))
        throw new Error("Claim tier does not match its evidence");
    }
  }
  return manifest;
}

function reviewSourcePins(raw, readSource) {
  const manifest = validateSourceManifest(raw);
  if (typeof readSource !== "function") throw new Error("Local source reader is required");
  const files = [], families = []; let totalBytes = 0;
  for (const sdk of manifest.sdks) {
    const rows = [];
    for (const pin of sdk.reviewed_files) {
      let bytes, status = "MATCH", actualSha = null, actualBlob = null, actualBytes = null;
      try {
        const allowance = Math.min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - totalBytes);
        if (allowance < 1) throw new Error("Source read budget exhausted");
        bytes = readSource(sdk.source_directory, pin.path, allowance);
        if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > allowance)
          throw new Error("Unreadable source");
        totalBytes += bytes.length;
        actualBytes = bytes.length;
        actualSha = crypto.createHash("sha256").update(bytes).digest("hex");
        actualBlob = crypto.createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
        if (bytes.length !== pin.bytes || actualSha !== pin.sha256 || actualBlob !== pin.git_blob_sha1)
          status = "MISMATCH";
      } catch (error) { status = error?.code === "ENOENT" ? "MISSING" : "UNREADABLE"; }
      const row = {sdk: sdk.id, path: pin.path, source_url: pin.source_url, acquired_on: pin.acquired_on,
        status, expected_bytes: pin.bytes, observed_bytes: actualBytes,
        expected_sha256: pin.sha256, observed_sha256: actualSha,
        expected_git_blob_sha1: pin.git_blob_sha1, observed_git_blob_sha1: actualBlob};
      rows.push(row); files.push(row);
    }
    families.push({id: sdk.id, source_kind: sdk.source_kind, repository: sdk.repository, revision: sdk.revision,
      source_status: !rows.length ? "NOT COVERED" : rows.every(r => r.status === "MATCH") ?
        "PINNED FILES VERIFIED" : rows.some(r => r.status === "MISMATCH") ? "SOURCE DRIFT" : "INCOMPLETE SOURCES",
      reviewed_files: rows.length, verified_files: rows.filter(r => r.status === "MATCH").length,
      claim_review: "MANUAL REVIEW RECORDED; NOT REVALIDATED BY HASH CHECK",
      vendor_sdk_execution: "NOT COVERED", native_browser_enforcement: "NOT COVERED"});
  }
  const mismatch = files.some(f => f.status === "MISMATCH"), incomplete = files.some(f => f.status !== "MATCH");
  return {
    schema: 1, manifest_id: manifest.id, reviewed_on: manifest.reviewed_on, evidence_level: "source-byte-check-only",
    status: mismatch ? "SOURCE DRIFT" : incomplete || !files.length ? "NOT COVERED" : "SOURCE PINS VERIFIED",
    inventory_families: manifest.sdks.length, families_with_verified_files: families.filter(f => f.source_status === "PINNED FILES VERIFIED").length,
    files_verified: files.filter(f => f.status === "MATCH").length, files_declared: files.length,
    vendor_sdk_execution: "NOT COVERED", native_browser_enforcement: "NOT COVERED", receiver_bytes: "NOT COVERED",
    not_covered: [...manifest.not_covered], families, files,
    qualification: "Checks only selected local bytes against a manually reviewed manifest. It does not authenticate the publisher or independently establish that a Git revision contains these files, re-evaluate source claims, execute an SDK, or verify browser/proxy enforcement. Documentation-only and proprietary bundles remain unacquired."
  };
}

module.exports = {SDK_IDS, MAX_FILE_BYTES, MAX_TOTAL_BYTES, validateSourceManifest, reviewSourcePins, sourcePath};
