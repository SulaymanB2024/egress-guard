// Read-only artifact inventory and optional Chrome isRegexSupported attestation.
// No process launch, ruleset mutation, dependency installation or network service.
// Native calls run only through an explicitly supplied extension-worker evaluator.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const LIMITS = Object.freeze({manifestBytes: 1024 * 1024, rulesetBytes: 32 * 1024 * 1024,
  totalBytes: 512 * 1024 * 1024, rulesets: 100, rules: 100000, regexes: 10000,
  regexBytes: 32768, totalRegexBytes: 8 * 1024 * 1024, depth: 24, batch: 16, failures: 100});
const sha = value => crypto.createHash("sha256").update(value).digest("hex");
const plain = value => value !== null && typeof value === "object" && !Array.isArray(value);
const own = (object, key) => Object.hasOwn(object, key);
class AttestationError extends Error {}
const insist = (condition, code) => { if (!condition) throw new AttestationError(code); };
const keysAre = (object, keys) => plain(object) && Object.keys(object).length === keys.length && keys.every(key => own(object, key));

function relativeParts(value) {
  insist(typeof value === "string" && value.length > 0 && value.length <= 1024 && !/[\\\0:%?#]/.test(value), "unsafe-artifact-path");
  const parts = value.split("/");
  insist(parts.every(part => part && part !== "." && part !== ".." && Buffer.byteLength(part) <= 255), "unsafe-artifact-path");
  return parts;
}

// JSON.parse alone silently accepts duplicate keys. Refuse ambiguous rule fields
// and deeply nested input before parsing the complete bounded artifact document.
function parseJson(bytes) {
  try { return parseJsonInner(bytes); }
  catch (error) { if (error instanceof AttestationError) throw error; throw new AttestationError("invalid-artifact-json"); }
}
function parseJsonInner(bytes) {
  const source = new TextDecoder("utf-8", {fatal: true}).decode(bytes), stack = [];
  let index = 0;
  while (index < source.length) {
    const token = source[index++];
    if (token === '"') {
      const start = index - 1; let closed = false;
      while (index < source.length) {
        if (source[index] === "\\") { index += 2; continue; }
        if (source[index++] === '"') { closed = true; break; }
      }
      insist(closed, "invalid-artifact-json");
      const top = stack.at(-1);
      if (top?.object && top.key) {
        const key = JSON.parse(source.slice(start, index));
        insist(!top.keys.has(key), "duplicate-artifact-json-key"); top.keys.add(key);
      }
    } else if (token === "{" || token === "[") {
      stack.push({object: token === "{", key: true, keys: new Set()});
      insist(stack.length <= LIMITS.depth, "artifact-json-depth");
    } else if (token === "}" || token === "]") stack.pop();
    else if (token === ":" && stack.at(-1)?.object) stack.at(-1).key = false;
    else if (token === "," && stack.at(-1)?.object) stack.at(-1).key = true;
  }
  return JSON.parse(source, (_key, value) => {
    insist(typeof value !== "number" || Number.isFinite(value), "invalid-artifact-number"); return value;
  });
}

function artifactReader(folder) {
  insist(typeof folder === "string" && path.isAbsolute(folder), "absolute-artifact-required");
  // Refuse a symlink supplied as the artifact itself. Canonicalize platform
  // ancestors (e.g. macOS /var) without accepting linked resources underneath it.
  const rootInfo = fs.lstatSync(path.resolve(folder));
  insist(rootInfo.isDirectory() && !rootInfo.isSymbolicLink(), "artifact-directory-required");
  const root = fs.realpathSync(folder), rootStat = fs.lstatSync(root); let total = 0;
  insist(rootStat.isDirectory() && !rootStat.isSymbolicLink(), "artifact-directory-required");
  const sameIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
  return (relative, limit) => {
    const parts = relativeParts(relative), lineage = [{name: root, stat: rootStat}]; let current = root;
    for (const part of parts.slice(0, -1)) {
      current = path.join(current, part); const info = fs.lstatSync(current);
      insist(info.isDirectory() && !info.isSymbolicLink(), "unsafe-artifact-directory");
      lineage.push({name: current, stat: info});
    }
    insist(typeof fs.constants.O_NOFOLLOW === "number", "secure-file-api-unavailable");
    const file = path.join(current, parts.at(-1));
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const start = fs.fstatSync(fd), allowance = Math.min(limit, LIMITS.totalBytes - total);
      insist(start.isFile() && start.nlink === 1, "independent-regular-artifact-required");
      const checkPath = () => {
        for (const entry of lineage) {
          const actual = fs.lstatSync(entry.name);
          insist(actual.isDirectory() && !actual.isSymbolicLink() && sameIdentity(actual, entry.stat), "artifact-path-changed");
        }
        const entry = fs.lstatSync(file);
        insist(entry.isFile() && !entry.isSymbolicLink() && entry.nlink === 1 && sameIdentity(entry, start) &&
          fs.realpathSync(file) === file, "artifact-path-changed");
      };
      // Revalidate the opened file against its original directory chain before
      // reading bytes and afterward. This detects observed path swaps; it is
      // not a sandbox against a hostile process with equal filesystem access.
      checkPath();
      insist(Number.isSafeInteger(start.size) && start.size <= allowance, "artifact-byte-limit");
      const buffer = Buffer.alloc(Math.min(start.size + 1, allowance + 1)); let length = 0;
      while (length < buffer.length) {
        const count = fs.readSync(fd, buffer, length, buffer.length - length, null);
        if (!count) break; length += count;
      }
      insist(length <= allowance, "artifact-byte-limit");
      const finish = fs.fstatSync(fd);
      insist(finish.isFile() && finish.nlink === 1 && finish.size === length && start.size === length &&
        start.dev === finish.dev && start.ino === finish.ino && start.mtimeMs === finish.mtimeMs, "artifact-changed-during-read");
      checkPath();
      total += length; return buffer.subarray(0, length);
    } finally { fs.closeSync(fd); }
  };
}

export function readArtifactRegexInventory(folder) {
  try { return readInventory(folder); }
  catch (error) { if (error instanceof AttestationError) throw error; throw new AttestationError("artifact-unreadable"); }
}
function readInventory(folder) {
  const read = artifactReader(folder), manifestBytes = read("manifest.json", LIMITS.manifestBytes);
  const manifest = parseJson(manifestBytes), resources = manifest?.declarative_net_request?.rule_resources;
  insist(manifest?.manifest_version === 3 && Array.isArray(resources) && resources.length > 0 && resources.length <= LIMITS.rulesets, "invalid-static-manifest");
  const files = [{path: "manifest.json", bytes: manifestBytes.length, sha256: sha(manifestBytes)}];
  const rows = [], rulesets = [], usedIds = new Set(), usedPaths = new Set();
  let rules = 0, regexBytes = 0;
  for (const resource of resources) {
    insist(keysAre(resource, ["id", "path", "enabled"]) && typeof resource.id === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(resource.id) && typeof resource.enabled === "boolean" &&
      !usedIds.has(resource.id), "invalid-static-declaration");
    relativeParts(resource.path); insist(!usedPaths.has(resource.path), "duplicate-static-path");
    usedIds.add(resource.id); usedPaths.add(resource.path);
    const bytes = read(resource.path, LIMITS.rulesetBytes), entries = parseJson(bytes);
    insist(Array.isArray(entries) && entries.length + rules <= LIMITS.rules, "artifact-rule-limit");
    rules += entries.length;
    const file = {path: resource.path, bytes: bytes.length, sha256: sha(bytes)}; files.push(file);
    const ids = new Set(), start = rows.length;
    for (const rule of entries) {
      insist(plain(rule) && Number.isInteger(rule.id) && rule.id >= 1 && rule.id <= 2147483647 &&
        !ids.has(rule.id) && plain(rule.condition) && plain(rule.action), "invalid-artifact-rule");
      ids.add(rule.id);
      if (!own(rule.condition, "regexFilter")) continue;
      const regex = rule.condition.regexFilter, isCaseSensitive = rule.condition.isUrlFilterCaseSensitive ?? false;
      insist(typeof regex === "string" && regex.length > 0 && typeof isCaseSensitive === "boolean" &&
        (!own(rule.condition, "isUrlFilterCaseSensitive") || typeof rule.condition.isUrlFilterCaseSensitive === "boolean"), "invalid-artifact-regex");
      const size = Buffer.byteLength(regex); regexBytes += size;
      insist(size <= LIMITS.regexBytes && regexBytes <= LIMITS.totalRegexBytes && rows.length < LIMITS.regexes, "artifact-regex-limit");
      const redirect = rule.action.type === "redirect" ? rule.action.redirect : null;
      const requireCapturing = plain(redirect) && own(redirect, "regexSubstitution");
      insist(!requireCapturing || typeof redirect.regexSubstitution === "string", "invalid-artifact-substitution");
      const options = Object.freeze({regex, isCaseSensitive, requireCapturing});
      rows.push(Object.freeze({ordinal: rows.length, ruleset: resource.id, id: rule.id, options,
        optionsSha256: sha(JSON.stringify(options))}));
    }
    rulesets.push(Object.freeze({id: resource.id, path: resource.path, enabled: resource.enabled,
      sha256: file.sha256, rules: entries.length, regexes: rows.length - start,
      regexRuleIdsSha256: sha(JSON.stringify(rows.slice(start).map(row => row.id)))}));
  }
  const metadata = {schema: 1, scope: "all-manifest-static-regexes-including-disabled", files: files.map(Object.freeze), rulesets,
    rules, regexes: rows.length, regexSourceBytes: regexBytes};
  const inputsSha256 = sha(JSON.stringify(rows.map(({ordinal, ruleset, id, optionsSha256}) => ({ordinal, ruleset, id, optionsSha256}))));
  const inventorySha256 = sha(JSON.stringify({metadata, inputsSha256}));
  return Object.freeze({...metadata, files: Object.freeze(metadata.files), rulesets: Object.freeze(rulesets), rows: Object.freeze(rows), inputsSha256, inventorySha256});
}

export function publicRegexInventory(inventory) {
  const {rows: _rows, ...publicFields} = inventory; return publicFields;
}

export function artifactRegexesUnchanged(folder, inventory) {
  try { return readArtifactRegexInventory(folder).inventorySha256 === inventory.inventorySha256; }
  catch { return false; }
}

// These self-contained functions are serialized into the loaded extension
// worker. Fetches stay on its own packaged origin. They never add/remove rules.
async function browserFiles(files) {
  try {
    if (typeof globalThis.chrome?.runtime?.getURL !== "function" || !globalThis.crypto?.subtle) return {available: false};
    const origin = new URL(chrome.runtime.getURL("/")).origin, result = [];
    for (const file of files) {
      const url = chrome.runtime.getURL(file.path);
      if (new URL(url).origin !== origin) return {available: false};
      const response = await fetch(url, {cache: "no-store", credentials: "omit", redirect: "error"});
      if (!response.ok || !response.body) return {available: false};
      const reader = response.body.getReader(), chunks = []; let size = 0;
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > file.bytes) { await reader.cancel(); return {available: true, mismatch: true, files: []}; }
        chunks.push(chunk.value);
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(value => value.toString(16).padStart(2, "0")).join("");
      result.push({path: file.path, bytes: size, sha256: hash});
    }
    return {available: true, mismatch: false, files: result};
  } catch { return {available: false}; }
}

async function browserBatch(rows) {
  if (typeof globalThis.chrome?.declarativeNetRequest?.isRegexSupported !== "function") return {available: false, attempted: 0, results: []};
  const results = await Promise.all(rows.map(async row => {
    // Hash the actual options passed to Chrome, including both explicit flags.
    const optionsSha256 = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(row.options))))]
      .map(value => value.toString(16).padStart(2, "0")).join("");
    try {
      const result = await chrome.declarativeNetRequest.isRegexSupported(row.options);
      return {ordinal: row.ordinal, optionsSha256, result};
    } catch { return {ordinal: row.ordinal, optionsSha256, error: "api-call-rejected"}; }
  }));
  return {available: true, attempted: rows.length, results};
}

export async function attestNativeRegexes({inventory, evaluate, recheck = () => false, browserProduct = null}) {
  const expected = inventory.regexes, results = new Map(), errors = [];
  const receipt = {schema: 1, status: "NOT COVERED", complete: false, api: "chrome.declarativeNetRequest.isRegexSupported",
    browserProduct, scope: inventory.scope, inventorySha256: inventory.inventorySha256, expectedInputsSha256: inventory.inputsSha256,
    expected, attempted: 0, checked: 0, passed: 0, rejected: 0, unavailable: expected,
    packagedFilesVerified: false, artifactUnchanged: false, checkedInputsSha256: null,
    rulesets: inventory.rulesets.map(row => ({id: row.id, enabled: row.enabled, expected: row.regexes,
      checked: 0, passed: 0, rejected: 0, unavailable: row.regexes})), errors, errorsOmitted: 0,
    limitation: "Regex compilation support only. Does not attest ruleset installation, enabled quotas, redirect rewrite validity, URL matches or transmitted bytes."};
  const error = (code, row) => {
    if (errors.length < LIMITS.failures) errors.push({code, ...(row ? {ruleset: row.ruleset, id: row.id} : {})});
    else receipt.errorsOmitted++;
  };
  const finish = async () => {
    receipt.artifactUnchanged = await Promise.resolve().then(recheck).then(Boolean, () => false);
    if (!receipt.artifactUnchanged) { error("artifact-changed"); receipt.status = "FAIL"; }
    receipt.unavailable = expected - receipt.checked;
    receipt.checkedInputsSha256 = sha(JSON.stringify(inventory.rows.filter(row => results.has(row.ordinal))
      .map(({ordinal, ruleset, id, optionsSha256}) => ({ordinal, ruleset, id, optionsSha256}))));
    receipt.complete = expected > 0 && receipt.checked === expected && receipt.checkedInputsSha256 === receipt.expectedInputsSha256 && receipt.packagedFilesVerified && receipt.artifactUnchanged;
    if (receipt.status !== "FAIL") receipt.status = receipt.rejected ? "FAIL" : receipt.complete ? "PASS" : "NOT COVERED";
    return receipt;
  };
  if (!Number.isSafeInteger(expected) || expected <= 0 || expected !== inventory.rows.length || typeof evaluate !== "function") {
    error("no-complete-regex-inventory"); return finish();
  }
  let packaged;
  try { packaged = await evaluate(`(${browserFiles.toString()})(${JSON.stringify(inventory.files)})`); }
  catch { error("packaged-assets-unavailable"); return finish(); }
  if (packaged?.available !== true) { error("packaged-assets-unavailable"); return finish(); }
  if (packaged.mismatch !== false || JSON.stringify(packaged.files) !== JSON.stringify(inventory.files)) {
    error("packaged-asset-mismatch"); receipt.status = "FAIL"; return finish();
  }
  receipt.packagedFilesVerified = true;
  for (let offset = 0; offset < expected; offset += LIMITS.batch) {
    const batch = inventory.rows.slice(offset, offset + LIMITS.batch); let reply;
    try { reply = await evaluate(`(${browserBatch.toString()})(${JSON.stringify(batch.map(({ordinal, options}) => ({ordinal, options})))})`); }
    catch { for (const row of batch) error("native-api-unavailable", row); continue; }
    if (reply?.available === false) { error("native-api-unavailable"); break; }
    if (!keysAre(reply, ["available", "attempted", "results"]) || reply.available !== true || reply.attempted !== batch.length ||
        !Array.isArray(reply.results) || reply.results.length !== batch.length) {
      for (const row of batch) error("incomplete-native-batch", row); continue;
    }
    receipt.attempted += reply.attempted;
    for (let index = 0; index < batch.length; index++) {
      const row = batch[index], answer = reply.results[index];
      if (!plain(answer) || answer.ordinal !== row.ordinal || answer.optionsSha256 !== row.optionsSha256 ||
          !keysAre(answer, ["ordinal", "optionsSha256", own(answer, "result") ? "result" : "error"])) { error("mismatched-native-answer", row); continue; }
      if (own(answer, "error")) { error("native-api-unavailable", row); continue; }
      const native = answer.result;
      const supported = keysAre(native, ["isSupported"]) && native.isSupported === true;
      const rejected = keysAre(native, ["isSupported", "reason"]) && native.isSupported === false &&
        ["syntaxError", "memoryLimitExceeded"].includes(native.reason);
      if (!supported && !rejected) { error("invalid-native-result", row); continue; }
      results.set(row.ordinal, supported); receipt.checked++;
      const set = receipt.rulesets.find(value => value.id === row.ruleset); set.checked++; set.unavailable--;
      if (supported) { receipt.passed++; set.passed++; }
      else { receipt.rejected++; set.rejected++; error(native.reason, row); }
    }
  }
  return finish();
}
