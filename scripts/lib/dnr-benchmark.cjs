"use strict";
// Deliberately bounded, offline model of one extension's pre-request DNR stage.
// This is not a browser emulator or evidence of Chrome rule installation.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const TYPES = new Set(["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "webtransport", "webbundle", "other"]);
const METHODS = new Set(["get", "head", "post", "put", "delete", "connect", "options", "trace", "patch", "other"]);
const CONDITIONS = new Set(["resourceTypes", "excludedResourceTypes", "requestMethods", "excludedRequestMethods", "requestDomains", "excludedRequestDomains", "initiatorDomains", "excludedInitiatorDomains", "topDomains", "excludedTopDomains", "domainType", "regexFilter", "urlFilter", "isUrlFilterCaseSensitive", "tabIds", "excludedTabIds", "responseHeaders", "excludedResponseHeaders"]);
const RANK = {allow: 4, block: 3, upgradeScheme: 2, redirect: 1};

function urlFilterRegex(value) {
  let out = "", start = 0;
  if (value.startsWith("||")) { out = "^[a-z][a-z0-9+.-]*://(?:[^/?#]*\\.)?"; start = 2; }
  else if (value.startsWith("|")) { out = "^"; start = 1; }
  for (let i = start; i < value.length; i++) {
    const ch = value[i];
    out += ch === "*" ? ".*" : ch === "^" ? "(?:[^A-Za-z0-9_.%-]|$)" : ch === "|" && i === value.length - 1 ? "$" : ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return out;
}
function domainMatcher(list) {
  if (!list) return null;
  const names = new Set(list.map((x) => x.toLowerCase()));
  return (host) => {
    if (!host) return false;
    for (let tail = host.toLowerCase(); tail; tail = tail.includes(".") ? tail.slice(tail.indexOf(".") + 1) : "") if (names.has(tail)) return true;
    return false;
  };
}
function normalizeRequest(request) {
  const url = new URL(request.url);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || /[^\x20-\x7e]/.test(request.url)) throw new Error("Benchmark supports ASCII HTTP(S) requests without URL credentials only");
  if (!TYPES.has(request.type)) throw new Error(`Unsupported resource type ${request.type}`);
  if (!METHODS.has((request.method || "get").toLowerCase())) throw new Error(`Unsupported request method ${request.method}`);
  url.hash = ""; // Fragments are not sent in requests.
  const initiator = request.initiator ? new URL(request.initiator).hostname : null;
  const top = request.topUrl ? new URL(request.topUrl).hostname : initiator;
  return {...request, url: url.href, host: url.hostname, initiatorHost: initiator, topHost: top, method: (request.method || "get").toLowerCase()};
}
function compileRule(rule, siteOf) {
  const c = rule.condition || {};
  if (!Number.isInteger(rule.id) || rule.id < 1 || rule.priority !== undefined && (!Number.isInteger(rule.priority) || rule.priority < 1) || typeof c !== "object" || Array.isArray(c)) throw new Error("Malformed DNR rule");
  for (const key of Object.keys(c)) if (!CONDITIONS.has(key)) throw new Error(`Unmodeled DNR condition ${key} in ${rule.ruleset}:${rule.id}`);
  if (c.domainType !== undefined && !["firstParty", "thirdParty"].includes(c.domainType)) throw new Error("Malformed DNR domainType");
  if (c.isUrlFilterCaseSensitive !== undefined && typeof c.isUrlFilterCaseSensitive !== "boolean") throw new Error("Malformed DNR case sensitivity");
  for (const [key, value] of Object.entries(c)) {
    if (/Domains$|Methods$|Types$/.test(key)) {
      if (!Array.isArray(value) || !value.length || value.some((entry) => typeof entry !== "string" || !entry)) throw new Error(`Malformed DNR ${key}`);
      const values = /Types$/.test(key) ? TYPES : /Methods$/.test(key) ? METHODS : null;
      if (values && value.some((entry) => !values.has(entry))) throw new Error(`Unmodeled DNR ${key} value`);
    }
    if (/TabIds$|^tabIds$/.test(key) && (!Array.isArray(value) || !value.length || value.some((entry) => !Number.isInteger(entry) || entry < -1))) throw new Error(`Malformed DNR ${key}`);
    if (["urlFilter", "regexFilter"].includes(key) && (typeof value !== "string" || !value)) throw new Error(`Malformed DNR ${key}`);
    if (["responseHeaders", "excludedResponseHeaders"].includes(key) && (!Array.isArray(value) || !value.length || value.some((entry) => !entry || typeof entry.header !== "string" || !entry.header))) throw new Error(`Malformed DNR ${key}`);
  }
  if (!Object.hasOwn(RANK, rule.action.type) && rule.action.type !== "modifyHeaders") throw new Error(`Unmodeled DNR action ${rule.action.type}; frame inheritance is not modeled`);
  if (c.urlFilter && c.regexFilter) throw new Error("Rule has both filter forms");
  const rx = c.regexFilter || (c.urlFilter && urlFilterRegex(c.urlFilter));
  const pattern = rx ? new RegExp(rx, c.isUrlFilterCaseSensitive ? "" : "i") : null;
  const lists = Object.fromEntries(["requestDomains", "excludedRequestDomains", "initiatorDomains", "excludedInitiatorDomains", "topDomains", "excludedTopDomains"].map((key) => [key, domainMatcher(c[key])]));
  const has = (key, value) => c[key] && c[key].includes(value);
  return {rule, test(request) {
    // Header-stage blocks cannot establish that a request was prevented before sending.
    if (c.responseHeaders || c.excludedResponseHeaders) return false;
    if (c.resourceTypes ? !has("resourceTypes", request.type) : request.type === "main_frame") return false;
    if (has("excludedResourceTypes", request.type)) return false;
    if (c.requestMethods && !has("requestMethods", request.method) || has("excludedRequestMethods", request.method)) return false;
    if (c.tabIds && !has("tabIds", request.tabId) || has("excludedTabIds", request.tabId)) return false;
    for (const [include, exclude, host] of [["requestDomains", "excludedRequestDomains", request.host], ["initiatorDomains", "excludedInitiatorDomains", request.initiatorHost], ["topDomains", "excludedTopDomains", request.topHost]]) {
      if (lists[include] && !lists[include](host) || lists[exclude] && lists[exclude](host)) return false;
    }
    const firstParty = !!request.initiatorHost && !!siteOf(request.host) && siteOf(request.host) === siteOf(request.initiatorHost);
    if (c.domainType === "firstParty" && !firstParty || c.domainType === "thirdParty" && firstParty) return false;
    return !pattern || pattern.test(request.url);
  }};
}

function evaluateRequest(compiled, raw) {
  const request = normalizeRequest(raw);
  const matches = compiled.filter(({rule, test}) => rule.action.type !== "modifyHeaders" && test(request));
  matches.sort((a, b) => (b.rule.priority || 1) - (a.rule.priority || 1) || RANK[b.rule.action.type] - RANK[a.rule.action.type]);
  const best = matches[0] && matches[0].rule;
  if (best && best.action.type === "redirect") {
    const peers = matches.filter(({rule}) => rule.action.type === "redirect" && (rule.priority || 1) === (best.priority || 1));
    if (peers.some(({rule}) => JSON.stringify(rule.action) !== JSON.stringify(best.action))) throw new Error(`Ambiguous equal-priority redirects for ${raw.url}`);
  }
  const localRedirect = best && best.action.type === "redirect" && (!!best.action.redirect.extensionPath || /^chrome-extension:\/\//.test(best.action.redirect.url || best.action.redirect.regexSubstitution || ""));
  const prevented = !!best && (best.action.type === "block" || localRedirect);
  const conditionSummary = best && Object.fromEntries(Object.entries(best.condition).map(([key, value]) => {
    if (!Array.isArray(value) || value.length <= 20) return [key, value];
    const host = /RequestDomains$|^requestDomains$/.test(key) ? request.host : /TopDomains$|^topDomains$/.test(key) ? request.topHost : request.initiatorHost;
    return [key, {entries: value.length, sha256: sha256(JSON.stringify(value)), matchingDomains: /Domains$/.test(key) && host ? value.filter((name) => host === name || host.endsWith(`.${name}`)) : []}];
  }));
  return {prevented, action: best ? best.action.type : "none", winner: best ? {ruleset: best.ruleset, id: best.id, priority: best.priority || 1, action: best.action.type, conditionSummary} : null,
    note: best && best.action.type === "redirect" && !localRedirect ? "Nonlocal redirect is not counted as prevented; no redirect-chain model." : null};
}

function summarize(corpus, results) {
  const byId = new Map(results.map((r) => [r.id, r]));
  const families = corpus.families.map((family) => {
    const cases = corpus.fixtures.filter((f) => f.family === family && f.label === "tracking");
    const mechanisms = [...new Set(cases.map((f) => f.mechanism))].map((mechanism) => {
      const members = cases.filter((f) => f.mechanism === mechanism);
      const escaped = members.filter((f) => !byId.get(f.id).prevented).length;
      return {mechanism, cases: members.length, escaped, escapeRate: escaped / members.length};
    });
    return {family, cases: cases.length, escaped: cases.filter((f) => !byId.get(f.id).prevented).length, escapeRate: mechanisms.reduce((sum, m) => sum + m.escapeRate, 0) / mechanisms.length, mechanisms};
  });
  const tracking = results.filter((r) => r.label === "tracking"), functional = results.filter((r) => r.label === "functional");
  return {trackingCases: tracking.length, escaped: tracking.filter((r) => !r.prevented).length, prevented: tracking.filter((r) => r.prevented).length,
    rawEscapeRate: tracking.filter((r) => !r.prevented).length / tracking.length,
    equalFamilyEscapeRate: families.reduce((sum, f) => sum + f.escapeRate, 0) / families.length,
    functionalCases: functional.length, functionalPrevented: functional.filter((r) => r.prevented).map((r) => r.id), families};
}

function artifactModel(directory) {
  const base = path.resolve(directory), manifestBytes = fs.readFileSync(path.join(base, "manifest.json")), manifest = JSON.parse(manifestBytes);
  const hosts = require(path.join(base, "core/hosts.js"));
  const resources = manifest.declarative_net_request.rule_resources;
  const hashes = [{path: "manifest.json", sha256: sha256(manifestBytes)}], rules = [];
  for (const resource of resources) {
    if (path.isAbsolute(resource.path) || resource.path.split(/[\\/]/).includes("..")) throw new Error("Ruleset path escapes artifact");
    const raw = fs.readFileSync(path.join(base, resource.path));
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || new Set(parsed.map((r) => r.id)).size !== parsed.length) throw new Error(`Invalid or duplicate rules in ${resource.id}`);
    hashes.push({path: resource.path, sha256: sha256(raw), enabled: resource.enabled, rules: parsed.length});
    if (resource.enabled) rules.push(...parsed.map((rule) => ({...rule, ruleset: resource.id})));
  }
  for (const name of ["core/psl-data.js", "core/hosts.js"]) hashes.push({path: name, sha256: sha256(fs.readFileSync(path.join(base, name)))});
  const notice = fs.readFileSync(path.join(base, "NOTICE.txt"), "utf8");
  let source = null;
  const inputs = [];
  for (const line of notice.split("\n")) {
    const match = line.match(/^\s+source:\s+(\S+)/);
    if (match) source = match[1];
    const digest = line.match(/sha256:\s+([0-9a-f]{64})/);
    if (digest && source) { inputs.push({url: source, sha256: digest[1]}); source = null; }
  }
  if (!inputs.length) throw new Error("Artifact source hashes are absent");
  inputs.sort((a, b) => a.url.localeCompare(b.url));
  return {compiled: rules.map((rule) => compileRule(rule, hosts.siteOf)), receipt: {version: manifest.version, rules: rules.length, enabledRulesets: resources.filter((r) => r.enabled).map((r) => r.id),
    sha256: sha256(JSON.stringify(hashes)), files: hashes, inputs, inputsSha256: sha256(JSON.stringify(inputs)),
    stage: "before-request; Standard; empty user state; all manifest-enabled static rules", nativeBrowserQualified: false}};
}
function benchmark(artifact, corpusFile) {
  const bytes = fs.readFileSync(corpusFile), corpus = JSON.parse(bytes), {compiled, receipt} = artifactModel(artifact);
  const ids = new Set();
  for (const f of corpus.fixtures) {
    if (ids.has(f.id) || !corpus.families.includes(f.family) || !corpus.sources[f.source] || !["tracking", "functional"].includes(f.label)) throw new Error(`Invalid fixture ${f.id}`);
    ids.add(f.id);
  }
  const results = corpus.fixtures.map((fixture) => ({id: fixture.id, family: fixture.family, mechanism: fixture.mechanism, label: fixture.label, ...evaluateRequest(compiled, fixture.request)}));
  return {schema: 1, evaluation: corpus.evaluation, corpusSha256: sha256(bytes), artifact: receipt, summary: summarize(corpus, results), results};
}
function compare(baseline, candidate) {
  if (baseline.corpusSha256 !== candidate.corpusSha256) throw new Error("Corpus changed after baseline freeze");
  if (baseline.artifact.inputsSha256 !== candidate.artifact.inputsSha256) throw new Error("Source snapshots differ; not a controlled comparison");
  const before = baseline.summary.equalFamilyEscapeRate, after = candidate.summary.equalFamilyEscapeRate;
  const previous = new Map(baseline.results.map((r) => [r.id, r]));
  const newFalsePositives = candidate.results.filter((r) => r.label === "functional" && r.prevented && !previous.get(r.id)?.prevented).map((r) => r.id);
  const regressions = candidate.results.filter((r) => r.label === "tracking" && !r.prevented && previous.get(r.id)?.prevented).map((r) => r.id);
  return {equalFamilyEscapeRateBefore: before, equalFamilyEscapeRateAfter: after, absoluteEscapeRateReduction: before - after,
    relativeEscapedRequestReduction: before ? (before - after) / before : null,
    rawEscapedBefore: baseline.summary.escaped, rawEscapedAfter: candidate.summary.escaped,
    rawRelativeEscapedRequestReduction: baseline.summary.escaped ? (baseline.summary.escaped - candidate.summary.escaped) / baseline.summary.escaped : null,
    newFalsePositives, regressions, metThirtyPercentTarget: before > 0 && (before - after) / before >= .3 && !newFalsePositives.length && !regressions.length,
    scope: "Frozen challenge corpus only; no internet-wide prevalence or anonymity claim."};
}
module.exports = {urlFilterRegex, normalizeRequest, compileRule, evaluateRequest, summarize, artifactModel, benchmark, compare, sha256};
