#!/usr/bin/env node
// Build the browser companion for Chrome and Firefox from the shared sources in browser/.
//
//   node scripts/build-browser.mjs [--feeds DIR] [--tier pro.plus] [--out dist-browser] [--no-lists]
//
// Lists come from the proxy's verified feed cache (DIR/blocklists/*.txt|*.exact, the files
// `egress-guard` writes after downloading and validating each feed). Each snapshot is checked again
// here: SHA-256 of the body against its header, entry count, hostname syntax and the proxy's minimum
// size. URL-filter downloads happen only at build time; --offline uses verified caches.
// The extension itself never downloads filters or executable code.
// Plain Node, no dependencies. Output is gitignored.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "browser");
const dnr = require(path.join(SRC, "core/dnr.js"));
const abp = require(path.join(ROOT, "scripts/lib/abp-dnr.cjs"));
const cosmetics = require(path.join(ROOT, "scripts/lib/cosmetic-compiler.cjs"));

// Mirrors src/egress_guard/feeds.py (tests/browser/build.test.cjs checks they stay in sync).
const HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";
const ADGUARD = "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/";
const HAGEZI_LICENSE = {name: "GPL-3.0", url: "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE"};
const ADGUARD_LICENSE = {name: "MIT", url: "https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE"};
export const TIERS = {
  "pro": {name: "HaGeZi Multi PRO", minimum: 20000},
  "pro.plus": {name: "HaGeZi Multi PRO++", minimum: 50000},
  "ultimate": {name: "HaGeZi Multi Ultimate", minimum: 50000},
};
export const THREAT_TIERS = {
  full: {id: "hagezi-threat-intel-full", name: "HaGeZi Threat Intelligence (Full)", url: HAGEZI + "tif-onlydomains.txt", minimum: 500000},
  medium: {id: "hagezi-threat-intel", name: "HaGeZi Threat Intelligence (Medium)", url: HAGEZI + "tif.medium-onlydomains.txt", minimum: 100000},
};
const PHISHING_ARMY = {id: "phishing-army", name: "Phishing Army", url: "https://phishing.army/download/phishing-army-domains.txt",
  minimum: 20000, license: {name: "Phishing Army terms (upstream sources' terms apply)", url: "https://phishing.army/license/"}};
const URLHAUS = {id: "urlhaus-filter", name: "URLhaus malware hosts (malware-filter)",
  url: "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains.txt", minimum: 1000, ips: true,
  license: {name: "CC0-1.0 and MIT", url: "https://gitlab.com/malware-filter/urlhaus-filter#license"}};

/**
 * Feeds per list kind. Threats mirror the proxy's threat group (feeds.selected_feeds): URLhaus, Phishing Army and a
 * HaGeZi Threat Intelligence tier. `threatTier` "full" (the proxy's default) falls back to "medium" when only the
 * medium snapshot is cached. The DoH list is not used: DNR cannot see Chrome's own secure-DNS lookups, and blocking
 * page requests to resolver hosts protects nothing.
 */
export function feedSpecs(tier, threatTier = "full") {
  const t = TIERS[tier];
  if (!t) throw new Error(`unknown tier ${tier}; use ${Object.keys(TIERS).join(", ")}`);
  if (!THREAT_TIERS[threatTier]) throw new Error(`unknown threat tier ${threatTier}; use full or medium`);
  const hagezi = (key, extra = {}) => ({...THREAT_TIERS[key], file: `${THREAT_TIERS[key].id}.txt`, license: HAGEZI_LICENSE, hagezi: true, ...extra});
  return {
    threats: [
      {...URLHAUS, file: `${URLHAUS.id}.txt`},
      {...PHISHING_ARMY, file: `${PHISHING_ARMY.id}.txt`},
      threatTier === "full" ? hagezi("full", {fallback: hagezi("medium")}) : hagezi("medium"),
    ],
    trackers: [{id: `hagezi-${tier}`, file: `hagezi-${tier}.txt`, name: t.name, url: HAGEZI + `${tier}-onlydomains.txt`,
      minimum: t.minimum, license: HAGEZI_LICENSE}],
    cname: ["ads", "trackers"].map((category) => ({id: `adguard-cname-${category}`, file: `adguard-cname-${category}.exact`,
      name: `AdGuard CNAME-cloaked ${category}`, url: ADGUARD + `combined_disguised_${category}_justdomains.txt`,
      minimum: category === "ads" ? 1000 : 20000, license: ADGUARD_LICENSE})),
  };
}

// ---- URL filter lists (EasyPrivacy, EasyList) ------------------------------------------------------------------
// Not proxy feeds (the proxy matches host names only), so the build keeps its own cache: <data>/browser-filters/
// <id>.snapshot atomically contains a bounded metadata line plus the exact downloaded body. Legacy .txt/.json
// pairs are read only when no snapshot exists. The build downloads a list only when its cached copy is missing
// or older than FILTER_MAX_AGE; --offline never does.
// The extension itself never fetches anything.
const EASYLIST_LICENSE = {name: "GPL-3.0 or CC BY-SA 3.0 (dual licensed)", url: "https://easylist.to/pages/licence.html"};
export const FILTER_LISTS = Object.freeze([
  {id: "easyprivacy", name: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt", minimum: 20000, license: EASYLIST_LICENSE},
  {id: "easylist", name: "EasyList", url: "https://easylist.to/easylist/easylist.txt", minimum: 20000, license: EASYLIST_LICENSE},
  // Not a filter list: first-party click-through subdomains that CNAME to affiliate and email click trackers. Used
  // for the "bounce" ruleset (their cookies are stripped on the hop), never to block a navigation.
  {id: "adguard-clickthroughs", kind: "domains", name: "AdGuard disguised click-throughs", minimum: 5000,
    url: "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs_justdomains.txt",
    license: {name: "MIT", url: "https://github.com/AdguardTeam/cname-trackers/blob/master/LICENSE"}},
]);
const FILTER_MAX_AGE = 24 * 3600;
const MAX_FILTER_BYTES = 16 * 1024 * 1024;
// An upstream list is unpinned: a fresh copy whose size, entry count or exception count moved by more than this factor
// since the last accepted copy (recorded beside its hash in snapshot metadata) fails the build until someone has looked at it
// (`--accept-list-change ID`).
export const LIST_CHANGE_FACTOR = 2;
// Exceptions and $important filters not anchored to a host are dropped and counted (scripts/lib/abp-dnr.cjs). A few are
// ordinary list noise; more than this many in one list means the list is not what it should be, and the build stops.
export const MAX_SUSPICIOUS = 25;

/** Counts recorded beside a list's hash: size, entries, and (filter lists) exception lines. */
export function listCounts(spec, body) {
  const text = body.toString("utf8");
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("!") && !l.startsWith("[") && !l.startsWith("#"));
  return {bytes: body.length, entries: lines.length, exceptions: spec.kind === "domains" ? 0 : lines.filter((l) => l.startsWith("@@")).length};
}

/** Throws when `next` moved by more than LIST_CHANGE_FACTOR from `prior` on any recorded count. */
export function checkListChange(spec, prior, next, factor = LIST_CHANGE_FACTOR) {
  if (!prior) return;
  for (const key of ["bytes", "entries", "exceptions"]) {
    const a = Number(prior[key]), b = Number(next[key]);
    if (!Number.isFinite(a) || !Number.isFinite(b)) continue;
    // Small counts (a handful of exceptions) may double without meaning anything; compare above a floor.
    const lo = Math.max(Math.min(a, b), 50), hi = Math.max(a, b);
    if (hi > lo * factor) {
      const error = new Error(`${spec.name}: ${key} changed from ${a} to ${b} since the last accepted copy (more than ${factor}×). Review the new list, then rebuild with --accept-list-change ${spec.id}`);
      error.listChange = true;
      throw error;
    }
  }
}

export function defaultFiltersDir() { return path.join(defaultFeedsDir(), "browser-filters"); }

/** Check one downloaded or cached list body. Returns its header; throws with a reason. */
export function checkFilterBody(spec, body) {
  if (body.length > MAX_FILTER_BYTES) throw new Error(`${spec.name} exceeds ${MAX_FILTER_BYTES} bytes`);
  const text = body.toString("utf8");
  if (spec.kind === "domains") {
    const names = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("!"));
    // A few entries (underscored labels such as "mkt_vis.example") are not host names Chrome rules accept; they are
    // left out when the list is used. More than 1% of them means the file is not what it should be.
    const bad = names.filter((n) => !dnsName(n));
    if (bad.length > names.length / 100) throw new Error(`${spec.name} has ${bad.length} invalid hostnames, e.g. ${JSON.stringify(bad[0].slice(0, 80))}`);
    if (names.length < spec.minimum) throw new Error(`${spec.name} has ${names.length} names, fewer than the minimum of ${spec.minimum}`);
    return {filters: names.length, names};
  }
  if (!/^\[Adblock Plus[^\]]*\]\r?\n/.test(text)) throw new Error(`${spec.name} has no "[Adblock Plus …]" header`);
  const head = abp.header(text);
  if (head.title !== spec.name) throw new Error(`${spec.name}: unexpected title ${JSON.stringify(head.title || null)}`);
  if (!head.licence || !head.licence.includes("easylist.to/pages/licence")) throw new Error(`${spec.name}: licence line missing or changed; review it before building`);
  const filters = text.split("\n").filter((l) => l && !l.startsWith("!") && !l.startsWith("[")).length;
  if (filters < spec.minimum) throw new Error(`${spec.name} has ${filters} filters, fewer than the minimum of ${spec.minimum}`);
  return {...head, filters};
}

function readBoundedFile(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > limit) throw new Error(`${path.basename(file)} is not a bounded regular file`);
    const chunks = [];
    let total = 0;
    for (;;) {
      const buffer = Buffer.alloc(Math.min(65536, limit + 1 - total));
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!count) return Buffer.concat(chunks, total);
      total += count;
      if (total > limit) throw new Error("Cached file exceeded its size limit while reading.");
      chunks.push(buffer.subarray(0, count));
    }
  } finally { fs.closeSync(fd); }
}

export const FILTER_CACHE_MAGIC = "# egress-guard-browser-filter-v1 ";
export const MAX_FILTER_META_BYTES = 65536;

function verifyCachedFilter(spec, body, meta) {
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) throw new Error(`${spec.id} cache metadata is invalid`);
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  if (digest !== meta.sha256) throw new Error(`${spec.id} cache body SHA-256 does not match its metadata`);
  if (meta.url !== spec.url || meta.id !== undefined && meta.id !== spec.id) throw new Error(`${spec.id} cache names a different source`);
  checkFilterBody(spec, body);
  const counts = listCounts(spec, body);
  for (const key of ["bytes", "entries", "exceptions"]) {
    if (meta[key] !== undefined && meta[key] !== counts[key]) throw new Error(`${spec.id} cached ${key} does not match its body`);
  }
  // Legacy caches may predate recorded counts; always derive the comparison
  // baseline from the same verified body instead of trusting absent metadata.
  return {body, meta: {...meta, ...counts}};
}

export function readCachedFilter(dir, spec) {
  const snapshot = path.join(dir, `${spec.id}.snapshot`);
  let exists = true;
  try { fs.lstatSync(snapshot); } catch (error) { if (error.code === "ENOENT") exists = false; else throw error; }
  if (exists) {
    const raw = readBoundedFile(snapshot, Buffer.byteLength(FILTER_CACHE_MAGIC) + MAX_FILTER_META_BYTES + 1 + MAX_FILTER_BYTES);
    const newline = raw.indexOf(0x0a), start = Buffer.byteLength(FILTER_CACHE_MAGIC);
    if (newline < start || newline - start > MAX_FILTER_META_BYTES || !raw.subarray(0, start).equals(Buffer.from(FILTER_CACHE_MAGIC))) {
      throw new Error(`${spec.id} snapshot has an invalid or oversized metadata header`);
    }
    const meta = JSON.parse(raw.subarray(start, newline).toString("utf8"));
    return verifyCachedFilter(spec, raw.subarray(newline + 1), meta);
  }
  // Read-only migration: the old pair is never overwritten or removed. The next
  // successful download publishes a single snapshot that takes precedence.
  const body = readBoundedFile(path.join(dir, `${spec.id}.txt`), MAX_FILTER_BYTES);
  const meta = JSON.parse(readBoundedFile(path.join(dir, `${spec.id}.json`), MAX_FILTER_META_BYTES).toString("utf8"));
  return verifyCachedFilter(spec, body, meta);
}

async function downloadFilter(spec, fetchImpl) {
  const response = await fetchImpl(spec.url, {redirect: "error", signal: AbortSignal.timeout(60000), headers: {"accept": "text/plain"}});
  if (!response.ok) throw new Error(`${spec.url}: HTTP ${response.status}`);
  if (response.url && (new URL(response.url).origin !== new URL(spec.url).origin || !response.url.startsWith("https://"))) throw new Error(`${spec.url} changed its trusted source origin`);
  const declared = Number(response.headers.get("content-length"));
  if (declared > MAX_FILTER_BYTES) throw new Error(`${spec.url} is larger than ${MAX_FILTER_BYTES} bytes`);
  if (!response.body || typeof response.body.getReader !== "function") throw new Error("Filter response has no bounded readable body.");
  const reader = response.body.getReader(), chunks = [];
  let received = 0;
  try {
    for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_FILTER_BYTES) throw new Error("Filter download exceeded its size limit.");
      chunks.push(Buffer.from(value));
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const body = Buffer.concat(chunks, received);
  const head = checkFilterBody(spec, body);
  return {body, meta: {id: spec.id, url: spec.url, sha256: crypto.createHash("sha256").update(body).digest("hex"), bytes: body.length,
    fetched_at: Math.floor(Date.now() / 1000), version: head.version || null, last_modified: head.last_modified || null, licence: head.licence,
    ...listCounts(spec, body)}};
}

function writeAtomic(file, data) {
  // A private, unique staging directory prevents predictable temporary-file
  // collisions. Until the one rename succeeds, the prior cache is untouched.
  const stage = fs.mkdtempSync(path.join(path.dirname(file), ".filter-write-"));
  const temporary = path.join(stage, "snapshot");
  try {
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try {
      fs.writeFileSync(fd, data);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    fs.renameSync(temporary, file);
    // Persist the destination directory entry where directory fsync is supported.
    if (process.platform !== "win32") {
      const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
      try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
    }
  } finally { fs.rmSync(stage, {recursive: true, force: true}); }
}

function writeCachedFilter(dir, spec, value) {
  const {body, meta} = verifyCachedFilter(spec, value.body, value.meta);
  const header = Buffer.from(JSON.stringify(meta));
  if (header.length > MAX_FILTER_META_BYTES) throw new Error(`${spec.id} cache metadata exceeds its size limit`);
  const snapshot = Buffer.concat([Buffer.from(FILTER_CACHE_MAGIC), header, Buffer.from("\n"), body]);
  writeAtomic(path.join(dir, `${spec.id}.snapshot`), snapshot);
}

/**
 * The URL filter lists for a build: cached copies younger than a day, otherwise a fresh download (verified, then
 * cached). A failed download falls back to the cache with a warning; with neither, that list is left out.
 */
export async function loadFilters(dir, {offline = false, allowMissing = false, log = () => {}, fetchImpl = globalThis.fetch, now = Date.now() / 1000, acceptChange = []} = {}) {
  fs.mkdirSync(dir, {recursive: true, mode: 0o700});
  const out = {};
  for (const spec of FILTER_LISTS) {
    let cached = null;
    try { cached = readCachedFilter(dir, spec); } catch (error) { if (error.code !== "ENOENT") log(`${spec.id} cache unusable: ${error.message}`); }
    let use = cached;
    if (!offline && (!cached || now - cached.meta.fetched_at > FILTER_MAX_AGE)) {
      let fresh = null;
      try {
        fresh = await downloadFilter(spec, fetchImpl);
      } catch (error) {
        log(`could not download ${spec.name}: ${error.message}${cached ? "; using the cached copy" : ""}`);
      }
      if (fresh) {
        // Compare with the last accepted copy (its counts were recorded beside its hash). A big move fails the build.
        if (cached && !acceptChange.includes(spec.id)) checkListChange(spec, {...listCounts(spec, cached.body), ...cached.meta}, fresh.meta);
        writeCachedFilter(dir, spec, fresh);
        use = fresh;
      }
    }
    if (!use) {
      if (!allowMissing) throw new Error(`Required filter ${spec.name} is unavailable; refresh it or explicitly use --allow-missing for a reduced build.`);
      log(`${spec.name} is not available: the build has no ${spec.name} rules`); continue;
    }
    out[spec.id] = {text: use.body.toString("utf8"), source: {id: spec.id, name: spec.name, url: spec.url, license: spec.license,
      sha256: use.meta.sha256, bytes: use.meta.bytes, fetched_at: use.meta.fetched_at, version: use.meta.version, last_modified: use.meta.last_modified,
      stale: !Number.isFinite(use.meta.fetched_at) || now - use.meta.fetched_at > FILTER_MAX_AGE}};
  }
  return out;
}

/**
 * Compile EasyPrivacy and EasyList into rulesets: "fp-trackers" (EasyPrivacy path filters that match on any host,
 * which is what catches first-party and proxied trackers, plus the hand-written ones), "easyprivacy" (the rest),
 * "easylist", and "filter-allow" (both lists' exceptions). Each list's blocks and exceptions sit at that list's own
 * pair of priorities (dnr.FILTER_PRIORITY), so EasyList's exceptions cannot lift EasyPrivacy's blocks, and no list
 * exception reaches the hand-written filters or any cleaning rule. Returns {rulesets: {id: rules}, stats}.
 */
export function compileFilterRulesets(filters, {maxSuspicious = MAX_SUSPICIOUS} = {}) {
  const P = dnr.PRIORITY;
  const sets = {"fp-trackers": dnr.compileHand("fp-trackers"), easyprivacy: [], easylist: [], "filter-allow": [], replay: dnr.compileHand("replay")};
  const stats = {};
  const generic = (r) => r.condition.urlFilter && !r.condition.urlFilter.startsWith("||") && !r.condition.urlFilter.startsWith("|") && !r.condition.requestDomains;
  for (const spec of FILTER_LISTS) {
    const data = filters && filters[spec.id];
    if (!data || spec.kind === "domains") continue;
    const compiled = abp.compileFilters(data.text);
    stats[spec.id] = {...compiled.stats, blockingRules: compiled.block.length + compiled.important.length};
    if (compiled.stats.suspicious > maxSuspicious) {
      throw new Error(`${spec.name} has ${compiled.stats.suspicious} exceptions or $important filters not anchored to a host (at most ${maxSuspicious} allowed), e.g. ${JSON.stringify(compiled.stats.suspiciousLines[0])}. Review the list before building.`);
    }
    const pri = dnr.FILTER_PRIORITY[spec.id];
    const place = (set, rule, priority) => sets[set].push({id: sets[set].length + 1, priority, ...rule});
    for (const rule of compiled.block) place(spec.id === "easyprivacy" && generic(rule) ? "fp-trackers" : spec.id, rule, pri.block);
    for (const rule of compiled.important) place(spec.id, rule, P.filterImportant);
    for (const rule of compiled.allow) place("filter-allow", rule, pri.allow);
  }
  // Hosts the lists block wholesale (folded `||host^` filters): their third-party cookies are stripped whenever a
  // request to them still goes out (an exception, a list's own @@).
  const trackerDomains = [];
  for (const id of ["fp-trackers", "easyprivacy", "easylist"]) {
    for (const r of sets[id]) if (r.condition.requestDomains && !r.condition.initiatorDomains && !r.condition.urlFilter && !r.condition.regexFilter) trackerDomains.push(...r.condition.requestDomains);
  }
  return {rulesets: sets, stats, trackerDomains};
}

/** Host names from a "domains" list in the filter cache (already checked when cached). */
export function filterDomains(filters, id) {
  const data = filters && filters[id];
  if (!data) return [];
  // core/dnr.js compilePrivacy() takes only subdomains, and never payment, sign-in or console hosts, from this list.
  return data.text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("!") && dnsName(l));
}

const MAX_FEED_BYTES = 64 * 1024 * 1024;   // feeds.MAX_FEED_BYTES
const DNS_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DNS_NAME = new RegExp(`^(?:${DNS_LABEL}\\.)+${DNS_LABEL}$`);

/** Same rule as feeds.dns_name(dotted=True): lowercase ASCII, at least two labels, a letter in the last one. */
export function dnsName(value) {
  if (typeof value !== "string" || value.length > 253 || !DNS_NAME.test(value)) return null;
  return /[a-z]/.test(value.slice(value.lastIndexOf(".") + 1)) ? value : null;
}

/** Read and re-verify one proxy snapshot ("# {json}\n" + sorted names). Throws with a reason. */
/** IPv4 dotted quad or a bracket-free IPv6 literal, as feeds.ip_literal() stores them. */
export function ipLiteral(value) {
  if (/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(value)) return value;
  return /^[0-9a-f:]+$/.test(value) && value.includes(":") && value.length <= 39 ? value : null;
}

/**
 * Read and re-verify one proxy snapshot. With `ips`, IP literals are accepted and returned separately: Chrome's
 * requestDomains takes host names, so the extension uses only the names.
 */
export function readSnapshot(file, {minimum = 0, ips = false} = {}) {
  // Check what the path is before reading it: no symlinks, devices or directories, nothing oversized.
  const info = fs.lstatSync(file);
  if (!info.isFile()) throw new Error(`${path.basename(file)} is not a regular file`);
  if (info.size > MAX_FEED_BYTES) throw new Error("snapshot exceeds the size limit");
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  let data;
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== info.ino) throw new Error(`${path.basename(file)} is not a regular file`);
    data = fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
  if (data.length > MAX_FEED_BYTES) throw new Error("snapshot exceeds the size limit");
  const newline = data.indexOf(0x0a);
  if (newline < 0 || data[0] !== 0x23 || data[1] !== 0x20) throw new Error("snapshot has no metadata header");
  const meta = JSON.parse(data.subarray(2, newline).toString("utf8"));
  const body = data.subarray(newline + 1);
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  if (!meta || digest !== meta.sha256) throw new Error("snapshot SHA-256 does not match its header");
  const entries = body.toString("ascii").split("\n").filter(Boolean);
  if (entries.length !== meta.entries) throw new Error("snapshot entry count does not match its header");
  const names = [], addresses = [];
  for (const entry of entries) {
    if (dnsName(entry)) names.push(entry);
    else if (ips && ipLiteral(entry)) addresses.push(entry);
    else throw new Error(`snapshot contains an invalid hostname: ${JSON.stringify(entry.slice(0, 80))}`);
  }
  if (entries.length < minimum) throw new Error(`snapshot has ${entries.length} entries, fewer than the proxy's minimum of ${minimum}`);
  const stamp = (v) => (typeof v === "number" && v > 0 ? v : null);
  return {names, addresses, sha256: digest, published_at: stamp(meta.published_at), updated_at: stamp(meta.updated_at)};
}

export function defaultFeedsDir() {
  if (process.env.EGRESS_GUARD_DATA) return path.resolve(process.env.EGRESS_GUARD_DATA);
  if (process.platform === "darwin") return path.join(os.homedir(), "Library/Application Support/Egress Guard/data");
  if (process.platform === "win32") return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData/Local"), "Egress Guard/data");
  return path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local/state"), "egress-guard");
}

/**
 * Load every list for `tier` from `feedsDir/blocklists`. Missing files are reported, never guessed. A missing
 * malware and phishing feed is fatal unless `allowMissing`: a build without it would silently protect nothing.
 */
export function loadLists(feedsDir, {tier = "pro.plus", threatTier = "full", allowSmall = false, allowMissing = false, log = () => {}} = {}) {
  const dir = path.join(feedsDir, "blocklists");
  const exists = (file) => { try { fs.lstatSync(file); return true; } catch { return false; } };
  const out = {};
  for (const [kind, specs] of Object.entries(feedSpecs(tier, threatTier))) {
    const names = [];
    const sources = [];
    for (let spec of specs) {
      if (!exists(path.join(dir, spec.file)) && spec.fallback && exists(path.join(dir, spec.fallback.file))) {
        log(`${spec.file} not cached; using ${spec.fallback.name}`);
        spec = spec.fallback;
      }
      const file = path.join(dir, spec.file);
      if (!exists(file)) {
        // Every selected source is required. Reduced development builds must opt in and carry a coverage receipt.
        if (!allowMissing) throw new Error(`Required ${kind} feed ${spec.file} is missing from ${dir}; refresh the proxy's feeds, or pass --allow-missing for a reduced build`);
        log(`missing ${spec.file}: ${kind} list will not include ${spec.name}`);
        continue;
      }
      const snap = readSnapshot(file, {minimum: allowSmall ? 0 : spec.minimum, ips: Boolean(spec.ips)});
      for (const name of snap.names) names.push(name);
      if (snap.addresses.length) log(`${spec.file}: ${snap.addresses.length} IP addresses not used (Chrome rules match host names)`);
      sources.push({id: spec.id, name: spec.name, url: spec.url, license: spec.license, entries: snap.names.length,
        sha256: snap.sha256, published_at: snap.published_at, updated_at: snap.updated_at});
    }
    out[kind] = {names, sources, required: specs.map(spec => spec.id), development: allowSmall};
  }
  return out;
}

function chromeExtensionId(manifest) {
  return dnr.extensionIdFromHex(crypto.createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex"));
}

const SHARED = ["core/psl-data.js", "core/hosts.js", "core/selectors.js", "core/rules.js", "core/decide.js", "core/store.js", "core/picker.js", "core/links.js", "core/params.js", "core/dnr.js", "core/cosmetic-data.js", "core/cosmetic-selectors.js", "core/cosmetic.js", "core/semantic.js",
  "vendor/PSL-NOTICE.md", "vendor/public_suffix_list.dat", "content.js", "popup.html", "popup.css", "popup.js", "ui.css"];
const SURROGATE_FILES = [...new Set(dnr.SURROGATES.map((s) => `surrogates/${s.file}`))];
const CHROME_ONLY = ["warning.html", "warning.css", "warning.js", "unwrap.html", "unwrap.css", "unwrap.js", "page-gpc.js", "page-guard.js", "offscreen.html", "offscreen.js", "core/cookies.js", "semantic.html", "semantic.css", "semantic.js", "core/local-model.js", "privacy.html", "privacy.css", "privacy.js", "core/browser-privacy.js", ...SURROGATE_FILES];
const CHROME_WORKER = ["core/psl-data.js", "core/hosts.js", "core/selectors.js", "core/rules.js", "core/store.js", "core/links.js", "core/params.js", "core/cookies.js", "core/dnr.js", "core/cosmetic-selectors.js", "core/cosmetic.js", "core/browser-privacy.js"];
export const GUARANTEED_STATIC_RULES = 30000;   // Chrome's GUARANTEED_MINIMUM_STATIC_RULES
export const MAX_STATIC_REGEX_RULES = 1000;     // Chrome's MAX_NUMBER_OF_REGEX_RULES

function copy(files, dest) {
  for (const file of files) {
    fs.mkdirSync(path.dirname(path.join(dest, file)), {recursive: true});
    fs.copyFileSync(path.join(SRC, file), path.join(dest, file));
  }
}

/** "AdGuard CNAME-cloaked ads" + "AdGuard CNAME-cloaked trackers" -> "AdGuard CNAME-cloaked ads and trackers". */
export function joinNames(names) {
  if (!names.length) return "none";
  if (names.length === 1) return names[0];
  const words = names.map((n) => n.split(" "));
  let common = 0;
  while (words.every((w) => w.length > common + 1 && w[common] === words[0][common])) common++;
  if (!common) return names.join(" + ");
  return `${words[0].slice(0, common).join(" ")} ${words.map((w) => w.slice(common).join(" ")).join(" and ")}`;
}

function notice(lists, filters = {}) {
  const lines = ["Egress Guard Companion: bundled list data", "",
    "The extension code is MIT licensed. The rulesets in rules/ are generated from the lists below and keep",
    "their upstream licenses. HaGeZi lists are GPL-3.0: if you pass this build to anyone else, include this",
    "notice, the GPL-3.0 text (https://www.gnu.org/licenses/gpl-3.0.txt) and the list sources linked here.",
    "EasyPrivacy and EasyList are dual licensed GPL-3.0 or CC BY-SA 3.0 (https://easylist.to/pages/licence.html);",
    "this build uses them under GPL-3.0, like the HaGeZi data. The rules in rules/fp-trackers.json, easyprivacy.json,",
    "easylist.json, filter-allow.json and core/cosmetic-data.js are converted from them (see each source below).", "",
    "Public Suffix List data is packaged in vendor/public_suffix_list.dat and compiled into core/psl-data.js.",
    "Its source notice, version and license (MPL-2.0) are preserved in vendor/PSL-NOTICE.md and the data header.",
    "Source: https://publicsuffix.org/list/public_suffix_list.dat", ""];
  for (const data of Object.values(filters || {})) {
    const s = data.source;
    lines.push(`filters: ${s.name}`, `  source:  ${s.url}`, `  license: ${s.license.name} ${s.license.url}`,
      `  version: ${s.version || "unknown"}  last modified: ${s.last_modified || "unknown"}  fetched: ${new Date(s.fetched_at * 1000).toISOString()}  sha256: ${s.sha256}`, "");
  }
  for (const [kind, meta] of Object.entries(lists)) {
    for (const s of meta.sources) {
      const when = s.published_at ? new Date(s.published_at * 1000).toISOString() : "unknown";
      lines.push(`${kind}: ${s.name}`, `  source:  ${s.url}`, `  license: ${s.license.name} ${s.license.url}`,
        `  entries: ${s.entries}  published: ${when}  sha256: ${s.sha256}`, "");
    }
  }
  return lines.join("\n");
}

export const MAX_RULESET_BYTES = 32 * 1024 * 1024;  // per ruleset file; see build()
const MAX_ENABLED_RULESETS = 50;                       // Chrome's MAX_NUMBER_OF_ENABLED_STATIC_RULESETS

/** Split rules into consecutive groups whose JSON stays under `limit` bytes (always at least one group). */
export function splitRules(rules, limit = MAX_RULESET_BYTES) {
  const parts = [[]];
  let size = 2;
  for (const rule of rules) {
    const n = JSON.stringify(rule).length + 1;
    if (parts[parts.length - 1].length && size + n > limit) { parts.push([]); size = 2; }
    parts[parts.length - 1].push(rule);
    size += n;
  }
  return parts;
}

/** Replace both output folders with rollback on any ordinary rename failure. A killed process can leave the
 * staging folder containing its last-good backups; retain that folder if rollback itself fails. */
export function publishBuild(stage, out, rename = fs.renameSync) {
  const changed = [];
  try {
    for (const name of ["chrome", "firefox"]) {
      const destination = path.join(out, name), backup = path.join(stage, ".previous-" + name);
      const entry = {destination, backup, saved: false, installed: false};
      changed.push(entry);
      if (fs.existsSync(destination)) { rename(destination, backup); entry.saved = true; }
      rename(path.join(stage, name), destination); entry.installed = true;
    }
  } catch (error) {
    const failures = [];
    for (const entry of changed.reverse()) {
      try {
        if (entry.installed) fs.rmSync(entry.destination, {recursive: true, force: true});
        if (entry.saved) rename(entry.backup, entry.destination);
      } catch (restoreError) { failures.push(String(restoreError.message || restoreError)); }
    }
    if (failures.length) {
      error.preserveStage = true;
      error.message += "; last-good output could not be fully restored; keep " + stage + ": " + failures.join("; ");
    }
    throw error;
  }
}

/** Build both browsers. Returns a summary. `lists` null means "no built-in lists". */
export function buildCoverage(lists, filters, compilation = null, cosmeticData = null) {
  const missing = [], stale = [];
  for (const [kind, specs] of Object.entries(feedSpecs("pro.plus"))) {
    const sources = lists && lists[kind] && lists[kind].sources || [];
    const required = lists && lists[kind] && lists[kind].required || specs.map(spec => spec.id);
    for (const id of required) {
      const found = sources.find(source => source.id === id);
      if (!found) missing.push(id);
      else if (!Number.isFinite(found.updated_at) || Date.now() / 1000 - found.updated_at > 48 * 3600) stale.push(found.id);
    }
  }
  for (const spec of FILTER_LISTS) {
    if (!filters || !filters[spec.id]) missing.push(spec.id);
    else if (filters[spec.id].source.stale) stale.push(spec.id);
  }
  const ineffective = compilation ? FILTER_LISTS.filter(spec => spec.kind !== "domains" && filters && filters[spec.id] &&
    (!compilation[spec.id] || !compilation[spec.id].blockingRules)).map(spec => spec.id) : [];
  const development = Object.values(lists || {}).some(data => data.development === true);
  const cosmeticCoverage = cosmeticData ? {
    scopedRules: cosmeticData.rules.length, genericRules: cosmeticData.genericRules.length,
    selectorExceptions: cosmeticData.exceptions.length, pageExceptions: cosmeticData.hideExceptions.length,
    relationalRules: cosmeticData.stats.relational, entityScoped: cosmeticData.stats.entityScoped,
    disabledFamilies: ["generic", "scoped"].filter(kind => cosmeticData.fallback[kind] === true),
    quarantinedSelectors: cosmeticData.fallback.selectors.length,
    fallbackCounts: {...cosmeticData.stats.fallbacks},
  } : null;
  if (cosmeticCoverage) cosmeticCoverage.reduced = cosmeticCoverage.disabledFamilies.length > 0 || cosmeticCoverage.quarantinedSelectors > 0;
  return {schema: 1, complete: !missing.length && !ineffective.length && !development && !(cosmeticCoverage && cosmeticCoverage.reduced), missing, stale: [...new Set(stale)],
    ineffective, development, filterSyntax: "supported-subset", compilation: compilation || {},
    cosmetics: cosmeticCoverage,
    capabilities: ["domain-blocking", "url-filtering", "site-cosmetics", "indexed-generic-cosmetics", "bounded-relational-cosmetics", "local-ad-review", "optional-browser-privacy"],
    compiler: "egress-guard-0.8"};
}

export function build({out = path.join(ROOT, "dist-browser"), lists = null, filters = null, requireComplete = false, chunk = dnr.DEFAULT_CHUNK, maxRulesetBytes = MAX_RULESET_BYTES} = {}) {
  const compiledFilters = compileFilterRulesets(filters);
  const cosmeticData = cosmetics.compileCosmetics(FILTER_LISTS.filter(f => f.kind !== "domains" && filters && filters[f.id]).map(f => filters[f.id].text));
  const coverage = buildCoverage(lists, filters, compiledFilters.stats, cosmeticData);
  if (requireComplete && !coverage.complete) throw new Error("Incomplete browser coverage: " +
    [...coverage.missing, ...coverage.ineffective.map(id => id + " produced no blocking rules"), ...(coverage.development ? ["development feed-size override"] : []),
      ...(coverage.cosmetics.reduced ? ["imported cosmetic coverage was reduced by an unsupported source exemption"] : [])].join(", "));
  const chromeManifest = JSON.parse(fs.readFileSync(path.join(SRC, "manifest.chrome.json"), "utf8"));
  const firefoxManifest = JSON.parse(fs.readFileSync(path.join(SRC, "manifest.json"), "utf8"));
  const id = chromeExtensionId(chromeManifest);
  const warningUrl = `chrome-extension://${id}/warning.html`;
  fs.mkdirSync(out, {recursive: true});
  const stage = fs.mkdtempSync(path.join(out, ".build-"));
  const summary = {extensionId: id, out, lists: {}, coverage};
  let preserveStage = false;
  try {
    // ---- Chrome ----
    const chrome = path.join(stage, "chrome");
    copy([...SHARED, ...CHROME_ONLY], chrome);
    const cosmeticBody = "/* Generated from verified filter data; see NOTICE.txt. */\nglobalThis.EGCosmeticData = Object.freeze(" + JSON.stringify(cosmeticData) + ");\n";
    fs.writeFileSync(path.join(chrome, "core/cosmetic-data.js"), cosmeticBody);
    summary.cosmetics = cosmeticData.stats;
    fs.mkdirSync(path.join(chrome, "rules"));
    const meta = {};
    const resources = [];
    for (const kind of ["threats", "trackers", "cname"]) {
      const data = lists && lists[kind] ? lists[kind] : {names: [], sources: []};
      const compiled = dnr.compileList(kind, data.names, {chunk, warningUrl});
      // Chrome documents no per-file size limit, and Chrome 157 indexed a 68 MB, 1.5 million-name threat file in our
      // headless test. Files are still capped at MAX_RULESET_BYTES so a growing list becomes more files (each tested
      // to load) rather than one ever larger file.
      const parts = splitRules(compiled.rules, maxRulesetBytes);
      let bytes = 0;
      parts.forEach((part, i) => {
        const rid = i === 0 ? kind : `${kind}-${i + 1}`;
        const body = JSON.stringify(part);
        bytes += body.length;
        fs.writeFileSync(path.join(chrome, "rules", `${rid}.json`), body);
        resources.push({id: rid, enabled: true, path: `rules/${rid}.json`});
      });
      const src = data.sources;
      const stamps = (key) => src.map((s) => s[key]).filter((t) => typeof t === "number");
      meta[kind] = {label: dnr.LIST_KINDS[kind].label, name: joinNames(src.map((s) => s.name)),
        files: parts.map((_, i) => `rules/${i === 0 ? kind : `${kind}-${i + 1}`}.json`),
        domains: compiled.domains, rules: compiled.rules.length,
        sources: src.map((s) => ({name: s.name, url: s.url, license: s.license.name, sha256: s.sha256 || null, last_modified: s.published_at ? new Date(s.published_at * 1000).toISOString() : null})),
        published_at: stamps("published_at").length ? Math.min(...stamps("published_at")) : null,
        updated_at: stamps("updated_at").length ? Math.min(...stamps("updated_at")) : null};
      summary.lists[kind] = {domains: compiled.domains, rules: compiled.rules.length, bytes, files: parts.length};
    }
    // Everything that is not a host list: small rulesets, one per popup category, each one file.
    const unwrapUrl = `chrome-extension://${id}/unwrap.html`;
    const privacy = dnr.compilePrivacy({trackerDomains: compiledFilters.trackerDomains, bounceDomains: filterDomains(filters, "adguard-clickthroughs")});
    const extra = {params: dnr.compileParams(), links: dnr.compileLinks(unwrapUrl), gpc: privacy.gpc, referrer: privacy.referrer,
      beacons: privacy.beacons, cookies: privacy.cookies, bounce: privacy.bounce, surrogates: dnr.compileSurrogates(), ...compiledFilters.rulesets};
    summary.filters = compiledFilters.stats;
    summary.rulesets = {};
    for (const [rid, rules] of Object.entries(extra)) {
      fs.writeFileSync(path.join(chrome, "rules", `${rid}.json`), JSON.stringify(rules));
      resources.push({id: rid, enabled: true, path: `rules/${rid}.json`});
      summary.rulesets[rid] = rules.length;
    }
    if (resources.length > MAX_ENABLED_RULESETS) throw new Error(`${resources.length} rulesets exceed Chrome's limit of ${MAX_ENABLED_RULESETS} enabled rulesets`);
    chromeManifest.declarative_net_request.rule_resources = resources;
    // Every static rule counts against the guaranteed minimum; a host list is a handful of rules however long it is.
    let staticRules = 0, regexRules = 0;
    for (const r of resources) {
      const rules = JSON.parse(fs.readFileSync(path.join(chrome, r.path), "utf8"));
      staticRules += rules.length;
      regexRules += rules.filter((x) => x.condition.regexFilter).length;
    }
    if (staticRules > GUARANTEED_STATIC_RULES) throw new Error(`${staticRules} static rules exceed Chrome's guaranteed ${GUARANTEED_STATIC_RULES}`);
    if (regexRules > MAX_STATIC_REGEX_RULES) throw new Error(`${regexRules} regular-expression rules exceed Chrome's limit of ${MAX_STATIC_REGEX_RULES}`);
    summary.staticRules = staticRules;
    summary.regexRules = regexRules;
    const sourceOf = (fid) => filters && filters[fid] ? filters[fid].source : null;
    meta.filters = {label: "URL filters", name: joinNames(FILTER_LISTS.filter((f) => sourceOf(f.id) && f.kind !== "domains").map((f) => f.name)),
      rules: Object.entries(compiledFilters.rulesets).reduce((n, [, r]) => n + r.length, 0), domains: 0,
      sources: FILTER_LISTS.filter((f) => sourceOf(f.id)).map((f) => ({name: f.name, url: f.url, license: f.license.name, version: sourceOf(f.id).version,
        sha256: sourceOf(f.id).sha256 || null, last_modified: sourceOf(f.id).last_modified || null})),
      published_at: null, updated_at: Math.min(...FILTER_LISTS.map((f) => (sourceOf(f.id) || {}).fetched_at || Infinity)) || null};
    if (!Number.isFinite(meta.filters.updated_at)) meta.filters.updated_at = null;
    // Build identity: a hash of every ruleset and of the list metadata. An unpacked extension reads its own folder
    // live, so the running worker compares this with rules/build.json on disk and reloads itself after a rebuild.
    const hash = crypto.createHash("sha256");
    for (const r of resources) hash.update(fs.readFileSync(path.join(chrome, r.path)));
    hash.update(JSON.stringify(meta));
    hash.update(JSON.stringify(coverage));
    hash.update(cosmeticBody);
    for (const f of [...SHARED, ...CHROME_ONLY, "background-chrome.js", "manifest.chrome.json"]) hash.update(fs.readFileSync(path.join(SRC, f)));
    const buildId = hash.digest("hex").slice(0, 32);
    fs.writeFileSync(path.join(chrome, "rules", "build.json"), JSON.stringify({build: buildId, built_at: Math.floor(Date.now() / 1000), coverage,
      cosmetics: cosmeticData.stats, psl_sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(SRC, "core/psl-data.js"))).digest("hex")}));
    summary.build = buildId;
    const worker = [...CHROME_WORKER.map((f) => `// ---- ${f}\n${fs.readFileSync(path.join(SRC, f), "utf8")}`),
      `// ---- lists (generated)\nglobalThis.EGLists = Object.freeze(${JSON.stringify({extensionId: id, build: buildId, lists: meta, coverage})});\n`,
      `// ---- background-chrome.js\n${fs.readFileSync(path.join(SRC, "background-chrome.js"), "utf8")}`].join("\n");
    fs.writeFileSync(path.join(chrome, "background.js"), worker);
    fs.writeFileSync(path.join(chrome, "manifest.json"), JSON.stringify(chromeManifest, null, 2) + "\n");
    fs.writeFileSync(path.join(chrome, "NOTICE.txt"), notice(lists || {}, filters || {}));

    // ---- Firefox (user rules through blocking webRequest; built-in lists are Chrome-only for now) ----
    const firefox = path.join(stage, "firefox");
    copy([...SHARED, "background.js"], firefox);
    fs.writeFileSync(path.join(firefox, "manifest.json"), JSON.stringify(firefoxManifest, null, 2) + "\n");
    fs.writeFileSync(path.join(firefox, "NOTICE.txt"), notice({}, {}));
    publishBuild(stage, out);
  } catch (error) {
    preserveStage = error.preserveStage === true;
    throw error;
  } finally {
    if (!preserveStage) fs.rmSync(stage, {recursive: true, force: true});
  }
  return summary;
}

function parseArgs(argv) {
  const args = {feeds: null, tier: "pro.plus", out: path.join(ROOT, "dist-browser"), lists: true, allowSmall: false, chunk: dnr.DEFAULT_CHUNK};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === "--feeds") args.feeds = path.resolve(next());
    else if (a === "--tier") args.tier = next();
    else if (a === "--threat-tier") args.threatTier = next();
    else if (a === "--out") args.out = path.resolve(next());
    else if (a === "--chunk") args.chunk = Number(next());
    else if (a === "--no-lists") args.lists = false;
    else if (a === "--allow-small") args.allowSmall = true;
    else if (a === "--allow-missing") args.allowMissing = true;
    else if (a === "--filters") args.filtersDir = path.resolve(next());
    else if (a === "--offline") args.offline = true;
    else if (a === "--no-filters") args.noFilters = true;
    else if (a === "--accept-list-change") (args.acceptChange = args.acceptChange || []).push(next());
    else if (a === "-h" || a === "--help") { console.log("usage: node scripts/build-browser.mjs [--feeds DIR] [--tier pro|pro.plus|ultimate] [--threat-tier full|medium] [--out DIR] [--no-lists] [--allow-missing] [--filters DIR] [--offline] [--no-filters] [--accept-list-change ID]"); process.exit(0); }
    else throw new Error(`unknown argument ${a}`);
  }
  return args;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = parseArgs(process.argv.slice(2));
    let lists = null;
    if (args.lists) {
      const feeds = args.feeds || defaultFeedsDir();
      if (!fs.existsSync(path.join(feeds, "blocklists"))) {
        throw new Error(`no feed cache at ${path.join(feeds, "blocklists")}. Run \`egress-guard refresh\` (or pass --feeds DIR), or build with --no-lists.`);
      }
      lists = loadLists(feeds, {tier: args.tier, threatTier: args.threatTier || "full", allowSmall: args.allowSmall, allowMissing: args.allowMissing, log: (m) => console.warn(`warning: ${m}`)});
      const day = 48 * 3600;
      for (const [kind, data] of Object.entries(lists)) for (const s of data.sources) {
        const stamp = s.published_at || s.updated_at;
        if (stamp && Date.now() / 1000 - stamp > day) console.warn(`warning: ${s.name} is older than 48 hours; refresh the proxy's feeds and rebuild`);
      }
    }
    let filters = null;
    if (!args.noFilters) {
      filters = await loadFilters(args.filtersDir || (args.feeds ? path.join(args.feeds, "browser-filters") : defaultFiltersDir()),
        {offline: Boolean(args.offline), allowMissing: Boolean(args.allowMissing), acceptChange: args.acceptChange || [], log: (m) => console.warn(`warning: ${m}`)});
    }
    const summary = build({out: args.out, lists, filters, chunk: args.chunk, requireComplete: args.lists && !args.noFilters && !args.allowMissing});
    console.log(`Coverage: ${summary.coverage.complete ? "complete" : "reduced: " + summary.coverage.missing.join(", ")}`);
    console.log(`Cosmetics: ${summary.cosmetics.accepted} scoped rules, ${summary.cosmetics.exceptions} exceptions`);
    console.log(`Chrome:  ${path.join(summary.out, "chrome")}  (extension id ${summary.extensionId})`);
    for (const [kind, s] of Object.entries(summary.lists)) console.log(`  ${kind.padEnd(8)} ${String(s.domains).padStart(7)} domains in ${s.rules} rules, ${(s.bytes / 1048576).toFixed(1)} MB`);
    for (const [fid, st] of Object.entries(summary.filters || {})) {
      const dropped = Object.values(st.dropped).reduce((a, b) => a + b, 0);
      console.log(`  ${fid.padEnd(12)} ${st.network} network filters: ${st.converted} converted into ${st.rules} rules, ${dropped} dropped (${st.suspicious} unanchored exceptions or $important)`);
    }
    console.log(`  rulesets: ${Object.entries(summary.rulesets).map(([k, v]) => `${k} ${v}`).join(", ")}`);
    console.log(`  ${summary.staticRules} static rules of ${GUARANTEED_STATIC_RULES} guaranteed, ${summary.regexRules} regex rules of ${MAX_STATIC_REGEX_RULES}`);
    console.log(`Firefox: ${path.join(summary.out, "firefox")}`);
  } catch (error) {
    console.error(`build-browser: ${error.message}`);
    process.exit(1);
  }
}
