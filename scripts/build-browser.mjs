#!/usr/bin/env node
// Build the browser companion for Chrome and Firefox from the shared sources in browser/.
//
//   node scripts/build-browser.mjs [--feeds DIR] [--tier pro.plus] [--out dist-browser] [--no-lists]
//
// Lists come from the proxy's verified feed cache (DIR/blocklists/*.txt|*.exact, the files
// `egress-guard` writes after downloading and validating each feed). Each snapshot is checked again
// here: SHA-256 of the body against its header, entry count, hostname syntax and the proxy's minimum
// size. Nothing is downloaded by this script and nothing is fetched by the extension at run time.
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
      {...URLHAUS, file: `${URLHAUS.id}.txt`, optional: true},
      {...PHISHING_ARMY, file: `${PHISHING_ARMY.id}.txt`, optional: true},
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
// <id>.txt (the body exactly as downloaded) and <id>.json (source, SHA-256, size, fetch time, list version). The
// build downloads a list only when its cached copy is missing or older than FILTER_MAX_AGE; --offline never does.
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

export function defaultFiltersDir() { return path.join(defaultFeedsDir(), "browser-filters"); }

/** Check one downloaded or cached list body. Returns its header; throws with a reason. */
export function checkFilterBody(spec, body) {
  if (body.length > MAX_FILTER_BYTES) throw new Error(`${spec.name} exceeds ${MAX_FILTER_BYTES} bytes`);
  const text = body.toString("utf8");
  if (spec.kind === "domains") {
    const names = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("!"));
    const bad = names.find((n) => !dnsName(n));
    if (bad !== undefined) throw new Error(`${spec.name} contains an invalid hostname: ${JSON.stringify(bad.slice(0, 80))}`);
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

function readCachedFilter(dir, spec) {
  const bodyFile = path.join(dir, `${spec.id}.txt`), metaFile = path.join(dir, `${spec.id}.json`);
  for (const f of [bodyFile, metaFile]) if (!fs.lstatSync(f).isFile()) throw new Error(`${path.basename(f)} is not a regular file`);
  const body = fs.readFileSync(bodyFile);
  const meta = JSON.parse(fs.readFileSync(metaFile, "utf8"));
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  if (digest !== meta.sha256) throw new Error(`${spec.id}.txt SHA-256 does not match ${spec.id}.json`);
  if (meta.url !== spec.url) throw new Error(`${spec.id}.json names a different source`);
  checkFilterBody(spec, body);
  return {body, meta};
}

async function downloadFilter(spec, fetchImpl) {
  const response = await fetchImpl(spec.url, {redirect: "follow", signal: AbortSignal.timeout(60000), headers: {"accept": "text/plain"}});
  if (!response.ok) throw new Error(`${spec.url}: HTTP ${response.status}`);
  if (response.url && !response.url.startsWith("https://")) throw new Error(`${spec.url} redirected to a non-HTTPS address`);
  const declared = Number(response.headers.get("content-length"));
  if (declared > MAX_FILTER_BYTES) throw new Error(`${spec.url} is larger than ${MAX_FILTER_BYTES} bytes`);
  const body = Buffer.from(await response.arrayBuffer());
  const head = checkFilterBody(spec, body);
  return {body, meta: {id: spec.id, url: spec.url, sha256: crypto.createHash("sha256").update(body).digest("hex"), bytes: body.length,
    fetched_at: Math.floor(Date.now() / 1000), version: head.version || null, last_modified: head.last_modified || null, licence: head.licence}};
}

function writeAtomic(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, {mode: 0o600});
  fs.renameSync(tmp, file);
}

/**
 * The URL filter lists for a build: cached copies younger than a day, otherwise a fresh download (verified, then
 * cached). A failed download falls back to the cache with a warning; with neither, that list is left out.
 */
export async function loadFilters(dir, {offline = false, log = () => {}, fetchImpl = globalThis.fetch, now = Date.now() / 1000} = {}) {
  fs.mkdirSync(dir, {recursive: true, mode: 0o700});
  const out = {};
  for (const spec of FILTER_LISTS) {
    let cached = null;
    try { cached = readCachedFilter(dir, spec); } catch (error) { if (error.code !== "ENOENT") log(`${spec.id} cache unusable: ${error.message}`); }
    let use = cached;
    if (!offline && (!cached || now - cached.meta.fetched_at > FILTER_MAX_AGE)) {
      try {
        use = await downloadFilter(spec, fetchImpl);
        writeAtomic(path.join(dir, `${spec.id}.txt`), use.body);
        writeAtomic(path.join(dir, `${spec.id}.json`), JSON.stringify(use.meta, null, 2) + "\n");
      } catch (error) {
        log(`could not download ${spec.name}: ${error.message}${cached ? "; using the cached copy" : ""}`);
      }
    }
    if (!use) { log(`${spec.name} is not available: the build has no ${spec.name} rules`); continue; }
    out[spec.id] = {text: use.body.toString("utf8"), source: {id: spec.id, name: spec.name, url: spec.url, license: spec.license,
      sha256: use.meta.sha256, bytes: use.meta.bytes, fetched_at: use.meta.fetched_at, version: use.meta.version, last_modified: use.meta.last_modified}};
  }
  return out;
}

/**
 * Compile EasyPrivacy and EasyList into rulesets: "fp-trackers" (EasyPrivacy path filters that match on any host,
 * which is what catches first-party and proxied trackers, plus the hand-written ones), "easyprivacy" (the rest),
 * "easylist", and "filter-allow" (both lists' exceptions). Returns {rulesets: {id: rules}, stats}.
 */
export function compileFilterRulesets(filters) {
  const P = dnr.PRIORITY;
  const sets = {"fp-trackers": dnr.compileHand("fp-trackers"), easyprivacy: [], easylist: [], "filter-allow": [], replay: dnr.compileHand("replay")};
  const stats = {};
  const generic = (r) => r.condition.urlFilter && !r.condition.urlFilter.startsWith("||") && !r.condition.urlFilter.startsWith("|") && !r.condition.requestDomains;
  for (const spec of FILTER_LISTS) {
    const data = filters && filters[spec.id];
    if (!data || spec.kind === "domains") continue;
    const compiled = abp.compileFilters(data.text);
    stats[spec.id] = compiled.stats;
    const place = (set, rule, priority) => sets[set].push({id: sets[set].length + 1, priority, ...rule});
    for (const rule of compiled.block) place(spec.id === "easyprivacy" && generic(rule) ? "fp-trackers" : spec.id, rule, P.filter);
    for (const rule of compiled.important) place(spec.id, rule, P.filterImportant);
    for (const rule of compiled.allow) place("filter-allow", rule, P.filterAllow);
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
        // HaGeZi Threat Intelligence is the backbone of the malware and phishing list; without it the build would
        // protect almost nothing, so its absence is fatal. The smaller threat feeds and the other lists only warn.
        if (kind === "threats" && spec.hagezi && !allowMissing) throw new Error(`the malware and phishing feed ${spec.file} is missing from ${dir}; refresh the proxy's feeds, or pass --allow-missing to build without it`);
        log(`missing ${spec.file}: ${kind} list will not include ${spec.name}`);
        continue;
      }
      const snap = readSnapshot(file, {minimum: allowSmall ? 0 : spec.minimum, ips: Boolean(spec.ips)});
      for (const name of snap.names) names.push(name);
      if (snap.addresses.length) log(`${spec.file}: ${snap.addresses.length} IP addresses not used (Chrome rules match host names)`);
      sources.push({id: spec.id, name: spec.name, url: spec.url, license: spec.license, entries: snap.names.length,
        sha256: snap.sha256, published_at: snap.published_at, updated_at: snap.updated_at});
    }
    out[kind] = {names, sources};
  }
  return out;
}

function chromeExtensionId(manifest) {
  return dnr.extensionIdFromHex(crypto.createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex"));
}

const SHARED = ["core/hosts.js", "core/selectors.js", "core/rules.js", "core/decide.js", "core/store.js", "core/picker.js", "core/links.js", "core/params.js", "core/dnr.js", "core/cosmetic.js",
  "content.js", "popup.html", "popup.css", "popup.js", "ui.css"];
const SURROGATE_FILES = [...new Set(dnr.SURROGATES.map((s) => `surrogates/${s.file}`))];
const CHROME_ONLY = ["warning.html", "warning.css", "warning.js", "unwrap.html", "unwrap.js", "page-gpc.js", "page-guard.js", "offscreen.html", "offscreen.js", "core/cookies.js", ...SURROGATE_FILES];
const CHROME_WORKER = ["core/hosts.js", "core/selectors.js", "core/rules.js", "core/store.js", "core/links.js", "core/params.js", "core/cookies.js", "core/dnr.js"];
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
    "easylist.json and filter-allow.json are converted from them (see each source below).", ""];
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

/** Build both browsers. Returns a summary. `lists` null means "no built-in lists". */
export function build({out = path.join(ROOT, "dist-browser"), lists = null, filters = null, chunk = dnr.DEFAULT_CHUNK, maxRulesetBytes = MAX_RULESET_BYTES} = {}) {
  const chromeManifest = JSON.parse(fs.readFileSync(path.join(SRC, "manifest.chrome.json"), "utf8"));
  const firefoxManifest = JSON.parse(fs.readFileSync(path.join(SRC, "manifest.json"), "utf8"));
  const id = chromeExtensionId(chromeManifest);
  const warningUrl = `chrome-extension://${id}/warning.html`;
  fs.mkdirSync(out, {recursive: true});
  const stage = fs.mkdtempSync(path.join(out, ".build-"));
  const summary = {extensionId: id, out, lists: {}};
  try {
    // ---- Chrome ----
    const chrome = path.join(stage, "chrome");
    copy([...SHARED, ...CHROME_ONLY], chrome);
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
        domains: compiled.domains, rules: compiled.rules.length, sources: src.map((s) => ({name: s.name, url: s.url, license: s.license.name})),
        published_at: stamps("published_at").length ? Math.min(...stamps("published_at")) : null,
        updated_at: stamps("updated_at").length ? Math.min(...stamps("updated_at")) : null};
      summary.lists[kind] = {domains: compiled.domains, rules: compiled.rules.length, bytes, files: parts.length};
    }
    // Everything that is not a host list: small rulesets, one per popup category, each one file.
    const unwrapUrl = `chrome-extension://${id}/unwrap.html`;
    const compiledFilters = compileFilterRulesets(filters);
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
      sources: FILTER_LISTS.filter((f) => sourceOf(f.id)).map((f) => ({name: f.name, url: f.url, license: f.license.name, version: sourceOf(f.id).version})),
      published_at: null, updated_at: Math.min(...FILTER_LISTS.map((f) => (sourceOf(f.id) || {}).fetched_at || Infinity)) || null};
    if (!Number.isFinite(meta.filters.updated_at)) meta.filters.updated_at = null;
    // Build identity: a hash of every ruleset and of the list metadata. An unpacked extension reads its own folder
    // live, so the running worker compares this with rules/build.json on disk and reloads itself after a rebuild.
    const hash = crypto.createHash("sha256");
    for (const r of resources) hash.update(fs.readFileSync(path.join(chrome, r.path)));
    hash.update(JSON.stringify(meta));
    for (const f of [...SHARED, ...CHROME_ONLY, "background-chrome.js", "manifest.chrome.json"]) hash.update(fs.readFileSync(path.join(SRC, f)));
    const buildId = hash.digest("hex").slice(0, 32);
    fs.writeFileSync(path.join(chrome, "rules", "build.json"), JSON.stringify({build: buildId, built_at: Math.floor(Date.now() / 1000)}));
    summary.build = buildId;
    const worker = [...CHROME_WORKER.map((f) => `// ---- ${f}\n${fs.readFileSync(path.join(SRC, f), "utf8")}`),
      `// ---- lists (generated)\nglobalThis.EGLists = Object.freeze(${JSON.stringify({extensionId: id, build: buildId, lists: meta})});\n`,
      `// ---- background-chrome.js\n${fs.readFileSync(path.join(SRC, "background-chrome.js"), "utf8")}`].join("\n");
    fs.writeFileSync(path.join(chrome, "background.js"), worker);
    fs.writeFileSync(path.join(chrome, "manifest.json"), JSON.stringify(chromeManifest, null, 2) + "\n");
    fs.writeFileSync(path.join(chrome, "NOTICE.txt"), notice(lists || {}, filters || {}));

    // ---- Firefox (user rules through blocking webRequest; built-in lists are Chrome-only for now) ----
    const firefox = path.join(stage, "firefox");
    copy([...SHARED, "background.js"], firefox);
    fs.writeFileSync(path.join(firefox, "manifest.json"), JSON.stringify(firefoxManifest, null, 2) + "\n");

    for (const name of ["chrome", "firefox"]) {
      fs.rmSync(path.join(out, name), {recursive: true, force: true});
      fs.renameSync(path.join(stage, name), path.join(out, name));
    }
  } finally {
    fs.rmSync(stage, {recursive: true, force: true});
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
    else if (a === "-h" || a === "--help") { console.log("usage: node scripts/build-browser.mjs [--feeds DIR] [--tier pro|pro.plus|ultimate] [--threat-tier full|medium] [--out DIR] [--no-lists] [--allow-missing] [--filters DIR] [--offline] [--no-filters]"); process.exit(0); }
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
        {offline: Boolean(args.offline), log: (m) => console.warn(`warning: ${m}`)});
    }
    const summary = build({out: args.out, lists, filters, chunk: args.chunk});
    console.log(`Chrome:  ${path.join(summary.out, "chrome")}  (extension id ${summary.extensionId})`);
    for (const [kind, s] of Object.entries(summary.lists)) console.log(`  ${kind.padEnd(8)} ${String(s.domains).padStart(7)} domains in ${s.rules} rules, ${(s.bytes / 1048576).toFixed(1)} MB`);
    for (const [fid, st] of Object.entries(summary.filters || {})) {
      const dropped = Object.values(st.dropped).reduce((a, b) => a + b, 0);
      console.log(`  ${fid.padEnd(12)} ${st.network} network filters: ${st.converted} converted into ${st.rules} rules, ${dropped} dropped`);
    }
    console.log(`  rulesets: ${Object.entries(summary.rulesets).map(([k, v]) => `${k} ${v}`).join(", ")}`);
    console.log(`  ${summary.staticRules} static rules of ${GUARANTEED_STATIC_RULES} guaranteed, ${summary.regexRules} regex rules of ${MAX_STATIC_REGEX_RULES}`);
    console.log(`Firefox: ${path.join(summary.out, "firefox")}`);
  } catch (error) {
    console.error(`build-browser: ${error.message}`);
    process.exit(1);
  }
}
