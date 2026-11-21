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
export function feedSpecs(tier) {
  const t = TIERS[tier];
  if (!t) throw new Error(`unknown tier ${tier}; use ${Object.keys(TIERS).join(", ")}`);
  return {
    threats: [{id: "hagezi-threat-intel", file: "hagezi-threat-intel.txt", name: "HaGeZi Threat Intelligence (Medium)",
      url: HAGEZI + "tif.medium-onlydomains.txt", minimum: 100000, license: HAGEZI_LICENSE}],
    trackers: [{id: `hagezi-${tier}`, file: `hagezi-${tier}.txt`, name: t.name, url: HAGEZI + `${tier}-onlydomains.txt`,
      minimum: t.minimum, license: HAGEZI_LICENSE}],
    cname: ["ads", "trackers"].map((category) => ({id: `adguard-cname-${category}`, file: `adguard-cname-${category}.exact`,
      name: `AdGuard CNAME-cloaked ${category}`, url: ADGUARD + `combined_disguised_${category}_justdomains.txt`,
      minimum: category === "ads" ? 1000 : 20000, license: ADGUARD_LICENSE})),
  };
}

const MAX_FEED_BYTES = 32 * 1024 * 1024;
const DNS_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DNS_NAME = new RegExp(`^(?:${DNS_LABEL}\\.)+${DNS_LABEL}$`);

/** Same rule as feeds.dns_name(dotted=True): lowercase ASCII, at least two labels, a letter in the last one. */
export function dnsName(value) {
  if (typeof value !== "string" || value.length > 253 || !DNS_NAME.test(value)) return null;
  return /[a-z]/.test(value.slice(value.lastIndexOf(".") + 1)) ? value : null;
}

/** Read and re-verify one proxy snapshot ("# {json}\n" + sorted names). Throws with a reason. */
export function readSnapshot(file, {minimum = 0} = {}) {
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
  const names = body.toString("ascii").split("\n").filter(Boolean);
  if (names.length !== meta.entries) throw new Error("snapshot entry count does not match its header");
  for (const name of names) if (!dnsName(name)) throw new Error(`snapshot contains an invalid hostname: ${JSON.stringify(name.slice(0, 80))}`);
  if (names.length < minimum) throw new Error(`snapshot has ${names.length} domains, fewer than the proxy's minimum of ${minimum}`);
  const stamp = (v) => (typeof v === "number" && v > 0 ? v : null);
  return {names, sha256: digest, published_at: stamp(meta.published_at), updated_at: stamp(meta.updated_at)};
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
export function loadLists(feedsDir, {tier = "pro.plus", allowSmall = false, allowMissing = false, log = () => {}} = {}) {
  const dir = path.join(feedsDir, "blocklists");
  const out = {};
  for (const [kind, specs] of Object.entries(feedSpecs(tier))) {
    const names = [];
    const sources = [];
    for (const spec of specs) {
      const file = path.join(dir, spec.file);
      let present = true;
      try { fs.lstatSync(file); } catch { present = false; }
      if (!present) {
        if (kind === "threats" && !allowMissing) throw new Error(`the malware and phishing feed ${spec.file} is missing from ${dir}; refresh the proxy's feeds, or pass --allow-missing to build without it`);
        log(`missing ${spec.file}: ${kind} list will be empty`);
        continue;
      }
      const snap = readSnapshot(file, {minimum: allowSmall ? 0 : spec.minimum});
      for (const name of snap.names) names.push(name);
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

const SHARED = ["core/hosts.js", "core/selectors.js", "core/rules.js", "core/decide.js", "core/store.js", "core/picker.js", "core/dnr.js",
  "content.js", "popup.html", "popup.css", "popup.js", "ui.css"];
const CHROME_ONLY = ["warning.html", "warning.css", "warning.js"];
const CHROME_WORKER = ["core/hosts.js", "core/selectors.js", "core/rules.js", "core/store.js", "core/dnr.js"];

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

function notice(lists) {
  const lines = ["Egress Guard Companion: bundled list data", "",
    "The extension code is MIT licensed. The rulesets in rules/ are generated from the lists below and keep",
    "their upstream licenses. HaGeZi lists are GPL-3.0: if you pass this build to anyone else, include this",
    "notice, the GPL-3.0 text (https://www.gnu.org/licenses/gpl-3.0.txt) and the list sources linked here.", ""];
  for (const [kind, meta] of Object.entries(lists)) {
    for (const s of meta.sources) {
      const when = s.published_at ? new Date(s.published_at * 1000).toISOString() : "unknown";
      lines.push(`${kind}: ${s.name}`, `  source:  ${s.url}`, `  license: ${s.license.name} ${s.license.url}`,
        `  entries: ${s.entries}  published: ${when}  sha256: ${s.sha256}`, "");
    }
  }
  return lines.join("\n");
}

/** Build both browsers. Returns a summary. `lists` null means "no built-in lists". */
export function build({out = path.join(ROOT, "dist-browser"), lists = null, chunk = dnr.DEFAULT_CHUNK} = {}) {
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
    for (const kind of ["threats", "trackers", "cname"]) {
      const data = lists && lists[kind] ? lists[kind] : {names: [], sources: []};
      const compiled = dnr.compileList(kind, data.names, {chunk, warningUrl});
      fs.writeFileSync(path.join(chrome, "rules", `${kind}.json`), JSON.stringify(compiled.rules));
      const src = data.sources;
      const stamps = (key) => src.map((s) => s[key]).filter((t) => typeof t === "number");
      meta[kind] = {label: dnr.LIST_KINDS[kind].label, name: joinNames(src.map((s) => s.name)),
        domains: compiled.domains, rules: compiled.rules.length, sources: src.map((s) => ({name: s.name, url: s.url, license: s.license.name})),
        published_at: stamps("published_at").length ? Math.min(...stamps("published_at")) : null,
        updated_at: stamps("updated_at").length ? Math.min(...stamps("updated_at")) : null};
      summary.lists[kind] = {domains: compiled.domains, rules: compiled.rules.length,
        bytes: fs.statSync(path.join(chrome, "rules", `${kind}.json`)).size};
    }
    fs.writeFileSync(path.join(chrome, "rules", "params.json"), JSON.stringify(dnr.compileParams()));
    const worker = [...CHROME_WORKER.map((f) => `// ---- ${f}\n${fs.readFileSync(path.join(SRC, f), "utf8")}`),
      `// ---- lists (generated)\nglobalThis.EGLists = Object.freeze(${JSON.stringify({extensionId: id, lists: meta})});\n`,
      `// ---- background-chrome.js\n${fs.readFileSync(path.join(SRC, "background-chrome.js"), "utf8")}`].join("\n");
    fs.writeFileSync(path.join(chrome, "background.js"), worker);
    fs.writeFileSync(path.join(chrome, "manifest.json"), JSON.stringify(chromeManifest, null, 2) + "\n");
    fs.writeFileSync(path.join(chrome, "NOTICE.txt"), notice(lists || {}));

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
    else if (a === "--out") args.out = path.resolve(next());
    else if (a === "--chunk") args.chunk = Number(next());
    else if (a === "--no-lists") args.lists = false;
    else if (a === "--allow-small") args.allowSmall = true;
    else if (a === "--allow-missing") args.allowMissing = true;
    else if (a === "-h" || a === "--help") { console.log("usage: node scripts/build-browser.mjs [--feeds DIR] [--tier pro|pro.plus|ultimate] [--out DIR] [--no-lists] [--allow-missing]"); process.exit(0); }
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
      lists = loadLists(feeds, {tier: args.tier, allowSmall: args.allowSmall, allowMissing: args.allowMissing, log: (m) => console.warn(`warning: ${m}`)});
      const day = 48 * 3600;
      for (const [kind, data] of Object.entries(lists)) for (const s of data.sources) {
        const stamp = s.published_at || s.updated_at;
        if (stamp && Date.now() / 1000 - stamp > day) console.warn(`warning: ${s.name} is older than 48 hours; refresh the proxy's feeds and rebuild`);
      }
    }
    const summary = build({out: args.out, lists, chunk: args.chunk});
    console.log(`Chrome:  ${path.join(summary.out, "chrome")}  (extension id ${summary.extensionId})`);
    for (const [kind, s] of Object.entries(summary.lists)) console.log(`  ${kind.padEnd(8)} ${String(s.domains).padStart(7)} domains in ${s.rules} rules, ${(s.bytes / 1048576).toFixed(1)} MB`);
    console.log(`Firefox: ${path.join(summary.out, "firefox")}`);
  } catch (error) {
    console.error(`build-browser: ${error.message}`);
    process.exit(1);
  }
}
