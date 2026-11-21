// Opt-in real-website trial. NOT part of `node --test`, and it contacts the public sites listed below.
//   node tests/browser/real-sites.mjs [--feeds DIR] [--chrome PATH] [--out DIR] [--sites a,b] [--settle MS]
//
// Builds the Chrome extension with the full lists from a proxy feed cache, then visits each site twice
// in headless Chrome, each run with its own throwaway profile and no proxy: once without the extension
// (control) and once with it. Read-only: it only navigates to public pages and reads them. It never
// clicks, types, submits forms, signs in or accepts cookie banners. Per site it records requests blocked
// by list (from the extension's own log), JavaScript and network console errors in both runs, visible
// text length and visible ad slots in both runs, and a viewport screenshot of each run.
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createRequire} from "node:module";
import {build, loadLists, loadFilters, defaultFeedsDir, defaultFiltersDir} from "../../scripts/build-browser.mjs";
import {launch, attachWorker, waitFor, sleep, DEFAULT_CHROME} from "./cdp.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const argv = process.argv.slice(2);
const opt = (name, fallback = null) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : fallback; };

export const SITES = [
  // Ad- and tracker-heavy pages.
  {id: "cnn", kind: "news", url: "https://www.cnn.com/"},
  {id: "guardian", kind: "news", url: "https://www.theguardian.com/international"},
  {id: "foxnews", kind: "news", url: "https://www.foxnews.com/"},
  {id: "dailymail", kind: "news", url: "https://www.dailymail.co.uk/home/index.html"},
  {id: "weather", kind: "news", url: "https://weather.com/"},
  {id: "allrecipes", kind: "recipe", url: "https://www.allrecipes.com/recipe/10813/best-chocolate-chip-cookies/"},
  {id: "foodnetwork", kind: "recipe", url: "https://www.foodnetwork.com/recipes/food-network-kitchen/chocolate-chip-cookies-recipe-2108716"},
  {id: "verge", kind: "tech", url: "https://www.theverge.com/"},
  {id: "techcrunch", kind: "tech", url: "https://techcrunch.com/"},
  {id: "tomsguide", kind: "tech", url: "https://www.tomsguide.com/"},
  {id: "bing", kind: "search", url: "https://www.bing.com/search?q=chocolate+chip+cookies"},
  {id: "ddg", kind: "search", url: "https://html.duckduckgo.com/html/?q=chocolate+chip+cookies"},
  // Sign-in and checkout pages that must keep working (loaded only, never filled in).
  {id: "github-login", kind: "sign-in", url: "https://github.com/login"},
  {id: "google-signin", kind: "sign-in", url: "https://accounts.google.com/"},
  {id: "microsoft-login", kind: "sign-in", url: "https://login.live.com/"},
  {id: "paypal-signin", kind: "sign-in", url: "https://www.paypal.com/signin"},
  {id: "stripe-checkout", kind: "checkout", url: "https://checkout.stripe.dev/preview"},
  {id: "shopify-store", kind: "checkout", url: "https://www.allbirds.com/cart"},
  // Server-side tagging and self-hosted analytics on the site's own domain.
  {id: "stape", kind: "sGTM", url: "https://stape.io/"},
  {id: "simoahava", kind: "sGTM", url: "https://www.simoahava.com/"},
  {id: "plausible", kind: "self-hosted", url: "https://plausible.io/"},
  {id: "posthog", kind: "self-hosted", url: "https://posthog.com/"},
  {id: "matomo", kind: "self-hosted", url: "https://matomo.org/"},
];
const require = createRequire(import.meta.url);
const cookieRules = require("../../browser/core/cookies.js");
const linkRules = require("../../browser/core/links.js");
const paramRules = require("../../browser/core/params.js");
// v0.4.0's parameter list, to compare link cleaning before and after.
const OLD_PARAMS = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id", "utm_name", "utm_cid", "utm_reader", "utm_referrer",
  "utm_social", "utm_social-type", "utm_brand", "utm_place", "utm_pubreferrer", "utm_swu", "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid",
  "yclid", "twclid", "ttclid", "igshid", "li_fat_id", "mc_eid", "oly_anon_id", "oly_enc_id", "vero_id", "rb_clickid", "s_cid", "wickedid", "epik", "_openstat", "srsltid"]);
function linkStats(hrefs) {
  let before = 0, after = 0, unwrapped = 0;
  for (const href of hrefs) {
    let u; try { u = new URL(href); } catch { continue; }
    if (!/^https?:$/.test(u.protocol)) continue;
    if ([...u.searchParams.keys()].some((k) => OLD_PARAMS.has(k))) before++;
    let dest = href;
    if (linkRules.wrapperOf(dest)) { const r = linkRules.unwrap(dest); if (r.url) { dest = r.url; unwrapped++; } }
    if (dest !== href || paramRules.clean(dest).removed.length) after++;
  }
  return {before, after, unwrapped, total: hrefs.length};
}

// Same generic selectors the extension hides (browser/core/cosmetic.js), plus label text, to count visible ad slots.
const AD_PROBE = `(() => {
  const sels = (globalThis.__egGeneric || []);
  const visible = (n) => { const r = n.getBoundingClientRect(); const s = getComputedStyle(n); return r.width > 1 && r.height > 1 && s.visibility !== "hidden" && s.display !== "none"; };
  let slots = 0;
  for (const sel of sels) { try { for (const n of document.querySelectorAll(sel)) if (visible(n)) slots++; } catch {} }
  let labels = 0;
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  for (let t = walker.nextNode(), seen = 0; t && seen < 200000; t = walker.nextNode(), seen++) {
    const s = t.nodeValue.trim().toLowerCase();
    if ((s === "advertisement" || s === "ad" || s === "sponsored" || s === "story continues below advertisement") && t.parentElement && visible(t.parentElement)) labels++;
  }
  return {slots, labels};
})()`;

// Style-recalc cost of the built-in ad-slot stylesheet: forced full recalcs (a root custom property change) with the
// sheet enabled and disabled, median of 7 each, plus the element count.
const CSS_COST = `(() => {
  const sheet = [...document.querySelectorAll("style[data-eg-page-ui]")][0];
  if (!sheet) return null;
  const root = document.documentElement;
  const recalc = (i) => { root.style.setProperty("--eg-probe", String(i)); const t = performance.now(); void document.body.offsetHeight; getComputedStyle(document.body).color; return performance.now() - t; };
  const median = (a) => a.sort((x, y) => x - y)[a.length >> 1];
  const on = [], off = [];
  for (let i = 0; i < 7; i++) { sheet.disabled = true; recalc(i * 2); off.push(recalc(i * 2 + 1000)); sheet.disabled = false; recalc(i * 2 + 1); on.push(recalc(i * 2 + 2000)); }
  root.style.removeProperty("--eg-probe");
  return {onMs: +median(on).toFixed(2), offMs: +median(off).toFixed(2), elements: document.getElementsByTagName("*").length};
})()`;

async function runMode(mode, {chromeBin, ext, extensionId, sites, shots, settle, generic}) {
  const out = {};
  let profile, browser, cdp, on, evaluate, sw;
  // A wedged headless Chrome (it happens on a few heavy pages) is restarted with a fresh profile and the run goes on.
  async function start() {
    profile = fs.mkdtempSync(path.join(root, ".cache", `real-${mode}-`));
    browser = launch({bin: chromeBin, profile, args: ["--no-proxy-server", "--window-size=1280,900", "--lang=en-US"]});
    ({cdp, on, evaluate} = browser);
    sw = null;
    if (mode !== "control") {
      const loaded = await cdp("Extensions.loadUnpacked", {path: ext});
      if (loaded.id !== extensionId) throw new Error(`unexpected extension id ${loaded.id}`);
      sw = await attachWorker(cdp, extensionId);
      if (!sw) throw new Error("service worker did not start");
      await waitFor(async () => (await evaluate(sw.sessionId, "typeof __EGBackground")) === "object", 60000);
      await evaluate(sw.sessionId, "__EGBackground.ready.then(() => true)");
      // Chrome enables the static rulesets a moment after the worker starts when the lists are large.
      if (!(await waitFor(async () => (await evaluate(sw.sessionId, "chrome.declarativeNetRequest.getEnabledRulesets()")).includes("trackers"), 120000, 1000))) {
        throw new Error("rulesets were not enabled");
      }
      if (mode === "strict") await evaluate(sw.sessionId, `__EGBackground.handle({type: "set-default-mode", mode: "strict"}, {id: chrome.runtime.id, url: chrome.runtime.getURL("popup.html")})`);
      // --popup '<json message>' (repeatable in a JSON array): popup actions to apply before the visits, for diagnosis.
      for (const message of JSON.parse(opt("--popup", "[]"))) {
        await evaluate(sw.sessionId, `__EGBackground.handle(${JSON.stringify(message)}, {id: chrome.runtime.id, url: chrome.runtime.getURL("popup.html")})`);
      }
    }
  }
  async function stop() { await browser.close(); fs.rmSync(profile, {recursive: true, force: true}); }
  await start();
  try {
    for (const site of sites) {
      const rec = {jsErrors: 0, consoleErrors: 0, netErrors: 0, blockedByClient: 0, requests: 0, errorSamples: []};
      try { await visit(site, rec); } catch (error) {
        rec.harnessError = String(error.message || error);
        console.log(`${mode.padEnd(9)} ${site.id.padEnd(16)} harness error (${rec.harnessError}); restarting Chrome`);
        out[site.id] = rec;
        await stop().catch(() => {});
        await start();
      }
    }
  } finally {
    await stop().catch(() => {});
  }
  return out;

  async function visit(site, rec) {
    {
      const {targetId} = await cdp("Target.createTarget", {url: "about:blank"});
      const session = (await cdp("Target.attachToTarget", {targetId, flatten: true})).sessionId;
      const mine = (fn) => (params, sid) => { if (sid === session) fn(params); };
      const sample = (text) => { if (rec.errorSamples.length < 4) rec.errorSamples.push(String(text).slice(0, 160)); };
      on("Runtime.exceptionThrown", mine((p) => { rec.jsErrors++; sample(p.exceptionDetails.exception ? p.exceptionDetails.exception.description : p.exceptionDetails.text); }));
      on("Runtime.consoleAPICalled", mine((p) => { if (p.type === "error") { rec.consoleErrors++; sample(p.args.map((a) => a.value || a.description || "").join(" ")); } }));
      on("Log.entryAdded", mine((p) => { if (p.entry.level === "error" && p.entry.source === "network") rec.netErrors++; }));
      on("Network.requestWillBeSent", mine(() => { rec.requests++; }));
      on("Network.loadingFailed", mine((p) => { if (p.errorText === "net::ERR_BLOCKED_BY_CLIENT") rec.blockedByClient++; }));
      for (const domain of ["Page", "Runtime", "Network", "Log"]) await cdp(`${domain}.enable`, {}, session);
      await cdp("Emulation.setDeviceMetricsOverride", {width: 1280, height: 900, deviceScaleFactor: 1, mobile: false}, session);
      const started = Date.now();
      try {
        const nav = await cdp("Page.navigate", {url: site.url}, session);
        if (nav.errorText) rec.navError = nav.errorText;
        await waitFor(async () => (await evaluate(session, "document.readyState")) === "complete", 45000, 500);
      } catch (error) { rec.navError = String(error.message || error); }
      await sleep(settle);
      rec.loadMs = Date.now() - started;
      try {
        await evaluate(session, `globalThis.__egGeneric = ${JSON.stringify(generic)}; true`);
        const page = await evaluate(session, `({url: location.href, title: document.title.slice(0, 80), text: (document.body && document.body.innerText || "").length})`);
        Object.assign(rec, page, await evaluate(session, AD_PROBE));
        if (mode === "extension") rec.css = await evaluate(session, CSS_COST);
        rec.links = linkStats(await evaluate(session, "[...document.querySelectorAll('a[href]')].slice(0, 3000).map((a) => a.href)"));
        const {cookies} = await cdp("Network.getCookies", {}, session);
        rec.trackerCookies = cookies.filter((c) => cookieRules.classify(c.name)).map((c) => c.name);
      } catch (error) { rec.probeError = String(error.message || error); }
      if (shots) {
        try {
          const {data} = await cdp("Page.captureScreenshot", {format: "jpeg", quality: 55}, session);
          fs.writeFileSync(path.join(shots, `${site.id}-${mode}.jpg`), Buffer.from(data, "base64"));
        } catch {}
      }
      if (sw) {
        rec.blocked = await evaluate(sw.sessionId, `chrome.tabs.query({}).then(async (tabs) => {
          const tab = tabs.filter((t) => /^https?:/.test(t.url || "")).pop();
          if (!tab) return {};
          const log = await __EGBackground.tabLog(tab.id);
          const by = {};
          for (const x of log.items) by[x.list] = (by[x.list] || 0) + x.count;
          by.linksCleaned = __EGBackground.counts.links.get(tab.id) || 0;
          by.cookiesRemoved = [...__EGBackground.counts.cookies.values()].reduce((a, b) => a + b, 0);
          by.hosts = [...new Set(log.items.map((x) => x.host))].slice(0, 60);
          by.items = log.items.filter((x) => x.list !== "trackers" && x.list !== "cname").slice(0, 80).map((x) => x.list + " " + x.type + " " + x.host + x.path);
          return by;
        })`).catch((e) => ({error: String(e.message || e)}));
      }
      await cdp("Target.closeTarget", {targetId}).catch(() => {});
      out[site.id] = rec;
      console.log(`${mode.padEnd(9)} ${site.id.padEnd(16)} text ${String(rec.text ?? "-").padStart(6)}  js ${rec.jsErrors + rec.consoleErrors}  ` +
        `blocked ${rec.blockedByClient}  slots ${rec.slots ?? "-"}/${rec.labels ?? "-"}${rec.blocked ? `  ${JSON.stringify({...rec.blocked, hosts: undefined})}` : ""}${rec.navError ? `  nav ${rec.navError}` : ""}`);
    }
  }
}

function table(sites, control, ext, strict = {}) {
  const cats = ["trackers", "cname", "threats", "fp-trackers", "easyprivacy", "easylist", "replay", "beacons", "links", "surrogates", "user"];
  const lines = ["| Site | Kind | Blocked by category (ext) | Links with tracking: v0.4 / now | Tracker cookies control → ext | JS errors control → ext → strict | Text control → ext → strict | Strict blocked | Verdict (ext / strict) |",
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"];
  const js = (r) => (r.jsErrors || 0) + (r.consoleErrors || 0);
  const verdict = (c, e) => e.navError ? `nav error` : !c.text ? "control failed" : e.text / c.text < 0.8 ? "CHECK: text dropped" : "renders";
  for (const s of sites) {
    const c = control[s.id] || {}, e = ext[s.id] || {}, t = strict[s.id] || {};
    const b = e.blocked || {};
    const byCat = cats.filter((k) => b[k]).map((k) => `${k} ${b[k]}`).join(", ") || "0";
    const l = c.links || {};
    lines.push(`| ${s.id} | ${s.kind} | ${byCat} | ${l.before ?? "-"} / ${l.after ?? "-"} | ${(c.trackerCookies || []).length} → ${(e.trackerCookies || []).length} | ${js(c)} → ${js(e)} → ${t.text === undefined ? "-" : js(t)} | ` +
      `${c.text ?? "-"} → ${e.text ?? "-"} → ${t.text ?? "-"} | ${(t.blocked || {}).strict || 0} | ${verdict(c, e)} / ${t.text === undefined ? "-" : verdict(c, t)} |`);
  }
  return lines.join("\n");
}

function tableOld(sites, control, ext) {
  const lines = ["| Site | Kind | Blocked (trackers / CNAME / threats / user) | JS errors control → ext | Text control → ext | Ad slots + labels control → ext | Verdict |",
    "| --- | --- | --- | --- | --- | --- | --- |"];
  for (const s of sites) {
    const c = control[s.id] || {}, e = ext[s.id] || {};
    const b = e.blocked || {};
    const js = (r) => (r.jsErrors || 0) + (r.consoleErrors || 0);
    const ratio = c.text ? e.text / c.text : null;
    const verdict = e.navError ? `nav error ${e.navError}` : ratio === null ? "control failed" : ratio < 0.8 ? "CHECK: text dropped" : "content renders";
    lines.push(`| ${s.id} | ${s.kind} | ${b.trackers || 0} / ${b.cname || 0} / ${b.threats || 0} / ${b.user || 0} | ${js(c)} → ${js(e)} | ` +
      `${c.text ?? "-"} → ${e.text ?? "-"} | ${(c.slots ?? 0) + (c.labels ?? 0)} → ${(e.slots ?? 0) + (e.labels ?? 0)} | ${verdict} |`);
  }
  return lines.join("\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const chromeBin = opt("--chrome", DEFAULT_CHROME);
  const feeds = path.resolve(opt("--feeds", defaultFeedsDir()));
  const settle = Number(opt("--settle", "6000"));
  const pick = opt("--sites");
  const sites = pick ? SITES.filter((s) => pick.split(",").includes(s.id)) : SITES;
  const modes = (opt("--modes", "control,extension")).split(",");
  fs.mkdirSync(path.join(root, ".cache"), {recursive: true});
  const outDir = path.resolve(opt("--out", path.join(root, ".cache", `real-sites-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "")}`)));
  const shots = path.join(outDir, "shots");
  fs.mkdirSync(shots, {recursive: true});
  const work = fs.mkdtempSync(path.join(root, ".cache", "real-build-"));
  try {
    const lists = loadLists(feeds, {log: (m) => console.log(`note: ${m}`)});
    const filters = await loadFilters(defaultFiltersDir(), {offline: true, log: (m) => console.log(`note: ${m}`)});
    const built = build({out: path.join(work, "dist"), lists, filters});
    const ext = path.join(work, "dist", "chrome");
    const {GENERIC_SELECTORS} = createRequire(import.meta.url)("../../browser/core/cosmetic.js");
    console.log(`built: ${Object.entries(built.lists).map(([k, v]) => `${k} ${v.domains}`).join(", ")}; ${sites.length} sites; output ${outDir}`);
    const ctx = {chromeBin, ext, extensionId: built.extensionId, sites, shots, settle, generic: GENERIC_SELECTORS || []};
    const results = {};
    for (const mode of modes) results[mode] = await runMode(mode, ctx);
    fs.writeFileSync(path.join(outDir, "results.json"), JSON.stringify({when: new Date().toISOString(), sites, results}, null, 2));
    const md = table(sites, results.control || {}, results.extension || {}, results.strict || {});
    fs.writeFileSync(path.join(outDir, "results.md"), md + "\n");
    console.log(`\n${md}\n\nresults: ${path.join(outDir, "results.json")}\nscreenshots: ${shots}`);
  } finally {
    fs.rmSync(work, {recursive: true, force: true});
  }
}
