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
import {build, loadLists, defaultFeedsDir} from "../../scripts/build-browser.mjs";
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
];

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

async function runMode(mode, {chromeBin, ext, extensionId, sites, shots, settle, generic}) {
  const profile = fs.mkdtempSync(path.join(root, ".cache", `real-${mode}-`));
  const browser = launch({bin: chromeBin, profile, args: ["--no-proxy-server", "--window-size=1280,900", "--lang=en-US"]});
  const {cdp, on, evaluate} = browser;
  const out = {};
  try {
    let sw = null;
    if (mode === "extension") {
      const loaded = await cdp("Extensions.loadUnpacked", {path: ext});
      if (loaded.id !== extensionId) throw new Error(`unexpected extension id ${loaded.id}`);
      sw = await attachWorker(cdp, extensionId);
      if (!sw) throw new Error("service worker did not start");
      await waitFor(async () => (await evaluate(sw.sessionId, "typeof __EGBackground")) === "object", 60000);
      await evaluate(sw.sessionId, "__EGBackground.ready.then(() => true)");
    }
    for (const site of sites) {
      const rec = {jsErrors: 0, consoleErrors: 0, netErrors: 0, blockedByClient: 0, requests: 0, errorSamples: []};
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
          by.hosts = [...new Set(log.items.map((x) => x.host))].slice(0, 60);
          return by;
        })`).catch((e) => ({error: String(e.message || e)}));
      }
      await cdp("Target.closeTarget", {targetId}).catch(() => {});
      out[site.id] = rec;
      console.log(`${mode.padEnd(9)} ${site.id.padEnd(16)} text ${String(rec.text ?? "-").padStart(6)}  js ${rec.jsErrors + rec.consoleErrors}  ` +
        `blocked ${rec.blockedByClient}  slots ${rec.slots ?? "-"}/${rec.labels ?? "-"}${rec.blocked ? `  ${JSON.stringify({...rec.blocked, hosts: undefined})}` : ""}${rec.navError ? `  nav ${rec.navError}` : ""}`);
    }
  } finally {
    await browser.close();
    fs.rmSync(profile, {recursive: true, force: true});
  }
  return out;
}

function table(sites, control, ext) {
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
    const built = build({out: path.join(work, "dist"), lists});
    const ext = path.join(work, "dist", "chrome");
    const {GENERIC_SELECTORS} = createRequire(import.meta.url)("../../browser/core/cosmetic.js");
    console.log(`built: ${Object.entries(built.lists).map(([k, v]) => `${k} ${v.domains}`).join(", ")}; ${sites.length} sites; output ${outDir}`);
    const ctx = {chromeBin, ext, extensionId: built.extensionId, sites, shots, settle, generic: GENERIC_SELECTORS || []};
    const results = {};
    for (const mode of modes) results[mode] = await runMode(mode, ctx);
    fs.writeFileSync(path.join(outDir, "results.json"), JSON.stringify({when: new Date().toISOString(), sites, results}, null, 2));
    const md = table(sites, results.control || {}, results.extension || {});
    fs.writeFileSync(path.join(outDir, "results.md"), md + "\n");
    console.log(`\n${md}\n\nresults: ${path.join(outDir, "results.json")}\nscreenshots: ${shots}`);
  } finally {
    fs.rmSync(work, {recursive: true, force: true});
  }
}
