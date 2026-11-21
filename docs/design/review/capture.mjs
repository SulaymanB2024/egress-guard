// Headless capture of the design mockups (and the warning-page "before") into docs/design/review/.
// node docs/design/review/capture.mjs [filter]   — headless Chrome, throwaway profile, no visible window.
// node docs/design/review/capture.mjs --extension [--before] [filter]
//   Captures and audits the real extension pages (browser/popup.html, warning.html, unwrap.html and the page-guard.js
//   placeholder) with a stubbed extension API and the fixture states in ext-fixtures.mjs, into review/ext/{after,before}/.
//   Exits non-zero when the audit finds a problem (see extAudit below).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {launch, sleep} from "../../../tests/browser/cdp.mjs";
import * as fx from "./ext-fixtures.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../../..");
const out = (n) => path.join(here, "after", n);
const before = (n) => path.join(here, "before", n);
const mock = (f, hash = "") => pathToFileURL(path.join(repo, "docs/design/mockups", f)).href + hash;
fs.mkdirSync(path.join(here, "after"), {recursive: true});
fs.mkdirSync(path.join(here, "before"), {recursive: true});

const schemes = ["light", "dark"];
const jobs = [];
// Frame sheets: every .frame[data-name] captured at its own size, 2x.
for (const f of ["popup.html", "placeholder.html", "mac-popover.html"]) jobs.push({kind: "frames", url: mock(f), prefix: f.replace(".html", "")});
// Pages at 1440 and 390 (full height).
for (const [f, hashes] of [["warning.html", ["", "#confirm"]], ["interstitial.html", ["", "#idn", "#unread"]],
  ["dashboard.html", ["", "#reduced", "#empty"]], ["scorecard.html", [""]]]) {
  for (const h of hashes) for (const w of [1440, 390]) jobs.push({kind: "page", url: mock(f, h), width: w, file: `${f.replace(".html", "")}${h ? "-" + h.slice(1) : ""}-${w}`});
}
// Mac main window at its real size.
for (const f of ["mac-overview.html", "mac-overview.html#reduced", "mac-overview.html#down", "mac-activity.html"]) {
  const [name, h] = f.split("#");
  jobs.push({kind: "page", url: mock(name, h ? "#" + h : ""), width: 1180, height: 760, file: name.replace(".html", "") + (h ? "-" + h : "")});
}
// Before: the current warning page, rendered from browser/warning.html with a stubbed extension API.
const stub = `window.chrome={runtime:{sendMessage:async(m)=>m.type==="warning-info"?{list:{label:"Malware and phishing",name:"HaGeZi Threat Intelligence (Medium)",published_at:1763424000},minutes:10}:{}},tabs:{update:async()=>{}}};`;
for (const w of [1440, 390]) jobs.push({kind: "page", before: true, url: pathToFileURL(path.join(repo, "browser/warning.html")).href + "?list=threats#https://login-verify.example-phish.test/account/session?continue=%2Fwallet", width: w, file: `warning-${w}`, init: stub});
jobs.push({kind: "frames", before: true, url: pathToFileURL(path.join(here, "before-placeholder.html")).href, prefix: "before-placeholder"});

const args = process.argv.slice(2);
const extMode = args.includes("--extension"), extBefore = args.includes("--before");
const filter = args.find((a) => !a.startsWith("--"));
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "eg-design-"));
const chrome = launch({profile, args: ["--allow-file-access-from-files", "--hide-scrollbars", "--disable-gpu"]});
const {cdp} = chrome;

async function open(url, width, height, scheme, dpr, init) {
  const {targetId} = await cdp("Target.createTarget", {url: "about:blank", background: true});
  const {sessionId} = await cdp("Target.attachToTarget", {targetId, flatten: true});
  await cdp("Page.enable", {}, sessionId);
  await cdp("Emulation.setDeviceMetricsOverride", {width, height, deviceScaleFactor: dpr, mobile: width < 600}, sessionId);
  await cdp("Emulation.setEmulatedMedia", {features: [{name: "prefers-color-scheme", value: scheme}]}, sessionId);
  if (init) await cdp("Page.addScriptToEvaluateOnNewDocument", {source: init}, sessionId);
  await cdp("Page.navigate", {url}, sessionId);
  await sleep(700);
  const ev = async (expression) => (await cdp("Runtime.evaluate", {expression, returnByValue: true, awaitPromise: true}, sessionId)).result.value;
  return {sessionId, targetId, ev};
}
const shot = async (sessionId, clip, file) => {
  const {data} = await cdp("Page.captureScreenshot", {format: "png", captureBeyondViewport: true, clip: {...clip, scale: 1}}, sessionId);
  fs.writeFileSync(file, Buffer.from(data, "base64"));
};

// Measured checks run on every capture (light only): clipped text, horizontal page overflow, type sizes in use,
// spacing values off the 4/8 scale, and more than one filled primary button per frame.
const AUDIT = `(() => {
  const scale = new Set([0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64]);
  const roots = document.querySelectorAll('.frame[data-name]').length ? [...document.querySelectorAll('.frame[data-name]')] : [document.body];
  const out = [];
  for (const root of roots) {
    const name = root.dataset ? root.dataset.name || 'page' : 'page';
    const clipped = [], sizes = new Set(), off = new Set();
    for (const el of root.querySelectorAll('*')) {
      const cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden' || el.closest('[hidden]')) continue;
      const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      if (hasText) sizes.add(cs.fontSize + (cs.fontFamily.includes('mono') ? ' mono' : ''));
      if (hasText && el.scrollWidth > el.clientWidth + 1 && cs.overflowX !== 'visible') clipped.push(el.textContent.trim().slice(0, 50));
      if (el.closest('.sheet > figure > figcaption') || el.matches('.lights i, .bars i, .days i, .dot, .mark, svg *, .switch, .sk')) continue;
      for (const p of ['paddingTop','paddingRight','paddingBottom','paddingLeft','marginTop','marginBottom','rowGap','columnGap']) {
        const v = parseFloat(cs[p]); if (!isNaN(v) && !scale.has(Math.abs(Math.round(v))) && Math.abs(v - Math.round(v)) < .01) off.add(p + ':' + v + ' ' + (el.className || el.tagName));
      }
    }
    const primaries = [...root.querySelectorAll('.btn.primary')].filter((b) => b.offsetParent && !b.closest('[hidden]')).length;
    out.push({name, clipped, primaries, sizes: [...sizes].sort(), off: [...off].slice(0, 12), hscroll: document.documentElement.scrollWidth > innerWidth + 1 && !document.querySelector('.sheet')});
  }
  return out;
})()`;
const auditLog = [];

if (extMode) await extension();
else for (const job of jobs) {
  const tag = job.file || job.prefix;
  if (filter && !tag.includes(filter)) continue;
  for (const scheme of schemes) {
    if (job.kind === "frames") {
      const {sessionId, targetId, ev} = await open(job.url, 1600, 1200, scheme, 2);
      if (scheme === "light" && !job.before) auditLog.push({tag, result: await ev(AUDIT)});
      const dest = job.before ? before : out;
      const rects = await ev(`[...document.querySelectorAll('.frame[data-name]')].map(e=>{const r=e.getBoundingClientRect();return {name:e.dataset.name,x:r.left+scrollX,y:r.top+scrollY,width:r.width,height:r.height}})`);
      for (const r of rects) await shot(sessionId, {x: r.x, y: r.y, width: r.width, height: r.height}, dest(`${r.name}-${scheme}.png`));
      if (!job.before) {
        const full = await ev(`({w:document.documentElement.scrollWidth,h:document.documentElement.scrollHeight})`);
        await shot(sessionId, {x: 0, y: 0, width: full.w, height: full.h}, out(`${job.prefix}-sheet-${scheme}.png`));
      }
      await cdp("Target.closeTarget", {targetId});
    } else {
      const dpr = job.width <= 400 ? 2 : 1;
      const {sessionId, targetId, ev} = await open(job.url, job.width, job.height || 900, scheme, dpr, job.init);
      if (scheme === "light" && !job.before) auditLog.push({tag, result: await ev(AUDIT)});
      const h = job.height || await ev(`Math.max(document.documentElement.scrollHeight, document.body.scrollHeight)`);
      await shot(sessionId, {x: 0, y: 0, width: job.width, height: h}, (job.before ? before : out)(`${job.file}-${scheme}.png`));
      await cdp("Target.closeTarget", {targetId});
    }
  }
  console.log("ok", tag);
}
if (!extMode) fs.writeFileSync(path.join(here, filter ? `audit-${filter}.json` : "audit.json"), JSON.stringify(auditLog, null, 1));
await chrome.close();
fs.rmSync(profile, {recursive: true, force: true});
if (extMode && process.exitCode) console.log("extension audit: FAIL"); else if (extMode) console.log("extension audit: clean");

// ---- Extension mode: the real pages, stubbed API, measured audit ------------------------------------------------
// Fails on: clipped text (an ellipsis on an element whose full value is in a title counts as truncation, not
// clipping), horizontal scroll, more than one filled button, more than five text sizes, off-scale spacing,
// a focusable control without an accessible name, and a popup main view over 520 px or with an inner scroller.
function extAudit() { return `(() => {
  const scale = new Set([0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64]);
  const clipped = [], ellipsis = [], sizes = new Set(), off = new Set(), unnamed = [], scrollers = [];
  const visible = (el) => { const cs = getComputedStyle(el); return cs.display !== 'none' && cs.visibility !== 'hidden' && !el.closest('[hidden]') && el.getClientRects().length > 0; };
  const all = [];
  const walk = (root) => { for (const el of root.querySelectorAll('*')) { all.push(el); if (el.shadowRoot) walk(el.shadowRoot); } };
  walk(document);
  for (const el of all) {
    if (!visible(el)) continue;
    const cs = getComputedStyle(el);
    const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (hasText) sizes.add(parseFloat(cs.fontSize) + (/mono|Menlo|Consolas/.test(cs.fontFamily) ? ' mono' : ''));
    if (hasText && el.scrollWidth > el.clientWidth + 1 && cs.overflowX !== 'visible') {
      (cs.textOverflow === 'ellipsis' && el.closest('[title]') ? ellipsis : clipped).push(el.textContent.trim().slice(0, 60));
    }
    if (/(auto|scroll)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 1) scrollers.push((el.id || el.className || el.tagName) + ' ' + el.scrollHeight + '>' + el.clientHeight);
    if (el.matches('button, input, select, textarea, a[href], [role=tab], [tabindex]')) {
      const label = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.textContent.trim() || el.title || (el.labels && el.labels.length && el.labels[0].textContent.trim());
      if (!label) unnamed.push(el.outerHTML.slice(0, 80));
    }
    if (el.matches('.dot, .mark, .switch, .seg, .seg button, .tabs [role=tab], .sheet, figure, figcaption')) continue;
    for (const p of ['paddingTop','paddingRight','paddingBottom','paddingLeft','marginTop','marginBottom','marginLeft','marginRight','rowGap','columnGap']) {
      const v = parseFloat(cs[p]); if (!isNaN(v) && !scale.has(Math.abs(Math.round(v))) && Math.abs(v - Math.round(v)) < .01) off.add(p + ':' + v + ' ' + (el.id || el.className || el.tagName));
    }
  }
  const primaries = all.filter((b) => b.matches('.btn.primary') && visible(b)).length;
  const textSizes = [...sizes].filter((s) => !String(s).endsWith('mono'));
  return {clipped, ellipsis, primaries, sizes: [...sizes].sort(), textSizes: textSizes.length, off: [...off].slice(0, 20), unnamed, scrollers,
    hscroll: document.documentElement.scrollWidth > innerWidth + 1, height: document.documentElement.scrollHeight};
})()`; }

async function extension() {
  const dir = path.join(here, "ext", extBefore ? "before" : "after");
  fs.mkdirSync(dir, {recursive: true});
  const page = (f) => pathToFileURL(path.join(repo, "browser", f)).href;
  const log = [];
  const problems = [];
  const judge = (tag, r, {budget} = {}) => {
    const bad = [];
    if (r.clipped.length) bad.push(`clipped: ${r.clipped.join(" | ")}`);
    if (r.hscroll) bad.push("scrolls horizontally");
    if (r.primaries > 1) bad.push(`${r.primaries} filled buttons`);
    if (r.textSizes > 5) bad.push(`${r.textSizes} font sizes: ${r.sizes.join(", ")}`);
    if (r.off.length) bad.push(`off-scale: ${r.off.join(", ")}`);
    if (r.unnamed.length) bad.push(`no accessible name: ${r.unnamed.join(" | ")}`);
    if (budget && (r.height > budget || r.scrollers.length)) bad.push(`main view ${r.height} px tall (budget ${budget}) ${r.scrollers.join(" ")}`);
    log.push({tag, ...r, bad});
    if (bad.length && !extBefore) { problems.push(`${tag}: ${bad.join("; ")}`); process.exitCode = 1; }
  };

  // Popup at its real 360 px width, 2x.
  const states = Object.fromEntries(fx.POPUP.map((s) => [s[0], s]));
  for (const [name, state0, page0, url0, setup = ""] of fx.POPUP) {
    if (filter && !`popup-${name}`.includes(filter)) continue;
    if (extBefore && name !== "main") continue;
    const steps = setup.split(";").filter(Boolean);
    const same = steps.find((s) => s.startsWith("same:"));
    const [, state, pageStatus, url] = same ? states[same.slice(5)] : [name, state0, page0, url0];
    for (const scheme of schemes) {
      const {sessionId, targetId, ev} = await open(page("popup.html"), 360, 600, scheme, 2, fx.popupStub(state, pageStatus, url));
      await sleep(300);
      for (const s of steps) {
        if (s.startsWith("tab:")) await ev(`document.getElementById('tab-${s.slice(4)}').click()`);
        if (s.startsWith("focusrow:")) await ev(`(() => { const r = [...document.querySelectorAll('[role=tabpanel]:not([hidden]) .row[tabindex]')][${Number(s.slice(9))}]; r.focus(); })()`);
        if (s === "add") await ev(`document.getElementById('rule-add').click()`);
      }
      await sleep(250);
      const main = /^(main|idn|threat|packed|badge|reduced|paused|unsupported|firefox|longhost)$/.test(name);
      if (scheme === "light") judge(`popup-${name}`, await ev(extAudit()), {budget: !extBefore && main ? 520 : 0});
      const h = await ev(`document.documentElement.scrollHeight`);
      await shot(sessionId, {x: 0, y: 0, width: 360, height: h}, path.join(dir, `popup-${name}-${scheme}.png`));
      await cdp("Target.closeTarget", {targetId});
    }
    console.log("ok", `popup-${name}`);
  }

  // Decision pages at 1440 and 390.
  for (const [name, file, rest, stub, setup] of fx.PAGES) {
    if (filter && !name.includes(filter)) continue;
    if (extBefore && !["warning", "interstitial", "unread"].includes(name)) continue;
    for (const w of [1440, 390]) for (const scheme of schemes) {
      const {sessionId, targetId, ev} = await open(page(file) + rest, w, 900, scheme, w <= 400 ? 2 : 1, stub);
      await sleep(300);
      if (setup) { await ev(setup); await sleep(200); }
      if (scheme === "light") {
        const r = await ev(extAudit());
        r.focused = await ev(`document.activeElement && (document.activeElement.id || document.activeElement.textContent.trim())`);
        judge(`${name}-${w}`, r);
      }
      const h = await ev(`Math.max(document.documentElement.scrollHeight, document.body.scrollHeight)`);
      await shot(sessionId, {x: 0, y: 0, width: w, height: h}, path.join(dir, `${name}-${w}-${scheme}.png`));
      await cdp("Target.closeTarget", {targetId});
    }
    console.log("ok", name);
  }

  // The click-to-load placeholder, rendered by page-guard.js inside a stand-in article.
  if (!filter || filter.includes("placeholder")) {
    for (const scheme of schemes) {
      const {sessionId, targetId, ev} = await open(pathToFileURL(path.join(here, "ext-placeholder.html")).href, 1600, 1200, scheme, 2);
      await sleep(300);
      const rects = await ev(`[...document.querySelectorAll('.frame[data-name]')].map(e=>{const r=e.getBoundingClientRect();return {name:e.dataset.name,x:r.left+scrollX,y:r.top+scrollY,width:r.width,height:r.height}})`);
      if (scheme === "light") judge("placeholder", await ev(extAudit().replace("walk(document);", "for (const f of document.querySelectorAll('.frame [data-eg-embed]')) { all.push(f); walk(f.shadowRoot); }")));
      for (const r of rects) await shot(sessionId, {x: r.x, y: r.y, width: r.width, height: r.height}, path.join(dir, `${r.name}-${scheme}.png`));
      await cdp("Target.closeTarget", {targetId});
    }
    console.log("ok", "placeholder");
  }
  fs.writeFileSync(path.join(dir, "audit.json"), JSON.stringify(log, null, 1));
  for (const p of problems) console.log("AUDIT", p);
}
