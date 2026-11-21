// Headless capture of the design mockups (and the warning-page "before") into docs/design/review/.
// node docs/design/review/capture.mjs [filter]   — headless Chrome, throwaway profile, no visible window.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {launch, sleep} from "../../../tests/browser/cdp.mjs";

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

// The real dashboard, served by the real server from src/egress_guard/web, when a capture harness is given:
//   EG_DASHBOARD_HARNESS=docs/design/review/dashboard-harness.py EG_PYTHON=.venv/bin/python
//   EGRESS_GUARD_DATA=<private temp dir> EGRESS_GUARD_CONFIG=<dir>/config.toml node docs/design/review/capture.mjs live
// The harness must already be serving (`harness serve`); each capture writes <data>/scenario.json and takes a
// fresh single-use URL from `harness url`. EG_DASHBOARD_OUT picks the output folder (default after/live).
// Jobs: [file, status, ledger, widths, schemes, tab]
const live = process.env.EG_DASHBOARD_HARNESS ? [
  ["full", "protected", "full", [1440, 768, 390], ["light", "dark"], ""],
  ["empty", "degraded", "empty", [1440, 390], ["light", "dark"], ""],
  ["new", "protected", "empty", [1440, 390], ["light"], ""],
  ["reduced", "reduced", "full", [1440, 390], ["light"], ""],
  ["paused", "paused", "full", [1440], ["light"], ""],
  ["degraded", "degraded", "full", [1440, 390], ["light"], ""],
  ["aggregate", "protected", "aggregate", [1440, 390], ["light"], ""],
  ["none", "protected", "none", [1440, 390], ["light"], ""],
  ["tab-top", "protected", "full", [1440, 390], ["light"], "top"],
  ["tab-threats", "protected", "full", [1440, 390], ["light", "dark"], "threats"],
  ["week", "protected", "full", [1440], ["light"], "week"],
  ["row-action", "protected", "full", [1440, 390], ["light"], "row"],
  ["confirm", "protected", "full", [1440, 390], ["light"], "confirm"],
] : [];
const liveOut = process.env.EG_DASHBOARD_OUT || path.join(here, "after", "live");
for (const [file, status, ledger, widths, liveSchemes, tab] of live) {
  for (const w of widths) jobs.push({kind: "live", file: `live-${file}-${w}`, width: w, status, ledger, liveSchemes, tab});
}
const {execFileSync} = await import("node:child_process");
const liveUrl = (status, ledger) => {
  fs.writeFileSync(path.join(process.env.EGRESS_GUARD_DATA, "scenario.json"), JSON.stringify({status, ledger}));
  return execFileSync(process.env.EG_PYTHON || "python3", ["-B", process.env.EG_DASHBOARD_HARNESS, "url"], {encoding: "utf8"}).trim();
};

// Overlap check for the live dashboard: two visible text boxes that intersect and are not nested.
const OVERLAP = `(() => {
  // With a modal open, only the modal is the view (the page behind it is inert).
  const els = [...(document.querySelector('dialog[open]') || document.body).querySelectorAll('*')].filter((el) => {
    if (el.closest('[hidden], .sr-only, dialog:not([open])')) return false;
    const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden') return false;
    return [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
  });
  // One rect per rendered line, so inline text that wraps is not mistaken for an overlap.
  const boxes = els.map((el) => { const r = document.createRange(); r.selectNodeContents(el); return [el, [...r.getClientRects()].filter((x) => x.width && x.height)]; });
  const meet = (p, q) => p.left < q.right - 1 && q.left < p.right - 1 && p.top < q.bottom - 1 && q.top < p.bottom - 1;
  const hits = [];
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const [a, ps] = boxes[i], [b, qs] = boxes[j];
    if (a.contains(b) || b.contains(a)) continue;
    if (ps.some((p) => qs.some((q) => meet(p, q)))) hits.push(a.textContent.trim().slice(0, 30) + ' / ' + b.textContent.trim().slice(0, 30));
  }
  return hits.slice(0, 12);
})()`;

const filter = process.argv[2];
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
      if (cs.display === 'none' || cs.visibility === 'hidden' || el.closest('[hidden], .sr-only, dialog:not([open]), noscript')) continue;
      const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
      if (hasText) sizes.add(cs.fontSize + (cs.fontFamily.includes('mono') ? ' mono' : ''));
      if (hasText && el.scrollWidth > el.clientWidth + 1 && cs.overflowX !== 'visible') clipped.push(el.textContent.trim().slice(0, 50));
      if (el.closest('.sheet > figure > figcaption') || el.matches('.lights i, .bars i, .days i, .dot, .mark, svg *, .switch, .sk, dialog')) continue;
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

for (const job of jobs) {
  const tag = job.file || job.prefix;
  if (filter && !tag.includes(filter)) continue;
  if (job.kind === "live") {
    fs.mkdirSync(liveOut, {recursive: true});
    for (const scheme of job.liveSchemes) {
      const dpr = job.width <= 400 ? 2 : 1;
      const {sessionId, targetId, ev} = await open(liveUrl(job.status, job.ledger), job.width, 900, scheme, dpr);
      for (let i = 0; i < 50 && !(await ev(`document.body.dataset.ready === '1'`)); i++) await sleep(100);
      if (job.tab === "week") await ev(`document.getElementById('range-week')?.click()`);
      else if (job.tab === "row" || job.tab === "confirm") {
        // "row": focus the row blocked by the user's own rule (its "Unblock…" is the widest trailing action).
        // "confirm": open Block… on an allowed row, which checks /api/domain and then opens the dialog.
        await ev(`(() => { const row = [...document.querySelectorAll('#activity-rows .row')].find((r) => r.getAttribute('aria-label').includes(${job.tab === "confirm" ? "'app.example-maps.test'" : "'Your block rule'"})); row.focus(); if (${job.tab === "confirm"}) row.querySelector('.act button').click(); })()`);
        await sleep(600);
      } else if (job.tab) await ev(`document.querySelector('[role=tab][data-tab=${job.tab}]')?.click()`);
      await sleep(400);
      if (scheme === "light") auditLog.push({tag: job.file, result: await ev(AUDIT), overlap: await ev(OVERLAP)});
      const h = Math.min(4000, await ev(`Math.max(document.documentElement.scrollHeight, document.body.scrollHeight)`));
      const {data} = await cdp("Page.captureScreenshot", {format: "jpeg", quality: 82, captureBeyondViewport: true,
        clip: {x: 0, y: 0, width: job.width, height: h, scale: job.width <= 400 ? 0.6 : 0.75}}, sessionId);
      fs.writeFileSync(path.join(liveOut, `${job.file}-${scheme}.jpg`), Buffer.from(data, "base64"));
      await cdp("Target.closeTarget", {targetId});
    }
    console.log("ok", tag);
    continue;
  }
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
fs.writeFileSync(path.join(here, filter ? `audit-${filter}.json` : "audit.json"), JSON.stringify(auditLog, null, 1));
await chrome.close();
fs.rmSync(profile, {recursive: true, force: true});
