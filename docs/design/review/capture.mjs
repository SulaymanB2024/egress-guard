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

for (const job of jobs) {
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
fs.writeFileSync(path.join(here, filter ? `audit-${filter}.json` : "audit.json"), JSON.stringify(auditLog, null, 1));
await chrome.close();
fs.rmSync(profile, {recursive: true, force: true});
