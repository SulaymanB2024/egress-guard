// Optional real-Firefox check. Not part of `node --test`; run it explicitly:
//   node tests/browser/firefox-headless.mjs [/path/to/firefox]
// Launches headless Firefox with a throwaway profile under .cache/ (never the user's profile),
// installs a temporary copy of browser/ through Marionette, and serves the publisher fixture
// from 127.0.0.1. Every non-fixture host is sent to a dead loopback proxy, so nothing external
// is contacted. The copy adds one test-only background file (seed) that stores the fixture rules
// through the same RuleStore API the popup uses, and starts the picker on "#pick" URLs.
import fs from "node:fs";
import net from "node:net";
import http from "node:http";
import path from "node:path";
import {spawn} from "node:child_process";
import {fileURLToPath} from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const firefox = process.argv[2] || "/Applications/Firefox.app/Contents/MacOS/firefox";
const fixtureDir = path.join(here, "fixtures/publisher");
fs.mkdirSync(path.join(root, ".cache"), {recursive: true});
const work = fs.mkdtempSync(path.join(root, ".cache", "ff-check-"));
const ADDON_ID = "browser-companion@egress-guard.invalid";
const results = [];
const check = (name, ok, detail = "") => { results.push({name, ok, detail}); console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const {port} = s.address(); s.close(() => resolve(port)); }); });

// ---- fixture server -----------------------------------------------------------
const hits = [];
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://fixture");
  hits.push({method: req.method, host: req.headers.host, path: url.pathname});
  const send = (code, type, body) => { res.writeHead(code, {"content-type": type, "cache-control": "no-store"}); res.end(body); };
  if (url.pathname === "/article") return send(200, "text/html; charset=utf-8", fs.readFileSync(path.join(fixtureDir, "index.html")));
  if (url.pathname === "/static/app.js") return send(200, "text/javascript", fs.readFileSync(path.join(fixtureDir, "static/app.js")));
  if (url.pathname === "/static/site.css") return send(200, "text/css", fs.readFileSync(path.join(fixtureDir, "static/site.css")));
  if (url.pathname === "/api/session") return send(200, "text/plain", "ok");
  if (url.pathname === "/collect") return send(204, "text/plain", "");
  return send(404, "text/plain", "not found");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const marionettePort = await freePort();

// ---- extension copy with test-only seed ------------------------------------------
const ext = path.join(work, "extension");
fs.cpSync(path.join(root, "browser"), ext, {recursive: true});
const manifest = JSON.parse(fs.readFileSync(path.join(ext, "manifest.json"), "utf8"));
manifest.background.scripts.push("test-seed.js");
fs.writeFileSync(path.join(ext, "manifest.json"), JSON.stringify(manifest, null, 2));
const rules = JSON.parse(fs.readFileSync(path.join(fixtureDir, "rules.json"), "utf8")).rules;
fs.writeFileSync(path.join(ext, "test-seed.js"), `"use strict";
(async () => {
  const bg = globalThis.__EGBackground; await bg.ready;
  for (const rule of ${JSON.stringify(rules)}) { try { await bg.store.addRule(rule); } catch (e) { console.warn(e.message); } }
  browser.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (info.status === "complete" && tab.url && tab.url.endsWith("#pick")) browser.tabs.sendMessage(tabId, {type: "start-picker"}).catch(() => {});
  });
  globalThis.__seeded = true;
})();
`);

// ---- throwaway profile --------------------------------------------------------
const profile = path.join(work, "profile");
fs.mkdirSync(profile);
const prefs = {
  "marionette.port": marionettePort,
  "network.proxy.type": 1, "network.proxy.http": "127.0.0.1", "network.proxy.http_port": 9,
  "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": 9, "network.proxy.socks": "127.0.0.1", "network.proxy.socks_port": 9,
  "network.proxy.share_proxy_settings": true, "network.proxy.no_proxies_on": "publisher.example,127.0.0.1",
  "network.proxy.allow_hijacking_localhost": false, "network.dns.localDomains": "publisher.example",
  "network.trr.mode": 5, "network.dns.disablePrefetch": true, "network.prefetch-next": false, "network.http.speculative-parallel-limit": 0,
  "network.captive-portal-service.enabled": false, "network.connectivity-service.enabled": false, "network.http.http3.enable": false,
  "app.update.disabledForTesting": true, "app.normandy.enabled": false, "toolkit.telemetry.enabled": false,
  "datareporting.healthreport.uploadEnabled": false, "datareporting.policy.dataSubmissionEnabled": false,
  "services.settings.server": "http://127.0.0.1:9/", "extensions.update.enabled": false, "extensions.getAddons.cache.enabled": false,
  "extensions.blocklist.enabled": false, "extensions.systemAddon.update.enabled": false, "browser.region.network.url": "",
  "browser.region.update.enabled": false, "browser.safebrowsing.malware.enabled": false, "browser.safebrowsing.phishing.enabled": false,
  "browser.safebrowsing.downloads.remote.enabled": false, "browser.shell.checkDefaultBrowser": false, "browser.startup.page": 0,
  "browser.startup.homepage": "about:blank", "browser.newtabpage.enabled": false, "browser.aboutwelcome.enabled": false,
  "datareporting.policy.firstRunURL": "", "security.OCSP.enabled": 0, "dom.push.connection.enabled": false, "geo.provider.network.url": "",
  "media.gmp-provider.enabled": false, "browser.search.update": false, "browser.topsites.contile.enabled": false,
  "extensions.webextensions.uuids": JSON.stringify({[ADDON_ID]: "8c0f6f3e-5b1a-4c55-9d7e-1f2a3b4c5d6e"}),
};
fs.writeFileSync(path.join(profile, "user.js"), Object.entries(prefs).map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join("\n") + "\n");

const child = spawn(firefox, ["--headless", "--marionette", "--no-remote", "-new-instance", "--profile", profile], {stdio: ["ignore", "pipe", "pipe"]});
let stderr = "";
child.stderr.on("data", (d) => { stderr += d; });
child.stdout.on("data", () => {});

// ---- minimal Marionette client --------------------------------------------------
async function connect() {
  for (let i = 0; i < 100; i++) {
    try { return await new Promise((resolve, reject) => { const s = net.connect(marionettePort, "127.0.0.1", () => resolve(s)); s.on("error", reject); }); }
    catch { await sleep(200); }
  }
  throw new Error("Marionette did not start");
}
const socket = await connect();
let buffer = "", nextId = 1;
const waiting = new Map();
let greeted;
const greeting = new Promise((r) => { greeted = r; });
socket.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  for (;;) {
    const colon = buffer.indexOf(":");
    if (colon < 0) return;
    const len = Number(buffer.slice(0, colon));
    if (Buffer.byteLength(buffer.slice(colon + 1)) < len) return;
    const bytes = Buffer.from(buffer.slice(colon + 1));
    const body = bytes.subarray(0, len).toString("utf8");
    buffer = bytes.subarray(len).toString("utf8");
    const msg = JSON.parse(body);
    if (!Array.isArray(msg)) { greeted(msg); continue; }
    const [, id, error, result] = msg;
    const w = waiting.get(id); waiting.delete(id);
    if (w) error ? w.reject(new Error(`${error.error}: ${error.message}`)) : w.resolve(result);
  }
});
const call = (name, params = {}) => new Promise((resolve, reject) => {
  const id = nextId++;
  waiting.set(id, {resolve, reject});
  const body = JSON.stringify([0, id, name, params]);
  socket.write(`${Buffer.byteLength(body)}:${body}`);
});
const js = async (script, args = []) => (await call("WebDriver:ExecuteScript", {script, args})).value;
async function until(script, label, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await js(script)) return true; await sleep(150); }
  check(label, false, "timed out");
  return false;
}
async function clickAt(x, y) {
  await call("WebDriver:PerformActions", {actions: [{type: "pointer", id: "mouse", parameters: {pointerType: "mouse"}, actions: [
    {type: "pointerMove", x: Math.round(x), y: Math.round(y), origin: "viewport"}, {type: "pointerDown", button: 0}, {type: "pointerUp", button: 0}]}]});
  await call("WebDriver:ReleaseActions");
}

const PAGE = `http://publisher.example:${port}/article`;
const CONTROL = `http://127.0.0.1:${port}/article`;
const pageReady = "return document.getElementById('fixture-status')?.textContent === 'session:ok'";
const shown = (id) => `const n = document.getElementById('${id}'); return n && getComputedStyle(n).display !== 'none'`;
try {
  await greeting;
  await call("WebDriver:NewSession", {capabilities: {alwaysMatch: {}}});
  const installed = await call("Addon:Install", {path: ext, temporary: true});
  check("temporary install accepted the MV3 manifest", (installed.value || installed) === ADDON_ID, JSON.stringify(installed));
  await sleep(1500); // let the seed store rules

  // Control: same page on an IP origin is outside every site scope, so the beacon is sent.
  hits.length = 0;
  await call("WebDriver:Navigate", {url: CONTROL});
  await until(pageReady, "control page loaded");
  await sleep(800);
  check("control: /collect reaches the server outside the rule's site", hits.some((h) => h.path === "/collect"));

  // Rule site: the same-origin collector is cancelled before it is sent; everything else loads.
  hits.length = 0;
  await call("WebDriver:Navigate", {url: PAGE});
  const loaded = await until(pageReady, "publisher page loaded with session XHR");
  await sleep(1200);
  const paths = hits.map((h) => h.path);
  check("publisher: article, script, stylesheet and session XHR load", loaded && ["/article", "/static/app.js", "/static/site.css", "/api/session"].every((p) => paths.includes(p)), paths.join(" "));
  check("publisher: /collect beacon never reaches the server", !paths.includes("/collect"));
  check("publisher: video element requested its media", paths.includes("/media/clip.webm"), "informational: depends on headless media preload");
  check("publisher: login form and video remain visible", await js(`return ['login', 'clip', 'story'].every((id) => getComputedStyle(document.getElementById(id)).display !== 'none')`));

  // Cosmetic: only the sponsored card is hidden; Show restores it (trusted click via WebDriver actions).
  await until(`return getComputedStyle(document.getElementById('card-sponsored')).display === 'none'`, "sponsored card hidden");
  check("cosmetic: sponsored card hidden", !(await js(shown("card-sponsored"))));
  check("cosmetic: organic cards visible", (await js(shown("card-organic-1"))) && (await js(shown("card-organic-2"))));
  const rect = await js(`const p = document.querySelector('egress-guard-hidden'); if (!p) return null; const r = p.getBoundingClientRect(); return {right: r.right, top: r.top, height: r.height}`);
  check("cosmetic: placeholder inserted", Boolean(rect), JSON.stringify(rect));
  if (rect) {
    await js(`document.querySelector('egress-guard-hidden').scrollIntoView({block: 'center'})`);
    const r2 = await js(`const r = document.querySelector('egress-guard-hidden').getBoundingClientRect(); return {right: r.right, top: r.top, height: r.height}`);
    await clickAt(r2.right - 40, r2.top + r2.height / 2);
    await sleep(300);
    check("cosmetic: Show (real click) restores the sponsored card", await js(shown("card-sponsored")));
  }
  // Page scripts cannot press the companion's buttons: the shadow root is closed.
  check("cosmetic: placeholder shadow root is closed to page scripts", await js(`return document.querySelector('egress-guard-hidden').shadowRoot === null`));

  // Picker on a second load: remove the seeded hide rule's effect by picking on a fresh rule-less selector.
  hits.length = 0;
  await call("WebDriver:Navigate", {url: `${PAGE}#pick`});
  await until(pageReady, "picker page loaded");
  const pickerUp = await until(`return Boolean(document.querySelector('egress-guard-picker'))`, "picker opened", 5000);
  if (pickerUp) {
    await js(`document.getElementById('card-organic-1').scrollIntoView({block: 'center'})`);
    const card = await js(`const r = document.getElementById('card-organic-1').getBoundingClientRect(); return {x: r.left + r.width / 2, y: r.top + r.height / 2}`);
    await clickAt(card.x, card.y);
    await sleep(300);
    const panel = await js(`const r = document.querySelector('egress-guard-picker').getBoundingClientRect(); return {left: r.left, bottom: r.bottom, width: r.width, height: r.height}`);
    // "Create rule" is the first button in the panel's last row.
    await clickAt(panel.left + 12 + 45, panel.bottom - 12 - 17);
    await sleep(600);
    check("picker: real clicks create a rule that hides only the picked organic card", !(await js(shown("card-organic-1"))) && (await js(shown("card-organic-2"))), JSON.stringify(panel));
    const toast = await js(`const t = document.querySelector('egress-guard-toast'); if (!t) return null; const r = t.getBoundingClientRect(); return {left: r.left, bottom: r.bottom}`);
    if (toast) {
      await clickAt(toast.left + 12 + 25, toast.bottom - 12 - 17);
      await sleep(600);
      check("picker: Undo restores the card", await js(shown("card-organic-1")));
    } else check("picker: Undo toast shown", false);
  }
  const external = hits.filter((h) => !/^(publisher\.example|127\.0\.0\.1):/.test(h.host || ""));
  check("no unexpected hosts reached the fixture server", external.length === 0, JSON.stringify(external));
} catch (error) {
  check("harness", false, error.stack || String(error));
} finally {
  try { await call("Marionette:Quit", {flags: ["eForceQuit"]}); } catch {}
  socket.destroy();
  await sleep(500);
  child.kill("SIGKILL");
  server.close();
  fs.rmSync(work, {recursive: true, force: true});
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length && /error|exception/i.test(stderr)) console.log(stderr.split("\n").filter((l) => /egress|companion|error/i.test(l)).slice(0, 20).join("\n"));
  process.exitCode = failed.length ? 1 : 0;
}
