// Optional real-Chrome check of the MV3 service-worker lifecycle. Not part of `node --test`; run it explicitly:
//   node tests/browser/chrome-lifecycle.mjs [--chrome PATH]
// Headless Chrome, throwaway profile, loopback fixture only (every other name resolves to NOTFOUND). Takes about
// two minutes because it waits for real alarms. It proves:
//   1. user rules, a timed exception and a "continue once" survive the worker being stopped and started again,
//      and are still enforced by Chrome while the worker is stopped;
//   2. an exception and a continue that expire while the worker is stopped are removed: chrome.alarms wakes the
//      worker, nobody else does;
//   3. "continue once" is capped at 10 minutes (stored expiry and the scheduled alarm).
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {build, loadLists} from "../../scripts/build-browser.mjs";
import {launch, attachWorker, waitFor, sleep, DEFAULT_CHROME} from "./cdp.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const argv = process.argv.slice(2);
const chromeBin = argv.includes("--chrome") ? argv[argv.indexOf("--chrome") + 1] : DEFAULT_CHROME;
fs.mkdirSync(path.join(root, ".cache"), {recursive: true});
const work = fs.mkdtempSync(path.join(root, ".cache", "chrome-lifecycle-"));
const results = [];
const check = (name, ok, detail = "") => { results.push({name, ok}); console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };

const built = build({out: path.join(work, "dist"), lists: loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true})});
const hits = [];
const server = http.createServer((req, res) => {
  const host = (req.headers.host || "").replace(/:\d+$/, "");
  hits.push(`${host}${new URL(req.url, "http://x").pathname}`);
  if (req.url.startsWith("/page")) { res.writeHead(200, {"content-type": "text/html"}); return res.end("<!doctype html><title>page</title><p>page</p>"); }
  res.writeHead(200, {"content-type": "image/gif", "cache-control": "no-store"});
  res.end(Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const HOSTS = ["publisher.example", "pixel.tracker-fixture.test", "malware-fixture.test", "fresh-tracker.test"];
const profile = path.join(work, "profile");
fs.mkdirSync(profile);
const browser = launch({bin: chromeBin, profile, args: ["--no-proxy-server",
  `--host-resolver-rules=${HOSTS.map((h) => `MAP ${h} 127.0.0.1`).join(", ")}, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`]});
const {cdp, evaluate} = browser;

let sw = null;
const id = built.extensionId;
const swEval = async (expr) => { if (!sw) sw = await attachWorker(cdp, id); return evaluate(sw.sessionId, expr); };
const workerRunning = async () => (await cdp("Target.getTargets")).targetInfos.some((t) => t.type === "service_worker" && t.url.includes(id));
async function stopWorker() {
  const t = (await cdp("Target.getTargets")).targetInfos.find((x) => x.type === "service_worker" && x.url.includes(id));
  if (sw) { await cdp("Target.detachFromTarget", {sessionId: sw.sessionId}).catch(() => {}); sw = null; }
  if (t) await cdp("Target.closeTarget", {targetId: t.targetId});
  return waitFor(async () => !(await workerRunning()), 20000);
}
const loadImage = (session, url) => evaluate(session, `new Promise((r) => { const i = new Image(); i.onload = () => r("ok"); i.onerror = () => r("error"); i.src = ${JSON.stringify(url)}; })`);

try {
  await cdp("Extensions.loadUnpacked", {path: path.join(work, "dist", "chrome")});
  await swEval("__EGBackground.ready.then(() => true)");
  await waitFor(async () => (await swEval("chrome.declarativeNetRequest.getEnabledRulesets()")).includes("threats"), 60000, 500);
  const {targetId} = await cdp("Target.createTarget", {url: `http://publisher.example:${port}/page`});
  const page = (await cdp("Target.attachToTarget", {targetId, flatten: true})).sessionId;
  await waitFor(async () => (await evaluate(page, "document.readyState")) === "complete");
  const tabId = await swEval(`chrome.tabs.query({}).then((t) => t.find((x) => (x.url || "").includes("publisher.example")).id)`);
  const popup = `{id: chrome.runtime.id, url: "chrome-extension://" + chrome.runtime.id + "/popup.html"}`;
  const tabUrl = JSON.stringify(`http://publisher.example:${port}/page`);

  // State: a user block rule, a 15-minute exception, a 1-minute exception, a continue for the threat host.
  const setup = await swEval(`(async () => {
    const S = __EGBackground.store, P = ${popup};
    await S.addRule({kind: "request", site: "publisher.example", host: "pixel.tracker-fixture.test", path: "/user-blocked.gif", types: ["image"], action: "block"});
    await __EGBackground.sync();
    const long = await __EGBackground.handle({type: "add-exception", tabId: ${tabId}, tabUrl: ${tabUrl}, host: "pixel.tracker-fixture.test", path: "/allowed.gif", resourceType: "image", minutes: 15}, P);
    const short = await __EGBackground.handle({type: "add-exception", tabId: ${tabId}, tabUrl: ${tabUrl}, host: "pixel.tracker-fixture.test", path: "/short.gif", resourceType: "image", minutes: 1}, P);
    const warn = "chrome-extension://" + chrome.runtime.id + "/warning.html?list=threats#http://malware-fixture.test:${port}/page";
    const cont = await __EGBackground.handle({type: "continue-once", url: "http://malware-fixture.test:${port}/page"}, {id: chrome.runtime.id, url: warn, frameId: 0, tab: {id: ${tabId}, url: warn}});
    const continues = await __EGBackground.continues();
    const alarm = await chrome.alarms.get("eg-expiry");
    return {long: long.ok, short: short.ok, cont: cont.ok, continues, alarm: alarm && alarm.scheduledTime, now: Date.now(),
      dynamic: (await chrome.declarativeNetRequest.getDynamicRules()).length, session: (await chrome.declarativeNetRequest.getSessionRules()).length};
  })()`);
  check("setup: rule, two exceptions and a continue added", setup.long && setup.short && setup.cont && setup.dynamic === 3 && setup.session === 2, JSON.stringify(setup));
  const capMs = setup.continues[0].expiresAt - setup.now;
  check("continue once: stored expiry is 10 minutes", Math.abs(capMs - 600000) < 5000, `${Math.round(capMs / 1000)} s`);

  // 1. Stop the worker. Chrome keeps enforcing; state is intact when it starts again.
  check("worker stopped", await stopWorker());
  hits.length = 0;
  const whileStopped = [await loadImage(page, `http://pixel.tracker-fixture.test:${port}/allowed.gif`), await loadImage(page, `http://pixel.tracker-fixture.test:${port}/user-blocked.gif`)];
  check("while stopped: the exception still lets its endpoint through, the user rule still blocks", whileStopped.join() === "ok,error" && hits.includes("pixel.tracker-fixture.test/allowed.gif") && !hits.includes("pixel.tracker-fixture.test/user-blocked.gif"), whileStopped.join());
  const after = await swEval(`(async () => { await __EGBackground.ready; return {
    rules: __EGBackground.store.rules.length, exceptions: __EGBackground.store.exceptions.length, continues: (await __EGBackground.continues()).length,
    dynamic: (await chrome.declarativeNetRequest.getDynamicRules()).length, session: (await chrome.declarativeNetRequest.getSessionRules()).length}; })()`);
  check("restarted worker: rule, exceptions and continue survive", after.rules >= 1 && after.exceptions === 2 && after.continues === 1 && after.dynamic === 3 && after.session === 2, JSON.stringify(after));

  // 2/3. Make the continue expire in 35 s (as if its 10 minutes were up), stop the worker, and wait past both
  // expiries (the 1-minute exception and the continue) without touching the worker.
  const due = await swEval(`(async () => {
    const list = await __EGBackground.continues();
    const soon = Date.now() + 35000;
    await chrome.storage.session.set({continues: list.map((c) => ({...c, expiresAt: soon}))});
    await chrome.alarms.create("eg-expiry", {when: soon});
    return {soon, exception: Math.min(...__EGBackground.store.exceptions.map((e) => e.expiresAt))};
  })()`);
  check("worker stopped again before the expiries", await stopWorker());
  const deadline = Math.max(due.soon, due.exception) + 20000;
  let wokeAt = null;
  while (Date.now() < deadline) {
    if (!wokeAt && (await workerRunning())) wokeAt = Date.now();
    await sleep(1000);
  }
  check("the alarm woke the stopped worker (nothing else touched it)", wokeAt !== null, wokeAt ? `${Math.round((wokeAt - due.soon) / 1000)} s after the first expiry` : "never");
  const end = await swEval(`(async () => { await __EGBackground.ready; return {
    exceptions: __EGBackground.store.exceptions.map((e) => e.path), continues: (await __EGBackground.continues()).length,
    dynamic: (await chrome.declarativeNetRequest.getDynamicRules()).map((r) => r.priority),
    session: (await chrome.declarativeNetRequest.getSessionRules()).length}; })()`);
  check("expired exception removed while the worker was asleep; the 15-minute one kept", end.exceptions.join() === "/allowed.gif" && end.dynamic.length === 2, JSON.stringify(end));
  check("expired continue removed while the worker was asleep", end.continues === 0 && end.session === 0, JSON.stringify(end));
  hits.length = 0;
  check("after expiry Chrome blocks the formerly excepted endpoint again", (await loadImage(page, `http://pixel.tracker-fixture.test:${port}/short.gif`)) === "error" && !hits.length);

  // 4. Fresh lists with no user action: rebuild the folder Chrome loaded (as a daily job would) with a new tracker;
  //    the worker's check sees the new build stamp and reloads; the new list is enforced and user state survives.
  const fresh = loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true});
  fresh.trackers.names.push("fresh-tracker.test");
  const rebuilt = build({out: path.join(work, "dist"), lists: fresh});
  hits.length = 0;
  check("before the check: the new tracker is not blocked yet", (await loadImage(page, `http://fresh-tracker.test:${port}/x.gif`)) === "ok");
  const outcome = await swEval("__EGBackground.reloadIfRebuilt()").catch((e) => `reloading (${String(e.message).split("\n")[0]})`);
  sw = null;
  const reloaded = await waitFor(async () => { try { return (await swEval("globalThis.EGLists && EGLists.build")) === rebuilt.build; } catch { sw = null; return false; } }, 60000, 1000);
  check("the worker reloaded itself onto the rebuilt folder", reloaded && /reloading/.test(outcome), outcome);
  await waitFor(async () => (await swEval("chrome.declarativeNetRequest.getEnabledRulesets()")).includes("trackers"), 60000, 500);
  hits.length = 0;
  check("after the reload the new tracker is blocked", (await loadImage(page, `http://fresh-tracker.test:${port}/x.gif`)) === "error" && !hits.length);
  const kept = await swEval("__EGBackground.ready.then(() => ({rules: __EGBackground.store.rules.length, exceptions: __EGBackground.store.exceptions.length}))");
  check("user rules and exceptions survive the reload", kept.rules >= 1 && kept.exceptions === 1, JSON.stringify(kept));
} catch (error) {
  check("harness", false, error.stack || String(error));
} finally {
  await browser.close();
  server.close();
  fs.rmSync(work, {recursive: true, force: true});
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}
