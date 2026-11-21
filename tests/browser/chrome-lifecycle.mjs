// Optional real-Chrome check of the MV3 service-worker lifecycle. Not part of `node --test`; run it explicitly:
//   node tests/browser/chrome-lifecycle.mjs [--chrome PATH]
// Headless Chrome, throwaway profile, loopback fixture only (every other name resolves to NOTFOUND). Takes about
// two minutes because it waits for real alarms. It proves:
//   1. user rules, a timed exception and a "continue once" survive the worker being stopped and started again,
//      and Chrome continues enforcing the installed DNR policy after that stop;
//   2. expiry/recovery alarms wake the worker and reconcile scheduled deadlines;
//      there is no built-in wall-clock TTL in DNR and suspension can delay removal;
//   3. "continue once" has a ten-minute scheduled deadline, an intent journal and a
//      navigation-only allow paired with credential removal.
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

const built = build({out: path.join(work, "dist"), lists: loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true, allowMissing: true})});
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
  // The tab can take a moment to show its URL to the worker when Chrome is busy (the first run after another suite).
  await waitFor(async () => (await swEval(`chrome.tabs.query({}).then((t) => t.some((x) => (x.url || "").includes("publisher.example")))`)) === true);
  const tabId = await swEval(`chrome.tabs.query({}).then((t) => t.find((x) => (x.url || "").includes("publisher.example")).id)`);
  const popup = `{id: chrome.runtime.id, url: "chrome-extension://" + chrome.runtime.id + "/popup.html"}`;
  const tabUrl = JSON.stringify(`http://publisher.example:${port}/page`);

  // Threat consent has its own real warning tab; it cannot borrow the publisher tab's scope.
  const warningUrl = `chrome-extension://${id}/warning.html?list=threats#http://malware-fixture.test:${port}/page`;
  const consentTab = await swEval(`chrome.tabs.create({url: ${JSON.stringify(warningUrl)}, active: false}).then((t) => t.id)`);
  await waitFor(async () => await swEval(`chrome.tabs.get(${consentTab}).then((t) => t.url === ${JSON.stringify(warningUrl)})`));

  // State: a user block rule, a 15-minute exception, a 1-minute exception, a continue for the threat host.
  const setup = await swEval(`(async () => {
    const S = __EGBackground.store, P = ${popup};
    await S.addRule({kind: "request", site: "publisher.example", host: "pixel.tracker-fixture.test", path: "/user-blocked.gif", types: ["image"], action: "block"});
    await __EGBackground.sync();
    const long = await __EGBackground.handle({type: "add-exception", tabId: ${tabId}, tabUrl: ${tabUrl}, host: "pixel.tracker-fixture.test", path: "/allowed.gif", resourceType: "image", minutes: 15}, P);
    const short = await __EGBackground.handle({type: "add-exception", tabId: ${tabId}, tabUrl: ${tabUrl}, host: "pixel.tracker-fixture.test", path: "/short.gif", resourceType: "image", minutes: 1}, P);
    const warn = "chrome-extension://" + chrome.runtime.id + "/warning.html?list=threats#http://malware-fixture.test:${port}/page";
    const cont = await __EGBackground.handle({type: "continue-once", url: "http://malware-fixture.test:${port}/page"}, {id: chrome.runtime.id, url: warn, frameId: 0, tab: {id: ${consentTab}, url: warn}});
    const continues = await __EGBackground.continues();
    const alarm = await chrome.alarms.get("eg-expiry");
    return {long: long.ok, short: short.ok, cont: cont.ok, continues, alarm: alarm && alarm.scheduledTime, now: Date.now(),
      dynamic: (await chrome.declarativeNetRequest.getDynamicRules()).length, session: (await chrome.declarativeNetRequest.getSessionRules()).length};
  })()`);
  check("setup: rule, two exceptions and a continue added", setup.long && setup.short && setup.cont && setup.dynamic === 1 && setup.session === 6, JSON.stringify(setup));
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
  check("restarted worker: rule, exceptions and continue survive", after.rules >= 1 && after.exceptions === 2 && after.continues === 1 && after.dynamic === 1 && after.session === 6, JSON.stringify(after));

  // 2/3. Make the continue expire in 35 s (as if its 10 minutes were up), stop the worker, and wait past both
  // expiries (the 1-minute exception and the continue) without touching the worker.
  // A timed pause of the site, from the popup, made to end at the same moment (as if its 15 minutes were up).
  const paused = await swEval(`(async () => {
    const r = await __EGBackground.handle({type: "pause-site", tabId: ${tabId}, tabUrl: ${tabUrl}}, ${popup});
    const relax = (await chrome.declarativeNetRequest.getDynamicRules()).some((x) => x.action.type === "allowAllRequests" && x.condition.requestDomains.includes("publisher.example"));
    return {ok: r.ok, until: r.until, now: Date.now(), relax};
  })()`);
  check("pause: the popup pauses the site for 15 minutes (Relaxed in place)", paused.ok && paused.relax && Math.abs(paused.until - paused.now - 900000) < 5000, JSON.stringify(paused));
  hits.length = 0;
  check("pause: the user's own block rule still blocks while paused", (await loadImage(page, `http://pixel.tracker-fixture.test:${port}/user-blocked.gif`)) === "error" && !hits.length);
  // Fixture-only shortening happens after the last controller action, so it cannot
  // be overwritten by an in-memory copy. Preserve journal schema/phase/epoch.
  const due = await swEval(`(async () => {
    const soon = Date.now() + 35000;
    const record = (await chrome.storage.session.get("egressGuardGrants")).egressGuardGrants;
    await chrome.storage.session.set({egressGuardGrants: {...record, entries: record.entries.map((entry) => entry.kind === "continue" ? {...entry, expiresAt: soon} : entry)}});
    await chrome.storage.local.set({egressGuardPauses: {schema: 2, scope: "top-level-psl-v2", items: {"publisher.example": soon}}});
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
  check("expired exception removed while the worker was asleep; the 15-minute one kept", end.exceptions.join() === "/allowed.gif" && end.dynamic.length === 1, JSON.stringify(end));
  check("expired continue removed while the worker was asleep", end.continues === 0 && end.session === 2, JSON.stringify(end));
  const pauseEnd = await swEval(`(async () => { await __EGBackground.ready; return {stored: (await chrome.storage.local.get("egressGuardPauses")).egressGuardPauses || {},
    relax: (await chrome.declarativeNetRequest.getDynamicRules()).some((x) => x.action.type === "allowAllRequests"),
    state: await __EGBackground.handle({type: "popup-state", tabId: ${tabId}, tabUrl: ${tabUrl}}, ${popup})}; })()`);
  check("pause ended on the alarm while the worker was stopped; the site's own level is back", Object.keys(pauseEnd.stored.items || {}).length === 0 && !pauseEnd.relax && pauseEnd.state.paused === null && pauseEnd.state.mode === "standard",
    JSON.stringify({stored: pauseEnd.stored, relax: pauseEnd.relax, paused: pauseEnd.state.paused, mode: pauseEnd.state.mode}));
  hits.length = 0;
  check("after expiry Chrome blocks the formerly excepted endpoint again", (await loadImage(page, `http://pixel.tracker-fixture.test:${port}/short.gif`)) === "error" && !hits.length);

  // 4. A rebuilt folder (as a daily job would write it) is noticed by the running worker, which only reads its own
  //    file. (runtime.reload() is not used: an unpacked extension that reloaded itself came back disabled here.)
  const fresh = loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true, allowMissing: true});
  fresh.trackers.names.push("fresh-tracker.test");
  build({out: path.join(work, "dist"), lists: fresh});
  const before = await swEval("__EGBackground.reloadIfRebuilt()");
  const state = await swEval(`__EGBackground.handle({type: "popup-state", tabId: ${tabId}, tabUrl: ${tabUrl}}, ${popup})`);
  check("the worker notices the rebuilt folder and the popup asks for a reload", before === "rebuilt" && state.rebuilt === true, `${before} ${state.rebuilt}`);
  check("still enabled and enforcing the loaded lists", (await swEval("chrome.declarativeNetRequest.getEnabledRulesets()")).includes("trackers"));
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
