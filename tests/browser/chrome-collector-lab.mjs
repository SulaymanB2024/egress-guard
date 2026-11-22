// Optional real-browser/real-proxy collector qualification. Never run Chrome in
// the restricted implementation environment. --check reads source files only.
//
// node tests/browser/chrome-collector-lab.mjs --check
// node tests/browser/chrome-collector-lab.mjs --chrome /absolute/chrome \
//   --python /absolute/venv/bin/python --extension /absolute/dist/chrome \
//   --out /absolute/new-receipt.json
//
// No existing profile, global trust exception, resolver change or downloaded SDK.
// The helper includes --no-pings: HTML hyperlink auditing is NOT qualified here.
// Context completion + positive controls + browser closure bound observations;
// an empty collector alone never earns credit for preventing a request.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import {spawn} from "node:child_process";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";
import {launch, attachWorker, waitFor, sleep} from "./cdp.mjs";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const FIXTURE = path.join(ROOT, "tests/privacy_lab.py");
const hardening = require("../../browser/core/privacy-hardening.js");
const hosts = require("../../browser/core/hosts.js");
const {measureActionWindow, summarizeActionWindows, assessFirstPartyActionWindows} = require("./collector-byte-windows.cjs");
export const HOSTS = Object.freeze(["publisher.test", "shop.test", "tracker.test", "alias.test", "allowed.test", "blocked.test"]);
export const CHANNELS = Object.freeze(["ga4", "opaque", "third-party", "image", "worker", "service-worker", "cart"]);
export const EXPECTED_BLOCKED = Object.freeze(["ga4", "third-party", "image", "worker", "service-worker"]);
const HIGH_KEYS = ["architecture", "bitness", "formFactors", "fullVersionList", "model", "platformVersion", "uaFullVersion", "wow64"];
const EXISTING_POLICY = "camera=(), microphone=(), geolocation=()";
const sha = value => crypto.createHash("sha256").update(value).digest("hex");
const read = name => fs.readFileSync(path.join(ROOT, name), "utf8");

export function parseOptions(args) {
  const out = {check: false, subjects: 4, timeout: 600000};
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    assert(!seen.has(key), "Duplicate option"); seen.add(key);
    if (key === "--check") out.check = true;
    else {
      assert(["--chrome", "--python", "--extension", "--out", "--subjects", "--timeout"].includes(key), "Unknown option");
      const value = args[++i]; assert(value && !value.startsWith("--"), "Option requires a value");
      out[key.slice(2)] = ["--subjects", "--timeout"].includes(key) ? Number(value) : value;
    }
  }
  assert(Number.isInteger(out.subjects) && out.subjects >= 2 && out.subjects <= 8, "Use two to eight synthetic subjects");
  assert(Number.isInteger(out.timeout) && out.timeout >= 60000 && out.timeout <= 900000, "Timeout must be 60000–900000 ms");
  if (!out.check) for (const key of ["chrome", "python", "extension", "out"]) assert(typeof out[key] === "string" && path.isAbsolute(out[key]), `Native execution requires explicit absolute --${key}`);
  return out;
}

export function makeVisits(arm, subjects) {
  assert(["baseline", "protected"].includes(arm));
  assert(Number.isInteger(subjects) && subjects >= 2 && subjects <= 8);
  const visits = {}, rows = [];
  for (let subject = 0; subject < subjects; subject++) for (const site of HOSTS.slice(0, 2)) {
    const visit = sha(`egress-guard-lab-visit:${arm}:${site}:${subject}`).slice(0, 24);
    const identifier = `eglab-id-${sha(`egress-guard-lab-subject-${subject}`).slice(0, 24)}`;
    visits[visit] = {subject, site}; rows.push({visit, site, identifier});
  }
  return {visits, rows};
}

export function validateMetadata(meta) {
  assert(meta?.schema === 1 && JSON.stringify(meta.hosts) === JSON.stringify(HOSTS), "Unexpected fixture hosts/schema");
  for (const key of ["proxy_port", "origin_port"]) assert(Number.isInteger(meta[key]) && meta[key] > 0 && meta[key] < 65536, "Invalid fixture port");
  assert(/^[a-f0-9]{64}$/.test(meta.origin_certificate_sha256) && /^[A-Za-z0-9+/]{43}=$/.test(meta.origin_spki), "Invalid fixture certificate receipt");
  assert(meta.proxy?.ready === true && meta.proxy.revision && meta.history === "none" && meta.mitmproxy === "12.3.1", "Unconfirmed fixture proxy");
  assert(hosts.siteOf(HOSTS[0]) !== hosts.siteOf(HOSTS[1]), "The two sites must be cross-site under the packaged PSL");
  return meta;
}

export function browserArguments(meta) {
  validateMetadata(meta);
  return [
    `--proxy-server=http://127.0.0.1:${meta.proxy_port}`, "--proxy-bypass-list=<-loopback>",
    `--ignore-certificate-errors-spki-list=${meta.origin_spki}`,
    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--disable-quic",
    "--disable-features=OptimizationHints,MediaRouter,Translate",
  ];
}

// CDP Network.getCertificate returns a base64 DER chain in `tableNames`.
// https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-getCertificate
// The first certificate must be the fixture leaf, not merely a trusted SPKI.
export function certificateReceipt(result, expectedSha256) {
  if (!Array.isArray(result?.tableNames) || !result.tableNames.length || result.tableNames.length > 8) return {status: "NOT COVERED"};
  try {
    const encoded = result.tableNames[0];
    assert(typeof encoded === "string" && encoded.length <= 32768 && /^[A-Za-z0-9+/]+={0,2}$/.test(encoded));
    const certificate = new crypto.X509Certificate(Buffer.from(encoded, "base64"));
    const observed = sha(certificate.raw);
    return {status: observed === expectedSha256 ? "PASS" : "FAIL", certificateSha256: observed};
  } catch { return {status: "NOT COVERED"}; }
}

export function staticCheck() {
  const fixture = fs.readFileSync(FIXTURE, "utf8"), worker = read("browser/background-chrome.js");
  for (const host of HOSTS) assert(fixture.includes(`"${host}"`));
  assert(new Set(HOSTS.map(hosts.siteOf)).size === HOSTS.length);
  for (const command of ["snapshot", "configure", "clear", "score", "close"]) assert(fixture.includes(`command == "${command}"`));
  for (const field of ["decrypted_origin_application_bytes", "proxy_route_observed", "handler_errors", "transport_disconnects", "distinct_identifier_bytes", "returnedHighEntropyKeys"]) assert(fixture.includes(field));
  for (const action of ["status", "apply", "release"]) assert(worker.includes(`browser-privacy-hardening-${action}`));
  assert(hardening.compile({enabled: true}).length === 2 && hardening.CAPABILITIES.behaviorVerified === false);
  return {schema: 1, mode: "source-contracts", nativeExecuted: false, qualification: "NOT COVERED",
    startedProcesses: 0, openedSockets: 0, fixtureSha256: sha(fixture), runnerSha256: sha(fs.readFileSync(fileURLToPath(import.meta.url))),
    cases: CHANNELS, subjects: 4, sites: HOSTS.slice(0, 2),
    scope: "Source contracts only. No Chrome, Python, proxy, collector or network listener was started."};
}

function inspectArtifact(folder) {
  const manifest = JSON.parse(fs.readFileSync(path.join(folder, "manifest.json"), "utf8"));
  const receipt = JSON.parse(fs.readFileSync(path.join(folder, "rules/build.json"), "utf8"));
  assert(manifest.manifest_version === 3 && manifest.key && manifest.background?.service_worker === "background.js", "Use a built Chrome artifact");
  assert(manifest.declarative_net_request?.rule_resources?.length > 0 && /^[a-f0-9]{32}$/.test(receipt.build), "Missing production build receipt/rules");
  assert(fs.readFileSync(path.join(folder, "core/privacy-hardening.js"), "utf8") === read("browser/core/privacy-hardening.js"), "Build must contain this Client Hints implementation");
  assert(fs.readFileSync(path.join(folder, "background.js"), "utf8").includes("browser-privacy-hardening-apply"), "Build lacks the Client Hints controller");
  const id = sha(Buffer.from(manifest.key, "base64")).slice(0, 32).replace(/[a-f0-9]/g, digit => String.fromCharCode(97 + parseInt(digit, 16)));
  return {id, build: receipt.build, version: manifest.version, coverageComplete: receipt.coverage?.complete === true,
    manifestSha256: sha(JSON.stringify(manifest)), buildReceiptSha256: sha(JSON.stringify(receipt))};
}

function startFixture(python) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => ["PATH", "LANG", "LC_ALL", "SYSTEMROOT"].includes(key)));
  env.PYTHONDONTWRITEBYTECODE = "1";
  env.PYTHONPATH = path.join(ROOT, "src");
  const child = spawn(python, ["-u", FIXTURE], {stdio: ["pipe", "pipe", "pipe"], detached: true, env});
  let buffer = "", next = 0, done = false, fatal = false, readyResolve, readyReject;
  const pending = new Map();
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const readyTimer = setTimeout(() => readyReject(new Error("Fixture startup timed out")), 30000);
  function fail() { fatal = true; readyReject(new Error("Fixture process or protocol failed")); for (const entry of pending.values()) entry.reject(new Error("Fixture RPC failed")); pending.clear(); }
  child.on("error", fail); child.stdin.on("error", fail); child.on("exit", () => { if (!done) fail(); });
  // Drain without retaining a raw traceback or local filesystem details.
  child.stderr.on("data", () => {});
  child.stdout.on("data", bytes => {
    buffer += bytes.toString("utf8");
    if (buffer.length > 8 * 1024 * 1024) { fail(); return; }
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      try {
        const message = JSON.parse(line);
        if (message.ready) { clearTimeout(readyTimer); readyResolve(validateMetadata(message.ready)); }
        else if (pending.has(message.id)) { const entry = pending.get(message.id); pending.delete(message.id); entry.resolve(message.result); }
        else fail();
      } catch { fail(); }
    }
  });
  const rpc = (command, fields = {}) => new Promise((resolve, reject) => {
    if (fatal) { reject(new Error("Fixture protocol is invalid")); return; }
    const id = ++next, message = JSON.stringify({id, command, ...fields}) + "\n";
    if (Buffer.byteLength(message) > 65536) { reject(new Error("Fixture RPC bound exceeded")); return; }
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("Fixture RPC timed out")); }, 20000);
    pending.set(id, {resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); }});
    child.stdin.write(message, error => { if (error) { pending.get(id)?.reject(new Error("Fixture pipe closed")); pending.delete(id); } });
  });
  function kill() { try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch {} } }
  async function close() {
    done = true; clearTimeout(readyTimer);
    try { await Promise.race([rpc("close"), sleep(2000)]); } catch {}
    child.stdin.end();
    if (child.exitCode === null) await Promise.race([new Promise(resolve => child.once("exit", resolve)), sleep(6000)]);
    if (child.exitCode === null) kill();
    for (const entry of pending.values()) entry.reject(new Error("Fixture closed")); pending.clear();
  }
  return {ready, rpc, close, kill, child};
}

// These functions execute only inside the disposable page. Return outcomes and
// property names, never UA values, arbitrary page text, cookies or storage.
async function pageProbe() {
  let returnedHighEntropyKeys = null;
  try { if (navigator.userAgentData?.getHighEntropyValues) {
    const values = await navigator.userAgentData.getHighEntropyValues(["architecture", "bitness", "formFactors", "fullVersionList", "model", "platformVersion", "uaFullVersion", "wow64"]);
    returnedHighEntropyKeys = Object.keys(values).filter(key => ["architecture", "bitness", "formFactors", "fullVersionList", "model", "platformVersion", "uaFullVersion", "wow64"].includes(key)).sort();
  } } catch {}
  return {gpcPresent: "globalPrivacyControl" in navigator, gpc: typeof navigator.globalPrivacyControl === "boolean" ? navigator.globalPrivacyControl : null, returnedHighEntropyKeys};
}

async function action({kind, url, identifier}) {
  if (kind === "image") return new Promise(resolve => {
    const image = new Image(), timer = setTimeout(() => { image.src = ""; resolve({completed: false, timeout: true}); }, 8000);
    image.onload = () => { clearTimeout(timer); resolve({completed: true, blocked: false}); };
    image.onerror = () => { clearTimeout(timer); resolve({completed: true, blocked: true}); }; image.src = url;
  });
  if (kind === "worker") return new Promise(resolve => {
    const worker = new Worker("/worker.js"), timer = setTimeout(() => { worker.terminate(); resolve({completed: false, timeout: true}); }, 8000);
    worker.onmessage = ({data}) => { clearTimeout(timer); worker.terminate(); resolve({completed: data.done === true, ...data}); };
    worker.onerror = () => { clearTimeout(timer); worker.terminate(); resolve({completed: false, unavailable: true}); }; worker.postMessage({url});
  });
  if (kind === "service-worker") {
    if (!navigator.serviceWorker) return {completed: false, unavailable: true};
    let registration;
    const task = (async () => {
      registration = await navigator.serviceWorker.register("/service-worker.js");
      await navigator.serviceWorker.ready;
      const channel = new MessageChannel();
      return new Promise(resolve => { channel.port1.onmessage = ({data}) => { channel.port1.close(); resolve({completed: data.done === true, ...data}); }; registration.active.postMessage({url}, [channel.port2]); });
    })().catch(() => ({completed: false, unavailable: true}));
    let timer; const result = await Promise.race([task, new Promise(resolve => { timer = setTimeout(() => resolve({completed: false, timeout: true}), 8000); })]);
    clearTimeout(timer); if (registration) await registration.unregister(); return result;
  }
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
  try {
    const post = ["opaque", "cart", "third-party"].includes(kind);
    const response = await fetch(url, {method: post ? "POST" : "GET", cache: "no-store", signal: controller.signal,
      ...(post ? {headers: {"Content-Type": "text/plain"}, body: JSON.stringify(kind === "cart" ? {item: "synthetic-control", quantity: 1} : {distinct_id: identifier, event: "synthetic"})} : {})});
    await response.arrayBuffer(); return {completed: true, blocked: false, ok: response.ok};
  } catch { return {completed: !controller.signal.aborted, blocked: true, timeout: controller.signal.aborted}; }
  finally { clearTimeout(timer); }
}

export function summarizeArm(snapshot, before, visits, outcomes) {
  assert(!snapshot.overflow && snapshot.handler_errors === 0, "Collector errors/overflow invalidate native evidence");
  assert(snapshot.decrypted_origin_application_bytes >= before.decrypted_origin_application_bytes, "Raw byte counters must be monotonic");
  const events = snapshot.events.filter(event => Object.hasOwn(visits, event.visit));
  assert(events.every(event => event.proxy_route_observed === true), "Every received event needs proxy-route correlation");
  assert(snapshot.connections.length >= before.connections.length, "Connection evidence must be append-only");
  // A later connection can reuse a closed TCP source port. The fixture's array
  // is monotonic; slicing its checkpoint avoids misclassifying that new route.
  const connections = snapshot.connections.slice(before.connections.length);
  assert(connections.filter(row => row.application_bytes > 0).every(row => row.proxy_route_observed === true), "Unrouted origin bytes invalidate qualification");
  const channels = {};
  for (const kind of CHANNELS) {
    const rows = events.filter(event => event.case === kind);
    channels[kind] = {receivedVisits: new Set(rows.map(row => row.visit)).size, events: rows.length,
      completedContexts: outcomes.filter(row => row.kind === kind && row.result.completed === true).length,
      bodyBytes: rows.reduce((sum, row) => sum + row.body_bytes, 0),
      distinctIdentifierBytesSummedAcrossEvents: rows.reduce((sum, row) => sum + row.distinct_identifier_bytes, 0),
      actionWindows: summarizeActionWindows(outcomes, kind)};
  }
  return {visits: Object.keys(visits).length, channels, rawApplicationBytesDelta: snapshot.decrypted_origin_application_bytes - before.decrypted_origin_application_bytes,
    trackerHostApplicationBytes: connections.filter(row => row.host === HOSTS[2]).reduce((sum, row) => sum + row.application_bytes, 0),
    connections: connections.length, connectionsClosed: connections.every(row => row.closed),
    transportDisconnectsDelta: snapshot.transport_disconnects - before.transport_disconnects,
    routeCorrelated: true, handlerErrors: snapshot.handler_errors, overflow: snapshot.overflow,
    gpc: {receivedHeaders: events.filter(row => row.gpc).length, receivedEvents: events.length},
    eventsForScoring: events.map(({visit, case: kind, identifiers}) => ({visit, case: kind, identifiers}))};
}

export function assessDelivery(baseline, protectedArm, n) {
  const checks = [], record = (name, status, detail) => checks.push({name, status, ...(detail ? {detail} : {})});
  const subjects = n / 2;
  // One visit per subject per site gives k true and k*(k-1) false pairs.
  // A shared token on every visit has TPR 1 but FPR 1: it is not identification.
  // Require the actual confusion counts, not rate labels or empty denominators.
  const identifiesCohort = (score, channel) => Number.isSafeInteger(subjects) && subjects >= 2 &&
    score?.channel === channel && score.subjects === subjects &&
    score.positive_pairs === subjects && score.negative_pairs === subjects * (subjects - 1) &&
    score.true_matches === subjects && score.false_matches === 0 &&
    score.true_match_rate === 1 && score.false_match_rate === 0 &&
    score.threshold === 1 && score.threshold_chosen_from_ground_truth === false;
  for (const channel of EXPECTED_BLOCKED) {
    const a = baseline.channels[channel], b = protectedArm.channels[channel];
    const baselineIdentifiable = identifiesCohort(baseline.scores[channel], channel);
    record(`collector:${channel}`, a.receivedVisits !== n || a.completedContexts !== n || b.completedContexts !== n || !baselineIdentifiable ? "NOT COVERED" : b.receivedVisits === 0 ? "PASS" : "FAIL",
      {baselineReceivedVisits: a.receivedVisits, protectedReceivedVisits: b.receivedVisits, expectedVisits: n, baselineIdentifiable,
        evidenceScope: ["third-party", "image"].includes(channel) ? "Completed collector events; separate isolated-host check measures all application bytes." : "No completed semantic collector event; partial bytes on the shared first-party connection are not attributed to this channel."});
  }
  const ga4Window = assessFirstPartyActionWindows(baseline.channels.ga4.actionWindows, protectedArm.channels.ga4.actionWindows, n);
  record("sampled first-party GA4 receiver-byte window", ga4Window.status, ga4Window.detail);
  record("functional POST controls", [baseline, protectedArm].every(arm => arm.channels.cart.events === 2 * n && arm.channels.cart.completedContexts === 2 * n) ? "PASS" : "FAIL");
  record("opaque first-party body residual remains measured", [baseline, protectedArm].every(arm =>
    arm.channels.opaque.receivedVisits === n && arm.channels.opaque.completedContexts === n &&
    identifiesCohort(arm.scores.opaque, "opaque") && identifiesCohort(arm.scores.all, "all")) ? "PASS" : "FAIL");
  record("collector and route evidence", [baseline, protectedArm].every(arm => arm.routeCorrelated && arm.connectionsClosed && arm.rawApplicationBytesDelta > 0) ? "PASS" : "NOT COVERED");
  record("tracker host received zero application bytes", baseline.trackerHostApplicationBytes > 0 && protectedArm.trackerHostApplicationBytes === 0 && protectedArm.connectionsClosed ? "PASS" : "FAIL",
    {baselineBytes: baseline.trackerHostApplicationBytes, protectedBytes: protectedArm.trackerHostApplicationBytes});
  return checks;
}

export async function runNative(options) {
  const checks = [], arms = {}, record = (name, status, detail) => checks.push({name, status, ...(detail ? {detail} : {})});
  let stage = "prerequisites", fixture, browser, work, expired = false, nativeExecuted = false, output;
  const report = {schema: 1, mode: "native-collector", nativeAttempted: false, nativeExecuted: false, qualification: "NOT COVERED", checks, arms,
    scope: "Synthetic exact-identifier channels in disposable profiles; combined proxy+extension protection, not a population anonymity estimate.",
    observation: "Every attempted action has a bounded completion deadline; positive controls bracket each visit. Final collector snapshots follow browser closure. Timeouts receive no blocking credit.",
    notCovered: ["HTML ping auditing (--no-pings helper baseline)", "public IP/VPN/Tor or WebRTC routing", "arbitrary trackers, SDKs, encrypted/encoded bodies", "late arrivals and positive shared-origin byte deltas remain unattributed despite action-window samples", "worker/service-worker first-party partial bytes share functional script-loading origins", "worker JavaScript Client Hints restriction guarantee", "WSS live revocation", "optional Chrome privacy-permission handoff and ChromeSetting precedence"]};
  try {
    for (const key of ["chrome", "python"]) { fs.accessSync(options[key], fs.constants.X_OK); assert(fs.statSync(options[key]).isFile(), "Executable must be a file"); }
    output = fs.openSync(options.out, "wx", 0o600);
    const artifact = inspectArtifact(options.extension); report.artifact = artifact;
    work = fs.mkdtempSync(path.join(os.tmpdir(), "egress-guard-collector-browser-"));
    fixture = startFixture(options.python); const meta = await fixture.ready;
    report.fixture = {certificateSha256: meta.origin_certificate_sha256, proxy: meta.proxy, mitmproxy: meta.mitmproxy,
      hosts: meta.hosts, history: meta.history, sourceSha256: sha(fs.readFileSync(FIXTURE)), scope: meta.scope};
    const deadline = setTimeout(() => { expired = true; try { process.kill(-browser?.child.pid, "SIGKILL"); } catch {} fixture.kill(); }, options.timeout);
    const checkDeadline = () => assert(!expired, "Overall native deadline exceeded");
    try {
      for (const arm of ["baseline", "protected"]) {
        stage = `${arm}-startup`; checkDeadline();
        const proxy = await fixture.rpc("configure", {paused: arm === "baseline", denied: null});
        assert(proxy.ready); await fixture.rpc("clear"); const before = await fixture.rpc("snapshot");
        const profile = path.join(work, arm); fs.mkdirSync(profile, {mode: 0o700});
        report.nativeAttempted = true;
        browser = launch({bin: options.chrome, profile, timeout: 15000, args: browserArguments(meta)});
        browser.child.once("spawn", () => { nativeExecuted = true; report.nativeExecuted = true; });
        let processError = false; browser.child.on("error", () => { processError = true; });
        const {cdp, evaluate} = browser;
        const version = await cdp("Browser.getVersion"); nativeExecuted = true; report.nativeExecuted = true;
        assert(!processError && Number((version.product.match(/\/(\d+)/) || [])[1]) >= 145, "Chrome 145+ required");
        const responsePolicies = new Map(), certificates = [];
        browser.on("Network.responseReceived", (event, session) => {
          if (event.type !== "Document") return;
          const value = Object.entries(event.response.headers).find(([key]) => key.toLowerCase() === "permissions-policy")?.[1];
          responsePolicies.set(session, {url: event.response.url, policy: value ?? null});
        });
        async function open(url) {
          checkDeadline(); const {targetId} = await cdp("Target.createTarget", {url: "about:blank"});
          const {sessionId} = await cdp("Target.attachToTarget", {targetId, flatten: true});
          await cdp("Page.enable", {}, sessionId); await cdp("Runtime.enable", {}, sessionId); await cdp("Network.enable", {}, sessionId);
          const result = await cdp("Page.navigate", {url}, sessionId); assert(!result.errorText, "Fixture navigation failed");
          assert(await waitFor(() => evaluate(sessionId, `location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`), 12000), "Fixture document did not load");
          if (url.startsWith("https://")) {
            let chain;
            try { chain = await cdp("Network.getCertificate", {origin: new URL(url).origin}, sessionId); } catch {}
            certificates.push({host: new URL(url).hostname, ...certificateReceipt(chain, meta.origin_certificate_sha256)});
          }
          return {targetId, sessionId};
        }
        const closePage = page => cdp("Target.closeTarget", {targetId: page.targetId});
        let privacy, send;
        if (arm === "protected") {
          const loaded = await cdp("Extensions.loadUnpacked", {path: options.extension}); assert.equal(loaded.id, artifact.id);
          const worker = await attachWorker(cdp, loaded.id, {tries: 50}); assert(worker, "Extension worker missing");
          await evaluate(worker.sessionId, "__EGBackground.ready.then(() => true)");
          privacy = await open(`chrome-extension://${loaded.id}/privacy.html`);
          send = message => evaluate(privacy.sessionId, `chrome.runtime.sendMessage(${JSON.stringify(message)})`);
          const off = await send({type: "browser-privacy-hardening-status"});
          assert(off.enabled === false && off.installed === false && off.rulesConfirmed === true, "Fresh profile must start with hardening off");
          report.hardeningDefault = off;
        }
        const {visits, rows} = makeVisits(arm, options.subjects), outcomes = [], probes = [];
        const origin = host => `https://${host}:${meta.origin_port}`;
        for (const row of rows) {
          stage = `${arm}-cohort`; checkDeadline();
          const page = await open(`${origin(row.site)}/page?policy=absent`);
          probes.push({site: row.site, ...await evaluate(page.sessionId, `(${pageProbe.toString()})()`)});
          for (const kind of ["cart", ...CHANNELS.filter(value => value !== "cart"), "cart"]) {
            checkDeadline(); const targetHost = ["third-party", "image"].includes(kind) ? HOSTS[2] : row.site;
            const url = new URL(`${origin(targetHost)}/${kind === "image" ? "pixel.gif" : ["ga4", "worker", "service-worker"].includes(kind) ? "measure" : "api/fixture"}`);
            url.search = new URLSearchParams({visit: row.visit, case: kind, ...(["ga4", "worker", "service-worker"].includes(kind) ? {v: "2", tid: "G-LAB12345", cid: row.identifier} : kind === "image" ? {id: row.identifier} : {})});
            const beforeAction = await fixture.rpc("snapshot");
            const result = await evaluate(page.sessionId, `(${action.toString()})(${JSON.stringify({kind, url: url.href, identifier: row.identifier})})`);
            const afterAction = await fixture.rpc("snapshot");
            const byteWindow = measureActionWindow(beforeAction, afterAction, targetHost);
            outcomes.push({visit: row.visit, kind, result, byteWindow});
          }
          await closePage(page);
        }
        // Header/policy phases use distinct visits outside the scoring cohort.
        async function policyProbe(policy, label) {
          const visit = sha(`egress-guard-policy:${arm}:${label}`).slice(0, 24), url = `${origin(HOSTS[0])}/page?policy=${policy}`;
          const page = await open(url), probe = await evaluate(page.sessionId, `(${pageProbe.toString()})()`);
          const received = responsePolicies.get(page.sessionId); assert(received?.url === url, "Document response headers were not observed");
          const start = (await fixture.rpc("snapshot")).events.length;
          const result = await evaluate(page.sessionId, `(${action.toString()})(${JSON.stringify({kind: "headers", url: `${origin(HOSTS[0])}/headers?visit=${visit}&case=headers`})})`);
          assert(result.completed && !result.blocked, "Functional header probe failed");
          await closePage(page); const events = (await fixture.rpc("snapshot")).events.slice(start).filter(event => event.visit === visit && event.case === "headers");
          assert(events.length === 1 && events[0].proxy_route_observed, "Header probe requires one routed collector event");
          return {policy: received.policy, ...probe, highEntropyRequestHeaders: events[0].high_entropy_headers, headerGpc: events[0].gpc};
        }
        const headerPhases = {off: await policyProbe("absent", "off")};
        if (arm === "protected") {
          stage = "client-hints-apply";
          const applied = await send({type: "browser-privacy-hardening-apply", enabled: true});
          assert(applied.enabled && applied.installed && applied.rulesConfirmed && applied.verifiedRuleCount === 2 && applied.behaviorVerified === false, "Native installed-rule receipt missing");
          report.hardeningApplied = applied;
          for (const policy of ["absent", "existing", "malformed"]) headerPhases[policy] = await policyProbe(policy, `on-${policy}`);
          const released = await send({type: "browser-privacy-hardening-release"});
          assert(!released.enabled && !released.installed && released.rulesConfirmed && released.observedRuleCount === 0, "Rule release not confirmed");
          report.hardeningReleased = released; headerPhases.released = await policyProbe("absent", "released");
          await closePage(privacy);
        }
        await browser.close(); browser = null;
        // This bounded closure wait is reported, never a substitute for positive
        // controls or successful baseline delivery of every expected-blocked case.
        await waitFor(async () => (await fixture.rpc("snapshot")).connections.every(row => row.closed), 4000, 100);
        const snapshot = await fixture.rpc("snapshot"), summary = summarizeArm(snapshot, before, visits, outcomes);
        const scoringEvents = summary.eventsForScoring; delete summary.eventsForScoring;
        const scores = {};
        for (const channel of [null, ...CHANNELS.filter(value => value !== "cart")]) scores[channel || "all"] = await fixture.rpc("score", {events: scoringEvents, visits, ...(channel ? {case: channel} : {})});
        record(`${arm}: native leaf certificate matches collector DER`, certificates.some(row => row.status === "FAIL") ? "FAIL" : certificates.length && certificates.every(row => row.status === "PASS") ? "PASS" : "NOT COVERED");
        arms[arm] = {browser: version.product, proxy, ...summary, outcomes, windowProbes: probes, headerPhases, scores, certificates};
      }
      stage = "assessment";
      const baseline = arms.baseline, protectedArm = arms.protected, n = options.subjects * 2;
      checks.push(...assessDelivery(baseline, protectedArm, n));
      const phases = protectedArm.headerPhases;
      record("Permissions-Policy absent-only insertion and existing/malformed preservation", phases.absent.policy === hardening.POLICY && phases.existing.policy === EXISTING_POLICY && phases.malformed.policy === "camera=(" && phases.off.policy === null && phases.released.policy === null ? "PASS" : "FAIL");
      const emitted = phases.off.highEntropyRequestHeaders;
      record("high-entropy request header suppression", emitted.length === 0 ? "NOT COVERED" : ["absent", "existing", "malformed"].every(key => phases[key].highEntropyRequestHeaders.length === 0) ? "PASS" : "FAIL",
        {baselineEmittedNames: emitted, releasedNames: phases.released.highEntropyRequestHeaders});
      const keys = phases.off.returnedHighEntropyKeys;
      record("absent-policy document high-entropy API restriction", !keys?.length ? "NOT COVERED" : phases.absent.returnedHighEntropyKeys?.length === 0 ? "PASS" : "FAIL");
      record("Client Hints release restores exposed baseline surfaces", !emitted.length || !keys?.length ? "NOT COVERED" : emitted.every(name => phases.released.highEntropyRequestHeaders.includes(name)) && keys.every(key => phases.released.returnedHighEntropyKeys?.includes(key)) ? "PASS" : "FAIL");
      report.gpc = {interpretation: "Observed only: native/previous values are preserved; window, worker and HTTP signals need not agree. No worker shim or native-conformance claim.",
        baselineWindow: baseline.windowProbes, protectedWindow: protectedArm.windowProbes,
        workerObservations: protectedArm.outcomes.filter(row => ["worker", "service-worker"].includes(row.kind)).map(({kind, result}) => ({kind, gpcPresent: result.gpcPresent ?? null, gpc: result.gpc ?? null, returnedHighEntropyKeys: result.returnedHighEntropyKeys ?? null})),
        baselineHeaders: baseline.gpc, protectedHeaders: protectedArm.gpc};
      report.qualification = checks.some(check => check.status === "FAIL") ? "FAIL" : checks.some(check => check.status === "NOT COVERED") ? "INCOMPLETE" : "PASS";
    } finally { clearTimeout(deadline); }
  } catch {
    report.qualification = "FAIL"; report.failure = {stage, detail: "The controlled run stopped before qualification. Check local Chrome/Python/artifact prerequisites; raw process output is not retained."};
  } finally {
    if (browser) await browser.close().catch(() => {});
    if (fixture) await fixture.close().catch(() => fixture.kill());
    if (work) fs.rmSync(work, {recursive: true, force: true});
    report.nativeExecuted = nativeExecuted;
    if (output !== undefined) { fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n"); fs.closeSync(output); }
  }
  return report;
}

export async function main(args, native = runNative) {
  const options = parseOptions(args);
  // Keep this branch before artifact/executable checks, temp paths and processes.
  if (options.check) return staticCheck();
  return native(options);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(report => {
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.qualification === "FAIL" ? 1 : report.qualification === "INCOMPLETE" ? 2 : 0;
  }).catch(() => { console.error("Invalid runner arguments. Use --check, or explicit absolute --chrome, --python, --extension and new --out paths."); process.exitCode = 1; });
}
