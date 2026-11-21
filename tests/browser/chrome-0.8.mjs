// Focused, opt-in Chrome 145+ qualification for the 0.8 boundary changes.
// Authored without native execution in the restricted implementation environment.
//
// Static contracts only; NEVER launches Chrome or opens a listening socket:
//   node tests/browser/chrome-0.8.mjs --check
// Disposable headless profile, synthetic loopback pages and native DNR evaluator:
//   node tests/browser/chrome-0.8.mjs --chrome /path/to/chrome
// Also exercise the real optional-permission UI in a VISIBLE disposable window:
//   node tests/browser/chrome-0.8.mjs --chrome /path/to/chrome --privacy
// Approve Chrome's privacy-permission prompt within 60 seconds when instructed.
// A denial, unavailable control or incomplete permission handoff is reported as
// INCOMPLETE (exit 2), never as a passed privacy qualification. No existing user
// profile is accepted. All fixture names resolve to loopback; other DNS names fail.
//
// Scope: native CSS matching/revalidation; native testMatchOutcome origin policy;
// real ChromeSetting get/set/clear/permission/release readback. DNR hypothetical
// outcomes do not prove cold-navigation timing, wire headers, prerender/BFCache,
// service-worker/cache behavior or POST reload safety. The shared driver's quiet
// flags include --no-pings: this runner makes NO ping, public-IP or route claims.
// Permission denial, competing extension/enterprise precedence, incognito and
// browser restart remain separate manual qualification cases.
// API contracts: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#type-TestMatchRequestDetails
// https://developer.chrome.com/docs/extensions/reference/api/permissions#method-request
// https://developer.chrome.com/docs/extensions/reference/api/types#type-ChromeSetting
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import {fileURLToPath} from "node:url";
import {build, loadLists} from "../../scripts/build-browser.mjs";
import {launch, attachWorker, waitFor, DEFAULT_CHROME} from "./cdp.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const options = {check: false, privacy: false, chrome: DEFAULT_CHROME};
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--check") options.check = true;
  else if (argv[i] === "--privacy") options.privacy = true;
  else if (argv[i] === "--chrome" && argv[i + 1] && !argv[i + 1].startsWith("--")) options.chrome = argv[++i];
  else throw new Error(`Unknown or incomplete option: ${argv[i]}`);
}
assert(!(options.check && options.privacy), "--check does not execute the native --privacy qualification");

const COSMETICS = `[Adblock Plus 2.0]
! Synthetic 0.8 qualification rules, not a production filter snapshot.
##.fixture-generic
###fixture-id-ad
##.fixture-exempt
publisher.example#@#.fixture-exempt
publisher.example##.fixture-site
publisher.example##.fixture-rel:has(> .fixture-paid[data-paid="yes"])
egfixture.*##.fixture-entity
github.*##.fixture-hosting-entity
@@/exception^$generichide,domain=publisher.example
`;
const filter = (id, text) => ({text, source: {id, name: `${id} (0.8 fixture)`, url: "fixture", license: {name: "fixture", url: "fixture"}, sha256: "-", fetched_at: Math.floor(Date.now() / 1000)}});
const HOSTS = ["publisher.example", "www.egfixture.co.uk", "egfixture.evil.test", "tenant.github.io", "cold.example", "foreign-frame.example", "amazonaws.com", "tenant.s3.amazonaws.com"];
const HTML = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Egress Guard 0.8 local fixture</title>
<body><h1>Local qualification fixture</h1>
<div id="generic" class="fixture-generic" style="display:grid!important">Synthetic placement A</div>
<div id="fixture-id-ad">Synthetic placement B</div>
<div id="scoped" class="fixture-site">Synthetic placement C</div>
<section id="relational" class="fixture-rel"><span id="paid" class="fixture-paid" data-paid="no">Synthetic marker</span><a href="/story">Ordinary story</a></section>
<div id="entity" class="fixture-entity">Synthetic entity placement</div>
<div id="hosting" class="fixture-hosting-entity">Independent tenant content</div>
<div id="exempt" class="fixture-exempt">Compatibility exemption</div>
<form><div id="protected" class="fixture-generic">Required field instructions</div><input aria-label="Fixture field"></form>
<article id="organic">Ordinary editorial content</article></body></html>`;

const work = fs.mkdtempSync(path.join(os.tmpdir(), "egress-guard-chrome-08-"));
let browser, server, nativeExecuted = false, incomplete = false;
const results = [];
function pass(name, detail = undefined) {
  results.push({name, status: "passed", ...(detail === undefined ? {} : {detail})});
  console.log(`${options.check ? "CONTRACT" : "PASS"} ${name}`);
}
function unqualified(name, detail) {
  incomplete = true; results.push({name, status: "incomplete", detail});
  console.log(`INCOMPLETE ${name}: ${detail}`);
}
try {
  const built = build({out: path.join(work, "dist"),
    lists: loadLists(path.join(here, "fixtures/feeds"), {allowSmall: true, allowMissing: true}),
    filters: {easylist: filter("easylist", COSMETICS), easyprivacy: filter("easyprivacy", "||fixture-tracker.test^$script\n")},
    requireComplete: false});
  const ext = path.join(work, "dist/chrome");
  const manifest = JSON.parse(fs.readFileSync(path.join(ext, "manifest.json"), "utf8"));
  const context = vm.createContext({});
  vm.runInContext(fs.readFileSync(path.join(ext, "core/cosmetic-data.js"), "utf8"), context, {timeout: 1000});
  const data = JSON.parse(JSON.stringify(context.EGCosmeticData));
  assert.equal(data.genericRules.length, 3);
  assert.equal(data.rules.length, 4);
  assert.equal(data.exceptions.length, 1);
  assert.equal(data.hideExceptions.length, 1);
  assert(data.rules.some(rule => rule.selector.includes(":has(")));
  assert(data.rules.some(rule => rule.include.includes("egfixture.*")));
  assert(!data.fallback.generic && !data.fallback.scoped && data.fallback.selectors.length === 0);
  assert.equal(built.coverage.complete, false, "this is explicitly a reduced fixture build");
  const content = manifest.content_scripts.find(entry => entry.js.includes("content.js")).js;
  for (const pair of [["core/psl-data.js", "core/hosts.js"], ["core/hosts.js", "core/cosmetic.js"], ["core/cosmetic-data.js", "core/cosmetic.js"], ["core/cosmetic-selectors.js", "core/cosmetic.js"], ["core/cosmetic.js", "content.js"]]) {
    assert(content.includes(pair[0]) && content.indexOf(pair[0]) < content.indexOf(pair[1]), pair.join(" precedes "));
  }
  assert(manifest.optional_permissions.includes("privacy"));
  assert(!manifest.permissions.includes("privacy"));
  for (const file of ["privacy.html", "privacy.js", "core/browser-privacy.js"]) assert(fs.existsSync(path.join(ext, file)));
  pass("fixture build contains the intended cosmetic rules, exceptions, dependency order and optional permission");

  if (options.check) {
    console.log(JSON.stringify({mode: "static-contracts", nativeExecuted: false, results, note: "No browser process or HTTP listener was started. Native qualification remains unexecuted."}, null, 2));
  } else {
    // No listener or launch is reachable in --check mode.
    assert(fs.existsSync(options.chrome), "Set --chrome to an installed Chrome 145+ executable");
    server = http.createServer((req, res) => {
      const host = (req.headers.host || "").replace(/:\d+$/, "");
      if (!HOSTS.includes(host)) { res.writeHead(421); res.end(); return; }
      res.writeHead(200, {"content-type": "text/html; charset=utf-8", "cache-control": "no-store"}); res.end(HTML);
    });
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const port = server.address().port;
    const url = (host, route = "/fixture") => `http://${host}:${port}${route}`;
    const profile = path.join(work, "profile"); fs.mkdirSync(profile);
    browser = launch({bin: options.chrome, profile, headless: !options.privacy, timeout: 30000, args: [
      "--no-proxy-server", "--window-size=1280,900",
      "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,OptimizationHints,MediaRouter,Translate",
      `--host-resolver-rules=${HOSTS.map(host => `MAP ${host} 127.0.0.1`).join(", ")}, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`,
    ]});
    const {cdp, evaluate} = browser;
    const version = await cdp("Browser.getVersion"); nativeExecuted = true;
    const major = Number((version.product.match(/\/(\d+)/) || [])[1]);
    assert(major >= 145, `Chrome 145+ required; got ${version.product}`);
    console.log(`Native browser: ${version.product}`);
    const loaded = await cdp("Extensions.loadUnpacked", {path: ext});
    assert.equal(loaded.id, built.extensionId);
    const own = `chrome-extension://${loaded.id}/`;
    const worker = await attachWorker(cdp, loaded.id);
    assert(worker, "extension service worker appeared");
    assert(await waitFor(() => evaluate(worker.sessionId, "typeof __EGBackground === 'object'")), "worker initialized");
    await evaluate(worker.sessionId, "__EGBackground.ready.then(() => true)");

    async function openPage(address) {
      const {targetId} = await cdp("Target.createTarget", {url: "about:blank"});
      const {sessionId} = await cdp("Target.attachToTarget", {targetId, flatten: true});
      await cdp("Page.enable", {}, sessionId); await cdp("Runtime.enable", {}, sessionId);
      const page = {targetId, sessionId}; await navigate(page, address); return page;
    }
    async function navigate(page, address) {
      const result = await cdp("Page.navigate", {url: address}, page.sessionId);
      assert(!result.errorText, result.errorText || "navigation accepted");
      assert(await waitFor(() => evaluate(page.sessionId, `location.href === ${JSON.stringify(address)} && document.readyState === 'complete'`)), `loaded ${address}`);
    }
    async function eventually(page, expression, name) {
      assert(await waitFor(() => evaluate(page.sessionId, expression)), `${name}: timed out`); pass(name);
    }
    async function click(page, selector) {
      await cdp("Page.bringToFront", {}, page.sessionId);
      const point = await evaluate(page.sessionId, `(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (!e || e.disabled) throw new Error('Control unavailable'); e.scrollIntoView({block:'center'}); const r = e.getBoundingClientRect(); return {x:r.left+r.width/2,y:r.top+r.height/2}; })()`);
      for (const type of ["mousePressed", "mouseReleased"]) await cdp("Input.dispatchMouseEvent", {type, ...point, button: "left", clickCount: 1}, page.sessionId);
    }
    const display = id => `getComputedStyle(document.getElementById(${JSON.stringify(id)})).display`;
    const hidden = id => `${display(id)} === 'none'`;
    const shown = id => `${display(id)} !== 'none'`;
    const page = await openPage(url("publisher.example"));
    // The actual popup document supplies runtime sender identity. No fake sender
    // object, direct controller call or manifest permission escalation is used.
    const control = await openPage(own + "popup.html");
    const api = expression => evaluate(control.sessionId, expression);
    const send = message => api(`chrome.runtime.sendMessage(${JSON.stringify(message)})`);
    const tabFor = address => api(`chrome.tabs.query({}).then(tabs => tabs.find(tab => tab.url === ${JSON.stringify(address)})?.id)`);
    const tabId = await tabFor(url("publisher.example")); assert(Number.isInteger(tabId));
    const contentSend = message => api(`chrome.tabs.sendMessage(${tabId}, ${JSON.stringify(message)}, {frameId:0})`);
    await eventually(page, [hidden("generic"), hidden("fixture-id-ad"), hidden("scoped"), shown("exempt"), shown("protected"), shown("organic"), shown("relational")].join(" && "), "native generic/id/scoped hides preserve exact exceptions, forms and ordinary content");
    await evaluate(page.sessionId, "document.getElementById('generic').className = 'ordinary'; true");
    await eventually(page, `${display("generic")} === 'grid'`, "removing a generic token restores the original important inline display");
    await evaluate(page.sessionId, "document.getElementById('generic').className = 'fixture-generic'; true");
    await eventually(page, hidden("generic"), "reusing an existing node re-enables its matching generic rule");
    await evaluate(page.sessionId, "document.getElementById('paid').dataset.paid = 'yes'; true");
    await eventually(page, hidden("relational"), "native :has reacts to a descendant attribute change");
    await evaluate(page.sessionId, "const input = document.createElement('input'); input.id = 'new-essential'; input.setAttribute('aria-label','Necessary input'); document.getElementById('relational').append(input); true");
    await eventually(page, shown("relational"), "a newly protected descendant restores an already hidden relational target");
    await evaluate(page.sessionId, "document.getElementById('new-essential').remove(); true");
    await eventually(page, hidden("relational"), "removing the protected descendant revalidates the still-matching relation");
    await evaluate(page.sessionId, "document.getElementById('paid').dataset.paid = 'no'; true");
    await eventually(page, shown("relational"), "ending the relation restores its target");
    await evaluate(page.sessionId, "history.pushState(null,'','/exception'); true");
    // Deliberately no DOM change and no manual page-location message: Chrome's
    // actual URL-update path must deliver the compatibility-policy refresh.
    await eventually(page, `${shown("generic")} && ${shown("fixture-id-ad")} && ${hidden("scoped")}`, "same-document URL exemption refresh releases generic hides only");
    const exempt = await contentSend({type: "status"});
    assert(exempt.imported.sourceExemptions.includes("generic"));
    await evaluate(page.sessionId, "history.pushState(null,'','/fixture'); true");
    await eventually(page, `${hidden("generic")} && ${hidden("fixture-id-ad")}`, "leaving the exempt route restores imported generic protection");
    await contentSend({type: "restore-page"});
    await eventually(page, `${shown("generic")} && ${shown("fixture-id-ad")} && ${shown("scoped")}`, "Restore releases imported page hides");
    await contentSend({type: "resume"});
    await eventually(page, `${hidden("generic")} && ${hidden("fixture-id-ad")} && ${hidden("scoped")}`, "Resume applies matching imported hides again");

    const entity = await openPage(url("www.egfixture.co.uk"));
    await eventually(entity, `${hidden("generic")} && ${hidden("entity")}`, "entity scope matches the registrant before the complete co.uk suffix");
    await navigate(entity, url("egfixture.evil.test"));
    await eventually(entity, `${hidden("generic")} && ${shown("entity")}`, "an entity-like subdomain under a different registrant does not match");
    await navigate(entity, url("tenant.github.io"));
    await eventually(entity, `${hidden("generic")} && ${shown("hosting")}`, "a private PSL hosting suffix is not mistaken for the tenant's entity");

    const strict = await send({type: "set-default-mode", mode: "strict"}); assert.equal(strict.ok, true, JSON.stringify(strict));
    const state = address => send({type: "popup-state", tabId, tabUrl: address});
    const cold = url("cold.example"), foreign = url("foreign-frame.example");
    const coldState = await state(cold);
    assert.equal(coldState.preparation.state, "held"); assert.equal(coldState.policy.state, "applied");
    const statics = new Map();
    for (const set of manifest.declarative_net_request.rule_resources) for (const rule of JSON.parse(fs.readFileSync(path.join(ext, set.path), "utf8"))) statics.set(`${set.id}:${rule.id}`, rule);
    async function match(request) {
      const receipt = await api(`(async () => { const d = chrome.declarativeNetRequest; return {outcome:await d.testMatchOutcome(${JSON.stringify(request)}),dynamic:await d.getDynamicRules(),session:await d.getSessionRules()}; })()`);
      const rules = new Map(statics);
      for (const [kind, entries] of [["_dynamic", receipt.dynamic], ["_session", receipt.session]]) for (const rule of entries) rules.set(`${kind}:${rule.id}`, rule);
      return receipt.outcome.matchedRules.map(item => {
        const rule = rules.get(`${item.rulesetId}:${item.ruleId}`); assert(rule, "native matched rule belongs to the current package or live rule set");
        return {set: item.rulesetId, ...rule};
      });
    }
    const modeBlock = matches => matches.some(rule => rule.set === "_dynamic" && rule.action.type === "block");
    for (const [name, request] of [
      ["cold first-party script", {url: url("cold.example", "/static/site.js"), initiator: cold, topUrl: cold, type: "script"}],
      ["cold foreign-frame same-origin script", {url: url("foreign-frame.example", "/static/site.js"), initiator: foreign, topUrl: cold, type: "script"}],
      ["cold no-associated-top-frame fallback", {url: url("cold.example", "/static/site.js"), initiator: cold, type: "script"}],
    ]) { assert(modeBlock(await match(request)), name); pass(`native DNR evaluator holds ${name}`); }
    await navigate(entity, cold);
    assert(await waitFor(async () => (await state(cold)).preparation.state === "prepared"), "actual open cold site becomes prepared");
    assert(!modeBlock(await match({url: url("cold.example", "/static/site.js"), initiator: cold, topUrl: cold, type: "script"})));
    assert(modeBlock(await match({url: url("foreign-frame.example", "/static/site.js"), initiator: foreign, topUrl: cold, type: "script"})));
    pass("native prepared policy releases its own script while retaining the cross-top-site frame block");
    await navigate(entity, url("amazonaws.com"));
    assert(await waitFor(async () => (await state(url("amazonaws.com"))).preparation.state === "prepared"));
    const tenant = url("tenant.s3.amazonaws.com");
    assert.equal((await state(tenant)).preparation.state, "held");
    assert(modeBlock(await match({url: url("tenant.s3.amazonaws.com", "/static/site.js"), initiator: tenant, topUrl: tenant, type: "script"})));
    pass("native DNR evaluator holds an unseen private tenant below a prepared parent");
    const reset = await send({type: "set-default-mode", mode: "standard"}); assert.equal(reset.ok, true);

    if (options.privacy) {
      const privacy = await openPage(own + "privacy.html");
      assert(await waitFor(() => evaluate(privacy.sessionId, "!!globalThis.__EGPrivacyUI?.state")));
      await evaluate(privacy.sessionId, "__EGPrivacyUI.ready.then(() => true)");
      const initial = await evaluate(privacy.sessionId, "__EGPrivacyUI.state");
      assert.equal(initial.permission, false, "optional permission is absent in a fresh disposable profile");
      assert.equal(initial.saved, false);
      pass("real privacy page starts without optional permission or saved authority");
      async function choose(ids) {
        await evaluate(privacy.sessionId, `(() => { const ids = new Set(${JSON.stringify(ids)}); for (const box of document.querySelectorAll('#settings input[type=checkbox]')) { box.checked = ids.has(box.id.slice('control-'.length)); box.dispatchEvent(new Event('change',{bubbles:true})); } return true; })()`);
      }
      await choose([]); // First grant with no selected overrides so baseline is genuine.
      console.log("ACTION: In the visible disposable Chrome window, approve the optional privacy permission. No controls are selected for this first Apply. The runner waits up to 60 seconds.");
      await click(privacy, "#apply");
      const granted = await waitFor(() => evaluate(privacy.sessionId, "__EGPrivacyUI.state.permission && __EGPrivacyUI.state.saved && !document.getElementById('apply').disabled"), 60000, 250);
      if (!granted) unqualified("privacy permission handoff", "Permission was denied, not approved in time, or the UI failed. Re-run --privacy and inspect the native prompt/page error. Setting tests did not pass.");
      else {
        const wanted = ["prediction", "webrtc", "auditing"];
        const baseline = await evaluate(privacy.sessionId, `Promise.all(EGBrowserPrivacy.CATALOG.filter(spec=>${JSON.stringify(wanted)}.includes(spec.id)).map(async spec=>{ const setting=chrome.privacy?.[spec.path[0]]?.[spec.path[1]]; return {id:spec.id,target:spec.value,...(setting ? await setting.get({incognito:false}) : {unavailable:true})}; }))`);
        const usable = baseline.filter(row => !row.unavailable && row.levelOfControl === "controllable_by_this_extension");
        for (const row of baseline) if (!usable.includes(row)) unqualified(`native setting ${row.id}`, `Not controllable in this browser: ${row.levelOfControl || "unavailable"}. No ownership success is inferred.`);
        if (usable.length) {
          const selected = usable.map(row => row.id).sort();
          await choose(selected); await click(privacy, "#apply");
          assert(await waitFor(() => evaluate(privacy.sessionId, `!document.getElementById('apply').disabled && JSON.stringify(__EGPrivacyUI.state.selected)===${JSON.stringify(JSON.stringify(selected))}`)), "selected controls completed Apply");
          const applied = await evaluate(privacy.sessionId, "__EGPrivacyUI.state");
          for (const before of usable) {
            const row = applied.rows.find(item => item.id === before.id);
            assert(row && row.effective && row.owned && row.value === before.target && row.state === "applied", JSON.stringify(row));
          }
          pass("real optional-permission Apply verifies selected ChromeSetting targets and ownership", selected);
          await click(privacy, "#release");
          assert(await waitFor(() => evaluate(privacy.sessionId, "!document.getElementById('release').disabled && __EGPrivacyUI.state.selected.length===0 && __EGPrivacyUI.state.state==='inactive'")), "Release completed");
          const released = await evaluate(privacy.sessionId, "__EGPrivacyUI.state");
          for (const before of usable) {
            const row = released.rows.find(item => item.id === before.id);
            assert(row && !row.owned && row.state === "released" && row.value === before.value, JSON.stringify({before, row}));
          }
          pass("Release removes only this extension's overrides and exposes the original disposable-profile values");
        }
        assert.equal(await evaluate(privacy.sessionId, "chrome.permissions.remove({permissions:['privacy']})"), true);
        await evaluate(privacy.sessionId, "__EGPrivacyUI.refresh().then(() => true)");
        const removed = await evaluate(privacy.sessionId, "__EGPrivacyUI.state");
        assert.equal(removed.permission, false);
        assert(removed.rows.every(row => row.state === "permission-required" && row.value === null));
        pass("revoking the optional permission withdraws value and ownership attestations");
      }
    } else results.push({name: "privacy settings and native permission UI", status: "not-requested", detail: "Run again with --privacy for a visible disposable permission handoff."});
    console.log(JSON.stringify({mode: "native-fixture", nativeExecuted, browser: version.product, status: incomplete ? "incomplete" : "passed-for-requested-scope", results,
      limitations: ["DNR origin cases use Chrome's hypothetical evaluator, not navigation wire/timing proof.", "ChromeSetting readback does not qualify network behavior, IP concealment or ping causality.", "The filter bundle is synthetic and deliberately reduced."]}, null, 2));
    if (incomplete) process.exitCode = 2;
  }
} catch (error) {
  console.error(`FAIL ${error.stack || error}`);
  if (browser) console.error(browser.stderr().slice(-6000));
  console.error(JSON.stringify({nativeExecuted, status: "failed", results}, null, 2));
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  if (server && server.listening) await new Promise(resolve => server.close(resolve));
  fs.rmSync(work, {recursive: true, force: true});
}
