"use strict";
// The extension's UI against the design system (docs/design/DESIGN.md, docs/design/tokens.css): one token source,
// no off-token colours, sizes or spacing, contrast per section 4, no inline scripts or styles, and the popup's
// keyboard and truncation rules. No browser; the real-browser audit is docs/design/review/capture.mjs --extension.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {parseHTML, event, userClick, allText} = require("./dom-stub.cjs");

const root = path.resolve(__dirname, "../..");
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");
const TOKENS = read("docs/design/tokens.css");
const TOKEN_BODY = TOKENS.slice(TOKENS.indexOf(":root {"));
const CSS_FILES = fs.readdirSync(path.join(root, "browser")).filter((f) => f.endsWith(".css")).map((f) => `browser/${f}`);

/** The extension's own CSS: every stylesheet with the verbatim token block removed, plus the placeholder's rules. */
function ownCss() {
  const out = CSS_FILES.map((f) => [f, read(f).replace(TOKEN_BODY, "")]);
  const guard = read("browser/page-guard.js");
  const css = guard.slice(guard.indexOf("const PLACEHOLDER_CSS = `"), guard.indexOf("`;", guard.indexOf("const PLACEHOLDER_CSS = `")));
  out.push(["browser/page-guard.js (placeholder)", css]);
  return out;
}

/** Custom properties of one block of tokens.css: light (:root) or dark (the prefers-color-scheme block). */
function tokenValues(scheme) {
  const light = TOKENS.slice(TOKENS.indexOf(":root {"), TOKENS.indexOf("@media (prefers-color-scheme: dark)"));
  const dark = TOKENS.slice(TOKENS.indexOf("@media (prefers-color-scheme: dark)"), TOKENS.indexOf("/* macOS mapping"));
  const map = {};
  const parse = (text) => { for (const m of text.matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)) map[m[1]] = m[2].trim(); };
  parse(light);
  if (scheme === "dark") parse(dark);
  return map;
}

test("ui.css carries docs/design/tokens.css byte for byte, so every surface shares one token source", () => {
  const ui = read("browser/ui.css");
  assert.ok(ui.includes(TOKEN_BODY), "ui.css must contain tokens.css from ':root {' to its end, unchanged");
  assert.equal(ui.indexOf(":root {"), ui.indexOf(TOKEN_BODY), "the copied block is the first token definition in ui.css");
  assert.equal(ui.split(":root {").length, TOKEN_BODY.split(":root {").length, "no extra :root block redefines a token");
  for (const f of CSS_FILES.filter((x) => x !== "browser/ui.css")) {
    assert.doesNotMatch(read(f), /--(paper|raised|sunken|ink|muted|faint|line|edge|fill-primary|focus|protected|reduced|unprotected|s[1-8]|t-[a-z]+)\s*:/, `${f} redefines a design token`);
  }
  for (const f of ["browser/popup.html", "browser/warning.html", "browser/unwrap.html", "browser/privacy.html"]) {
    assert.match(read(f), /<link rel="stylesheet" href="ui\.css">/, `${f} loads ui.css`);
  }
});

test("extension CSS uses only token colours, type sizes and spacing", () => {
  const problems = [];
  const sizes = new Set();
  for (const [file, css] of ownCss()) {
    const body = css.replace(/\/\*[\s\S]*?\*\//g, "");
    for (const m of body.matchAll(/#[0-9a-f]{3,8}\b|\b(rgba?|hsla?)\(/gi)) problems.push(`${file}: literal colour ${m[0]}`);
    for (const m of body.matchAll(/(?:^|[;{\s])(font-size|font)\s*:\s*([^;}]+)/g)) {
      const value = m[2];
      for (const t of value.matchAll(/var\(--t-([a-z]+)\)/g)) sizes.add(t[1]);
      if (/\d+(\.\d+)?px/.test(value)) problems.push(`${file}: raw font size "${m[1]}: ${value.trim()}"`);
    }
    for (const m of body.matchAll(/(?:^|[;{\s])((?:padding|margin)(?:-[a-z]+)?|gap|row-gap|column-gap)\s*:\s*([^;}]+)/g)) {
      for (const px of m[2].matchAll(/(-?\d*\.?\d+)px/g)) {
        if (![1, 2, 4, 8, 12, 16, 24, 32, 48, 64].includes(Math.abs(Number(px[1])))) problems.push(`${file}: off-scale ${m[1]}: ${m[2].trim()}`);
      }
    }
  }
  // The token file's own rules count too: the whole extension may use at most the five type roles.
  for (const t of TOKEN_BODY.matchAll(/var\(--t-([a-z]+)\)/g)) sizes.add(t[1]);
  assert.deepEqual(problems, []);
  assert.ok(sizes.size <= 5, `more than five font sizes: ${[...sizes].join(", ")}`);
});

test("the embed placeholder's inlined tokens equal tokens.css in light and dark", () => {
  const guard = read("browser/page-guard.js");
  const start = guard.indexOf("const PLACEHOLDER_TOKENS = ") + "const PLACEHOLDER_TOKENS = ".length;
  const literal = guard.slice(start, guard.indexOf("};", start) + 1);
  const inlined = vm.runInNewContext(`(${literal})`);
  for (const scheme of ["light", "dark"]) {
    const want = tokenValues(scheme);
    for (const [k, v] of Object.entries({...inlined.common, ...inlined[scheme]})) assert.equal(v, want[k], `${scheme} ${k}`);
  }
});

// WCAG 2.x relative luminance contrast.
const lum = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

test("contrast per DESIGN.md section 4, light and dark", () => {
  for (const scheme of ["light", "dark"]) {
    const t = tokenValues(scheme);
    const text = [["ink", "paper"], ["ink", "raised"], ["ink", "sunken"], ["muted", "paper"], ["muted", "raised"], ["muted", "sunken"],
      ["protected", "paper"], ["reduced", "paper"], ["unprotected", "paper"], ["protected", "raised"], ["reduced", "raised"], ["unprotected", "raised"],
      ["unprotected", "sunken"], ["protected", "protected-tint"], ["reduced", "reduced-tint"], ["unprotected", "threat-tint"], ["ink", "reduced-tint"],
      ["ink", "threat-tint"], ["on-primary", "fill-primary"]];
    for (const [fg, bg] of text) assert.ok(ratio(t[`--${fg}`], t[`--${bg}`]) >= 4.5, `${scheme}: ${fg} on ${bg} ${ratio(t[`--${fg}`], t[`--${bg}`]).toFixed(2)}`);
    for (const [fg, bg] of [["edge", "paper"], ["edge", "raised"], ["focus", "paper"], ["focus", "raised"], ["fill-primary", "paper"]]) {
      assert.ok(ratio(t[`--${fg}`], t[`--${bg}`]) >= 3, `${scheme}: ${fg} against ${bg} ${ratio(t[`--${fg}`], t[`--${bg}`]).toFixed(2)}`);
    }
  }
  // Dark mode: the filled button is the brightest control (the owner's decision on open question 4).
  const dark = tokenValues("dark");
  for (const k of ["--raised", "--ink", "--edge", "--protected"]) assert.ok(lum(dark["--fill-primary"]) >= lum(dark[k]) || k === "--ink", k);
});

test("extension pages: no inline scripts or styles, no remote resources, at most one filled button per view", () => {
  for (const f of fs.readdirSync(path.join(root, "browser")).filter((x) => x.endsWith(".html"))) {
    const html = read(`browser/${f}`);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/, `${f}: inline script`);
    assert.doesNotMatch(html, /<style\b|\sstyle="/, `${f}: inline style`);
    assert.doesNotMatch(html, /(src|href)="(https?:)?\/\//, `${f}: remote resource`);
    for (const view of html.split(/<main\b|<section id="panel-/).slice(1)) {
      assert.ok((view.match(/class="btn primary/g) || []).length <= 1, `${f}: more than one filled button in a view`);
    }
  }
});

// ---- popup behaviour ---------------------------------------------------------------------------------------------
async function popupWith(state, page = {site: "publisher.example", paused: false, hidden: 0, shown: 0, protectedRules: [], overbroadRules: []}, options = {}) {
  const doc = parseHTML(read("browser/popup.html"));
  const sent = [];
  const browser = {
    runtime: {sendMessage: async (msg) => { sent.push(msg); return msg.type === "popup-state" ? JSON.parse(JSON.stringify(state)) : {ok: true}; }},
    tabs: {query: async () => [{id: 1, url: "https://publisher.example/a"}], sendMessage: async () => page},
  };
  if (options.chrome) browser.runtime.getManifest = () => ({manifest_version: 3});
  if (options.native) {
    browser.permissions = {request: async value => { sent.push({type: "permission", value}); return true; }};
    browser.runtime.sendNativeMessage = async (host, value) => { sent.push({type: "native", host, value}); return options.native; };
  }
  const ctx = vm.createContext({document: doc, browser, ...(options.chrome ? {chrome: browser} : {}), console, close: () => {}});
  vm.runInContext(read("browser/popup.js"), ctx, {filename: "popup.js"});
  await ctx.__EGPopup.ready;
  return {doc, sent, api: ctx.__EGPopup, $: (id) => doc.getElementById(id), text: (id) => allText(doc.getElementById(id))};
}
const STATE = {host: "publisher.example", site: "publisher.example", lists: [], requestRules: [], cosmeticRules: [], exceptions: [],
  mode: "standard", defaultMode: "standard", feedback: "debug", types: ["script", "image", "beacon"], cleaning: {on: true, links: 3, cookies: 1},
  blocked: [{host: "cdn.bad.example", path: "/x.js", type: "script", list: "threats", count: 1}, {host: "t.example", path: "/p.gif", type: "image", list: "trackers", count: 2}]};

test("popup explains Strict preparation without auto-reload or endpoint bypass suggestions", async () => {
  const p = await popupWith({...STATE, mode: "strict", preparation: {state: "held", site: "publisher.example", revision: "fixture"},
    categories: {preparation: "Strict preparation"}, blocked: [{host: "publisher.example", path: "/boot.js", type: "script", list: "preparation", count: 1}]}, undefined, {chrome: true});
  assert.equal(p.$("strict-preparation").hidden, false); assert.equal(p.$("prepare-site").hidden, false);
  assert.equal(p.text("status-word"), "Preparing"); assert.match(p.text("preparation-note"), /Chrome's Reload button/);
  assert.doesNotMatch(p.text("blocked"), /Allow for 15|Allow under Strict/);
  assert.equal(p.sent.some(message => message.type === "prepare-strict-site"), false);
  userClick(p.$("prepare-site")); await new Promise(resolve => setImmediate(resolve));
  const request = p.sent.find(message => message.type === "prepare-strict-site");
  assert.equal(request.tabId, 1); assert.equal(request.tabUrl, "https://publisher.example/a");
  const prepared = await popupWith({...STATE, mode: "strict", preparation: {state: "prepared", site: "publisher.example", revision: "fixture"}}, undefined, {chrome: true});
  assert.equal(prepared.$("prepare-site").hidden, true); assert.match(prepared.text("preparation-note"), /site rules are installed/);
});

test("unscopable Strict-held addresses retain a truthful receipt and default-mode recovery", async () => {
  const p = await popupWith({site: null, lists: [], defaultMode: "strict", preparation: {state: "held", canPrepare: false,
    reason: "This address cannot be safely represented by domain conditions."}}, undefined, {chrome: true});
  assert.equal(p.$("page-view").hidden, true); assert.equal(p.$("strict-preparation").hidden, false);
  assert.equal(p.text("status-word"), "Held"); assert.equal(p.$("prepare-site").hidden, true);
  assert.equal(p.$("defaults-group").hidden, false); assert.equal(p.$("default-modes").children.length, 2);
  assert.match(p.text("preparation-note"), /default to Standard/);
  assert.doesNotMatch(p.text("unsupported-title"), /can't be filtered/);
});

test("isolation shows its confirmed boundary and suppresses ordinary repair and Pause", async () => {
  const p = await popupWith({...STATE, mode: "isolated", requestedMode: "isolated", isolation: {
    state: "applied", active: true, revision: "fixture", existingConnections: "not-revoked", reloadNeeded: true},
    cleaning: {...STATE.cleaning, on: false}, blocked: [...STATE.blocked,
      {host: "external.example", path: "/pixel", type: "image", list: "isolated", count: 1},
      {host: "external.example", path: "/library.js", type: "script", list: "strict", count: 1}]}, undefined, {chrome: true});
  assert.equal(p.$("modes").children.length, 5);
  assert.equal(p.$("modes").children.find(button => button.textContent === "Isolated").getAttribute("aria-pressed"), "true");
  assert.equal(p.$("default-modes").children.length, 2, "isolation is a named-site choice");
  assert.equal(p.$("pause").disabled, true);
  assert.equal(p.$("isolation-note").hidden, false);
  assert.match(p.text("isolation-note"), /rules are installed/);
  assert.match(p.text("isolation-note"), /existing connections are not forcibly closed/i);
  assert.match(p.text("isolation-note"), /Site storage and your public IP/);
  assert.doesNotMatch(p.text("blocked"), /Allow 15|Allow host/);
  assert.match(p.text("clean-note"), /Isolation still removes/);
  assert.equal(p.sent.some(message => ["pause-site", "set-mode", "add-exception"].includes(message.type)), false);
  userClick(p.$("modes").children.find(button => button.textContent === "Strict"));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(p.sent.find(message => message.type === "set-mode").mode, "strict");
});

test("a requested isolation mode is never displayed as installed before readback", async () => {
  for (const receipt of [undefined, {state: "pending", active: false}, {state: "unsupported", active: false}, {state: "degraded", active: false}]) {
    const p = await popupWith({...STATE, requestedMode: "isolated", isolation: receipt}, undefined, {chrome: true});
    assert.equal(p.$("pause").disabled, true);
    assert.equal(p.$("isolation-note").hidden, false);
    assert.doesNotMatch(p.text("isolation-note"), /^Isolation rules are installed/);
    assert.match(p.text("isolation-note"), /not confirmed/);
    assert.notEqual(p.text("status-word"), "Protected");
  }
  const retained = await popupWith({...STATE, requestedMode: "standard", mode: "isolated",
    isolation: {state: "degraded", active: true}}, undefined, {chrome: true});
  assert.match(retained.text("isolation-note"), /last verified isolation rules remain/);
  assert.equal(retained.$("pause").disabled, true);
});

test("runtime cosmetic failures and hard work caps reduce the page receipt, source exemptions do not", async () => {
  const page = {paused: false, hidden: 3, shown: 0, protectedRules: [], overbroadRules: [],
    imported: {degradedFamilies: ["generic"], limits: ["subtree-nodes"], sourceExemptions: []}};
  const reduced = await popupWith(STATE, page, {chrome: true});
  assert.equal(reduced.text("status-word"), "Reduced"); assert.match(reduced.text("hidden"), /some cosmetic matches may remain/);
  assert.match(reduced.text("hidden"), /generic hiding is unavailable/);
  const intended = await popupWith(STATE, {...page, imported: {degradedFamilies: [], limits: [], sourceExemptions: ["generic"]}}, {chrome: true});
  assert.equal(intended.text("status-word"), "Protected");
});

test("popup tabs follow the ARIA tabs pattern: one tab stop, arrows, Home and End select and focus", async () => {
  const p = await popupWith(STATE);
  const tab = (id) => p.$(`tab-${id}`);
  assert.equal(p.$("tabs").getAttribute("role"), "tablist");
  assert.equal(tab("page").getAttribute("aria-selected"), "true");
  assert.equal(p.$("panel-blocked").hidden, true);
  const key = (k) => { const e = event("keydown", {key: k}); p.$("tabs").dispatchEvent(e); return e; };
  assert.ok(key("ArrowRight").defaultPrevented);
  assert.equal(tab("blocked").getAttribute("aria-selected"), "true");
  assert.equal(tab("blocked").getAttribute("tabindex"), "0");
  assert.equal(tab("page").getAttribute("tabindex"), "-1");
  assert.equal(p.doc.activeElement, tab("blocked"));
  assert.equal(p.$("panel-blocked").hidden, false);
  assert.equal(p.$("panel-page").hidden, true);
  key("End");
  assert.equal(tab("settings").getAttribute("aria-selected"), "true");
  key("ArrowRight");
  assert.equal(tab("page").getAttribute("aria-selected"), "true", "wraps around");
  key("ArrowLeft");
  assert.equal(tab("settings").getAttribute("aria-selected"), "true");
  for (const id of ["page", "blocked", "rules", "settings"]) assert.equal(tab(id).getAttribute("aria-controls"), `panel-${id}`);
});

test("popup: a stopped threat is counted in the threat colour and never offered a timed exception", async () => {
  const p = await popupWith(STATE);
  assert.equal(p.text("blocked-count"), "3");
  assert.equal(p.$("threat-line").hidden, false);
  assert.equal(p.$("threat-line").getAttribute("data-state"), "threat");
  assert.match(p.text("threat-line"), /1 threat stopped/);
  const groups = p.$("blocked").childNodes;
  assert.equal(groups[0].getAttribute("data-state"), "threat", "the threat group heading uses the threat state");
  assert.equal(groups[1].getAttribute("data-state"), null, "nothing else uses it");
  assert.equal(groups[0].querySelectorAll(".btn").length, 0, "no Allow on a threat-listed host");
  const allow = groups[1].querySelectorAll(".btn");
  assert.equal(allow.length, 1);
  assert.equal(allow[0].className, "btn act", "Allow 15 min is a trailing action, hidden at rest by .row .act");
  const li = groups[1].querySelector(".row");
  assert.equal(li.getAttribute("tabindex"), "0", "its row is focusable, so the action is keyboard reachable");
  assert.equal(li.getAttribute("title"), "t.example/p.gif", "the full address stays available");
});

test("popup: the endpoint form opens from Add…, closes with Escape and returns focus", async () => {
  const p = await popupWith(STATE);
  assert.equal(p.$("rules-empty").hidden, false, "no rules: the designed empty state");
  userClick(p.$("rule-add-empty"));
  assert.equal(p.$("add-rule").hidden, false);
  assert.equal(p.$("rules-empty").hidden, true);
  assert.equal(p.doc.activeElement, p.$("rule-path"));
  const esc = event("keydown", {key: "Escape"});
  p.doc.dispatchEvent(esc);
  assert.equal(p.$("add-rule").hidden, true);
  assert.equal(p.$("rule-add").getAttribute("aria-expanded"), "false");
  assert.equal(p.doc.activeElement, p.$("rule-add-empty"));
});

test("popup: every second-level view has its empty state; unsupported pages say so", async () => {
  const p = await popupWith({...STATE, blocked: []});
  assert.equal(p.$("blocked-empty").hidden, false);
  assert.match(p.text("blocked-empty"), /Nothing blocked on this page/);
  assert.equal(p.text("blocked-count"), "0", "zero is shown as 0");
  assert.equal(p.$("rules-empty").hidden, false);
  const none = await popupWith({site: null});
  assert.equal(none.$("unsupported").hidden, false);
  assert.equal(none.$("tab-blocked").hidden, true);
  assert.equal(none.$("status").getAttribute("data-state"), "neutral");
});

test("popup: protection levels are a segmented control; Pause and the default stay separate controls", async () => {
  const p = await popupWith(STATE);
  const modes = p.$("modes").childNodes;
  assert.deepEqual(modes.map((b) => b.textContent), ["Relaxed", "Standard", "Strict", "No scripts"]);
  assert.equal(modes[1].getAttribute("aria-pressed"), "true");
  userClick(modes[2]);
  await new Promise((r) => setImmediate(r));
  assert.ok(p.sent.some((m) => m.type === "set-mode" && m.mode === "strict"));
  assert.equal(p.$("pause").className, "btn quiet", "Pause is quiet, not a fifth segment");
  assert.deepEqual(p.$("default-modes").childNodes.map((b) => b.textContent), ["Standard", "Strict"]);
  const ff = await popupWith({...STATE, mode: undefined, cleaning: undefined});
  assert.equal(ff.$("protection").hidden, true, "a build without levels (Firefox) shows none");
  assert.equal(ff.$("fact-links").hidden, true);
  assert.equal(ff.text("status-word"), "Manual rules");
});

test("truncation: hostnames in the middle by whole labels; URLs keep the host and the last segment", async () => {
  const {api} = await popupWith(STATE);
  const long = "accounts.internal-billing-portal.eu-west1.cdn.example-enterprise.co.uk";
  assert.equal(long.length, 70);
  assert.equal(api.fitHost(long, 80), long);
  assert.equal(api.fitHost(long, 40), "accounts.….example-enterprise.co.uk");
  assert.equal(api.fitHost(long, 28), "….example-enterprise.co.uk");
  for (const max of [20, 30, 45, 60]) {
    const out = api.fitHost(long, max);
    assert.ok(out.length <= max, `${out} fits ${max}`);
    const kept = out.split(".").filter((l) => l !== "…" && !l.includes("…"));
    for (const label of kept) assert.ok(long.split(".").includes(label), `"${label}" is a whole label`);
  }
  assert.equal(api.fitHost("xn--pypal-4ve.com", 30), "xn--pypal-4ve.com", "punycode is shown as is");
  assert.deepEqual([...api.fitUrl("publisher.example", "/sgtm/gtm.js", 40)], ["publisher.example", "/sgtm/gtm.js"]);
  assert.deepEqual([...api.fitUrl("publisher.example", "/a/very/long/path/to/gtm.js", 28)], ["publisher.example", "/…/gtm.js"]);
  assert.deepEqual([...api.fitUrl("securepubads.g.doubleclick.net", "/pagead/managed/js/gpt/m202611180101/pubads_impl.js", 40)], ["securepubads.g.doubleclick.net", "/…"]);
  const [h, rest] = api.fitUrl(long, "/p.gif", 40);
  assert.ok((h + rest).length <= 40 && rest === "/p.gif" && h.endsWith("example-enterprise.co.uk"));
  assert.equal(api.fmt(9999), "9,999");
  assert.equal(api.fmt(12480), "12.5k");
  assert.equal(api.fmt(1870000), "1.9M");
});

test("popup: a paused site says Paused until HH:MM, offers a filled Resume, and shows the level that comes back, disabled", async () => {
  const until = new Date(2026, 10, 20, 15, 42).getTime();
  const p = await popupWith({...STATE, mode: "relaxed", resumeMode: "strict", paused: until});
  assert.equal(p.text("status-word"), "Paused");
  assert.equal(p.$("status").getAttribute("data-state"), "reduced");
  assert.equal(p.$("paused").hidden, false);
  assert.equal(p.text("paused-text"), "Paused on this site until 15:42");
  assert.equal(p.$("resume").className, "btn primary", "Resume is the one filled button");
  assert.equal(p.$("paused-note").hidden, false);
  assert.equal(p.text("paused-note"), "Malware and phishing blocking stays on.");
  assert.equal(p.$("pause").hidden, true);
  const modes = p.$("modes").childNodes;
  assert.ok(modes.every((b) => b.disabled), "levels cannot change while paused");
  assert.equal(modes.find((b) => b.getAttribute("aria-pressed") === "true").textContent, "Strict", "the level that will be restored");
  userClick(p.$("resume"));
  await new Promise((r) => setImmediate(r));
  assert.ok(p.sent.some((m) => m.type === "resume-site"));
  const live = await popupWith(STATE);
  assert.equal(live.$("paused").hidden, true);
  userClick(live.$("pause"));
  await new Promise((r) => setImmediate(r));
  assert.ok(live.sent.some((m) => m.type === "pause-site"), "Pause asks the worker, not the page");
});

test("popup does not present saved-but-unapplied policy or incomplete lists as protected", async () => {
  const p = await popupWith({...STATE, requestedMode: "strict", policy: {state: "degraded", error: "DNR update failed"}});
  assert.equal(p.text("status-word"), "Degraded");
  assert.equal(p.$("policy-issue").hidden, false);
  assert.equal(p.$("modes").childNodes.find(node => node.getAttribute("aria-pressed") === "true").textContent, "Standard");
  userClick(p.$("policy-retry"));
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(p.sent.some(message => message.type === "retry-policy"));
  const reduced = await popupWith({...STATE, policy: {state: "applied"}, coverage: {complete: false, missing: ["easyprivacy"], stale: []}});
  assert.equal(reduced.text("status-word"), "Reduced");
  assert.match(reduced.text("coverage-note"), /easyprivacy/);
});

test("popup reports failed or pending built-in CSS instead of calling the page protected", async () => {
  for (const generic of [{available: true, on: false, error: "scripting unavailable"}, {available: true, on: false, pending: true}]) {
    const p = await popupWith({...STATE, generic: true}, {site: STATE.site, paused: false, hidden: 0, shown: 0, protectedRules: [], overbroadRules: [], generic});
    assert.equal(p.text("status-word"), "Reduced");
    assert.match(p.text("generic-note"), /could not be applied|waiting for the browser/);
  }
});

test("Chrome browser alias keeps review visible and native receipts are read only after a permission gesture", async () => {
  const receipt = {schema: 1, ok: true, product: "egress-guard", capabilities: {read_only: true, mutations: false},
    status: {proxy_ready: true, policy: {applied: true, complete: true, pending: false, degraded: false, saved_revision: "a".repeat(64), applied_revision: "a".repeat(64)},
      logging: {saved: {history: "none", retention_days: 7, max_queue: 1000}, runtime: {history: "none", retention_days: 7, max_queue: 1000, applied: true}},
      transport: {saved: {profile: "hardened", connect_ports: [443], address_guard: true}, runtime: {
        profile: "hardened", connect_ports: [443], address_guard: {selected: true, state: "active", reason: null}, scope: "proxy-tcp", tunnel_policy: "per-forward", applied: true}}}};
  const p = await popupWith(STATE, undefined, {chrome: true, native: receipt});
  assert.equal(p.$("semantic-item").hidden, false);
  assert.equal(p.$("native-group").hidden, false);
  assert.equal(p.sent.some(message => message.type === "native"), false);
  userClick(p.$("native-check"));
  await new Promise(resolve => setImmediate(resolve));
  const messages = p.sent.filter(message => ["permission", "native"].includes(message.type));
  assert.deepEqual(messages.map(message => message.type), ["permission", "native"]);
  assert.equal(messages[1].host, "org.egress_guard.receipts");
  assert.equal(messages[1].value.command, "status");
  assert.match(p.text("native-note"), /Runtime history: none \(acknowledged\)/);
  assert.match(p.text("native-note"), /Runtime transport: hardened \(acknowledged\)/);
  assert.match(p.text("native-note"), /Tunnel permissions are checked before each forwarding operation/);
  assert.match(p.text("native-note"), /Experimental address guard: active/);
  assert.match(p.text("native-note"), /Browser routing and device-wide coverage are not verified/);
  const bad = await popupWith(STATE, undefined, {chrome: true, native: {...receipt, capabilities: {read_only: true, mutations: true}}});
  userClick(bad.$("native-check"));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(bad.text("native-note"), /invalid receipt/);
  const mismatch = JSON.parse(JSON.stringify(receipt));
  mismatch.status.logging.runtime.history = "full";
  const old = await popupWith(STATE, undefined, {chrome: true, native: mismatch});
  userClick(old.$("native-check")); await new Promise(resolve => setImmediate(resolve));
  assert.match(old.text("native-note"), /Proxy not fully ready/);
  assert.match(old.text("native-note"), /does not acknowledge saved settings/);
  mismatch.status.logging.runtime.applied = "false";
  const malformed = await popupWith(STATE, undefined, {chrome: true, native: mismatch});
  userClick(malformed.$("native-check")); await new Promise(resolve => setImmediate(resolve));
  assert.match(malformed.text("native-note"), /incomplete receipt/);
  for (const runtime of [null, {...receipt.status.transport.runtime, applied: false},
    {...receipt.status.transport.runtime, profile: "compatible"},
    {...receipt.status.transport.runtime, connect_ports: [443, 8443]}]) {
    const altered = JSON.parse(JSON.stringify(receipt)); altered.status.transport.runtime = runtime;
    const waiting = await popupWith(STATE, undefined, {chrome: true, native: altered});
    userClick(waiting.$("native-check")); await new Promise(resolve => setImmediate(resolve));
    assert.match(waiting.text("native-note"), /Proxy not fully ready/);
    assert.doesNotMatch(waiting.text("native-note"), /^Proxy ready/);
  }
  const oldTransport = {...receipt.status.transport.runtime};
  delete oldTransport.tunnel_policy;
  for (const runtime of [oldTransport, {...receipt.status.transport.runtime, tunnel_policy: "initial-only"},
    {...receipt.status.transport.runtime, tunnel_policy: true},
    {...receipt.status.transport.runtime, connect_ports: [443, 443]},
    {...receipt.status.transport.runtime, address_guard: {selected: true, state: "unavailable", reason: "self-test-failed"}},
    {...receipt.status.transport.runtime, peer: "private.example"}]) {
    const altered = JSON.parse(JSON.stringify(receipt)); altered.status.transport.runtime = runtime;
    const invalid = await popupWith(STATE, undefined, {chrome: true, native: altered});
    userClick(invalid.$("native-check")); await new Promise(resolve => setImmediate(resolve));
    assert.match(invalid.text("native-note"), /incomplete receipt/);
    assert.doesNotMatch(invalid.text("native-note"), /Tunnel permissions are checked|^Proxy ready/);
    assert.doesNotMatch(invalid.text("native-note"), /private\.example/);
  }
});
