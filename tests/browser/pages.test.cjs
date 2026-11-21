"use strict";
// Page-side code that used to be covered only in headless Chrome, run here against the DOM stub: the click-time link
// cleaner and the click-to-load placeholder (page-guard.js), the unwrap page and mail-scanner interstitial
// (unwrap.js), and the surrogates' callback stacks.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {parseHTML, Document, event} = require("./dom-stub.cjs");

const root = path.join(__dirname, "../..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(setImmediate); };

// ---- page-guard.js ----------------------------------------------------------------------------------------------
function guard({host = "publisher.example", mode = "standard", io = null, computed = null} = {}) {
  const doc = new Document();
  const html = doc.createElement("html"); doc.append(html);
  const body = doc.createElement("body"); html.append(body);
  const sent = [];
  const chrome = {runtime: {sendMessage: async (m) => {
    sent.push(JSON.parse(JSON.stringify(m)));
    if (m.type === "guard-config") return {clean: true, mode, embeds: [{id: "youtube", name: "YouTube", domains: ["youtube.com"]}]};
    if (m.type === "load-embed") return {ok: true};
    return {ok: true};
  }, onMessage: {addListener() {}}}};
  const ctx = vm.createContext({document: doc, chrome, URL, setTimeout, clearTimeout, console, Date,
    location: {href: `https://${host}/page`, hostname: host}, history: {state: null, replaceState() {}},
    addEventListener() {}, getComputedStyle: computed || (() => ({display: "block", visibility: "visible", opacity: "1", filter: "none"})),
    ...(io ? {IntersectionObserver: io} : {})});
  for (const f of ["browser/core/links.js", "browser/core/params.js", "browser/page-guard.js"]) vm.runInContext(read(f), ctx, {filename: f});
  return {doc, ctx, sent, api: ctx.__EGPageGuard};
}
const link = (href, attrs = {}) => ({href, getAttribute: (n) => (n in attrs ? attrs[n] : null)});

test("click-time cleaning: a redirector is unwrapped only on its own site; elsewhere only its tracking parameters go", () => {
  const g = "https://www.google.com/url?q=" + encodeURIComponent("https://shop.example/p?id=1&fbclid=x") + "&utm_source=mail&sa=U";
  const onGoogle = guard({host: "www.google.com"}).api;
  assert.equal(onGoogle.cleanHref(link(g)), "https://shop.example/p?id=1");
  const elsewhere = guard({host: "phish.example"}).api;
  assert.equal(elsewhere.cleanHref(link(g)), "https://www.google.com/url?q=" + encodeURIComponent("https://shop.example/p?id=1&fbclid=x") + "&sa=U",
    "Google's own check stays; utm_source on the wrapper is still removed");
  const fb = "https://l.facebook.com/l.php?u=" + encodeURIComponent("https://evil.example/") + "&h=AT0";
  assert.equal(elsewhere.cleanHref(link(fb)), null);
  assert.equal(guard({host: "www.facebook.com"}).api.cleanHref(link(fb)), "https://evil.example/");
  // Open affiliate redirectors are unwrapped anywhere.
  assert.equal(elsewhere.cleanHref(link("https://www.awin1.com/cread.php?ued=" + encodeURIComponent("https://shop.example/p"))), "https://shop.example/p");
});

test("click-time cleaning: a mail scanner's link is never touched, even behind t.co or a redirector", () => {
  const scanner = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.org%2F&data=x&utm_source=y";
  const api = guard({host: "outlook.office.com"}).api;
  assert.equal(api.cleanHref(link(scanner)), null);
  assert.equal(guard({host: "x.com"}).api.cleanHref(link("https://t.co/Ab", {"data-expanded-url": scanner})), null);
  const viaGoogle = "https://www.google.com/url?q=" + encodeURIComponent(scanner);
  assert.equal(guard({host: "www.google.com"}).api.cleanHref(link(viaGoogle)), scanner, "unwrapped down to the scanner, then left as it is");
});

test("placeholder: the host carries !important styles and all:initial; a click counts only when the button is visibly there", async () => {
  const g = guard();
  const {placeholder, clickAllowed} = g.api;
  let loaded = 0;
  const box = placeholder({id: "youtube", name: "YouTube"}, () => loaded++, null);
  g.doc.body.append(box);
  for (const prop of ["display", "opacity", "visibility", "transform", "filter", "pointer-events", "clip-path", "position"]) {
    assert.equal(box.style.getPropertyPriority(prop), "important", prop);
  }
  assert.equal(box.style.getPropertyValue("opacity"), "1");
  const shadow = box.shadowRoot;
  assert.match(shadow.childNodes[0].textContent, /:host\{all:initial !important;display:block !important/);
  const buttons = [];
  const walk = (n) => { if (n.localName === "button") buttons.push(n); for (const c of n.childNodes) walk(c); };
  walk(shadow);
  const [load, withCookies] = buttons;
  assert.equal(withCookies.textContent, "Load with cookies (signed in)");
  // The heuristics, one by one.
  const ev = (extra = {}) => ({...event("click"), ...extra});
  const now = 10000;
  assert.equal(clickAllowed(load, shadow, event("click", {isTrusted: false}), undefined, now), false, "synthetic");
  assert.equal(clickAllowed(load, shadow, ev(), null, now), false, "IntersectionObserver v2 says not visible");
  assert.equal(clickAllowed(load, shadow, ev(), now - 200, now), false, "visible for too short a time");
  assert.equal(clickAllowed(load, shadow, ev(), now - 600, now), true);
  assert.equal(clickAllowed(load, shadow, ev(), undefined, now), true, "no v2 in this browser: heuristics only");
  const tiny = {...load, getBoundingClientRect: () => ({width: 4, height: 4}), parentNode: load.parentNode, nodeType: 1};
  assert.equal(clickAllowed(tiny, shadow, ev(), undefined, now), false, "shrunk");
  shadow.elementFromPoint = () => g.doc.body;
  assert.equal(clickAllowed(load, shadow, ev({clientX: 5, clientY: 5}), undefined, now), false, "something else is under the pointer");
  shadow.elementFromPoint = () => load;
  assert.equal(clickAllowed(load, shadow, ev({clientX: 5, clientY: 5}), undefined, now), true);
  // An ancestor the page made transparent.
  const faded = guard({computed: (el) => ({display: "block", visibility: "visible", opacity: el.localName === "body" ? "0.01" : "1", filter: "none"})});
  const box2 = faded.api.placeholder({id: "youtube", name: "YouTube"}, () => loaded++, null);
  faded.doc.body.append(box2);
  const b2 = []; (function w(n) { if (n.localName === "button") b2.push(n); for (const c of n.childNodes) w(c); })(box2.shadowRoot);
  assert.equal(faded.api.clickAllowed(b2[0], box2.shadowRoot, ev(), undefined, now), false, "transparent ancestor");
  // Real clicks through the placeholder: allowed -> load-embed; "with cookies" asks for cookies.
  load.dispatchEvent(event("click"));
  await settle();
  assert.equal(loaded, 1);
  assert.deepEqual(g.sent.filter((m) => m.type === "load-embed"), [{type: "load-embed", embed: "youtube", cookies: false}]);
  const g3 = guard();
  const box3 = g3.api.placeholder({id: "youtube", name: "YouTube"}, () => {}, null);
  g3.doc.body.append(box3);
  const b3 = []; (function w(n) { if (n.localName === "button") b3.push(n); for (const c of n.childNodes) w(c); })(box3.shadowRoot);
  b3[1].dispatchEvent(event("click"));
  await settle();
  assert.deepEqual(g3.sent.filter((m) => m.type === "load-embed"), [{type: "load-embed", embed: "youtube", cookies: true}]);
});

test("placeholder: with IntersectionObserver v2 reporting it hidden, a real click loads nothing", async () => {
  let report = null;
  class IO { constructor(cb, opts) { this.cb = cb; IO.opts = opts; report = (isVisible) => cb([{isVisible}]); } observe() {} }
  const g = guard({io: IO});
  const box = g.api.placeholder({id: "youtube", name: "YouTube"}, () => {}, null);
  g.doc.body.append(box);
  assert.equal(IO.opts.trackVisibility, true);
  assert.ok(IO.opts.delay >= 100);
  const buttons = []; (function w(n) { if (n.localName === "button") buttons.push(n); for (const c of n.childNodes) w(c); })(box.shadowRoot);
  buttons[0].dispatchEvent(event("click"));
  await settle();
  assert.equal(g.sent.filter((m) => m.type === "load-embed").length, 0, "never reported visible");
  report(false);
  buttons[0].dispatchEvent(event("click"));
  await settle();
  assert.equal(g.sent.filter((m) => m.type === "load-embed").length, 0, "reported covered");
});

// ---- unwrap.js ----------------------------------------------------------------------------------------------------
function unwrapPage(link, {threat = () => false, config = {scannedDirect: false}, framed = false, failCheck = false} = {}) {
  const doc = parseHTML(read("browser/unwrap.html"));
  const replaced = [];
  const sent = [];
  const chrome = {runtime: {sendMessage: async (m) => {
    sent.push(JSON.parse(JSON.stringify(m)));
    if (m.type === "unwrap-config") return config;
    if (m.type === "check-destination") return failCheck ? null : {ok: true, threat: threat(new URL(m.url).hostname)};
    if (m.type === "scanner-continue") return {ok: true};
    return {error: "unexpected"};
  }}};
  const win = {};
  const ctx = vm.createContext({document: doc, chrome, URL, console, setTimeout, TextDecoder, atob,
    location: {hash: `#${link}`, href: `chrome-extension://x/unwrap.html#${link}`, replace: (u) => replaced.push(u), reload() {}},
    history: {length: 1, back() {}}, close() {}, addEventListener() {}});
  ctx.top = framed ? win : ctx;
  ctx.self = ctx;
  vm.runInContext("globalThis.top = top; globalThis.self = self;", ctx);
  for (const f of ["browser/core/links.js", "browser/unwrap.js"]) vm.runInContext(read(f), ctx, {filename: f});
  const $ = (id) => doc.getElementById(id);
  return {doc, $, replaced, sent, ready: ctx.__EGUnwrap.ready};
}

test("unwrap page: a tracker's destination is checked against the threat list before it opens; a listed one goes to the warning page", async () => {
  const g = "https://www.google.com/url?q=" + encodeURIComponent("https://example.org/a");
  const ok = unwrapPage(g);
  await ok.ready;
  assert.deepEqual(ok.replaced, ["https://example.org/a"]);
  assert.deepEqual(ok.sent.map((m) => m.type), ["check-destination"]);
  const bad = unwrapPage("https://www.google.com/url?q=" + encodeURIComponent("https://login.bad.example/x"), {threat: (h) => h.endsWith("bad.example")});
  await bad.ready;
  assert.deepEqual(bad.replaced, ["warning.html?list=threats#https://login.bad.example/x"]);
  // Fails safe: no answer from the worker, nothing opens.
  const silent = unwrapPage(g, {failCheck: true});
  await silent.ready;
  assert.deepEqual(silent.replaced, []);
  assert.equal(silent.$("card").hidden, false);
  // Inside a frame: refuses.
  const framed = unwrapPage(g, {framed: true});
  await framed.ready;
  assert.deepEqual(framed.replaced, []);
  assert.match(framed.$("reason").textContent, /inside another page/);
  // A layer from another site keeps its own check: Google -> Facebook stops at Facebook's address.
  const fb = unwrapPage("https://www.google.com/url?q=" + encodeURIComponent("https://l.facebook.com/l.php?u=" + encodeURIComponent("https://example.org/f")));
  await fb.ready;
  assert.deepEqual(fb.replaced, ["https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2Ff"]);
});

test("scanner interstitial: shows the destination, never opens anything by itself; Continue goes through the scanner, Open directly is checked", async () => {
  const scanner = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.org%2Fdoc%3Fid%3D3&data=05&sdata=x";
  const p = unwrapPage(scanner);
  await p.ready;
  await settle();
  assert.deepEqual(p.replaced, [], "no auto-navigation");
  assert.equal(p.$("scan").hidden, false);
  assert.equal(p.$("scan-host").textContent, "example.org");
  assert.equal(p.$("scan-url").textContent, "https://example.org/doc?id=3");
  assert.equal(p.$("scan-title").textContent, "This link goes through Microsoft Safe Links");
  assert.equal(p.doc.activeElement, p.$("through"), "Continue through the scanner has the focus");
  assert.equal(p.$("direct").hidden, false);
  assert.match(p.$("direct").textContent, /skips the mail scan/);
  p.$("through").dispatchEvent(event("click"));
  await settle();
  assert.deepEqual(p.sent.filter((m) => m.type === "scanner-continue"), [{type: "scanner-continue", url: scanner}]);
  assert.deepEqual(p.replaced, [scanner], "the original, untouched address");
  // Open directly: checked first; a listed destination lands on the warning page.
  const d = unwrapPage(scanner.replace("example.org", "login.bad.example"), {threat: (h) => h.endsWith("bad.example")});
  await d.ready;
  d.$("direct").dispatchEvent(event("click"));
  await settle();
  assert.deepEqual(d.replaced, ["warning.html?list=threats#https://login.bad.example/doc?id=3"]);
  const clean = unwrapPage(scanner);
  await clean.ready;
  clean.$("direct").dispatchEvent(event("click"));
  await settle();
  assert.deepEqual(clean.replaced, ["https://example.org/doc?id=3"]);
});

test("scanner interstitial: IDN shown both ways; Mimecast offers no direct open; the setting opens directly but still checks", async () => {
  const idn = unwrapPage("https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2F%D0%B0%D1%80%D1%80%D3%8F%D0%B5.com%2Flogin");
  await idn.ready;
  assert.equal(idn.$("scan-host").textContent, "xn--80ak6aa92e.com");
  assert.equal(idn.$("scan-idn").hidden, false);
  assert.match(idn.$("scan-idn").textContent, /аррӏе\.com/);
  const mime = unwrapPage("https://protect-eu.mimecast.com/s/AbCdEf?domain=example.org");
  await mime.ready;
  assert.equal(mime.$("direct").hidden, true);
  assert.equal(mime.$("scan-host").textContent, "example.org");
  assert.deepEqual(mime.replaced, []);
  const direct = unwrapPage("https://urldefense.com/v3/__https://example.org/a__;!!x$", {config: {scannedDirect: true}});
  await direct.ready;
  assert.deepEqual(direct.replaced, ["https://example.org/a"]);
  const directBad = unwrapPage("https://urldefense.com/v3/__https://evil.bad.example/a__;!!x$", {config: {scannedDirect: true}, threat: (h) => h.endsWith("bad.example")});
  await directBad.ready;
  assert.deepEqual(directBad.replaced, ["warning.html?list=threats#https://evil.bad.example/a"]);
  const mimeDirect = unwrapPage("https://protect-eu.mimecast.com/s/AbCdEf?domain=example.org", {config: {scannedDirect: true}});
  await mimeDirect.ready;
  assert.deepEqual(mimeDirect.replaced, [], "no readable address: the interstitial still shows");
});

test("interstitial and unwrap page: refuse framing by CSP and are web-accessible only through the dynamic URL", () => {
  const manifest = JSON.parse(read("browser/manifest.chrome.json"));
  assert.match(manifest.content_security_policy.extension_pages, /frame-ancestors 'none'/);
  const war = manifest.web_accessible_resources.find((w) => w.resources.includes("unwrap.html"));
  assert.equal(war.use_dynamic_url, true);
  assert.ok(!/setTimeout|setInterval|location\.(assign|href\s*=)/.test(read("browser/unwrap.js").replace(/location\.replace\(/g, "")), "nothing navigates on a timer");
});

// ---- surrogates: no extension frame on a page callback's stack ----------------------------------------------------
test("surrogates call page callbacks with no surrogate frame on the stack", async () => {
  const stacks = [];
  const capture = () => stacks.push(new Error("probe").stack);
  const run = (file, window) => {
    const ctx = vm.createContext({window, setTimeout, queueMicrotask, Array, Object, Error});
    window.window = window;
    vm.runInContext(`with (window) {${read(`browser/surrogates/${file}`)}}`, ctx, {filename: `chrome-extension://abcdefghijklmnopabcdefghijklmnop/surrogates/${file}`});
    return window;
  };
  const ga = run("google-analytics.js", {ga: Object.assign(() => {}, {q: [["send", "pageview", {hitCallback: capture}]]})});
  ga.ga("send", "event", {hitCallback: capture});
  ga.ga(capture);
  const gtm = run("google-tag-manager.js", {dataLayer: [{event: "x", eventCallback: capture}]});
  gtm.dataLayer.push({event: "y", eventCallback: capture});
  gtm.gtag("event", "z", {event_callback: capture});
  const gpt = run("google-publisher-tag.js", {googletag: {cmd: [capture]}});
  gpt.googletag.cmd.push(capture);
  const seg = run("segment.js", {analytics: []});
  seg.analytics.ready(capture);
  seg.analytics.track("x", {}, capture);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(stacks.length, 10);
  for (const s of stacks) assert.doesNotMatch(s, /chrome-extension:|surrogates\//, s);
});
