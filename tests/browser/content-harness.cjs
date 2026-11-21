"use strict";
// Source-level DOM fixtures, not a replacement for the real-browser qualification.
const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const dom = require("./dom-stub.cjs");
const root = path.resolve(__dirname, "../..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const walk = (node, predicate) => { const out = []; for (const n of node.children || []) { if (predicate(n)) out.push(n); out.push(...walk(n, predicate)); } return out; };
// Native internal selectors are deliberately outside the user hide-rule grammar.
const query = dom.Element.prototype.querySelectorAll;
const matches = dom.Element.prototype.matches;
function internal(selector) {
  const oracle = this.ownerDocument.fixtureNativeSelectors && this.ownerDocument.fixtureNativeSelectors[selector];
  if (oracle) return walk(this, oracle);
  const m = /^(script|iframe|link|style)\[([a-z-]+)\]$/.exec(selector);
  return m ? walk(this, (n) => n.localName === m[1] && n.hasAttribute(m[2])) : query.call(this, selector);
}
dom.Element.prototype.querySelectorAll = internal;
dom.Document.prototype.querySelectorAll = internal;
dom.Element.prototype.matches = function (selector) {
  const oracle = this.ownerDocument.fixtureNativeSelectors && this.ownerDocument.fixtureNativeSelectors[selector];
  return oracle ? oracle(this) : matches.call(this, selector);
};
Object.defineProperty(dom.Document.prototype, "head", {get() { return this.documentElement.children.find((n) => n.localName === "head") || null; }});
Object.defineProperty(dom.Element.prototype, "src", {get() { return this.getAttribute("src") || ""; }, set(value) { this.setAttribute("src", value); }});
dom.Element.prototype.cloneNode = function () {
  const n = this.ownerDocument.createElement(this.localName);
  for (const a of this.attributes) n.setAttribute(a.name, a.value);
  for (const [name, p] of this.style.props) n.style.setProperty(name, p.value, p.priority);
  return n;
};
dom.Element.prototype.replaceWith = function (n) { this.before(n); this.remove(); };
function clock() {
  let now = 1000000, next = 1; const jobs = new Map(), observers = [];
  class Date0 extends Date { static now() { return now; } }
  class MutationObserver { constructor(fn) { this.fn = fn; this.active = false; observers.push(this); } observe(target, options) { this.active = true; this.options = options; } disconnect() { this.active = false; } }
  const advance = (ms) => { now += ms; for (const [id, job] of [...jobs]) if (job.at <= now) { jobs.delete(id); job.fn(); } };
  return {Date: Date0, MutationObserver, observers, setTimeout: (fn, ms = 0) => { const id = next++; jobs.set(id, {fn, at: now + ms}); return id; }, clearTimeout: (id) => jobs.delete(id), advance,
    emit: (mutations) => observers.filter((o) => o.active).forEach((o) => o.fn(mutations)),
    flush: () => { for (let i = 0; i < 200 && jobs.size; i++) advance(1000); if (jobs.size) throw new Error("work did not settle"); },
  };
}
const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(setImmediate); };
async function content({markup, rules = [], generic = false, semantic = true, host = "publisher.example", href = `https://${host}/feed`, data = null, chrome = false, styleFailures = 0, nativeSelectors = null} = {}) {
  const doc = dom.parseHTML(`<html><head></head><body>${markup || ""}</body></html>`), t = clock(), messages = []; let listener;
  // Explicit fixture oracles model only the named native relations. They do not
  // validate Chrome's selector implementation, cascade or layout.
  doc.fixtureNativeSelectors = nativeSelectors;
  const api = {runtime: {id: "fixture", sendMessage: async (m) => { messages.push(m); return m.type === "page-rules" ? {site: host, rules} : m.type === "cosmetic-style" ? styleFailures-- > 0 ? {error: "injected CSS failure"} : {ok: true, on: m.on} : {ok: true}; }, onMessage: {addListener(fn) { listener = fn; }}}};
  const ctx = vm.createContext({document: doc, URL, console, ...t, location: {hostname: host, href}, EGCosmeticData: data, [chrome ? "chrome" : "browser"]: api});
  for (const f of ["browser/core/selectors.js", "browser/core/picker.js", ...(generic ? ["browser/core/psl-data.js", "browser/core/hosts.js", "browser/core/cosmetic-selectors.js", "browser/core/cosmetic.js"] : []), ...(semantic ? ["browser/core/semantic.js"] : []), "browser/content.js"]) vm.runInContext(read(f), ctx, {filename: f});
  await ctx.__EGCosmetic.ready; await settle();
  return {doc, t, ctx, api: ctx.__EGCosmetic, messages, send: (m) => listener(m, {id: "fixture"}), hidden: (id) => doc.getElementById(id).style.getPropertyValue("display") === "none"};
}
async function guard(markup, provider = {id: "x", name: "X", domains: ["platform.twitter.com"]}) {
  const doc = dom.parseHTML(`<html><head></head><body>${markup}</body></html>`), t = clock(), messages = [];
  const ctx = vm.createContext({document: doc, URL, console, ...t, location: {href: "https://publisher.example/", hostname: "publisher.example"}, history: {state: null, replaceState() {}}, addEventListener() {},
    getComputedStyle: () => ({display: "block", visibility: "visible", opacity: "1", filter: "none"}),
    chrome: {runtime: {onMessage: {addListener() {}}, sendMessage: async (m) => { messages.push(m); return m.type === "guard-config" ? {clean: true, mode: "strict", embeds: [provider]} : {ok: true}; }}}});
  for (const f of ["browser/core/links.js", "browser/core/params.js", "browser/page-guard.js"]) vm.runInContext(read(f), ctx, {filename: f});
  await settle(); return {doc, t, ctx, messages, api: ctx.__EGPageGuard};
}
module.exports = {...dom, read, walk, content, guard, settle, vm};
