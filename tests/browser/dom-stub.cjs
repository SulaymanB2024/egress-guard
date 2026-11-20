"use strict";
/* A tiny, test-only DOM: enough of Element/Document/ShadowRoot/events for the companion's content
 * script and popup. Selector matching reuses the extension's own restricted grammar (parseSelector),
 * plus a few internal selectors the tests use. It models no layout, CSS cascade or network. */
const {parseSelector} = require("../../browser/core/selectors.js");

const VOID = new Set(["meta", "link", "input", "br", "img", "hr", "source", "area", "base", "col", "embed", "track", "wbr"]);

class Style {
  constructor() { this.props = new Map(); }
  setProperty(name, value, priority = "") { this.props.set(name, {value: String(value), priority: priority || ""}); }
  getPropertyValue(name) { return this.props.has(name) ? this.props.get(name).value : ""; }
  getPropertyPriority(name) { return this.props.has(name) ? this.props.get(name).priority : ""; }
  removeProperty(name) { this.props.delete(name); }
  set cssText(text) {
    this.props.clear();
    for (const decl of String(text).split(";")) {
      const m = /^\s*([a-z-]+)\s*:\s*(.*?)\s*(!important)?\s*$/.exec(decl);
      if (m) this.setProperty(m[1], m[2], m[3] ? "important" : "");
    }
  }
  get display() { return this.getPropertyValue("display"); }
}

class Node {
  constructor(ownerDocument) { this.ownerDocument = ownerDocument; this.parentNode = null; this.childNodes = []; this.listeners = []; }
  get parentElement() { return this.parentNode instanceof Element ? this.parentNode : null; }
  get children() { return this.childNodes.filter((n) => n instanceof Element); }
  get isConnected() {
    for (let n = this; n; n = n.parentNode instanceof ShadowRoot ? n.parentNode.host : n.parentNode) if (n instanceof Document) return true;
    return false;
  }
  append(...nodes) {
    for (let node of nodes) {
      if (typeof node === "string") node = this.ownerDocument.createTextNode(node);
      if (node.parentNode) node.remove();
      node.parentNode = this; this.childNodes.push(node);
    }
  }
  replaceChildren(...nodes) { for (const c of [...this.childNodes]) c.remove(); this.append(...nodes); }
  remove() {
    if (!this.parentNode) return;
    const list = this.parentNode.childNodes;
    list.splice(list.indexOf(this), 1);
    this.parentNode = null;
  }
  before(node) {
    if (node.parentNode) node.remove();
    const list = this.parentNode.childNodes;
    list.splice(list.indexOf(this), 0, node);
    node.parentNode = this.parentNode;
  }
  contains(other) { for (let n = other; n; n = n.parentNode) if (n === this) return true; return false; }
  get textContent() { return this.childNodes.map((c) => c.textContent).join(""); }
  set textContent(value) { this.replaceChildren(); if (value !== "" && value != null) this.append(this.ownerDocument.createTextNode(String(value))); }
  addEventListener(type, fn, options) {
    const capture = options === true || Boolean(options && options.capture);
    this.listeners.push({type, fn, capture, once: Boolean(options && options.once)});
  }
  removeEventListener(type, fn, options) {
    const capture = options === true || Boolean(options && options.capture);
    this.listeners = this.listeners.filter((l) => !(l.type === type && l.fn === fn && l.capture === capture));
  }
  fire(event, capture) {
    for (const l of [...this.listeners]) {
      if (l.type !== event.type || l.capture !== capture || event.stopped) continue;
      if (l.once) this.removeEventListener(l.type, l.fn, l.capture);
      event.currentTarget = this;
      l.fn.call(this, event);
    }
  }
  dispatchEvent(event) {
    event.target = event.target || this;
    const path = [];
    for (let n = this; n; n = n.parentNode instanceof ShadowRoot ? n.parentNode.host : n.parentNode) path.push(n);
    for (const n of [...path].reverse()) { n.fire(event, true); if (event.stopped) return !event.defaultPrevented; }
    for (const n of path) { n.fire(event, false); if (event.stopped || event.bubbles === false) break; }
    return !event.defaultPrevented;
  }
  querySelectorAll(selector) {
    const list = parseSelector(selector);
    const out = [];
    const walk = (node) => { for (const c of node.children) { if (list.some((complex) => matchComplex(c, complex, complex.length - 1))) out.push(c); walk(c); } };
    walk(this);
    return out;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

class Text extends Node {
  constructor(doc, data) { super(doc); this.data = data; this.nodeType = 3; }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}

class Element extends Node {
  constructor(doc, tag) {
    super(doc);
    this.nodeType = 1; this.localName = tag.toLowerCase(); this.attrs = new Map(); this.style = new Style(); this.shadowRoot = null;
    this.value = ""; this.checked = false; this.disabled = false; this._type = null;
  }
  get tagName() { return this.localName.toUpperCase(); }
  get attributes() { return [...this.attrs].map(([name, value]) => ({name, value})); }
  getAttribute(name) { return this.attrs.has(name) ? this.attrs.get(name) : null; }
  setAttribute(name, value) {
    this.attrs.set(name, String(value));
    if (name === "style") this.style.cssText = value;
    if (name === "value") this.value = String(value);
    if (name === "checked") this.checked = true;
  }
  hasAttribute(name) { return this.attrs.has(name); }
  removeAttribute(name) { this.attrs.delete(name); }
  get id() { return this.getAttribute("id") || ""; }
  set id(v) { this.setAttribute("id", v); }
  get className() { return this.getAttribute("class") || ""; }
  set className(v) { this.setAttribute("class", v); }
  get classList() { return this.className.split(/\s+/).filter(Boolean); }
  get hidden() { return this.hasAttribute("hidden"); }
  set hidden(v) { if (v) this.setAttribute("hidden", ""); else this.removeAttribute("hidden"); }
  get type() { return this.getAttribute("type") ?? (this.localName === "button" ? "submit" : "text"); }
  set type(v) { this.setAttribute("type", v); } // reflected, as in a real DOM
  get previousElementSibling() {
    if (!this.parentNode) return null;
    const siblings = this.parentNode.children;
    return siblings[siblings.indexOf(this) - 1] || null;
  }
  get dataset() { return {}; }
  set onclick(_) { throw new Error("inline handlers are not used by the companion"); }
  set innerHTML(_) { throw new Error("innerHTML is forbidden in the companion"); }
  attachShadow({mode}) { this.shadowRoot = new ShadowRoot(this.ownerDocument, this, mode); return this.shadowRoot; }
  matches(selector) { return parseSelector(selector).some((complex) => matchComplex(this, complex, complex.length - 1)); }
  getBoundingClientRect() { return {width: 100, height: 50, top: 0, left: 0, right: 100, bottom: 50, x: 0, y: 0}; }
}

class ShadowRoot extends Node {
  constructor(doc, host, mode) { super(doc); this.host = host; this.mode = mode; }
}

class Document extends Node {
  constructor() { super(null); this.ownerDocument = this; this.readyState = "complete"; this.activeElement = null; }
  createElement(tag) { return new Element(this, tag); }
  createTextNode(text) { return new Text(this, text); }
  get documentElement() { return this.children[0] || null; }
  get body() { return this.documentElement ? this.documentElement.children.find((c) => c.localName === "body") || null : null; }
  getElementById(id) { return findById(this, id); }
}

function findById(node, id) {
  for (const c of node.children) { if (c.id === id) return c; const hit = findById(c, id); if (hit) return hit; }
  return null;
}

function nth(arg, index) {
  if (arg === "odd") return index % 2 === 1;
  if (arg === "even") return index % 2 === 0;
  const m = /^([+-]?\d*)n([+-]\d+)?$/.exec(arg);
  if (!m) return index === Number(arg);
  const a = m[1] === "" || m[1] === "+" ? 1 : m[1] === "-" ? -1 : Number(m[1]);
  const b = Number(m[2] || 0);
  if (a === 0) return index === b;
  return (index - b) / a >= 0 && Number.isInteger((index - b) / a);
}

function matchCompound(el, c) {
  if (c.tag && el.localName !== c.tag) return false;
  if (c.ids.some((id) => el.id !== id)) return false;
  const classes = el.classList;
  if (c.classes.some((x) => !classes.includes(x))) return false;
  for (const a of c.attrs) {
    const v = el.getAttribute(a.name);
    if (v === null) return false;
    if (a.op === "=" && v !== a.value) return false;
    if (a.op === "~=" && !v.split(/\s+/).includes(a.value)) return false;
    if (a.op === "^=" && !v.startsWith(a.value)) return false;
    if (a.op === "$=" && !v.endsWith(a.value)) return false;
    if (a.op === "*=" && !v.includes(a.value)) return false;
    if (a.op === "|=" && !(v === a.value || v.startsWith(`${a.value}-`))) return false;
  }
  const siblings = el.parentNode ? el.parentNode.children : [el];
  const same = siblings.filter((s) => s.localName === el.localName);
  for (const p of c.pseudos) {
    const ok = {
      "first-child": () => siblings[0] === el, "last-child": () => siblings[siblings.length - 1] === el, "only-child": () => siblings.length === 1,
      "first-of-type": () => same[0] === el, "last-of-type": () => same[same.length - 1] === el, "only-of-type": () => same.length === 1,
      "nth-child": () => nth(p.arg, siblings.indexOf(el) + 1), "nth-of-type": () => nth(p.arg, same.indexOf(el) + 1),
      not: () => !matchCompound(el, p.arg),
    }[p.name];
    if (!ok || !ok()) return false;
  }
  return true;
}

function matchComplex(el, complex, i) {
  if (!el || !(el instanceof Element) || !matchCompound(el, complex[i].compound)) return false;
  if (i === 0) return true;
  const comb = complex[i].combinator;
  if (comb === ">") return matchComplex(el.parentElement, complex, i - 1);
  if (comb === "+") return matchComplex(el.previousElementSibling, complex, i - 1);
  if (comb === "~") { for (let s = el.previousElementSibling; s; s = s.previousElementSibling) if (matchComplex(s, complex, i - 1)) return true; return false; }
  for (let a = el.parentElement; a; a = a.parentElement) if (matchComplex(a, complex, i - 1)) return true;
  return false;
}

/** Minimal parser for the authored fixtures (well-formed, no inline scripts). */
function parseHTML(html) {
  const doc = new Document();
  const stack = [doc];
  const re = /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/([a-zA-Z0-9-]+)\s*>|<([a-zA-Z0-9-]+)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+)/gi;
  let m;
  while ((m = re.exec(html))) {
    const top = stack[stack.length - 1];
    if (m[1]) { const tag = m[1].toLowerCase(); for (let i = stack.length - 1; i > 0; i--) if (stack[i].localName === tag) { stack.length = i; break; } }
    else if (m[2]) {
      const el = doc.createElement(m[2]);
      for (const a of m[3].matchAll(/([^\s=>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) el.setAttribute(a[1].toLowerCase(), a[2] ?? a[3] ?? a[4] ?? "");
      top.append(el);
      if (!VOID.has(el.localName) && !m[0].endsWith("/>")) stack.push(el);
    } else if (m[4] && m[4].trim()) top.append(doc.createTextNode(m[4].replace(/&hellip;/g, "…").replace(/&amp;/g, "&")));
  }
  return doc;
}

function event(type, {isTrusted = true, key} = {}) {
  return {type, isTrusted, key, bubbles: true, defaultPrevented: false, stopped: false,
    preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; }};
}

/** Click as a user would (isTrusted true) or as a page script would (false). */
const userClick = (el) => el.dispatchEvent(event("click", {isTrusted: true}));
const scriptClick = (el) => el.dispatchEvent(event("click", {isTrusted: false}));

/** Every text and attribute string in a subtree, including open/closed shadow roots. */
function allText(node) {
  let out = node instanceof Text ? node.data : "";
  for (const c of node.childNodes) out += allText(c);
  if (node.shadowRoot) out += allText(node.shadowRoot);
  return out;
}

module.exports = {parseHTML, Document, Element, Text, ShadowRoot, event, userClick, scriptClick, allText};
