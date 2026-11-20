/* Top-frame content script: applies this site's validated cosmetic rules reversibly and runs the
 * "Block this element" picker. Page data is only ever written with textContent. The hide/restore
 * record pattern and protected-structure checks come from the earlier page-controls candidate. */
(function (root) {
  "use strict";
  if (root.__EGCosmetic) return;
  const B = root.browser;
  const picker = root.EGPicker;
  const MAX_PER_RULE = 25;
  const MAX_SCANS_PER_MINUTE = 40;
  const MAX_WALK = 3000;
  const PROTECTED_TAGS = new Set(["html", "head", "body", "main", "nav", "header", "footer", "form", "video", "audio", "dialog", "input", "textarea", "select", "button"]);
  const PROTECTED_INSIDE = new Set(["main", "nav", "form", "video", "audio", "input", "textarea", "select", "dialog", "iframe"]);
  const PROTECTED_ROLES = new Set(["main", "navigation", "dialog", "alertdialog", "textbox", "searchbox", "combobox"]);
  const UI = "data-eg-page-ui";
  const CSS = `
    :host { all: initial; display: block; font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1b1f1d; }
    * { box-sizing: border-box; }
    .row { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 10px; padding: 6px 10px; background: #f4f4f0; border: 1px dashed #b8beb6; border-radius: 6px; }
    .label { flex: 1; min-width: 120px; }
    .panel { background: #fff; border: 1px solid #b8beb6; border-radius: 8px; box-shadow: 0 4px 20px #0002; padding: 10px 12px; max-width: 360px; }
    .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; background: #f4f4f0; padding: 2px 4px; border-radius: 4px; }
    p { margin: 0 0 8px; }
    button { font: inherit; font-weight: 600; border: 1px solid #8a948c; border-radius: 5px; padding: 4px 10px; min-height: 32px; color: #183d2e; background: #fff; cursor: pointer; margin-right: 6px; }
    button:focus-visible { outline: 3px solid #2f6f58; outline-offset: 2px; }
  `;

  let rules = [], site = null, paused = false, observer = null, timer = null, scans = [];
  const records = new Map();           // node -> record
  let revealed = new WeakSet();        // shown by the user for this page load
  const protectedHits = new Set();     // rule ids that matched protected structure
  const overbroad = new Set();         // rule ids matching more than MAX_PER_RULE elements
  let pick = null, toast = null;

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function uiHost(tag) {
    const node = document.createElement(tag);
    node.setAttribute(UI, "");
    const shadow = node.attachShadow({mode: "closed"});
    shadow.append(element("style", CSS));
    return {node, shadow};
  }

  // Walks out of shadow roots too, so clicks inside the companion's own UI are recognized.
  const inUi = (node) => {
    for (let n = node; n; n = n.parentElement || (n.parentNode && n.parentNode.host) || null) if (n.hasAttribute && n.hasAttribute(UI)) return true;
    return false;
  };

  /** Never hide page structure, media, forms or editors, or anything containing them or focus. */
  function safe(node) {
    if (!node.isConnected || !node.parentElement || inUi(node)) return false;
    if (PROTECTED_TAGS.has(node.localName) || PROTECTED_ROLES.has(node.getAttribute("role"))) return false;
    if (document.activeElement && document.activeElement !== document.body && node.contains(document.activeElement)) return false;
    const stack = [...node.children];
    let seen = 0;
    while (stack.length) {
      const child = stack.pop();
      if (++seen > MAX_WALK) return false;
      if (PROTECTED_INSIDE.has(child.localName) || PROTECTED_ROLES.has(child.getAttribute("role"))) return false;
      const editable = child.getAttribute("contenteditable");
      if (editable !== null && editable !== "false") return false;
      stack.push(...child.children);
    }
    return true;
  }

  function ownsDisplay(record) {
    return record.node.style.getPropertyValue("display") === "none" && record.node.style.getPropertyPriority("display") === "important";
  }

  function setHidden(record, hidden) {
    if (hidden) {
      revealed.delete(record.node);
      record.display = record.node.style.getPropertyValue("display");
      record.priority = record.node.style.getPropertyPriority("display");
      record.node.style.setProperty("display", "none", "important");
    } else {
      revealed.add(record.node);
      restoreDisplay(record);
    }
    record.hidden = hidden;
    record.label.textContent = hidden ? "Hidden by your rule for this site." : "Shown for this page load.";
    record.button.textContent = hidden ? "Show" : "Hide again";
    record.button.setAttribute("aria-expanded", String(!hidden));
  }

  function restoreDisplay(record) {
    if (!ownsDisplay(record)) return;
    if (record.display) record.node.style.setProperty("display", record.display, record.priority);
    else record.node.style.removeProperty("display");
  }

  function release(record) {
    restoreDisplay(record);
    record.placeholder.remove();
    records.delete(record.node);
  }

  function hide(node, rule) {
    const {node: placeholder, shadow} = uiHost("egress-guard-hidden");
    placeholder.style.setProperty("display", "block", "important");
    placeholder.style.setProperty("margin", "6px 0", "important");
    const row = element("div", null, "row");
    const label = element("span", null, "label");
    const button = element("button");
    button.type = "button";
    const record = {node, placeholder, label, button, ruleId: rule.id, hidden: false, display: "", priority: ""};
    button.addEventListener("click", () => { if (records.get(node) === record) setHidden(record, !record.hidden); });
    row.append(label, button);
    shadow.append(row);
    node.before(placeholder);
    records.set(node, record);
    setHidden(record, true);
  }

  function scan() {
    timer = null;
    if (paused) return;
    const now = Date.now();
    scans = scans.filter((t) => now - t < 60000);
    if (scans.length >= MAX_SCANS_PER_MINUTE) { restorePage("This page changes too often; hiding paused."); return; }
    scans.push(now);
    if (observer) observer.disconnect();
    const live = new Map(rules.map((r) => [r.id, r]));
    for (const record of [...records.values()]) {
      const rule = live.get(record.ruleId);
      if (!rule || !record.node.isConnected || !record.node.matches(rule.selector) || record.placeholder.parentElement !== record.node.parentElement) release(record);
    }
    for (const rule of rules) {
      let nodes;
      try { nodes = [...document.querySelectorAll(rule.selector)]; } catch { continue; }
      if (nodes.length > MAX_PER_RULE) { overbroad.add(rule.id); continue; }
      overbroad.delete(rule.id);
      for (const node of nodes) {
        if (records.has(node) || revealed.has(node)) continue;
        if (!safe(node)) { protectedHits.add(rule.id); continue; }
        hide(node, rule);
      }
    }
    if (observer) observer.observe(document.documentElement, {childList: true, subtree: true, attributes: true, attributeFilter: ["class", "id", "hidden"].concat(attrNames())});
  }

  function attrNames() {
    const names = new Set();
    for (const r of rules) for (const m of r.selector.matchAll(/\[([a-z][a-z0-9_:-]*)/g)) names.add(m[1]);
    return [...names].slice(0, 20);
  }

  function onMutations(mutations) {
    if (paused || timer !== null) return;
    if (mutations.some((m) => !inUi(m.target))) timer = setTimeout(scan, 150);
  }

  function setRules(list) {
    rules = Array.isArray(list) ? list.filter((r) => r && r.kind === "cosmetic" && typeof r.selector === "string" && typeof r.id === "string") : [];
    protectedHits.clear();
    if (!observer && rules.length && typeof root.MutationObserver === "function") observer = new root.MutationObserver(onMutations);
    scan();
    return status();
  }

  let pausedReason = "";
  function restorePage(reason = "Restored for this page load.") {
    paused = true; pausedReason = reason;
    if (observer) observer.disconnect();
    clearTimeout(timer); timer = null;
    for (const record of [...records.values()]) release(record);
    revealed = new WeakSet();
    return status();
  }

  function resume() { paused = false; pausedReason = ""; scan(); return status(); }

  function status() {
    const values = [...records.values()];
    return {
      site, paused, reason: pausedReason, rules: rules.length,
      hidden: values.filter((r) => r.hidden).length, shown: values.filter((r) => !r.hidden).length,
      protectedRules: [...protectedHits], overbroadRules: [...overbroad], picking: Boolean(pick),
    };
  }

  // ---- "Block this element" -------------------------------------------------
  function describe(node) {
    const ancestry = [];
    for (let n = node, depth = 0; n && n.localName !== "body" && depth < 5; n = n.parentElement, depth++) {
      let index = 1;
      for (let s = n.previousElementSibling; s; s = s.previousElementSibling) if (s.localName === n.localName) index++;
      ancestry.push({tag: n.localName, id: n.id || "", index});
      if (depth > 0 && n.id) break;
    }
    return {
      tag: node.localName, id: node.id || "", classes: [...node.classList],
      attrs: [...node.attributes].filter((a) => a.name.startsWith("data-")).map((a) => ({name: a.name, value: a.value})), ancestry,
    };
  }

  /** First candidate that matches the element, at most MAX_PER_RULE elements, and nothing protected. */
  function proposal(node, {positional = true} = {}) {
    for (const selector of picker.candidates(describe(node))) {
      if (!positional && selector.includes(":nth-of-type(")) continue;
      let matches;
      try { matches = [...document.querySelectorAll(selector)]; } catch { continue; }
      if (!matches.includes(node) || matches.length > MAX_PER_RULE || !matches.every(safe)) continue;
      return {selector, count: matches.length};
    }
    return null;
  }

  function targetFrom(event) {
    for (let n = event.target; n && n !== document.body; n = n.parentElement) {
      if (n.nodeType === 1 && !inUi(n)) return n;
    }
    return null;
  }

  function startPicker() {
    stopPicker();
    const {node: host, shadow} = uiHost("egress-guard-picker");
    host.style.cssText = "position:fixed!important;left:16px!important;bottom:16px!important;z-index:2147483647!important;display:block!important";
    const panel = element("section", null, "panel");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Block an element");
    const text = element("p", "Click the ad or element to block on this site. Press Escape to cancel.");
    const code = element("p", "", "code");
    code.hidden = true;
    const actions = element("div");
    const create = element("button", "Create rule"); create.type = "button"; create.hidden = true;
    const cancel = element("button", "Cancel"); cancel.type = "button";
    actions.append(create, cancel);
    panel.append(text, code, actions);
    shadow.append(panel);
    document.documentElement.append(host);
    pick = {host, text, code, create, proposal: null, chosen: null};
    cancel.addEventListener("click", () => stopPicker());
    create.addEventListener("click", (event) => {
      if (event.isTrusted !== true || !pick || !pick.proposal) return; // only a real user activation creates a rule
      commit(pick.proposal.selector);
    });
    document.addEventListener("click", onPickClick, true);
    document.addEventListener("keydown", onPickKey, true);
  }

  function onPickClick(event) {
    if (!pick || inUi(event.target)) return;
    event.preventDefault(); event.stopPropagation();
    if (event.isTrusted !== true) return;
    const node = targetFrom(event);
    if (!node) return;
    // Prefer the nearest container with an attribute or id (the ad card, not its heading);
    // fall back to a position under an id'd ancestor for the clicked element itself.
    let result = null;
    for (let n = node, depth = 0; n && n !== document.body && !result && depth < 6; n = n.parentElement, depth++) {
      if (safe(n)) result = proposal(n, {positional: false});
    }
    if (!result && safe(node)) result = proposal(node);
    pick.proposal = result;
    if (!result) {
      pick.text.textContent = "No specific, safe rule fits that element. Try a different spot, or Cancel.";
      pick.code.hidden = true; pick.create.hidden = true;
      return;
    }
    pick.text.textContent = `Hide ${result.count === 1 ? "this element" : `these ${result.count} elements`} on ${site || "this site"} from now on?`;
    pick.code.textContent = result.selector;
    pick.code.hidden = false; pick.create.hidden = false;
  }

  function onPickKey(event) { if (pick && event.key === "Escape") stopPicker(); }

  function stopPicker() {
    document.removeEventListener("click", onPickClick, true);
    document.removeEventListener("keydown", onPickKey, true);
    if (pick) pick.host.remove();
    pick = null;
  }

  async function commit(selector) {
    stopPicker();
    const reply = await B.runtime.sendMessage({type: "add-cosmetic", selector});
    if (!reply || reply.error || !reply.value) { showToast(reply && reply.error ? reply.error : "The rule was not saved.", null); return status(); }
    if (!rules.some((r) => r.id === reply.value.id)) setRules([...rules, reply.value]);
    showToast("Rule added for this site.", reply.value.id);
    return status();
  }

  async function undo(id) {
    const reply = await B.runtime.sendMessage({type: "undo-cosmetic", id});
    setRules(rules.filter((r) => r.id !== id));
    clearToast();
    return reply;
  }

  function showToast(message, ruleId) {
    clearToast();
    const {node: host, shadow} = uiHost("egress-guard-toast");
    host.style.cssText = "position:fixed!important;left:16px!important;bottom:16px!important;z-index:2147483647!important;display:block!important";
    const panel = element("section", null, "panel");
    panel.setAttribute("role", "status");
    panel.append(element("p", message));
    if (ruleId) {
      const button = element("button", "Undo"); button.type = "button";
      button.addEventListener("click", () => undo(ruleId));
      panel.append(button);
    }
    const close = element("button", "Dismiss"); close.type = "button";
    close.addEventListener("click", clearToast);
    panel.append(close);
    shadow.append(panel);
    document.documentElement.append(host);
    toast = {host, ruleId};
  }

  function clearToast() { if (toast) toast.host.remove(); toast = null; }

  // ---- wiring ---------------------------------------------------------------
  B.runtime.onMessage.addListener((message) => {
    if (!message || typeof message !== "object") return undefined;
    switch (message.type) {
      case "rules-changed": return Promise.resolve(setRules(message.rules));
      case "status": return Promise.resolve(status());
      case "restore-page": return Promise.resolve(restorePage());
      case "resume": return Promise.resolve(resume());
      case "start-picker": startPicker(); return Promise.resolve(status());
      default: return undefined;
    }
  });

  const ready = B.runtime.sendMessage({type: "page-rules"}).then((reply) => {
    site = reply && reply.site ? reply.site : null;
    const apply = () => setRules(reply && reply.rules);
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", apply, {once: true});
    else apply();
  }).catch(() => {});

  root.__EGCosmetic = Object.freeze({ready, setRules, restorePage, resume, status, startPicker, stopPicker, proposal, commit, undo});
})(globalThis);
