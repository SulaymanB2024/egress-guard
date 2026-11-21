/* Top-frame content script: applies this site's validated cosmetic rules reversibly and runs the
 * "Block this element" picker. Page data is only ever written with textContent. The hide/restore
 * record pattern and protected-structure checks come from the earlier page-controls candidate. */
(function (root) {
  "use strict";
  if (root.__EGCosmetic) return;
  // Firefox exposes promise-based `browser`; Chrome exposes `chrome` and needs sendResponse for async replies.
  const B = root.browser || root.chrome;
  // Chrome now also exposes browser.*. Detect the build manifest rather than treating
  // that namespace as Firefox; otherwise Chrome would reintroduce page-visible styles.
  const chromeStyle = Boolean(root.chrome) && !(B.runtime.getManifest?.().browser_specific_settings?.gecko);
  const picker = root.EGPicker;
  const MAX_PER_RULE = 25;
  const MAX_TASKS_PER_TURN = 12;
  const MAX_DIRTY_ROOTS = 32;
  const MAX_RECORDS = 500;
  const MAX_WALK = 3000;
  const PROTECTED_TAGS = new Set(["html", "head", "body", "main", "nav", "header", "footer", "form", "video", "audio", "dialog", "input", "textarea", "select", "button"]);
  const PROTECTED_INSIDE = new Set(["main", "nav", "form", "video", "audio", "input", "textarea", "select", "button", "dialog", "iframe"]);
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

  let rules = [], scoped = [], site = null, paused = false, observer = null, timer = null;
  let fullScan = false, tasks = [], taskAt = 0;
  const dirtyRoots = new Set();
  // Built-in ad-slot hiding (Chrome build only: core/cosmetic.js is not in the Firefox manifest).
  // Requested at document_start, removed again if this site has it switched off.
  const generic = root.EGCosmeticList || null;
  const semantic = root.EGSemantic || null;
  // "Restore this page" lifts the stylesheet for this load. Discovery backpressure
  // does not undo this independent, browser-enforced CSS policy.
  let genericStyle = null, genericWanted = Boolean(generic), genericPaused = false;
  let styleTarget = null, styleWork = Promise.resolve(), styleError = null, styleQueued = 0;
  const records = new Map();           // node -> record
  let revealed = new WeakSet();        // shown by the user for this page load
  const protectedHits = new Set();     // rule ids that matched protected structure
  const overbroad = new Set();         // rule ids matching more than MAX_PER_RULE elements
  let pick = null, toast = null;
  const documentId = root.crypto && typeof root.crypto.randomUUID === "function" ? root.crypto.randomUUID() : `doc-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  let domGeneration = 0, nextCandidate = 0, semanticMuted = false;
  const candidates = new Map();
  const MAX_CANDIDATES = 24;
  const MAX_CANDIDATE_AGE = 120000;
  const currentHref = () => root.location && typeof root.location.href === "string" ? root.location.href : "";
  let lastHref = currentHref();

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
    if (PROTECTED_TAGS.has(node.localName) || protectedRole(node) || editable(node)) return false;
    if (document.activeElement && document.activeElement !== document.body && node.contains(document.activeElement)) return false;
    const stack = [...node.children];
    let seen = 0;
    while (stack.length) {
      const child = stack.pop();
      if (++seen > MAX_WALK) return false;
      if (PROTECTED_INSIDE.has(child.localName) || protectedRole(child) || editable(child)) return false;
      stack.push(...child.children);
    }
    return true;
  }
  const protectedRole = (n) => String(n.getAttribute("role") || "").split(/\s+/).some((r) => PROTECTED_ROLES.has(r));
  const editable = (n) => n.isContentEditable === true || (n.getAttribute("contenteditable") !== null && n.getAttribute("contenteditable") !== "false");

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
    record.label.textContent = hidden ? (record.source === "native" || record.source === "model" ? "Paid placement hidden on this page." : record.source === "scoped" ? "Hidden by a rule for this site." : "Hidden by your rule for this site.") : "Shown for this page load.";
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
    if (records.size >= MAX_RECORDS) return false;
    const {node: placeholder, shadow} = uiHost("egress-guard-hidden");
    placeholder.style.setProperty("display", "block", "important");
    placeholder.style.setProperty("margin", "6px 0", "important");
    const row = element("div", null, "row");
    const label = element("span", null, "label");
    const button = element("button");
    button.type = "button";
    const record = {node, placeholder, label, button, ruleId: rule.id, source: rule.source || "user", fingerprint: rule.fingerprint || null, hidden: false, display: "", priority: ""};
    button.addEventListener("click", () => { if (records.get(node) === record && (record.hidden || safe(node))) setHidden(record, !record.hidden); });
    row.append(label, button);
    shadow.append(row);
    node.before(placeholder);
    records.set(node, record);
    setHidden(record, true);
    return true;
  }

  const activeRules = () => rules.concat(genericWanted && !genericPaused ? scoped : []);
  function observe() {
    if (observer && !paused && document.documentElement) observer.observe(document.documentElement, {
      childList: true, subtree: true, characterData: true, attributes: true,
      attributeFilter: [...new Set(["class", "id", "hidden", "role", "contenteditable", "aria-label", "href", "type", "autocomplete"].concat(attrNames()))],
    });
  }
  function enqueue(scope = document, complete = false) {
    if (complete || scope === document || dirtyRoots.size >= MAX_DIRTY_ROOTS) { fullScan = true; dirtyRoots.clear(); }
    else if (!fullScan && scope) {
      for (const existing of dirtyRoots) if (existing.contains && existing.contains(scope)) return;
      for (const existing of dirtyRoots) if (scope.contains && scope.contains(existing)) dirtyRoots.delete(existing);
      dirtyRoots.add(scope);
    }
    if (!paused && timer === null) timer = setTimeout(scan, 150);
  }
  function prepareTasks() {
    const scopes = fullScan ? [document] : [...dirtyRoots].filter((n) => n.isConnected);
    fullScan = false; dirtyRoots.clear();
    const live = new Map(activeRules().map((r) => [r.id, r]));
    // Checking records is bounded and separate from finding new matches. Workload never restores them en masse.
    for (const record of records.values()) tasks.push({kind: "record", record, rule: live.get(record.ruleId)});
    for (const scope of scopes) {
      for (const rule of live.values()) tasks.push({kind: "rule", scope, rule});
      if (semantic && genericWanted && !genericPaused && !semanticMuted) tasks.push({kind: "native", scope});
    }
  }
  function scan() {
    timer = null;
    if (paused) return;
    if (observer) observer.disconnect();
    if (taskAt >= tasks.length) { tasks = []; taskAt = 0; prepareTasks(); }
    const started = Date.now();
    for (let count = 0; taskAt < tasks.length && count < MAX_TASKS_PER_TURN && Date.now() - started < 12; count++) {
      const task = tasks[taskAt++];
      if (task.kind === "record") {
        const {record, rule} = task;
        if (records.get(record.node) !== record) continue;
        const semanticRecord = record.source === "native" || record.source === "model";
        if (!safe(record.node) || record.placeholder.parentElement !== record.node.parentElement ||
            (semanticRecord ? record.stale || fingerprint(record.node) !== record.fingerprint : !rule || !record.node.matches(rule.selector))) release(record);
      } else if (task.kind === "native") {
        if (semanticMuted || !genericWanted || genericPaused || sensitivePage()) continue;
        for (const node of collectCards(task.scope, true)) {
          if (records.has(node) || revealed.has(node) || !safe(node)) continue;
          const data = describeCard(node);
          if (data && data.classification === "paid-placement" && data.confidence === "high") {
            hide(node, {id: `native-${++nextCandidate}`, source: "native", fingerprint: fingerprint(node)});
          }
        }
      } else {
        const {rule, scope} = task;
        if (scope !== document && !scope.isConnected) continue;
        // A task queued before a setting/rule change cannot resurrect a removed policy.
        if (!activeRules().some((r) => r.id === rule.id && r.selector === rule.selector)) continue;
        let nodes;
        try { nodes = [...(scope.querySelectorAll ? scope.querySelectorAll(rule.selector) : [])]; if (scope.nodeType === 1 && scope.matches(rule.selector)) nodes.unshift(scope); } catch { continue; }
        if (nodes.length > MAX_PER_RULE) { overbroad.add(rule.id); continue; }
        overbroad.delete(rule.id);
        for (const node of nodes) {
          if (records.has(node) || revealed.has(node)) continue;
          if (!safe(node)) { protectedHits.add(rule.id); continue; }
          hide(node, rule);
        }
      }
    }
    observe();
    if (taskAt < tasks.length || fullScan || dirtyRoots.size) timer = setTimeout(scan, 32);
  }

  function attrNames() {
    const names = new Set();
    for (const r of activeRules()) for (const m of r.selector.matchAll(/\[([a-z][a-z0-9_:-]*)/g)) names.add(m[1]);
    return [...names].slice(0, 100);
  }

  function onMutations(mutations) {
    if (paused) return;
    if (lastHref !== currentHref()) {
      lastHref = currentHref(); invalidateCandidates();
      for (const record of [...records.values()]) if (record.source === "native" || record.source === "model") release(record);
    }
    for (const m of mutations) {
      if (inUi(m.target)) continue;
      const target = m.target.nodeType === 1 ? m.target : m.target.parentElement;
      if (!target) continue;
      const changes = (node) => node === target || node.contains(target) || (m.type === "attributes" && target.contains(node)) ||
        [...(m.addedNodes || []), ...(m.removedNodes || [])].some((n) => n === node || n.contains && n.contains(node));
      for (const c of candidates.values()) if (changes(c.node)) c.stale = true;
      for (const record of records.values()) if ((record.source === "native" || record.source === "model") && changes(record.node)) record.stale = true;
      // Preserve scoped/sibling/nth selectors by scanning the changed node's parent subtree.
      enqueue(target.parentElement || target);
    }
  }

  function setRules(list) {
    rules = Array.isArray(list) ? list.filter((r) => r && r.kind === "cosmetic" && typeof r.selector === "string" && typeof r.id === "string") : [];
    protectedHits.clear();
    applyGeneric(); // Recovery broadcasts retry a previously rejected stylesheet operation.
    if (!observer && (rules.length || scoped.length || semantic) && typeof root.MutationObserver === "function") observer = new root.MutationObserver(onMutations);
    tasks = []; taskAt = 0; fullScan = true; dirtyRoots.clear();
    clearTimeout(timer); timer = null;
    scan();
    return status();
  }

  function applyGeneric() {
    const on = Boolean(generic) && genericWanted && !genericPaused;
    if (chromeStyle && generic) {
      if (styleTarget === on && (styleQueued > 0 || !styleError)) return;
      styleTarget = on;
      styleQueued++;
      // Only the worker can insert a USER-origin sheet. No distinctive style element is
      // exposed in Chrome's shared page DOM and content cannot submit arbitrary CSS.
      styleWork = styleWork.then(async () => {
        try {
          const reply = await B.runtime.sendMessage({type: "cosmetic-style", on});
          if (!reply || reply.ok !== true || reply.on !== on) throw new Error("The built-in stylesheet could not be applied.");
          genericStyle = on ? {remote: true} : null; styleError = null;
        } catch (e) { styleError = String(e && e.message || e); }
        finally { styleQueued--; }
      });
      return;
    }
    if (on && !genericStyle) {
      genericStyle = document.createElement("style");
      genericStyle.setAttribute(UI, "");
      genericStyle.textContent = generic.stylesheet();
      (document.head || document.documentElement).append(genericStyle);
    } else if (!on && genericStyle) {
      genericStyle.remove();
      genericStyle = null;
    }
  }

  function setGeneric(on) {
    genericWanted = Boolean(on); applyGeneric();
    if (!genericWanted) {
      // Whole-site Pause uses this same switch. Previously selected semantic hides
      // must not survive a user action that restores this site's automatic hiding.
      if (observer) observer.disconnect();
      for (const record of [...records.values()]) if (record.source === "native" || record.source === "model") release(record);
      invalidateCandidates(); observe();
    }
    enqueue(document, true); return status();
  }

  /** Ad slots the built-in stylesheet hides right now (counted only when the popup asks). */
  function genericCount() {
    if (!genericStyle) return 0;
    let count = 0;
    for (const selector of generic.GENERIC_SELECTORS) { try { count += document.querySelectorAll(selector).length; } catch {} }
    return count;
  }

  let pausedReason = "";
  function restorePage(reason = "Restored for this page load.") {
    paused = true; pausedReason = reason;
    if (observer) observer.disconnect();
    clearTimeout(timer); timer = null;
    tasks = []; taskAt = 0; fullScan = false; dirtyRoots.clear();
    invalidateCandidates();
    for (const record of [...records.values()]) release(record);
    revealed = new WeakSet();
    applyGeneric();
    return status();
  }

  function resume() { paused = false; pausedReason = ""; genericPaused = false; semanticMuted = false; applyGeneric(); fullScan = true; scan(); return status(); }

  function status() {
    const values = [...records.values()];
    return {
      site, paused, reason: pausedReason, rules: rules.length,
      hidden: values.filter((r) => r.hidden).length, shown: values.filter((r) => !r.hidden).length,
      protectedRules: [...protectedHits], overbroadRules: [...overbroad], picking: Boolean(pick),
      generic: generic ? {available: true, on: Boolean(genericStyle), wanted: genericWanted, slots: genericCount(), error: styleError, pending: styleQueued > 0, scopedRules: scoped.length} : {available: false},
      semantic: {available: Boolean(semantic), hidden: values.filter((r) => r.hidden && (r.source === "native" || r.source === "model")).length, paused: semanticMuted, documentId, domGeneration},
      workPending: taskAt < tasks.length || fullScan || dirtyRoots.size > 0,
    };
  }

  // ---- Bounded native-ad candidates --------------------------------------------------------
  const CARD_TAGS = new Set(["article", "li", "div", "section"]);
  const TEXT_SKIP = new Set(["script", "style", "noscript", "template", "form", "input", "textarea", "select", "iframe", "svg"]);
  function textOf(node, maxChars = 1200, maxNodes = 160) {
    const stack = [node]; let text = "", seen = 0;
    while (stack.length) {
      const n = stack.pop();
      if (++seen > maxNodes) return {text: text.trim(), overflow: true};
      if (n.nodeType === 3) { text += ` ${n.textContent || ""}`; if (text.length > maxChars) return {text: text.slice(0, maxChars).trim(), overflow: true}; }
      else if (n.nodeType === 1 && !inUi(n) && !TEXT_SKIP.has(n.localName) && !editable(n) && !protectedRole(n)) stack.push(...[...n.childNodes].reverse());
    }
    return {text: text.replace(/\s+/g, " ").trim(), overflow: false};
  }
  function fingerprint(node) {
    const value = textOf(node);
    const stack = [node], structure = []; let seen = 0;
    while (stack.length && seen++ < 160) {
      const n = stack.pop();
      if (n.nodeType !== 1 || inUi(n) || TEXT_SKIP.has(n.localName) || editable(n)) continue;
      structure.push([n.localName, n.getAttribute("role"), n.getAttribute("aria-label"), n.getAttribute("href"), n.className || ""]);
      stack.push(...n.children);
    }
    return JSON.stringify([node.id || "", value.overflow, value.text, structure]);
  }
  function sensitivePage() {
    if (!semantic) return "Native-ad classification is unavailable.";
    if (semantic.sensitiveLocation(currentHref())) return "Classification is disabled on account, message, payment, medical and other sensitive pages.";
    try { if (document.querySelector('input[type="password"], input[autocomplete="current-password"], input[autocomplete="new-password"]')) return "Classification is disabled on pages with password fields."; } catch { /* no usable document */ }
    return null;
  }
  function peers(node) {
    if (!node.parentElement) return 0;
    const classes = [...node.classList].filter((c) => !c.startsWith("eg-"));
    return [...node.parentElement.children].slice(0, 100).filter((n) => n !== node && n.localName === node.localName &&
      (node.localName === "article" || node.localName === "li" || classes.some((c) => n.classList.includes ? n.classList.includes(c) : n.classList.contains(c)))).length;
  }
  function describeCard(node) {
    const value = textOf(node);
    if (value.overflow || value.text.length < 12 || !CARD_TAGS.has(node.localName)) return null;
    const stack = [node], disclosures = [], relations = new Set(); let seen = 0, hasLink = false, nestedCards = 0;
    while (stack.length && seen++ < 160) {
      const n = stack.pop();
      if (n.nodeType !== 1 || inUi(n) || TEXT_SKIP.has(n.localName) || editable(n)) continue;
      if (n !== node && (["article", "li"].includes(n.localName) || /(?:^|\s)(?:article|listitem)(?:\s|$)/.test(n.getAttribute("role") || ""))) nestedCards++;
      const label = n.getAttribute("aria-label") || "";
      // Headlines are not disclosures: an article entitled "Sponsored" is an ordinary article.
      let heading = false;
      for (let a = n; a && a !== node.parentElement; a = a.parentElement) if (/^h[1-6]$/.test(a.localName)) { heading = true; break; }
      if (!heading && semantic.disclosure(label)) disclosures.push(label);
      const inside = [...n.children]; let checked = 0;
      while (!heading && inside.length && checked++ < 20) { const child = inside.pop(); if (/^h[1-6]$/.test(child.localName)) heading = true; else inside.push(...child.children); }
      if (!heading && ["span", "small", "a", "label", "div", "p"].includes(n.localName)) {
        const short = textOf(n, 80, 20);
        if (!short.overflow && semantic.disclosure(short.text)) disclosures.push(short.text);
      }
      if (n.localName === "a" && n.hasAttribute("href")) {
        hasLink = true;
        try {
          const dest = new URL(n.getAttribute("href"), currentHref() || `https://${site || "invalid.example"}/`);
          const own = root.location && root.location.hostname || site;
          if (/^https?:$/.test(dest.protocol)) relations.add(dest.hostname === own ? "same-host" : "other-host");
        } catch { /* only a relationship, never a URL, leaves this adapter */ }
      }
      stack.push(...n.children);
    }
    const structure = {tag: node.localName, repeatedPeers: peers(node), hasLink, textLength: value.text.length, nestedCards};
    const protectedNode = !safe(node);
    const result = semantic.classify({disclosures, structure, protected: protectedNode});
    return {
      kind: "card", disclosures: [...new Set(disclosures)].slice(0, 4).map((s) => s.slice(0, 80)),
      accessibleLabel: semantic.sanitizeText(node.getAttribute("aria-label") || "", 160), structure,
      destinationRelation: relations.size > 1 ? "mixed" : [...relations][0] || "none",
      classification: result.category, confidence: result.confidence,
      // Protected cards never export their text. No form values, attributes or URL values are exported.
      ...(protectedNode ? {} : {text: semantic.sanitizeText(value.text, 400)}),
    };
  }
  function collectCards(scope, disclosuresOnly = false) {
    if (!semantic) return [];
    const found = new Set(), stack = [scope]; let seen = 0, considered = 0;
    while (stack.length && seen++ < 2000 && found.size < MAX_CANDIDATES) {
      const n = stack.pop();
      if (n.nodeType !== 1 && n !== document) continue;
      if (n.nodeType === 1 && (inUi(n) || TEXT_SKIP.has(n.localName) || editable(n) || n.hidden || n.style.getPropertyValue("display") === "none")) continue;
      if (n.nodeType === 1 && CARD_TAGS.has(n.localName) && peers(n) >= 1 && !records.has(n) && !revealed.has(n)) {
        if (++considered > 100) break;
        const data = describeCard(n);
        // Prefer card boundaries over a repeated column/feed that mixes several cards.
        if (data && !data.structure.nestedCards && (!disclosuresOnly || data.classification === "paid-placement")) { found.add(n); continue; }
      }
      stack.push(...[...n.children].reverse());
    }
    return [...found];
  }
  function invalidateCandidates() { candidates.clear(); domGeneration++; }
  function semanticCandidates() {
    invalidateCandidates();
    const disabledReason = paused ? "Hiding is paused for this page." : sensitivePage();
    const response = {ok: true, documentId, domGeneration, site, candidates: []};
    if (disabledReason) return {...response, disabledReason};
    lastHref = currentHref();
    for (const node of collectCards(document)) {
      const data = describeCard(node);
      if (!data) continue;
      const id = `c${++nextCandidate}`;
      candidates.set(id, {node, fingerprint: fingerprint(node), data, href: lastHref, at: Date.now(), stale: false});
      response.candidates.push({id, ...data});
    }
    return response;
  }
  function semanticApply(message) {
    if (!semantic || paused || sensitivePage()) return {ok: false, error: "Classification cannot be applied on this page."};
    if (message.documentId !== documentId || message.domGeneration !== domGeneration || !Array.isArray(message.labels) || message.labels.length > MAX_CANDIDATES) return {ok: false, error: "The candidate snapshot is stale or invalid. Scan this page again."};
    const used = new Set(), pending = [];
    for (const label of message.labels) {
      if (!label || Object.keys(label).some((k) => k !== "id" && k !== "category") || typeof label.id !== "string" || used.has(label.id) || !semantic.CATEGORIES.includes(label.category)) return {ok: false, error: "Only unique candidate IDs and supported categories are accepted."};
      used.add(label.id); pending.push(label);
    }
    let applied = 0; const rejected = [];
    if (observer) observer.disconnect();
    for (const label of pending) {
      const c = candidates.get(label.id);
      if (!c || c.stale || c.href !== currentHref() || Date.now() - c.at > MAX_CANDIDATE_AGE || !c.node.isConnected || fingerprint(c.node) !== c.fingerprint) { rejected.push({id: label.id, reason: "stale"}); continue; }
      if (label.category !== "paid-placement") continue;
      if (c.data.classification === "essential-commerce" || !safe(c.node) || revealed.has(c.node)) { rejected.push({id: label.id, reason: "protected"}); continue; }
      if (!records.has(c.node) && hide(c.node, {id: `model-${label.id}`, source: "model", fingerprint: c.fingerprint})) applied++;
      candidates.delete(label.id);
    }
    observe();
    return {ok: true, applied, rejected, ...status().semantic};
  }
  function semanticRestore() {
    semanticMuted = true; invalidateCandidates();
    if (observer) observer.disconnect();
    for (const record of [...records.values()]) if (record.source === "native" || record.source === "model") { revealed.add(record.node); release(record); }
    observe();
    return {ok: true, ...status().semantic};
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
      // A shared attribute is no stronger evidence than a shared class. Multiple matches
      // require independent paid-placement evidence; otherwise keep searching for one card.
      if (matches.length > 1 && !matches.every((n) => semantic && describeCard(n)?.classification === "paid-placement")) continue;
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
  function onMessage(message) {
    if (!message || typeof message !== "object") return undefined;
    switch (message.type) {
      case "rules-changed": return Promise.resolve(setRules(message.rules));
      case "status": return Promise.resolve(status());
      case "restore-page": genericPaused = true; return Promise.resolve(restorePage());
      case "resume": return Promise.resolve(resume());
      case "start-picker": startPicker(); return Promise.resolve(status());
      case "generic": return Promise.resolve(setGeneric(message.on));
      case "semantic-candidates": return Promise.resolve(semanticCandidates());
      case "semantic-apply": return Promise.resolve(semanticApply(message));
      case "semantic-restore": return Promise.resolve(semanticRestore());
      default: return undefined;
    }
  }
  B.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender && sender.id && B.runtime.id && sender.id !== B.runtime.id) return undefined;
    const reply = onMessage(message);
    if (!reply || !chromeStyle) return reply;
    reply.then(sendResponse, () => sendResponse(null));
    return true;
  });

  applyGeneric();
  document.addEventListener("focusin", () => {
    for (const record of [...records.values()]) if (document.activeElement && record.node.contains(document.activeElement)) release(record);
  }, true);
  const ready = B.runtime.sendMessage({type: "page-rules"}).then((reply) => {
    site = reply && reply.site ? reply.site : null;
    scoped = generic && generic.scopedRules ? generic.scopedRules(root.location && root.location.hostname || site) : [];
    if (reply && reply.generic === false) setGeneric(false);
    const apply = () => setRules(reply && reply.rules);
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", apply, {once: true});
    else apply();
  }).catch(() => {});

  root.__EGCosmetic = Object.freeze({ready, setRules, setGeneric, restorePage, resume, status, startPicker, stopPicker, proposal, commit, undo,
    semanticCandidates, semanticApply, semanticRestore});
})(globalThis);
