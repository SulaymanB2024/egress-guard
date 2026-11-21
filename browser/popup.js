/* Popup: one answer first (requests blocked on this page), three facts and the one control; Blocked, Rules and
 * Settings are tabs (ARIA tabs pattern). Layout and wording follow docs/design/DESIGN.md section 12.
 * Works in Firefox (browser.*) and Chrome (chrome.*). All page-derived strings are set with textContent. */
(function (root) {
  "use strict";
  const B = root.browser || root.chrome;
  const $ = (id) => document.getElementById(id);
  const FORM_TYPES = ["beacon", "ping", "xmlhttprequest", "image", "script", "sub_frame"];
  const EXCEPTION_MINUTES = 15;
  const LIST_LABELS = {threats: "Malware and phishing", trackers: "Ads and trackers", cname: "Disguised trackers", user: "Your rules"};
  const LIST_ORDER = ["threats", "trackers", "cname", "fp-trackers", "easyprivacy", "replay", "beacons", "easylist", "links", "surrogates", "strict", "noscript", "embeds", "user"];
  // Categories whose entries are a request you could let through for a while. Unwrapped links are navigations.
  const NO_EXCEPTION = new Set(["threats", "links"]);
  const MODES = [
    ["relaxed", "Relaxed", "Host lists, malware protection and your rules only. URL filters, beacon blocking and link unwrapping are off here."],
    ["standard", "Standard", "Host lists plus URL filters for first-party trackers, fingerprinting and session replay, beacons and link trackers."],
    ["strict", "Strict", "Standard, plus third-party scripts, frames and fonts blocked (payment, sign-in and captcha providers excepted), third-party cookies stripped and video or social embeds held until you click."],
    ["noscript", "No scripts", "Strict, and no JavaScript runs on this site at all. For reading."],
  ];
  const TYPE_NAMES = {beacon: "Beacon", ping: "Ping", xmlhttprequest: "Fetch", image: "Image", imageset: "Image", script: "Script", stylesheet: "Stylesheet",
    font: "Font", media: "Media", sub_frame: "Frame", main_frame: "Page", object: "Plug-in", csp_report: "CSP report", websocket: "Socket",
    webtransport: "Transport", webbundle: "Web bundle", other: "Other"};
  const TABS = ["page", "blocked", "rules", "settings"];
  // Real layout (Chrome, Firefox) truncates by measurement; the test DOM has none and shows strings whole.
  const LAYOUT = typeof root.getComputedStyle === "function";
  let tab = null;
  let genericOn = true;
  let categories = {};
  let lastState = null;

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  const typeName = (t) => TYPE_NAMES[t] || t;
  const plural = (n, one, many) => (n === 1 ? one : many);

  /** Counts: grouped below 10,000; compact with one decimal from there (DESIGN.md section 7). */
  function fmt(n) {
    const v = Number(n) || 0;
    if (v < 10000) return v.toLocaleString("en-US");
    if (v < 1e6) return `${(v / 1000).toFixed(1).replace(/\.0$/, "")}k`;
    return `${(v / 1e6).toFixed(1).replace(/\.0$/, "")}M`;
  }
  const shortDate = (seconds) => new Date(seconds * 1000).toLocaleDateString("en-US", {month: "short", day: "numeric"});

  // ---- truncation (DESIGN.md section 8) -------------------------------------------------------------------------
  /** Hostnames truncate in the middle by whole labels, keeping the registrable domain; never inside a label unless
   *  the registrable domain alone does not fit. Same algorithm as fitHost() in docs/design/mockups/mac-activity.html. */
  function fitHost(host, max) {
    if (host.length <= max) return host;
    const L = host.split(".");
    const k = L.length > 2 && L[L.length - 1].length === 2 && /^(co|com|org|net|ac|gov|edu)$/.test(L[L.length - 2]) ? 3 : 2;
    const tail = L.slice(-k).join(".");
    const head = [];
    for (const label of L.slice(0, -k)) {
      if (`${[...head, label].join(".")}.….${tail}`.length > max) break;
      head.push(label);
    }
    if (head.length) return `${head.join(".")}.….${tail}`;
    if (`….${tail}`.length <= max) return `….${tail}`;
    const keep = Math.max(2, max - 1), a = Math.ceil(keep / 2);
    return `${tail.slice(0, a)}…${tail.slice(tail.length - (keep - a))}`;
  }
  /** URLs keep the host whole and truncate the path in the middle by segment: host/…/last, then host/…. */
  function fitUrl(host, path, max) {
    const p = String(path || "").split(/[?#]/)[0] || "/";
    if ((host + p).length <= max) return [host, p];
    const segs = p.split("/").filter(Boolean);
    const last = segs.length > 1 ? segs[segs.length - 1] : "";
    if (last && (`${host}/…/${last}`).length <= max) return [host, `/…/${last}`];
    if ((`${host}/…`).length <= max) return [host, "/…"];
    const tail = p.length <= 12 ? p : "/…";
    return [fitHost(host, Math.max(8, max - tail.length)), tail];
  }

  let measurer = null;
  /** Width of one mono character inside `context` (the advance is the same for every glyph). */
  function monoWidth(context) {
    if (!measurer) measurer = el("span", "0".repeat(20), "host measure");
    context.append(measurer);
    const w = measurer.getBoundingClientRect().width / 20;
    measurer.remove();
    return w || 8;
  }
  function widthOf(node) {
    const probe = node.cloneNode(true);
    probe.className = `${node.className} measure`;
    document.body.append(probe);
    const w = probe.getBoundingClientRect().width;
    probe.remove();
    return w;
  }

  /** Fit a row's first line for the space it has at rest and with its actions showing (rule 8.5). */
  function fitRow(row) {
    const fit = row.__fit;
    if (!fit) return;
    const line = row.querySelector(".line1");
    const cw = monoWidth(row.querySelector(".main"));
    const acts = row.querySelector(".acts");
    // With an action, the row is one column at rest (the action takes no space); 16 is the row's own padding.
    const rest = acts ? row.getBoundingClientRect().width - 16 : row.querySelector(".main").getBoundingClientRect().width;
    const actsWidth = acts ? widthOf(acts) + 12 : 0;                   // column gap 12
    const variants = acts ? [["fit-rest", rest], ["fit-act", rest - actsWidth]] : [["fit-rest", rest]];
    line.replaceChildren(...variants.map(([cls, px]) => {
      const max = Math.max(6, Math.floor(px / cw));
      const span = el("span", null, cls);
      if (fit.path !== undefined) {
        const [h, p] = fitUrl(fit.host, fit.path, max);
        span.append(document.createTextNode(h), el("span", p, "path"));
      } else span.textContent = fitHost(fit.host, max);
      return span;
    }));
  }
  function fitVisible() {
    if (!LAYOUT) return;
    fitHeader();
    const panel = $(`panel-${currentTab}`);
    if (!panel || panel.hidden) return;
    for (const row of panel.querySelectorAll(".row")) fitRow(row);
  }
  function fitHeader() {
    const site = $("site");
    const full = site.getAttribute("title");
    if (!LAYOUT || !full || !/^[a-z0-9.-]+$/i.test(full)) return;
    site.textContent = full;
    const max = Math.floor(site.getBoundingClientRect().width / monoWidth(site.parentNode));
    site.textContent = fitHost(full, max);
  }

  // ---- rows -----------------------------------------------------------------------------------------------------
  /**
   * One list row: line 1 (an address, a host or free text), line 2 (caption), and trailing actions that show only
   * on hover or focus. `buttons` are [label, onClick, ariaLabel].
   */
  function row({host, path, text, line2, trail, state}, buttons = []) {
    const li = el("li", null, "row");
    const main = el("div", null, "main");
    const line1 = el("div", null, "line1");
    if (host !== undefined) {
      line1.className = `line1 host${path !== undefined ? " url" : ""}`;
      const full = path !== undefined ? `${host}${path}` : host;
      if (path !== undefined) line1.append(document.createTextNode(host), el("span", path, "path"));
      else line1.textContent = host;
      li.setAttribute("title", full);
      li.__fit = {host, path};
    } else {
      line1.className = `line1 ellipsis${text && text.mono ? " host" : ""}`;
      line1.textContent = text && text.mono ? text.mono : text;
      line1.setAttribute("title", text && text.mono ? text.mono : text);
    }
    main.append(line1);
    if (line2) main.append(el("div", line2, "line2"));
    li.append(main);
    if (state) li.setAttribute("data-state", state);
    if (trail !== undefined) li.append(el("span", trail, "trail"));
    if (buttons.length) {
      const acts = el("span", null, "acts");
      for (const [label, onClick, aria, quiet] of buttons) {
        const button = el("button", label, `btn act${quiet ? " quiet" : ""}`);
        button.type = "button";
        if (aria) button.setAttribute("aria-label", aria);
        button.addEventListener("click", onClick);
        acts.append(button);
      }
      li.append(acts);
      li.className = "row has-act";
      li.setAttribute("tabindex", "0");
    }
    return li;
  }

  function group(title, count, items, state) {
    const section = el("section", null, "group");
    if (state) section.setAttribute("data-state", state);
    const h = el("h2");
    h.append(el("span", title), el("span", count, "num"));
    const list = el("ul", null, "list");
    list.append(...items);
    section.append(h, list);
    return section;
  }

  function showError(message) { $("error").textContent = message || ""; $("error").hidden = !message; }

  function minutesLeft(ms) {
    const minutes = Math.ceil(ms / 60000);
    return minutes <= 1 ? "under a minute left" : `${minutes} min left`;
  }

  async function send(message) {
    const reply = await B.runtime.sendMessage({...message, tabId: tab.id, tabUrl: tab.url});
    if (reply && reply.error) showError(reply.error); else showError("");
    return reply;
  }

  async function tabMessage(message) {
    try { return await B.tabs.sendMessage(tab.id, message); } catch { return null; }
  }

  const listLabel = (id, lists) => {
    const meta = lists.find((l) => l.id === id && l.domains > 0);
    return (meta && meta.label) || categories[id] || LIST_LABELS[id] || id;
  };

  // ---- tabs (ARIA tabs pattern: arrows, Home and End move and select; one tab stop) -----------------------------
  let currentTab = "page";
  function selectTab(name, focus = false) {
    currentTab = name;
    for (const id of TABS) {
      const t = $(`tab-${id}`), on = id === name;
      t.setAttribute("aria-selected", String(on));
      t.setAttribute("tabindex", on ? "0" : "-1");
      $(`panel-${id}`).hidden = !on;
    }
    if (focus) $(`tab-${name}`).focus();
    fitVisible();
  }
  function onTabKey(event) {
    const visible = TABS.filter((id) => !$(`tab-${id}`).hidden);
    const at = visible.indexOf(currentTab);
    const to = {ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: visible.length - 1}[event.key];
    if (to === undefined) return;
    event.preventDefault();
    selectTab(visible[(to + visible.length) % visible.length], true);
  }

  // ---- This page -------------------------------------------------------------------------------------------------
  function setStatus(state, word, hollow = false) {
    $("status").setAttribute("data-state", state);
    $("status-dot").className = hollow ? "dot hollow" : "dot";
    $("status-word").textContent = word;
    $("status").setAttribute("aria-label", `Protection: ${word}`);
  }

  function renderModes(state) {
    const supported = typeof state.mode === "string";
    $("protection").hidden = !supported;
    $("defaults-group").hidden = !supported;
    if (!supported) return;
    const current = state.mode || "standard";
    $("modes").replaceChildren(...MODES.map(([id, label, about]) => {
      const button = el("button", label);
      button.type = "button";
      button.setAttribute("aria-pressed", String(id === current));
      button.setAttribute("title", `${about}${id === state.defaultMode ? " (the default for every site)" : ""}`);
      button.addEventListener("click", () => act({type: "set-mode", mode: id === state.defaultMode ? "default" : id}));
      return button;
    }));
    const def = state.defaultMode === "strict" ? "strict" : "standard";
    $("default-modes").replaceChildren(...MODES.filter(([id]) => id === "standard" || id === "strict").map(([id, label, about]) => {
      const button = el("button", label);
      button.type = "button";
      button.setAttribute("aria-pressed", String(id === def));
      button.setAttribute("title", about);
      button.addEventListener("click", () => act({type: "set-default-mode", mode: id}));
      return button;
    }));
    $("scanned-direct").checked = state.scannedDirect === true;
  }

  /** Link and cookie cleaning: two facts on the main view; the per-site brake is a page tool. */
  function renderCleaning(state) {
    const c = state.cleaning;
    $("fact-links").hidden = !c;
    $("fact-cookies").hidden = !c;
    $("facts").className = c ? "metric-row facts" : "metric-row facts cols-1";
    $("clean-item").hidden = !c;
    if (!c) return;
    $("links-cleaned").textContent = fmt(c.links);
    $("links-unit").textContent = plural(c.links, "link cleaned", "links cleaned");
    $("cookies-removed").textContent = fmt(c.cookies);
    $("cookies-unit").textContent = plural(c.cookies, "cookie removed", "cookies removed");
    $("clean-label").textContent = c.on ? "Stop cleaning on this site" : "Clean links and cookies on this site";
    $("clean-note").textContent = c.on ? "Tracking parameters and cookies are removed here" : "Off: links keep their parameters, tracking cookies stay";
    $("clean-toggle").setAttribute("aria-pressed", String(!c.on));
    $("clean-toggle").__on = c.on;
  }

  function totals(blocked, counts) {
    const out = {};
    if (counts) for (const [id, n] of Object.entries(counts)) out[id] = n;
    else for (const b of blocked) { const id = b.list || "user"; out[id] = (out[id] || 0) + b.count; }
    return out;
  }

  function renderFocal(sum, threats, feedback) {
    $("blocked-count").textContent = feedback === "badge" ? "–" : fmt(sum);
    $("blocked-unit").textContent = feedback === "badge" ? "blocked count is on the toolbar badge" : `${plural(sum, "request", "requests")} blocked on this page`;
    $("threat-line").hidden = !(threats > 0);
    $("threat-count").textContent = `${fmt(threats)} ${plural(threats, "threat", "threats")} stopped`;
    $("blocked-tab-count").textContent = feedback === "badge" ? "" : fmt(sum);
  }

  // ---- Blocked ---------------------------------------------------------------------------------------------------
  function renderBlocked(state, lists) {
    const items = [...(state.blocked || [])].sort((a, b) => LIST_ORDER.indexOf(a.list || "user") - LIST_ORDER.indexOf(b.list || "user") || b.count - a.count);
    const counted = state.feedback === "counts" ? state.counts || {} : null;
    const sums = totals(items, counted);
    const ids = Object.keys(sums).sort((a, b) => LIST_ORDER.indexOf(a) - LIST_ORDER.indexOf(b));
    const sum = ids.reduce((n, id) => n + sums[id], 0);
    renderFocal(sum, sums.threats || 0, state.feedback);

    // Packed build: counts by reason only.
    $("breakdown-group").hidden = !(counted && ids.length);
    $("breakdown").replaceChildren(...(counted ? ids.map((id) => row({text: listLabel(id, lists), trail: fmt(sums[id]), state: id === "threats" ? "threat" : null})) : []));
    $("hero-note").hidden = !(counted && ids.length);
    $("hero-note").textContent = "Counts by list from Chrome. This installed build cannot see which addresses were blocked.";

    const byList = new Map();
    for (const b of items) { const id = b.list || "user"; if (!byList.has(id)) byList.set(id, []); byList.get(id).push(b); }
    $("blocked").replaceChildren(...[...byList].map(([list, rows]) => group(listLabel(list, lists), fmt(sums[list]), rows.map((b) => {
      // No one-click exception for malware and phishing hosts, navigations, or types an exception cannot name exactly.
      const allowable = !NO_EXCEPTION.has(list) && b.type !== "main_frame" && (state.types || []).includes(b.type);
      const buttons = !allowable ? [] : [[`Allow ${EXCEPTION_MINUTES} min`,
        () => act({type: "add-exception", host: b.host, path: b.path, resourceType: b.type, minutes: EXCEPTION_MINUTES}),
        `Allow ${b.host}${b.path} (${b.type}) on this site for ${EXCEPTION_MINUTES} minutes`]];
      // Under Strict the repair is the whole host, for this site, until you remove it.
      if (list === "strict") buttons.unshift(["Allow host", () => act({type: "strict-allow", host: b.host}), `Allow ${b.host} on this site under Strict`]);
      return row({host: b.host, path: b.path, line2: `${typeName(b.type)}${b.count > 1 ? ` ×${fmt(b.count)}` : ""}`}, buttons);
    }), list === "threats" ? "threat" : null)));

    const none = !items.length && !(counted && ids.length);
    $("blocked-empty").hidden = !none;
    if (state.feedback === "badge") {
      $("blocked-empty-title").textContent = "Counts are on the toolbar badge";
      $("blocked-empty-text").textContent = "This build cannot count or list blocked requests here; the toolbar badge shows Chrome's count.";
    } else if (state.feedback === "counts") {
      $("blocked-empty-title").textContent = "Nothing blocked on this page";
      $("blocked-empty-text").textContent = "Addresses are listed only in a development (unpacked) build.";
    } else {
      $("blocked-empty-title").textContent = "Nothing blocked on this page";
      $("blocked-empty-text").textContent = "Requests appear here as the page makes them.";
    }
  }

  // ---- Rules -----------------------------------------------------------------------------------------------------
  function renderRules(state) {
    const rules = [
      ...state.requestRules.map((r) => row({host: r.host, path: r.path, line2: `Always block · ${r.types.join(", ")}`},
        [["Remove", () => act({type: "remove-rule", id: r.id}), `Remove rule ${r.host}${r.path}`, true]])),
      ...state.cosmeticRules.map((r) => row({text: {mono: r.selector}, line2: "Hidden on this site"},
        [["Remove", () => act({type: "remove-rule", id: r.id}), `Remove rule ${r.selector}`, true]])),
      ...(state.strictAllowed || []).map((h) => row({host: h, line2: "Allowed under Strict"},
        [["Remove", () => act({type: "strict-unallow", host: h}), `Stop allowing ${h} on this site`, true]])),
    ];
    $("rules").replaceChildren(...rules);
    $("exceptions").replaceChildren(...state.exceptions.map((e) => row({host: e.host, path: e.path, line2: `${typeName(e.type)} · ${minutesLeft(e.msLeft)}`},
      [["End now", () => act({type: "remove-exception", id: e.id}), `Remove exception for ${e.host}${e.path}`, true]])));
    const n = rules.length + state.exceptions.length;
    $("rules-tab-count").textContent = n ? fmt(n) : "";
    layoutRules();
  }
  function layoutRules() {
    const open = !$("add-rule").hidden;
    const rules = $("rules").childNodes.length, exceptions = $("exceptions").childNodes.length;
    $("rules-group").hidden = !rules && !open;
    $("exceptions-group").hidden = !exceptions;
    $("rules-empty").hidden = Boolean(rules || exceptions || open);
  }
  function openForm(open, focus = true) {
    $("add-rule").hidden = !open;
    $("rule-add").setAttribute("aria-expanded", String(open));
    layoutRules();
    if (open && focus) $("rule-path").focus();
    if (!open && focus) ($("rules-group").hidden ? $("rule-add-empty") : $("rule-add")).focus();
  }

  // ---- Settings ----------------------------------------------------------------------------------------------------
  function renderLists(lists) {
    const active = lists.filter((l) => l.domains > 0 || l.rules > 0 && l.id === "filters");
    const sources = active.flatMap((l) => (l.sources || []).filter(Boolean).map((s) => ({...s, at: s.last_modified ? Date.parse(s.last_modified) / 1000 : l.published_at || l.updated_at})));
    if (!active.length) {
      $("lists").replaceChildren(el("li", "No built-in lists in this build: only your own rules apply.", "muted"));
      $("sources").hidden = true;
      return;
    }
    $("lists").replaceChildren(...sources.map((s) => row({text: s.name, trail: typeof s.at === "number" && s.at > 0 ? shortDate(s.at) : "Unknown"})));
    // Every source with its SHA-256 and last-modified date, so a build can be matched to the exact list files.
    const hashed = sources.filter((s) => s.sha256);
    $("sources").hidden = !hashed.length;
    $("hashes").replaceChildren(...hashed.map((s) => {
      const li = el("li");
      li.append(el("span", `${s.name} · ${s.last_modified || s.version || "date unknown"}`, "name"), el("code", s.sha256, "host"));
      return li;
    }));
  }

  // ---- render ------------------------------------------------------------------------------------------------------
  async function render() {
    const state = await send({type: "popup-state"});
    lastState = state;
    const lists = (state && state.lists) || [];
    categories = (state && state.categories) || {};
    renderLists(lists);
    $("rebuilt").hidden = !(state && state.rebuilt === true);
    if (!state || !state.site) {
      const where = String(tab && tab.url || "").replace(/^([a-z-]+:\/\/[^/?#]*).*$/i, "$1");
      $("site").textContent = where || "Not a web page";
      $("site").removeAttribute("title");
      setStatus("neutral", "Not filtered", true);
      $("page-view").hidden = true;
      $("unsupported").hidden = false;
      $("unsupported-title").textContent = root.browser ? "Browser pages can't be filtered" : "Chrome pages can't be filtered";
      for (const id of ["blocked", "rules"]) $(`tab-${id}`).hidden = true;
      for (const id of ["pick", "restore"]) $(id).disabled = true;
      $("protection").hidden = true;
      renderFocal(0, 0, "debug");
      fitVisible();
      return;
    }
    $("page-view").hidden = false;
    $("unsupported").hidden = true;
    for (const id of ["blocked", "rules"]) $(`tab-${id}`).hidden = false;
    $("site").textContent = state.host;
    $("site").setAttribute("title", state.host);
    if (!$("rule-host").value) $("rule-host").value = state.host;
    renderModes(state);
    renderCleaning(state);
    renderBlocked(state, lists);
    renderRules(state);

    const page = await tabMessage({type: "status"});
    if (!page) $("hidden").textContent = "The companion has not loaded on this page yet. Reload it after installing.";
    else if (page.paused) $("hidden").textContent = `${page.reason} Hiding is off until you resume.`;
    else {
      const notes = [];
      if (page.protectedRules.length) notes.push(`${page.protectedRules.length} rule(s) skipped protected content`);
      if (page.overbroadRules.length) notes.push(`${page.overbroadRules.length} rule(s) matched too much and were skipped`);
      $("hidden").textContent = `${page.hidden} element${page.hidden === 1 ? "" : "s"} hidden, ${page.shown} shown by you.${notes.length ? ` ${notes.join("; ")}.` : ""}`;
    }
    $("hidden-count").textContent = page ? fmt(page.paused ? 0 : page.hidden) : "–";
    $("hidden-unit").textContent = page && page.hidden === 1 && !page.paused ? "element hidden" : "elements hidden";
    const paused = Boolean(page && page.paused);
    $("paused").hidden = !paused;
    $("paused").setAttribute("title", paused ? page.reason || "" : "");
    $("pause").hidden = !page || paused;
    setStatus(paused || state.rebuilt === true ? "reduced" : "protected", paused || state.rebuilt === true ? "Reduced" : "Protected");

    // Built-in ad-slot hiding (Chrome): on by default, switchable per site, takes effect at once on open tabs.
    const genericShown = Boolean(page && page.generic && page.generic.available && typeof state.generic === "boolean");
    $("generic-item").hidden = !genericShown;
    if (genericShown) {
      const slots = page.generic.slots;
      $("generic-note").textContent = state.generic
        ? (page.generic.on ? `${slots} ad slot${slots === 1 ? "" : "s"} hidden by built-in rules.` : "Built-in ad-slot hiding is paused for this page load.")
        : "Built-in ad-slot hiding is off for this site.";
      $("generic-label").textContent = state.generic ? "Show hidden ad slots" : "Hide ad slots on this site";
      $("generic").setAttribute("aria-pressed", String(!state.generic));
      genericOn = state.generic;
    }
    $("pick").disabled = !page;
    $("restore").disabled = !page;
    $("restore-label").textContent = paused ? "Resume hiding" : "Restore everything hidden here";
    fitVisible();
  }

  async function act(message) {
    const reply = await send(message);
    if (reply && !reply.error) await render();
    // Switching a site to No scripts or Strict clears its service workers and Cache Storage, for the origins the
    // extension can name; say which, and what it could not reach.
    if (reply && reply.cleared) {
      const note = $("worker-note");
      note.hidden = false;
      note.className = reply.cleared.ok ? "note t-caption muted" : "note inline-error";
      note.textContent = reply.cleared.ok
        ? `Service workers and cached files cleared for ${reply.cleared.origins.length} origins of this site. Other subdomains keep theirs until you clear site data in Chrome.`
        : "Could not clear this site's service workers. Clear site data in Chrome to be sure.";
    }
    return reply;
  }

  function buildTypeBoxes() {
    const set = $("rule-types");
    for (const type of FORM_TYPES) {
      const label = el("label", null, "host");
      const box = document.createElement("input");
      box.type = "checkbox"; box.name = "types"; box.value = type;
      box.checked = type === "beacon" || type === "ping";
      label.append(box, document.createTextNode(type));
      set.append(label);
    }
  }

  /** The active tab, or (for development captures) the tab named by ?tab=<id>. */
  async function currentTabOf() {
    const search = root.location && typeof root.location.search === "string" ? root.location.search : "";
    const named = /^\?tab=([0-9]{1,12})$/.exec(search);
    if (named && B.tabs.get) return B.tabs.get(Number(named[1]));
    const [active] = await B.tabs.query({active: true, currentWindow: true});
    return active;
  }

  async function restoreOrResume() {
    const page = await tabMessage({type: "status"});
    await tabMessage({type: page && page.paused ? "resume" : "restore-page"});
    await render();
  }

  async function init() {
    buildTypeBoxes();
    tab = await currentTabOf();
    for (const id of TABS) $(`tab-${id}`).addEventListener("click", () => selectTab(id));
    $("tabs").addEventListener("keydown", onTabKey);
    document.addEventListener("keydown", (event) => {
      // Escape closes the open sheet (the endpoint form), and focus returns to what opened it.
      if (event.key === "Escape" && !$("add-rule").hidden) { event.preventDefault(); openForm(false); }
    });
    $("pick").addEventListener("click", async () => { await tabMessage({type: "start-picker"}); root.close(); });
    $("restore").addEventListener("click", restoreOrResume);
    $("pause").addEventListener("click", async () => { await tabMessage({type: "restore-page"}); await render(); $("resume").focus(); });
    $("resume").addEventListener("click", async () => { await tabMessage({type: "resume"}); await render(); $("pause").focus(); });
    $("generic").addEventListener("click", () => act({type: "set-generic", on: !genericOn}));
    $("clean-toggle").addEventListener("click", () => act({type: "set-clean", on: !$("clean-toggle").__on}));
    $("scanned-direct").addEventListener("change", (event) => act({type: "set-scanned-direct", on: event.target.checked}));
    $("rule-add").addEventListener("click", () => openForm($("add-rule").hidden));
    $("rule-add-empty").addEventListener("click", () => openForm(true));
    $("rule-cancel").addEventListener("click", () => openForm(false));
    $("add-rule").addEventListener("submit", async (event) => {
      event.preventDefault();
      const types = [...$("rule-types").querySelectorAll("input")].filter((b) => b.checked).map((b) => b.value);
      const reply = await act({type: "add-request-rule", host: $("rule-host").value, path: $("rule-path").value, types});
      if (reply && !reply.error) { $("rule-path").value = ""; openForm(false); }
    });
    if (typeof root.addEventListener === "function") root.addEventListener("resize", fitVisible);
    await render();
  }

  root.__EGPopup = {ready: init().catch((error) => showError(String(error && error.message || error))), render, fitHost, fitUrl, fmt, get state() { return lastState; }};
})(globalThis);
