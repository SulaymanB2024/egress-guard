/* Popup: one answer first (requests blocked on this page), three facts and the one control; Blocked, Rules and
 * Settings are tabs (ARIA tabs pattern). Layout and wording follow docs/design/DESIGN.md section 12.
 * Works in Firefox (browser.*) and Chrome (chrome.*). All page-derived strings are set with textContent. */
(function (root) {
  "use strict";
  const B = root.browser || root.chrome;
  // Chrome also exposes browser.*; a namespace is not a reliable platform test.
  const IS_FIREFOX = B.runtime.getManifest
    ? Boolean((B.runtime.getManifest().browser_specific_settings || {}).gecko)
    : Boolean(root.browser && !root.chrome);
  const $ = (id) => document.getElementById(id);
  const FORM_TYPES = ["beacon", "ping", "xmlhttprequest", "image", "script", "sub_frame"];
  const EXCEPTION_MINUTES = 15;
  const LIST_LABELS = {threats: "Malware and phishing", trackers: "Ads and trackers", cname: "Disguised trackers", user: "Your rules"};
  const LIST_ORDER = ["threats", "trackers", "cname", "fp-trackers", "easyprivacy", "replay", "beacons", "easylist", "links", "surrogates", "preparation", "isolated", "strict", "noscript", "embeds", "user"];
  // Categories whose entries are a request you could let through for a while. Unwrapped links are navigations.
  const NO_EXCEPTION = new Set(["threats", "links", "preparation", "isolated"]);
  const MODES = [
    ["relaxed", "Relaxed", "Host lists, malware protection and your rules only. URL filters, beacon blocking and link unwrapping are off here."],
    ["standard", "Standard", "Host lists plus URL filters for first-party trackers, fingerprinting and session replay, beacons and link trackers."],
    ["strict", "Strict", "Standard, plus third-party scripts, frames and fonts blocked (payment, sign-in and captcha providers excepted), third-party cookies stripped and video or social embeds held until you click."],
    ["noscript", "No scripts", "Strict, plus blocked script requests and a script-restricting policy on network responses. Existing pages and cached content may need a fresh load."],
    ["isolated", "Isolated", "Block every cross-site subresource, including images, fetches and socket handshakes. Remove Cookie, Authorization, Referer and Set-Cookie on this site's HTTP requests. Sign-in and embedded services may stop working. Change modes to relax isolation."],
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
  const clock = (ms) => new Date(ms).toLocaleTimeString("en-GB", {hour: "2-digit", minute: "2-digit"});
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
    const supported = Boolean(state.site) && typeof state.mode === "string";
    const defaultsSupported = typeof state.defaultMode === "string";
    $("protection").hidden = !supported;
    $("defaults-group").hidden = !defaultsSupported;
    // While the site is paused the control shows the level that comes back, and cannot be changed.
    const paused = typeof state.paused === "number";
    const current = (paused ? state.resumeMode : state.mode) || "standard";
    $("modes").replaceChildren(...(supported ? MODES : []).filter(([id]) => id !== "isolated" || !IS_FIREFOX).map(([id, label, about]) => {
      const button = el("button", label);
      button.type = "button";
      button.disabled = paused;
      button.setAttribute("aria-pressed", String(id === current));
      button.setAttribute("data-mode", id);
      button.setAttribute("title", `${about}${id === state.defaultMode ? " (the default for every site)" : ""}`);
      button.addEventListener("click", () => act({type: "set-mode", mode: id === state.defaultMode ? "default" : id}));
      return button;
    }));
    const def = ["standard", "strict"].includes(state.defaultMode) ? state.defaultMode : null;
    $("default-modes").replaceChildren(...(defaultsSupported ? MODES : []).filter(([id]) => id === "standard" || id === "strict").map(([id, label, about]) => {
      const button = el("button", label);
      button.type = "button";
      button.setAttribute("aria-pressed", String(id === def));
      button.setAttribute("title", about);
      button.addEventListener("click", () => act({type: "set-default-mode", mode: id}));
      return button;
    }));
    $("scanned-direct").checked = state.scannedDirect === true;
  }

  function renderPreparation(state) {
    const preparation = state && state.preparation;
    $("strict-preparation").hidden = IS_FIREFOX || !preparation || preparation.state === "not-applicable";
    $("prepare-site").hidden = !preparation || preparation.state !== "held" || preparation.canPrepare === false;
    if (!preparation) return preparation;
    $("preparation-note").textContent = preparation.state === "held"
      ? preparation.canPrepare === false
        ? String(preparation.reason || "This address cannot be scoped safely. Strict continues to hold active resources here.") + " Change the default to Standard in Settings if you need to use this address."
        : "Strict is holding scripts, frames, fonts and plug-ins until this site's rules are installed. Prepare the site, then use Chrome's Reload button if the page is incomplete."
      : preparation.state === "prepared"
      ? "Strict site rules are installed. If initial resources were held and the page is incomplete, use Chrome's Reload button."
      : "Strict preparation could not be verified. Retry the policy update before relying on it.";
    $("strict-preparation").setAttribute("data-state", preparation.state === "prepared" ? "neutral" : "reduced");
    return preparation;
  }

  function isolationSelected(state) {
    return Boolean(state && (state.mode === "isolated" || state.requestedMode === "isolated" ||
      state.isolation && state.isolation.active === true));
  }

  function renderIsolation(state) {
    const receipt = state && state.isolation;
    const selected = !IS_FIREFOX && (isolationSelected(state) || Boolean(receipt));
    $("isolation-note").hidden = !selected;
    if (!selected) return null;
    const verified = receipt && receipt.state === "applied" && receipt.active === true;
    $("isolation-note").setAttribute("data-state", verified ? "neutral" : "reduced");
    $("isolation-note").textContent = verified
      ? "Isolation rules are installed. New cross-site resource requests are blocked; HTTP cookies, authorization, referrers and known PostHog identity headers are removed. Existing connections are not forcibly closed. Reload for a fresh page. Sign-in may stop working. Site storage and your public IP remain visible to the site. Change modes to relax isolation."
      : receipt && receipt.state === "unsupported"
      ? "Isolation cannot be applied safely to this address. This page is not confirmed isolated."
      : receipt && receipt.active === true
      ? "The last verified isolation rules remain installed, but the requested change is not confirmed. Retry the policy update."
      : "Isolation was requested but its rules are not confirmed. Retry the policy update before relying on it.";
    return receipt || {state: "pending", active: false};
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
    if (isolationSelected(state)) $("clean-note").textContent = c.on
      ? "Tracking links are cleaned. Isolation also removes HTTP identity headers."
      : "Optional link and tracker-cookie cleaning is off. Isolation still removes HTTP identity headers.";
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
      const allowable = !isolationSelected(state) && !NO_EXCEPTION.has(list) && b.type !== "main_frame" && (state.types || []).includes(b.type);
      const buttons = !allowable ? [] : [[`Allow ${EXCEPTION_MINUTES} min`,
        () => act({type: "add-exception", host: b.host, path: b.path, resourceType: b.type, minutes: EXCEPTION_MINUTES}),
        `Allow ${b.host}${b.path} (${b.type}) on this site for ${EXCEPTION_MINUTES} minutes`]];
      // Under Strict the repair is the whole host, for this site, until you remove it.
      if (list === "strict" && !isolationSelected(state)) buttons.unshift(["Allow host", () => act({type: "strict-allow", host: b.host}), `Allow ${b.host} on this site under Strict`]);
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
  function renderPolicy(state) {
    const policy = state && state.policy;
    const issue = Boolean(policy && policy.state !== "applied");
    $("policy-issue").hidden = !issue;
    if (issue) {
      $("policy-note").textContent = policy.state === "pending"
        ? "Saved changes are waiting to be applied. The controls show the last applied policy."
        : "Chrome could not confirm the requested policy. Retry the update; protection may be incomplete.";
      if (policy.error) $("policy-note").textContent += " " + String(policy.error).slice(0, 300);
    }
    const coverage = state && state.coverage;
    const reduced = Boolean(coverage && (!coverage.complete || (coverage.stale || []).length ||
      coverage.cosmetics && coverage.cosmetics.reduced || coverage.parameters && coverage.parameters.reduced));
    $("coverage-note").hidden = !reduced;
    if (reduced) {
      const parts = [];
      if ((coverage.missing || []).length) parts.push("Incomplete build: " + coverage.missing.join(", "));
      if ((coverage.ineffective || []).length) parts.push("No effective compiled rules for: " + coverage.ineffective.join(", "));
      if (coverage.development) parts.push("Development build: production feed-size checks were skipped");
      if (coverage.cosmetics && coverage.cosmetics.reduced) {
        if (coverage.cosmetics.disabledFamilies.length) parts.push("Imported hiding disabled by unsupported source exemptions: " + coverage.cosmetics.disabledFamilies.join(", "));
        if (coverage.cosmetics.quarantinedSelectors) parts.push(coverage.cosmetics.quarantinedSelectors + " imported selector(s) withheld because an exemption could not be represented");
      }
      if (coverage.parameters && coverage.parameters.reduced) {
        if (coverage.parameters.disabled) parts.push("Parameter cleaning was disabled because a source exception could not be represented safely");
        if ((coverage.parameters.quarantined || []).length) parts.push(coverage.parameters.quarantined.length + " parameter name(s) were preserved because a source exception could not be represented");
      }
      if (!coverage.complete && !parts.length) parts.push("Build completeness could not be verified");
      if ((coverage.stale || []).length) parts.push("Old list snapshots: " + coverage.stale.join(", "));
      const refreshNeeded = (coverage.missing || []).length || (coverage.stale || []).length || (coverage.ineffective || []).length;
      $("coverage-note").textContent = parts.join(". ") + (refreshNeeded
        ? ". Refresh the lists and rebuild."
        : ". Review the build coverage receipt before relying on the reduced policy.");
    }
    return {issue, reduced};
  }

  async function checkNative() {
    const button = $("native-check"), note = $("native-note");
    button.disabled = true;
    try {
      if (!B.permissions || !B.runtime.sendNativeMessage) throw new Error("Native messaging is unavailable in this browser.");
      const granted = await B.permissions.request({permissions: ["nativeMessaging"]});
      if (!granted) throw new Error("Permission was not granted. Proxy status was not read.");
      const value = await B.runtime.sendNativeMessage("org.egress_guard.receipts", {schema: 1, command: "status"});
      if (!value || value.schema !== 1 || value.ok !== true || value.product !== "egress-guard" ||
          !value.capabilities || value.capabilities.read_only !== true || value.capabilities.mutations !== false ||
          !value.status || typeof value.status.proxy_ready !== "boolean") throw new Error("The local host returned an invalid receipt.");
      const status = value.status, policy = status.policy, logging = status.logging, transport = status.transport;
      if (!policy || typeof policy.applied !== "boolean" || typeof policy.complete !== "boolean" ||
          typeof policy.pending !== "boolean" || typeof policy.degraded !== "boolean" ||
          !/^[a-f0-9]{64}$/.test(policy.saved_revision) ||
          !(policy.applied_revision === null || /^[a-f0-9]{64}$/.test(policy.applied_revision)) ||
          !logging || !validLogging(logging.saved) ||
          !(logging.runtime === null || validLogging(logging.runtime) && typeof logging.runtime.applied === "boolean") ||
          !transport || !validTransportSettings(transport.saved) ||
          !(transport.runtime === null || validTransportRuntime(transport.runtime))) throw new Error("The local host returned an incomplete receipt.");
      const loggingApplied = Boolean(logging.runtime && logging.runtime.applied === true &&
        ["history", "retention_days", "max_queue"].every(key => logging.runtime[key] === logging.saved[key]));
      const transportApplied = Boolean(transport.runtime && transport.runtime.applied === true &&
        transport.runtime.profile === transport.saved.profile &&
        JSON.stringify(transport.runtime.connect_ports) === JSON.stringify(transport.saved.connect_ports) &&
        transport.runtime.address_guard.selected === transport.saved.address_guard &&
        transport.runtime.address_guard.state === (transport.saved.address_guard ? "active" : "disabled"));
      const ready = status.proxy_ready && policy.applied && policy.complete && policy.pending === false &&
        policy.degraded === false && policy.applied_revision === policy.saved_revision && loggingApplied && transportApplied;
      let text = ready ? "Proxy ready; its saved policy is applied." : "Proxy not fully ready; its policy, feeds or process need attention.";
      text += " Saved history: " + logging.saved.history + ".";
      if (logging.runtime) text += " Runtime history: " + logging.runtime.history + (loggingApplied ? " (acknowledged)." : " (does not acknowledge saved settings).");
      else text += " No runtime logging acknowledgment.";
      text += " Saved transport: " + transport.saved.profile + ".";
      if (transport.runtime) {
        text += " Runtime transport: " + transport.runtime.profile + (transportApplied ? " (acknowledged)." : " (does not acknowledge saved settings).");
        if (transportApplied) text += " Tunnel permissions are checked before each forwarding operation.";
        text += " Experimental address guard: " + transport.runtime.address_guard.state + ".";
        if (transport.runtime.address_guard.reason) text += " Guard status: " + transport.runtime.address_guard.reason + ".";
      } else text += " No runtime transport acknowledgment.";
      note.textContent = text + " Browser routing and device-wide coverage are not verified by this receipt.";
    } catch (e) {
      note.textContent = "Could not verify the local proxy. " + String(e && e.message || e).slice(0, 300) + " Register the read-only native host using the setup instructions.";
    } finally { button.disabled = false; }
  }
  function validLogging(value) {
    return value && ["none", "aggregate", "full"].includes(value.history) &&
      Number.isInteger(value.retention_days) && value.retention_days >= 1 && value.retention_days <= 30 &&
      Number.isInteger(value.max_queue) && value.max_queue >= 100 && value.max_queue <= 10000;
  }
  function exactKeys(value, keys) {
    return value && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  }
  function validTransportSettings(value) {
    return exactKeys(value, ["profile", "connect_ports", "address_guard"]) &&
      ["compatible", "hardened"].includes(value.profile) && typeof value.address_guard === "boolean" &&
      Array.isArray(value.connect_ports) && value.connect_ports.length >= 1 && value.connect_ports.length <= 32 &&
      value.connect_ports.every((port, index) => Number.isInteger(port) && port >= 1 && port <= 65535 &&
        (index === 0 || value.connect_ports[index - 1] < port));
  }
  function validTransportRuntime(value) {
    if (!exactKeys(value, ["profile", "connect_ports", "address_guard", "scope", "tunnel_policy", "applied"]) ||
        !exactKeys(value.address_guard, ["selected", "state", "reason"]) ||
        value.scope !== "proxy-tcp" || value.tunnel_policy !== "per-forward" || typeof value.applied !== "boolean") return false;
    const guard = value.address_guard;
    if (!validTransportSettings({profile: value.profile, connect_ports: value.connect_ports, address_guard: guard.selected})) return false;
    return guard.state === "disabled" && guard.selected === false && guard.reason === null ||
      guard.state === "active" && guard.selected === true && guard.reason === null ||
      guard.state === "unavailable" && value.applied === false &&
      ["unsupported-runtime", "ownership-conflict", "registration-failed", "self-test-failed", "ownership-lost", "stopped"].includes(guard.reason);
  }

  async function render() {
    const state = await send({type: "popup-state"});
    lastState = state;
    const lists = (state && state.lists) || [];
    categories = (state && state.categories) || {};
    const policyState = renderPolicy(state);
    renderModes(state || {});
    const preparation = renderPreparation(state);
    const isolation = renderIsolation(state);
    renderLists(lists);
    $("rebuilt").hidden = !(state && state.rebuilt === true);
    if (!state || !state.site) {
      const where = String(tab && tab.url || "").replace(/^([a-z-]+:\/\/[^/?#]*).*$/i, "$1");
      $("site").textContent = where || "Not a web page";
      $("site").removeAttribute("title");
      const held = preparation && preparation.state === "held";
      setStatus(held ? "reduced" : "neutral", held ? "Held" : "Not filtered", !held);
      $("page-view").hidden = true;
      $("unsupported").hidden = false;
      $("unsupported-title").textContent = held ? "This address cannot use site-scoped rules" : IS_FIREFOX ? "Browser pages can't be filtered" : "Chrome pages can't be filtered";
      $("unsupported-note").textContent = held ? "The default protection level is available in Settings. Browser privacy controls are also available there." : "Open a website to see what Egress Guard blocks on it.";
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
      if (page.imported && (page.imported.degradedFamilies || []).length) notes.push("Imported " + page.imported.degradedFamilies.join(" and ") + " hiding is unavailable on this page");
      if (page.imported && (page.imported.limits || []).length) notes.push("Page-work limits were reached; some cosmetic matches may remain");
      $("hidden").textContent = `${page.hidden} element${page.hidden === 1 ? "" : "s"} hidden, ${page.shown} shown by you.${notes.length ? ` ${notes.join("; ")}.` : ""}`;
    }
    $("hidden-count").textContent = page ? fmt(page.paused ? 0 : page.hidden) : "–";
    $("hidden-unit").textContent = page && page.hidden === 1 && !page.paused ? "element hidden" : "elements hidden";
    const paused = Boolean(page && page.paused);   // element hiding restored on this page (Rules › Restore)
    // Timed pause of the whole site: one callout with the filled Resume; the stale-lists callout waits.
    const sitePaused = typeof state.paused === "number";
    $("paused").hidden = !sitePaused;
    $("paused-note").hidden = !sitePaused;
    if (sitePaused) $("paused-text").replaceChildren(document.createTextNode("Paused on this site until "), el("strong", clock(state.paused), "num"));
    $("rebuilt").hidden = sitePaused || policyState.issue || state.rebuilt !== true;
    $("pause").hidden = sitePaused;
    $("pause").disabled = isolationSelected(state);
    $("pause").setAttribute("aria-describedby", isolationSelected(state) ? "isolation-note" : "pause-desc");
    for (const id of ["clean-toggle", "generic"]) $(id).disabled = sitePaused;
    const contentIssue = Boolean(page && (page.generic && (page.generic.error || page.generic.pending) ||
      page.imported && ((page.imported.degradedFamilies || []).length || (page.imported.limits || []).length)));
    if (policyState.issue) setStatus("reduced", state.policy.state === "pending" ? "Pending" : "Degraded");
    else if (isolation && (isolation.state !== "applied" || isolation.active !== true)) setStatus("reduced", isolation.state === "pending" ? "Pending" : "Degraded");
    else if (sitePaused) setStatus("reduced", "Paused");
    else if (preparation && preparation.state === "held") setStatus("reduced", "Preparing");
    else if (preparation && preparation.state === "unknown") setStatus("reduced", "Degraded");
    else if (IS_FIREFOX && typeof state.mode !== "string") setStatus("reduced", "Manual rules");
    else setStatus(state.rebuilt === true || policyState.reduced || contentIssue ? "reduced" : "protected", state.rebuilt === true || policyState.reduced || contentIssue ? "Reduced" : "Protected");

    // Built-in ad-slot hiding (Chrome): on by default, switchable per site, takes effect at once on open tabs.
    const genericShown = Boolean(page && page.generic && page.generic.available && typeof state.generic === "boolean");
    $("generic-item").hidden = !genericShown;
    if (genericShown) {
      const slots = page.generic.slots;
      $("generic-note").textContent = page.generic.error ? "Built-in ad-slot hiding could not be applied. " + String(page.generic.error).slice(0, 240)
        : page.generic.pending ? "Built-in ad-slot hiding is waiting for the browser."
        : state.generic
        ? (page.generic.on ? `${slots} ad slot${slots === 1 ? "" : "s"} hidden by built-in rules.` : "Built-in ad-slot hiding is paused for this page load.")
        : "Built-in ad-slot hiding is off for this site.";
      $("generic-label").textContent = state.generic ? "Show hidden ad slots" : "Hide ad slots on this site";
      $("generic").setAttribute("aria-pressed", String(!state.generic));
      genericOn = state.generic;
    }
    $("pick").disabled = !page;
    $("semantic-item").hidden = IS_FIREFOX || !page;
    $("semantic-review").disabled = !page || sitePaused;
    $("restore").disabled = !page;
    $("restore-label").textContent = paused ? "Resume hiding" : "Restore everything hidden here";
    fitVisible();
  }

  async function act(message) {
    const reply = await send(message);
    if (reply) await render();
    if (reply && reply.error) showError(reply.error);
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
    $("semantic-review").addEventListener("click", async () => {
      try { await B.tabs.create({url: B.runtime.getURL("semantic.html") + "?tab=" + tab.id}); root.close(); }
      catch (e) { showError(String(e && e.message || e)); }
    });
    $("policy-retry").addEventListener("click", () => act({type: "retry-policy"}));
    $("prepare-site").addEventListener("click", () => act({type: "prepare-strict-site"}));
    $("native-group").hidden = IS_FIREFOX || typeof B.runtime.sendNativeMessage !== "function";
    $("native-check").addEventListener("click", checkNative);
    $("privacy-group").hidden = IS_FIREFOX;
    $("privacy-open").addEventListener("click", async () => {
      try { await B.tabs.create({url: B.runtime.getURL("privacy.html")}); root.close(); }
      catch (e) { showError(String(e && e.message || e)); }
    });
    $("restore").addEventListener("click", restoreOrResume);
    $("pause").addEventListener("click", async () => { const r = await act({type: "pause-site"}); if (r && !r.error) $("resume").focus(); });
    $("resume").addEventListener("click", async () => { const r = await act({type: "resume-site"}); if (r && !r.error) $("pause").focus(); });
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
