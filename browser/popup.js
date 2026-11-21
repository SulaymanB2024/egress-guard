/* Popup: leads with what was blocked on this page, then the controls for this site.
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
  let tab = null;
  let genericOn = true;
  let categories = {};

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  /** One row: an endpoint (host + path), tags underneath, and optional buttons. */
  function row({verb, host, path, text, tags = []}, buttons = []) {
    const li = el("li");
    const what = el("span", null, "what");
    const line = el("span", null, "line");
    if (verb) line.append(el("span", verb, "verb"), document.createTextNode(" "));
    if (host !== undefined) {
      const code = el("code");
      code.append(el("span", host, "h"), el("span", path, "p"));
      code.setAttribute("title", `${host}${path}`);
      line.append(code);
    } else {
      const code = el("code", text);
      code.setAttribute("title", text);
      line.append(code);
    }
    what.append(line);
    const meta = el("span", null, "meta");
    for (const [label, kind] of tags) meta.append(el("span", label, `tag${kind ? ` ${kind}` : ""}`), document.createTextNode(" "));
    what.append(meta);
    li.append(what);
    for (const [label, onClick, aria] of buttons) {
      const button = el("button", label);
      button.type = "button";
      if (aria) button.setAttribute("aria-label", aria);
      button.addEventListener("click", onClick);
      li.append(button);
    }
    return li;
  }

  function empty(list, text) {
    list.replaceChildren(el("li", text, "empty"));
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

  /** Link and cookie cleaning: what it did here, and the one brake (per site). */
  function renderCleaning(state) {
    const c = state.cleaning;
    $("cleaning").hidden = !c;
    if (!c) return;
    $("links-cleaned").textContent = String(c.links);
    $("links-unit").textContent = c.links === 1 ? "link cleaned in this tab" : "links cleaned in this tab";
    $("cookies-removed").textContent = String(c.cookies);
    $("cookies-unit").textContent = c.cookies === 1 ? "tracking cookie removed on this site" : "tracking cookies removed on this site";
    $("cleaning").classList.toggle("off", !c.on);
    $("clean-note").textContent = c.on
      ? "Tracking parameters and link redirectors are stripped from every link, and tracking cookies are deleted as they are set."
      : "Cleaning is off for this site: its links keep their parameters and its tracking cookies stay.";
    $("clean-toggle").textContent = c.on ? "Stop cleaning on this site" : "Clean links and cookies on this site";
    $("clean-toggle").setAttribute("aria-pressed", String(!c.on));
    $("clean-toggle").onclick = () => act({type: "set-clean", on: !c.on});
  }

  /** Protection level for this site: four radio buttons, the default, and hosts allowed under Strict. */
  function renderModes(state) {
    const group = $("modes");
    const current = state.mode || "standard";
    group.replaceChildren(...MODES.map(([id, label]) => {
      const wrap = el("label", null, "mode");
      const input = document.createElement("input");
      input.type = "radio"; input.name = "mode"; input.value = id; input.checked = id === current;
      input.addEventListener("change", () => act({type: "set-mode", mode: id === state.defaultMode ? "default" : id}));
      wrap.append(input, el("span", label));
      return wrap;
    }));
    const info = MODES.find((m) => m[0] === current);
    $("mode-note").textContent = `${info ? info[2] : ""}${state.siteMode ? "" : " (the default for every site)"}`;
    $("default-mode").value = state.defaultMode === "strict" ? "strict" : "standard";
    const allowed = $("strict-allowed");
    allowed.hidden = !(state.strictAllowed && state.strictAllowed.length);
    allowed.replaceChildren(...(state.strictAllowed || []).map((h) => row({verb: "Allowed", text: h, tags: [["third party under Strict", ""]]},
      [["Remove", () => act({type: "strict-unallow", host: h}), `Stop allowing ${h} on this site`]])));
  }

  function renderHero(blocked, lists, counts = null) {
    const totals = {};
    let sum = 0;
    if (counts) for (const [id, n] of Object.entries(counts)) { totals[id] = n; sum += n; }
    else for (const b of blocked) { const id = b.list || "user"; totals[id] = (totals[id] || 0) + b.count; sum += b.count; }
    $("blocked-count").textContent = String(sum);
    $("blocked-unit").textContent = sum === 1 ? "request" : "requests";
    const ids = Object.keys(totals).sort((a, b) => LIST_ORDER.indexOf(a) - LIST_ORDER.indexOf(b));
    const chips = ids.map((id) => {
      const li = el("li", null, id);
      li.append(el("b", String(totals[id])), document.createTextNode(" "), el("span", listLabel(id, lists)));
      return li;
    });
    $("breakdown").replaceChildren(...chips);
    $("breakdown").hidden = !chips.length;
  }

  function renderLists(lists) {
    const footer = $("lists");
    const active = lists.filter((l) => l.domains > 0 || l.rules > 0 && l.id === "filters");
    if (!active.length) { footer.textContent = "No built-in lists in this build: only your own rules apply."; return; }
    const stamps = active.map((l) => l.published_at || l.updated_at).filter((t) => typeof t === "number");
    const day = stamps.length ? new Date(Math.min(...stamps) * 1000).toLocaleDateString(undefined, {month: "short", day: "numeric"}) : null;
    const parts = [el("span", day ? `Built-in lists (oldest from ${day}): ` : "Built-in lists: ")];
    active.forEach((l, i) => {
      if (i) parts.push(document.createTextNode(" · "));
      parts.push(el("b", l.name), document.createTextNode(l.domains > 0 ? ` (${Number(l.domains).toLocaleString("en-US")})` : ` (${Number(l.rules).toLocaleString("en-US")} URL rules)`));
    });
    parts.push(document.createTextNode("."));
    footer.replaceChildren(...parts);
  }

  async function render() {
    const state = await send({type: "popup-state"});
    const lists = (state && state.lists) || [];
    categories = (state && state.categories) || {};
    renderLists(lists);
    $("rebuilt").hidden = !(state && state.rebuilt === true);
    if (!state || !state.site) {
      $("site").textContent = "Not a web page";
      for (const id of ["pick", "restore"]) $(id).disabled = true;
      $("protection").hidden = true;
      $("cleaning").hidden = true;
      renderHero([], lists);
      for (const id of ["blocked", "rules", "exceptions"]) empty($(id), "Nothing here.");
      $("hidden").textContent = "Open a regular web page to see its rules.";
      return;
    }
    $("site").textContent = state.host;
    if (!$("rule-host").value) $("rule-host").value = state.host;
    $("protection").hidden = false;
    renderModes(state);
    renderCleaning(state);

    const blocked = $("blocked");
    const items = [...state.blocked].sort((a, b) => LIST_ORDER.indexOf(a.list || "user") - LIST_ORDER.indexOf(b.list || "user") || b.count - a.count);
    renderHero(items, lists, state.feedback === "counts" ? state.counts || {} : null);
    $("hero-note").hidden = state.feedback === "debug" || state.feedback === undefined;
    $("hero-note").textContent = state.feedback === "counts"
      ? "Counts by list from Chrome. This installed build cannot see which addresses were blocked."
      : "This build cannot count or list blocked requests here; the toolbar badge shows Chrome's count.";
    if (state.feedback === "badge") { $("blocked-count").textContent = "–"; $("blocked-unit").textContent = "see the toolbar badge"; }
    if (!items.length) empty(blocked, state.feedback === "counts" || state.feedback === "badge"
      ? "Addresses are listed only in a development (unpacked) build." : "Nothing blocked on this page.");
    else blocked.replaceChildren(...items.map((b) => {
      const list = b.list || "user";
      const tags = [[`${b.type}${b.count > 1 ? ` ×${b.count}` : ""}`, ""], [listLabel(list, lists), list]];
      // No one-click exception for malware and phishing hosts, navigations, or types an exception cannot name exactly.
      const allowable = !NO_EXCEPTION.has(list) && b.type !== "main_frame" && (state.types || []).includes(b.type);
      const buttons = !allowable ? [] : [[`Allow ${EXCEPTION_MINUTES} min`,
        () => act({type: "add-exception", host: b.host, path: b.path, resourceType: b.type, minutes: EXCEPTION_MINUTES}),
        `Allow ${b.host}${b.path} (${b.type}) on this site for ${EXCEPTION_MINUTES} minutes`]];
      // Under Strict the repair is the whole host, for this site, until you remove it.
      if (list === "strict") buttons.unshift(["Allow host", () => act({type: "strict-allow", host: b.host}), `Allow ${b.host} on this site under Strict`]);
      return row({host: b.host, path: b.path, tags}, buttons);
    }));

    const page = await tabMessage({type: "status"});
    if (!page) $("hidden").textContent = "The companion has not loaded on this page yet. Reload it after installing.";
    else if (page.paused) $("hidden").textContent = `${page.reason} Hiding is off until you resume.`;
    else {
      const notes = [];
      if (page.protectedRules.length) notes.push(`${page.protectedRules.length} rule(s) skipped protected content`);
      if (page.overbroadRules.length) notes.push(`${page.overbroadRules.length} rule(s) matched too much and were skipped`);
      $("hidden").textContent = `${page.hidden} element${page.hidden === 1 ? "" : "s"} hidden, ${page.shown} shown by you.${notes.length ? ` ${notes.join("; ")}.` : ""}`;
    }
    // Built-in ad-slot hiding (Chrome): on by default, switchable per site, takes effect at once on open tabs.
    const genericShown = Boolean(page && page.generic && page.generic.available && typeof state.generic === "boolean");
    $("generic").hidden = !genericShown;
    $("generic-note").hidden = !genericShown;
    if (genericShown) {
      const slots = page.generic.slots;
      $("generic-note").textContent = state.generic
        ? (page.generic.on ? `${slots} ad slot${slots === 1 ? "" : "s"} hidden by built-in rules.` : "Built-in ad-slot hiding is paused for this page load.")
        : "Built-in ad-slot hiding is off for this site.";
      $("generic").textContent = state.generic ? "Show ad slots on this site" : "Hide ad slots on this site";
      $("generic").setAttribute("aria-pressed", String(!state.generic));
      genericOn = state.generic;
    }
    $("pick").disabled = !page;
    $("restore").disabled = !page;
    $("restore").textContent = page && page.paused ? "Resume hiding" : "Restore this page";

    const rules = $("rules");
    const all = [...state.requestRules, ...state.cosmeticRules];
    if (!all.length) empty(rules, "No rules for this site yet.");
    else rules.replaceChildren(...all.map((r) => row(
      r.kind === "request"
        ? {verb: "Block", host: r.host, path: r.path, tags: r.types.map((t) => [t, ""])}
        : {verb: "Hide", text: r.selector},
      [["Remove", () => act({type: "remove-rule", id: r.id}), `Remove rule ${r.kind === "request" ? r.host + r.path : r.selector}`]],
    )));

    const exceptions = $("exceptions");
    if (!state.exceptions.length) empty(exceptions, "No exceptions.");
    else exceptions.replaceChildren(...state.exceptions.map((e) => row(
      {verb: "Allow", host: e.host, path: e.path, tags: [[`${e.type} · ${minutesLeft(e.msLeft)}`, ""]]},
      [["Remove", () => act({type: "remove-exception", id: e.id}), `Remove exception for ${e.host}${e.path}`]],
    )));
  }

  async function act(message) {
    const reply = await send(message);
    if (reply && !reply.error) await render();
    return reply;
  }

  function buildTypeBoxes() {
    const set = $("rule-types");
    for (const type of FORM_TYPES) {
      const label = document.createElement("label");
      const box = document.createElement("input");
      box.type = "checkbox"; box.name = "types"; box.value = type;
      box.checked = type === "beacon" || type === "ping";
      label.append(box, document.createTextNode(type));
      set.append(label);
    }
  }

  /** The active tab, or (for development captures) the tab named by ?tab=<id>. */
  async function currentTab() {
    const search = root.location && typeof root.location.search === "string" ? root.location.search : "";
    const named = /^\?tab=([0-9]{1,12})$/.exec(search);
    if (named && B.tabs.get) return B.tabs.get(Number(named[1]));
    const [active] = await B.tabs.query({active: true, currentWindow: true});
    return active;
  }

  async function init() {
    buildTypeBoxes();
    tab = await currentTab();
    $("pick").addEventListener("click", async () => { await tabMessage({type: "start-picker"}); root.close(); });
    $("restore").addEventListener("click", async () => {
      const page = await tabMessage({type: "status"});
      await tabMessage({type: page && page.paused ? "resume" : "restore-page"});
      await render();
    });
    $("generic").addEventListener("click", () => act({type: "set-generic", on: !genericOn}));
    $("default-mode").addEventListener("change", (event) => act({type: "set-default-mode", mode: event.target.value}));
    $("add-rule").addEventListener("submit", async (event) => {
      event.preventDefault();
      const types = [...$("rule-types").querySelectorAll('input[name="types"]')].filter((b) => b.checked).map((b) => b.value);
      const reply = await act({type: "add-request-rule", host: $("rule-host").value, path: $("rule-path").value, types});
      if (reply && !reply.error) $("rule-path").value = "";
    });
    await render();
  }

  root.__EGPopup = {ready: init().catch((error) => showError(String(error && error.message || error))), render};
})(globalThis);
