/* Popup: shows what applies on the current site. All page-derived strings are set with textContent. */
(function (root) {
  "use strict";
  const B = root.browser;
  const $ = (id) => document.getElementById(id);
  const FORM_TYPES = ["beacon", "ping", "xmlhttprequest", "image", "script", "sub_frame"];
  const EXCEPTION_MINUTES = 15;
  let tab = null;

  function item(parts, buttons = []) {
    const li = document.createElement("li");
    const what = document.createElement("span");
    what.className = "what";
    for (const [text, className] of parts) {
      const span = document.createElement(className === "code" ? "code" : "span");
      span.textContent = text;
      if (className && className !== "code") span.className = className;
      what.append(span, document.createTextNode(" "));
    }
    li.append(what);
    for (const [label, onClick, aria] of buttons) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      if (aria) button.setAttribute("aria-label", aria);
      button.addEventListener("click", onClick);
      li.append(button);
    }
    return li;
  }

  function empty(list, text) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = text;
    list.replaceChildren(li);
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

  async function render() {
    const state = await send({type: "popup-state"});
    if (!state || !state.site) {
      $("site").textContent = "Open a regular web page to see its rules.";
      for (const id of ["pick", "restore"]) $(id).disabled = true;
      for (const id of ["blocked", "rules", "exceptions"]) empty($(id), "Nothing here.");
      $("hidden").textContent = "";
      return;
    }
    $("site").textContent = `Site: ${state.site}`;
    if (!$("rule-host").value) $("rule-host").value = state.host;

    const blocked = $("blocked");
    if (!state.blocked.length) empty(blocked, "Nothing blocked on this page.");
    else blocked.replaceChildren(...state.blocked.map((b) => item(
      [[`${b.host}${b.path}`, "code"], [`${b.type}${b.count > 1 ? ` ×${b.count}` : ""}`, "meta"]],
      [[`Allow ${EXCEPTION_MINUTES} min`, () => act({type: "add-exception", host: b.host, path: b.path, resourceType: b.type, minutes: EXCEPTION_MINUTES}),
        `Allow ${b.host}${b.path} (${b.type}) on this site for ${EXCEPTION_MINUTES} minutes`]],
    )));

    const page = await tabMessage({type: "status"});
    if (!page) $("hidden").textContent = "This page has not loaded the companion (reload it after installing).";
    else if (page.paused) $("hidden").textContent = `${page.reason} Hiding is off until you resume.`;
    else {
      const notes = [];
      if (page.protectedRules.length) notes.push(`${page.protectedRules.length} rule(s) skipped protected content`);
      if (page.overbroadRules.length) notes.push(`${page.overbroadRules.length} rule(s) matched too much and were skipped`);
      $("hidden").textContent = `${page.hidden} element${page.hidden === 1 ? "" : "s"} hidden, ${page.shown} shown by you.${notes.length ? ` ${notes.join("; ")}.` : ""}`;
    }
    $("pick").disabled = !page;
    $("restore").disabled = !page;
    $("restore").textContent = page && page.paused ? "Resume hiding" : "Restore this page";

    const rules = $("rules");
    const all = [...state.requestRules, ...state.cosmeticRules];
    if (!all.length) empty(rules, "No rules for this site yet.");
    else rules.replaceChildren(...all.map((r) => item(
      r.kind === "request"
        ? [["Block", "meta"], [`${r.host}${r.path}`, "code"], [r.types.join(", "), "meta"]]
        : [["Hide", "meta"], [r.selector, "code"]],
      [["Remove", () => act({type: "remove-rule", id: r.id}), `Remove rule ${r.kind === "request" ? r.host + r.path : r.selector}`]],
    )));

    const exceptions = $("exceptions");
    if (!state.exceptions.length) empty(exceptions, "No exceptions.");
    else exceptions.replaceChildren(...state.exceptions.map((e) => item(
      [["Allow", "meta"], [`${e.host}${e.path}`, "code"], [`${e.type} · ${minutesLeft(e.msLeft)}`, "meta"]],
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

  async function init() {
    buildTypeBoxes();
    [tab] = await B.tabs.query({active: true, currentWindow: true});
    $("pick").addEventListener("click", async () => { await tabMessage({type: "start-picker"}); root.close(); });
    $("restore").addEventListener("click", async () => {
      const page = await tabMessage({type: "status"});
      await tabMessage({type: page && page.paused ? "resume" : "restore-page"});
      await render();
    });
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
