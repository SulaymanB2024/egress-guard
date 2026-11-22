(function (root) {
  "use strict";
  const C = root.chrome, catalog = root.EGBrowserPrivacy.CATALOG, $ = id => document.getElementById(id);
  const boxes = new Map(), receipts = new Map();
  let current = null, hardeningCurrent = null, busy = false, dirty = false, hardeningDirty = false;
  const bad = error => { $("error").textContent = String(error && error.message || error).slice(0, 500); $("error").hidden = false; };
  const clearError = () => { $("error").textContent = ""; $("error").hidden = true; };
  const hardeningBad = error => { $("hardening-error").textContent = String(error && error.message || error).slice(0, 500); $("hardening-error").hidden = false; };
  const clearHardeningError = () => { $("hardening-error").textContent = ""; $("hardening-error").hidden = true; };
  function controls() {
    $("apply").disabled = busy || !current;
    $("retry").disabled = busy || !current || !current.saved;
    $("release").disabled = busy || !current || !(current.saved || current.rows.some(row => row.owned));
    $("refresh").disabled = busy;
    for (const box of boxes.values()) box.disabled = busy;
    $("hardening-apply").disabled = busy || !hardeningCurrent;
    $("hardening-retry").disabled = busy || !hardeningCurrent || !hardeningCurrent.saved;
    $("hardening-release").disabled = busy || !hardeningCurrent || !(hardeningCurrent.saved || hardeningCurrent.observedRuleCount);
    $("hardening-refresh").disabled = busy;
    $("hardening-enabled").disabled = busy;
  }
  async function send(type, extra = {}) {
    const reply = await C.runtime.sendMessage({type, ...extra});
    if (!reply || reply.error && !reply.rows) throw new Error(reply && reply.error || "No browser privacy receipt was returned.");
    if (reply.schema !== 1 || !Array.isArray(reply.rows) || !Array.isArray(reply.selected) || typeof reply.permission !== "boolean") throw new Error("The browser privacy receipt is invalid.");
    return reply;
  }
  function render(receipt, resetChoices = false) {
    current = receipt;
    const selected = new Set(receipt.selected);
    if (resetChoices || !dirty) {
      for (const spec of catalog) boxes.get(spec.id).checked = receipt.saved ? selected.has(spec.id) : spec.recommended;
      dirty = false;
    }
    for (const row of receipt.rows) {
      const out = receipts.get(row.id); if (!out) continue;
      let text;
      if (!receipt.permission) text = "Permission required. No value has been verified.";
      else if (!row.supported) text = "This Chrome control is unavailable.";
      else if (row.state === "unknown") text = "Current value could not be verified.";
      else {
        const owner = row.levelOfControl === "controlled_by_this_extension" ? "Egress Guard" : row.levelOfControl === "controlled_by_other_extensions" ? "another extension" : row.levelOfControl === "not_controllable" ? "browser or organization policy" : "Chrome preferences";
        const value = typeof row.value === "boolean" ? (row.value ? "enabled" : "disabled") : row.value;
        text = `Current: ${value}. Controlled by ${owner}.`;
        if (row.selected) text += row.effective ? " Requested setting value is confirmed." : " Requested setting value is not confirmed.";
        if (catalog.find(spec => spec.id === row.id).lifecycle === "legacy") text += " This legacy preference does not attest that the retired advertising API still operates.";
        if (row.state === "release-pending") text += " Release has not been verified; retry.";
      }
      if (row.error) text += " " + row.error;
      out.textContent = text;
      out.dataset.state = row.selected && !row.effective || row.state === "release-pending" || row.state === "unknown" ? "degraded" : "normal";
    }
    const active = new Set(catalog.filter(spec => spec.lifecycle === "active").map(spec => spec.id));
    const activeSelected = receipt.selected.filter(id => active.has(id)).length;
    const count = receipt.rows.filter(row => row.selected && row.effective && active.has(row.id)).length;
    const legacySelected = receipt.selected.length - activeSelected;
    const legacyCount = receipt.rows.filter(row => row.selected && row.effective && !active.has(row.id)).length;
    $("status").textContent = receipt.state === "inactive" ? "No privacy controls are selected. Select protections to apply." :
      `${count} of ${activeSelected} current settings confirmed.${legacySelected ? ` ${legacyCount} of ${legacySelected} legacy preferences confirmed; these are not counted as current protections.` : ""}${receipt.state === "applied" ? "" : " Some controls need attention."}`;
    if (!receipt.permission) $("status").textContent += " Apply asks Chrome for the optional privacy permission.";
    if (receipt.error) bad(receipt.error);
    controls();
  }
  async function perform(work, resetChoices = false) {
    if (busy) return;
    busy = true; clearError(); controls();
    try { render(await work(), resetChoices); }
    catch (error) { bad(error); }
    finally { busy = false; controls(); }
  }
  async function apply() {
    const selected = [...boxes].filter(([, box]) => box.checked).map(([id]) => id);
    return perform(async () => {
      const allowed = await C.permissions.request({permissions: ["privacy"]});
      if (allowed !== true) throw new Error("Chrome did not grant privacy control. Your choices have not been applied.");
      return send("browser-privacy-apply", {selected});
    }, true);
  }
  const refresh = () => perform(() => send("browser-privacy-status"));
  const retry = () => perform(() => send("browser-privacy-retry"));
  const release = () => perform(() => send("browser-privacy-release"), true);

  async function hardeningSend(type, extra = {}) {
    const reply = await C.runtime.sendMessage({type: `browser-privacy-hardening-${type}`, ...extra});
    if (!reply || reply.error && reply.schema !== 1) throw new Error(reply && reply.error || "No Client Hints rule receipt was returned.");
    if (reply.schema !== 1 || reply.control !== "high-entropy-client-hints" || typeof reply.enabled !== "boolean" ||
        typeof reply.rulesConfirmed !== "boolean" || reply.experimental !== true || reply.behaviorVerified !== false ||
        ![true, false, null].includes(reply.installed)) throw new Error("The Client Hints rule receipt is invalid.");
    return reply;
  }
  function renderHardening(receipt, resetChoice = false) {
    hardeningCurrent = receipt;
    if (resetChoice || !hardeningDirty) { $("hardening-enabled").checked = receipt.enabled; hardeningDirty = false; }
    let text = receipt.state === "inactive" ? "Off. No Client Hints rules are installed." : receipt.state === "installed"
      ? "Both fixed rules are confirmed in Chrome’s rule store. Native browser behavior has not been qualified. Reload pages to use the document policy."
      : receipt.state === "release-pending" ? "Release is saved, but removal of the Client Hints rules has not been confirmed. Retry the saved choice."
      : "The saved Client Hints choice has not been confirmed in Chrome’s rule store.";
    if (receipt.installed === null) text = "Chrome’s current Client Hints rules could not be read. No installed-rule claim is available.";
    else if (receipt.installed && receipt.state === "degraded") text = "Both fixed Client Hints rules remain installed, but their saved choice could not be validated. Apply a new choice or release this control.";
    $("hardening-status").textContent = text;
    if (receipt.error) hardeningBad(receipt.error);
    controls();
  }
  async function hardeningPerform(work, resetChoice = false) {
    if (busy) return;
    busy = true; clearHardeningError(); controls();
    try { renderHardening(await work(), resetChoice); }
    catch (error) { hardeningBad(error); }
    finally { busy = false; controls(); }
  }
  const hardeningRefresh = () => hardeningPerform(() => hardeningSend("status"));
  const hardeningApply = () => hardeningPerform(() => hardeningSend("apply", {enabled: $("hardening-enabled").checked}), true);
  const hardeningRetry = () => hardeningPerform(() => hardeningSend("retry"));
  const hardeningRelease = () => hardeningPerform(() => hardeningSend("release"), true);
  async function init() {
    let group = "", fieldset;
    for (const spec of catalog) {
      if (spec.group !== group) {
        group = spec.group; fieldset = document.createElement("fieldset");
        const legend = document.createElement("legend"); legend.textContent = group; fieldset.append(legend); $("settings").append(fieldset);
      }
      const container = document.createElement("div"); container.className = "control";
      const label = document.createElement("label"), box = document.createElement("input"), name = document.createElement("span");
      box.type = "checkbox"; box.id = `control-${spec.id}`; box.setAttribute("aria-describedby", `detail-${spec.id} receipt-${spec.id}`);
      name.textContent = spec.label; label.append(box, name);
      const detail = document.createElement("p"); detail.className = "detail"; detail.id = `detail-${spec.id}`; detail.textContent = spec.detail;
      const receipt = document.createElement("p"); receipt.className = "receipt"; receipt.id = `receipt-${spec.id}`;
      box.addEventListener("change", () => { dirty = true; });
      boxes.set(spec.id, box); receipts.set(spec.id, receipt); container.append(label, detail, receipt); fieldset.append(container);
    }
    $("choices").addEventListener("submit", event => { event.preventDefault(); apply(); });
    $("retry").addEventListener("click", retry); $("refresh").addEventListener("click", refresh); $("release").addEventListener("click", release);
    $("hardening-choices").addEventListener("submit", event => { event.preventDefault(); hardeningApply(); });
    $("hardening-enabled").addEventListener("change", () => { hardeningDirty = true; });
    $("hardening-retry").addEventListener("click", hardeningRetry); $("hardening-refresh").addEventListener("click", hardeningRefresh);
    $("hardening-release").addEventListener("click", hardeningRelease);
    if (typeof root.addEventListener === "function") root.addEventListener("focus", async () => { if (!busy) { await refresh(); await hardeningRefresh(); } });
    await refresh();
    await hardeningRefresh();
  }
  root.__EGPrivacyUI = Object.freeze({ready: init().catch(bad), apply, refresh, retry, release,
    hardeningApply, hardeningRefresh, hardeningRetry, hardeningRelease,
    get state() { return current; }, get hardeningState() { return hardeningCurrent; }});
})(globalThis);
