(function (root) {
  "use strict";
  const C = root.chrome, catalog = root.EGBrowserPrivacy.CATALOG, $ = id => document.getElementById(id);
  const boxes = new Map(), receipts = new Map();
  let current = null, busy = false, dirty = false;
  const bad = error => { $("error").textContent = String(error && error.message || error).slice(0, 500); $("error").hidden = false; };
  const clearError = () => { $("error").textContent = ""; $("error").hidden = true; };
  function controls() {
    $("apply").disabled = busy || !current;
    $("retry").disabled = busy || !current || !current.saved;
    $("release").disabled = busy || !current || !(current.saved || current.rows.some(row => row.owned));
    $("refresh").disabled = busy;
    for (const box of boxes.values()) box.disabled = busy;
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
      for (const [id, box] of boxes) box.checked = receipt.saved ? selected.has(id) : true;
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
        if (row.selected) text += row.effective ? " Selected protection is effective." : " Selected protection is not effective.";
        if (row.state === "release-pending") text += " Release has not been verified; retry.";
      }
      if (row.error) text += " " + row.error;
      out.textContent = text;
      out.dataset.state = row.selected && !row.effective || row.state === "release-pending" || row.state === "unknown" ? "degraded" : "normal";
    }
    const count = receipt.rows.filter(row => row.selected && row.effective).length;
    $("status").textContent = receipt.state === "inactive" ? "No privacy controls are selected. Select protections to apply." :
      `${count} of ${receipt.selected.length} selected protections verified.${receipt.state === "applied" ? "" : " Some controls need attention."}`;
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
    if (typeof root.addEventListener === "function") root.addEventListener("focus", () => { if (!busy) refresh(); });
    await refresh();
  }
  root.__EGPrivacyUI = Object.freeze({ready: init().catch(bad), apply, refresh, retry, release, get state() { return current; }});
})(globalThis);
