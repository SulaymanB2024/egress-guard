/* Extension-owned UI. Page text is rendered as text; model labels require a separate user action. */
(function (root) {
  "use strict";
  const B = root.chrome;
  const M = root.EGLocalModel;
  const $ = id => document.getElementById(id);
  const match = /^\?tab=([0-9]{1,12})$/.exec(root.location.search);
  const tabId = match ? Number(match[1]) : null;
  const LABELS = {"paid-placement": "Paid placement", organic: "Organic content", "essential-commerce": "Protected commerce", uncertain: "Uncertain"};
  let batch = null, labels = new Map(), boxes = new Map(), controller = null, busy = false, sourceUrl = "", modelState = "unavailable", epoch = 0;
  const element = (tag, value, className) => {
    const node = document.createElement(tag);
    if (value !== undefined) node.textContent = value;
    if (className) node.className = className;
    return node;
  };
  function error(message) { $("error").textContent = message || ""; $("error").hidden = !message; }
  function controls() {
    $("scan").disabled = busy || !sourceUrl || !$("public-page").checked;
    $("analyze").disabled = busy || !batch || !batch.candidates.length || modelState === "unavailable";
    $("apply").disabled = busy || !batch || ![...boxes.values()].some(box => box.checked && !box.disabled);
    $("restore").disabled = busy || tabId === null || !sourceUrl;
    $("cancel").hidden = !controller;
    $("public-page").disabled = busy;
  }
  async function message(value) {
    if (tabId === null) throw new Error("Open Local ad review from the popup on a web page.");
    const reply = await B.tabs.sendMessage(tabId, value, {frameId: 0});
    if (!reply || reply.ok === false || reply.error) throw new Error(reply && (reply.error || reply.disabledReason) || "The source page is unavailable. Reload it and scan again.");
    return reply;
  }
  function draw() {
    boxes = new Map();
    const rows = (batch ? batch.candidates : []).map((card, index) => {
      const row = element("li", undefined, "candidate");
      const choice = element("label");
      const box = element("input"); box.type = "checkbox";
      const category = labels.get(card.id) || card.classification;
      box.disabled = category !== "paid-placement" || card.classification === "essential-commerce";
      box.checked = false; // Recommendations are never silently applied or preselected.
      box.addEventListener("change", controls);
      boxes.set(card.id, box);
      choice.append(box, element("span", card.accessibleLabel || card.disclosures.join(" · ") || "Candidate " + (index + 1)));
      row.append(choice, element("p", LABELS[category] || LABELS.uncertain, "classification"));
      if (card.text) row.append(element("p", card.text, "excerpt"));
      return row;
    });
    $("candidates").replaceChildren(...rows);
    $("empty").hidden = Boolean(rows.length);
    $("empty").textContent = batch ? "No eligible ad cards were found in this bounded scan." : "No page content has been collected.";
    controls();
  }
  function forget(reason) {
    epoch++;
    if (controller) controller.abort();
    batch = null; labels.clear(); boxes.clear();
    $("notice").textContent = reason;
    draw();
  }
  async function scan() {
    if (busy || !$("public-page").checked) return;
    forget("Scanning the source page…");
    const current = epoch;
    busy = true; error(""); controls();
    try {
      const tab = await B.tabs.get(tabId);
      if (!tab || !/^https?:\/\//.test(tab.url || "") || tab.url !== sourceUrl) throw new Error("The source page changed. Reopen Local ad review from its popup.");
      const reply = await message({type: "semantic-candidates"});
      if (current !== epoch) return;
      batch = M.snapshot(reply);
      $("notice").textContent = batch.candidates.length + " candidate(s) collected. Review the excerpts, then optionally analyze locally.";
      draw();
    } catch (e) { if (current === epoch) error(String(e.message || e)); }
    finally { busy = false; controls(); }
  }
  async function analyze() {
    if (busy || !batch) return;
    const current = epoch, input = batch;
    controller = new AbortController(); busy = true; error(""); controls();
    $("notice").textContent = "Analyzing on this device…";
    try {
      const result = await M.analyze(input, {signal: controller.signal, onProgress: value => {
        if (current === epoch) $("notice").textContent = "Preparing the local model: " + Math.round(value * 100) + "%";
      }});
      if (current !== epoch) return;
      labels = new Map(result.labels.map(label => [label.id, label.category]));
      draw();
      $("notice").textContent = "Local review complete. Select the paid cards you want to hide. Nothing has been changed by the model.";
    } catch (e) { if (current === epoch) { error(String(e.message || e)); $("notice").textContent = "Analysis did not change the page."; } }
    finally { controller = null; busy = false; controls(); }
  }
  async function apply() {
    if (busy || !batch) return;
    const selected = [...boxes].filter(([, box]) => box.checked && !box.disabled).map(([id]) => ({id, category: "paid-placement"}));
    if (!selected.length) return;
    busy = true; error(""); controls();
    try {
      const reply = await message({type: "semantic-apply", documentId: batch.documentId, domGeneration: batch.domGeneration, labels: selected});
      const rejected = Array.isArray(reply.rejected) ? reply.rejected.length : Number(reply.rejected) || 0;
      forget(String(reply.applied || 0) + " card(s) hidden; " + rejected + " rejected. Scan again for a fresh review.");
    } catch (e) { error(String(e.message || e)); forget("The page may have changed. Scan again before hiding anything."); }
    finally { busy = false; controls(); }
  }
  async function restore() {
    if (busy || !sourceUrl) return;
    busy = true; error(""); controls();
    try { await message({type: "semantic-restore"}); forget("Reviewed cards restored. Other protection remains active."); }
    catch (e) { error(String(e.message || e)); }
    finally { busy = false; controls(); }
  }
  async function init() {
    $("public-page").addEventListener("change", () => { if (!$("public-page").checked) forget("Page content discarded."); controls(); });
    $("scan").addEventListener("click", scan);
    $("analyze").addEventListener("click", analyze);
    $("apply").addEventListener("click", apply);
    $("restore").addEventListener("click", restore);
    $("cancel").addEventListener("click", () => { if (controller) controller.abort(); });
    root.addEventListener("pagehide", () => forget("Review closed."));
    if (B.tabs.onUpdated) B.tabs.onUpdated.addListener((id, change) => {
      if (id === tabId && (change.url || change.status === "loading")) {
        sourceUrl = "";
        $("public-page").checked = false;
        forget("The source page changed. Reopen Local ad review from its popup.");
      }
    });
    if (B.tabs.onRemoved) B.tabs.onRemoved.addListener(id => { if (id === tabId) { sourceUrl = ""; forget("The source tab was closed."); } });
    if (tabId === null) throw new Error("Open Local ad review from the popup on a web page.");
    const tab = await B.tabs.get(tabId);
    if (!tab || !/^https?:\/\//.test(tab.url || "")) throw new Error("The source is not a supported web page.");
    sourceUrl = tab.url;
    $("site").textContent = new URL(sourceUrl).hostname;
    controls();
    try { modelState = await M.availability(); } catch { modelState = "unavailable"; }
    $("model-note").textContent = modelState === "available" ? "The local model is ready."
      : modelState === "downloadable" || modelState === "downloading" ? "Chrome needs to prepare its model. Analyze locally may start a model download."
      : "This device does not expose Chrome’s local model. Deterministic ad detection and manual review remain available.";
    controls();
  }
  root.__EGSemanticUI = {ready: init().catch(e => { error(String(e.message || e)); controls(); }), scan, analyze, apply, restore, get batch() { return batch; }};
})(globalThis);
