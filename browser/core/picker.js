/* Candidate selectors for "block this element". Pure: works on a plain descriptor the content
 * script extracts from the clicked element. Class-only selectors are never proposed, because
 * sponsored and organic cards commonly share every class. */
(function (root) {
  "use strict";
  const selectors = typeof module !== "undefined" && module.exports ? require("./selectors.js") : root.EGSelectors;
  const IDENT = /^-?[A-Za-z_][A-Za-z0-9_-]{0,79}$/;
  const TAG = /^[a-z][a-z0-9-]{0,39}$/;
  const ATTR = /^data-[a-z0-9_-]{1,40}$/;
  const MAX_CLASSES = 3;
  const MAX_DEPTH = 4;

  /**
   * descriptor: {tag, id, classes[], attrs[{name, value}], ancestry[{tag, id, index}]}
   * `ancestry` runs from the element itself (index = its :nth-of-type position) upward and stops
    * at the first ancestor with an id. Returns validated selector strings, precise first.
   */
  function candidates(descriptor) {
    const out = [];
    const push = (value) => { if (!out.includes(value) && selectors.validateSelector(value).ok) out.push(value); };
    const tag = TAG.test(descriptor.tag || "") ? descriptor.tag : "";
    const classes = (descriptor.classes || []).filter((c) => IDENT.test(c) && !c.startsWith("eg-")).slice(0, MAX_CLASSES);
    const base = tag + classes.map((c) => `.${c}`).join("");
    const attrs = (descriptor.attrs || []).filter((a) => ATTR.test(a.name) && !a.name.startsWith("data-eg-"))
      .sort((a, b) => a.name.localeCompare(b.name));
    // The selected element is the positive example; other matches are not evidence of ads.
    // Prefer its stable id/value over an attribute shared by every organic and sponsored card.
    if (descriptor.id && IDENT.test(descriptor.id)) push(`#${descriptor.id}`);
    for (const a of attrs) {
      if (typeof a.value === "string" && a.value.length && a.value.length <= 60 && /^[A-Za-z0-9 _:./-]+$/.test(a.value)) push(`${base}[${a.name}="${a.value}"]`);
    }
    for (const a of attrs) push(`${base}[${a.name}]`);
    const chain = (descriptor.ancestry || []).slice(0, MAX_DEPTH + 1);
    const anchor = chain.findIndex((step, i) => i > 0 && step.id && IDENT.test(step.id));
    if (anchor > 0 && chain.slice(0, anchor).every((s) => TAG.test(s.tag || "") && Number.isInteger(s.index) && s.index > 0)) {
      const parts = chain.slice(0, anchor).reverse().map((s) => `${s.tag}:nth-of-type(${s.index})`);
      push(`#${chain[anchor].id} > ${parts.join(" > ")}`);
    }
    return out;
  }

  const api = Object.freeze({candidates});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGPicker = api;
})(globalThis);
