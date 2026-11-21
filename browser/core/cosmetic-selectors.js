/* Import-only CSS validation. Manual rules keep core/selectors.js's smaller
 * grammar. Relational selectors stay native CSS; this is not a scriptlet or
 * procedural-filter interpreter. */
(function (root) {
  "use strict";
  const base = typeof module !== "undefined" && module.exports ? require("./selectors.js") : root.EGSelectors;
  const MAX_HAS = 2, MAX_RELATIVE_PARTS = 3, MAX_RELATIVE_ALTERNATIVES = 2, MAX_ARGUMENT = 160;
  const SIMPLE = /^([.#])(-?[A-Za-z_][A-Za-z0-9_-]{0,79})$/;

  function simpleToken(selector) {
    if (typeof selector !== "string") return null;
    const m = SIMPLE.exec(selector);
    return m && base.validateSelector(selector).ok ? {kind: m[1] === "#" ? "id" : "class", value: m[2]} : null;
  }

  function splitAlternatives(text) {
    const out = []; let start = 0, depth = 0, quoted = false;
    for (let i = 0; i < text.length; i++) {
      if (text[i] === '"') quoted = !quoted;
      if (quoted) continue;
      if (text[i] === "(") depth++;
      if (text[i] === ")" && --depth < 0) throw new Error("Unbalanced relational selector.");
      if (text[i] === "," && depth === 0) { out.push(text.slice(start, i).trim()); start = i + 1; }
    }
    if (quoted || depth) throw new Error("Unbalanced relational selector.");
    out.push(text.slice(start).trim());
    if (out.length > MAX_RELATIVE_ALTERNATIVES || out.some((s) => !s)) throw new Error("Relational selector has too many or empty alternatives.");
    return out;
  }

  function validateSelector(selector) {
    if (!base || typeof selector !== "string" || selector.length > base.MAX_LENGTH) return {ok: false, error: "Imported selector is missing or too long."};
    try {
      let masked = "", quote = false, depth = 0, count = 0;
      for (let i = 0; i < selector.length; i++) {
        const char = selector[i];
        if (char === '"') quote = !quote;
        if (!quote && selector.startsWith(":has(", i)) {
          if (depth || ++count > MAX_HAS) throw new Error("Only two non-nested :has() conditions are supported.");
          let end = i + 5, innerDepth = 1, innerQuote = false;
          for (; end < selector.length; end++) {
            if (selector[end] === '"') innerQuote = !innerQuote;
            if (innerQuote) continue;
            if (selector[end] === "(") innerDepth++;
            if (selector[end] === ")" && --innerDepth === 0) break;
          }
          if (innerDepth || innerQuote) throw new Error("Unterminated :has() condition.");
          const arg = selector.slice(i + 5, end).trim();
          if (!arg || arg.length > MAX_ARGUMENT || /:has\s*\(/i.test(arg)) throw new Error("Nested or oversized :has() conditions are unsupported.");
          for (const relative of splitAlternatives(arg)) {
            if (/[>+~]$/.test(relative)) throw new Error("A relative selector cannot end with a combinator.");
            // The synthetic anchor is only a validation aid. It is never emitted
            // or queried. Adding a final class keeps the manual parser's breadth
            // rule separate from read-only relative selection such as '> a'.
            const source = `.eg-relative-anchor ${relative}.eg-relative-target`;
            const ast = base.parseSelector(source);
            if (ast.length !== 1 || ast[0].length - 1 > MAX_RELATIVE_PARTS) throw new Error("Relational selector is nested too deeply.");
          }
          i = end;
          continue;
        }
        if (!quote && char === "(") depth++;
        if (!quote && char === ")") depth--;
        masked += char;
      }
      // Removing :has must leave an independently specific target. A broad
      // 'div:has(.ad)' cannot turn every ancestor of an ad into a hide target.
      const checked = base.validateSelector(masked);
      if (!checked.ok) return checked;
      return {ok: true, relational: count > 0, hasCount: count};
    } catch (error) { return {ok: false, error: String(error && error.message || error)}; }
  }

  const api = Object.freeze({validateSelector, simpleToken, MAX_HAS, MAX_RELATIVE_PARTS, MAX_RELATIVE_ALTERNATIVES});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGCosmeticSelectors = api;
})(globalThis);
