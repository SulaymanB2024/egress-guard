/* A deliberately small CSS selector grammar for cosmetic rules.
 * Anything outside it is refused. Parsing returns an AST so tests (and a future
 * DNR/cosmetic compiler) can reason about selectors without a browser.
 *
 *   list     := complex ("," complex){0,3}
 *   complex  := compound (combinator compound){0,5}      combinator: " " ">" "+" "~"
 *   compound := [tag] (#id | .class | [attr] | [attr op "value"] | pseudo)*
 *   pseudo   := :first-child :last-child :only-child :first-of-type :last-of-type
 *               :only-of-type :nth-child(An+B) :nth-of-type(An+B) :not(compound)
 */
(function (root) {
  "use strict";
  const MAX_LENGTH = 300;
  const IDENT = /^-?[A-Za-z_][A-Za-z0-9_-]{0,79}/;
  const TAG = /^[a-z][a-z0-9-]{0,39}/;
  const ATTR_NAME = /^[a-z][a-z0-9_:-]{0,39}/;
  const ATTR_OPS = ["~=", "^=", "$=", "*=", "|=", "="];
  const SIMPLE_PSEUDO = new Set(["first-child", "last-child", "only-child", "first-of-type", "last-of-type", "only-of-type"]);
  const NTH = /^(?:odd|even|[+-]?\d{0,3}n(?:\s*[+-]\s*\d{1,3})?|[+-]?\d{1,3})$/;
  // Targets that hide the page, its structure or its primary content.
  const FORBIDDEN_TARGET_TAGS = new Set(["html", "head", "body", "main", "script", "style", "link", "meta", "title", "base", "iframe", "frame", "frameset", "object", "embed"]);
  const NEVER_IN_CHAIN = new Set(["head", "script", "style", "template", "noscript", "title", "meta", "link"]);
  const SCRIPTY = /javascript:|vbscript:|data:|expression\s*\(|url\s*\(|<|\\|\/\*|@|\{|\}|;|`/i;

  class SelectorError extends Error {}

  function fail(message) { throw new SelectorError(message); }

  function parseCompound(src, pos, nested) {
    const compound = {tag: null, ids: [], classes: [], attrs: [], pseudos: []};
    let m;
    if ((m = TAG.exec(src.slice(pos)))) { compound.tag = m[0]; pos += m[0].length; }
    else if (src[pos] === "*") fail("The universal selector * is too broad.");
    for (;;) {
      const ch = src[pos];
      if (ch === "#" || ch === ".") {
        m = IDENT.exec(src.slice(pos + 1));
        if (!m) fail(`Expected a name after "${ch}".`);
        (ch === "#" ? compound.ids : compound.classes).push(m[0]);
        pos += 1 + m[0].length;
      } else if (ch === "[") {
        pos++;
        m = ATTR_NAME.exec(src.slice(pos));
        if (!m) fail("Expected an attribute name.");
        const name = m[0];
        if (/^on/.test(name) || name === "style") fail(`Attribute "${name}" is not allowed in rules.`);
        pos += name.length;
        const op = ATTR_OPS.find((item) => src.startsWith(item, pos));
        let value = null;
        if (op) {
          pos += op.length;
          if (src[pos] !== '"') fail("Attribute values must be double-quoted.");
          const end = src.indexOf('"', pos + 1);
          if (end < 0) fail("Unterminated attribute value.");
          value = src.slice(pos + 1, end);
          if (value.length > 100 || /[\n\r"]/.test(value)) fail("Attribute value is too long or malformed.");
          pos = end + 1;
        }
        if (src[pos] !== "]") fail("Expected ].");
        pos++;
        compound.attrs.push({name, op: op || null, value});
      } else if (ch === ":") {
        if (src[pos + 1] === ":") fail("Pseudo-elements are not allowed.");
        m = /^[a-z-]{1,20}/.exec(src.slice(pos + 1));
        if (!m) fail("Expected a pseudo-class name.");
        const name = m[0];
        pos += 1 + name.length;
        if (SIMPLE_PSEUDO.has(name)) { compound.pseudos.push({name}); continue; }
        if (src[pos] !== "(") fail(`Pseudo-class :${name} is not allowed.`);
        const close = src.indexOf(")", pos);
        if (close < 0) fail("Unterminated pseudo-class.");
        const inner = src.slice(pos + 1, close).trim();
        if (name === "nth-child" || name === "nth-of-type") {
          if (!NTH.test(inner)) fail(`Invalid :${name} argument.`);
          compound.pseudos.push({name, arg: inner.replace(/\s+/g, "")});
        } else if (name === "not" && !nested) {
          const parsed = parseCompound(inner, 0, true);
          if (parsed.pos !== inner.length || isEmpty(parsed.compound)) fail("Invalid :not() argument.");
          compound.pseudos.push({name, arg: parsed.compound});
        } else fail(`Pseudo-class :${name} is not allowed.`);
        pos = close + 1;
      } else break;
    }
    return {compound, pos};
  }

  function isEmpty(compound) {
    return !compound.tag && !compound.ids.length && !compound.classes.length && !compound.attrs.length && !compound.pseudos.length;
  }

  /** Parse and validate. Returns an array of complex selectors; throws SelectorError. */
  function parseSelector(text) {
    if (typeof text !== "string") fail("Selector must be text.");
    const src = text.trim();
    if (!src || src.length > MAX_LENGTH) fail(`Selector must be 1-${MAX_LENGTH} characters.`);
    if (SCRIPTY.test(src)) fail("Selector contains characters or text that are not allowed.");
    const list = [];
    let pos = 0;
    for (;;) {
      const complex = [];
      let combinator = null;
      for (;;) {
        const {compound, pos: next} = parseCompound(src, pos, false);
        if (isEmpty(compound)) fail("Empty or unsupported selector part.");
        complex.push({combinator, compound});
        pos = next;
        const ws = /^\s*/.exec(src.slice(pos))[0];
        pos += ws.length;
        if (pos >= src.length || src[pos] === ",") break;
        if (">+~".includes(src[pos])) { combinator = src[pos]; pos++; pos += /^\s*/.exec(src.slice(pos))[0].length; }
        else if (ws) combinator = " ";
        else fail(`Unexpected "${src[pos]}".`);
        if (complex.length >= 6) fail("Selector is nested too deeply.");
      }
      checkBreadth(complex);
      list.push(complex);
      if (pos >= src.length) break;
      pos++; // ","
      pos += /^\s*/.exec(src.slice(pos))[0].length;
      if (list.length >= 4) fail("At most four comma-separated selectors.");
    }
    return list;
  }

  function checkBreadth(complex) {
    const target = complex[complex.length - 1].compound;
    if (target.tag && FORBIDDEN_TARGET_TAGS.has(target.tag)) fail(`Hiding <${target.tag}> is not allowed.`);
    for (const {compound} of complex) if (compound.tag && NEVER_IN_CHAIN.has(compound.tag)) fail(`<${compound.tag}> is not allowed in rules.`);
    // A position under an element with an id is specific ("#feed > article:nth-of-type(2)").
    const positional = target.pseudos.some((p) => p.name === "nth-child" || p.name === "nth-of-type") &&
      complex.slice(0, -1).some(({compound}) => compound.ids.length);
    // Otherwise the hidden element needs something specific: an id, a class or an attribute.
    if (!positional && !target.ids.length && !target.classes.length && !target.attrs.length) {
      fail("Selector is too broad: the hidden element needs an id, class or attribute.");
    }
    // A bare presence test of a ubiquitous attribute is still everything.
    if (!positional && !target.ids.length && !target.classes.length && target.attrs.every((a) => a.op === null && ["class", "id", "href", "src", "lang", "dir"].includes(a.name))) {
      fail("Selector is too broad.");
    }
  }

  function validateSelector(text) {
    try { parseSelector(text); return {ok: true}; } catch (error) {
      if (error instanceof SelectorError) return {ok: false, error: error.message};
      throw error;
    }
  }

  const api = Object.freeze({parseSelector, validateSelector, SelectorError, MAX_LENGTH});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGSelectors = api;
})(globalThis);
