"use strict";
/* Build-only regular-language helpers. No I/O and no browser execution.
 *
 * The parser deliberately accepts less than RE2. It has no captures, flags,
 * backreferences, lookaround, Unicode escapes, or quoted literal regions. A
 * refused expression stays a regex; refusal never removes a source rule.
 * Capturing parentheses are accepted only as grouping: callers must not use
 * these helpers for regexSubstitution or any other capture-sensitive action.
 */
const MAX_SOURCE = 4096;
const MAX_NODES = 2048;
const MAX_DEPTH = 32;
const MAX_FILTERS = 128;
const MAX_FILTER_LENGTH = 512;

const seq = (parts) => parts.length === 1 ? parts[0] : {kind: "seq", parts};
const alt = (parts) => parts.length === 1 ? parts[0] : {kind: "alt", parts};

/** Parse a bounded RE2 subset. All syntax outside that subset is refused. */
function parse(source) {
  if (typeof source !== "string" || !source.length || source.length > MAX_SOURCE || !/^[\x20-\x7e]+$/.test(source)) return null;
  let at = 0, nodes = 0;
  const make = (value) => { if (++nodes > MAX_NODES) throw Error("nodes"); return value; };
  function expression(depth) {
    if (depth > MAX_DEPTH) throw Error("depth");
    const choices = [];
    do {
      if (choices.length) at++;
      const parts = [];
      while (at < source.length && source[at] !== ")" && source[at] !== "|") {
        let node;
        const char = source[at++];
        if (char === "(") {
          if (source[at] === "?") {
            if (source.slice(at, at + 2) !== "?:") throw Error("group");
            at += 2;
          }
          node = expression(depth + 1);
          if (source[at++] !== ")") throw Error("group-end");
        } else if (char === "[") {
          const start = at - 1;
          if (source[at] === "^") at++;
          if (source[at] === "]") throw Error("class-initial-close");
          let closed = false;
          while (at < source.length) {
            const next = source[at++];
            if (next === "\\") { if (at >= source.length) throw Error("class-escape"); at++; }
            else if (next === "[") throw Error("nested-class");
            else if (next === "]") { closed = true; break; }
          }
          if (!closed) throw Error("class-end");
          node = make({kind: "class", value: source.slice(start, at)});
        } else if (char === "\\") {
          if (at >= source.length) throw Error("escape-end");
          const next = source[at++];
          if (/[^A-Za-z0-9]/.test(next)) node = make({kind: "literal", value: next});
          else if (/[dDsSwWbBAz]/.test(next)) node = make({kind: "escape", value: "\\" + next});
          else throw Error("escape");
        } else if (char === ".") node = make({kind: "any"});
        else if (char === "^" || char === "$") node = make({kind: "assert", value: char});
        else if (/[?*+{}\]]/.test(char)) throw Error("atom");
        else node = make({kind: "literal", value: char});

        let minimum, maximum, suffix = source[at];
        if (suffix === "?" || suffix === "*" || suffix === "+") {
          minimum = suffix === "+" ? 1 : 0; maximum = suffix === "?" ? 1 : Infinity; at++;
        } else if (suffix === "{") {
          const match = /^\{(\d{1,4})(?:,(\d{0,4}))?\}/.exec(source.slice(at));
          if (!match) throw Error("repeat");
          minimum = Number(match[1]); maximum = match[2] === undefined ? minimum : match[2] === "" ? Infinity : Number(match[2]);
          if (minimum > 1000 || maximum < minimum || (maximum !== Infinity && maximum > 1000)) throw Error("repeat-bound");
          suffix = match[0]; at += suffix.length;
        }
        if (minimum !== undefined) {
          if (node.kind === "assert" || (node.kind === "escape" && /[bBAz]/.test(node.value[1]))) throw Error("quantified-assertion");
          if (source[at] === "?") { suffix += "?"; at++; }
          node = make({kind: "repeat", part: node, minimum, maximum, suffix});
        }
        parts.push(node);
      }
      choices.push(make(seq(parts)));
    } while (source[at] === "|");
    return make(alt(choices));
  }
  try {
    const tree = expression(0);
    return at === source.length ? tree : null;
  } catch { return null; }
}

const regexLiteral = (value) => value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
function emit(node) {
  switch (node.kind) {
    case "literal": return regexLiteral(node.value);
    case "assert": case "escape": case "class": return node.value;
    case "any": return ".";
    case "seq": return node.parts.map((part) => part.kind === "alt" ? "(?:" + emit(part) + ")" : emit(part)).join("");
    case "alt": return node.parts.map(emit).join("|");
    case "repeat": {
      const child = node.part, body = emit(child);
      return (child.kind === "seq" || child.kind === "alt" || child.kind === "repeat" ? "(?:" + body + ")" : body) + node.suffix;
    }
    default: throw Error("Unknown regex node");
  }
}

/** The sole algebraic rewrite: P A S | P B S = P (A|B) S.
 * Atom boundaries come from the parser. Escapes and classes are never split.
 * Capture identity and greediness are irrelevant only for boolean matching.
 */
function factor(node) {
  if (node.kind === "repeat") return {...node, part: factor(node.part)};
  if (node.kind !== "seq" && node.kind !== "alt") return node;
  let parts = node.parts.map(factor).flatMap((part) => part.kind === node.kind ? part.parts : [part]);
  if (node.kind === "seq") return seq(parts);
  parts = [...new Map(parts.map((part) => [emit(part), part])).values()];
  if (parts.length < 2) return alt(parts);
  const branches = parts.map((part) => part.kind === "seq" ? [...part.parts] : [part]);
  const prefix = [], suffix = [];
  while (branches.every((branch) => branch.length && emit(branch[0]) === emit(branches[0][0]))) {
    prefix.push(branches[0][0]); for (const branch of branches) branch.shift();
  }
  while (branches.every((branch) => branch.length && emit(branch.at(-1)) === emit(branches[0].at(-1)))) {
    suffix.unshift(branches[0].at(-1)); for (const branch of branches) branch.pop();
  }
  if (prefix.length || suffix.length) return seq([...prefix, factor(alt(branches.map(seq))), ...suffix]);
  const groups = new Map();
  for (const branch of branches) {
    const key = branch.length ? emit(branch[0]) : "";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(seq(branch));
  }
  // Factoring groups with a shared first atom is a trie over syntax atoms. A
  // group with no common atom is left as an ordinary disjunction.
  return alt([...groups.values()].map((group) => group.length > 1 ? factor(alt(group)) : group[0]));
}

/** Candidate exact OR, not a resource-budget approval. A caller must verify
 * the result with RE2 using the rule's actual flags before replacing rules.
 */
function unionPatterns(patterns) {
  if (!Array.isArray(patterns) || !patterns.length || patterns.length > 16) return null;
  const unique = [...new Set(patterns)].sort();
  const trees = unique.map(parse);
  if (trees.some((tree) => !tree)) return null;
  const candidate = emit(factor(alt(trees)));
  return candidate.length && candidate.length <= MAX_SOURCE ? candidate : null;
}

/** Exact finite expansion into urlFilter's literal / wildcard / anchor
 * language. Domain anchors (||) and separators (^) are never synthesized.
 * Equivalence is over the same ASCII canonical URL seen by both DNR matchers:
 * it contains no raw newline, and .* therefore has urlFilter * semantics.
 */
function lowerToUrlFilters(source, {maxFilters = MAX_FILTERS, maxFilterLength = MAX_FILTER_LENGTH} = {}) {
  if (!Number.isInteger(maxFilters) || maxFilters < 1 || maxFilters > MAX_FILTERS ||
      !Number.isInteger(maxFilterLength) || maxFilterLength < 1 || maxFilterLength > MAX_FILTER_LENGTH) return null;
  const tree = parse(source);
  if (!tree) return null;
  const combine = (a, b) => {
    if (a.length * b.length > maxFilters) throw Error("expansion");
    const out = [];
    for (const left of a) for (const right of b) {
      const tokens = [...left, ...right];
      if (tokens.length > maxFilterLength) throw Error("length");
      out.push(tokens);
    }
    return out;
  };
  function expand(node) {
    switch (node.kind) {
      case "literal":
        if (/[\s*^|\\]/.test(node.value)) throw Error("filter-metacharacter");
        return [[node.value]];
      case "assert": return [[node.value === "^" ? "START" : "END"]];
      case "seq": return node.parts.reduce((out, part) => combine(out, expand(part)), [[]]);
      case "alt": {
        const out = node.parts.flatMap(expand);
        if (out.length > maxFilters) throw Error("expansion");
        return out;
      }
      case "repeat": {
        if (node.part.kind === "any" && node.minimum === 0 && node.maximum === Infinity) return [["*"]];
        if (!Number.isFinite(node.maximum) || node.maximum > 64) throw Error("repeat-language");
        const atom = expand(node.part), out = []; let current = [[]];
        for (let count = 0; count <= node.maximum; count++) {
          if (count >= node.minimum) { out.push(...current); if (out.length > maxFilters) throw Error("expansion"); }
          if (count < node.maximum) current = combine(current, atom);
        }
        return out;
      }
      default: throw Error("unsupported-atom");
    }
  }
  try {
    const filters = [];
    for (const tokens of expand(tree)) {
      let beginning = "", ending = "";
      if (tokens[0] === "START") { tokens.shift(); beginning = "|"; }
      if (tokens.at(-1) === "END") { tokens.pop(); ending = "|"; }
      if (tokens.includes("START") || tokens.includes("END")) return null;
      const body = tokens.join("").replace(/\*+/g, "*");
      // Empty patterns and all-wildcard patterns require separate broad-rule
      // authority. Retain their original regex rather than minting one here.
      if (!body || !/[^*]/.test(body)) return null;
      const filter = beginning + body + ending;
      if (filter.length > maxFilterLength) return null;
      filters.push(filter);
    }
    return [...new Set(filters)];
  } catch { return null; }
}

module.exports = Object.freeze({lowerToUrlFilters, unionPatterns, MAX_FILTERS, MAX_FILTER_LENGTH});
