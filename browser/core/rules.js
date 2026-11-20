/* Typed rule and exception validation. Pure: no browser APIs.
 *
 * Request rule:  {id, kind:"request", site, host, path, types[], action:"block"|"allow", party?, expiresAt?, createdAt?, note?}
 * Cosmetic rule: {id, kind:"cosmetic", site, selector, expiresAt?, createdAt?, note?}
 * Exception:     {id, site, host, path, type, expiresAt}   (exact path, one type, always expires)
 *
 * `site` is the top-level page's host scope (that host and its subdomains). `host` is the exact
 * destination host. Paths are matched against the URL path only, never the query string. */
(function (root) {
  "use strict";
  const hosts = typeof module !== "undefined" && module.exports ? require("./hosts.js") : root.EGHosts;
  const selectors = typeof module !== "undefined" && module.exports ? require("./selectors.js") : root.EGSelectors;

  // main_frame is never blockable: a rule must not be able to stop navigation to a site.
  const RESOURCE_TYPES = Object.freeze(["beacon", "ping", "xmlhttprequest", "script", "image", "imageset", "stylesheet",
    "font", "media", "sub_frame", "websocket", "object", "csp_report", "other"]);
  const ACTIONS = Object.freeze(["block", "allow"]);
  const PARTIES = Object.freeze(["any", "first", "third"]);
  const MAX_PATH = 256;
  const MAX_WILDCARDS = 3;
  const MAX_NOTE = 120;
  const MAX_EXCEPTION_MINUTES = 24 * 60;
  const ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
  // No ( ) + $ ^ | ? [ ] { } \ : a pattern must not read as a regular expression or carry a query.
  const PATH_CHARS = /^\/[A-Za-z0-9\-._~%!&',;=:@/*]*$/;
  const REQUEST_FIELDS = new Set(["id", "kind", "site", "host", "path", "types", "action", "party", "expiresAt", "createdAt", "note"]);
  const COSMETIC_FIELDS = new Set(["id", "kind", "site", "selector", "expiresAt", "createdAt", "note"]);
  const EXCEPTION_FIELDS = new Set(["id", "site", "host", "path", "type", "expiresAt", "createdAt"]);

  class RuleError extends Error {}
  const fail = (message) => { throw new RuleError(message); };

  function plainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype;
  }

  function checkFields(value, allowed) {
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`Unknown field "${key}".`);
  }

  function checkScope(value, label) {
    const host = hosts.normalizeHost(value);
    if (!host) fail(`${label} must be a valid hostname (no IP addresses, ports, paths or wildcards).`);
    if (hosts.isSuffixLike(host)) fail(`${label} "${host}" looks like a public suffix; name one site.`);
    return host;
  }

  /** Validate a path pattern: literal path with up to three "*" wildcards and real literal content. */
  function checkPath(value, {exact = false} = {}) {
    if (typeof value !== "string" || value.length < 2 || value.length > MAX_PATH) fail(`Path must be 2-${MAX_PATH} characters starting with "/".`);
    if (!PATH_CHARS.test(value)) fail("Path contains characters that are not allowed (no query strings, spaces or regular expressions).");
    if (/\/\.\.?(?:\/|$)/.test(value)) fail("Path must not contain dot segments.");
    const stars = (value.match(/\*/g) || []).length;
    if (exact && stars) fail("Exceptions name one exact path; wildcards are not allowed.");
    if (stars > MAX_WILDCARDS) fail(`At most ${MAX_WILDCARDS} wildcards.`);
    if (/\*\*/.test(value)) fail("Consecutive wildcards are not allowed.");
    const literal = value.replace(/[*/]/g, "");
    if (literal.length < 2) fail("Path pattern is too broad; it must name an endpoint.");
    return value;
  }

  function checkExpiry(value, now) {
    if (value === undefined) return undefined;
    if (!Number.isSafeInteger(value) || value <= 0) fail("expiresAt must be a millisecond timestamp.");
    if (now !== undefined && value <= now) fail("expiresAt is already in the past.");
    return value;
  }

  function checkNote(value) {
    if (value === undefined) return undefined;
    if (typeof value !== "string" || value.length > MAX_NOTE || /[<>\u0000-\u001f]/.test(value)) fail(`note must be plain text of at most ${MAX_NOTE} characters.`);
    return value;
  }

  function checkId(value) {
    if (typeof value !== "string" || !ID.test(value)) fail("id must be 1-64 lowercase letters, digits or hyphens.");
    return value;
  }

  /** Validate a rule; returns a frozen normalized copy or throws RuleError. `now` rejects already-expired rules. */
  function validateRule(input, {now} = {}) {
    if (!plainObject(input)) fail("A rule must be a plain object.");
    const common = {id: checkId(input.id), site: checkScope(input.site, "site")};
    const expiresAt = checkExpiry(input.expiresAt, now);
    const note = checkNote(input.note);
    const createdAt = input.createdAt === undefined ? undefined : (Number.isSafeInteger(input.createdAt) && input.createdAt > 0 ? input.createdAt : fail("createdAt must be a millisecond timestamp."));
    const extra = {...(expiresAt !== undefined ? {expiresAt} : {}), ...(createdAt !== undefined ? {createdAt} : {}), ...(note !== undefined ? {note} : {})};
    if (input.kind === "request") {
      checkFields(input, REQUEST_FIELDS);
      const host = hosts.normalizeHost(input.host);
      if (!host) fail("host must be one exact, valid hostname.");
      const path = checkPath(input.path);
      if (!Array.isArray(input.types) || !input.types.length || input.types.length > RESOURCE_TYPES.length) fail("types must list one or more resource types.");
      const types = [...new Set(input.types)];
      for (const type of types) if (!RESOURCE_TYPES.includes(type)) fail(`Resource type "${type}" is not allowed.`);
      if (!ACTIONS.includes(input.action)) fail('action must be "block" or "allow".');
      const party = input.party === undefined ? "any" : (PARTIES.includes(input.party) ? input.party : fail('party must be "any", "first" or "third".'));
      return Object.freeze({kind: "request", ...common, host, path, types: Object.freeze(types.sort()), action: input.action, party, ...extra});
    }
    if (input.kind === "cosmetic") {
      checkFields(input, COSMETIC_FIELDS);
      const result = selectors.validateSelector(input.selector);
      if (!result.ok) fail(result.error);
      return Object.freeze({kind: "cosmetic", ...common, selector: input.selector.trim(), ...extra});
    }
    return fail('kind must be "request" or "cosmetic".');
  }

  /** Validate an exception. Exceptions always expire, at most 24 hours ahead of `now`. */
  function validateException(input, {now} = {}) {
    if (!plainObject(input)) fail("An exception must be a plain object.");
    checkFields(input, EXCEPTION_FIELDS);
    const id = checkId(input.id);
    const site = checkScope(input.site, "site");
    const host = hosts.normalizeHost(input.host);
    if (!host) fail("host must be one exact, valid hostname.");
    const path = checkPath(input.path, {exact: true});
    if (!RESOURCE_TYPES.includes(input.type)) fail("type must be one allowed resource type.");
    if (input.expiresAt === undefined) fail("Exceptions must expire.");
    const expiresAt = checkExpiry(input.expiresAt, now);
    if (now !== undefined && expiresAt - now > MAX_EXCEPTION_MINUTES * 60000) fail("Exceptions may last at most 24 hours.");
    return Object.freeze({id, site, host, path, type: input.type, expiresAt, ...(Number.isSafeInteger(input.createdAt) ? {createdAt: input.createdAt} : {})});
  }

  /** Non-throwing wrapper. */
  function check(fn, input, options) {
    try { return {ok: true, value: fn(input, options)}; } catch (error) {
      if (error instanceof RuleError || error instanceof selectors.SelectorError) return {ok: false, error: error.message};
      throw error;
    }
  }

  const api = Object.freeze({
    RESOURCE_TYPES, ACTIONS, PARTIES, MAX_EXCEPTION_MINUTES, RuleError,
    validateRule, validateException, checkPath,
    tryRule: (input, options) => check(validateRule, input, options),
    tryException: (input, options) => check(validateException, input, options),
  });
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGRules = api;
})(globalThis);
