/* Fixed, opt-in UA Client Hints restrictions. This module has no browser I/O.
 * Installation/readback belongs to the service worker's existing DNR owner.
 * A rule receipt is not evidence of native browser or connection behavior. */
(function (root) {
  "use strict";
  const KEY = "egressGuardPrivacyHardening";
  const FIRST_ID = 2000000000;
  const RULE_COUNT = 2;
  const PRIORITY = 48;
  const REQUEST_HEADERS = Object.freeze([
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-form-factors",
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-model",
    "sec-ch-ua-platform-version", "sec-ch-ua-wow64",
  ]);
  const DIRECTIVES = Object.freeze([
    "ch-ua-high-entropy-values", "ch-ua-arch", "ch-ua-bitness", "ch-ua-form-factors",
    "ch-ua-full-version", "ch-ua-full-version-list", "ch-ua-model",
    "ch-ua-platform-version", "ch-ua-wow64",
  ]);
  const POLICY = DIRECTIVES.map(name => `${name}=()`).join(", ");
  const RESOURCE_TYPES = Object.freeze([
    "main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object",
    "xmlhttprequest", "ping", "csp_report", "media", "websocket", "webtransport", "webbundle", "other",
  ]);
  const CAPABILITIES = Object.freeze({
    experimental: true,
    evidence: "installed-rules-only",
    behaviorVerified: false,
    requestScope: "exposed-http-and-https-requests",
    documentPolicy: "only-when-permissions-policy-is-absent",
    workerJavaScript: "not-qualified",
    existingDocuments: "reload-required",
    browserRouting: "not-verified",
  });
  const plain = value => value && typeof value === "object" && !Array.isArray(value);
  function validateState(value) {
    if (!plain(value) || value.schema !== 1 || typeof value.enabled !== "boolean" ||
        !Number.isSafeInteger(value.revision) || value.revision < 1 ||
        Object.keys(value).some(key => !["schema", "revision", "enabled"].includes(key))) {
      throw new Error("Saved Client Hints choices are invalid. Apply a new choice or release this control to recover.");
    }
    return {schema: 1, revision: value.revision, enabled: value.enabled};
  }
  function validateEnabled(value) {
    if (typeof value !== "boolean") throw new Error("Client Hints control must be explicitly enabled or disabled.");
    return value;
  }
  function compile({enabled = false, firstId = FIRST_ID, priority = PRIORITY} = {}) {
    validateEnabled(enabled);
    if (!Number.isSafeInteger(firstId) || firstId < 1 || firstId + RULE_COUNT - 1 > 2147483647 ||
        !Number.isSafeInteger(priority) || priority < 1 || priority > 2147483647) throw new Error("Invalid Client Hints rule allocation.");
    if (!enabled) return [];
    return [
      {
        id: firstId, priority,
        action: {type: "modifyHeaders", requestHeaders: REQUEST_HEADERS.map(header => ({header, operation: "remove"}))},
        // Chrome presents parsed URLs. The anchored prefix covers HTTP and HTTPS;
        // this does not assert coverage of browser-owned traffic or other schemes.
        condition: {urlFilter: "|http", resourceTypes: [...RESOURCE_TYPES]},
      },
      {
        id: firstId + 1, priority,
        action: {type: "modifyHeaders", responseHeaders: [{header: "permissions-policy", operation: "append", value: POLICY}]},
        condition: {urlFilter: "|http", resourceTypes: ["main_frame", "sub_frame"],
          // Never combine with an existing dictionary: invalid syntax and the
          // browser's 64KiB parser limit can invalidate ALL of a site's policies.
          // Even an empty, duplicated or malformed existing header stands down.
          excludedResponseHeaders: [{header: "permissions-policy"}]},
      },
    ];
  }
  function ownsRuleId(id) { return Number.isInteger(id) && id >= FIRST_ID && id < FIRST_ID + RULE_COUNT; }
  const api = Object.freeze({KEY, FIRST_ID, RULE_COUNT, PRIORITY, REQUEST_HEADERS, DIRECTIVES, POLICY, RESOURCE_TYPES,
    CAPABILITIES, validateState, validateEnabled, compile, ownsRuleId});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGPrivacyHardening = api;
})(globalThis);
