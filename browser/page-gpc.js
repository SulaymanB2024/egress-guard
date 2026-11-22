/* Global Privacy Control fallback in document MAIN worlds (Chrome).
 * The extension's eligible network requests carry Sec-GPC: 1. This fallback
 * supplies navigator.globalPrivacyControl only where no property already exists.
 * A browser/other implementation's existing value, including false, is preserved;
 * therefore HTTP/JS agreement is not asserted for those contexts or for workers.
 *
 * Shaped like a native accessor as far as is cheap: an enumerable, configurable getter on Navigator.prototype (never an
 * own property of navigator), whose function is a bound native function (Boolean bound to true). So its toString()
 * reads "function () { [native code] }", it has no prototype and length 0, its name is set to the native-looking
 * "get globalPrivacyControl", and calling it never puts an extension frame on the stack. A script can still tell it
 * from a native getter (the toString lacks the name; it does not throw on a foreign receiver).
 * This is an extension-defined signal, NOT native GPC, fingerprint resistance,
 * proof of a site's compliance, or a worker shim. No DNT preference is changed. */
(function () {
  "use strict";
  try {
    if (typeof Navigator === "undefined" || typeof navigator === "undefined") return;
    if ("globalPrivacyControl" in navigator || "globalPrivacyControl" in Navigator.prototype) return;
    const get = Boolean.bind(null, true);
    Object.defineProperty(get, "name", {value: "get globalPrivacyControl", configurable: true});
    Object.defineProperty(Navigator.prototype, "globalPrivacyControl", {get, set: undefined, configurable: true, enumerable: true});
  } catch (e) { /* frozen prototype: nothing to do */ }
})();
