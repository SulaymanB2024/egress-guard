/* Global Privacy Control in the page's own world (Chrome): navigator.globalPrivacyControl === true, matching the
 * Sec-GPC: 1 header the extension adds to every request. Defined only where the browser does not already have it.
 *
 * Shaped like a native accessor as far as is cheap: an enumerable, configurable getter on Navigator.prototype (never an
 * own property of navigator), whose function is a bound native function (Boolean bound to true). So its toString()
 * reads "function () { [native code] }", it has no prototype and length 0, its name is set to the native-looking
 * "get globalPrivacyControl", and calling it never puts an extension frame on the stack. A script can still tell it
 * from a native getter (the toString lacks the name; it does not throw on a foreign receiver); see the docs. */
(function () {
  "use strict";
  try {
    if ("globalPrivacyControl" in Navigator.prototype) return;
    const get = Boolean.bind(null, true);
    Object.defineProperty(get, "name", {value: "get globalPrivacyControl", configurable: true});
    Object.defineProperty(Navigator.prototype, "globalPrivacyControl", {get, set: undefined, configurable: true, enumerable: true});
  } catch (e) { /* frozen prototype: nothing to do */ }
})();
