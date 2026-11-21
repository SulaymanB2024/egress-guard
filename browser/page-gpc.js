/* Global Privacy Control in the page's own world (Chrome): navigator.globalPrivacyControl === true, matching the
 * Sec-GPC: 1 header the extension adds to every request. Defined only where the browser does not already have it. */
(function () {
  "use strict";
  try {
    if ("globalPrivacyControl" in Navigator.prototype) return;
    Object.defineProperty(Navigator.prototype, "globalPrivacyControl", {get: function globalPrivacyControl() { return true; }, configurable: true, enumerable: true});
  } catch (e) { /* frozen prototype: nothing to do */ }
})();
