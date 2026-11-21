/* Egress Guard surrogate for Google Tag Manager and gtag.js: no network, no storage.
 * Pages often wait for GTM before navigating (dataLayer.push({event, eventCallback})); the callback is called so
 * those links and forms still work. gtag("get", …, callback) gets undefined. */
(function () {
  "use strict";
  var w = window;
  // The page callback runs straight from the timer, so no surrogate frame (no extension address) is on its stack.
  var later = function (fn, arg) { if (typeof fn === "function") setTimeout(fn, 0, arg); };
  var handle = function (item) {
    if (!item || typeof item !== "object") return;
    later(item.eventCallback);
    // gtag(...) queues the arguments object itself: gtag("event", name, {event_callback}) and gtag("get", id, field, cb)
    if (item.length !== undefined) {
      if (item[0] === "event" && item[2] && typeof item[2] === "object") later(item[2].event_callback);
      if (item[0] === "get") later(item[3]);
    }
  };
  var layerName = "dataLayer";
  // The original script element retains its src attribute when its request is redirected.
  // GTM/gtag document a custom global queue through ?l=name. Do not walk arbitrary globals,
  // evaluate a path, invoke an accessor, or assign inherited/prototype-sensitive names.
  try {
    var script = typeof document !== "undefined" ? document.currentScript : null;
    var src = script && (typeof script.getAttribute === "function" ? script.getAttribute("src") : script.src);
    var match = typeof src === "string" && src.length <= 8192 ? /[?&]l=([^&#]*)/.exec(src) : null;
    if (match) {
      var requested = decodeURIComponent(match[1].replace(/\+/g, " "));
      if (!/^[A-Za-z_$][A-Za-z0-9_$]{0,79}$/.test(requested) || /^(?:__proto__|prototype|constructor)$/.test(requested)) return;
      layerName = requested;
    }
    var descriptor = Object.getOwnPropertyDescriptor(w, layerName);
    if (descriptor && (!("value" in descriptor) || !Array.isArray(descriptor.value))) return;
    if (!descriptor) Object.defineProperty(w, layerName, {value: [], writable: true, configurable: true, enumerable: true});
  } catch { return; }
  var layer = w[layerName];
  for (var i = 0; i < layer.length; i++) handle(layer[i]);
  var push = Array.prototype.push;
  layer.push = function () {
    for (var j = 0; j < arguments.length; j++) handle(arguments[j]);
    return push.apply(layer, arguments);
  };
  if (typeof w.gtag !== "function") w.gtag = function () { layer.push(arguments); };
  w.google_tag_manager = w.google_tag_manager || {dataLayer: {get: function () {}, set: function () {}, reset: function () {}}};
  w.google_tag_data = w.google_tag_data || {};
})();
