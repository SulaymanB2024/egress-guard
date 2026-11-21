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
  var layer = w[layerName] = w[layerName] || [];
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
