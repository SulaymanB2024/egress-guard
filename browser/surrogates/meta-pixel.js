/* Egress Guard surrogate for the Meta (Facebook) pixel, fbevents.js: fbq() exists and does nothing. */
(function () {
  "use strict";
  var w = window;
  var queued = w.fbq && w.fbq.queue;
  var fbq = function () {};
  fbq.callMethod = function () {};
  fbq.queue = [];
  fbq.push = fbq;
  fbq.loaded = true;
  fbq.version = "2.0";
  fbq.getState = function () { return {pixels: []}; };
  w.fbq = fbq;
  if (!w._fbq) w._fbq = fbq;
  void queued;
})();
