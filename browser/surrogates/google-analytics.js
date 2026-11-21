/* Egress Guard surrogate for Google Analytics (analytics.js, ga.js): the same API, no network, no storage.
 * hitCallback / eventCallback are called so links and forms that wait for a "sent" event still work. */
(function () {
  "use strict";
  var w = window;
  // The page callback runs straight from the timer, so no surrogate frame (no extension address) is on its stack.
  var later = function (fn, arg) { if (typeof fn === "function") setTimeout(fn, 0, arg); };
  var callbackOf = function (args) {
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      if (a && typeof a === "object") { later(a.hitCallback); later(a.eventCallback); }
    }
  };
  var tracker = {get: function () {}, set: function () {}, send: function () { callbackOf(arguments); }, toString: function () { return ""; }};
  var ga = function () {
    var args = arguments;
    if (typeof args[0] === "function") { later(args[0], tracker); return; }
    callbackOf(args);
  };
  ga.create = function () { return tracker; };
  ga.getByName = function () { return tracker; };
  ga.getAll = function () { return [tracker]; };
  ga.remove = function () {};
  ga.loaded = true;
  var name = w.GoogleAnalyticsObject || "ga";
  var queued = w[name] && w[name].q;
  w[name] = ga;
  if (queued && queued.length) for (var i = 0; i < queued.length; i++) ga.apply(null, queued[i]);
  // Legacy ga.js
  var legacy = {_trackPageview: function () {}, _trackEvent: function () {}, _setAccount: function () {}, _getLinkerUrl: function (u) { return u; }, _link: function (u) { location.href = u; }};
  w._gat = {_getTracker: function () { return legacy; }, _createTracker: function () { return legacy; }, _getTrackerByName: function () { return legacy; }, _anonymizeIp: function () {}};
  var q = w._gaq;
  w._gaq = {push: function () { for (var j = 0; j < arguments.length; j++) if (typeof arguments[j] === "function") later(arguments[j]); return 0; }};
  if (Array.isArray(q)) w._gaq.push.apply(null, q);
})();
