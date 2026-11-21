/* Egress Guard surrogate for Segment analytics.js: the snippet's queue is drained into no-ops. ready() and the
 * optional callbacks of track/page/identify/group/alias are called, so code waiting on them continues. */
(function () {
  "use strict";
  var w = window;
  // The page callback runs straight from the timer, so no surrogate frame (no extension address) is on its stack.
  var later = function (fn, arg) { if (typeof fn === "function") setTimeout(fn, 0, arg); };
  var lastFn = function (args) { for (var i = args.length - 1; i >= 0; i--) if (typeof args[i] === "function") return args[i]; return null; };
  var old = w.analytics;
  var user = {id: function () { return null; }, anonymousId: function () { return null; }, traits: function () { return {}; }};
  var api = {initialized: true, invoked: true, VERSION: "0.0.0",
    user: function () { return user; }, group: function () { later(lastFn(arguments)); }, reset: function () {}, debug: function () {},
    on: function () {}, once: function () {}, off: function () {}, addSourceMiddleware: function () {}, addIntegrationMiddleware: function () {},
    setAnonymousId: function () {}, addDestinationMiddleware: function () {}, load: function () {}, register: function () {}};
  ["track", "page", "identify", "alias", "screen", "trackSubmit", "trackClick", "trackLink", "trackForm", "pageview"].forEach(function (m) {
    api[m] = function () { later(lastFn(arguments)); };
  });
  api.ready = function (fn) { later(fn); };
  w.analytics = api;
  if (Array.isArray(old)) for (var i = 0; i < old.length; i++) {
    var call = old[i];
    if (call && typeof api[call[0]] === "function") api[call[0]].apply(api, Array.prototype.slice.call(call, 1));
  }
})();
