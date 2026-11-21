/* Egress Guard surrogate for Adobe Experience Platform Launch / DTM (_satellite) and AppMeasurement (s): no-ops. */
(function () {
  "use strict";
  var w = window;
  var noop = function () {};
  var sat = {track: noop, getVar: function () { return ""; }, setVar: noop, getVisitorId: function () { return null; }, pageBottom: noop,
    notify: noop, logger: {log: noop, info: noop, warn: noop, error: noop}, cookie: {get: function () { return ""; }, set: noop, remove: noop},
    buildInfo: {}, property: {name: ""}, company: {orgId: ""}, environment: {stage: "production"}, _container: {}};
  w._satellite = w._satellite || sat;
  if (typeof w.s_gi !== "function") {
    var s = {t: function () { return ""; }, tl: function (a, b, c, d, done) { if (typeof done === "function") setTimeout(done, 0); return ""; },
      clearVars: noop, abort: false, Util: {getQueryParam: function () { return ""; }}};
    w.s_gi = function () { return s; };
    w.s = w.s || s;
  }
})();
