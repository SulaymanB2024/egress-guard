/* Egress Guard surrogate for Google Publisher Tag (gpt.js) and AdSense (adsbygoogle.js): the APIs exist, every
 * slot stays empty, nothing is requested. googletag.cmd functions run, so page code queued behind them continues. */
(function () {
  "use strict";
  var w = window;
  var noop = function () {};
  var self = function () { return this; };
  var run = function (fn) { if (typeof fn === "function") { try { fn(); } catch (e) { /* page's own error */ } } };
  var slot = function (path, sizes, div) {
    var s = {};
    ["addService", "clearCategoryExclusions", "clearTargeting", "defineSizeMapping", "set", "setCategoryExclusion", "setClickUrl",
      "setCollapseEmptyDiv", "setForceSafeFrame", "setSafeFrameConfig", "setTargeting", "updateTargetingFromMap", "setConfig"].forEach(function (m) { s[m] = self; });
    s.getAdUnitPath = function () { return path || ""; };
    s.getSlotElementId = function () { return div || ""; };
    s.getTargeting = function () { return []; };
    s.getTargetingKeys = function () { return []; };
    s.getSizes = function () { return sizes || []; };
    s.getResponseInformation = function () { return null; };
    s.getConfig = function () { return {}; };
    return s;
  };
  var pubads = {};
  ["addEventListener", "removeEventListener", "clear", "clearTargeting", "collapseEmptyDivs", "disableInitialLoad", "display", "enableAsyncRendering",
    "enableLazyLoad", "enableSingleRequest", "enableVideoAds", "refresh", "set", "setCentering", "setCookieOptions", "setForceSafeFrame",
    "setLocation", "setPrivacySettings", "setPublisherProvidedId", "setRequestNonPersonalizedAds", "setSafeFrameConfig", "setTargeting",
    "setVideoContent", "updateCorrelator", "setTagForChildDirectedTreatment", "setConfig"].forEach(function (m) { pubads[m] = function () { return pubads; }; });
  pubads.getTargeting = function () { return []; };
  pubads.getTargetingKeys = function () { return []; };
  pubads.getSlots = function () { return []; };
  pubads.isInitialLoadDisabled = function () { return false; };
  var gt = w.googletag = w.googletag || {};
  var queued = Array.isArray(gt.cmd) ? gt.cmd.slice() : [];
  gt.apiReady = true;
  gt.pubadsReady = true;
  gt.cmd = {push: function () { for (var i = 0; i < arguments.length; i++) run(arguments[i]); return 0; }};
  gt.defineSlot = function (path, sizes, div) { return slot(path, sizes, div); };
  gt.defineOutOfPageSlot = function (path, div) { return slot(path, [], div); };
  gt.destroySlots = function () { return true; };
  gt.display = noop;
  gt.enableServices = noop;
  gt.disablePublisherConsole = noop;
  gt.openConsole = noop;
  gt.getVersion = function () { return ""; };
  gt.pubads = function () { return pubads; };
  gt.companionAds = function () { return pubads; };
  gt.content = function () { return pubads; };
  gt.sizeMapping = function () { var m = {addSize: function () { return m; }, build: function () { return []; }}; return m; };
  gt.setConfig = noop;
  gt.setAdIframeTitle = noop;
  gt.secureSignalProviders = {push: noop, clearAllCache: noop};
  gt.enums = {OutOfPageFormat: {}, TrafficSource: {}};
  queued.forEach(run);
  // AdSense
  var ads = w.adsbygoogle;
  w.adsbygoogle = {loaded: true, push: noop};
  void ads;
})();
