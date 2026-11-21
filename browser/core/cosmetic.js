/* Generic ad-slot hiding: a small first-party selector set, applied as one stylesheet (no per-element
 * script work), on by default and switchable off per site from the popup. Pure data and a CSS builder.
 *
 * Rules for adding a selector: it must name an ad container by a convention that ad servers or ad
 * frameworks themselves use (AdSense, Google Publisher Tag, Prebid, AMP, Taboola, Outbrain) or an
 * explicit "advertisement" label; never a word that ordinary content uses ("sponsored", "promo",
 * "banner"). Prefer class, id-prefix or tag-qualified attribute selectors: Chrome matches those from
 * a bucket, so the cost scales with matching elements, not with the whole page. No :has(), no
 * universal attribute selectors. MAX_SELECTORS caps the set; tests enforce both. */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;

  const GENERIC_SELECTORS = Object.freeze([
    // Google AdSense and Publisher Tag (GPT) slots.
    "ins.adsbygoogle",
    "div[id^=\"div-gpt-ad\"]",
    "div[id^=\"google_ads_iframe\"]",
    "iframe[id^=\"google_ads_iframe\"]",
    "div[data-google-query-id]",
    "div[data-ad-slot]",
    // Ad-server frames whose host the lists already block: the frame is empty, so hide the box.
    "iframe[src*=\"googlesyndication.com\"]",
    "iframe[src*=\"doubleclick.net\"]",
    "iframe[src*=\"amazon-adsystem.com\"]",
    "iframe[src*=\"adnxs.com\"]",
    // AMP ad elements.
    "amp-ad", "amp-sticky-ad", "amp-embed[type=\"taboola\"]", "amp-embed[type=\"outbrain\"]",
    // Content-recommendation ad widgets.
    "div.OUTBRAIN", "div.trc_related_container", "div[id^=\"taboola-\"]",
    // Explicitly labelled ad containers.
    "aside[aria-label=\"Advertisement\"]", "div[aria-label=\"Advertisement\"]", "section[aria-label=\"Advertisement\"]",
    "div[aria-label=\"advertisement\"]",
    // Common ad-slot class names (also on EasyList's generic list for years).
    ".ad-slot", ".ad-slot-container", ".ad-container", ".ad-wrapper", ".ad-unit", ".adunit", ".ad-placeholder",
    ".ad-banner", ".dfp-ad", ".gpt-ad", ".advertisement", ".ad-label", ".ad__slot", ".ad-slot__label",
  ]);
  const MAX_SELECTORS = 80;

  /** One stylesheet. Each selector is its own rule so a selector Chrome rejects cannot void the others. */
  function stylesheet(selectors = GENERIC_SELECTORS) {
    return selectors.slice(0, MAX_SELECTORS).map((s) => `${s}{display:none!important}`).join("\n");
  }

  const api = Object.freeze({GENERIC_SELECTORS, MAX_SELECTORS, stylesheet});
  if (isNode) module.exports = api;
  else root.EGCosmeticList = api;
})(globalThis);
