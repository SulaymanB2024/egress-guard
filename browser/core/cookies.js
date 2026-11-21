/* Tracking cookies the Chrome worker removes as soon as they are set (chrome.cookies.onChanged), on any site, first
 * or third party, by name. Pure: no browser APIs.
 *
 * Each entry is an analytics, advertising or attribution identifier: a visitor id, a session id or a stored click id
 * (gclid -> _gcl_aw, fbclid -> _fbc, msclkid -> _uetmsclkid, Reddit's and TikTok's click ids). None of them holds a
 * login, a cart, a consent choice or a preference, so removing them changes what trackers can link, not what the site
 * does. Scripts that set them again get a fresh, unlinked value each time.
 *   remove   deleted at once.
 *   session  rewritten without an expiry (gone when Chrome closes). No pattern uses it today (see MUID below).
 * Reviewed against the vendors' own cookie documentation; consent-manager cookies (OptanonConsent, CookieConsent,
 * euconsent-v2, _iub_cs, …) are never touched, and neither is anything not matched here. */
(function (root) {
  "use strict";

  const RULES = Object.freeze([
    // Google Analytics, Ads, Tag Manager, Ad Manager; legacy urchin
    {re: /^_ga(_[A-Z0-9]{4,16})?$/, vendor: "Google Analytics"}, {re: /^_gid$/, vendor: "Google Analytics"}, {re: /^_gat(_.+)?$/, vendor: "Google Analytics"},
    {re: /^_gcl_(au|aw|dc|gb|gf|ha|ag|gs)$/, vendor: "Google Ads"}, {re: /^_gac_.+$/, vendor: "Google Ads"}, {re: /^_dc_gtm_.+$/, vendor: "Google Tag Manager"},
    {re: /^__utm[abcvtz]$/, vendor: "Google Analytics (legacy)"}, {re: /^__gads$|^__gpi$|^__eoi$/, vendor: "Google Ad Manager"},
    {re: /^IDE$|^test_cookie$|^DSID$/, vendor: "DoubleClick"}, {re: /^FPID$|^FPLC$|^FPGCLAW$|^FPAU$/, vendor: "Google first-party tagging"},
    // Meta, Microsoft, TikTok, Snap, Pinterest, Reddit, LinkedIn, X, Quora
    {re: /^_fbp$|^_fbc$/, vendor: "Meta"}, {re: /^_uetsid$|^_uetvid$|^_uetmsclkid$/, vendor: "Microsoft Advertising"},
    // Not MUID: cutting Microsoft's MUID to a session cookie made Bing search render no results (real-site run,
    // 2026-11-21), and Microsoft sign-in reads it too. Bing's own tracking is blocked by URL instead.
    {re: /^_ttp$|^_tt_enable_cookie$|^ttcsid(_.+)?$/, vendor: "TikTok"}, {re: /^_scid(_r)?$|^_sctr$|^_screload$/, vendor: "Snap"},
    {re: /^_pin_unauth$|^_pinterest_ct_ua$|^_pinterest_ct_rt$|^_epik$|^_derived_epik$/, vendor: "Pinterest"},
    {re: /^_rdt_uuid$|^_rdt_cid$|^_rdt_em$/, vendor: "Reddit"}, {re: /^li_fat_id$|^_li_dcdm_c$|^li_sugr$/, vendor: "LinkedIn"},
    {re: /^_twclid$|^muc_ads$/, vendor: "X"},
    // Product analytics and session replay
    {re: /^_hj.+$/, vendor: "Hotjar"}, {re: /^ajs_(anonymous_id|user_id|group_id)$/, vendor: "Segment"}, {re: /^mp_[0-9a-f]+_mixpanel$/, vendor: "Mixpanel"},
    {re: /^amplitude_id_.+$|^AMP_(MKTG_)?[0-9a-f]{10}$/, vendor: "Amplitude"}, {re: /^_clck$|^_clsk$/, vendor: "Microsoft Clarity"},
    {re: /^_pk_(id|ses|ref|cvar|hsr)\..+$/, vendor: "Matomo"}, {re: /^_sp_(id|ses)\..+$/, vendor: "Snowplow"}, {re: /^_hp2_(id|ses_props|props)\..+$/, vendor: "Heap"},
    {re: /^_ym_(uid|d|isad|visorc)$/, vendor: "Yandex Metrica"}, {re: /^_parsely_(session|visitor)$/, vendor: "Parse.ly"},
    {re: /^__hstc$|^__hssc$|^__hssrc$|^hubspotutk$/, vendor: "HubSpot"}, {re: /^_mkto_trk$/, vendor: "Marketo"},
    {re: /^ph_phc_[A-Za-z0-9]+_posthog$/, vendor: "PostHog"}, {re: /^_lr_(uf|hb|tabs)_.+$/, vendor: "LogRocket"},
    {re: /^_fs_(uid|cd)$|^fs_uid$/, vendor: "FullStory"}, {re: /^_cs_(id|s|c)$/, vendor: "Contentsquare"},
    {re: /^_tq_id\..+$/, vendor: "TaboolaPush"}, {re: /^t_gid$|^taboola_.+$/, vendor: "Taboola"}, {re: /^outbrain_cid_fetch$|^obuid$/, vendor: "Outbrain"},
    {re: /^_kuid_$|^_cc_(id|cc|aud)$/, vendor: "Salesforce DMP"}, {re: /^_an_uid$|^uuid2$|^anj$/, vendor: "Xandr"},
    {re: /^__qca$/, vendor: "Quantcast"}, {re: /^_cb(_ls|_svref)?$|^_chartbeat\d$/, vendor: "Chartbeat"},
  ]);

  /** "remove", "session" or null for a cookie name. */
  function classify(name) {
    if (typeof name !== "string" || !name || name.length > 256) return null;
    const hit = RULES.find((r) => r.re.test(name));
    return hit ? (hit.action || "remove") : null;
  }

  const api = Object.freeze({RULES, classify});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGCookies = api;
})(globalThis);
