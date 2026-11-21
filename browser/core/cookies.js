/* Tracking cookies the Chrome worker removes as soon as they are set (chrome.cookies.onChanged), first or third party.
 * Pure: no browser APIs.
 *
 * Each entry is an analytics, advertising or attribution identifier: a visitor id, a session id or a stored click id
 * (gclid -> _gcl_aw, fbclid -> _fbc, msclkid -> _uetmsclkid, Reddit's and TikTok's click ids). None of them holds a
 * login, a cart, a consent choice or a preference, so removing them changes what trackers can link, not what the site
 * does. Scripts that set them again get a fresh, unlinked value each time.
 *
 * A name is matched everywhere only when it is unique to one tracker. A name another product could also use (IDE,
 * DSID, which is also the Pulse / Ivanti Connect Secure VPN session cookie, test_cookie, uuid2, anj, muc_ads, …) is
 * matched only on its vendor's own domains (`domains`). Opt-out and consent cookies are never removed, whatever their
 * name: deleting one would switch tracking back on (NEVER, checked first). docs/browser-companion.md has the table
 * with a reason for every entry.
 *   remove   deleted at once.
 *   session  rewritten without an expiry (gone when Chrome closes). No pattern uses it today (see MUID below). */
(function (root) {
  "use strict";

  // Opt-out, consent and do-not-track records: never touched (_hjOptOut, taboola_optout, _cs_c, mtm_consent, …).
  const NEVER = /opt-?out|optout|opt_out|consent|gdpr|ccpa|usprivacy|donottrack|do_not_track|^_cs_c$/i;

  const RULES = Object.freeze([
    // Google Analytics, Ads, Tag Manager, Ad Manager; legacy urchin
    {re: /^_ga(_[A-Z0-9]{4,16})?$/, vendor: "Google Analytics"}, {re: /^_gid$/, vendor: "Google Analytics"}, {re: /^_gat(_.+)?$/, vendor: "Google Analytics"},
    {re: /^_gcl_(au|aw|dc|gb|gf|ha|ag|gs)$/, vendor: "Google Ads"}, {re: /^_gac_.+$/, vendor: "Google Ads"}, {re: /^_dc_gtm_.+$/, vendor: "Google Tag Manager"},
    {re: /^__utm[abcvtz]$/, vendor: "Google Analytics (legacy)"}, {re: /^__gads$|^__gpi$|^__eoi$/, vendor: "Google Ad Manager"},
    {re: /^IDE$|^test_cookie$|^DSID$/, vendor: "DoubleClick", domains: ["doubleclick.net"]},
    {re: /^FPID$|^FPLC$|^FPGCLAW$|^FPAU$/, vendor: "Google first-party tagging"},
    // Meta, Microsoft, TikTok, Snap, Pinterest, Reddit, LinkedIn, X
    {re: /^_fbp$|^_fbc$/, vendor: "Meta"}, {re: /^_uetsid$|^_uetvid$|^_uetmsclkid$/, vendor: "Microsoft Advertising"},
    // Not MUID: cutting Microsoft's MUID to a session cookie made Bing search render no results (real-site run,
    // 2026-11-21), and Microsoft sign-in reads it too. Bing's own tracking is blocked by URL instead.
    {re: /^_ttp$|^_tt_enable_cookie$|^ttcsid(_.+)?$/, vendor: "TikTok"}, {re: /^_scid(_r)?$|^_sctr$|^_screload$/, vendor: "Snap"},
    {re: /^_pin_unauth$|^_pinterest_ct_ua$|^_pinterest_ct_rt$|^_epik$|^_derived_epik$/, vendor: "Pinterest"},
    {re: /^_rdt_uuid$|^_rdt_cid$|^_rdt_em$/, vendor: "Reddit"}, {re: /^li_fat_id$|^_li_dcdm_c$|^li_sugr$/, vendor: "LinkedIn"},
    {re: /^_twclid$/, vendor: "X"}, {re: /^muc_ads$/, vendor: "X", domains: ["twitter.com", "x.com"]},
    // Product analytics and session replay. Hotjar: its visitor, session and sampling ids only (not its opt-out flag,
    // not the poll and survey state that stops a widget from asking again).
    {re: /^_hj(SessionUser|Session)_[0-9]+$|^_hjid$|^_hjFirstSeen$|^_hjAbsoluteSessionInProgress$|^_hjIncludedIn(Session|Pageview)Sample(_[0-9]+)?$|^_hjRecording(Enabled|LastActivity)$|^_hjSessionRejected$|^_hjCachedUserAttributes$|^_hjUserAttributesHash$/, vendor: "Hotjar"},
    {re: /^ajs_(anonymous_id|user_id|group_id)$/, vendor: "Segment"}, {re: /^mp_[0-9a-f]+_mixpanel$/, vendor: "Mixpanel"},
    {re: /^amplitude_id_.+$|^AMP_(MKTG_)?[0-9a-f]{10}$/, vendor: "Amplitude"}, {re: /^_clck$|^_clsk$/, vendor: "Microsoft Clarity"},
    {re: /^_pk_(id|ses|ref|cvar|hsr)\..+$/, vendor: "Matomo"}, {re: /^_sp_(id|ses)\..+$/, vendor: "Snowplow"}, {re: /^_hp2_(id|ses_props|props)\..+$/, vendor: "Heap"},
    {re: /^_ym_(uid|d|isad|visorc)$/, vendor: "Yandex Metrica"}, {re: /^_parsely_(session|visitor)$/, vendor: "Parse.ly"},
    {re: /^__hstc$|^__hssc$|^__hssrc$|^hubspotutk$/, vendor: "HubSpot"}, {re: /^_mkto_trk$/, vendor: "Marketo"},
    {re: /^ph_phc_[A-Za-z0-9]+_posthog$/, vendor: "PostHog"}, {re: /^_lr_(uf|hb|tabs)_.+$/, vendor: "LogRocket"},
    {re: /^_fs_(uid|cd)$|^fs_uid$/, vendor: "FullStory"}, {re: /^_cs_(id|s)$/, vendor: "Contentsquare"},
    {re: /^_tq_id\..+$/, vendor: "TaboolaPush"}, {re: /^taboola_(session_id|fp_td_user_id|select|global_user_id)$/, vendor: "Taboola"},
    {re: /^t_gid$/, vendor: "Taboola", domains: ["taboola.com"]}, {re: /^outbrain_cid_fetch$|^obuid$/, vendor: "Outbrain"},
    {re: /^_kuid_$|^_cc_(id|cc|aud)$/, vendor: "Salesforce DMP", domains: ["krxd.net"]}, {re: /^_an_uid$/, vendor: "Xandr"},
    {re: /^uuid2$|^anj$/, vendor: "Xandr", domains: ["adnxs.com"]},
    {re: /^__qca$/, vendor: "Quantcast"}, {re: /^_cb_ls$|^_cb_svref$|^_chartbeat[0-9]$/, vendor: "Chartbeat"},
  ]);

  const lower = (d) => String(d || "").toLowerCase().replace(/^\./, "").replace(/\.$/, "");
  const covers = (host, domains) => domains.some((d) => host === d || host.endsWith(`.${d}`));

  /** "remove", "session" or null for a cookie `name` set on `domain` (the cookie's Domain, leading dot allowed). */
  function classify(name, domain) {
    if (typeof name !== "string" || !name || name.length > 256) return null;
    if (NEVER.test(name)) return null;
    const host = lower(domain);
    const hit = RULES.find((r) => r.re.test(name) && (!r.domains || (host && covers(host, r.domains))));
    return hit ? (hit.action || "remove") : null;
  }

  const api = Object.freeze({RULES, NEVER, classify});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGCookies = api;
})(globalThis);
