/* Link cleaning: which query parameters are tracking, and a cleaner that removes them. Pure: no browser APIs.
 *
 * The same data drives two layers. core/dnr.js compiles it into navigation redirects (every top-level and frame
 * navigation, including links opened from other apps), and page-guard.js uses cleanUrl() to rewrite a link's href at
 * click time, so "Copy link address" and middle-click get the clean address too.
 *
 * Built from first principles (what each vendor documents its parameters for) and checked for coverage against
 * ClearURLs, Brave's and Firefox's query stripping and AdGuard's URL tracking filter; names only, no data copied.
 * Generic parameters are global. Ambiguous names (ref, source, src, tag, cid, si, s, t) are removed only on the sites
 * where they are known to be tracking. Never removed anywhere: authentication, OAuth and payment parameters, the
 * unsubscribe tokens in KEPT, pagination and search queries. */
(function (root) {
  "use strict";

  const GLOBAL = Object.freeze([
    // Campaign tags: Google Analytics / Ads, Matomo / Piwik, Adobe, Webtrends, Yandex, HubSpot ads
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id", "utm_name", "utm_cid", "utm_reader", "utm_referrer",
    "utm_social", "utm_social-type", "utm_brand", "utm_place", "utm_pubreferrer", "utm_swu", "utm_source_platform", "utm_creative_format",
    "utm_marketing_tactic", "utm_campaign_id", "utm_viz_id", "utm_keyword", "utm_matchtype", "utm_device", "utm_adgroup",
    "pk_campaign", "pk_kwd", "pk_keyword", "pk_source", "pk_medium", "pk_content", "pk_cid",
    "piwik_campaign", "piwik_kwd", "piwik_keyword",
    "mtm_campaign", "mtm_keyword", "mtm_kwd", "mtm_source", "mtm_medium", "mtm_content", "mtm_cid", "mtm_group", "mtm_placement",
    "hsa_acc", "hsa_cam", "hsa_grp", "hsa_ad", "hsa_src", "hsa_tgt", "hsa_kw", "hsa_mt", "hsa_net", "hsa_ver", "hsa_la", "hsa_ol",
    "s_cid", "s_kwcid", "ef_id", "WT.mc_id", "WT.tsrc", "_openstat", "yclid", "ysclid",
    // Click ids: Google, Microsoft, Meta, X, TikTok, LinkedIn, Snapchat, Reddit, Pinterest, Impact, Taboola, Outbrain, Branch
    "gclid", "gclsrc", "gbraid", "wbraid", "dclid", "gad_source", "gad_campaignid", "srsltid", "_gl", "_ga", "_gac",
    "msclkid", "fbclid", "twclid", "ttclid", "li_fat_id", "igshid", "igsh", "epik", "_derived_epik", "ScCid", "sccid", "rdt_cid",
    "irclickid", "irgwc", "ndclid", "tblci", "dicbo", "obOrigUrl", "rb_clickid", "wickedid", "_branch_match_id", "_branch_referrer",
    "mibextid", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source", "action_object_map", "action_type_map", "action_ref_map",
    "__tn__", "__cft__[0]", "__xts__[0]",
    // Email platforms' subscriber and campaign ids (they identify the reader on the landing page). Not the ones that
    // double as the recipient's credential on preference and unsubscribe pages (ConvertKit ck_subscriber_id, MailerLite
    // ml_subscriber(_hash), Eloqua elq / elqTrackId): those are in KEPT.
    "mc_cid", "mc_eid", "oly_anon_id", "oly_enc_id", "vero_id", "vero_conv", "_kx", "__s", "vgo_ee",
    "_bhlid", "_bta_tid", "_bta_c", "dm_i", "sms_source", "sms_click", "sms_uph", "spReportId",
    "spJobID", "spUserID", "spMailingID", "elqTrack", "elqaid", "elqat", "elqCampaignId", "nr_email_referer",
    "trk_contact", "trk_msg", "trk_module", "trk_sid", "et_rid", "et_cid", "sc_cid", "cvosrc", "cvo_campaign", "rtid",
    // HubSpot analytics cookies passed in links (not _hsenc / _hsmi: see KEPT)
    "__hstc", "__hssc", "__hsfp", "hsCtaTracking",
  ]);

  const GOOGLE = ["google.com", "google.co.uk", "google.de", "google.fr", "google.ca", "google.com.au", "google.co.in", "google.es", "google.it", "google.nl",
    "google.co.jp", "google.com.br", "google.com.mx", "google.ie", "google.ch", "google.at", "google.be", "google.se", "google.pl"];
  const AMAZON = ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amazon.in", "amazon.com.au", "amazon.nl", "amazon.se", "amazon.com.mx"];

  // Per-site sets: names that are tracking on these sites (and their subdomains) only.
  const SCOPED = Object.freeze([
    {domains: GOOGLE, params: ["ved", "ei", "sxsrf", "gs_lcrp", "gs_lp", "gs_ssp", "oq", "aqs", "sourceid", "sclient", "uact", "iflsig", "rlz", "bih", "biw", "dpr", "sca_esv", "sca_upv", "sei", "source"]},
    {domains: ["bing.com"], params: ["form", "sp", "pq", "sc", "qs", "sk", "cvid", "ghc", "lq", "ghsh", "ghacc", "ghpl", "ocid"]},
    {domains: ["youtube.com", "youtu.be"], params: ["si", "pp", "feature", "embeds_referring_euri", "embeds_referring_origin", "source_ve_path", "ab_channel"]},
    {domains: ["open.spotify.com", "spotify.link"], params: ["si", "nd", "dlsi", "context"]},
    {domains: ["x.com", "twitter.com"], params: ["s", "t", "ref_src", "ref_url", "src"]},
    {domains: ["facebook.com"], params: ["eid", "sfnsn", "rdid", "share_url", "ref", "fref", "hc_ref", "__mref"]},
    {domains: ["linkedin.com"], params: ["trk", "trkCampaign", "trkEmail", "trackingId", "lipi", "refId", "lici", "originalSubdomain"]},
    {domains: ["tiktok.com"], params: ["is_from_webapp", "sender_device", "sender_web_id", "_r", "_t", "is_copy_url", "share_app_id", "share_link_id", "social_share_type", "u_code", "tt_from", "checksum", "share_item_id"]},
    {domains: ["reddit.com"], params: ["share_id", "ref", "ref_source", "rdt"]},
    {domains: ["medium.com"], params: ["source"]},
    {domains: ["etsy.com"], params: ["click_key", "click_sum", "ref", "organic_search_click", "sts", "frs", "pro", "pf_from"]},
    {domains: ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.ca", "ebay.com.au", "ebay.fr", "ebay.it"], params: ["mkevt", "mkcid", "mkrid", "campid", "toolid", "customid", "_trkparms", "_trksid", "amdata", "mkpid", "emsid", "ssspo", "sssrc", "ssuid"]},
    {domains: AMAZON, params: ["pd_rd_w", "pd_rd_wg", "pd_rd_r", "pd_rd_i", "pf_rd_p", "pf_rd_r", "pf_rd_s", "pf_rd_t", "pf_rd_i", "pf_rd_m", "content-id", "ref", "ref_",
      "crid", "sprefix", "dib", "dib_tag", "qid", "sr", "psc", "_encoding", "tag", "linkCode", "linkId", "camp", "creative", "creativeASIN", "ascsubtag", "spIA", "hvadid", "hvpos", "hvnetw", "hvrand", "hvpone", "hvptwo", "hvqmt", "hvdev", "hvdvcmdl", "hvlocint", "hvlocphy", "hvtargid", "asc_campaign", "asc_refurl", "asc_source"]},
    {domains: ["imdb.com"], params: ["ref_", "pf_rd_m", "pf_rd_p", "pf_rd_r", "pf_rd_s", "pf_rd_t", "pf_rd_i"]},
    {domains: ["aliexpress.com", "aliexpress.us", "taobao.com", "tmall.com", "alibaba.com"], params: ["spm", "scm", "pvid", "algo_pvid", "algo_exp_id", "aff_platform", "aff_trace_key", "aff_fcid", "aff_fsk", "aff_request_id", "terminal_id", "gps-id", "scm_id", "scm-url", "btsid", "ws_ab_test", "srcSns", "businessType", "afSmartRedirect"]},
    {domains: ["walmart.com"], params: ["athbdg", "athcpid", "athpgid", "athznid", "athieid", "athena", "athancid", "athposb", "athstid", "athguid", "athwpid", "athtvid", "athrsf", "athsrc"]},
    {domains: ["twitch.tv"], params: ["tt_medium", "tt_content", "sr"]},
    {domains: ["nytimes.com"], params: ["smid", "smtyp", "partner", "emc", "te", "campaign_id"]},
    {domains: ["washingtonpost.com"], params: ["itid"]},
    {domains: ["cnn.com"], params: ["iid", "cid", "hpt", "sr"]},
    {domains: ["bloomberg.com"], params: ["cmpid", "srnd", "leadSource"]},
    {domains: ["substack.com"], params: ["r", "triedRedirect", "publication_id", "post_id", "isFreemail", "showWelcome"]},
    {domains: ["stackoverflow.com", "stackexchange.com"], params: ["cb", "lq"]},
  ]);

  // Never removed, even if a list names them: unsubscribe and preference links need these (they identify, and often
  // authenticate, the recipient), and OAuth, payment and session flows break without the rest.
  const KEPT = Object.freeze(["mkt_tok", "_hsenc", "_hsmi", "ck_subscriber_id", "ml_subscriber", "ml_subscriber_hash", "elq", "elqTrackId",
    "midToken", "midSig", "nl", "user_id", "segment_id", "code", "state", "token", "session", "session_id", "nonce", "id_token", "access_token",
    "oauth_token", "oauth_verifier", "SAMLRequest", "SAMLResponse", "RelayState", "client_id", "redirect_uri", "q", "page", "p", "query", "search"]);

  // Hosts where no parameter is ever removed: sign-in, payment, cloud consoles and advertiser / affiliate / email-platform
  // consoles, where campaign and ad ids are the page's own data and every parameter may be part of a signed flow. Each
  // also covers its subdomains. The navigation rules carry these as excludedRequestDomains; clean() checks them too.
  const EXCLUDED_HOSTS = Object.freeze([
    // sign-in
    "accounts.google.com", "myaccount.google.com", "login.microsoftonline.com", "login.live.com", "account.microsoft.com", "appleid.apple.com",
    "idmsa.apple.com", "signin.aws.amazon.com", "auth0.com", "okta.com", "login.yahoo.com", "id.atlassian.com",
    // payment
    "pay.google.com", "payments.google.com", "pay.amazon.com", "payments.amazon.com", "paypal.com", "stripe.com", "checkout.stripe.com",
    "klarna.com", "affirm.com", "afterpay.com", "squareup.com", "adyen.com", "checkout.com",
    // cloud consoles
    "console.cloud.google.com", "cloud.google.com", "console.firebase.google.com", "aws.amazon.com", "console.aws.amazon.com",
    "portal.azure.com", "dash.cloudflare.com",
    // advertiser, analytics, affiliate and seller consoles
    "ads.google.com", "analytics.google.com", "tagmanager.google.com", "search.google.com", "marketingplatform.google.com",
    "business.google.com", "merchants.google.com", "admanager.google.com", "adsense.google.com", "business.facebook.com",
    "adsmanager.facebook.com", "ads.tiktok.com", "business.tiktok.com", "ads.linkedin.com", "ads.x.com", "ads.twitter.com",
    "ads.microsoft.com", "ui.ads.microsoft.com", "ads.pinterest.com", "ads.reddit.com", "ads.snapchat.com",
    "affiliate-program.amazon.com", "advertising.amazon.com", "sellercentral.amazon.com", "vendorcentral.amazon.com",
    "partnernet.amazon.de", "affiliate.amazon.co.jp",
    // email platforms' own consoles
    "admin.mailchimp.com", "login.mailchimp.com", "app.hubspot.com", "app.klaviyo.com", "app.convertkit.com", "app.kit.com",
    "dashboard.mailerlite.com", "app.sendgrid.com", "app.braze.com", "fly.customer.io",
  ]);

  // Unsubscribe, opt-out and preference pages: the link's parameters are left alone there (they usually identify and
  // authenticate the recipient), on navigation and at click time. Matched against the path only.
  const PRESERVE_PATH = /(^|[\/_.-])(unsub|unsubscribe[a-z]*|opt-?out|opt-?down|preferences?|preference-?cent(?:er|re)|email-?(?:settings|preferences|prefs)|manage-?(?:subscriptions?|preferences|email)|subscriptions?|subscription-?cent(?:er|re)|notification-?settings|communication-?preferences)([\/_.-]|$)/i;
  // The same test as an RE2 pattern for the navigation rule (whole address; case-insensitive in the rule).
  const PRESERVE_REGEX = "^https?://[^/?#]+/(?:[^?#]*[/_.-])?(?:unsub|unsubscribe[a-z]*|opt-?out|opt-?down|preferences?|preference-?cent(?:er|re)|email-?(?:settings|preferences|prefs)|manage-?(?:subscriptions?|preferences|email)|subscriptions?|subscription-?cent(?:er|re)|notification-?settings|communication-?preferences)(?:[/_.?#-]|$)";

  // Path-embedded tracking: Amazon's "/ref=…" segment (it only records which link was clicked).
  const PATH_RULES = Object.freeze([{domains: AMAZON, pattern: /\/ref=[^/?#]*/}]);

  const covers = (host, domains) => domains.some((d) => host === d || host.endsWith(`.${d}`));
  const lower = (h) => String(h || "").toLowerCase().replace(/\.$/, "");

  const excluded = (host) => covers(lower(host), EXCLUDED_HOSTS);
  const preservedPath = (pathname) => PRESERVE_PATH.test(String(pathname || ""));

  /** Names removed on `host` (global plus every scoped set that covers it); none on an excluded host. */
  function namesFor(host) {
    const h = lower(host);
    if (excluded(h)) return new Set();
    const names = new Set(GLOBAL);
    for (const scope of SCOPED) if (covers(h, scope.domains)) for (const n of scope.params) names.add(n);
    for (const k of KEPT) names.delete(k);
    return names;
  }

  function decodeKey(raw) {
    try { return decodeURIComponent(raw.replace(/\+/g, " ")); } catch { return raw; }
  }

  /**
   * Remove tracking parameters (and Amazon's /ref= path segment) from an http(s) address. Every other parameter keeps
   * its exact spelling, order and encoding. Returns {url, removed: [names]}; a non-http(s) or unparsable input comes
   * back unchanged with removed = [].
   */
  function clean(href) {
    let url;
    try { url = new URL(href); } catch { return {url: href, removed: []}; }
    if (url.protocol !== "http:" && url.protocol !== "https:") return {url: href, removed: []};
    if (excluded(url.hostname) || preservedPath(url.pathname)) return {url: href, removed: []};
    const names = namesFor(url.hostname);
    const removed = [];
    if (url.search.length > 1) {
      const kept = [];
      for (const part of url.search.slice(1).split("&")) {
        if (!part) continue;
        const eq = part.indexOf("=");
        const key = decodeKey(eq < 0 ? part : part.slice(0, eq));
        if (names.has(key)) removed.push(key); else kept.push(part);
      }
      if (removed.length) url.search = kept.length ? `?${kept.join("&")}` : "";
    }
    for (const rule of PATH_RULES) {
      if (covers(lower(url.hostname), rule.domains) && rule.pattern.test(url.pathname)) {
        url.pathname = url.pathname.replace(rule.pattern, "");
        removed.push("/ref=");
      }
    }
    return {url: removed.length ? url.href : href, removed};
  }

  const api = Object.freeze({GLOBAL, SCOPED, KEPT, PATH_RULES, AMAZON, GOOGLE, EXCLUDED_HOSTS, PRESERVE_PATH, PRESERVE_REGEX, namesFor, clean, excluded, preservedPath});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGParams = api;
})(globalThis);
