/* Chrome 145+ declarativeNetRequest compiler. No browser APIs.
 * Top-level permissions use topDomains, not the immediate frame's initiatorDomains.
 * Chrome falls back to the initiator for requests without an associated top frame;
 * the adapter therefore installs permissive endpoint rules only in named tabs.
 *
 * Priority is an explicit security boundary. Manual denies > threat navigation grant
 * > threats > ordinary endpoint grants > lists. Ordinary allows have a paired,
 * higher-priority sanitation rule: allowing a resource never grants cookies.
 * Embed-with-cookies stays below tracker lists; it only lifts Strict and baseline
 * header cleaning. A warning-page Continue permits navigation only, not resources.
 * DNR modifyHeaders applies only above the winning allow. Never merge these tiers.
 */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;
  const hosts = isNode ? require("./hosts.js") : root.EGHosts;
  const links = isNode ? require("./links.js") : root.EGLinks;
  const params = isNode ? require("./params.js") : root.EGParams;

  const PRIORITY = Object.freeze({easylist: 1, easylistAllow: 2, easyprivacy: 3, easyprivacyAllow: 4, filterImportant: 5, hand: 6,
    mode: 7, embed: 8, params: 9, clean: 10, scanner: 11, scannerPass: 12, embedCookies: 13, relax: 14,
    list: 17, surrogate: 18, userAllow: 20, exception: 21, grantHeaders: 22, isolation: 24, threat: 30, continue: 31,
    continueHeaders: 32, userBlock: 40, modeHeaders: 45, isolationHeaders: 46, clientHints: 48, gpc: 50});
  // Each URL filter list's own block / exception pair.
  const FILTER_PRIORITY = Object.freeze({easylist: {block: PRIORITY.easylist, allow: PRIORITY.easylistAllow},
    easyprivacy: {block: PRIORITY.easyprivacy, allow: PRIORITY.easyprivacyAllow}});

  // Every Chrome resource type except main_frame. Lists never stop a top-level navigation;
  // threat navigations are redirected to the warning page instead.
  const SUBRESOURCE_TYPES = Object.freeze(["sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest",
    "ping", "csp_report", "media", "websocket", "webtransport", "webbundle", "other"]);

  // Core (Firefox webRequest) type -> Chrome DNR types. Chrome reports beacons as "ping".
  const TYPE_MAP = Object.freeze({
    beacon: ["ping"], ping: ["ping"], xmlhttprequest: ["xmlhttprequest"], script: ["script"], image: ["image"],
    imageset: ["image"], stylesheet: ["stylesheet"], font: ["font"], media: ["media"], sub_frame: ["sub_frame"],
    object: ["object"], csp_report: ["csp_report"], other: ["other", "websocket", "webtransport", "webbundle"],
  });
  // Chrome type -> type shown in the popup. Web sockets, web transport and web bundles keep their own names: they are not
  // rule types, so the popup offers no exception for them, and an "other" exception never covers them.
  const CHROME_TO_CORE = Object.freeze({ping: "ping", xmlhttprequest: "xmlhttprequest", script: "script", image: "image",
    stylesheet: "stylesheet", font: "font", media: "media", sub_frame: "sub_frame", object: "object", csp_report: "csp_report",
    websocket: "websocket", webtransport: "webtransport", webbundle: "webbundle", other: "other"});
  // Exceptions open exactly the type that was shown.
  const EXCEPTION_TYPE_MAP = Object.freeze({...TYPE_MAP, other: ["other"]});
  // Isolated mode also removes analytics identity carried on ordinary application
  // requests. PostHog's pinned browser SDK emits these tracing headers; arbitrary custom
  // headers and identifiers in bodies remain outside this bounded control.
  const ISOLATION_REQUEST_HEADERS = Object.freeze(["cookie", "authorization", "referer",
    "x-posthog-distinct-id", "x-posthog-session-id", "x-posthog-window-id"]);

  // Tracking parameters live in core/params.js (shared with the click-time cleaner in page-guard.js).
  const TRACKING_PARAMS = params.GLOBAL;
  const SCOPED_PARAMS = params.SCOPED;
  const KEPT_PARAMS = params.KEPT;

  const LIST_KINDS = Object.freeze({
    threats: {label: "Malware and phishing", priority: PRIORITY.threat},
    trackers: {label: "Ads and trackers", priority: PRIORITY.list},
    cname: {label: "Disguised trackers", priority: PRIORITY.list},
  });

  /**
   * What the popup calls each source of a block. Static ruleset ids map here (split lists drop their "-2" suffix);
   * "quiet" sources change requests without blocking them (headers, allows) and are never shown as blocks.
   */
  const CATEGORIES = Object.freeze({
    threats: {label: "Malware and phishing"},
    trackers: {label: "Ads and trackers"},
    cname: {label: "Disguised trackers"},
    "fp-trackers": {label: "First-party tracking request"},
    easyprivacy: {label: "Tracking request"},
    easylist: {label: "Ad request"},
    replay: {label: "Fingerprinting or session replay"},
    beacons: {label: "Third-party beacon"},
    links: {label: "Link tracker unwrapped"},
    surrogates: {label: "Tracker answered by a stub"},
    preparation: {label: "Strict preparation"},
    strict: {label: "Strict mode (third party)"},
    isolated: {label: "Isolation (cross-site resource)"},
    noscript: {label: "Scripts off for this site"},
    embeds: {label: "Embed held until clicked"},
    user: {label: "Your rules"},
    params: {quiet: true}, gpc: {quiet: true}, "client-hints": {quiet: true}, referrer: {quiet: true}, "filter-allow": {quiet: true}, cookies: {quiet: true}, bounce: {quiet: true},
  });
  const DEFAULT_CHUNK = 25000;

  const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  /** Glob path ("*" = any run of characters) -> anchored URL regex for one exact host. */
  function endpointRegex(host, pathPattern, {includeWebSockets = false} = {}) {
    const path = pathPattern.split("*").map(escapeRegex).join("[^?#]*");
    // A saved "other" deny includes socket handshakes. Expanding allow rules here
    // would silently create transport permissions from older HTTP-only grants.
    const scheme = includeWebSockets ? "(?:https?|wss?)" : "https?";
    return `^${scheme}://${escapeRegex(host)}\\.?(?::[0-9]+)?${path}(?:[?#].*)?$`;
  }

  /** Drop any domain whose parent domain is also listed: DNR requestDomains already covers subdomains. */
  function minimize(domains) {
    const set = new Set(domains);
    const out = [];
    for (const name of set) {
      const labels = name.split(".");
      let covered = false;
      for (let i = 1; i < labels.length - 1 && !covered; i++) covered = set.has(labels.slice(i).join("."));
      if (!covered) out.push(name);
    }
    return out.sort();
  }

  function chunks(items, size) {
    const out = [];
    for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
    return out;
  }

  /**
   * Static ruleset for one list. `warningUrl` (chrome-extension://<id>/warning.html) is required for threats:
   * a threat navigation is redirected there with the blocked URL after "#".
   */
  function compileList(kind, domains, {chunk = DEFAULT_CHUNK, warningUrl = null} = {}) {
    const info = LIST_KINDS[kind];
    if (!info) throw new Error(`unknown list ${kind}`);
    if (!Number.isInteger(chunk) || chunk < 1) throw new Error("chunk must be a positive integer");
    const names = minimize(domains);
    const rules = [];
    let id = 1;
    for (const part of chunks(names, chunk)) {
      rules.push({id: id++, priority: info.priority, action: {type: "block"},
        condition: {requestDomains: part, resourceTypes: [...SUBRESOURCE_TYPES]}});
      if (kind === "threats") {
        if (!/^chrome-extension:\/\/[a-p]{32}\/warning\.html$/.test(warningUrl || "")) throw new Error("threats need the extension's warning page URL");
        rules.push({id: id++, priority: info.priority,
          action: {type: "redirect", redirect: {regexSubstitution: `${warningUrl}?list=${kind}#\\0`}},
          condition: {requestDomains: part, regexFilter: "^https?://.*$", resourceTypes: ["main_frame"]}});
      }
    }
    return {rules, domains: names.length};
  }

  /**
   * Static ruleset that strips tracking parameters from GET page navigations. One plain urlFilter
   * rule per parameter ("?name=" and "&name="), each removing the whole set: a single regex with every
   * name exceeds Chrome's compiled-regex size limit and is silently dropped.
   */
  function compileParams({global = TRACKING_PARAMS, scoped = SCOPED_PARAMS, kept = KEPT_PARAMS, excludedHosts = params.EXCLUDED_HOSTS} = {}) {
    const redirect = (names) => ({type: "redirect", redirect: {transform: {queryTransform: {removeParams: names}}}});
    // The protected names (unsubscribe tokens, OAuth, sessions) are never removed, whatever a list says.
    const keep = new Set(kept);
    const globalNames = global.filter((n) => !keep.has(n));
    const excludedRequestDomains = [...excludedHosts].sort();
    const out = [];
    let id = 1;
    const action = redirect([...globalNames]);
    for (const name of globalNames) {
      for (const sep of ["?", "&"]) {
        out.push({id: id++, priority: PRIORITY.params, action,
          condition: {urlFilter: `${sep}${name}=`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame"], requestMethods: ["get"], excludedRequestDomains}});
      }
    }
    // A scoped rule removes its own names and every global one. If a global rule wins the race on the same
    // navigation, the redirected request is matched again and the scoped rule removes the rest.
    for (const scope of scoped) {
      const names = scope.params.filter((n) => !keep.has(n));
      const scopedAction = redirect([...globalNames, ...names]);
      for (const name of names) {
        for (const sep of ["?", "&"]) {
          out.push({id: id++, priority: PRIORITY.params, action: scopedAction,
            condition: {urlFilter: `${sep}${name}=`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame"], requestMethods: ["get"], requestDomains: [...scope.domains], excludedRequestDomains}});
        }
      }
    }
    // Amazon's "/ref=…" path segment: cut out of the path, the rest of the address untouched.
    for (const rule of params.PATH_RULES) {
      out.push({id: id++, priority: PRIORITY.params, action: {type: "redirect", redirect: {regexSubstitution: "\\1\\2"}},
        condition: {regexFilter: "^(https?://[^/?#]+/[^?#]*?)/ref=[^/?#]*(.*)$", requestDomains: [...rule.domains], excludedRequestDomains, resourceTypes: ["main_frame"], requestMethods: ["get"]}});
    }
    // Unsubscribe, opt-out and preference pages keep every parameter (allow beats redirect at equal priority). The
    // page cleaner applies the same test (params.preservedPath). This must never
    // apply to frames: a generic allow would lift Strict's cross-site frame block.
    // Headers stay above this brake, so preserving tokens cannot restore cookies.
    for (const regexFilter of params.PRESERVE_URL_REGEXES || [params.PRESERVE_REGEX]) {
      out.push({id: id++, priority: PRIORITY.params, action: {type: "allow"},
        condition: {regexFilter, isUrlFilterCaseSensitive: false, resourceTypes: ["main_frame"], requestMethods: ["get"], excludedRequestDomains}});
    }
    return out;
  }

  /**
   * Link trackers: a navigation to a known redirector whose destination sits in a parameter goes to the extension's
   * own unwrap page (`unwrapUrl`, chrome-extension://<id>/unwrap.html) with the whole address after "#". That page
   * decodes and checks the destination (core/links.js) and replaces itself with it; the redirector never sees the
   * click. Main-frame only, and only for the strict patterns in links.js.
   */
  function compileLinks(unwrapUrl) {
    if (!/^chrome-extension:\/\/[a-p]{32}\/unwrap\.html$/.test(unwrapUrl || "")) throw new Error("link unwrapping needs the extension's unwrap page URL");
    const redirect = {type: "redirect", redirect: {regexSubstitution: `${unwrapUrl}#\\0`}};
    // "\0" is the whole match, so the pattern runs to the end of the address.
    // A redirector with a safety check of its own is unwrapped only when the navigation starts on its own site
    // (initiatorDomains); one arriving from a mail client, another site or the address bar keeps its check.
    const wrapped = links.WRAPPERS.map((w) => ({priority: PRIORITY.clean, action: redirect,
      condition: {regexFilter: `${w.dnr}.*$`, requestDomains: [...w.domains], ...(w.open ? {} : {initiatorDomains: [...w.sites]}), resourceTypes: ["main_frame"]}}));
    // Mail security scanners always go to the interstitial, wherever the navigation started. Above the cleaning tier
    // so parameter stripping never rewrites a scanner's signed address first.
    const scanners = links.SCANNERS.map((w) => ({priority: PRIORITY.scanner, action: redirect,
      condition: {regexFilter: w.dnr, requestDomains: [...w.domains], resourceTypes: ["main_frame"]}}));
    return [...wrapped, ...scanners].map((r, i) => ({id: i + 1, ...r}));
  }

  /** Session rule for "Continue through the scanner": the next navigation to that scanner host in that tab passes. */
  function scannerPassRule(id, host, tabId) {
    const name = hosts.normalizeHost(host);
    if (!name || !links.SCANNERS.some((s) => s.domains.some((d) => name === d || name.endsWith(`.${d}`)))) throw new Error("not a scanner host");
    if (!Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(id) || id < 1) throw new Error("scanner pass needs a tab");
    return {id, priority: PRIORITY.scannerPass, action: {type: "allow"}, condition: {requestDomains: [name], resourceTypes: ["main_frame"], tabIds: [tabId]}};
  }

  // Third-party providers that sign-in, payment, captcha and public script CDNs need. Strict mode does not block
  // their scripts and frames or strip their cookies, and their own frames are not held to Strict.
  const FUNCTIONAL_HOSTS = Object.freeze([
    // payments
    "stripe.com", "stripe.network", "stripecdn.com", "paypal.com", "paypalobjects.com", "braintreegateway.com", "braintree-api.com",
    "adyen.com", "adyenpayments.com", "checkout.com", "squareup.com", "squarecdn.com", "klarna.com", "klarnaservices.com", "affirm.com",
    "afterpay.com", "shop.app", "pay.google.com", "apple-pay-gateway.apple.com",
    // sign-in
    "accounts.google.com", "apis.google.com", "appleid.apple.com", "appleid.cdn-apple.com", "login.microsoftonline.com",
    "login.live.com", "msftauth.net", "msauth.net", "lgincdnmsftuswe2.azureedge.net", "lgincdn.azureedge.net", "ssl.gstatic.com", "auth0.com", "okta.com", "oktacdn.com", "clerk.com", "clerk.accounts.dev", "github.com", "githubassets.com",
    // captcha and bot checks (blocking them locks the user out)
    "recaptcha.net", "hcaptcha.com", "challenges.cloudflare.com", "arkoselabs.com", "funcaptcha.com",
    // public script CDNs (they host libraries, not trackers)
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com", "code.jquery.com", "polyfill-fastly.io",
    "www.gstatic.com",
  ]);
  // Click-to-load embeds. Strict and No-scripts hold these frames (and the scripts that build them) until a click.
  const EMBEDS = Object.freeze([
    {id: "youtube", name: "YouTube", domains: ["youtube.com", "youtube-nocookie.com", "ytimg.com", "googlevideo.com"]},
    {id: "x", name: "X (Twitter)", domains: ["platform.twitter.com", "syndication.twitter.com", "platform.x.com"]},
    {id: "instagram", name: "Instagram", domains: ["instagram.com", "cdninstagram.com"]},
    {id: "facebook", name: "Facebook", domains: ["facebook.com", "facebook.net", "fbcdn.net"]},
    {id: "tiktok", name: "TikTok", domains: ["tiktok.com", "tiktokcdn.com", "ttwstatic.com"]},
    {id: "disqus", name: "Disqus", domains: ["disqus.com", "disquscdn.com"]},
  ]);
  const SITE_MODES = Object.freeze(["relaxed", "standard", "strict", "noscript", "isolated"]);
  // Tracking hosts that stay reachable (embeds, share buttons, sign-in elsewhere on the same company's domains) and
  // so are not on the block lists: their third-party requests lose their cookies instead.
  const TRACKER_COOKIE_HOSTS = Object.freeze(["facebook.com", "facebook.net", "instagram.com", "twitter.com", "x.com", "twimg.com", "linkedin.com",
    "licdn.com", "tiktok.com", "pinterest.com", "reddit.com", "youtube.com", "youtube-nocookie.com", "doubleclick.net",
    "googlesyndication.com", "bing.com", "clarity.ms", "yandex.ru", "yandex.com", "snapchat.com", "quora.com", "amazon-adsystem.com", "criteo.com", "adnxs.com"]);
  // Opaque redirectors: the destination is not in the address, so the hop cannot be skipped; its cookies are.
  const BOUNCE_HOSTS = Object.freeze(["t.co", "bit.ly", "bitly.com", "ow.ly", "buff.ly", "lnkd.in", "tinyurl.com", "rebrand.ly", "trib.al", "dlvr.it", "ift.tt",
    "fb.me", "amzn.to", "a.co", "spoti.fi", "list-manage.com", "ct.sendgrid.net", "sendgrid.net", "hubspotlinks.com", "hs-sites.com", "mandrillapp.com",
    "mailchi.mp", "clicks.aweber.com", "click.convertkit-mail.com", "convertkit-mail2.com", "klclick.com", "klclick1.com", "klclick2.com", "klclick3.com",
    "rs6.net", "cmail19.com", "cmail20.com", "createsend1.com", "mjt.lu", "sparkpostmail.com", "mlsend.com", "email.mg.mailgun.org", "awstrack.me",
    "links.iterable.com", "braze.com", "e.customeriomail.com", "track.customer.io", "click.pstmrk.it", "shareasale.com",
    "anrdoezrs.net", "jdoqocy.com", "tkqlhce.com", "dpbolvw.net", "kqzyfj.com", "awin1.com", "pjtra.com", "pntrs.com", "pntra.com", "gopjn.com",
    "go.skimresources.com", "redirectingat.com", "linksynergy.com", "click.linksynergy.com", "prf.hn", "evyy.net", "sjv.io", "pxf.io", "ojrq.net"]);
  const MODE_BASE = 500000;   // dynamic rule ids for site modes; user rules start at 1

  /**
   * Dynamic rules for site modes. `modes` = {defaultMode: "standard"|"strict", sites: {site: mode}, allowHosts:
   * {site: [host]}}. Returns {rules, kinds} where kinds maps each rule id to the popup category it reports as (null for
   * allows and header changes).
   *   relaxed  allowAllRequests for the site's pages at "relax": URL filters, beacons, link unwrapping, parameter and
   *            cookie stripping, Strict and the Referrer-Policy fix stand down; host lists, threats, your rules and GPC
   *            stay.
   *   strict   third-party scripts, frames and fonts blocked (FUNCTIONAL_HOSTS and the hosts you allowed excepted);
   *            third-party Cookie / Set-Cookie removed; the Referer removed from third-party frames; embeds held.
   *   noscript every script the site's pages request is blocked and a `script-src 'none'` policy is added to them.
   *   isolated all cross-top-site subresources are blocked, without compatibility exemptions;
   *            HTTP credentials/referrers are removed for its resources and navigations to it.
   */
  const topScope = (site) => {
    const excluded = hosts.scopeExclusions(site);
    return {topDomains: [site], ...(excluded.length ? {excludedTopDomains: excluded} : {})};
  };

  /**
   * Complement of the prepared PSL site scopes. A bare excludedTopDomains list
   * would exempt independent tenants as well as their hosting company's pages.
   * Restore those nested boundaries, excluding only prepared sites *inside*
   * each boundary. Equal exclusion sets can share one bounded domain list.
   * No request-to-initiator comparison is involved: the unknown top page is held
   * even when a foreign iframe requests its own same-origin script.
   */
  function preparationScopes(preparedSites) {
    const prepared = [...new Set(preparedSites.filter((site) => hosts.siteOf(site) === site && hosts.canScopeSite(site)))].sort();
    if (prepared.length > 4096) throw new Error("Too many sites to prepare safely. Close unused tabs or reduce site overrides.");
    const scopes = [{...(prepared.length ? {excludedTopDomains: prepared} : {})}];
    const boundaries = [...new Set(prepared.flatMap((site) => hosts.scopeExclusions(site)))].sort();
    const groups = new Map();
    for (const boundary of boundaries) {
      const excluded = prepared.filter((site) => hosts.withinScope(site, boundary));
      const key = excluded.join("\n");
      if (!groups.has(key)) groups.set(key, {domains: [], excluded});
      groups.get(key).domains.push(boundary);
    }
    for (const {domains, excluded} of groups.values()) {
      for (const part of chunks(domains, 1000)) scopes.push({topDomains: part, ...(excluded.length ? {excludedTopDomains: excluded} : {})});
    }
    return scopes;
  }

  function compileModes(modes, {firstId = MODE_BASE, topSites = []} = {}) {
    const sites = (modes && modes.sites) || {};
    const allowHosts = (modes && modes.allowHosts) || {};
    const defaultMode = modes && modes.defaultMode === "strict" ? "strict" : "standard";
    const by = {relaxed: [], standard: [], strict: [], noscript: [], isolated: []};
    for (const [site, mode] of Object.entries(sites)) if (by[mode] && hosts.siteOf(site) === site && hosts.canScopeSite(site)) by[mode].push(site);
    for (const k of Object.keys(by)) by[k].sort();
    const rules = [];
    const kinds = {};
    let id = firstId;
    const add = (kind, priority, action, condition) => { kinds[id] = kind; rules.push({id: id++, priority, action, condition}); };
    for (const site of by.relaxed) {
      const excluded = hosts.scopeExclusions(site);
      add(null, PRIORITY.relax, {type: "allowAllRequests"}, {requestDomains: [site], ...(excluded.length ? {excludedRequestDomains: excluded} : {}), resourceTypes: ["main_frame"]});
    }
    // "Clean links and cookies" off for a site: navigations to it keep their parameters and are not unwrapped. One
    // main-frame allow at the cleaning tier; lists do not block navigations, so it lifts nothing else. Third-party
    // cookie stripping on its pages stays: an allow for the site's subresources at that tier would also lift every URL
    // filter below it. Relaxed is the level that lifts cookie stripping.
    const cleanOff = ((modes && modes.cleanOff) || []).filter((s) => hosts.siteOf(s) === s && hosts.canScopeSite(s)).sort();
    for (const site of cleanOff) {
      const excluded = hosts.scopeExclusions(site);
      add(null, PRIORITY.clean, {type: "allow"}, {requestDomains: [site], ...(excluded.length ? {excludedRequestDomains: excluded} : {}), resourceTypes: ["main_frame"]});
    }

    // Named Strict policy is released atomically with the preparation hold's
    // exclusion. Until then, default Strict blocks active resources regardless
    // of initiator and sanitizes subresources, including first-party requests.
    const strictSets = [];
    // Under a Strict default, a site with hosts you allowed (and no level of its own) gets its own Strict rules, so
    // that its allowances apply there and nowhere else.
    const strictSites = defaultMode === "strict"
      ? [...new Set([...by.strict, ...Object.keys(allowHosts), ...topSites].filter((s) => hosts.siteOf(s) === s && hosts.canScopeSite(s) && (!sites[s] || sites[s] === "strict")))].sort()
      : by.strict;
    if (strictSites.length) strictSets.push({topDomains: strictSites});
    if (defaultMode === "strict") {
      const excluded = [...by.relaxed, ...by.standard, ...strictSites, ...by.noscript, ...by.isolated];
      for (const scope of preparationScopes(excluded)) {
        add("preparation", PRIORITY.mode, {type: "block"}, {...scope, resourceTypes: ["script", "sub_frame", "font", "object"]});
        // The hold grants no implicit functional-host exception. Named policy
        // restores the existing compatibility exceptions only after readback.
        add(null, PRIORITY.clean, {type: "modifyHeaders", requestHeaders: [{header: "cookie", operation: "remove"}, {header: "referer", operation: "remove"}],
          responseHeaders: [{header: "set-cookie", operation: "remove"}]}, {...scope, resourceTypes: [...SUBRESOURCE_TYPES]});
      }
    }
    for (const scope of [...strictSets, ...(by.noscript.length ? [{topDomains: by.noscript, noscript: true}] : [])]) {
      const {noscript, ...who} = scope;
      // Hosts the user allowed under Strict apply only to that site, so per-site sets get their own exclusions.
      const perSite = who.topDomains ? who.topDomains.map((s) => ({...topScope(s), extra: (allowHosts[s] || []).filter((h) => hosts.normalizeHost(h))}))
        : [{...who, extra: []}];
      for (const {extra, ...scopeWho} of perSite) {
        const sameSite = scopeWho.topDomains || [];
        const excludedRequestDomains = [...new Set([...sameSite, ...FUNCTIONAL_HOSTS, ...extra])].sort();
        add(noscript ? "noscript" : "strict", PRIORITY.mode, {type: "block"},
          {...scopeWho, resourceTypes: ["script", "sub_frame", "font", "object"], excludedRequestDomains});
        // Header changes sit at the cleaning tier, above a clicked-to-load embed's allow: a loaded embed still gets no
        // cookies unless the user chose "with cookies".
        add(null, PRIORITY.clean, {type: "modifyHeaders", requestHeaders: [{header: "cookie", operation: "remove"}], responseHeaders: [{header: "set-cookie", operation: "remove"}]},
          {...scopeWho, excludedRequestDomains: [...new Set([...sameSite, ...FUNCTIONAL_HOSTS])].sort(), resourceTypes: [...SUBRESOURCE_TYPES]});
        add(null, PRIORITY.clean, {type: "modifyHeaders", requestHeaders: [{header: "referer", operation: "remove"}]},
          {...scopeWho, excludedRequestDomains: [...sameSite, ...FUNCTIONAL_HOSTS, "youtube.com", "youtube-nocookie.com"].sort(), resourceTypes: ["sub_frame"]});
        // A same-site request-domain exclusion otherwise also exempts independently
        // hosted tenants below a private PSL suffix (amazonaws.com -> s3.amazonaws.com).
        const nested = sameSite.flatMap((site) => hosts.scopeExclusions(site));
        if (nested.length) {
          add(noscript ? "noscript" : "strict", PRIORITY.mode, {type: "block"},
            {...scopeWho, requestDomains: nested, excludedRequestDomains: [...new Set([...FUNCTIONAL_HOSTS, ...extra])].sort(), resourceTypes: ["script", "sub_frame", "font", "object"]});
          add(null, PRIORITY.clean, {type: "modifyHeaders", requestHeaders: [{header: "cookie", operation: "remove"}], responseHeaders: [{header: "set-cookie", operation: "remove"}]},
            {...scopeWho, requestDomains: nested, excludedRequestDomains: [...FUNCTIONAL_HOSTS], resourceTypes: [...SUBRESOURCE_TYPES]});
          add(null, PRIORITY.clean, {type: "modifyHeaders", requestHeaders: [{header: "referer", operation: "remove"}]},
            {...scopeWho, requestDomains: nested, excludedRequestDomains: [...FUNCTIONAL_HOSTS, "youtube.com", "youtube-nocookie.com"], resourceTypes: ["sub_frame"]});
        }
      }
    }
    for (const site of by.isolated) {
      const scope = topScope(site), nested = hosts.scopeExclusions(site);
      // No functional-host list, saved host allowance or ordinary permission can
      // override this tier. A site's own inline/first-party code remains enabled.
      add("isolated", PRIORITY.isolation, {type: "block"},
        {...scope, excludedRequestDomains: [site], resourceTypes: [...SUBRESOURCE_TYPES]});
      // requestDomains includes children: restore independent tenants below PSL
      // boundaries inside the otherwise same-site destination exclusion.
      if (nested.length) add("isolated", PRIORITY.isolation, {type: "block"},
        {...scope, requestDomains: nested, resourceTypes: [...SUBRESOURCE_TYPES]});
      const sanitize = {type: "modifyHeaders", requestHeaders: ISOLATION_REQUEST_HEADERS.map(header => ({header, operation: "remove"})),
      responseHeaders: [{header: "set-cookie", operation: "remove"}]};
      add(null, PRIORITY.isolationHeaders, sanitize, {...scope, resourceTypes: [...SUBRESOURCE_TYPES]});
      // Destination-scoped: the first omnibox navigation is covered without a
      // worker/navigation-event race. It does not claim to contain navigation away.
      add(null, PRIORITY.isolationHeaders, sanitize, {requestDomains: [site], ...(nested.length ? {excludedRequestDomains: nested} : {}), resourceTypes: ["main_frame"]});
    }
    for (const site of by.noscript) {
      const scope = topScope(site), excluded = hosts.scopeExclusions(site);
      add("noscript", PRIORITY.mode, {type: "block"}, {...scope, resourceTypes: ["script"]});
      const noScriptHeaders = {type: "modifyHeaders", responseHeaders: [{header: "content-security-policy", operation: "append", value: "script-src 'none'"}]};
      add(null, PRIORITY.modeHeaders, noScriptHeaders, {requestDomains: [site], ...(excluded.length ? {excludedRequestDomains: excluded} : {}), resourceTypes: ["main_frame"]});
      add(null, PRIORITY.modeHeaders, noScriptHeaders, {...scope, resourceTypes: ["sub_frame"]});
    }
    return {rules, kinds, preparedSites: strictSites, preparationHold: defaultMode === "strict"};
  }

  /**
   * Session rule that lets one embed provider load in one tab after a click. It beats Strict's blocks but not its cookie
   * stripping (or the tracker-host cookie stripping): the embed loads without cookies. `withCookies` puts it above the
   * stripping too, for embeds that need a sign-in.
   */
  function embedRule(id, embedId, tabId, {withCookies = false, topSite = null} = {}) {
    const embed = EMBEDS.find((e) => e.id === embedId);
    if (!embed || !Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(id) || id < 1) throw new Error("embed needs a provider and a tab");
    if (topSite !== null && (hosts.siteOf(topSite) !== topSite || !hosts.canScopeSite(topSite))) throw new Error("embed needs a safely scoped top site");
    return {id, priority: withCookies ? PRIORITY.embedCookies : PRIORITY.embed, action: {type: "allow"},
      condition: {requestDomains: [...embed.domains], ...(topSite ? topScope(topSite) : {}), tabIds: [tabId], resourceTypes: ["sub_frame", "script", "stylesheet", "image", "font", "xmlhttprequest", "media"]}};
  }

  /**
   * Static privacy rules that block nothing on their own page:
   *   gpc       Sec-GPC: 1 on every request.
   *   referrer  a page or frame whose Referrer-Policy would send full addresses cross-site gets Chrome's default
   *             (strict-origin-when-cross-origin) instead; stricter policies are left alone.
   *   beacons   third-party `ping` requests (the Beacon API and <a ping>) are blocked.
   */
  function compilePrivacy({trackerDomains = [], bounceDomains = [], chunk = DEFAULT_CHUNK} = {}) {
    const strip = {type: "modifyHeaders", requestHeaders: [{header: "cookie", operation: "remove"}], responseHeaders: [{header: "set-cookie", operation: "remove"}]};
    const functional = new Set(FUNCTIONAL_HOSTS);
    const coveredBy = (name, list) => list.some((d) => name === d || name.endsWith(`.${d}`));
    // The click-through list comes from an unpinned upstream file: only subdomains are taken (a bare registrable
    // domain would strip the cookies of a whole site's navigations), and never a payment, sign-in or console host.
    const keepOut = [...FUNCTIONAL_HOSTS, ...params.EXCLUDED_HOSTS];
    const bounceNames = bounceDomains.filter((d) => hosts.normalizeHost(d) === d && hosts.siteOf(d) && hosts.siteOf(d) !== d && !coveredBy(d, keepOut));
    let cid = 1, bid = 1;
    return {
      // Third-party requests to tracker hosts that are not blocked outright (social and ad hosts that embeds need,
      // hosts a list's own exception lets through) go without cookies, so they cannot recognise the visitor.
      cookies: chunks(minimize([...TRACKER_COOKIE_HOSTS, ...trackerDomains]).filter((d) => !functional.has(d)), chunk).map((part) => ({id: cid++, priority: PRIORITY.clean,
        action: strip, condition: {requestDomains: part, excludedRequestDomains: [...FUNCTIONAL_HOSTS], domainType: "thirdParty",
          resourceTypes: SUBRESOURCE_TYPES.filter((t) => t !== "websocket" && t !== "webtransport")}})),
      // Opaque redirectors (short links, email click trackers, disguised click-through subdomains): the hop still
      // happens, but the redirector can neither read nor set a cookie on the way through.
      bounce: chunks(minimize([...BOUNCE_HOSTS, ...bounceNames]), chunk).map((part) => ({id: bid++, priority: PRIORITY.clean,
        action: strip, condition: {requestDomains: part, excludedRequestDomains: [...new Set(keepOut)].sort(), resourceTypes: ["main_frame", "sub_frame"]}})),
      gpc: [{id: 1, priority: PRIORITY.gpc, action: {type: "modifyHeaders", requestHeaders: [{header: "sec-gpc", operation: "set", value: "1"}]},
        condition: {resourceTypes: ["main_frame", ...SUBRESOURCE_TYPES]}}],
      referrer: [{id: 1, priority: PRIORITY.clean,
        action: {type: "modifyHeaders", responseHeaders: [{header: "referrer-policy", operation: "set", value: "strict-origin-when-cross-origin"}]},
        condition: {resourceTypes: ["main_frame", "sub_frame"],
          responseHeaders: [{header: "referrer-policy", values: ["*unsafe-url", "*no-referrer-when-downgrade", "origin-when-cross-origin", "*, origin-when-cross-origin", "*,origin-when-cross-origin"]}]}}],
      beacons: [{id: 1, priority: PRIORITY.hand, action: {type: "block"}, condition: {domainType: "thirdParty", resourceTypes: ["ping"]}}],
    };
  }

  const live = (item, now) => item.expiresAt === undefined || item.expiresAt > now;
  const chromeTypes = (types, map = TYPE_MAP) => [...new Set(types.flatMap((t) => map[t] || []))].sort();

  /**
   * Dynamic rules for the user's request rules and live exceptions.
   * Returns {rules, sources}: `sources` maps each DNR id to the store id it came from (for the popup log).
   */
  function compileUserState(rules, exceptions, now, {firstId = 1, tabIdsBySite = null} = {}) {
    const out = [];
    const sources = {};
    let id = firstId;
    const push = (sourceId, priority, actionType, site, host, path, types, party, map, sourceTabId) => {
      const resourceTypes = chromeTypes(types, map);
      const condition = {regexFilter: endpointRegex(host, path, {includeWebSockets: actionType === "block" && resourceTypes.includes("websocket")}), isUrlFilterCaseSensitive: true, requestDomains: [host],
        topDomains: [site], resourceTypes};
      const excludedTop = hosts.scopeExclusions(site);
      if (excludedTop.length) condition.excludedTopDomains = excludedTop;
      // Destination is exact and site is known, so party is evaluated against the top
      // site's PSL boundary. domainType would compare the iframe initiator instead.
      const third = hosts.isThirdParty(host, site);
      if ((party === "first" && third) || (party === "third" && !third)) return;
      if (actionType === "allow" && tabIdsBySite) {
        const ids = [...new Set(Object.entries(tabIdsBySite).filter(([top]) => hosts.withinScope(top, site) && hosts.siteOf(top) === hosts.siteOf(site)).flatMap(([, tabs]) => tabs))].filter((x) => Number.isInteger(x) && x >= 0);
        const scopedIds = sourceTabId === undefined ? ids : ids.filter((id) => id === sourceTabId);
        if (!scopedIds.length) return; // No background/service-worker-only permissions.
        condition.tabIds = scopedIds.sort((a, b) => a - b);
      } else if (actionType === "allow" && sourceTabId !== undefined) condition.tabIds = [sourceTabId];
      sources[id] = sourceId;
      out.push({id: id++, priority, action: {type: actionType}, condition});
      if (actionType === "allow") {
        sources[id] = sourceId;
        out.push({id: id++, priority: PRIORITY.grantHeaders,
          action: {type: "modifyHeaders", requestHeaders: [{header: "cookie", operation: "remove"}, {header: "referer", operation: "remove"}],
            responseHeaders: [{header: "set-cookie", operation: "remove"}]}, condition: {...condition}});
      }
    };
    for (const rule of rules) {
      if (rule.kind !== "request" || !live(rule, now)) continue;
      const allow = rule.action === "allow";
      push(rule.id, allow ? PRIORITY.userAllow : PRIORITY.userBlock, allow ? "allow" : "block", rule.site, rule.host, rule.path, rule.types, rule.party);
    }
    for (const exc of exceptions) {
      if (!live(exc, now)) continue;
      push(exc.id, PRIORITY.exception, "allow", exc.site, exc.host, exc.path, [exc.type], undefined, EXCEPTION_TYPE_MAP, exc.tabId);
    }
    return {rules: out, sources};
  }

  /** Explicit threat consent is exact-host/tab navigation only. All subresources
   * remain blocked by their ordinary policy. Navigation is always cookieless. */
  function continueRules(id, host, tabId) {
    const name = hosts.normalizeHost(host);
    if (!name || !Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(id) || id < 1) throw new Error("continue needs a host and a tab");
    const condition = {regexFilter: `^https?://${escapeRegex(name)}\\.?(?::[0-9]+)?(?:/|$)`, isUrlFilterCaseSensitive: false,
      requestDomains: [name], resourceTypes: ["main_frame"], tabIds: [tabId]};
    return [
      {id, priority: PRIORITY.continue, action: {type: "allow"}, condition},
      {id: id + 1, priority: PRIORITY.continueHeaders, action: {type: "modifyHeaders",
        requestHeaders: [{header: "cookie", operation: "remove"}, {header: "referer", operation: "remove"}],
        responseHeaders: [{header: "set-cookie", operation: "remove"}]}, condition: {...condition}},
    ];
  }

  /** Parse the warning page's location (…/warning.html?list=threats#<blocked URL>). */
  function parseWarning(href) {
    let url;
    try { url = new URL(href); } catch { return null; }
    const list = url.searchParams.get("list");
    const blocked = url.hash.slice(1);
    let target;
    try { target = new URL(blocked); } catch { return null; }
    if (target.protocol !== "http:" && target.protocol !== "https:") return null;
    const host = hosts.normalizeHost(target.hostname);
    if (!host) return null;
    return {list: LIST_KINDS[list] ? list : "threats", url: target.href, host};
  }

  /** Chrome extension id for a manifest "key" (base64 DER public key): sha256 -> first 32 hex -> a..p. */
  function extensionIdFromHex(sha256Hex) {
    return [...sha256Hex.slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  }

  // Hand-written path filters for what survives host lists because it is served from the site's own domain, a custom
  // subdomain or a neutral CDN, and that EasyPrivacy does not already cover by path (checked against 2026-11 lists).
  // Each is specific to one vendor's loader or collector; generic names (/collect, /api/event, /i) are not used.
  const S = ["script"], X = ["xmlhttprequest", "ping"];
  const HAND_FILTERS = Object.freeze({
    replay: [
      // FingerprintJS Pro custom-subdomain and proxy integrations keep these query parameters; the open-source build
      {regexFilter: "[?&]apiKey=[A-Za-z0-9]{10,}&version=[0-9]+&loaderVersion=", resourceTypes: S},
      {urlFilter: "?ci=js/", resourceTypes: X},
      {urlFilter: "/@fingerprintjs/", resourceTypes: S},
      {urlFilter: "/fingerprintjs", resourceTypes: S},
      {urlFilter: "/fingerprint2.", resourceTypes: S},
      // ThreatMetrix first-party profiling paths not in EasyPrivacy; iovation
      {urlFilter: "/fp/tags?org_id=", resourceTypes: [...S, "image", "sub_frame", ...X]},
      {urlFilter: "/iojs/", resourceTypes: S},
      {urlFilter: "/snare.js", resourceTypes: S},
      // Session replay loaders and recorders served first-party or proxied
      {urlFilter: "/hotjar-*.js?sv=", resourceTypes: S},
      {urlFilter: "/s/fs.js", resourceTypes: S},
      {urlFilter: "/rec/bundle", resourceTypes: X},
      {urlFilter: "/rec/page", resourceTypes: X},
      {urlFilter: "/LogRocket.min.js", resourceTypes: S},
      {urlFilter: "/clarity.js", resourceTypes: S},
      {urlFilter: "mouseflow", resourceTypes: S},
      {urlFilter: "/uxa/", resourceTypes: S},
      {urlFilter: "/static/recorder.js", resourceTypes: S},
      {urlFilter: "/static/recorder-v2.js", resourceTypes: S},
      {urlFilter: "/smartlook.js", resourceTypes: S},
    ],
    "fp-trackers": [
      // Server-side GTM loaders renamed on custom domains keep the container id parameter
      {urlFilter: ".js?id=GTM-", resourceTypes: S},
      // PostHog and Amplitude through first-party proxies
      {urlFilter: "/static/array.js", resourceTypes: S},
      {urlFilter: "/static/array.full.js", resourceTypes: S},
      {urlFilter: "/array/phc_", resourceTypes: S},
      {urlFilter: "/e/?ip=", resourceTypes: X},
      {regexFilter: "^https?://[^/?#]+/(?:[^?#]*/)?i/v0/e/", resourceTypes: X},
      {urlFilter: "/2/httpapi", resourceTypes: X},
      // TikTok and Meta pixels proxied
      {urlFilter: "/events.js?sdkid=", resourceTypes: S},
      {regexFilter: "^https?://[^/?#]+/(?:[^?#]*/)?tr/?\\?id=[0-9]{6,}&ev=", resourceTypes: ["image", ...X]},
    ],
  });

  /** Static rules for the hand-written filters of one category. */
  function compileHand(kind) {
    const list = HAND_FILTERS[kind];
    if (!list) throw new Error(`unknown filter set ${kind}`);
    return list.map((c, i) => ({id: i + 1, priority: PRIORITY.hand, action: {type: "block"}, condition: {...c, isUrlFilterCaseSensitive: false}}));
  }

  // Known tracker scripts answered by an inert stub (browser/surrogates/) instead of being blocked, so pages that call
  // into them (ga(), gtag(), dataLayer callbacks, fbq(), _satellite, analytics.track, googletag) keep working.
  const SURROGATES = Object.freeze([
    {file: "google-analytics.js", urlFilter: "||google-analytics.com/analytics.js"},
    {file: "google-analytics.js", urlFilter: "||google-analytics.com/ga.js"},
    {file: "google-tag-manager.js", urlFilter: "||googletagmanager.com/gtm.js"},
    {file: "google-tag-manager.js", urlFilter: "||googletagmanager.com/gtag/js"},
    {file: "meta-pixel.js", urlFilter: "||connect.facebook.net/*/fbevents.js"},
    {file: "segment.js", urlFilter: "||cdn.segment.com/analytics.js/v1/"},
    {file: "adobe-launch.js", urlFilter: "||assets.adobedtm.com/*/launch-"},
    {file: "adobe-launch.js", urlFilter: "||assets.adobedtm.com/*/satelliteLib-"},
    {file: "google-publisher-tag.js", urlFilter: "||securepubads.g.doubleclick.net/tag/js/gpt.js"},
    {file: "google-publisher-tag.js", urlFilter: "||googletagservices.com/tag/js/gpt.js"},
    {file: "google-publisher-tag.js", urlFilter: "||pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"},
  ]);
  function compileSurrogates() {
    return SURROGATES.map((s, i) => ({id: i + 1, priority: PRIORITY.surrogate,
      action: {type: "redirect", redirect: {extensionPath: `/surrogates/${s.file}`}},
      condition: {urlFilter: s.urlFilter, resourceTypes: ["script"]}}));
  }

  /** Popup category for a static ruleset id ("threats-2" -> "threats"), or null for rulesets that never block. */
  function categoryOf(rulesetId) {
    if (typeof rulesetId !== "string") return null;
    const id = rulesetId.replace(/-[0-9]+$/, "");
    const info = CATEGORIES[id];
    if (!info) return id;
    return info.quiet ? null : id;
  }

  const api = Object.freeze({PRIORITY, FILTER_PRIORITY, SUBRESOURCE_TYPES, TYPE_MAP, CHROME_TO_CORE, EXCEPTION_TYPE_MAP, ISOLATION_REQUEST_HEADERS, TRACKING_PARAMS, SCOPED_PARAMS, KEPT_PARAMS,
    LIST_KINDS, CATEGORIES, DEFAULT_CHUNK, FUNCTIONAL_HOSTS, TRACKER_COOKIE_HOSTS, BOUNCE_HOSTS, EMBEDS, SITE_MODES, MODE_BASE, HAND_FILTERS, SURROGATES,
    endpointRegex, minimize, compileList, compileParams, compileLinks, scannerPassRule, compilePrivacy, compileHand, compileSurrogates, compileModes, embedRule, compileUserState, continueRules,
    parseWarning, extensionIdFromHex, categoryOf});
  if (isNode) module.exports = api;
  else root.EGDnr = api;
})(globalThis);
