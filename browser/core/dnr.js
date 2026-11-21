/* Chrome declarativeNetRequest compiler. Pure: no browser APIs.
 *
 * Two jobs, one priority ladder:
 *   - compileList(): build-time. Turns verified domain lists into static rulesets.
 *   - compileUserState(): run time. Turns validated user rules and exceptions into dynamic rules.
 *
 * Priority ladder (higher wins; within one extension allow beats block at equal priority; a modifyHeaders rule
 * applies only when its priority is above every matching allow rule):
 *   1 params        strip tracking parameters from navigations (redirect)
 *   2 filter        URL filters (EasyPrivacy, EasyList, fingerprinting and session-replay paths), third-party
 *                   beacons, link-tracker unwrapping, the Referrer-Policy fix
 *   3 filterAllow   the filter lists' own exceptions (@@); they lift only the filters below them
 *   4 filterImportant  $important filters, which the lists' exceptions must not lift
 *   5 mode          Strict and No-scripts site modes, click-to-load embeds, third-party cookie stripping
 *   6 relax         "Relaxed" site mode (allowAllRequests) and a clicked-to-load embed: lift everything above
 *   7 threat        malware/phishing: navigation -> local warning page, everything else blocked
 *   8 continue      "continue once" from the warning page: session `allow` rules for one tab and one host, its
 *                   navigation and its own requests. Never allowAllRequests, which would lift every lower-priority
 *                   rule (other threat hosts included) for the whole frame tree.
 *   9 list          ad/tracker and CNAME-cloaked tracker host lists
 *  10 surrogate     known tracker scripts answered by an inert bundled stub instead of a block
 *  11 user block    endpoint rules added in the popup
 *  12 user allow    endpoint allow rules
 *  13 exception     timed exceptions; beat every list and rule above
 *  14 gpc           Sec-GPC: 1 on every request (modifyHeaders; above every allow so nothing switches it off)
 * "continue" sits below "list" on purpose: continuing to a flagged site does not unblock its trackers. Nothing a
 * filter list or a site mode can allow reaches the threat list: their allow rules sit below it. */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;
  const hosts = isNode ? require("./hosts.js") : root.EGHosts;
  const links = isNode ? require("./links.js") : root.EGLinks;
  const params = isNode ? require("./params.js") : root.EGParams;

  const PRIORITY = Object.freeze({params: 1, filter: 2, filterAllow: 3, filterImportant: 4, mode: 5, relax: 6, threat: 7,
    continue: 8, list: 9, surrogate: 10, userBlock: 11, userAllow: 12, exception: 13, gpc: 14});

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
    "fp-trackers": {label: "First-party tracker script"},
    easyprivacy: {label: "Tracking request"},
    easylist: {label: "Ad request"},
    replay: {label: "Fingerprinting or session replay"},
    beacons: {label: "Third-party beacon"},
    links: {label: "Link tracker unwrapped"},
    surrogates: {label: "Tracker answered by a stub"},
    strict: {label: "Strict mode (third party)"},
    noscript: {label: "Scripts off for this site"},
    embeds: {label: "Embed held until clicked"},
    user: {label: "Your rules"},
    params: {quiet: true}, gpc: {quiet: true}, referrer: {quiet: true}, "filter-allow": {quiet: true}, cookies: {quiet: true}, bounce: {quiet: true},
  });
  const DEFAULT_CHUNK = 25000;

  const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  /** Glob path ("*" = any run of characters) -> anchored URL regex for one exact host. */
  function endpointRegex(host, pathPattern) {
    const path = pathPattern.split("*").map(escapeRegex).join("[^?#]*");
    return `^https?://${escapeRegex(host)}(?::[0-9]+)?${path}(?:[?#].*)?$`;
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
   * Static ruleset that strips tracking parameters from page and frame navigations. One plain urlFilter
   * rule per parameter ("?name=" and "&name="), each removing the whole set: a single regex with every
   * name exceeds Chrome's compiled-regex size limit and is silently dropped.
   */
  function compileParams() {
    const redirect = (names) => ({type: "redirect", redirect: {transform: {queryTransform: {removeParams: names}}}});
    const out = [];
    let id = 1;
    const global = redirect([...TRACKING_PARAMS]);
    for (const name of TRACKING_PARAMS) {
      for (const sep of ["?", "&"]) {
        out.push({id: id++, priority: PRIORITY.params, action: global,
          condition: {urlFilter: `${sep}${name}=`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame", "sub_frame"]}});
      }
    }
    // A scoped rule removes its own names and every global one. If a global rule wins the race on the same
    // navigation, the redirected request is matched again and the scoped rule removes the rest.
    for (const scope of SCOPED_PARAMS) {
      const action = redirect([...TRACKING_PARAMS, ...scope.params]);
      for (const name of scope.params) {
        for (const sep of ["?", "&"]) {
          out.push({id: id++, priority: PRIORITY.params, action,
            condition: {urlFilter: `${sep}${name}=`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame", "sub_frame"], requestDomains: [...scope.domains]}});
        }
      }
    }
    // Amazon's "/ref=…" path segment: cut out of the path, the rest of the address untouched.
    for (const rule of params.PATH_RULES) {
      out.push({id: id++, priority: PRIORITY.params, action: {type: "redirect", redirect: {regexSubstitution: "\\1\\2"}},
        condition: {regexFilter: "^(https?://[^/?#]+/[^?#]*?)/ref=[^/?#]*(.*)$", requestDomains: [...rule.domains], resourceTypes: ["main_frame"]}});
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
    return links.WRAPPERS.map((w, i) => ({id: i + 1, priority: PRIORITY.filter,
      action: {type: "redirect", redirect: {regexSubstitution: `${unwrapUrl}#\\0`}},
      // "\0" is the whole match, so the pattern runs to the end of the address.
      condition: {regexFilter: `${w.dnr}.*$`, requestDomains: [...w.domains], resourceTypes: ["main_frame"]}}));
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
    "login.live.com", "auth0.com", "okta.com", "oktacdn.com", "clerk.com", "clerk.accounts.dev", "github.com", "githubassets.com",
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
  const SITE_MODES = Object.freeze(["relaxed", "standard", "strict", "noscript"]);
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
   *   relaxed  allowAllRequests for the site's pages at "relax": URL filters, beacons, link unwrapping, Strict and the
   *            Referrer-Policy fix stand down; host lists, threats, your rules and GPC stay.
   *   strict   third-party scripts, frames and fonts blocked (FUNCTIONAL_HOSTS and the hosts you allowed excepted);
   *            third-party Cookie / Set-Cookie removed; the Referer removed from third-party frames; embeds held.
   *   noscript every script the site's pages request is blocked and a `script-src 'none'` policy is added to them.
   */
  function compileModes(modes, {firstId = MODE_BASE} = {}) {
    const sites = (modes && modes.sites) || {};
    const allowHosts = (modes && modes.allowHosts) || {};
    const defaultMode = modes && modes.defaultMode === "strict" ? "strict" : "standard";
    const by = {relaxed: [], standard: [], strict: [], noscript: []};
    for (const [site, mode] of Object.entries(sites)) if (by[mode] && hosts.siteOf(site) === site) by[mode].push(site);
    for (const k of Object.keys(by)) by[k].sort();
    const rules = [];
    const kinds = {};
    let id = firstId;
    const add = (kind, priority, action, condition) => { kinds[id] = kind; rules.push({id: id++, priority, action, condition}); };
    if (by.relaxed.length) add(null, PRIORITY.relax, {type: "allowAllRequests"}, {requestDomains: by.relaxed, resourceTypes: ["main_frame"]});
    // "Clean links and cookies" off for a site: navigations to it keep their parameters and are not unwrapped, and
    // its pages' third-party requests keep their cookies. Plain allows at the cleaning tiers lift nothing else.
    const cleanOff = ((modes && modes.cleanOff) || []).filter((s) => hosts.siteOf(s) === s).sort();
    if (cleanOff.length) {
      add(null, PRIORITY.filter, {type: "allow"}, {requestDomains: cleanOff, resourceTypes: ["main_frame"]});
      add(null, PRIORITY.params, {type: "allow"}, {initiatorDomains: cleanOff, resourceTypes: [...SUBRESOURCE_TYPES]});
    }

    // Strict: one set for the sites switched to Strict, one for "everything else" when Strict is the default.
    const strictSets = [];
    if (by.strict.length) strictSets.push({initiatorDomains: by.strict});
    if (defaultMode === "strict") {
      const excluded = [...by.relaxed, ...by.standard, ...by.strict, ...by.noscript, ...FUNCTIONAL_HOSTS.filter((h) => hosts.siteOf(h) === h)];
      strictSets.push({excludedInitiatorDomains: [...new Set(excluded)].sort()});
    }
    for (const scope of [...strictSets, ...(by.noscript.length ? [{initiatorDomains: by.noscript, noscript: true}] : [])]) {
      const {noscript, ...who} = scope;
      // Hosts the user allowed under Strict apply only to that site, so per-site sets get their own exclusions.
      const perSite = who.initiatorDomains ? who.initiatorDomains.map((s) => ({initiatorDomains: [s], extra: (allowHosts[s] || []).filter((h) => hosts.normalizeHost(h))}))
        : [{...who, extra: []}];
      for (const {extra, ...scopeWho} of perSite) {
        const excludedRequestDomains = [...new Set([...FUNCTIONAL_HOSTS, ...extra])].sort();
        add(noscript ? "noscript" : "strict", PRIORITY.mode, {type: "block"},
          {...scopeWho, domainType: "thirdParty", resourceTypes: ["script", "sub_frame", "font", "object"], excludedRequestDomains});
        add(null, PRIORITY.mode, {type: "modifyHeaders", requestHeaders: [{header: "cookie", operation: "remove"}], responseHeaders: [{header: "set-cookie", operation: "remove"}]},
          {...scopeWho, domainType: "thirdParty", excludedRequestDomains, resourceTypes: ["sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "media", "other"]});
        add(null, PRIORITY.mode, {type: "modifyHeaders", requestHeaders: [{header: "referer", operation: "remove"}]},
          {...scopeWho, domainType: "thirdParty", excludedRequestDomains: [...excludedRequestDomains, "youtube.com", "youtube-nocookie.com"], resourceTypes: ["sub_frame"]});
      }
    }
    if (by.noscript.length) {
      add("noscript", PRIORITY.mode, {type: "block"}, {initiatorDomains: by.noscript, resourceTypes: ["script"]});
      add(null, PRIORITY.mode, {type: "modifyHeaders", responseHeaders: [{header: "content-security-policy", operation: "append", value: "script-src 'none'"}]},
        {requestDomains: by.noscript, resourceTypes: ["main_frame", "sub_frame"]});
    }
    return {rules, kinds};
  }

  /** Session rule that lets one embed provider load in one tab after a click (beats Strict, nothing above it). */
  function embedRule(id, embedId, tabId) {
    const embed = EMBEDS.find((e) => e.id === embedId);
    if (!embed || !Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(id) || id < 1) throw new Error("embed needs a provider and a tab");
    return {id, priority: PRIORITY.relax, action: {type: "allow"},
      condition: {requestDomains: [...embed.domains], tabIds: [tabId], resourceTypes: ["sub_frame", "script", "stylesheet", "image", "font", "xmlhttprequest", "media"]}};
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
    let cid = 1, bid = 1;
    return {
      // Third-party requests to tracker hosts that are not blocked outright (social and ad hosts that embeds need,
      // hosts a list's own exception lets through) go without cookies, so they cannot recognise the visitor.
      cookies: chunks(minimize([...TRACKER_COOKIE_HOSTS, ...trackerDomains]).filter((d) => !functional.has(d)), chunk).map((part) => ({id: cid++, priority: PRIORITY.params,
        action: strip, condition: {requestDomains: part, excludedRequestDomains: [...FUNCTIONAL_HOSTS], domainType: "thirdParty",
          resourceTypes: SUBRESOURCE_TYPES.filter((t) => t !== "websocket" && t !== "webtransport")}})),
      // Opaque redirectors (short links, email click trackers, disguised click-through subdomains): the hop still
      // happens, but the redirector can neither read nor set a cookie on the way through.
      bounce: chunks(minimize([...BOUNCE_HOSTS, ...bounceDomains]), chunk).map((part) => ({id: bid++, priority: PRIORITY.params,
        action: strip, condition: {requestDomains: part, resourceTypes: ["main_frame", "sub_frame"]}})),
      gpc: [{id: 1, priority: PRIORITY.gpc, action: {type: "modifyHeaders", requestHeaders: [{header: "sec-gpc", operation: "set", value: "1"}]},
        condition: {resourceTypes: ["main_frame", ...SUBRESOURCE_TYPES]}}],
      referrer: [{id: 1, priority: PRIORITY.filter,
        action: {type: "modifyHeaders", responseHeaders: [{header: "referrer-policy", operation: "set", value: "strict-origin-when-cross-origin"}]},
        condition: {resourceTypes: ["main_frame", "sub_frame"],
          responseHeaders: [{header: "referrer-policy", values: ["*unsafe-url", "*no-referrer-when-downgrade", "origin-when-cross-origin", "*, origin-when-cross-origin", "*,origin-when-cross-origin"]}]}}],
      beacons: [{id: 1, priority: PRIORITY.filter, action: {type: "block"}, condition: {domainType: "thirdParty", resourceTypes: ["ping"]}}],
    };
  }

  const live = (item, now) => item.expiresAt === undefined || item.expiresAt > now;
  const chromeTypes = (types, map = TYPE_MAP) => [...new Set(types.flatMap((t) => map[t] || []))].sort();

  /**
   * Dynamic rules for the user's request rules and live exceptions.
   * Returns {rules, sources}: `sources` maps each DNR id to the store id it came from (for the popup log).
   */
  function compileUserState(rules, exceptions, now, {firstId = 1} = {}) {
    const out = [];
    const sources = {};
    let id = firstId;
    const push = (sourceId, priority, actionType, site, host, path, types, party, map) => {
      const condition = {regexFilter: endpointRegex(host, path), isUrlFilterCaseSensitive: true, requestDomains: [host],
        initiatorDomains: [site], resourceTypes: chromeTypes(types, map)};
      if (party === "first") condition.domainType = "firstParty";
      if (party === "third") condition.domainType = "thirdParty";
      sources[id] = sourceId;
      out.push({id: id++, priority, action: {type: actionType}, condition});
    };
    for (const rule of rules) {
      if (rule.kind !== "request" || !live(rule, now)) continue;
      const allow = rule.action === "allow";
      push(rule.id, allow ? PRIORITY.userAllow : PRIORITY.userBlock, allow ? "allow" : "block", rule.site, rule.host, rule.path, rule.types, rule.party);
    }
    for (const exc of exceptions) {
      if (!live(exc, now)) continue;
      push(exc.id, PRIORITY.exception, "allow", exc.site, exc.host, exc.path, [exc.type], undefined, EXCEPTION_TYPE_MAP);
    }
    return {rules: out, sources};
  }

  /**
   * Session rules for "continue once" (ids `id` and `id + 1`), below the tracker lists: in one tab, the navigation to
   * one host, and requests to that host made by that host itself. Plain `allow`, so other threat-listed hosts the page
   * pulls in stay blocked.
   */
  function continueRules(id, host, tabId) {
    const name = hosts.normalizeHost(host);
    if (!name || !Number.isInteger(tabId) || tabId < 0 || !Number.isInteger(id) || id < 1) throw new Error("continue needs a host and a tab");
    return [
      {id, priority: PRIORITY.continue, action: {type: "allow"},
        condition: {requestDomains: [name], resourceTypes: ["main_frame"], tabIds: [tabId]}},
      {id: id + 1, priority: PRIORITY.continue, action: {type: "allow"},
        condition: {requestDomains: [name], initiatorDomains: [name], resourceTypes: [...SUBRESOURCE_TYPES], tabIds: [tabId]}},
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
      {urlFilter: "/i/v0/e/", resourceTypes: X},
      {urlFilter: "/2/httpapi", resourceTypes: X},
      // TikTok and Meta pixels proxied
      {urlFilter: "/events.js?sdkid=", resourceTypes: S},
      {regexFilter: "/tr/?\\?id=[0-9]{6,}&ev=", resourceTypes: ["image", ...X]},
    ],
  });

  /** Static rules for the hand-written filters of one category. */
  function compileHand(kind) {
    const list = HAND_FILTERS[kind];
    if (!list) throw new Error(`unknown filter set ${kind}`);
    return list.map((c, i) => ({id: i + 1, priority: PRIORITY.filter, action: {type: "block"}, condition: {...c, isUrlFilterCaseSensitive: false}}));
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

  const api = Object.freeze({PRIORITY, SUBRESOURCE_TYPES, TYPE_MAP, CHROME_TO_CORE, EXCEPTION_TYPE_MAP, TRACKING_PARAMS, SCOPED_PARAMS, KEPT_PARAMS,
    LIST_KINDS, CATEGORIES, DEFAULT_CHUNK, FUNCTIONAL_HOSTS, TRACKER_COOKIE_HOSTS, BOUNCE_HOSTS, EMBEDS, SITE_MODES, MODE_BASE, HAND_FILTERS, SURROGATES,
    endpointRegex, minimize, compileList, compileParams, compileLinks, compilePrivacy, compileHand, compileSurrogates, compileModes, embedRule, compileUserState, continueRules,
    parseWarning, extensionIdFromHex, categoryOf});
  if (isNode) module.exports = api;
  else root.EGDnr = api;
})(globalThis);
