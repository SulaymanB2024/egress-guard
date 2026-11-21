/* Link-tracker unwrapping. Pure: no browser APIs.
 *
 * A strict allow-list of redirectors whose destination is written in the address itself (a query parameter, a path
 * segment, or an encoding of one). The build compiles each `dnr` pattern into a main-frame redirect to the
 * extension's unwrap page (core/dnr.js compileLinks); that page calls unwrap() and replaces itself with the result.
 * page-guard.js calls unwrap() at click time too. Nothing here makes a network request, so redirectors that hide
 * the destination behind a lookup (t.co, bit.ly, most email-platform click links) cannot be unwrapped; the extension
 * strips their cookies instead (the "bounce" ruleset).
 *
 * Where a link is unwrapped. Many redirectors run their own safety check on the way through (Google's redirect
 * notice, Facebook's and LinkedIn's "leaving" pages, VK's and YouTube's warnings). A link to such a redirector that
 * arrives from anywhere else (a phishing email linking to google.com/url?q=…, another site, a typed address) must
 * keep that check, so each wrapper names its own `sites`: it is unwrapped only when the click or navigation comes
 * from one of them (DNR `initiatorDomains`; at click time, the page's own site). Wrappers marked `open` (affiliate and
 * email click trackers, a dereferrer) run no safety check of their own and are unwrapped from anywhere.
 *
 * Mail security scanners (SCANNERS: Microsoft Safe Links, Proofpoint URL Defense, Mimecast, Barracuda, Trend Micro)
 * are never unwrapped automatically. Their links go to a local interstitial (unwrap.html) that shows where the link
 * leads and offers "Continue through the scanner" (the default) or "Open directly"; scanned() decodes them for it.
 *
 * unwrap() only ever returns an absolute http: or https: address without credentials; anything else, including
 * javascript:, data:, file: and extension addresses, nested or not, is an error. */
(function (root) {
  "use strict";

  const B = "https?://";
  const DEST = "https?(%3A|:)";
  // prefix: RE2 pattern for the redirector up to its query or path payload (Chrome matches case-insensitively).
  // param: the parameter name(s) as a pattern, params: where to read the destination, first usable one wins.
  // dest: what the payload must start with (default an encoded or plain http(s) scheme).
  // dnr: a complete pattern, for redirectors whose payload is not a parameter. decode: special decoding.
  // sites: where a click must come from for the link to be unwrapped. open: no safety check of its own; from anywhere.
  const GOOGLE = ["google.com", "google.co.uk", "google.de", "google.fr", "google.ca", "google.com.au", "google.co.in", "google.es", "google.it", "google.nl", "google.co.jp", "google.com.br", "google.com.mx", "google.ie", "google.ch", "google.at", "google.be", "google.se", "google.pl"];
  const WRAPPERS = Object.freeze([
    {id: "google", name: "Google", domains: GOOGLE, sites: GOOGLE,
      prefix: `^${B}(www\\.)?google\\.(com|co\\.[a-z]{2}|com\\.[a-z]{2}|[a-z]{2})/url\\?`, param: "(q|url)", params: ["q", "url"]},
    {id: "google-amp", name: "Google AMP", domains: ["google.com"], sites: GOOGLE, prefix: `^${B}(www\\.)?google\\.com/amp/s/`, dnr: `^${B}(www\\.)?google\\.com/amp/s/[a-z0-9.-]+\\.[a-z]{2,}/`, decode: "amp"},
    {id: "facebook", name: "Facebook", domains: ["l.facebook.com", "lm.facebook.com", "l.messenger.com"], sites: ["facebook.com", "messenger.com"], prefix: `^${B}(l|lm)\\.(facebook|messenger)\\.com/l\\.php\\?`, param: "u", params: ["u"]},
    {id: "instagram", name: "Instagram", domains: ["l.instagram.com"], sites: ["instagram.com"], prefix: `^${B}l\\.instagram\\.com/\\?`, param: "u", params: ["u"]},
    {id: "threads", name: "Threads", domains: ["l.threads.net", "l.threads.com"], sites: ["threads.net", "threads.com"], prefix: `^${B}l\\.threads\\.(net|com)/\\?`, param: "u", params: ["u"]},
    {id: "reddit", name: "Reddit", domains: ["out.reddit.com"], sites: ["reddit.com"], prefix: `^${B}out\\.reddit\\.com/[^?#]*\\?`, param: "url", params: ["url"]},
    {id: "tumblr", name: "Tumblr", domains: ["t.umblr.com"], sites: ["tumblr.com"], prefix: `^${B}t\\.umblr\\.com/redirect\\?`, param: "z", params: ["z"]},
    {id: "vk", name: "VK", domains: ["away.vk.com", "vk.com"], sites: ["vk.com"], prefix: `^${B}(away\\.)?vk\\.com/away\\.php\\?`, param: "to", params: ["to"]},
    {id: "youtube", name: "YouTube", domains: ["youtube.com"], sites: ["youtube.com"], prefix: `^${B}(www\\.|m\\.)?youtube\\.com/redirect\\?`, param: "q", params: ["q"]},
    {id: "slack", name: "Slack", domains: ["slack-redir.net"], sites: ["slack.com"], prefix: `^${B}slack-redir\\.net/link\\?`, param: "url", params: ["url"]},
    {id: "linkedin", name: "LinkedIn", domains: ["linkedin.com"], sites: ["linkedin.com"], prefix: `^${B}(www\\.)?linkedin\\.com/redir/redirect/?\\?`, param: "url", params: ["url"]},
    {id: "duckduckgo", name: "DuckDuckGo", domains: ["duckduckgo.com"], sites: ["duckduckgo.com"], prefix: `^${B}(html\\.|lite\\.)?duckduckgo\\.com/l/\\?`, param: "uddg", params: ["uddg"]},
    {id: "bing", name: "Bing", domains: ["bing.com"], sites: ["bing.com"], prefix: `^${B}(www\\.)?bing\\.com/ck/a\\?`, param: "u", dest: "a1[A-Za-z0-9_-]", params: ["u"], decode: "bing"},
    {id: "yahoo", name: "Yahoo", domains: ["r.search.yahoo.com"], sites: ["yahoo.com"], prefix: `^${B}r\\.search\\.yahoo\\.com/`, dnr: `^${B}r\\.search\\.yahoo\\.com/[^?#]*/RU=${DEST}`, decode: "yahoo"},
    {id: "disqus", name: "Disqus", domains: ["disq.us"], sites: ["disqus.com", "disq.us"], prefix: `^${B}disq\\.us/url\\?`, param: "url", params: ["url"], decode: "disqus"},
    {id: "hrefli", name: "href.li", domains: ["href.li"], open: true, prefix: `^${B}href\\.li/\\?`, dnr: `^${B}href\\.li/\\?${DEST}`, decode: "rawquery"},
    {id: "skimlinks", name: "Skimlinks", domains: ["go.redirectingat.com"], open: true, prefix: `^${B}go\\.redirectingat\\.com/?\\?`, param: "url", params: ["url"]},
    {id: "rakuten", name: "Rakuten Advertising", domains: ["click.linksynergy.com"], open: true, prefix: `^${B}click\\.linksynergy\\.com/deeplink\\?`, param: "murl", params: ["murl"]},
    {id: "awin", name: "Awin", domains: ["awin1.com"], open: true, prefix: `^${B}www\\.awin1\\.com/cread\\.php\\?`, param: "ued", params: ["ued"]},
    {id: "mandrill", name: "Mandrill", domains: ["mandrillapp.com"], open: true, prefix: `^${B}mandrillapp\\.com/track/click/`, dnr: `^${B}mandrillapp\\.com/track/click/[0-9]+/[^?#]*\\?(.*&)?p=ey`, params: ["p"], decode: "mandrill"},
  ].map((w) => Object.freeze({...w, sites: w.open ? [] : w.sites, dnr: w.dnr || `${w.prefix}(.*&)?${w.param}=${w.dest || DEST}`})));
  // Mail security scanners: interstitial only, never unwrapped on their own. `dnr` matches every link of the scanner
  // (decodable or not); params / decode read the destination where the address carries it; hostParam names a parameter
  // that reports only the destination host (Mimecast).
  const SCANNERS = Object.freeze([
    {id: "safelinks", name: "Microsoft Safe Links", domains: ["safelinks.protection.outlook.com"], prefix: `^${B}[a-z0-9-]+\\.safelinks\\.protection\\.outlook\\.com/`, params: ["url"]},
    {id: "proofpoint2", name: "Proofpoint URL Defense", domains: ["urldefense.proofpoint.com"], prefix: `^${B}urldefense\\.proofpoint\\.com/v2/url`, params: ["u"], decode: "proofpoint2"},
    {id: "proofpoint3", name: "Proofpoint URL Defense", domains: ["urldefense.com"], prefix: `^${B}urldefense\\.com/v3/__`, decode: "proofpoint3"},
    {id: "mimecast", name: "Mimecast", domains: ["mimecast.com"], prefix: `^${B}protect[a-z0-9-]*\\.mimecast\\.com/s/`, hostParam: "domain"},
    {id: "barracuda", name: "Barracuda Link Protection", domains: ["linkprotect.cudasvc.com"], prefix: `^${B}linkprotect\\.cudasvc\\.com/url`, params: ["a"]},
    {id: "trendmicro", name: "Trend Micro Click Time Protection", domains: ["trendmicro.com", "trendmicro.eu"], prefix: `^${B}[a-z0-9-]+\\.trendmicro\\.(com|eu)(:[0-9]+)?/wis/clicktime/v1/query`, params: ["url"]},
  ].map((w) => Object.freeze({...w, dnr: `${w.prefix}.*$`})));
  const MAX_DEPTH = 4;
  const MAX_LENGTH = 8192;

  const compiled = WRAPPERS.map((w) => ({w, re: new RegExp(w.dnr, "i"), shape: new RegExp(w.prefix, "i")}));

  /** The wrapper `href` belongs to, or null. */
  function wrapperOf(href) {
    if (typeof href !== "string" || href.length > MAX_LENGTH) return null;
    const hit = compiled.find((c) => c.re.test(href));
    return hit ? hit.w : null;
  }

  function base64url(text) {
    const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "===".slice((b64.length + 3) % 4);
    const bin = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", {fatal: true}).decode(bytes);
  }
  const tryDecode = (s) => { try { return decodeURIComponent(s); } catch { return null; } };

  /** Candidate destinations for one wrapper, from the whole address (path-based) or one parameter value. */
  function candidates(w, url) {
    switch (w.decode) {
      case "amp": {
        const rest = url.href.replace(new RegExp(w.prefix, "i"), "");
        return [["https:", rest].join("//")];   // AMP cache addresses are always https
      }
      case "yahoo": {
        const m = /\/RU=([^/]+)\//.exec(url.pathname + "/");
        return m ? [tryDecode(m[1])] : [];
      }
      case "rawquery": return [tryDecode(url.search.slice(1))];
      case "proofpoint3": {
        const m = /^\/v3\/__(.+?)__;/.exec(url.pathname + url.search + url.hash);
        // "*" marks characters Proofpoint moved into the trailing table; without that table the address is incomplete.
        if (!m || m[1].includes("*")) return [];
        return [m[1]];
      }
    }
    const out = [];
    for (const raw of (w.params || []).flatMap((name) => url.searchParams.getAll(name))) {
      if (w.decode === "bing") {
        if (!/^a1[A-Za-z0-9_-]+$/.test(raw)) continue;
        try { out.push(base64url(raw.slice(2))); } catch { /* not base64 */ }
      } else if (w.decode === "disqus") out.push(raw.replace(/:[A-Za-z0-9_-]{8,}$/, ""));
      else if (w.decode === "proofpoint2") {
        if (!/^[A-Za-z0-9_.~-]+$/.test(raw)) continue;
        out.push(tryDecode(raw.replace(/_/g, "/").replace(/-([0-9A-F]{2})/g, "%$1")));
      } else if (w.decode === "mandrill") {
        try {
          const outer = JSON.parse(base64url(raw));
          const inner = typeof outer.p === "string" ? JSON.parse(outer.p) : outer.p;
          if (inner && typeof inner.url === "string") out.push(inner.url);
        } catch { /* not the documented payload */ }
      } else out.push(raw);
    }
    return out;
  }

  /** An absolute http(s) address with a host and no credentials, normalised; otherwise null. */
  function safeDestination(text) {
    if (typeof text !== "string" || !text || text.length > MAX_LENGTH) return null;
    // Control characters, tabs and newlines are refused rather than silently stripped by the URL parser. A space can
    // only come from a "+" or "%20" in the wrapped query, so it is kept, encoded.
    if (/[\u0000-\u001f\u007f]/.test(text)) return null;
    text = text.replace(/ /g, "%20");
    if (!/^https?:\/\//i.test(text)) return null;
    let url;
    try { url = new URL(text); } catch { return null; }
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (!url.hostname || url.username || url.password) return null;
    return url.href;
  }

  const coversHost = (domains, host) => typeof host === "string" && domains.some((d) => host === d || host.endsWith(`.${d}`));
  /** May wrapper `w` be unwrapped for a click or navigation that came from `fromHost`? */
  function allowedFrom(w, fromHost) {
    if (!w) return false;
    if (w.open) return true;
    const host = typeof fromHost === "string" ? fromHost.toLowerCase().replace(/\.$/, "") : null;
    return Boolean(host) && coversHost(w.sites, host);
  }

  /**
   * Destination of a wrapped link: {url, via: [wrapper ids]} or {error}. Nested wrappers are unwrapped up to
   * MAX_DEPTH. `from` is the host the click or navigation came from: a layer whose wrapper may not be unwrapped from
   * there (see allowedFrom) stops the unwrap, and the result is that layer's own address, which then runs its own
   * check. If a layer fails to decode the whole unwrap fails. A scanner layer is never unwrapped.
   */
  function unwrap(href, {from = null} = {}) {
    const via = [];
    let current = href;
    for (let depth = 0; depth <= MAX_DEPTH; depth++) {
      const w = wrapperOf(current);
      if (!w) {
        // A redirector address whose destination is not a web address fails as a whole: never a partial unwrap.
        const shaped = typeof current === "string" && current.length <= MAX_LENGTH ? compiled.find((c) => c.shape.test(current)) : null;
        if (shaped) return {error: `the ${shaped.w.name} link has no web address to open`};
        if (!via.length) return {error: "not a known link tracker"};
        return {url: current, via};
      }
      if (!allowedFrom(w, from)) {
        if (!via.length) return {error: `the ${w.name} link did not come from ${w.name} itself, so its own safety check stays`};
        return {url: current, via};
      }
      if (depth === MAX_DEPTH) return {error: "too many nested link trackers"};
      let url;
      try { url = new URL(current); } catch { return {error: "unreadable link"}; }
      let next = null;
      for (const c of candidates(w, url)) { next = safeDestination(c); if (next) break; }
      if (!next) return {error: `the ${w.name} link has no web address to open`};
      via.push(w.id);
      current = next;
    }
    return {error: "too many nested link trackers"};
  }

  const scanners = SCANNERS.map((w) => ({w, re: new RegExp(w.dnr, "i")}));
  /** The mail security scanner `href` belongs to, or null. */
  function scannerOf(href) {
    if (typeof href !== "string" || href.length > MAX_LENGTH) return null;
    const hit = scanners.find((c) => c.re.test(href));
    return hit ? hit.w : null;
  }

  /**
   * What a scanner link leads to, for the interstitial: {scanner, url, host} where url is the decoded destination
   * (null when the scanner keeps it on its server) and host the destination host (from url, or the host the scanner
   * reports, or null). Null when `href` is not a scanner link. Never unwraps further layers.
   */
  function scanned(href) {
    const w = scannerOf(href);
    if (!w) return null;
    let parsed;
    try { parsed = new URL(href); } catch { return null; }
    let url = null;
    for (const c of candidates(w, parsed)) { url = safeDestination(c); if (url) break; }
    let host = url ? new URL(url).hostname : null;
    if (!host && w.hostParam) {
      const reported = parsed.searchParams.get(w.hostParam);
      if (reported && /^[A-Za-z0-9.-]{1,253}$/.test(reported) && reported.includes(".")) {
        try { host = new URL(["https:", "", reported, ""].join("/")).hostname; } catch { host = null; }
      }
    }
    return {scanner: w, url, host};
  }

  // RFC 3492 Punycode decoding, so an internationalized host can be shown in both forms (the ASCII "xn--" form is what
  // the browser really opens; the Unicode form is what a lookalike is trying to look like).
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const out = [];
    let i = 0, n = 128, bias = 72;
    const basic = input.lastIndexOf("-");
    for (let j = 0; j < Math.max(basic, 0); j++) { if (input.charCodeAt(j) >= 0x80) return null; out.push(input.charCodeAt(j)); }
    const adapt = (delta, points, first) => {
      let k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / points);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    };
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const old = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) return null;
        const c = input.charCodeAt(idx++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
        if (w > 0x7fffffff) return null;
      }
      bias = adapt(i - old, out.length + 1, old === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      if (n > 0x10ffff) return null;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  /** Unicode form of an ASCII host ("xn--bcher-kva.example" -> "bücher.example"), or null when it has no xn-- label. */
  function unicodeHost(host) {
    if (typeof host !== "string" || !/(^|\.)xn--/i.test(host)) return null;
    const labels = host.toLowerCase().split(".").map((l) => (l.startsWith("xn--") ? punyDecode(l.slice(4)) : l));
    return labels.some((l) => l === null) ? null : labels.join(".");
  }

  const api = Object.freeze({WRAPPERS, SCANNERS, MAX_DEPTH, wrapperOf, scannerOf, scanned, allowedFrom, unwrap, safeDestination, unicodeHost});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGLinks = api;
})(globalThis);
