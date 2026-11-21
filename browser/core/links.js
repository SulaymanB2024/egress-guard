/* Link-tracker unwrapping. Pure: no browser APIs.
 *
 * A strict allow-list of redirectors whose destination is written in the address itself (a query parameter, a path
 * segment, or an encoding of one). The build compiles each `dnr` pattern into a main-frame redirect to the
 * extension's unwrap page (core/dnr.js compileLinks); that page calls unwrap() and replaces itself with the result.
 * page-guard.js calls unwrap() at click time too. Nothing here makes a network request, so redirectors that hide
 * the destination behind a lookup (t.co, bit.ly, most email-platform click links) cannot be unwrapped; the extension
 * strips their cookies instead (the "bounce" ruleset).
 *
 * Mail security rewriters (Microsoft Safe Links, Proofpoint URL Defense) are unwrapped too, at the owner's request:
 * that skips the click-time scan an employer's mail security would have made. Mimecast links are opaque and are not.
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
  const WRAPPERS = Object.freeze([
    {id: "google", name: "Google", domains: ["google.com", "google.co.uk", "google.de", "google.fr", "google.ca", "google.com.au", "google.co.in", "google.es", "google.it", "google.nl", "google.co.jp", "google.com.br", "google.com.mx", "google.ie", "google.ch", "google.at", "google.be", "google.se", "google.pl"],
      prefix: `^${B}(www\\.)?google\\.(com|co\\.[a-z]{2}|com\\.[a-z]{2}|[a-z]{2})/url\\?`, param: "(q|url)", params: ["q", "url"]},
    {id: "google-amp", name: "Google AMP", domains: ["google.com"], prefix: `^${B}(www\\.)?google\\.com/amp/s/`, dnr: `^${B}(www\\.)?google\\.com/amp/s/[a-z0-9.-]+\\.[a-z]{2,}/`, decode: "amp"},
    {id: "facebook", name: "Facebook", domains: ["l.facebook.com", "lm.facebook.com", "l.messenger.com"], prefix: `^${B}(l|lm)\\.(facebook|messenger)\\.com/l\\.php\\?`, param: "u", params: ["u"]},
    {id: "instagram", name: "Instagram", domains: ["l.instagram.com"], prefix: `^${B}l\\.instagram\\.com/\\?`, param: "u", params: ["u"]},
    {id: "threads", name: "Threads", domains: ["l.threads.net", "l.threads.com"], prefix: `^${B}l\\.threads\\.(net|com)/\\?`, param: "u", params: ["u"]},
    {id: "reddit", name: "Reddit", domains: ["out.reddit.com"], prefix: `^${B}out\\.reddit\\.com/[^?#]*\\?`, param: "url", params: ["url"]},
    {id: "tumblr", name: "Tumblr", domains: ["t.umblr.com"], prefix: `^${B}t\\.umblr\\.com/redirect\\?`, param: "z", params: ["z"]},
    {id: "vk", name: "VK", domains: ["away.vk.com", "vk.com"], prefix: `^${B}(away\\.)?vk\\.com/away\\.php\\?`, param: "to", params: ["to"]},
    {id: "youtube", name: "YouTube", domains: ["youtube.com"], prefix: `^${B}(www\\.|m\\.)?youtube\\.com/redirect\\?`, param: "q", params: ["q"]},
    {id: "slack", name: "Slack", domains: ["slack-redir.net"], prefix: `^${B}slack-redir\\.net/link\\?`, param: "url", params: ["url"]},
    {id: "linkedin", name: "LinkedIn", domains: ["linkedin.com"], prefix: `^${B}(www\\.)?linkedin\\.com/redir/redirect/?\\?`, param: "url", params: ["url"]},
    {id: "duckduckgo", name: "DuckDuckGo", domains: ["duckduckgo.com"], prefix: `^${B}(html\\.|lite\\.)?duckduckgo\\.com/l/\\?`, param: "uddg", params: ["uddg"]},
    {id: "bing", name: "Bing", domains: ["bing.com"], prefix: `^${B}(www\\.)?bing\\.com/ck/a\\?`, param: "u", dest: "a1[A-Za-z0-9_-]", params: ["u"], decode: "bing"},
    {id: "yahoo", name: "Yahoo", domains: ["r.search.yahoo.com"], prefix: `^${B}r\\.search\\.yahoo\\.com/`, dnr: `^${B}r\\.search\\.yahoo\\.com/[^?#]*/RU=${DEST}`, decode: "yahoo"},
    {id: "disqus", name: "Disqus", domains: ["disq.us"], prefix: `^${B}disq\\.us/url\\?`, param: "url", params: ["url"], decode: "disqus"},
    {id: "hrefli", name: "href.li", domains: ["href.li"], prefix: `^${B}href\\.li/\\?`, dnr: `^${B}href\\.li/\\?${DEST}`, decode: "rawquery"},
    {id: "skimlinks", name: "Skimlinks", domains: ["go.redirectingat.com"], prefix: `^${B}go\\.redirectingat\\.com/?\\?`, param: "url", params: ["url"]},
    {id: "rakuten", name: "Rakuten Advertising", domains: ["click.linksynergy.com"], prefix: `^${B}click\\.linksynergy\\.com/deeplink\\?`, param: "murl", params: ["murl"]},
    {id: "awin", name: "Awin", domains: ["awin1.com"], prefix: `^${B}www\\.awin1\\.com/cread\\.php\\?`, param: "ued", params: ["ued"]},
    {id: "mandrill", name: "Mandrill", domains: ["mandrillapp.com"], prefix: `^${B}mandrillapp\\.com/track/click/`, dnr: `^${B}mandrillapp\\.com/track/click/[0-9]+/[^?#]*\\?(.*&)?p=ey`, params: ["p"], decode: "mandrill"},
    {id: "safelinks", name: "Microsoft Safe Links", domains: ["safelinks.protection.outlook.com"], prefix: `^${B}[a-z0-9]+\\.safelinks\\.protection\\.outlook\\.com/\\?`, param: "url", params: ["url"]},
    {id: "proofpoint2", name: "Proofpoint URL Defense", domains: ["urldefense.proofpoint.com"], prefix: `^${B}urldefense\\.proofpoint\\.com/v2/url\\?`, param: "u", dest: "https?-3A__", params: ["u"], decode: "proofpoint2"},
    {id: "proofpoint3", name: "Proofpoint URL Defense", domains: ["urldefense.com"], prefix: `^${B}urldefense\\.com/v3/__`, dnr: `^${B}urldefense\\.com/v3/__https?(:|%3A)`, decode: "proofpoint3"},
  ].map((w) => Object.freeze({...w, dnr: w.dnr || `${w.prefix}(.*&)?${w.param}=${w.dest || DEST}`})));
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

  /**
   * Destination of a wrapped link: {url, via: [wrapper ids]} or {error}. Nested wrappers are unwrapped up to
   * MAX_DEPTH; if any layer fails the whole unwrap fails (never a partial result that would loop through a redirector).
   */
  function unwrap(href) {
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

  const api = Object.freeze({WRAPPERS, MAX_DEPTH, wrapperOf, unwrap, safeDestination});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGLinks = api;
})(globalThis);
