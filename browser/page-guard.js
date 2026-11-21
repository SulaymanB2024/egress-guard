/* Chrome, isolated world, top frame: link cleaning at click time, and small leak reducers rules cannot express.
 *
 *   - Links: on mousedown, click, middle click, context menu and Enter, a link's href is rewritten to its clean
 *     destination before the browser reads it: known redirectors unwrapped (core/links.js), tracking parameters
 *     removed (core/params.js). It runs again on click, so a page that swaps the href on mousedown (Google's rwt,
 *     Facebook's l.php) is undone before the navigation starts, and "Copy link address" copies the clean address.
 *     X's t.co links are replaced with the real address the page itself shows in data-expanded-url or the title.
 *   - Hyperlink auditing: a link's `ping` attribute is removed before it can fire, first or third party.
 *   - Address bar: tracking parameters that arrived by a client-side redirect are removed with
 *     history.replaceState once the page has loaded (global names only; never a reload).
 * The navigation rules (core/dnr.js) clean every link anyway; this layer makes the visible and copied address clean
 * too. "Clean links and cookies" switched off for a site in the popup turns all of it off there.
 * Page data is never parsed as HTML; nothing here makes a request. */
(function (root) {
  "use strict";
  if (root.__EGPageGuard) return;
  const B = root.chrome;
  const links = root.EGLinks;
  const params = root.EGParams;
  let enabled = true;
  let pingsRemoved = 0, cleaned = 0, pending = 0, flushTimer = null;
  const seen = new WeakMap();          // link -> last clean href we wrote

  function report(n) {
    pending += n;
    if (flushTimer) return;
    flushTimer = setTimeout(() => {
      flushTimer = null;
      const count = pending; pending = 0;
      try { B.runtime.sendMessage({type: "links-cleaned", count}).catch(() => {}); } catch { /* extension reloaded */ }
    }, 250);
  }

  /**
   * The clean address for a link's href, or null when it is already clean or cannot be cleaned safely. A redirector is
   * unwrapped only on its own site (core/links.js allowedFrom): a google.com/url link on any other page keeps Google's
   * own check, and only its tracking parameters go. A mail scanner's link is never touched.
   */
  function cleanHref(link) {
    let href = link.href;
    if (typeof href !== "string" || !/^https?:/i.test(href)) return null;
    let host = "";
    try { host = new URL(href).hostname; } catch { return null; }
    if (links.scannerOf(href)) return null;
    if (host === "t.co") {
      const shown = link.getAttribute("data-expanded-url") || link.getAttribute("title") || "";
      const real = links.safeDestination(shown.trim());
      if (real && !links.scannerOf(real)) href = real;
    }
    if (links.wrapperOf(href)) {
      const r = links.unwrap(href, {from: root.location.hostname});
      if (r.url) href = r.url;
    }
    if (!links.scannerOf(href)) href = params.clean(href).url;
    return href !== link.href ? href : null;
  }

  function onActivate(event) {
    if (!enabled) return;
    if (event.type === "keydown" && event.key !== "Enter") return;
    const target = event.target;
    if (!target || typeof target.closest !== "function") return;
    const link = target.closest("a[href], area[href]");
    if (!link) return;
    apply(link);
    // A page handler that swaps the href during this same event (after this capture listener) is undone once the
    // event has finished dispatching, before the click or the context menu reads it.
    if (event.type === "mousedown" || event.type === "contextmenu") setTimeout(() => apply(link), 0);
  }
  function apply(link) {
    if (link.hasAttribute("ping")) { link.removeAttribute("ping"); pingsRemoved++; }
    const clean = cleanHref(link);
    if (!clean) return;
    link.setAttribute("href", clean);
    if (seen.get(link) !== clean) { seen.set(link, clean); cleaned++; report(1); }
  }
  for (const type of ["mousedown", "auxclick", "click", "contextmenu", "keydown"]) root.addEventListener(type, onActivate, {capture: true});

  function cleanAddressBar() {
    if (!enabled) return;
    let current;
    try { current = new URL(root.location.href); } catch { return; }
    if (current.protocol !== "http:" && current.protocol !== "https:") return;
    const result = params.clean(current.href);
    // Only names that are tracking everywhere: a site's own scoped names might still be read by its scripts.
    if (!result.removed.length || !result.removed.every((n) => params.GLOBAL.includes(n))) return;
    try { root.history.replaceState(root.history.state, "", result.url); cleaned++; report(1); } catch { /* sandboxed or cross-origin */ }
  }
  const afterLoad = () => setTimeout(cleanAddressBar, 1500);
  if (document.readyState === "complete") afterLoad(); else root.addEventListener("load", afterLoad, {once: true});

  function onMessage(message, sender, sendResponse) {
    if (!message || typeof message !== "object") return false;
    if (message.type === "guard-status") { sendResponse({enabled, cleaned, pingsRemoved}); return false; }
    if (message.type === "clean-enabled") { enabled = Boolean(message.on); sendResponse({enabled}); return false; }
    return false;
  }
  B.runtime.onMessage.addListener(onMessage);

  // ---- Strict and No scripts: click-to-load embeds, no third-party connection hints -------------------------
  let embeds = [];
  const PLACEHOLDER = "data-eg-embed";
  const SCRIPT_EMBEDS = {x: "blockquote.twitter-tweet, blockquote.twitter-video, a.twitter-timeline", instagram: "blockquote.instagram-media",
    tiktok: "blockquote.tiktok-embed", facebook: "div.fb-post, div.fb-video, div.fb-comments, div.fb-page", disqus: "#disqus_thread"};
  const hostOf = (u) => { try { return new URL(u, root.location.href).hostname; } catch { return ""; } };
  const providerOf = (u) => { const h = hostOf(u); return embeds.find((e) => e.domains.some((d) => h === d || h.endsWith(`.${d}`))) || null; };

  // ---- click-to-load placeholder: hardened against clickjacking ------------------------------------------------
  // The page owns the DOM around the placeholder, so it could make it invisible, cover it, or swap something under
  // the pointer to steal the click that loads a tracker's embed. The host element carries !important inline styles
  // and `all:initial !important`; a click counts only when the button is really visible (IntersectionObserver v2
  // `trackVisibility`, for at least MIN_VISIBLE_MS), big enough, under the pointer, and no ancestor is transparent,
  // hidden or transformed away.
  const MIN_VISIBLE_MS = 500;
  const HOST_STYLE = [["display", "block"], ["position", "static"], ["opacity", "1"], ["visibility", "visible"], ["transform", "none"],
    ["filter", "none"], ["clip-path", "none"], ["mask", "none"], ["pointer-events", "auto"], ["mix-blend-mode", "normal"], ["margin", "8px 0"],
    ["contain", "none"], ["z-index", "auto"]];
  // What each held embed is, for its title and button ("YouTube video", "Load video").
  const EMBED_KINDS = {youtube: "video", tiktok: "video", x: "post", instagram: "post", facebook: "post", disqus: "comments"};
  // The placeholder sits in a closed shadow root on someone else's page, so it cannot use the extension's ui.css:
  // these are the design tokens it needs, copied from docs/design/tokens.css (tests/browser/ui-tokens.test.cjs
  // fails if any value drifts), and the component rules of docs/design/mockups/placeholder.html.
  const PLACEHOLDER_TOKENS = {
    light: {"--paper": "#f5f5ef", "--raised": "#fbfbf7", "--sunken": "#ebebe3", "--ink": "#182721", "--muted": "#56645d", "--edge": "#7c8780",
      "--fill-primary": "#19382e", "--on-primary": "#fbfbf7", "--focus": "#2f6f58", "--unprotected": "#913f37"},
    dark: {"--paper": "#0f1713", "--raised": "#17221d", "--sunken": "#0a110e", "--ink": "#e6e8df", "--muted": "#9aa69f", "--edge": "#64726b",
      "--fill-primary": "#cfe3d6", "--on-primary": "#0f1713", "--focus": "#8fc9ac", "--unprotected": "#e08a7f"},
    common: {"--s1": "4px", "--s2": "8px", "--s3": "12px", "--s4": "16px", "--t-caption": "12px", "--lh-caption": "16px", "--t-body": "14px", "--lh-body": "20px",
      "--t-title": "16px", "--lh-title": "22px", "--w-regular": "400", "--w-strong": "600", "--r-control": "6px", "--r-surface": "10px", "--hit": "28px",
      "--font-sans": '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif'},
  };
  const vars = (o) => Object.entries(o).map(([k, v]) => `${k}:${v}`).join(";");
  const PLACEHOLDER_CSS = `:host{all:initial !important;display:block !important;position:static !important;opacity:1 !important;visibility:visible !important;transform:none !important;filter:none !important;clip-path:none !important;pointer-events:auto !important;margin:8px 0 !important}
      .b{${vars(PLACEHOLDER_TOKENS.common)};${vars(PLACEHOLDER_TOKENS.light)};display:flex !important;flex-direction:column;justify-content:center;align-items:flex-start;gap:var(--s3);box-sizing:border-box;min-height:120px;padding:var(--s4);border-radius:var(--r-surface);background:var(--sunken);color:var(--ink);font:var(--w-regular) var(--t-body)/var(--lh-body) var(--font-sans);text-align:left;opacity:1 !important;visibility:visible !important}
      @media (prefers-color-scheme:dark){.b{${vars(PLACEHOLDER_TOKENS.dark)}}}
      p{margin:0}
      .w{display:flex;align-items:center;gap:var(--s2);color:var(--muted);font-size:var(--t-caption);line-height:var(--lh-caption)}
      .mk{width:14px;height:16px;flex:none;background:var(--fill-primary);clip-path:polygon(50% 0, 100% 18%, 94% 66%, 50% 100%, 6% 66%, 0 18%)}
      .t{font-size:var(--t-title);line-height:var(--lh-title);font-weight:var(--w-strong)}
      .row{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s2) var(--s3)}
      button{display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;min-width:24px;min-height:var(--hit);margin:0;padding:0 var(--s3);border:1px solid var(--fill-primary);border-radius:var(--r-control);background:var(--fill-primary);color:var(--on-primary);font:var(--w-strong) var(--t-body)/1 var(--font-sans);white-space:nowrap;cursor:pointer;opacity:1 !important;visibility:visible !important}
      button.c{min-width:var(--hit);padding:0;background:transparent;border-color:transparent;color:var(--ink);text-decoration:underline;text-decoration-color:var(--edge);text-underline-offset:3px}
      button:disabled{cursor:default}
      button:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
      .n{color:var(--unprotected)}
      .n[hidden]{display:none}`;
  const computed = (el) => { try { return typeof root.getComputedStyle === "function" ? root.getComputedStyle(el) : null; } catch { return null; } };

  /**
   * May this click on the placeholder's button load the embed? `visibleSince` is when IntersectionObserver v2 last
   * reported the button fully visible (null: not visible now; undefined: the browser has no v2, heuristics only).
   */
  function clickAllowed(button, shadow, event, visibleSince, now = Date.now()) {
    if (!event || !event.isTrusted) return false;
    if (visibleSince !== undefined && (visibleSince === null || now - visibleSince < MIN_VISIBLE_MS)) return false;
    const rect = button.getBoundingClientRect();
    if (!rect || rect.width < 24 || rect.height < 16) return false;
    // Up the tree, across the shadow boundary to the host and the page's own ancestors.
    let n = button, depth = 0;
    while (n && depth++ < 128) {
      const cs = n.nodeType === 1 ? computed(n) : null;
      if (cs) {
        if (cs.display === "none" || (cs.visibility && cs.visibility !== "visible")) return false;
        if (parseFloat(cs.opacity) < 0.99) return false;
        if (cs.filter && cs.filter !== "none") return false;
      }
      n = n.parentNode || n.host || null;
    }
    // The pointer must be on the button itself, not on something layered over it.
    if (typeof event.clientX === "number" && typeof shadow.elementFromPoint === "function") {
      const hit = shadow.elementFromPoint(event.clientX, event.clientY);
      if (!hit || !(hit === button || button.contains(hit))) return false;
    }
    return true;
  }

  function placeholder(provider, onLoad, sizeFrom, current = () => true) {
    const box = document.createElement("div");
    box.setAttribute(PLACEHOLDER, provider.id);
    for (const [k, v] of HOST_STYLE) box.style.setProperty(k, v, "important");
    const shadow = box.attachShadow({mode: "closed"});
    const style = document.createElement("style");
    style.textContent = PLACEHOLDER_CSS;
    const wrap = document.createElement("div");
    wrap.className = "b";
    if (sizeFrom) {
      const w = parseInt(sizeFrom.getAttribute("width"), 10), h = parseInt(sizeFrom.getAttribute("height"), 10);
      if (w > 0) wrap.style.maxWidth = `${Math.min(w, 2000)}px`;
      if (h > 0) wrap.style.minHeight = `${Math.min(h, 2000)}px`;
    }
    // "Held by Egress Guard" (caption) -> provider and kind (title) -> Load (primary) and Load signed in (quiet).
    const kind = EMBED_KINDS[provider.id] || "content";
    const who = document.createElement("p"); who.className = "w";
    const mark = document.createElement("span"); mark.className = "mk"; mark.setAttribute("aria-hidden", "true");
    who.append(mark, document.createTextNode("Held by Egress Guard"));
    const title = document.createElement("p"); title.className = "t"; title.textContent = `${provider.name} ${kind}`;
    const note = document.createElement("p"); note.className = "n"; note.setAttribute("role", "alert"); note.hidden = true;
    const button = document.createElement("button"); button.type = "button"; button.textContent = `Load ${kind}`;
    button.setAttribute("aria-label", `Load ${provider.name} ${kind}, without cookies`);
    const withCookies = document.createElement("button"); withCookies.type = "button"; withCookies.className = "c"; withCookies.textContent = "Load signed in";
    withCookies.setAttribute("aria-label", "Load signed in, with cookies");
    let visibleSince;   // undefined until IntersectionObserver v2 reports; see clickAllowed
    if (typeof root.IntersectionObserver === "function") {
      try {
        const io = new root.IntersectionObserver((entries) => {
          for (const e of entries) {
            if (typeof e.isVisible !== "boolean") { visibleSince = undefined; continue; }
            visibleSince = e.isVisible ? (visibleSince || Date.now()) : null;
          }
        }, {threshold: [1], trackVisibility: true, delay: 100});
        io.observe(wrap);
        visibleSince = null;   // not visible until the observer says so
      } catch { visibleSince = undefined; }
    }
    const load = (cookies, from) => async (event) => {
      if (!current() || !clickAllowed(from, shadow, event, visibleSince)) {
        note.textContent = "Not loaded: the button was covered or had just appeared. Click again.";
        note.hidden = false;
        return;
      }
      button.disabled = true; withCookies.disabled = true;
      const reply = await B.runtime.sendMessage({type: "load-embed", embed: provider.id, cookies}).catch(() => null);
      if (reply && reply.ok && current()) {
        try { await onLoad(); box.remove(); } catch {
          note.textContent = "Not loaded: the original resource changed or could not be restored safely.";
          note.hidden = false; button.disabled = false; withCookies.disabled = false;
        }
      } else { button.disabled = false; withCookies.disabled = false; }
    };
    button.addEventListener("click", load(false, button));
    withCookies.addEventListener("click", load(true, withCookies));
    const row = document.createElement("div"); row.className = "row";
    row.append(button, withCookies);
    wrap.append(who, title, row, note);
    shadow.append(style, wrap);
    return box;
  }

  const heldFrames = new Map(), scripted = new Map(), loadedProviders = new Set();
  let scriptedTimer = null;
  function releaseFrame(record) {
    if (record.frame.style.getPropertyValue("display") === "none" && record.frame.style.getPropertyPriority("display") === "important") {
      if (record.display) record.frame.style.setProperty("display", record.display, record.priority);
      else record.frame.style.removeProperty("display");
    }
    record.box.remove(); heldFrames.delete(record.frame); record.frame.removeAttribute("data-eg-held");
  }
  function holdFrame(frame) {
    const old = heldFrames.get(frame);
    if (old && frame.getAttribute("src") === old.src && frame.isConnected) return;
    if (old) releaseFrame(old);
    const provider = providerOf(frame.getAttribute("src") || "");
    if (!provider || loadedProviders.has(provider.id) || heldFrames.size >= 200) return;
    const src = frame.getAttribute("src");
    frame.setAttribute("data-eg-held", "1");
    const display = frame.style.getPropertyValue("display"), priority = frame.style.getPropertyPriority("display");
    frame.style.setProperty("display", "none", "important");
    // A fresh copy navigates for certain; re-setting the same src on a frame that already failed may not.
    const current = () => frame.isConnected && frame.getAttribute("src") === src;
    const box = placeholder(provider, () => {
      if (!current()) throw new Error("stale frame");
      const fresh = frame.cloneNode(false); fresh.removeAttribute("data-eg-held");
      if (display) fresh.style.setProperty("display", display, priority); else fresh.style.removeProperty("display");
      fresh.setAttribute("src", src); loadedProviders.add(provider.id); heldFrames.delete(frame); frame.replaceWith(fresh);
    }, frame, current);
    frame.before(box); heldFrames.set(frame, {frame, box, src, display, priority, provider});
  }

  const SCRIPT_ATTRIBUTES = ["type", "integrity", "crossorigin", "referrerpolicy", "nonce", "nomodule", "defer", "fetchpriority", "blocking", "charset"];
  function scriptSpec(script, provider) {
    let src;
    try { src = new URL(script.getAttribute("src") || "", document.baseURI || root.location.href).href; } catch { return null; }
    if (!/^https?:/.test(src) || providerOf(src) !== provider) return null;
    const type = (script.getAttribute("type") || "").trim().toLowerCase();
    if (type && !["module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"].includes(type)) return null;
    const attrs = {};
    for (const name of SCRIPT_ATTRIBUTES) if (script.hasAttribute(name)) attrs[name] = script.getAttribute(name);
    // Browsers conceal a nonce through getAttribute, but preserve it through the nonce property.
    if (typeof script.nonce === "string" && script.nonce) attrs.nonce = script.nonce;
    const async = typeof script.async === "boolean" ? script.async : script.hasAttribute("async");
    return {src, attrs, async};
  }
  function retryScript(old, spec) {
    const fresh = document.createElement("script");
    // A cloned script can retain HTML's already-started flag. A fresh element is required,
    // with fetch/security attributes copied BEFORE src, and non-async scripts kept ordered.
    for (const [name, value] of Object.entries(spec.attrs)) fresh.setAttribute(name, value);
    if (spec.attrs.nonce && "nonce" in fresh) fresh.nonce = spec.attrs.nonce;
    fresh.async = spec.async;
    if (spec.async) fresh.setAttribute("async", "");
    fresh.setAttribute("src", spec.src);
    if (old.isConnected) { old.before(fresh); old.remove(); }
    else throw new Error("script detached");
  }
  function holdScripted() {
    scriptedTimer = null;
    for (const [id, record] of scripted) {
      if (!record.blocks.some((n) => n.isConnected) || !record.current()) { record.box.remove(); scripted.delete(id); }
    }
    for (const [id, selector] of Object.entries(SCRIPT_EMBEDS)) {
      const provider = embeds.find((e) => e.id === id);
      if (!provider || loadedProviders.has(id) || scripted.has(id)) continue;
      const blocks = [...document.querySelectorAll(selector)].slice(0, 100);
      if (!blocks.length) continue;
      const scripts = [...document.querySelectorAll("script[src]")].slice(0, 400).map((node) => ({node, spec: scriptSpec(node, provider)})).filter((s) => s.spec);
      if (!scripts.length || scripts.length > 20) continue;
      const current = () => blocks.some((n) => n.isConnected) && scripts.every(({node, spec}) => node.isConnected && JSON.stringify(scriptSpec(node, provider)) === JSON.stringify(spec));
      // One placeholder per provider: loading it re-adds the page's own provider scripts, which render every block.
      const box = placeholder(provider, () => {
        if (!current()) throw new Error("stale script contract");
        loadedProviders.add(id); scripted.delete(id);
        for (const {node, spec} of scripts) retryScript(node, spec);
      }, null, current);
      blocks[0].before(box); scripted.set(id, {box, blocks, current});
    }
  }

  function dropHints(node) {
    if (node.tagName !== "LINK") return;
    const rel = (node.getAttribute("rel") || "").toLowerCase();
    if (!/\b(preconnect|dns-prefetch|prefetch|prerender)\b/.test(rel)) return;
    if (hostOf(node.getAttribute("href") || "") !== root.location.hostname) node.remove();
  }

  function holdAll(root0) {
    for (const f of root0.querySelectorAll ? root0.querySelectorAll("iframe[src]") : []) holdFrame(f);
    for (const l of root0.querySelectorAll ? root0.querySelectorAll("link[rel]") : []) dropHints(l);
  }
  function startStrict() {
    holdAll(document);
    new MutationObserver((mutations) => {
      let changed = false;
      for (const record of [...heldFrames.values()]) if (!record.frame.isConnected) releaseFrame(record);
      for (const m of mutations) {
        if (m.type === "attributes") {
          if (m.target.tagName === "IFRAME") holdFrame(m.target);
          else if (m.target.tagName === "LINK") dropHints(m.target);
          changed = true;
        }
        for (const n of m.addedNodes || []) {
          if (n.nodeType !== 1 || n.hasAttribute(PLACEHOLDER)) continue;
          if (n.tagName === "IFRAME") holdFrame(n); else if (n.tagName === "LINK") dropHints(n); else holdAll(n);
          changed = true;
        }
        if (m.removedNodes && m.removedNodes.length) changed = true;
      }
      if (changed && scriptedTimer === null) scriptedTimer = setTimeout(holdScripted, 150);
    }).observe(document.documentElement, {childList: true, subtree: true, attributes: true, attributeFilter: ["src", "class", "rel", "href", ...SCRIPT_ATTRIBUTES]});
    const later = () => holdScripted();
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", later, {once: true}); else later();
  }

  B.runtime.sendMessage({type: "guard-config"}).then((reply) => {
    if (!reply) return;
    if (reply.clean === false) enabled = false;
    if ((reply.mode === "strict" || reply.mode === "noscript") && Array.isArray(reply.embeds)) { embeds = reply.embeds; startStrict(); }
  }).catch(() => {});

  root.__EGPageGuard = Object.freeze({status: () => ({enabled, cleaned, pingsRemoved, held: document.querySelectorAll(`[${PLACEHOLDER}]`).length}), cleanHref, clickAllowed, placeholder});
})(globalThis);
