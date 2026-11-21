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

  /** The clean address for a link's href, or null when it is already clean or cannot be cleaned safely. */
  function cleanHref(link) {
    let href = link.href;
    if (typeof href !== "string" || !/^https?:/i.test(href)) return null;
    let host = "";
    try { host = new URL(href).hostname; } catch { return null; }
    if (host === "t.co") {
      const shown = link.getAttribute("data-expanded-url") || link.getAttribute("title") || "";
      const real = links.safeDestination(shown.trim());
      if (real) href = real;
    }
    if (links.wrapperOf(href)) {
      const r = links.unwrap(href);
      if (r.url) href = r.url;
    }
    href = params.clean(href).url;
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

  function placeholder(provider, onLoad, sizeFrom) {
    const box = document.createElement("div");
    box.setAttribute(PLACEHOLDER, provider.id);
    const shadow = box.attachShadow({mode: "closed"});
    const style = document.createElement("style");
    style.textContent = `:host{all:initial;display:block;margin:8px 0}
      .b{display:flex;flex-direction:column;align-items:flex-start;justify-content:center;gap:8px;box-sizing:border-box;min-height:120px;padding:16px;border:1px dashed #8a948c;border-radius:8px;background:#f4f4f0;color:#1b1f1d;font:14px/1.4 system-ui,-apple-system,"Segoe UI",sans-serif}
      .t{font-weight:650}.n{color:#4d5650;font-size:12.5px}
      button{font:inherit;font-weight:600;border:1px solid #2f6f58;border-radius:6px;padding:6px 12px;color:#fff;background:#19382e;cursor:pointer}
      button:focus-visible{outline:3px solid #2f6f58;outline-offset:2px}
      @media (prefers-color-scheme:dark){.b{background:#1d2421;color:#e8ece9;border-color:#5b665f}.n{color:#a9b3ad}}`;
    const wrap = document.createElement("div");
    wrap.className = "b";
    if (sizeFrom) {
      const w = parseInt(sizeFrom.getAttribute("width"), 10), h = parseInt(sizeFrom.getAttribute("height"), 10);
      if (w > 0) wrap.style.maxWidth = `${Math.min(w, 2000)}px`;
      if (h > 0) wrap.style.minHeight = `${Math.min(h, 2000)}px`;
    }
    const title = document.createElement("span"); title.className = "t"; title.textContent = `${provider.name} content held`;
    const note = document.createElement("span"); note.className = "n"; note.textContent = `Loading it lets ${provider.name} see this visit. Held by Egress Guard (Strict).`;
    const button = document.createElement("button"); button.type = "button"; button.textContent = `Load from ${provider.name}`;
    button.addEventListener("click", async (event) => {
      if (!event.isTrusted) return;   // only a real click
      button.disabled = true;
      const reply = await B.runtime.sendMessage({type: "load-embed", embed: provider.id}).catch(() => null);
      if (reply && reply.ok) { box.remove(); onLoad(); } else button.disabled = false;
    });
    wrap.append(title, note, button);
    shadow.append(style, wrap);
    return box;
  }

  function holdFrame(frame) {
    if (frame.hasAttribute("data-eg-held")) return;
    const provider = providerOf(frame.getAttribute("src") || "");
    if (!provider) return;
    const src = frame.getAttribute("src");
    frame.setAttribute("data-eg-held", "1");
    const display = frame.style.display;
    frame.style.display = "none";
    // A fresh copy navigates for certain; re-setting the same src on a frame that already failed may not.
    frame.before(placeholder(provider, () => { const fresh = frame.cloneNode(false); fresh.style.display = display; fresh.setAttribute("src", src); frame.replaceWith(fresh); }, frame));
  }

  function holdScripted() {
    for (const [id, selector] of Object.entries(SCRIPT_EMBEDS)) {
      const provider = embeds.find((e) => e.id === id);
      if (!provider) continue;
      const blocks = [...document.querySelectorAll(selector)].filter((n) => !n.hasAttribute("data-eg-held"));
      if (!blocks.length) continue;
      const scripts = [...document.querySelectorAll("script[src]")].filter((sc) => providerOf(sc.getAttribute("src")) === provider);
      if (!scripts.length) continue;
      for (const n of blocks) n.setAttribute("data-eg-held", "1");
      // One placeholder per provider: loading it re-adds the page's own provider scripts, which render every block.
      blocks[0].before(placeholder(provider, () => {
        for (const old of scripts) { const fresh = document.createElement("script"); fresh.src = old.getAttribute("src"); fresh.async = true; document.head.append(fresh); }
      }, null));
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
      for (const m of mutations) for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.tagName === "IFRAME") holdFrame(n); else if (n.tagName === "LINK") dropHints(n); else holdAll(n);
      }
    }).observe(document.documentElement, {childList: true, subtree: true});
    const later = () => holdScripted();
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", later, {once: true}); else later();
  }

  B.runtime.sendMessage({type: "guard-config"}).then((reply) => {
    if (!reply) return;
    if (reply.clean === false) enabled = false;
    if ((reply.mode === "strict" || reply.mode === "noscript") && Array.isArray(reply.embeds)) { embeds = reply.embeds; startStrict(); }
  }).catch(() => {});

  root.__EGPageGuard = Object.freeze({status: () => ({enabled, cleaned, pingsRemoved, held: document.querySelectorAll(`[${PLACEHOLDER}]`).length}), cleanHref});
})(globalThis);
