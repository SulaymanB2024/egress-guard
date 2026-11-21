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
  B.runtime.sendMessage({type: "guard-config"}).then((reply) => { if (reply && reply.clean === false) enabled = false; }).catch(() => {});

  root.__EGPageGuard = Object.freeze({status: () => ({enabled, cleaned, pingsRemoved}), cleanHref});
})(globalThis);
