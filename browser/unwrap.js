/* Unwrap page (Chrome). A navigation to a known link tracker arrives here as …/unwrap.html#<tracker URL> (a DNR
 * redirect, so the tracker never saw it). core/links.js reads the destination; the page replaces itself with it, so
 * Back returns to the page the link was on. Anything it cannot read is shown as text, never opened. */
(function (root) {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const links = root.EGLinks;

  function fail(original, reason) {
    $("card").hidden = false;
    $("url").textContent = original || "Unknown address";
    $("reason").textContent = reason ? `Reason: ${reason}.` : "";
    $("back").addEventListener("click", () => { if (root.history.length > 1) root.history.back(); else root.close(); });
  }

  function run() {
    const original = root.location.hash.slice(1);
    if (root.top !== root.self) return fail(original, "this page cannot run inside another page");
    const result = links.unwrap(original);
    if (result.error) return fail(original, result.error);
    root.location.replace(result.url);
    return result.url;
  }

  root.__EGUnwrap = {result: run()};
})(globalThis);
