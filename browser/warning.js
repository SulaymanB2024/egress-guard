/* Local warning page for blocked threat navigations (Chrome). Everything shown comes from this page's
 * own URL (…/warning.html?list=threats#<blocked URL>) and is written with textContent. */
(function (root) {
  "use strict";
  const B = root.browser || root.chrome;
  const $ = (id) => document.getElementById(id);
  const dnr = root.EGDnr;

  function showError(message) { $("error").textContent = message; $("error").hidden = !message; }

  function date(seconds) {
    if (typeof seconds !== "number") return "Unknown";
    return new Date(seconds * 1000).toLocaleDateString(undefined, {year: "numeric", month: "short", day: "numeric"});
  }

  async function init() {
    const target = parseLocation();
    if (!target) { $("host").textContent = "Unknown address"; $("reveal").disabled = true; return; }
    $("host").textContent = target.host;
    $("url").textContent = target.url;
    document.title = `Blocked: ${target.host}`;
    $("back").addEventListener("click", () => {
      if (root.history.length > 1) root.history.back();
      else B.tabs.update({url: "chrome://newtab/"}).catch(() => {});
    });
    $("reveal").addEventListener("click", () => {
      const open = $("confirm").hidden;
      $("confirm").hidden = !open;
      $("reveal").setAttribute("aria-expanded", String(open));
      if (open) $("continue").focus();
    });
    $("continue").addEventListener("click", async () => {
      $("continue").disabled = true;
      const reply = await B.runtime.sendMessage({type: "continue-once"});
      if (!reply || reply.error || !reply.url) { $("continue").disabled = false; showError(reply && reply.error ? reply.error : "Could not add the exception."); return; }
      root.location.replace(reply.url);
    });
    const info = await B.runtime.sendMessage({type: "warning-info", list: target.list}).catch(() => null);
    if (info && info.list) {
      $("list").textContent = `${info.list.label} · ${info.list.name}`;
      $("updated").textContent = date(info.list.published_at || info.list.updated_at);
    }
    if (info && info.minutes) $("minutes").textContent = String(info.minutes);
  }

  function parseLocation() { return dnr ? dnr.parseWarning(root.location.href) : null; }

  root.__EGWarning = {ready: init().catch((error) => showError(String(error && error.message || error)))};
})(globalThis);
