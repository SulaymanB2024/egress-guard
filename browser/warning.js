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

  function lock(message) {
    $("reveal").disabled = true;
    $("continue").disabled = true;
    $("confirm").hidden = true;
    if (message) showError(message);
  }

  async function init() {
    // Inside another page's frame the user cannot see what they would agree to (clickjacking): no Continue.
    if (root.top !== root.self) { lock("This warning cannot be used inside another page."); return; }
    const target = parseLocation();
    if (!target) { $("host").textContent = "Unknown address"; lock(); return; }
    // If anything changes the address after this page rendered, start over so the page never shows one host and
    // continues to another.
    root.addEventListener("hashchange", () => { lock(); root.location.reload(); });
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
      const reply = await B.runtime.sendMessage({type: "continue-once", url: target.url});
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
