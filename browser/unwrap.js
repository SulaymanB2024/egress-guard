/* Unwrap page and mail-scanner interstitial (Chrome). Reached only by a DNR redirect (…/unwrap.html#<link>): the page is
 * web-accessible by its per-session dynamic address alone, refuses to run inside a frame (here and through the
 * extension CSP's frame-ancestors 'none'), and shows anything it cannot read as text, never opening it.
 *
 *   - A link tracker (core/links.js WRAPPERS) whose navigation started on its own site: the destination is decoded,
 *     checked against the malware and phishing list, and opened with location.replace, so Back returns to the page
 *     the link was on. A listed destination goes to the local warning page instead.
 *   - A mail security scanner (SCANNERS): nothing opens by itself. The page shows the destination host (and its
 *     Unicode form for an internationalized name) and offers "Continue through the scanner" (the default: the worker
 *     lets the next navigation to that scanner in this tab pass, once) or "Open directly", which skips the scan and
 *     is checked against the threat list first. "Always open scanned links directly" in the popup skips the page. */
(function (root) {
  "use strict";
  const B = root.chrome;
  const $ = (id) => document.getElementById(id);
  const links = root.EGLinks;
  const send = (message) => Promise.resolve().then(() => B.runtime.sendMessage(message)).catch(() => null);
  let busy = false;
  // Button labels must fit one line at 390 px: the scanners' short names (the full name is in the headline).
  const SHORT = {safelinks: "Safe Links", proofpoint2: "Proofpoint", proofpoint3: "Proofpoint", mimecast: "Mimecast", barracuda: "Barracuda", trendmicro: "Trend Micro"};

  function fail(original, reason) {
    $("scan").hidden = true;
    $("card").hidden = false;
    $("url").textContent = original || "Unknown address";
    $("reason").textContent = reason ? `Reason: ${reason}.` : "";
    $("back").addEventListener("click", () => { if (root.history.length > 1) root.history.back(); else root.close(); });
    // Copy link: the address as text, for someone who knows where it should lead. Nothing is opened.
    $("copy").addEventListener("click", async () => {
      try { await root.navigator.clipboard.writeText(original || ""); $("copy").textContent = "Copied"; } catch {
        const range = document.createRange(); range.selectNodeContents($("url"));
        const selection = root.getSelection(); selection.removeAllRanges(); selection.addRange(range);
        $("copy").textContent = "Selected: press Ctrl+C or ⌘C";
      }
    });
    $("back").focus();
    return {error: reason || "failed"};
  }

  /** Open `url` unless it is on the threat list; a listed address goes to the warning page instead. */
  async function go(url, original) {
    const dest = links.safeDestination(url);
    if (!dest) return fail(original, "the destination is not a web address");
    const reply = await send({type: "check-destination", url: dest});
    if (!reply || reply.error || typeof reply.threat !== "boolean") return fail(original, (reply && reply.error) || "the destination could not be checked against the malware and phishing list");
    const next = reply.threat ? `warning.html?list=threats#${dest}` : dest;
    root.location.replace(next);
    return {url: next, threat: reply.threat};
  }

  /** A hostname as one box per label (dot included), so it wraps only between labels. */
  function byLabel(node, host) {
    const labels = host.split(".");
    node.replaceChildren(...labels.map((label, i) => Object.assign(document.createElement("span"), {className: "lbl", textContent: i < labels.length - 1 ? `${label}.` : label})));
  }

  function scanError(message) { $("scan-error").textContent = message; $("scan-error").hidden = !message; }

  function interstitial(scan, original) {
    $("card").hidden = true;
    $("scan").hidden = false;
    const name = scan.scanner.name;
    document.title = `${name} link`;
    $("scan-title").textContent = `Open this link through ${name}?`;
    $("through").textContent = `Continue through ${SHORT[scan.scanner.id] || "the scanner"}`;
    if (scan.host) {
      byLabel($("scan-host"), scan.host);
      const unicode = links.unicodeHost(scan.host);
      if (unicode && unicode !== scan.host) {
        // A look-alike name: the status line carries the reduced state; one sentence says what it imitates.
        $("scan").setAttribute("data-state", "reduced");
        $("scan-dot").hidden = false;
        $("scan-eyebrow").textContent = "Mail scanner link with look-alike letters";
        $("scan-idn").hidden = false;
        $("scan-idn").replaceChildren(document.createTextNode("This name displays as "), Object.assign(document.createElement("b"), {textContent: unicode, className: "host"}),
          document.createTextNode(" but opens the address above."));
      }
    } else {
      $("scan-host").textContent = "Not shown by the scanner";
      $("scan-host").className = "unknown";
    }
    $("scan-url").textContent = scan.url || original;
    if (!scan.url) {
      // The scanner keeps the full address on its server: it can only be opened through the scanner.
      $("direct").hidden = true;
      $("scan-body").hidden = false;
      $("scan-body").textContent = `${name} keeps the full address on its own server${scan.host ? "; only the host above is in the link" : ""}.`;
    }
    $("through").addEventListener("click", async () => {
      if (busy) return;
      busy = true; scanError("");
      const reply = await send({type: "scanner-continue", url: original});
      if (!reply || !reply.ok) { busy = false; scanError((reply && reply.error) || "Could not continue through the scanner."); return; }
      root.location.replace(original);
    });
    $("direct").addEventListener("click", async () => {
      if (busy || !scan.url) return;
      busy = true; scanError("");
      const r = await go(scan.url, original);
      if (r && r.error) busy = false;
    });
    $("through").focus();
    return {scanner: scan.scanner.id, url: scan.url, host: scan.host};
  }

  async function run() {
    const original = root.location.hash.slice(1);
    if (root.top !== root.self) return fail(original, "this page cannot run inside another page");
    // If anything changes the address after this page rendered, start over: never show one link and open another.
    root.addEventListener("hashchange", () => root.location.reload());
    const scan = links.scanned(original);
    if (scan) {
      const config = await send({type: "unwrap-config"});
      if (config && config.scannedDirect === true && scan.url) return go(scan.url, original);
      return interstitial(scan, original);
    }
    // The navigation rule fired only because it started on the tracker's own site (or the tracker has no safety
    // check of its own), so its first layer may be unwrapped; inner layers only if they belong to that same site.
    const first = links.wrapperOf(original);
    const from = first && !first.open ? first.sites[0] : null;
    const result = links.unwrap(original, {from});
    if (result.error) return fail(original, result.error);
    const inner = links.scanned(result.url);
    if (inner) return interstitial(inner, result.url);
    return go(result.url, original);
  }

  root.__EGUnwrap = {ready: run().catch((error) => fail(root.location.hash.slice(1), String(error && error.message || error)))};
})(globalThis);
