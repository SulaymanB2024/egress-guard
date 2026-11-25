/* Shown in place of Chrome's "tunnel connection failed" when the system proxy refused the site: the worker asked the
 * proxy which layer refused it (refused.html?layer=…&source=…&allow=0|1&file=<allow file>#<blocked URL>). Everything shown comes from
 * this page's own URL and is written with textContent; the page grants nothing, it only explains. */
(function (root) {
  "use strict";
  const B = root.browser || root.chrome;
  const $ = (id) => document.getElementById(id);
  const hosts = root.EGHosts;

  // What each refusing list means, and how to allow a site on it. A threat gets no allow advice.
  const SOURCES = {
    "threat-intel": {state: "threat", title: "This site is on a malware and phishing list", list: "Malware and phishing"},
    "local-block": {title: "This site is on your block list", list: "Your block list",
      how: "To unblock it, open Egress Guard, go to Rules and remove it from your block list."},
    "configured-tracker": {title: "Egress Guard blocks this site as a tracker", list: "A tracker rule in Egress Guard's policy",
      how: "To allow it, add the name to this file. It takes effect within seconds.", file: true},
    "tracker-feed": {title: "Egress Guard blocks this site as a tracker", list: "Ads and trackers",
      how: "To allow it, add the name to this file. It takes effect within seconds.", file: true,
      brief: "To allow it for a while, open Egress Guard, go to Rules and look up the name. To allow it for good, add it to this file."},
    "cname-feed": {title: "Egress Guard blocks this site as a hidden tracker", list: "Hidden trackers (first-party aliases)",
      how: "To allow it, add the name to this file. It takes effect within seconds.", file: true,
      brief: "To allow it for a while, open Egress Guard, go to Rules and look up the name. To allow it for good, add it to this file."},
  };
  const DNS = {title: "Egress Guard's DNS filter blocks this site", list: "The DNS filter's block lists",
    how: "To allow it, add the name to this file. It takes effect within seconds.", file: true};

  function parse(href) {
    let page;
    try { page = new URL(href); } catch { return null; }
    let target;
    try { target = new URL(page.hash.slice(1)); } catch { return null; }
    if (target.protocol !== "http:" && target.protocol !== "https:") return null;
    const host = hosts ? hosts.normalizeHost(target.hostname) : target.hostname;
    if (!host) return null;
    const layer = page.searchParams.get("layer") === "dns-filter" ? "dns-filter" : "proxy";
    return {url: target.href, host, layer, source: page.searchParams.get("source") || "", canAllow: page.searchParams.get("allow") === "1",
      file: (page.searchParams.get("file") || "").slice(0, 200)};
  }

  function note(text) { $("note").textContent = text; $("note").hidden = !text; }

  function init() {
    const target = parse(root.location.href);
    if (!target) { $("host").textContent = "Unknown address"; $("retry").disabled = true; $("copy").disabled = true; return; }
    const about = target.layer === "dns-filter" ? DNS : (SOURCES[target.source] || {title: "Egress Guard blocks this site", list: "A block list"});
    $("page").dataset.state = about.state || "reduced";
    $("title").textContent = about.title;
    // One box per label (dot included), so the hostname wraps only between labels.
    const labels = target.host.split(".");
    $("host").replaceChildren(...labels.map((label, i) => Object.assign(document.createElement("span"),
      {className: "lbl", textContent: i < labels.length - 1 ? `${label}.` : label})));
    $("url").textContent = target.url;
    $("layer").textContent = target.layer === "dns-filter" ? "DNS filter (every app on this Mac)" : "Egress Guard proxy";
    $("list").textContent = about.list;
    let how = target.canAllow && about.brief ? about.brief : about.how;
    // The guard says where its allow list lives; without that, name the list rather than a path.
    if (how && about.file && !target.file) how = how.replace("to this file", "to Egress Guard's allow list");
    if (how) { $("how").textContent = how; $("how").hidden = false; }
    if (about.file && target.file) { $("path").textContent = target.file; $("path-line").hidden = false; }
    document.title = `Blocked: ${target.host}`;
    // If anything changes the address after this page rendered, start over so it never describes one host and
    // retries another.
    root.addEventListener("hashchange", () => root.location.reload());

    $("back").addEventListener("click", () => {
      if (root.history.length > 2) root.history.go(-2);  // past the failed load to the page before it
      else if (B && B.tabs) B.tabs.update({url: "chrome://newtab/"}).catch(() => {});
    });
    $("retry").addEventListener("click", () => root.location.replace(target.url));
    $("copy").addEventListener("click", async () => {
      try { await root.navigator.clipboard.writeText(target.host); note(`Copied ${target.host}.`); }
      catch { note("Could not copy. Select the name above instead."); }
    });
    $("back").focus();
  }

  init();
})(globalThis);
