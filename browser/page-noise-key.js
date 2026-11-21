/* EXPERIMENTAL fingerprint noise, isolated world, every frame; registered together with page-noise.js and only while
 * the user has noise switched on. A per-session secret (the extension's per-session resource address, regenerated on
 * every browser start) hashed with this frame's site gives a key that is stable for the site all session and
 * different on every other site. The page world receives only the derived key, at document_start, before any page
 * script exists; the offer is withdrawn once the document is parsed. */
(function (root) {
  "use strict";
  const B = root.chrome;
  function noiseKey() {
    const secret = B.runtime.getURL("unwrap.html");
    const site = (root.EGHosts && root.EGHosts.siteOf(root.location.hostname)) || root.location.hostname;
    let h = 0x811c9dc5;
    for (const ch of `${secret}|${site}`) { h ^= ch.charCodeAt(0); h = Math.imul(h, 0x01000193) >>> 0; }
    return h.toString(16);
  }
  const giveKey = () => root.dispatchEvent(new CustomEvent("eg-noise-key", {detail: noiseKey()}));
  root.addEventListener("eg-noise-hello", giveKey, {once: true});
  giveKey();
  document.addEventListener("DOMContentLoaded", () => root.removeEventListener("eg-noise-hello", giveKey), {once: true});
})(globalThis);
