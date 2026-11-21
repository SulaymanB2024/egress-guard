/* Offscreen document (Chrome): the only place an MV3 extension can write the clipboard without the page seeing it.
 * The worker opens it for "Copy clean link", sends the already-cleaned address, and closes it again. */
(function (root) {
  "use strict";
  const C = root.chrome;
  // Only the extension's own worker may ask: same extension id, no tab (content scripts and extension pages in tabs
  // have one), and a sender URL on the extension's own origin.
  const OWN = `chrome-extension://${C.runtime.id}/`;
  const fromWorker = (sender) => Boolean(sender) && sender.id === C.runtime.id && !sender.tab && typeof sender.url === "string" && sender.url.startsWith(OWN);
  C.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.type !== "offscreen-copy" || !fromWorker(sender) || typeof message.text !== "string") return false;
    const box = document.getElementById("text");
    box.value = message.text.slice(0, 8192);
    box.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { ok = false; }
    box.value = "";
    sendResponse({ok});
    return false;
  });
})(globalThis);
