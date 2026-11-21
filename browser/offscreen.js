/* Offscreen document (Chrome): the only place an MV3 extension can write the clipboard without the page seeing it.
 * The worker opens it for "Copy clean link", sends the already-cleaned address, and closes it again. */
(function (root) {
  "use strict";
  const C = root.chrome;
  C.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || message.type !== "offscreen-copy" || sender.id !== C.runtime.id || typeof message.text !== "string") return false;
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
