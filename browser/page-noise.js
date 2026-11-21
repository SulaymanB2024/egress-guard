/* EXPERIMENTAL, off by default (popup: "Fingerprint noise"). Page world. Registered only while the user has it on.
 *
 * Adds small, deterministic noise to what a page reads back from canvas, WebGL and Web Audio, keyed per site and per
 * browser session: the same site sees the same values all session (so it does not look like a different visitor on
 * every call), another site sees different ones (so a fingerprint cannot be matched across sites), and the next
 * session starts over. The key comes from the isolated content script (page-guard.js) through one synchronous
 * event exchange at document_start, before any page script runs.
 *
 * Limits, stated in docs/browser-companion.md: this is detectable (a script can draw a known image and compare),
 * one user adding noise does not hide in a crowd the way Tor or Brave users do, and canvas-dependent sites (image
 * editors, some captchas) can misbehave. Fonts, screen size and the user agent are not touched. */
(function () {
  "use strict";
  let key = 0;
  const rawGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  window.addEventListener("eg-noise-key", (event) => { if (!key && typeof event.detail === "string") key = parseInt(event.detail, 16) >>> 0; }, {once: true});
  window.dispatchEvent(new CustomEvent("eg-noise-hello"));
  // If the isolated script runs after this one, its announcement arrives before any page script; only if it never
  // arrives (it was not injected) does a page get its own random key, which still never reveals the true value.
  const k = () => key || (key = (Math.random() * 0xffffffff) >>> 0);

  // xorshift-style hash of (key, index): deterministic per key.
  const prf = (i) => { let x = (k() ^ Math.imul(i + 0x9e3779b9, 0x85ebca6b)) >>> 0; x ^= x >>> 16; x = Math.imul(x, 0x7feb352d) >>> 0; x ^= x >>> 15; x = Math.imul(x, 0x846ca68b) >>> 0; return (x ^ (x >>> 16)) >>> 0; };

  /** Flip the lowest bit of one colour channel in about one pixel in 32, chosen by content and key. */
  function noisePixels(data) {
    for (let p = 0; p < data.length; p += 4) {
      const h = prf((p >> 2) ^ (data[p] << 16) ^ (data[p + 1] << 8) ^ data[p + 2]);
      if ((h & 31) === 0) data[p + (h >>> 5) % 3] ^= 1;
    }
    return data;
  }

  const define = (proto, name, make) => {
    const original = proto && proto[name];
    if (typeof original !== "function") return;
    const replacement = make(original);
    Object.defineProperty(proto, name, {value: replacement, writable: true, configurable: true, enumerable: false});
  };

  define(CanvasRenderingContext2D.prototype, "getImageData", (original) => function getImageData(...args) {
    const image = original.apply(this, args);
    noisePixels(image.data);
    return image;
  });

  /** A noised copy of a canvas (the page's own canvas is never changed). */
  function noisedCopy(canvas) {
    if (!canvas.width || !canvas.height) return null;
    const copy = document.createElement("canvas");
    copy.width = canvas.width; copy.height = canvas.height;
    const ctx = copy.getContext("2d");
    ctx.drawImage(canvas, 0, 0);
    const image = rawGetImageData.call(ctx, 0, 0, copy.width, copy.height);
    noisePixels(image.data);
    ctx.putImageData(image, 0, 0);
    return copy;
  }
  define(HTMLCanvasElement.prototype, "toDataURL", (original) => function toDataURL(...args) {
    const copy = noisedCopy(this);
    return original.apply(copy || this, args);
  });
  define(HTMLCanvasElement.prototype, "toBlob", (original) => function toBlob(...args) {
    const copy = noisedCopy(this);
    return original.apply(copy || this, args);
  });
  for (const proto of [window.WebGLRenderingContext && WebGLRenderingContext.prototype, window.WebGL2RenderingContext && WebGL2RenderingContext.prototype]) {
    define(proto, "readPixels", (original) => function readPixels(...args) {
      const result = original.apply(this, args);
      const out = args[6];
      if (out && out.length && out.BYTES_PER_ELEMENT === 1) noisePixels(out);
      return result;
    });
  }
  const touched = new WeakSet();
  define(window.AudioBuffer && AudioBuffer.prototype, "getChannelData", (original) => function getChannelData(channel) {
    const data = original.call(this, channel);
    if (!touched.has(data)) {
      touched.add(data);
      for (let i = 0; i < data.length; i += 97) data[i] += ((prf(i ^ channel) & 0xff) - 128) * 1e-9;
    }
    return data;
  });

})();
