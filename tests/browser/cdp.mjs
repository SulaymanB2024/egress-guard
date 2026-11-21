// Minimal headless-Chrome driver over --remote-debugging-pipe, shared by the opt-in real-Chrome
// scripts (real-sites.mjs, chrome-lifecycle.mjs). Always a throwaway --user-data-dir;
// headless unless an explicit permission-qualification run requests a visible window; no dependencies.
import fs from "node:fs";
import {spawn} from "node:child_process";

export const DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const QUIET_FLAGS = ["--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
  "--disable-sync", "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--no-pings",
  "--metrics-recording-only", "--disable-breakpad", "--password-store=basic", "--use-mock-keychain"];

/** Launch Chrome with a throwaway profile. Headed mode is opt-in for native permission prompts. */
export function launch({bin = DEFAULT_CHROME, profile, args = [], timeout = 90000, headless = true}) {
  if (!profile || !fs.existsSync(profile)) throw new Error("launch needs an existing throwaway profile directory");
  const child = spawn(bin, [...(headless ? ["--headless"] : []), "--remote-debugging-pipe", "--enable-unsafe-extension-debugging", `--user-data-dir=${profile}`,
    ...QUIET_FLAGS, ...args, "about:blank"], {stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"], detached: true});
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += d; if (stderr.length > 200000) stderr = stderr.slice(-100000); });
  const toChrome = child.stdio[3], fromChrome = child.stdio[4];
  let inbox = Buffer.alloc(0), nextId = 0;
  const waiting = new Map();
  const listeners = new Map();
  fromChrome.on("data", (chunk) => {
    inbox = Buffer.concat([inbox, chunk]);
    let end;
    while ((end = inbox.indexOf(0)) >= 0) {
      const msg = JSON.parse(inbox.subarray(0, end).toString("utf8"));
      inbox = inbox.subarray(end + 1);
      if (msg.id && waiting.has(msg.id)) {
        const w = waiting.get(msg.id); waiting.delete(msg.id);
        msg.error ? w.reject(new Error(`${msg.error.message} ${msg.error.data || ""}`)) : w.resolve(msg.result);
      } else if (msg.method) {
        for (const fn of listeners.get(msg.method) || []) { try { fn(msg.params, msg.sessionId); } catch {} }
      }
    }
  });
  const cdp = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`${method} timed out`)); }, timeout);
    waiting.set(id, {resolve: (v) => { clearTimeout(timer); resolve(v); }, reject: (e) => { clearTimeout(timer); reject(e); }});
    toChrome.write(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}) + "\0");
  });
  const on = (method, fn) => { if (!listeners.has(method)) listeners.set(method, []); listeners.get(method).push(fn); };
  async function evaluate(sessionId, expression) {
    const r = await cdp("Runtime.evaluate", {expression, awaitPromise: true, returnByValue: true}, sessionId);
    if (r.exceptionDetails) throw new Error(`evaluate: ${r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text}`);
    return r.result.value;
  }
  async function close() {
    try { await Promise.race([cdp("Browser.close"), sleep(5000)]); } catch {}
    await sleep(500);
    try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch {} }
  }
  return {cdp, on, evaluate, close, child, stderr: () => stderr};
}

/** Attach to (and if asked, wait for) the extension's service worker target. */
export async function attachWorker(cdp, extensionId, {tries = 100} = {}) {
  for (let i = 0; i < tries; i++) {
    const {targetInfos} = await cdp("Target.getTargets");
    const t = targetInfos.find((x) => x.type === "service_worker" && x.url === `chrome-extension://${extensionId}/background.js`);
    if (t) return {targetId: t.targetId, sessionId: (await cdp("Target.attachToTarget", {targetId: t.targetId, flatten: true})).sessionId};
    await sleep(200);
  }
  return null;
}

export async function waitFor(fn, ms = 20000, step = 200) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { if (await fn()) return true; } catch {} await sleep(step); }
  return false;
}
