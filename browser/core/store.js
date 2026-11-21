/* Rule and exception store. Pure: persistence is an injected adapter {load(): Promise<object|undefined>,
 * save(object): Promise<void>} and time is an injected clock, so the same store can back a Firefox
 * extension, a future Chrome DNR compiler, or a native-messaging bridge. */
(function (root) {
  "use strict";
  const isNode = typeof module !== "undefined" && module.exports;
  const rules = isNode ? require("./rules.js") : root.EGRules;
  const hosts = isNode ? require("./hosts.js") : root.EGHosts;
  const MAX_RULES = 500;
  const MAX_EXCEPTIONS = 50;
  const SCHEMA = 2;
  const SCOPE = "top-level-psl-v2";

  function randomId(prefix) {
    const bytes = new Uint8Array(6);
    globalThis.crypto.getRandomValues(bytes);
    return `${prefix}-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }

  class RuleStore {
    constructor({persist = null, now = () => Date.now()} = {}) {
      this.persist = persist;
      this.now = now;
      this.rules = [];
      this.exceptions = [];
      this.rejected = [];
    }

    /** Load persisted state, keeping only entries that still validate and have not expired. */
    async load() {
      const raw = this.persist ? await this.persist.load() : undefined;
      this.rules = []; this.exceptions = []; this.rejected = [];
      if (!raw || typeof raw !== "object") return this;
      if (raw.schema !== SCHEMA && raw.schema !== 1) { this.rejected.push("Unknown stored rule schema; entries were not restored."); return this; }
      const legacy = raw.schema !== SCHEMA || raw.scope !== SCOPE || raw.psl !== hosts.psl.sha256;
      // Old Chrome grants matched the immediate initiator and an incomplete suffix list.
      // Changing them into top-level permissions could widen authority: ask for a fresh grant.
      if (legacy) this.rejected.push("Legacy permissions were revoked for the top-level/PSL scope migration. Valid blocks and cosmetic rules were retained.");
      const now = this.now();
      for (const item of Array.isArray(raw.rules) ? raw.rules.slice(0, MAX_RULES) : []) {
        if (legacy && item && item.kind === "request" && item.action === "allow") continue;
        const result = rules.tryRule(item, {now});
        if (result.ok) this.rules.push(result.value); else this.rejected.push(result.error);
      }
      for (const item of !legacy && Array.isArray(raw.exceptions) ? raw.exceptions.slice(0, MAX_EXCEPTIONS) : []) {
        const result = rules.tryException(item, {now});
        if (result.ok) this.exceptions.push(result.value); else this.rejected.push(result.error);
      }
      return this;
    }

    snapshot(nextRules = this.rules, nextExceptions = this.exceptions) {
      return {schema: SCHEMA, scope: SCOPE, psl: hosts.psl.sha256, rules: nextRules.map((r) => ({...r, ...(r.types ? {types: [...r.types]} : {})})), exceptions: nextExceptions.map((e) => ({...e}))};
    }

    async save() { if (this.persist) await this.persist.save(this.snapshot()); }

    /** Persist the complete candidate before publishing it to callers. Storage failure is no mutation. */
    async commit(nextRules, nextExceptions) {
      if (this.persist) await this.persist.save(this.snapshot(nextRules, nextExceptions));
      this.rules = nextRules; this.exceptions = nextExceptions;
    }

    /** Add a rule (id generated when absent). Duplicates of an existing rule are refused. */
    async addRule(input) {
      if (this.rules.length >= MAX_RULES) throw new rules.RuleError(`At most ${MAX_RULES} rules.`);
      const now = this.now();
      const rule = rules.validateRule({createdAt: now, ...input, id: input && input.id ? input.id : randomId(input && input.kind === "cosmetic" ? "hide" : "req")}, {now});
      if (this.rules.some((r) => r.id === rule.id)) throw new rules.RuleError("A rule with that id exists.");
      if (this.rules.some((r) => sameRule(r, rule))) throw new rules.RuleError("An identical rule already exists.");
      await this.commit([...this.rules, rule], this.exceptions);
      return rule;
    }

    async removeRule(id) {
      const before = this.rules.length;
      const next = this.rules.filter((r) => r.id !== id);
      if (next.length !== before) await this.commit(next, this.exceptions);
      return next.length !== before;
    }

    /** Allow one exact endpoint for one site and resource type for `minutes` (1-1440). */
    async addException({site, host, path, type, minutes, tabId}) {
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > rules.MAX_EXCEPTION_MINUTES) {
        throw new rules.RuleError("Choose 1 to 1440 minutes.");
      }
      const now = this.now();
      const exc = rules.validateException({id: randomId("exc"), site, host, path, type, ...(tabId !== undefined ? {tabId} : {}), expiresAt: now + minutes * 60000, createdAt: now}, {now});
      const kept = this.exceptions.filter((e) => e.expiresAt > now && !(e.site === exc.site && e.host === exc.host && e.path === exc.path && e.type === exc.type && e.tabId === exc.tabId));
      if (kept.length >= MAX_EXCEPTIONS) throw new rules.RuleError(`At most ${MAX_EXCEPTIONS} exceptions.`);
      await this.commit(this.rules, [...kept, exc]);
      return exc;
    }

    async removeException(id) {
      const before = this.exceptions.length;
      const next = this.exceptions.filter((e) => e.id !== id);
      if (next.length !== before) await this.commit(this.rules, next);
      return next.length !== before;
    }

    pruneSync() {
      const now = this.now();
      const r = this.rules.length, e = this.exceptions.length;
      this.rules = this.rules.filter((x) => x.expiresAt === undefined || x.expiresAt > now);
      this.exceptions = this.exceptions.filter((x) => x.expiresAt > now);
      return r !== this.rules.length || e !== this.exceptions.length;
    }

    /** Remove expired rules and exceptions; persists when anything changed. */
    async prune() {
      const now = this.now();
      const nextRules = this.rules.filter((x) => x.expiresAt === undefined || x.expiresAt > now);
      const nextExceptions = this.exceptions.filter((x) => x.expiresAt > now);
      const changed = nextRules.length !== this.rules.length || nextExceptions.length !== this.exceptions.length;
      if (changed) await this.commit(nextRules, nextExceptions);
      return changed;
    }

    /** Earliest future expiry, for scheduling the next prune. */
    nextExpiry() {
      const times = [...this.rules, ...this.exceptions].map((x) => x.expiresAt).filter((t) => t !== undefined);
      return times.length ? Math.min(...times) : null;
    }

    /** Everything that applies on a top-level host right now. */
    activeFor(topHost) {
      const host = hosts.normalizeHost(topHost);
      const now = this.now();
      if (!host) return {requestRules: [], cosmeticRules: [], exceptions: []};
      const live = (x) => x.expiresAt === undefined || x.expiresAt > now;
      const scoped = (x) => hosts.inSiteScope(host, x.site) && live(x);
      return {
        requestRules: this.rules.filter((r) => r.kind === "request" && scoped(r)),
        cosmeticRules: this.rules.filter((r) => r.kind === "cosmetic" && scoped(r)),
        exceptions: this.exceptions.filter(scoped),
      };
    }
  }

  function sameRule(a, b) {
    if (a.kind !== b.kind || a.site !== b.site) return false;
    if (a.kind === "cosmetic") return a.selector === b.selector;
    return a.host === b.host && a.path === b.path && a.action === b.action && a.party === b.party && a.types.join() === b.types.join();
  }

  const api = Object.freeze({RuleStore, MAX_RULES, MAX_EXCEPTIONS, SCHEMA, SCOPE});
  if (isNode) module.exports = api;
  else root.EGStore = api;
})(globalThis);
