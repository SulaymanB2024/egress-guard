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
  const SCHEMA = 1;

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
      if (!raw || typeof raw !== "object" || raw.schema !== SCHEMA) return this;
      const now = this.now();
      for (const item of Array.isArray(raw.rules) ? raw.rules.slice(0, MAX_RULES) : []) {
        const result = rules.tryRule(item, {now});
        if (result.ok) this.rules.push(result.value); else this.rejected.push(result.error);
      }
      for (const item of Array.isArray(raw.exceptions) ? raw.exceptions.slice(0, MAX_EXCEPTIONS) : []) {
        const result = rules.tryException(item, {now});
        if (result.ok) this.exceptions.push(result.value); else this.rejected.push(result.error);
      }
      return this;
    }

    snapshot() {
      return {schema: SCHEMA, rules: this.rules.map((r) => ({...r, ...(r.types ? {types: [...r.types]} : {})})), exceptions: this.exceptions.map((e) => ({...e}))};
    }

    async save() { if (this.persist) await this.persist.save(this.snapshot()); }

    /** Add a rule (id generated when absent). Duplicates of an existing rule are refused. */
    async addRule(input) {
      if (this.rules.length >= MAX_RULES) throw new rules.RuleError(`At most ${MAX_RULES} rules.`);
      const now = this.now();
      const rule = rules.validateRule({createdAt: now, ...input, id: input && input.id ? input.id : randomId(input && input.kind === "cosmetic" ? "hide" : "req")}, {now});
      if (this.rules.some((r) => r.id === rule.id)) throw new rules.RuleError("A rule with that id exists.");
      if (this.rules.some((r) => sameRule(r, rule))) throw new rules.RuleError("An identical rule already exists.");
      this.rules.push(rule);
      await this.save();
      return rule;
    }

    async removeRule(id) {
      const before = this.rules.length;
      this.rules = this.rules.filter((r) => r.id !== id);
      if (this.rules.length !== before) await this.save();
      return this.rules.length !== before;
    }

    /** Allow one exact endpoint for one site and resource type for `minutes` (1-1440). */
    async addException({site, host, path, type, minutes}) {
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > rules.MAX_EXCEPTION_MINUTES) {
        throw new rules.RuleError("Choose 1 to 1440 minutes.");
      }
      const now = this.now();
      const exc = rules.validateException({id: randomId("exc"), site, host, path, type, expiresAt: now + minutes * 60000, createdAt: now}, {now});
      this.pruneSync();
      this.exceptions = this.exceptions.filter((e) => !(e.site === exc.site && e.host === exc.host && e.path === exc.path && e.type === exc.type));
      if (this.exceptions.length >= MAX_EXCEPTIONS) throw new rules.RuleError(`At most ${MAX_EXCEPTIONS} exceptions.`);
      this.exceptions.push(exc);
      await this.save();
      return exc;
    }

    async removeException(id) {
      const before = this.exceptions.length;
      this.exceptions = this.exceptions.filter((e) => e.id !== id);
      if (this.exceptions.length !== before) await this.save();
      return this.exceptions.length !== before;
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
      const changed = this.pruneSync();
      if (changed) await this.save();
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
      const scoped = (x) => hosts.withinScope(host, x.site) && live(x);
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

  const api = Object.freeze({RuleStore, MAX_RULES, MAX_EXCEPTIONS, SCHEMA});
  if (isNode) module.exports = api;
  else root.EGStore = api;
})(globalThis);
