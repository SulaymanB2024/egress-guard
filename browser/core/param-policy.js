/* Validated data-only query-removal policy, shared by click/address cleaning and
 * the build-time DNR compiler. Invalid generated policy disables cleaning; it
 * never falls back to legacy rules which could ignore a source exception. */
(function (root) {
  "use strict";
  const cache = new WeakMap();
  const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
  const NAME = /^[A-Za-z0-9_.~!$'()*+\[\]:@-]{1,128}$/;
  const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const PREFIX = /^[a-z0-9][a-z0-9-]{0,2}$/;
  const covers = (host, domains) => domains.some((d) => host === d || host.endsWith(`.${d}`));
  const lower = (host) => String(host || "").toLowerCase().replace(/\.$/, "");

  function prepare(data) {
    if (!data || typeof data !== "object" || data.schema !== 1 || data.generated !== true) return null;
    if (cache.has(data)) return cache.get(data);
    let result = null, cells = 0;
    try {
      if (typeof data.disabled !== "boolean" || !Array.isArray(data.groups) || data.groups.length > 10000) throw Error("policy-shape");
      const list = (xs, re, max) => {
        if (!Array.isArray(xs) || xs.length > max) throw Error("policy-array");
        cells += xs.length;
        if (cells > 200000 || xs.some((v) => typeof v !== "string" || !re.test(v))) throw Error("policy-value");
        return Object.freeze([...new Set(xs)]);
      };
      const globals = [], byHost = new Map();
      for (const raw of data.groups) {
        if (!raw || typeof raw !== "object") throw Error("policy-group");
        const group = Object.freeze({names: list(raw.names, NAME, 5000), include: list(raw.include, HOST, 2000),
          exclude: list(raw.exclude, HOST, 3000), excludeLabels: list(raw.excludeLabels || [], LABEL, 32),
          excludeLabelPrefixes: list(raw.excludeLabelPrefixes || [], PREFIX, 32)});
        if (!group.names.length) throw Error("policy-empty-group");
        if (!group.include.length) globals.push(group);
        for (const host of group.include) {
          if (!byHost.has(host)) byHost.set(host, []);
          byHost.get(host).push(group);
        }
      }
      const pathExcludedHosts = list(data.pathExcludedHosts || [], HOST, 3000);
      const pathExcludedLabels = list(data.pathExcludedLabels || [], LABEL, 32);
      const pathExcludedLabelPrefixes = list(data.pathExcludedLabelPrefixes || [], PREFIX, 32);
      result = {disabled: data.disabled, globals, byHost, pathExcludedHosts, pathExcludedLabels, pathExcludedLabelPrefixes};
    } catch (_) { /* A malformed generated policy cannot authorize any removal. */ }
    cache.set(data, result);
    return result;
  }

  function namesFor(host, data) {
    const policy = prepare(data), h = lower(host), names = new Set();
    if (!policy || policy.disabled || data.disabled || !HOST.test(h)) return names;
    const labels = new Set(h.split(".")), groups = new Set(policy.globals);
    let suffix = h;
    while (suffix) {
      for (const group of policy.byHost.get(suffix) || []) groups.add(group);
      const dot = suffix.indexOf(".");
      if (dot < 0) break;
      suffix = suffix.slice(dot + 1);
    }
    for (const group of groups) {
      if (covers(h, group.exclude) || group.excludeLabels.some((label) => labels.has(label)) ||
        group.excludeLabelPrefixes.some((prefix) => [...labels].some((label) => label.startsWith(prefix)))) continue;
      for (const name of group.names) names.add(name);
    }
    return names;
  }

  function pathAllowed(host, data) {
    const policy = prepare(data), h = lower(host);
    return !!policy && !policy.disabled && !data.disabled && HOST.test(h) && !covers(h, policy.pathExcludedHosts) &&
      !policy.pathExcludedLabels.some((label) => h.split(".").includes(label)) &&
      !policy.pathExcludedLabelPrefixes.some((prefix) => h.split(".").some((label) => label.startsWith(prefix)));
  }

  const api = Object.freeze({HOST, NAME, LABEL, PREFIX, covers, lower, prepare, namesFor, pathAllowed});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGParamPolicy = api;
})(globalThis);
