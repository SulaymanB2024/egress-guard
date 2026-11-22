/* Optional Chrome profile controls. Only this fixed catalog has write authority.
 * Saved intent precedes browser mutations; every result is read back. Clearing a
 * ChromeSetting removes this extension's layer, never writes an old user value. */
(function (root) {
  "use strict";
  const KEY = "egressGuardBrowserPrivacy";
  const SCOPE = "regular";
  const CATALOG = Object.freeze([
    {id: "prediction", group: "Network connections", path: ["network", "networkPredictionEnabled"], value: false,
      label: "Stop speculative page loading", detail: "Disables Chrome's prediction and page preloading, including Speculation Rules. Page-initiated preconnect and DNS-prefetch are outside this setting."},
    {id: "webrtc", group: "Network connections", path: ["network", "webRTCIPHandlingPolicy"], value: "disable_non_proxied_udp",
      label: "Restrict WebRTC UDP", detail: "Disables non-proxied UDP for WebRTC. Calls may use TCP or fail; TCP and the public IP address are not hidden by this control."},
    {id: "auditing", group: "Website tracking", path: ["websites", "hyperlinkAuditingEnabled"], value: false,
      label: "Disable link-auditing pings", detail: "Stops HTML hyperlink auditing across this profile. Other tracking requests still need network rules."},
    {id: "third-party-cookies", group: "Website tracking", path: ["websites", "thirdPartyCookiesAllowed"], value: false,
      label: "Block third-party cookies", detail: "Applies Chrome's third-party cookie restriction. Sign-in and embeds can break; browser exemptions and Storage Access grants can still allow access."},
    {id: "topics", group: "Legacy advertising controls", path: ["websites", "topicsEnabled"], value: false, lifecycle: "legacy",
      label: "Keep the legacy Topics preference disabled", detail: "Topics is being retired. This compatibility preference may still exist after its advertising API stops working; reading it back does not prove an additional privacy benefit."},
    {id: "ad-auctions", group: "Legacy advertising controls", path: ["websites", "fledgeEnabled"], value: false, lifecycle: "legacy",
      label: "Keep the legacy browser-auction preference disabled", detail: "Protected Audience / Fledge is being retired. Keep or release an existing override here; this switch is not counted as a current protection."},
    {id: "ad-measurement", group: "Legacy advertising controls", path: ["websites", "adMeasurementEnabled"], value: false, lifecycle: "legacy",
      label: "Keep the legacy ad-measurement preference disabled", detail: "Attribution Reporting and Private Aggregation are being retired. An exposed preference does not establish that those APIs still operate in this browser."},
    {id: "search-suggestions", group: "Browser services", path: ["services", "searchSuggestEnabled"], value: false,
      label: "Stop sending typed searches for suggestions", detail: "Disables search-provider suggestions while typing in the address bar. Searches you submit still go to the provider."},
    {id: "remote-spelling", group: "Browser services", path: ["services", "spellingServiceEnabled"], value: false,
      label: "Disable the online spelling service", detail: "Disables Chrome's remote spelling service; this does not disable local spell checking."},
    {id: "error-service", group: "Browser services", path: ["services", "alternateErrorPagesEnabled"], value: false,
      label: "Disable the navigation-error service", detail: "Stops Chrome's web service for resolving navigation errors."},
  ].map(spec => Object.freeze({lifecycle: "active", recommended: spec.lifecycle !== "legacy", ...spec, path: Object.freeze(spec.path)})));
  const IDS = new Set(CATALOG.map(spec => spec.id));
  const LEVELS = new Set(["not_controllable", "controlled_by_other_extensions", "controllable_by_this_extension", "controlled_by_this_extension"]);
  const IP_VALUES = new Set(["default", "default_public_and_private_interfaces", "default_public_interface_only", "disable_non_proxied_udp"]);
  const plain = value => value && typeof value === "object" && !Array.isArray(value);
  const messageOf = error => String(error && error.message || error).slice(0, 240);
  function validateSelection(value) {
    if (!Array.isArray(value) || value.length > CATALOG.length || value.some(id => typeof id !== "string" || !IDS.has(id)) || new Set(value).size !== value.length) {
      throw new Error("Select only the listed browser privacy controls, once each.");
    }
    return [...value].sort();
  }
  function validateState(value) {
    if (!plain(value) || value.schema !== 1 || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
        Object.keys(value).some(key => !["schema", "revision", "selected"].includes(key))) throw new Error("Saved browser privacy choices are invalid. Apply new choices or release the controls to recover.");
    return {schema: 1, revision: value.revision, selected: validateSelection(value.selected)};
  }
  function settingFor(C, spec) {
    const setting = C.privacy && C.privacy[spec.path[0]] && C.privacy[spec.path[0]][spec.path[1]];
    return setting && ["get", "set", "clear"].every(method => typeof setting[method] === "function") ? setting : null;
  }
  function checkedDetails(spec, details) {
    if (!plain(details) || !LEVELS.has(details.levelOfControl) || details.incognitoSpecific === true ||
        (spec.id === "webrtc" ? !IP_VALUES.has(details.value) : typeof details.value !== "boolean")) throw new Error("Chrome returned an invalid setting receipt.");
    return details;
  }

  function createController(C) {
    let state = {schema: 1, revision: 0, selected: []};
    let saved = false, loaded = false, configError = "", errors = {};
    let tail = Promise.resolve();
    const serial = work => { const result = tail.then(work, work); tail = result.catch(() => {}); return result; };
    async function permission() {
      if (!C.permissions || typeof C.permissions.contains !== "function") return false;
      return (await C.permissions.contains({permissions: ["privacy"]})) === true;
    }
    async function load() {
      if (loaded) return;
      try {
        const value = (await C.storage.local.get(KEY))[KEY];
        if (value !== undefined) { state = validateState(value); saved = true; }
        loaded = true; configError = "";
      } catch (error) { configError = messageOf(error); }
    }
    async function inspect() {
      await load();
      let permitted = false, permissionError = "";
      try { permitted = await permission(); } catch (error) { permissionError = messageOf(error); }
      const selected = new Set(state.selected), rows = [];
      for (const spec of CATALOG) {
        const wanted = selected.has(spec.id);
        const row = {id: spec.id, lifecycle: spec.lifecycle, selected: wanted, target: spec.value, supported: false, value: null,
          levelOfControl: null, effective: false, owned: false, state: permitted ? "unavailable" : "permission-required", error: ""};
        const setting = permitted && settingFor(C, spec);
        if (setting) {
          row.supported = true;
          try {
            const details = checkedDetails(spec, await setting.get({incognito: false}));
            row.value = details.value; row.levelOfControl = details.levelOfControl;
            row.effective = details.value === spec.value;
            row.owned = details.levelOfControl === "controlled_by_this_extension";
            row.state = wanted
              ? (row.effective ? (row.owned ? "applied" : "effective-elsewhere") : (details.levelOfControl === "not_controllable" || details.levelOfControl === "controlled_by_other_extensions" ? "overridden" : "pending"))
              : (row.owned ? "release-pending" : "released");
          } catch (error) { row.state = "unknown"; row.error = messageOf(error); }
        }
        // A failed clear may leave an invisible lower-precedence extension layer.
        // Effective-value readback cannot prove that layer was removed.
        if (errors[spec.id] && (!wanted || !row.effective)) {
          row.error = errors[spec.id];
          if (!wanted) row.state = "release-pending";
        }
        rows.push(row);
      }
      const needsRelease = rows.some(row => !row.selected && (row.owned || row.state === "release-pending"));
      const unreadable = rows.some(row => row.state === "unknown");
      const complete = permitted && !configError && !permissionError && !unreadable && !needsRelease && rows.filter(row => row.selected).every(row => row.effective);
      const count = lifecycle => ({selected: rows.filter(row => row.lifecycle === lifecycle && row.selected).length,
        confirmed: rows.filter(row => row.lifecycle === lifecycle && row.selected && row.effective).length});
      return {schema: 1, permission: permitted, scope: SCOPE, saved, revision: state.revision, selected: [...state.selected],
        state: configError || permissionError || unreadable ? "degraded" : !permitted && saved ? "permission-required" : !state.selected.length && !needsRelease ? "inactive" : complete ? "applied" : "degraded",
        complete, evidence: "chrome-setting-readback", behaviorVerified: false,
        counts: {active: count("active"), legacy: count("legacy")}, error: configError || permissionError, rows};
    }
    async function reconcileNow() {
      await load();
      if (configError || !saved) return inspect();
      let permitted;
      try { permitted = await permission(); } catch { return inspect(); }
      if (!permitted) return inspect();
      errors = {};
      const selected = new Set(state.selected);
      for (const spec of CATALOG) {
        const setting = settingFor(C, spec);
        if (!setting) continue;
        try {
          if (!selected.has(spec.id)) {
            // clear() affects only our own layer, even when another extension or
            // policy currently has precedence. Never restore a captured value.
            await setting.clear({scope: SCOPE});
          } else {
            const details = checkedDetails(spec, await setting.get({incognito: false}));
            if (details.levelOfControl === "controlled_by_other_extensions" || details.levelOfControl === "not_controllable") continue;
            if (details.levelOfControl !== "controlled_by_this_extension" || details.value !== spec.value) await setting.set({scope: SCOPE, value: spec.value});
          }
        } catch (error) { errors[spec.id] = messageOf(error); }
      }
      return inspect();
    }
    const ready = serial(async () => { await load(); return saved && !configError ? reconcileNow() : inspect(); });
    async function setNow(selection) {
      const next = validateSelection(selection);
      await load();
      const revision = Number.isSafeInteger(state.revision + 1) ? state.revision + 1 : 1;
      const replacement = {schema: 1, revision, selected: next};
      // Failing this write has no authority to mutate browser settings.
      await C.storage.local.set({[KEY]: replacement});
      state = replacement; saved = loaded = true; configError = "";
      return reconcileNow();
    }
    return Object.freeze({ready, status: () => serial(inspect), apply: selected => serial(() => setNow(selected)),
      release: () => serial(() => setNow([])), retry: () => serial(reconcileNow)});
  }
  const api = Object.freeze({KEY, SCOPE, CATALOG, validateSelection, validateState, createController});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGBrowserPrivacy = api;
})(globalThis);
