/* Selected tracker wire formats. Pure build-time compiler: no browser APIs, IO, SDK execution, or telemetry.
 *
 * These predicates recognize literal URL protocols, including publishers' same-origin reverse proxies.
 * They cannot identify arbitrarily renamed/encoded fields, opaque POST bodies, or server-to-server traffic.
 * The independently frozen evaluation corpus predates this module; see docs/tracking-protocols-0.10.md.
 */
(function (root) {
  "use strict";

  const SCHEMA = 1;
  const MAX_RULES = 32;
  const MAX_INTEGER = 2147483647;
  const OBSERVED = "2026-11-22";
  const COLLECT = ["image", "xmlhttprequest", "ping"];
  // DNR receives canonical request URLs. Consume everything up to their first query delimiter. In particular,
  // another URL inside a parameter value, a fragment, or a path is not a second request endpoint.
  const ORIGIN = "^https?://[^/?#@]+";
  const ANY_HTTP_QUERY = "^https?://[^?#]*\\?";
  const SKIP_FIELDS = "(?:[^&#]*&)*";
  const FIELD_END = "(?:[&#]|$)";

  function freeze(value) {
    if (value && typeof value === "object") {
      Object.values(value).forEach(freeze);
      Object.freeze(value);
    }
    return value;
  }

  const source = (url, revision) => ({url, ...(revision ? {revision} : {}), observed: OBSERVED});
  const MATOMO = "4cc2fa000b20f3c11eb0138fa782de89a3e5485e";
  const FINGERPRINT = "0d41a591f82b1f132c029a9a3e9d2ac8dfd9c524";
  const PREBID = "0f7916bfd975b82a185e9677d8196d94b2ea4dcc";

  const CATALOG = freeze([
    {
      id: "ga4-query", family: "google-tags", category: "fp-trackers", stage: "collection",
      conditions: {
        methods: ["get", "post"], resourceTypes: COLLECT, path: "/[^?#]*",
        query: [{key: "v", valuePattern: "2"}, {key: "tid", valuePattern: "G-[A-Z0-9]{4,16}"}],
      },
      sourceRefs: [
        source("https://developers.google.com/tag-platform/learn/sst-fundamentals/6-testing"),
        source("https://developers.google.com/static/tag-platform/learn/images/incoming-request.png"),
        source("https://developers.google.com/tag-platform/tag-manager/server-side/send-data"),
      ],
      limitations: ["Literal v/tid query fields only; renamed, encoded, and body-only fields are not recognized.",
        "The 4–16 uppercase-alphanumeric ID suffix is a conservative policy bound, not a universal vendor guarantee.",
        "Matching fields do not prove every request is tracking; the existing category and site controls apply."],
    },
    {
      id: "gtm-loader-query", family: "google-tags", category: "fp-trackers", stage: "loader",
      conditions: {
        methods: ["get"], resourceTypes: ["script"], path: "/[^?#]*",
        query: [{key: "id", valuePattern: "GTM-[A-Z0-9]{4,16}"}],
      },
      sourceRefs: [source("https://developers.google.com/tag-platform/tag-manager/datalayer"),
        source("https://developers.google.com/tag-platform/tag-manager/server-side/send-data")],
      limitations: ["Bundled or encoded loaders without the literal ID field are not recognized.",
        "GTM can deploy functional code as well as trackers; blocking may require a scoped site repair.",
        "The 4–16 uppercase-alphanumeric suffix is a conservative policy bound."],
    },
    {
      id: "meta-pixel-query", family: "meta", category: "fp-trackers", stage: "collection",
      conditions: {
        methods: ["get", "post"], resourceTypes: COLLECT, path: "/tr/?",
        query: [{key: "id", valuePattern: "[0-9]{5,}"},
          {key: "ev", valuePattern: "(?:PageView|ViewContent|AddToCart|Purchase)"}],
      },
      sourceRefs: [source("https://developers.facebook.com/documentation/meta-pixel/get-started"),
        source("https://developers.facebook.com/documentation/meta-pixel/advanced")],
      limitations: ["Only four documented standard events and the exact /tr endpoint are recognized here.",
        "Other events retain whatever protection the existing lists and hand rules provide.",
        "The source examples are image GETs; the same exact URL signature is also rejected for XHR/ping GET or POST.",
        "The numeric ID has a conservative five-digit minimum and no invented maximum; renamed endpoints and body-only conversion APIs are outside scope."],
    },
    {
      id: "matomo-visitor-query", family: "matomo", category: "fp-trackers", stage: "collection",
      conditions: {
        methods: ["get", "post"], resourceTypes: COLLECT, path: "/[^?#]*",
        query: [{key: "idsite", valuePattern: "[1-9][0-9]*"}, {key: "rec", valuePattern: "1"},
          {key: "_id", valuePattern: "[0-9a-f]{16}"}],
      },
      sourceRefs: [source(`https://github.com/matomo-org/matomo/blob/${MATOMO}/js/piwik.js`, MATOMO),
        source("https://developer.matomo.org/api-reference/tracking-api")],
      limitations: ["Requires the SDK's 16-hex visitor field in addition to idsite/rec; those two generic fields alone do not match.",
        "Forced/bulk POST payloads on arbitrary custom routes are opaque to DNR.",
        "No apiv requirement is invented: this source revision does not add it by default."],
    },
    {
      id: "matomo-image-query", family: "matomo", category: "fp-trackers", stage: "collection",
      conditions: {
        methods: ["get"], resourceTypes: ["image"], path: "/[^?#]*",
        query: [{key: "idsite", valuePattern: "[1-9][0-9]*"}, {key: "rec", valuePattern: "1"},
          {key: "send_image", valuePattern: "1"}],
      },
      sourceRefs: [source(`https://github.com/matomo-org/matomo/blob/${MATOMO}/js/piwik.js`, MATOMO),
        source("https://developer.matomo.org/api-reference/tracking-api")],
      limitations: ["Recognizes the image transport even when its optional visitor ID is absent.",
        "Requires literal idsite/rec/send_image fields and GET/image; bare idsite/rec is insufficient.",
        "No body inspection or broader XHR/POST rule is inferred from the image flag."],
    },
    {
      id: "fingerprint-pro-v3-loader", family: "fingerprint-pro", category: "fp-trackers", stage: "loader",
      conditions: {
        methods: ["get"], resourceTypes: ["script"], path: "/[^?#]*",
        query: [{key: "apiKey", valuePattern: "[A-Za-z0-9]{10,}"}, {key: "version", valuePattern: "3"},
          {key: "loaderVersion", valuePattern: "[0-9]+(?:\\.[0-9]+)*"}],
      },
      sourceRefs: [source(`https://github.com/fingerprintjs/cloudflare-worker-proxy/blob/${FINGERPRINT}/CHANGELOG.md`, FINGERPRINT)],
      limitations: ["Recognizes the maintained integration's legacy v3 query protocol, not v4 or all fingerprinting.",
        "A public API-key-like token is required; other encodings and key formats are outside this predicate.",
        "Fingerprinting can be used for fraud prevention, so blocking may affect login or commerce flows.",
        "Existing replay-category rules remain independently enabled; this is additional fp-trackers coverage."],
    },
    {
      id: "prebid-user-sync-query", family: "prebid", category: "fp-trackers", stage: "identity-sync",
      conditions: {
        methods: ["get"], resourceTypes: ["image", "sub_frame"], path: "/setuid", queryMode: "singleton-identity",
        query: [{key: "bidder", valuePattern: "[a-z][a-z0-9_-]*"},
          {key: "uid", valuePattern: "[A-Za-z0-9][A-Za-z0-9_-]+"}],
        optionalQueryKeys: ["gdpr", "gdpr_consent", "gpp", "gpp_sid", "account", "f"],
        optionalQueryLayout: "one-contiguous-group", allowExtraQueryFields: false,
      },
      sourceRefs: [source(`https://github.com/prebid/prebid-server/blob/${PREBID}/endpoints/setuid.go`, PREBID),
        source(`https://github.com/prebid/prebid-server/blob/${PREBID}/usersync/cookie.go`, PREBID),
        source("https://docs.prebid.org/prebid-server/endpoints/pbs-endpoint-setuid.html")],
      limitations: ["Only literal singleton bidder/uid fields and a contiguous group of approved optional keys match.",
        "Missing/empty uid deletes a sync in the server; duplicate identity fields, encoded/unknown keys, and empty segments decline this signature.",
        "Single-character IDs, including 0, and negative/encoded values, including -1, remain outside this conservative token grammar.",
        "Optional fields spread around both identities, other transports, renamed endpoints, and server-to-server operations remain outside scope."],
    },
  ]);

  function permutations(indices) {
    if (!indices.length) return [[]];
    return indices.flatMap((index, at) => permutations(indices.filter((_, i) => i !== at)).map((tail) => [index, ...tail]));
  }

  function patterns(entry) {
    const {path, query} = entry.conditions;
    if (entry.conditions.queryMode === "singleton-identity") return singletonIdentityPatterns(entry);
    if (!query.length) return [`${ORIGIN}${path}(?:[?#]|$)`];
    const prefix = `${path === "/[^?#]*" ? ANY_HTTP_QUERY : `${ORIGIN}${path}\\?`}${SKIP_FIELDS}`;
    const orders = permutations(query.map((_, i) => i));
    // Separate order alternatives keep every individual regex below Chrome's compiled-memory limit.
    // Do not widen a value predicate, omit a required field, or use an allow rule to save regex slots.
    return orders.map((order) => `${prefix}${order.map((index) => `${query[index].key}=${query[index].valuePattern}`).join(`&${SKIP_FIELDS}`)}${FIELD_END}`);
  }

  function singletonIdentityPatterns(entry) {
    const {path, query, optionalQueryKeys} = entry.conditions;
    const prefix = `${ORIGIN}${path}\\?`;
    const optional = `(?:${optionalQueryKeys.join("|")})=[^&#]*`;
    // Go's query.Get uses the first decoded key. Reusing SKIP_FIELDS here could skip an earlier
    // empty uid (a deletion) and match a later nonempty uid. A full-query allowlist rejects every
    // duplicate or encoded identity key, rather than adding an allow rule with broader authority.
    // One optional-key group per pattern also keeps each program inside Chrome's RE2 memory cap.
    return permutations(query.map((_, i) => i)).flatMap((order) => {
      const fields = order.map((index) => `${query[index].key}=${query[index].valuePattern}`);
      return [
        `${prefix}(?:${optional}&)*${fields[0]}&${fields[1]}(?:#|$)`,
        `${prefix}${fields[0]}&(?:${optional}&)*${fields[1]}(?:#|$)`,
        `${prefix}${fields[0]}&${fields[1]}(?:&${optional})*(?:#|$)`,
      ];
    });
  }

  function positiveInteger(value, name) {
    if (!Number.isInteger(value) || value < 1 || value > MAX_INTEGER) throw new TypeError(`Invalid protocol ${name}`);
    return value;
  }

  function compile(options = {}) {
    if (!options || typeof options !== "object" || Array.isArray(options)) throw new TypeError("Invalid protocol compiler options");
    const firstId = positiveInteger(options.firstId === undefined ? 1 : options.firstId, "firstId");
    const priority = positiveInteger(options.priority === undefined ? 6 : options.priority, "priority");
    const rules = [];
    for (const entry of CATALOG) {
      for (const regexFilter of patterns(entry)) {
        rules.push({id: firstId + rules.length, priority, action: {type: "block"}, condition: {
          regexFilter, isUrlFilterCaseSensitive: true,
          requestMethods: [...entry.conditions.methods], resourceTypes: [...entry.conditions.resourceTypes],
        }});
      }
    }
    if (rules.length > MAX_RULES || firstId + rules.length - 1 > MAX_INTEGER) throw new RangeError("Protocol rule budget exceeded");
    return {rules, stats: {schema: SCHEMA, families: new Set(CATALOG.map((entry) => entry.family)).size,
      signatures: CATALOG.length, regexRules: rules.length, querySignatures: CATALOG.filter((entry) => entry.conditions.query.length).length,
      pathSignatures: CATALOG.filter((entry) => !entry.conditions.query.length).length}, catalog: CATALOG};
  }

  const api = Object.freeze({SCHEMA, MAX_RULES, CATALOG, compile});
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.EGTrackingProtocols = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
