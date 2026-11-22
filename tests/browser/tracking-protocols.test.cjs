"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const protocols = require("../../browser/core/tracking-protocols.js");

// A narrow offline model of the emitted condition types. Native Chrome qualification remains separate.
const compiled = protocols.compile();
function blocked(url, type = "xmlhttprequest", method = "get") {
  let canonical;
  try { canonical = new URL(url); } catch { return false; }
  canonical.hash = ""; // A fragment is not transmitted to the HTTP server.
  return compiled.rules.some((rule) => rule.condition.resourceTypes.includes(type) &&
    rule.condition.requestMethods.includes(method) &&
    new RegExp(rule.condition.regexFilter, rule.condition.isUrlFilterCaseSensitive ? "" : "i").test(canonical.href));
}
function orders(items) {
  return items.length === 1 ? [items] : items.flatMap((head, index) =>
    orders(items.filter((_, i) => i !== index)).map((tail) => [head, ...tail]));
}
function noisyQueries(fields) {
  return orders(fields).flatMap((order) => [order.join("&"),
    `cache=fixture&${order.join("&region=fixture&")}&nonce=fixture`]);
}

test("compiler emits only bounded static blocks with explicit methods/types and independent output", () => {
  const a = protocols.compile({firstId: 200, priority: 6});
  const b = protocols.compile({firstId: 200, priority: 6});
  assert.deepEqual(a, b);
  assert.equal(a.rules.length, 29);
  assert.equal(a.stats.families, 5);
  assert.equal(a.stats.signatures, 7);
  assert.equal(a.stats.regexRules, a.rules.length);
  assert.deepEqual(a.rules.map((r) => r.id), Array.from({length: 29}, (_, i) => 200 + i));
  for (const rule of a.rules) {
    assert.equal(rule.priority, 6);
    assert.deepEqual(rule.action, {type: "block"});
    assert.equal(rule.condition.isUrlFilterCaseSensitive, true);
    assert.ok(rule.condition.regexFilter.startsWith("^https?://"));
    assert.ok(rule.condition.requestMethods.length && rule.condition.resourceTypes.length);
    assert.ok(!rule.condition.resourceTypes.includes("main_frame"));
    if (rule.condition.resourceTypes.includes("sub_frame")) {
      assert.ok(rule.condition.regexFilter.includes("/setuid\\?"), "only exact user-sync frames are in scope");
    }
    assert.ok(!("domainType" in rule.condition), "same-site collection remains in scope");
    assert.ok(!("tabIds" in rule.condition), "static rules carry no session authority");
  }
  a.rules[0].action.type = "allow";
  a.rules[0].condition.resourceTypes.push("main_frame");
  assert.deepEqual(protocols.compile({firstId: 200, priority: 6}), b, "returned rules cannot mutate future builds");
});

test("invalid allocation or priority fails before emitting any authority", () => {
  for (const firstId of [0, -1, NaN, Infinity, 1.5, "1", 2147483648]) {
    assert.throws(() => protocols.compile({firstId}), /Invalid protocol firstId/);
  }
  for (const priority of [0, -1, NaN, Infinity, 1.5, "6", 2147483648]) {
    assert.throws(() => protocols.compile({priority}), /Invalid protocol priority/);
  }
  assert.throws(() => protocols.compile({firstId: 2147483647}), /budget/);
  assert.equal(protocols.compile({firstId: 2147483619}).rules.at(-1).id, 2147483647);
  for (const options of [null, [], 1, "test"]) assert.throws(() => protocols.compile(options));
});

test("catalog and provenance are immutable and each signature names its visibility limit", () => {
  assert.ok(Object.isFrozen(protocols.CATALOG));
  for (const item of protocols.CATALOG) {
    assert.equal(item.category, "fp-trackers");
    assert.ok(item.sourceRefs.length && item.limitations.length);
    assert.ok(item.sourceRefs.every((ref) => ref.url.startsWith("https://") && ref.observed === "2026-11-22"));
    assert.throws(() => item.conditions.query.push({key: "anything", valuePattern: ".*"}), TypeError);
    assert.throws(() => { item.conditions.methods[0] = "delete"; }, TypeError);
  }
  const pinned = protocols.CATALOG.flatMap((item) => item.sourceRefs).filter((ref) => ref.revision);
  assert.equal(pinned.length, 5);
  assert.ok(pinned.every((ref) => /^[0-9a-f]{40}$/.test(ref.revision) && ref.url.includes(ref.revision)));
});

test("same pure module loads in a browser-style realm without APIs or IO", () => {
  const source = fs.readFileSync(path.join(__dirname, "../../browser/core/tracking-protocols.js"), "utf8");
  const context = vm.createContext({});
  vm.runInContext(source, context);
  const actual = vm.runInContext("JSON.stringify(EGTrackingProtocols.compile({firstId: 9, priority: 6}))", context);
  assert.deepEqual(JSON.parse(actual), protocols.compile({firstId: 9, priority: 6}));
  assert.deepEqual(Object.keys(context), ["EGTrackingProtocols"]);
});

test("GA4 recognizes required literal fields in either order on arbitrary same-origin paths", () => {
  for (const query of noisyQueries(["v=2", "tid=G-12345678"])) {
    for (const type of ["image", "xmlhttprequest", "ping"]) {
      for (const method of ["get", "post"]) {
        assert.equal(blocked(`https://shop.example:8443/assets/rpc?${query}`, type, method), true, `${query} ${type} ${method}`);
      }
    }
  }
  assert.equal(blocked("http://shop.example/measure?tid=G-ABCD&v=2"), true);
  assert.equal(blocked("https://shop.example/?v=2&tid=G-ABCDEFGHIJKLMNOP"), true);
});

test("GA4 near-neighbors, unsupported transports, and identifier boundaries stay outside the new catalog", () => {
  for (const query of ["v=20&tid=G-12345678", "v=2x&tid=G-12345678", "v=1&tid=G-12345678",
    "xv=2&tid=G-12345678", "v=2&xtid=G-12345678", "v=2&tid=ORDER-12345678",
    "v=2&tid=G-abc12345", "v=2&tid=G-ABC", "v=2&tid=G-ABCDEFGHIJKLMNOPQ",
    "v=2;tid=G-12345678", "V=2&tid=G-12345678", "v=2&TID=G-12345678",
    "v=2&tid=G-12345678-extra", "v=2&tid=G-12345678%20"]) {
    assert.equal(blocked(`https://shop.example/rpc?${query}`), false, query);
  }
  for (const type of ["main_frame", "sub_frame", "script", "stylesheet", "websocket", "other"]) {
    assert.equal(blocked("https://shop.example/rpc?v=2&tid=G-12345678", type), false, type);
  }
  for (const method of ["put", "delete", "head", "options"]) {
    assert.equal(blocked("https://shop.example/rpc?v=2&tid=G-12345678", "xmlhttprequest", method), false, method);
  }
  assert.equal(blocked("wss://shop.example/rpc?v=2&tid=G-12345678", "xmlhttprequest"), false);
});

test("GTM loader handles a custom queue and extensionless path while respecting ID and type bounds", () => {
  for (const query of ["id=GTM-ABC123", "l=privateQueue&id=GTM-ABC123", "cache=1&id=GTM-ABC123&l=privateQueue"]) {
    assert.equal(blocked(`https://shop.example/assets/container?${query}`, "script"), true);
    assert.equal(blocked(`https://shop.example/assets/container?${query}`, "image"), false);
    assert.equal(blocked(`https://shop.example/assets/container?${query}`, "script", "post"), false);
  }
  for (const query of ["id=GTM-ABC", "id=GTM-ABCDEFGHIJKLMNOPQ", "id=gtm-ABC123", "id=GTM-abc123",
    "id=SKU-GTM-ABC123", "custom_id=GTM-ABC123", "id=GTM-ABC123.js", "id=GTM-ABC123%00"]) {
    assert.equal(blocked(`https://shop.example/assets/container?${query}`, "script"), false, query);
  }
});

test("Meta exact endpoint and four known events survive reordering and extra fields", () => {
  for (const event of ["PageView", "ViewContent", "AddToCart", "Purchase"]) {
    for (const query of noisyQueries(["id=123456789012345", `ev=${event}`])) {
      for (const endpoint of ["/tr", "/tr/"]) assert.equal(blocked(`https://shop.example${endpoint}?${query}`, "image"), true);
    }
  }
  assert.equal(blocked("https://shop.example/tr?ev=PageView&id=12345", "image"), true, "official fictitious five-digit example fits");
  assert.equal(blocked(`https://shop.example/tr?ev=PageView&id=${"1".repeat(100)}`, "image"), true, "no unsupported maximum ID length is invented");
});

test("Meta does not turn an ordinary event name or a neighboring endpoint into a pixel", () => {
  for (const endpoint of ["/tr/status", "/other/tr", "/translator", "/TR", "/tr//", "/tr%2F"]) {
    assert.equal(blocked(`https://shop.example${endpoint}?ev=Purchase&id=123456789012345`, "image"), false, endpoint);
  }
  for (const query of ["ev=Translate&id=123456789012345", "ev=Purchase&id=order-12345", "ev=Purchase&id=1234",
    "ev=pageview&id=123456789012345", "ev=PageViewMore&id=123456789012345", "ev=PageView&id=12345a",
    "ev=PageView&pixel_id=123456789012345", "event=PageView&id=123456789012345"]) {
    assert.equal(blocked(`https://shop.example/tr?${query}`, "image"), false, query);
  }
  assert.equal(blocked("https://shop.example/tr?id=123456789012345&ev=PageView", "main_frame"), false);
});

test("Matomo requires all three distinct visitor-query fields in every order", () => {
  for (const query of noisyQueries(["idsite=17", "rec=1", "_id=0123456789abcdef"])) {
    assert.equal(blocked(`https://shop.example/visit?${query}`, "image"), true, query);
    assert.equal(blocked(`https://shop.example/visit?${query}`, "ping", "post"), true, query);
  }
  for (const query of ["idsite=17&rec=0&_id=0123456789abcdef", "idsite=0&rec=1&_id=0123456789abcdef",
    "idsite=-1&rec=1&_id=0123456789abcdef", "idsite=17&rec=1&_id=order-42", "idsite=17&rec=1&_id=0123456789abcde",
    "idsite=17&rec=1&_id=0123456789abcdef0", "idsite=17&rec=1&_id=0123456789abcdeg",
    "idsite=17&rec=1&user_id=0123456789abcdef", "rec=1&_id=0123456789abcdef"]) {
    assert.equal(blocked(`https://shop.example/visit?${query}`, "image"), false, query);
  }
});

test("Matomo optional-identity image collection requires GET/image and all transport markers", () => {
  for (const query of noisyQueries(["idsite=17", "rec=1", "send_image=1"])) {
    assert.equal(blocked(`https://shop.example/visit?${query}`, "image", "get"), true, query);
    assert.equal(blocked(`https://shop.example/visit?${query}`, "image", "post"), false, `POST ${query}`);
    assert.equal(blocked(`https://shop.example/visit?${query}`, "xmlhttprequest", "get"), false, `XHR ${query}`);
    assert.equal(blocked(`https://shop.example/visit?${query}`, "ping", "post"), false, `beacon ${query}`);
  }
  for (const query of ["idsite=17&rec=0&send_image=1", "idsite=17&rec=1&send_image=0",
    "idsite=17&rec=1&send_image=10", "idsite=17&rec=1&send_image=true", "idsite=17&rec=1&send_image=1x",
    "idsite=0&rec=1&send_image=1", "rec=1&send_image=1", "idsite=17&send_image=1", "idsite=17&rec=1",
    "idsite=17&rec=1&%73end_image=1", "idsite=17&rec=1&send_image=%31"]) {
    assert.equal(blocked(`https://shop.example/visit?${query}`, "image"), false, query);
  }
});

test("Fingerprint Pro v3 keeps all three markers with six orders and does not guess v4", () => {
  for (const query of noisyQueries(["apiKey=public123456789", "version=3", "loaderVersion=3.12.3"])) {
    assert.equal(blocked(`https://shop.example/identity/agent?${query}`, "script"), true, query);
  }
  for (const query of ["version=3&loaderVersion=3.12.3", "apiKey=short&version=3&loaderVersion=3.12.3",
    "apiKey=public123456789&version=2&loaderVersion=3.12.3", "apiKey=public123456789&version=4&loaderVersion=3.12.3",
    "apiKey=public123456789&version=3&loaderVersion=", "apiKey=public123456789&version=3&loaderVersion=3.x",
    "apiKey=public123456789&version=3&loaderVersion=3.12.", "apikey=public123456789&version=3&loaderVersion=3.12.3",
    "apiKey=public_123456789&version=3&loaderVersion=3.12.3"]) {
    assert.equal(blocked(`https://shop.example/identity/agent?${query}`, "script"), false, query);
  }
  assert.equal(blocked("https://shop.example/identity/?region=eu", "xmlhttprequest", "post"), false);
  assert.equal(blocked("https://shop.example/identity/agent?apiKey=public123456789&version=3&loaderVersion=3.12.3", "image"), false);
});

test("tracker-shaped strings inside a value, path, or fragment are not separate endpoints", () => {
  const fixtures = [
    ["https://collector.example/measure?v=2&tid=G-12345678", "xmlhttprequest"],
    ["https://collector.example/loader?id=GTM-ABC123", "script"],
    ["https://collector.example/tr/?id=123456789012345&ev=PageView", "image"],
    ["https://collector.example/visit?idsite=17&rec=1&_id=0123456789abcdef", "image"],
    ["https://collector.example/agent?apiKey=public123456789&version=3&loaderVersion=3.12.3", "script"],
    ["https://collector.example/setuid?bidder=pubmatic&uid=buyer12345", "image"],
  ];
  for (const [inner, type] of fixtures) {
    for (const url of [`https://shop.example/render?next=${encodeURIComponent(inner)}`, `https://shop.example/render?next=${inner}`,
      `https://shop.example/render#${inner}`, `https://shop.example/render/${encodeURIComponent(inner)}`]) {
      assert.equal(blocked(url, type), false, url);
    }
  }
});

test("encoded field names and opaque payloads remain explicit unrecognized cases", () => {
  for (const [url, type] of [
    ["https://shop.example/measure?%76=2&tid=G-12345678", "xmlhttprequest"],
    ["https://shop.example/loader?%69d=GTM-ABC123", "script"],
    ["https://shop.example/tr?%69d=123456789012345&ev=PageView", "image"],
    ["https://shop.example/visit?idsite=17&rec=1&%5Fid=0123456789abcdef", "image"],
    ["https://shop.example/agent?api%4Bey=public123456789&version=3&loaderVersion=3.12.3", "script"],
  ]) assert.equal(blocked(url, type), false, url);
  for (const endpoint of ["/rpc", "/visit", "/e/", "/api/events", "/collect", "/upload", "/v1/t"]) {
    assert.equal(blocked(`https://shop.example${endpoint}`, "xmlhttprequest", "post"), false, endpoint);
  }
});

test("presence matching makes no unsupported claim about duplicate-field server semantics", () => {
  assert.equal(blocked("https://shop.example/measure?v=9&v=2&tid=G-12345678"), true);
  assert.equal(blocked("https://shop.example/measure?v=2&tid=G-12345678&v=9"), true);
  assert.equal(blocked("https://shop.example/measure?v=9&v=20&tid=G-12345678"), false);
});

test("Prebid new-identity sync uses an exact endpoint, supported transports, and a complete query envelope", () => {
  assert.equal(blocked("https://shop.example/setuid?bidder=pubmatic&uid=123", "image"), true,
    "the pinned server's first successful setuid test uses this bidder and UID shape");
  const optional = "gdpr=0&gdpr_consent=fixture&gpp=fixture&gpp_sid=2&account=publisher&f=i";
  for (const [first, second] of orders(["bidder=pubmatic", "uid=buyer-12345"])) {
    for (const query of [`${first}&${second}`, `${optional}&${first}&${second}`,
      `${first}&${optional}&${second}`, `${first}&${second}&${optional}`]) {
      assert.equal(blocked(`https://shop.example/setuid?${query}`, "image"), true, query);
      assert.equal(blocked(`https://shop.example/setuid?${query}`, "sub_frame"), true, query);
      assert.equal(blocked(`https://shop.example/setuid?${query}`, "main_frame"), false, `navigation ${query}`);
      assert.equal(blocked(`https://shop.example/setuid?${query}`, "xmlhttprequest"), false, `XHR ${query}`);
      assert.equal(blocked(`https://shop.example/setuid?${query}`, "image", "post"), false, `POST ${query}`);
    }
  }
  assert.equal(blocked("https://shop.example/setuid?bidder=pubmatic&uid=buyer12345&gdpr_consent=x%26uid%3D", "image"), true,
    "encoded text in an optional value does not become a second identity key");
});

test("Prebid missing, empty, single-character, and negative identities never match a new-ID rule", () => {
  for (const query of ["bidder=pubmatic", "bidder=pubmatic&uid", "bidder=pubmatic&uid=", "uid=&bidder=pubmatic",
    "uid=&gdpr=0&bidder=pubmatic", "bidder=pubmatic&uid=&f=i", "bidder=pubmatic&uid=0", "bidder=pubmatic&uid=-1",
    "bidder=pubmatic&uid=%30", "bidder=pubmatic&uid=%2D1", "bidder=pubmatic&uid=%20", "bidder=pubmatic&uid=+",
    "uid=buyer12345", "bidder=&uid=buyer12345", "bidder=pubmatic&uid=a", "bidder=pubmatic&uid=buyer;uid="]) {
    assert.equal(blocked(`https://shop.example/setuid?${query}`, "image"), false, query);
    assert.equal(blocked(`https://shop.example/setuid?${query}`, "sub_frame"), false, query);
  }
});

test("Prebid refuses duplicate and encoded identity keys in every position, including first-empty deletion", () => {
  const identity = ["bidder=pubmatic", "uid=buyer12345"];
  const ambiguous = ["uid=", "uid=other12345", "uid=0", "uid=-1", "bidder=", "bidder=other",
    "%75id=", "u%69d=", "ui%64=", "%75%69%64=", "%75id=another123",
    "%62idder=pubmatic", "b%69dder=pubmatic", "bidde%72=pubmatic"];
  for (const pair of orders(identity)) {
    for (const extra of ambiguous) {
      for (let where = 0; where <= pair.length; where++) {
        const fields = [...pair]; fields.splice(where, 0, extra);
        const query = fields.join("&");
        assert.equal(blocked(`https://shop.example/setuid?${query}`, "image"), false, query);
      }
    }
  }
});

test("Prebid unknown/encoded keys, privacy-control requests, and unsupported query layouts decline", () => {
  for (const query of ["bidder=pubmatic&uid=buyer12345&optout=1", "bidder=pubmatic&uid=buyer12345&delete=true",
    "bidder=pubmatic&uid=buyer12345&privacy=deny", "bidder=pubmatic&uid=buyer12345&unknown=x",
    "bidder=pubmatic&uid=buyer12345&%66=i", "bidder=pubmatic&uid=buyer12345&GDPR=0",
    "bidder=pubmatic&uid=buyer12345&", "&bidder=pubmatic&uid=buyer12345", "bidder=pubmatic&&uid=buyer12345",
    "f=i&bidder=pubmatic&uid=buyer12345&gdpr=0", "bidder=pubmatic&f=i&uid=buyer12345&gdpr=0"]) {
    assert.equal(blocked(`https://shop.example/setuid?${query}`, "image"), false, query);
  }
  for (const endpoint of ["/setuid/", "/setuid/status", "/api/setuid", "/SETUID", "/cookie_sync", "/rpc"]) {
    assert.equal(blocked(`https://shop.example${endpoint}?bidder=pubmatic&uid=buyer12345`, "image"), false, endpoint);
  }
});
