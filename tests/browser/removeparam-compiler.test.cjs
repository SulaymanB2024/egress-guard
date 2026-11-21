"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {compileRemoveParams, presentRegex, labelPrefixComplement, partition} = require("../../scripts/lib/removeparam-compiler.cjs");
const params = require("../../browser/core/params.js");
const policy = require("../../browser/core/param-policy.js");

// A narrow deterministic model of this compiler's predicates and transforms.
// This does not claim Chrome has accepted a regex or executed a redirect.
function matching(rules, address, {type = "main_frame", method = "get"} = {}) {
  const url = new URL(address), host = url.hostname.toLowerCase().replace(/\.$/, "");
  return rules.filter(({condition: c}) => c.resourceTypes.includes(type) && c.requestMethods.includes(method) &&
    (!c.requestDomains || policy.covers(host, c.requestDomains)) && (!c.excludedRequestDomains || !policy.covers(host, c.excludedRequestDomains)) &&
    new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive ? "" : "i").test(url.href));
}
function navigation(result, address, reverse = false) {
  let url = address, hops = 0;
  while (hops < 30) {
    const matches = matching(result.rules, url);
    if (matches.some((r) => r.action.type === "allow")) return {url, hops};
    const choices = matches.filter((r) => r.action.type === "redirect");
    if (!choices.length) return {url, hops};
    const rule = reverse ? choices.at(-1) : choices[0], redirect = rule.action.redirect;
    let next;
    if (redirect.transform) {
      const u = new URL(url), removals = new Set(redirect.transform.queryTransform.removeParams.map((name) => encodeURIComponent(name).replace(/%20/g, "+")));
      const raw = u.search.slice(1).split("&"), kept = [];
      for (const part of raw) {
        const equal = part.indexOf("="), key = equal < 0 ? part : part.slice(0, equal), value = equal < 0 ? "" : part.slice(equal + 1);
        if (!removals.has(key)) kept.push(key + "=" + value);
      }
      u.search = kept.length ? "?" + kept.join("&") : ""; next = u.href;
    } else next = new URL(url.replace(new RegExp(rule.condition.regexFilter), redirect.regexSubstitution.replace(/\\([0-9])/g, "$$$1"))).href;
    assert.notEqual(next, url, "every modeled transform must make progress");
    url = next; hops++;
  }
  assert.fail("modeled parameter transforms did not converge");
}
const clean = (result, url) => params.clean(url, {data: result.data}).url;

test("maintained literal destination rules add real removals with main-frame GET predicates", () => {
  const result = compileRemoveParams("$removeparam=vendor_click\n||news.example^$removeparam=publisher_visitor\n$removeparam=shared_click,to=shop.example|news.example\n");
  assert.equal(result.stats.importedRules, 3);
  assert.equal(result.coverage.reduced, false);
  const input = "https://sub.news.example/read?vendor_click=123&publisher_visitor=456&shared_click=789&q=hello%2Bworld";
  for (const reverse of [false, true]) assert.equal(navigation(result, input, reverse).url, "https://sub.news.example/read?q=hello%2Bworld");
  assert.equal(clean(result, input), "https://sub.news.example/read?q=hello%2Bworld");
  assert.equal(clean(result, "https://elsewhere.example/?publisher_visitor=123&shared_click=456"), "https://elsewhere.example/?publisher_visitor=123&shared_click=456");
  for (const rule of result.rules) {
    assert.equal(rule.priority, 9); assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]); assert.deepEqual(rule.condition.requestMethods, ["get"]);
  }
  assert.equal(matching(result.rules, input, {type: "sub_frame"}).length, 0);
  assert.equal(matching(result.rules, input, {method: "post"}).length, 0);
});

test("named and all-name exceptions restrict legacy overlap without emitting source allows", () => {
  const result = compileRemoveParams("$removeparam=vendor_click\n@@||publisher.example/news/$removeparam=utm_source\n@@||account.example/confirm$removeparam\n@@||amazon.com/cart/$removeparam=ref\n");
  assert.equal(result.stats.coarsenedExceptions, 3);
  assert.equal(result.rules.filter((r) => r.action.type === "allow").length, params.PRESERVE_URL_REGEXES.length);
  for (const url of ["https://publisher.example/other?utm_source=keep", "https://account.example/other?utm_source=keep&vendor_click=keep", "https://amazon.com/dp/item?ref=keep"]) {
    assert.equal(clean(result, url), url); assert.equal(navigation(result, url).url, url);
  }
  assert.equal(clean(result, "https://publisher.example/read?utm_source=keep&vendor_click=remove"), "https://publisher.example/read?utm_source=keep");
  assert.equal(clean(result, "https://other.example/read?utm_source=remove&vendor_click=remove"), "https://other.example/read");
});

test("negative destination conditions cannot be undone by legacy GLOBAL or SCOPED", () => {
  const result = compileRemoveParams("$removeparam=utm_source,to=~links.example\n$removeparam=ref,to=amazon.com|~checkout.amazon.com\n");
  for (const address of ["https://sub.links.example/?utm_source=keep", "https://checkout.amazon.com/?ref=keep"]) {
    assert.equal(clean(result, address), address); assert.equal(navigation(result, address).url, address);
  }
  assert.equal(clean(result, "https://amazon.com/?ref=remove&utm_source=remove"), "https://amazon.com/");
});

test("coarse entity exceptions cover deceptive labels and preserve unrelated keys", () => {
  const result = compileRemoveParams("$removeparam=utm_source\n$removeparam=vendor_click\n@@||login.aliexpress.*/sync_cookie$removeparam=utm_source\n");
  for (const host of ["aliexpress.com", "login.aliexpress.co.uk", "aliexpress.example.org", "x.aliexpress.example", "ALiexpress.Example", "aliexpress.example.", "aliexpressx.example", "aliexpress-example.org", "alibaba.example", "alice.example"]) {
    const input = `https://${host}/read?utm_source=keep&vendor_click=remove`;
    assert.equal(new URL(clean(result, input)).search, "?utm_source=keep", host);
    assert.equal(new URL(navigation(result, input).url).search, "?utm_source=keep", host);
  }
  for (const host of ["notaliexpress.example", "example.com"]) {
    assert.equal(clean(result, `https://${host}/?utm_source=remove`), `https://${host}/`);
    assert.equal(navigation(result, `https://${host}/?utm_source=remove`).url, `https://${host}/`);
  }
});

test("entity prefix complements keep exact and longer prefixes, ports and trailing-dot forms", () => {
  const result = compileRemoveParams("$removeparam=utm_campaign\n@@||google.*/maps^$removeparam=utm_campaign\n");
  assert.deepEqual(result.stats.coarsenedEntityPrefixes, [{label: "google", prefix: "goo"}]);
  for (const host of ["google.com", "good.example", "x.goo.example", "goo.example:8443", "google.com.", "google.com.:8443"]) {
    const input = `https://${host}/article?utm_campaign=keep&fbclid=remove`;
    assert.equal(new URL(clean(result, input)).search, "?utm_campaign=keep", host);
    assert.equal(new URL(navigation(result, input).url).search, "?utm_campaign=keep", host);
  }
  const re = new RegExp("^(?:" + labelPrefixComplement(["goo"]) + ")$");
  for (const label of ["g", "go", "good", "google", "agoog", "x", "google:443", "good:443"]) assert.equal(re.test(label), !label.startsWith("goo"), label);
  const hyphenated = compileRemoveParams("$removeparam=click\n@@||ad-server.*/$removeparam=click\n");
  assert.equal(clean(hyphenated, "https://ad-other.example/?click=keep"), "https://ad-other.example/?click=keep");
});

test("positive-key proof is query-aware, case-sensitive and cannot match nested values or fragments", () => {
  const re = new RegExp(presentRegex(["vendor_click", "a.b", "bracket[0]"]));
  for (const url of ["https://site.example/?vendor_click=x", "https://site.example/?a=1&vendor_click=x&b=2", "https://site.example/?vendor_click", "https://site.example/?vendor_click=&vendor_click=x", "https://site.example/?a.b=1", "https://site.example/?bracket[0]=x"]) assert.ok(re.test(url), url);
  for (const url of ["https://site.example/path/vendor_click=x", "https://site.example/?next=https://target.example/?vendor_click=x", "https://site.example/?a=1#vendor_click=x", "https://site.example/?VENDOR_CLICK=x", "https://site.example/?notvendor_click=x", "https://site.example/?vendor_clicks=x", "https://site.example/?aXb=1"]) assert.equal(re.test(url), false, url);
});

test("no-op conditions do not starve another remover and redirect order converges", () => {
  const result = compileRemoveParams("$removeparam=absent_global\n||site.example^$removeparam=present_scoped\n$removeparam=conditional_click,to=~protected.example\n");
  const input = "https://site.example/?present_scoped=1&conditional_click=2&utm_source=3&data=4";
  for (const reverse of [false, true]) {
    const modeled = navigation(result, input, reverse);
    assert.equal(modeled.url, "https://site.example/?data=4"); assert.ok(modeled.hops <= 3);
  }
});

test("overlapping destination partitions preserve child exclusions and recovered descendants", () => {
  const groups = [
    {names: ["base"], include: [], exclude: ["example.com"]},
    {names: ["base"], include: ["restore.example.com"], exclude: ["off.restore.example.com"]},
    {names: ["second"], include: ["example.com"], exclude: ["restore.example.com"]},
    {names: ["second"], include: ["off.restore.example.com"], exclude: []},
    {names: ["special"], include: ["invalid.invalid"], exclude: []},
  ];
  const regions = partition(groups);
  for (const host of ["other.test", "example.com", "sub.example.com", "restore.example.com", "sub.restore.example.com", "off.restore.example.com", "sub.off.restore.example.com", "invalid.invalid"]) {
    const expected = new Set(groups.filter((g) => (!g.include.length || policy.covers(host, g.include)) && !policy.covers(host, g.exclude)).flatMap((g) => g.names));
    const actual = new Set(regions.filter((g) => (!g.include.length || policy.covers(host, g.include)) && !policy.covers(host, g.exclude)).flatMap((g) => g.names));
    assert.deepEqual(actual, expected, host);
  }
});

test("unsupported removers narrow coverage; malformed scoped arms cannot widen it", () => {
  const result = compileRemoveParams("$removeparam=vendor_click,to=valid.example|invalid.*\n$removeparam=initiator_click,domain=news.example\n||path.example/article/$removeparam=path_click\n$removeparam=/^private_/\n$removeparam\n||other.example^$removeheader=request:referer\nexample.test##.ad\n");
  assert.equal(result.stats.importedRules, 0); assert.equal(result.stats.unsupported, 5); assert.equal(result.stats.ignoredNonRemoval, 2);
  for (const host of ["valid.example", "invalid.com", "news.example", "path.example"]) assert.equal(clean(result, `https://${host}/article/?vendor_click=1&initiator_click=2&path_click=3&private_id=4`), `https://${host}/article/?vendor_click=1&initiator_click=2&path_click=3&private_id=4`);
});

test("URL end anchors and case-sensitive uppercase patterns cannot become whole-host removals", () => {
  const result = compileRemoveParams("||payments.example^|$removeparam=order_id\n||PAYMENTS.example^$removeparam=receipt_id,match-case\n");
  assert.equal(result.stats.importedRules, 0); assert.equal(result.stats.unsupported, 2);
  const input = "https://payments.example/orders?order_id=keep&receipt_id=keep";
  assert.equal(clean(result, input), input); assert.equal(navigation(result, input).url, input);
});

test("badfilter identities ignore option order and never become live removers", () => {
  const result = compileRemoveParams("||site.example^$removeparam=vendor_click,document\n||site.example^$document,badfilter,removeparam=vendor_click\n$removeparam=other_click\n");
  assert.equal(result.stats.badfiltered, 2); assert.equal(result.stats.importedRules, 1);
  assert.equal(clean(result, "https://site.example/?vendor_click=keep&other_click=remove"), "https://site.example/?vendor_click=keep");
  const legacy = compileRemoveParams("$removeparam=utm_source\n$removeparam=utm_source,badfilter\n||amazon.com^$removeparam=ref,badfilter\n");
  assert.deepEqual(legacy.stats.explicitlyDisabledNames, ["utm_source"]);
  const address = "https://amazon.com/?utm_source=keep&ref=keep";
  assert.equal(clean(legacy, address), address); assert.equal(navigation(legacy, address).url, address);
});

test("MV3 conditional branches suppress legacy overlap while retaining the active branch", () => {
  const result = compileRemoveParams("!#if !ext_ubol\n||amazon.*/dp/$removeparam=sr\n!#else\n$removeparam=active_click\n!#endif\n");
  assert.equal(result.stats.inactiveRows, 1); assert.equal(result.stats.compatibilityExclusions, 1);
  assert.equal(clean(result, "https://amazon.com/dp/item?sr=keep&active_click=remove"), "https://amazon.com/dp/item?sr=keep");
  assert.equal(navigation(result, "https://amazon.com/dp/item?sr=keep&active_click=remove").url, "https://amazon.com/dp/item?sr=keep");
});

test("unknown directives and unbounded exceptions fail explicitly and disable all cleaning in reduced mode", () => {
  for (const text of ["!#if future_flag\n$removeparam=click\n!#endif", "!#if ext_ubol\n$removeparam=click", "!#include remote.txt\n$removeparam=click", "@@/unbounded/path$removeparam\n$removeparam=click", "@@||scope.example^$removeparam=/^utm_/\n$removeparam=click"]) {
    assert.throws(() => compileRemoveParams(text), /explicit reduced build/);
    const result = compileRemoveParams(text, {allowReduced: true});
    assert.equal(result.coverage.disabled, true); assert.equal(result.coverage.reduced, true); assert.equal(result.rules.length, 0);
    const input = "https://amazon.com/product/ref=keep?utm_source=keep&click=keep";
    assert.equal(clean(result, input), input); assert.equal(result.stats.importedRules, 0);
  }
});

test("an unsupported named exception quarantines only that key, including overlapping legacy rules", () => {
  const source = "$removeparam=other_click\n@@/complex*path$removeparam=utm_source\n";
  assert.throws(() => compileRemoveParams(source), /quarantined:utm_source/);
  const result = compileRemoveParams(source, {allowReduced: true});
  assert.deepEqual(result.coverage.quarantined, ["utm_source"]); assert.equal(result.coverage.disabled, false);
  const input = "https://news.example/?utm_source=keep&other_click=remove&fbclid=remove";
  assert.equal(clean(result, input), "https://news.example/?utm_source=keep");
  assert.equal(navigation(result, input).url, "https://news.example/?utm_source=keep");
  assert.equal(result.rules.filter((r) => r.action.type === "allow").length, params.PRESERVE_URL_REGEXES.length);
});

test("first-party-only finite initiator exception safely bounds destination sites with private PSL", () => {
  const result = compileRemoveParams("$removeparam=click\n@@/embed/comments^$removeparam,~3p,domain=news.example.com|alice.github.io\n");
  for (const host of ["example.com", "other.example.com", "alice.github.io", "sub.alice.github.io"]) assert.equal(clean(result, `https://${host}/?utm_source=keep&click=keep`), `https://${host}/?utm_source=keep&click=keep`);
  assert.equal(clean(result, "https://bob.github.io/?utm_source=remove&click=remove"), "https://bob.github.io/");
  assert.equal(clean(result, "https://other.example/?click=remove"), "https://other.example/");
});

test("signature/auth brakes preserve whole addresses, KEPT survives, and ordinary search still cleans", () => {
  const result = compileRemoveParams("$removeparam=click\n$removeparam=token\n$removeparam=q\n$removeparam=mkt_tok\n");
  for (const input of ["https://files.example/file?X-Amz-Signature=xyz&click=keep", "https://cdn.example/file?sig=xyz&utm_source=keep", "https://app.example/cb?code=xyz&state=123&click=keep", "https://site.example/authentication/start?click=keep", "https://shop.example/checkout?utm_source=keep", "https://user:pass@site.example/?click=keep", "https://mail.example/unsubscribe?click=keep"]) {
    assert.equal(clean(result, input), input); assert.equal(navigation(result, input).url, input);
  }
  assert.equal(clean(result, "https://news.example/search?q=a+b%20c&page=2&mkt_tok=keep&click=remove"), "https://news.example/search?q=a+b%20c&page=2&mkt_tok=keep");
  assert.equal(clean(result, "https://news.example/?%73ig=secret&click=keep"), "https://news.example/?%73ig=secret&click=keep");
  assert.equal(navigation(result, "https://news.example/?%73ig=secret&click=keep").url, "https://news.example/?%73ig=secret&click=keep");
  assert.equal(clean(result, "https://news.example/?utm%5Fsource=remove&click=remove"), "https://news.example/");
  assert.equal(navigation(result, "https://news.example/?utm%5Fsource=keep&click=keep").hops, 0, "native encoded-key policy is conservatively preserved pending qualification");
});

test("runtime keeps untouched query bytes, empty components, duplicate values and fragments", () => {
  const result = compileRemoveParams("$removeparam=click\n");
  assert.equal(clean(result, "https://news.example/read?a=%2B+b&&click=1&same=1&same=2&click=&tail=#part"), "https://news.example/read?a=%2B+b&&same=1&same=2&tail=#part");
  assert.equal(clean(result, "https://news.example/?click&keep=1"), "https://news.example/?keep=1");
  const signed = "https://news.example/?signature=123&x=%2f&click=1";
  assert.equal(clean(result, signed), signed);
});

test("native query reconstruction never rewrites retained bare or empty parts", () => {
  const result = compileRemoveParams("$removeparam=click\n");
  for (const input of ["https://news.example/?flag&click=remove", "https://news.example/?a=1&&click=remove", "https://news.example/?click=remove&", "https://news.example/?click=remove&flag#part"]) {
    assert.equal(navigation(result, input).url, input);
    assert.notEqual(clean(result, input), input, "JS may safely retain the other query bytes");
  }
});

test("escaped native removal names are deferred instead of emitting no-op triggers", () => {
  const result = compileRemoveParams("$removeparam=click\n$removeparam=tag+id\n");
  assert.ok(result.coverage.nativeDeferredNames.includes("__cft__[0]"));
  assert.ok(result.coverage.nativeDeferredNames.includes("__xts__[0]"));
  assert.ok(result.coverage.nativeDeferredNames.includes("tag+id"));
  for (const rule of result.rules) for (const name of rule.action.redirect?.transform?.queryTransform.removeParams || []) assert.match(name, /^[A-Za-z0-9_!'()*\.~-]+$/);
  const input = "https://news.example/?__cft__[0]=keep&click=remove";
  assert.equal(navigation(result, input).url, "https://news.example/?__cft__[0]=keep");
  assert.equal(clean(result, input), "https://news.example/");
  assert.equal(navigation(result, "https://news.example/?__cft__[0]=keep").hops, 0);
});

test("invalid generated data cannot silently restore exception-less built-in behavior", () => {
  const input = "https://amazon.com/item/ref=keep?utm_source=keep";
  for (const data of [{schema: 1, generated: true, disabled: false, groups: [{names: ["utm_source"], include: [], exclude: ["bad.*"]}]},
    {schema: 99, generated: true, disabled: false, groups: []}, {schema: 1, generated: false, available: true}]) {
    assert.equal(params.clean(input, {data}).url, input);
    assert.equal(params.namesFor("amazon.com", data).size, 0);
  }
  assert.equal(params.clean("https://site.example/?utm_source=remove", {data: {schema: 1, generated: false, available: false}}).url, "https://site.example/");
  const corrupted = {schema: 1, generated: true, available: true, disabled: false, groups: [{names: ["mkt_tok", "q", "utm_source"], include: [], exclude: [], excludeLabels: []}]};
  assert.equal(params.clean("https://site.example/?mkt_tok=keep&q=keep&utm_source=remove", {data: corrupted}).url, "https://site.example/?mkt_tok=keep&q=keep", "runtime independently enforces the protected names");
});

test("Amazon path removal remains productive and all-name exceptions protect it", () => {
  const result = compileRemoveParams("");
  for (const input of ["https://amazon.com/item/ref=123?keep=1", "https://amazon.com/ref=123?keep=1"]) assert.equal(navigation(result, input).url, clean(result, input));
  const protectedPolicy = compileRemoveParams("@@||amazon.com/confirmation$removeparam\n$removeparam=click\n");
  const input = "https://amazon.com/item/ref=keep?click=keep";
  assert.equal(navigation(protectedPolicy, input).url, input); assert.equal(clean(protectedPolicy, input), input);
  const entityPolicy = compileRemoveParams("@@||google.*/$removeparam\n$removeparam=click\n");
  for (const host of ["google.amazon.com", "x.good.amazon.com", "google.amazon.com:8443"]) {
    const input = `https://${host}/item/ref=keep?click=keep`;
    assert.equal(navigation(entityPolicy, input).url, input); assert.equal(clean(entityPolicy, input), input);
  }
});
