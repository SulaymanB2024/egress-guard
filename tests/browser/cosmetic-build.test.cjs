"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {compileCosmetics} = require("../../scripts/lib/cosmetic-compiler.cjs");
test("domain cosmetic rules and global/scoped exceptions preserve exact scope", () => {
  const compiled = compileCosmetics([[
    "publisher.example,~paid.publisher.example##div.card[data-kind=sponsored]",
    "publisher.example#@#div.card[data-kind=sponsored]",
    "#@#.adunit", "##.adunit",
    "publisher.example##div.card[data-kind=sponsored]",
    "publisher.example##div.card[data-kind=sponsored]",
  ].join("\n")]);
  assert.equal(compiled.rules.length, 2);
  assert.deepEqual(compiled.rules[0], {include:["publisher.example"],exclude:["paid.publisher.example"],selector:'div.card[data-kind="sponsored"]'});
  assert.equal(compiled.exceptions.length, 2);
  assert.equal(compiled.stats.duplicate, 1);
  assert.equal(compiled.genericRules.length, 1);
});
test("cosmetic compiler refuses executable syntax and any unrepresentable scope", () => {
  const result = compileCosmetics([[
    "example.com##+js(set, foo, bar)", "example.com#$#body{display:none}",
    "example.com##body", "example.com##form", "example.com##.ad:has-text(Sponsored)",
    "example.com,~site.*.bad##.ad", "com##.ad", "example.com##div[style]",
    "example.com##div[data-note=\"url(secret)\"]",
  ].join("\n")]);
  assert.equal(result.rules.length, 0);
  assert.equal(result.stats.lines, 9);
  assert.throws(() => compileCosmetics(["example.com##.a\nexample.com##.b"], {maxRules:1}), /budget/);
});
test("cosmetic exceptions never become global hides and duplicates stay bounded", () => {
  const text = "example.com#@#.ad\n~excluded.example#@#.ad\n~excluded.example##.ad";
  const data = compileCosmetics([text,text]);
  assert.equal(data.rules.length, 0);
  assert.equal(data.genericRules.length, 1);
  assert.equal(data.exceptions.length, 2);
  assert.equal(data.stats.duplicate, 3);
});
