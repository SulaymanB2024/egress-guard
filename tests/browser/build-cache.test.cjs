"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {spawnSync} = require("node:child_process");
const {pathToFileURL} = require("node:url");
const script = path.resolve(__dirname, "../../scripts/build-browser.mjs");
const load = () => import(pathToFileURL(script).href);
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "eg-filter-cache-"));
const digest = body => crypto.createHash("sha256").update(body).digest("hex");

function bodyFor(spec, marker = "old") {
  const rows = Array.from({length: spec.minimum + 1}, (_, index) => spec.kind === "domains"
    ? `${marker}${index}.click.example` : `||${marker}${index}.example^`).join("\n") + "\n";
  return spec.kind === "domains" ? rows : `[Adblock Plus 2.0]\n! Title: ${spec.name}\n! Licence: https://easylist.to/pages/licence.html\n` + rows;
}
function fetcher(specs, marker = "old") {
  return async url => {
    const spec = specs.find(item => item.url === url);
    assert.ok(spec, "only a configured source is requested");
    const response = new Response(bodyFor(spec, marker));
    Object.defineProperty(response, "url", {value: url});
    return response;
  };
}
function writeLegacy(dir, api) {
  for (const spec of api.FILTER_LISTS) {
    const body = Buffer.from(bodyFor(spec));
    const meta = {id: spec.id, url: spec.url, sha256: digest(body), fetched_at: Date.now() / 1000 - 2 * 86400,
      ...api.listCounts(spec, body)};
    fs.writeFileSync(path.join(dir, spec.id + ".txt"), body);
    fs.writeFileSync(path.join(dir, spec.id + ".json"), JSON.stringify(meta));
  }
}

test("new cache commits metadata and exact list bytes in one private verified snapshot", async () => {
  const api = await load(), dir = temp();
  try {
    const filters = await api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS)});
    const offline = await api.loadFilters(dir, {offline: true});
    for (const spec of api.FILTER_LISTS) {
      const file = path.join(dir, spec.id + ".snapshot");
      const raw = fs.readFileSync(file), newline = raw.indexOf(10);
      assert.ok(raw.subarray(0, Buffer.byteLength(api.FILTER_CACHE_MAGIC)).equals(Buffer.from(api.FILTER_CACHE_MAGIC)));
      const meta = JSON.parse(raw.subarray(Buffer.byteLength(api.FILTER_CACHE_MAGIC), newline));
      assert.equal(meta.sha256, digest(raw.subarray(newline + 1)));
      assert.equal(meta.bytes, raw.length - newline - 1);
      assert.equal(offline[spec.id].text, filters[spec.id].text);
      if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.existsSync(path.join(dir, spec.id + ".txt")), false);
      assert.equal(fs.existsSync(path.join(dir, spec.id + ".json")), false);
    }
    assert.deepEqual(fs.readdirSync(dir).sort(), api.FILTER_LISTS.map(spec => spec.id + ".snapshot").sort());
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("failed fsync or replacement rename leaves the prior verified snapshot byte-identical", async () => {
  const api = await load(), dir = temp();
  try {
    await api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS)});
    const file = path.join(dir, "easyprivacy.snapshot"), before = fs.readFileSync(file);
    for (const operation of ["fsyncSync", "renameSync"]) {
      const original = fs[operation];
      try {
        fs[operation] = () => { throw new Error("injected precommit " + operation); };
        await assert.rejects(api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS, "new"),
          now: Date.now() / 1000 + 2 * 86400}), /injected precommit/);
      } finally { fs[operation] = original; }
      assert.deepEqual(fs.readFileSync(file), before);
      const offline = await api.loadFilters(dir, {offline: true});
      assert.match(offline.easyprivacy.text, /old0\.example/);
      assert.equal(fs.readdirSync(dir).some(name => name.startsWith(".filter-write-")), false);
    }
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("legacy cache migration is read-only until one new snapshot is committed", async () => {
  const api = await load(), dir = temp();
  try {
    writeLegacy(dir, api);
    const legacyBefore = Object.fromEntries(fs.readdirSync(dir).map(name => [name, fs.readFileSync(path.join(dir, name))]));
    assert.match((await api.loadFilters(dir, {offline: true})).easyprivacy.text, /old0\.example/);
    const original = fs.renameSync;
    try {
      fs.renameSync = () => { throw new Error("injected migration failure"); };
      await assert.rejects(api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS, "new")}), /injected migration failure/);
    } finally { fs.renameSync = original; }
    assert.match((await api.loadFilters(dir, {offline: true})).easyprivacy.text, /old0\.example/);
    for (const [name, bytes] of Object.entries(legacyBefore)) assert.deepEqual(fs.readFileSync(path.join(dir, name)), bytes);
    await api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS, "new")});
    assert.match((await api.loadFilters(dir, {offline: true})).easyprivacy.text, /new0\.example/);
    for (const [name, bytes] of Object.entries(legacyBefore)) assert.deepEqual(fs.readFileSync(path.join(dir, name)), bytes);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});

test("process interruption before or after the commit leaves one complete usable generation", async () => {
  const api = await load();
  for (const phase of ["before", "after"]) {
    const dir = temp();
    try {
      await api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS)});
      const child = `
        import fs from 'node:fs';
        import path from 'node:path';
        const api = await import(${JSON.stringify(pathToFileURL(script).href)});
        const dir = process.argv[1], phase = process.argv[2];
        const rename = fs.renameSync;
        fs.renameSync = (from, to) => {
          if (to === path.join(dir, 'easyprivacy.snapshot')) {
            if (phase === 'before') process.exit(77);
            rename(from, to); process.exit(78);
          }
          return rename(from, to);
        };
        await api.loadFilters(dir, {now: Date.now()/1000 + 2*86400, fetchImpl: async url => {
          const spec = api.FILTER_LISTS.find(s => s.url === url);
          const text = api.readCachedFilter(dir, spec).body.toString('utf8').replaceAll('old', 'new');
          const response = new Response(text); Object.defineProperty(response, 'url', {value: url}); return response;
        }});
      `;
      const processResult = spawnSync(process.execPath, ["--input-type=module", "-e", child, dir, phase],
        {encoding: "utf8", timeout: 20000});
      assert.equal(processResult.status, phase === "before" ? 77 : 78, processResult.stderr);
      const offline = await api.loadFilters(dir, {offline: true});
      assert.match(offline.easyprivacy.text, phase === "before" ? /old0\.example/ : /new0\.example/);
      assert.equal(Object.keys(offline).length, api.FILTER_LISTS.length);
      // An interrupted writer can leave private staging files. They are never selected as a cache.
      assert.ok(fs.readdirSync(dir).some(name => name.startsWith(".filter-write-")));
    } finally { fs.rmSync(dir, {recursive: true, force: true}); }
  }
});

test("snapshot corruption, forged count baselines and oversized metadata are refused", async () => {
  const api = await load(), dir = temp(), spec = api.FILTER_LISTS[0];
  try {
    await api.loadFilters(dir, {fetchImpl: fetcher(api.FILTER_LISTS)});
    const file = path.join(dir, spec.id + ".snapshot"), original = fs.readFileSync(file);
    const newline = original.indexOf(10), start = Buffer.byteLength(api.FILTER_CACHE_MAGIC);
    const meta = JSON.parse(original.subarray(start, newline));
    const altered = Buffer.concat([Buffer.from(api.FILTER_CACHE_MAGIC + JSON.stringify({...meta, entries: meta.entries + 1}) + "\n"), original.subarray(newline + 1)]);
    fs.writeFileSync(file, altered);
    assert.throws(() => api.readCachedFilter(dir, spec), /cached entries/);
    fs.writeFileSync(file, api.FILTER_CACHE_MAGIC + " ".repeat(api.MAX_FILTER_META_BYTES + 1) + "\n");
    assert.throws(() => api.readCachedFilter(dir, spec), /oversized metadata/);
    writeLegacy(dir, api);
    fs.writeFileSync(file, Buffer.concat([original, Buffer.from("tampering\n")]));
    assert.throws(() => api.readCachedFilter(dir, spec), /SHA-256/);
    await assert.rejects(api.loadFilters(dir, {offline: true}), /Required filter EasyPrivacy/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
