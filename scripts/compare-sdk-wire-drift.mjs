#!/usr/bin/env node
// Offline source-pinned SDK drift comparison. No network, browser launch,
// installer, credentials or production collector access.
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import {createRequire} from "node:module";
const require = createRequire(import.meta.url);
const {validateReceipt, compareReceipts} = require("./lib/sdk-wire-drift.cjs");
const names = new Set(["--before", "--after", "--before-bundle", "--after-bundle", "--out"]);
function options(args) {
  const out = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i], value = args[i + 1];
    if (!names.has(key) || !value || value.startsWith("--") || Object.hasOwn(out, key))
      throw new Error("Invalid options");
    out[key] = value;
  }
  for (const key of ["--before", "--after", "--before-bundle", "--after-bundle"])
    if (!out[key]) throw new Error("Missing required input");
  return out;
}
function boundedRead(file, maxBytes) {
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size < 1 || stat.size > maxBytes)
    throw new Error("Invalid input size");
  return fs.readFileSync(file);
}
function loadReceipt(file) {
  const bytes = boundedRead(file, 131072);
  return validateReceipt(JSON.parse(bytes.toString("utf8")));
}
function sourcePin(file, expected) {
  const actual = crypto.createHash("sha256").update(boundedRead(file, 16 * 1024 * 1024)).digest("hex");
  if (actual !== expected) throw new Error("SDK bundle does not match pinned digest");
}
function main(args) {
  const o = options(args);
  const before = loadReceipt(o["--before"]), after = loadReceipt(o["--after"]);
  sourcePin(o["--before-bundle"], before.sdk.bundle_sha256);
  sourcePin(o["--after-bundle"], after.sdk.bundle_sha256);
  const report = compareReceipts(before, after);
  const serialized = JSON.stringify(report, null, 2) + "\n";
  if (o["--out"]) {
    // Never overwrite a prior qualification or follow a preexisting symlink.
    const target = path.resolve(o["--out"]);
    const fd = fs.openSync(target, "wx", 0o600);
    try { fs.writeFileSync(fd, serialized, "utf8"); }
    finally { fs.closeSync(fd); }
  } else process.stdout.write(serialized);
  return report;
}
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try { main(process.argv.slice(2)); }
  catch { process.stderr.write("sdk-wire-drift: invalid input, source pin or output path\n"); process.exitCode = 1; }
}
export {options, main};
