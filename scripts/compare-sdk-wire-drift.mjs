#!/usr/bin/env node
// Offline source-pinned SDK drift comparison. No network, browser launch,
// installer, credentials or production collector access.
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createRequire} from "node:module";
const require = createRequire(import.meta.url);
const {validateReceipt, compareReceipts} = require("./lib/sdk-wire-drift.cjs");
const {validateSourceManifest, reviewSourcePins, sourcePath} = require("./lib/sdk-source-review.cjs");
const names = new Set(["--before", "--after", "--before-bundle", "--after-bundle", "--out",
  "--source-manifest", "--source-root"]);
const wireInputs = ["--before", "--after", "--before-bundle", "--after-bundle"];
function options(args) {
  const out = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i], value = args[i + 1];
    if (!names.has(key) || !value || value.startsWith("--") || Object.hasOwn(out, key))
      throw new Error("Invalid options");
    out[key] = value;
  }
  if (out["--source-manifest"] || out["--source-root"]) {
    if (!out["--source-manifest"] || !out["--source-root"] || wireInputs.some(k => out[k]))
      throw new Error("Source review and wire comparison are separate modes");
  } else for (const key of wireInputs) if (!out[key]) throw new Error("Missing required input");
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
function localSourceReader(root) {
  const base = path.resolve(root);
  // Refuse links in the configured tree. This remains a local snapshot reader,
  // not an attestation against a concurrently hostile filesystem.
  function noLinks(target) {
    const parsed = path.parse(target);
    let cursor = parsed.root;
    for (const part of target.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      if (fs.lstatSync(cursor).isSymbolicLink()) throw new Error("Linked source path");
    }
  }
  noLinks(base);
  if (!fs.lstatSync(base).isDirectory() || !fs.constants.O_NOFOLLOW || !fs.constants.O_NONBLOCK)
    throw new Error("Unsupported source directory");
  return (directory, relative, maxBytes) => {
    sourcePath(directory); sourcePath(relative);
    const target = path.resolve(base, directory, ...relative.split("/"));
    if (!target.startsWith(base + path.sep)) throw new Error("Source escapes root");
    noLinks(target);
    const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > maxBytes)
        throw new Error("Invalid source file");
      const buffer = Buffer.alloc(Math.min(stat.size + 1, maxBytes + 1));
      let length = 0, count;
      do { count = fs.readSync(fd, buffer, length, buffer.length - length, null); length += count; }
      while (count && length < buffer.length);
      if (length !== stat.size) throw new Error("Source changed while reading");
      return buffer.subarray(0, length);
    } finally { fs.closeSync(fd); }
  };
}
function main(args) {
  const o = options(args);
  let report;
  if (o["--source-manifest"]) {
    const raw = boundedRead(o["--source-manifest"], 131072);
    const manifest = validateSourceManifest(JSON.parse(raw.toString("utf8")));
    report = reviewSourcePins(manifest, localSourceReader(o["--source-root"]));
    report.manifest_sha256 = crypto.createHash("sha256").update(raw).digest("hex");
    report.verifier_sha256 = {
      entrypoint: crypto.createHash("sha256").update(boundedRead(fileURLToPath(import.meta.url), 131072)).digest("hex"),
      source_review_module: crypto.createHash("sha256").update(boundedRead(require.resolve("./lib/sdk-source-review.cjs"), 131072)).digest("hex"),
    };
  } else {
    const before = loadReceipt(o["--before"]), after = loadReceipt(o["--after"]);
    sourcePin(o["--before-bundle"], before.sdk.bundle_sha256);
    sourcePin(o["--after-bundle"], after.sdk.bundle_sha256);
    report = compareReceipts(before, after);
  }
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
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = main(process.argv.slice(2));
    if (report.evidence_level === "source-byte-check-only" && report.status !== "SOURCE PINS VERIFIED")
      process.exitCode = 2;
  }
  catch { process.stderr.write("sdk-wire-drift: invalid input, source pin or output path\n"); process.exitCode = 1; }
}
export {options, main};
