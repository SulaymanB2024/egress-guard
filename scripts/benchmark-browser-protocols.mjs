#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import model from "./lib/dnr-benchmark.cjs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2), flags = {};
for (let i = 0; i < args.length; i += 2) {
  if (!["--artifact", "--corpus", "--baseline", "--out"].includes(args[i]) || !args[i + 1]) throw new Error("Usage: node scripts/benchmark-browser-protocols.mjs --artifact BUILT_CHROME [--baseline RESULT.json] [--out RESULT.json] [--corpus FIXTURES.json]");
  flags[args[i]] = args[i + 1];
}
if (!flags["--artifact"]) throw new Error("--artifact is required; no network or automatic build is performed");
const result = model.benchmark(flags["--artifact"], flags["--corpus"] || path.join(root, "tests/browser/fixtures/protocols-v1.json"));
if (flags["--baseline"]) result.comparison = model.compare(JSON.parse(fs.readFileSync(flags["--baseline"])), result);
if (flags["--out"]) fs.writeFileSync(flags["--out"], JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify({corpusSha256: result.corpusSha256, artifact: result.artifact.sha256, inputs: result.artifact.inputsSha256, summary: result.summary, comparison: result.comparison}, null, 2));
