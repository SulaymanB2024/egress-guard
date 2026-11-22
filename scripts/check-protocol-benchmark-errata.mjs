#!/usr/bin/env node
// Replay disclosed source-validity corrections separately. Never rewrite the frozen corpus or score.
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import model from "./lib/dnr-benchmark.cjs";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const flags = {}, args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 2) {
  if (!["--baseline-artifact", "--candidate-artifact", "--out"].includes(args[i]) || !args[i + 1]) throw new Error("Usage: node scripts/check-protocol-benchmark-errata.mjs --baseline-artifact BUILT_0.9 --candidate-artifact BUILT_0.10 [--out RECEIPT.json]");
  flags[args[i]] = args[i + 1];
}
if (!flags["--baseline-artifact"] || !flags["--candidate-artifact"]) throw new Error("Both reviewed artifacts are required; no network or build is performed");
const corpusBytes = fs.readFileSync(path.join(root, "tests/browser/fixtures/protocols-v1.json"));
const corpus = JSON.parse(corpusBytes);
const errataBytes = fs.readFileSync(path.join(root, "docs/benchmarks/protocols-v1-errata.json"));
const errata = JSON.parse(errataBytes);
if (errata.corpusSha256 !== model.sha256(corpusBytes)) throw new Error("Erratum does not match frozen corpus");
const models = {
  baseline: model.artifactModel(flags["--baseline-artifact"]),
  candidate: model.artifactModel(flags["--candidate-artifact"]),
};
const receipts = Object.fromEntries(Object.entries(models).map(([arm, built]) => {
  const results = corpus.fixtures.map((fixture) => ({id: fixture.id, family: fixture.family, mechanism: fixture.mechanism, label: fixture.label, ...model.evaluateRequest(built.compiled, fixture.request)}));
  return [arm, {schema: 1, corpusSha256: model.sha256(corpusBytes), artifact: built.receipt, results, summary: model.summarize(corpus, results)}];
}));
const corrected = structuredClone(receipts), cases = [];
for (const correction of errata.corrections) {
  const fixture = corpus.fixtures.find((f) => f.id === correction.fixtureId);
  if (!fixture || correction.field !== "request.url" || fixture.request.url !== correction.original) throw new Error("Erratum original request does not match");
  const request = {...fixture.request, url: correction.replacement}, arms = {};
  for (const [arm, built] of Object.entries(models)) {
    const outcome = model.evaluateRequest(built.compiled, request);
    const old = receipts[arm].results.find((r) => r.id === fixture.id);
    corrected[arm].results = corrected[arm].results.map((r) => r.id === fixture.id ? {...r, ...outcome} : r);
    arms[arm] = {originalPrevented: old.prevented, corrected: outcome, unchanged: old.prevented === outcome.prevented};
  }
  cases.push({fixtureId: fixture.id, originalRequest: fixture.request, correctedRequest: request, ...arms});
}
for (const arm of Object.keys(corrected)) corrected[arm].summary = model.summarize(corpus, corrected[arm].results);
const originalComparison = model.compare(receipts.baseline, receipts.candidate), sensitivityComparison = model.compare(corrected.baseline, corrected.candidate);
const result = {schema: 1, kind: "post-freeze-source-validity-sensitivity", corpusSha256: model.sha256(corpusBytes), errataSha256: model.sha256(errataBytes),
  baselineArtifactSha256: models.baseline.receipt.sha256, candidateArtifactSha256: models.candidate.receipt.sha256,
  sourceInputsSha256: models.baseline.receipt.inputsSha256, cases, originalComparison, sensitivityComparison,
  decisionsUnchanged: cases.every((c) => c.baseline.unchanged && c.candidate.unchanged),
  scoreUnchanged: JSON.stringify(originalComparison) === JSON.stringify(sensitivityComparison),
  scope: "Separate sensitivity replay only. Frozen v1 corpus and original reports are unchanged; synthetic shapes are not server-accepted or captured traffic."};
if (flags["--out"]) fs.writeFileSync(flags["--out"], JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify(result, null, 2));
