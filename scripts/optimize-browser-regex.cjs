#!/usr/bin/env node
"use strict";
// Internal bounded build helper. Reads one JSON request from stdin and writes
// one JSON result. No network, installation, profile, or native Chrome access.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const {spawn} = require("node:child_process");
const {createInterface} = require("node:readline");
const {optimizeRegexRules} = require("./lib/regex-optimizer.cjs");
const {makePlan, validatePlan, digest} = require("./lib/regex-optimization-plan.cjs");
const ENGINE = Object.freeze({name: "google-re2", packageVersion: "1.1.20251105", maxMem: 2048, encoding: "Latin1"});
const MAX_BYTES = 64 * 1024 * 1024;
const PYTHON = String.raw`
import importlib.metadata, json, sys
try:
    import re2
    version = importlib.metadata.version('google-re2')
    if version != '1.1.20251105':
        raise ValueError('version')
    re2.Options.Encoding.LATIN1
    print(json.dumps({'ready': True, 'packageVersion': version}), flush=True)
except Exception:
    print(json.dumps({'ready': False}), flush=True)
    sys.exit(2)
while True:
    line = sys.stdin.readline(65537)
    if not line:
        break
    if len(line) > 65536 or not line.endswith('\n'):
        sys.exit(2)
    try:
        query = json.loads(line)
        pattern = query['regex']
        if (not isinstance(pattern, str) or not pattern or len(pattern) > 32768
                or type(query['isCaseSensitive']) is not bool or type(query['requireCapturing']) is not bool):
            raise ValueError('request')
        options = re2.Options()
        options.encoding = re2.Options.Encoding.LATIN1
        options.max_mem = 2048
        options.case_sensitive = query['isCaseSensitive']
        options.never_capture = not query['requireCapturing']
        options.log_errors = False
        try:
            re2.compile(pattern.encode('ascii'), options=options)
            print('true', flush=True)
        except re2.error:
            print('false', flush=True)
    except Exception:
        sys.exit(2)
`;

async function run(python, rulesets) {
  if (typeof python !== "string" || !python || python.length > 4096 || !rulesets || Array.isArray(rulesets) || typeof rulesets !== "object" ||
      Object.keys(rulesets).length > 50 || Object.entries(rulesets).some(([name, rules]) => !/^[a-z][a-z0-9-]{0,63}$/.test(name) || !Array.isArray(rules)) ||
      Object.values(rulesets).reduce((sum, rules) => sum + rules.length, 0) > 100000) throw Error("request");
  const engine = spawn(python, ["-u", "-c", PYTHON], {stdio: ["pipe", "pipe", "pipe"]});
  let failed = false;
  engine.on("error", () => { failed = true; });
  engine.stdin.on("error", () => { failed = true; });
  engine.stderr.resume();
  const lines = createInterface({input: engine.stdout, crlfDelay: Infinity})[Symbol.asyncIterator]();
  let timeout;
  const complete = new Promise((resolve, reject) => {
    engine.once("error", () => reject(Error("engine")));
    engine.once("exit", (code) => code === 0 ? resolve() : reject(Error("engine")));
  });
  // Mark any early exit handled while the consumer waits on the line reader.
  complete.catch(() => {});
  try {
    timeout = setTimeout(() => engine.kill(), 45000);
    const first = await lines.next();
    if (failed || first.done || first.value.length > 1024) throw Error("engine");
    const ready = JSON.parse(first.value);
    if (ready.ready !== true || ready.packageVersion !== ENGINE.packageVersion) throw Error("engine-version");
    const approvals = [];
    const verifyRegex = async (request) => {
      if (failed) throw Error("engine");
      engine.stdin.write(JSON.stringify(request) + "\n");
      const next = await lines.next();
      if (failed || next.done || !["true", "false"].includes(next.value)) throw Error("engine");
      const supported = next.value === "true";
      approvals.push({requestSha256: digest(request), supported});
      return supported;
    };
    const results = {};
    for (const [name, rules] of Object.entries(rulesets)) results[name] = await optimizeRegexRules(rules, {verifyRegex});
    const optimized = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, result.rules]));
    // Every output regex is checked again, including untouched capture rules.
    // The enclosing build also audits the actual staged artifact before publish.
    let checkedOutput = 0;
    for (const rules of Object.values(optimized)) for (const rule of rules) {
      if (typeof rule?.condition?.regexFilter !== "string") continue;
      const capture = rule.action?.type === "redirect" && "regexSubstitution" in (rule.action.redirect || {});
      if (!(await verifyRegex({regex: rule.condition.regexFilter, isCaseSensitive: rule.condition.isUrlFilterCaseSensitive ?? false, requireCapturing: capture}))) throw Error("output-rejected");
      checkedOutput++;
    }
    engine.stdin.end(); await complete;
    const sources = {};
    for (const name of ["optimize-browser-regex.cjs", "lib/regex-language.cjs", "lib/regex-optimizer.cjs", "lib/regex-optimization-plan.cjs"])
      sources[name] = crypto.createHash("sha256").update(fs.readFileSync(path.join(__dirname, name))).digest("hex");
    const plan = makePlan(rulesets, results, sources);
    validatePlan(rulesets, optimized, plan);
    const certificate = {schema: 1, complete: true, nativeChrome: false, engine: ENGINE, sources,
      beforeSha256: digest(rulesets), afterSha256: digest(optimized), planSha256: digest(plan),
      checkedOutputRegexRules: checkedOutput, verificationRequests: approvals.length, verificationLogSha256: digest(approvals),
      rejectedCandidates: approvals.filter((entry) => !entry.supported).length};
    return {rulesets: optimized, plan, certificate};
  } finally {
    clearTimeout(timeout); engine.kill();
  }
}

async function main() {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_BYTES) throw Error("input-budget");
    chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (request.schema !== 1) throw Error("request-schema");
  const result = await run(request.python, request.rulesets);
  const body = JSON.stringify(result);
  if (Buffer.byteLength(body) > MAX_BYTES) throw Error("output-budget");
  process.stdout.write(body);
}
main().catch(() => { process.stderr.write("Regex optimization requires complete verification by google-re2==1.1.20251105 with the pinned Chrome options. No optimized build was published.\n"); process.exitCode = 1; });
