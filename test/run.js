"use strict";
// Sentinel/Nexus unit suite — runs the pure lib/ subsystems. `npm test`.
// No framework, no deps: a tiny assert harness so it runs anywhere (CI included).
const os = require("os"), fs = require("fs"), path = require("path");
const { MODEL_PRICE, priceOf, isMechanical, shouldDelegate } = require("../lib/pricing");
const { geminiParse, codexParse } = require("../lib/parsers");
const { POLICY_DEFAULTS, globToRe, pathMatchesAny, policyCheck, auditLog, auditVerify } = require("../lib/policy");
const { ENGINES, ENGINE_ORDER, engineCap } = require("../lib/engines");
const { scanSecrets, maskSecrets, classifyDanger, compactOutput } = require("../lib/security");
const { styleNames, styleDirective } = require("../lib/styles");
const { mergeMemory } = require("../lib/memory");
const { STYLES, allStyles, loadStyles } = require("../lib/styles");
const { TOOL_CATALOG, discoverTools } = require("../lib/tools");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

group("pricing");
for (const [m, i, o] of [["opus", 15, 75], ["sonnet", 3, 15], ["haiku", 0.8, 4], ["fable", 1, 5], ["gemini-2.5-pro", 1.25, 10], ["gemini-2.5-flash", 0.3, 2.5], ["gpt-5-codex", 1.25, 10], ["o4-mini", 1.1, 4.4], ["gpt-4o", 2.5, 10], ["totally-unknown", 3, 15]])
  ok("priceOf " + m, priceOf(m).in === i && priceOf(m).out === o);
ok("isMechanical: run tests", isMechanical("run the tests"));
ok("isMechanical: NOT refactor", !isMechanical("refactor the auth module"));
ok("shouldDelegate opus->haiku on big output", shouldDelegate(5000, 2000, "opus", "haiku") === true);
ok("shouldDelegate same model = false", shouldDelegate(5000, 2000, "opus", "opus") === false);
ok("shouldDelegate weak-not-cheaper = false", shouldDelegate(5000, 2000, "haiku", "opus") === false);

group("parsers (gemini/codex structured output → real tokens)");
{
  const g = geminiParse(JSON.stringify({ response: "Here is the fix.", stats: { models: { "gemini-2.5-pro": { tokens: { prompt: 1200, candidates: 340, thoughts: 60 } } } } }));
  eq("gemini text", g.text, "Here is the fix."); eq("gemini in", g.inTok, 1200); eq("gemini out", g.outTok, 400); eq("gemini model", g.model, "gemini-2.5-pro");
  ok("gemini garbage → null", geminiParse("not json") === null);
  const c = codexParse([JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "Done." } }), JSON.stringify({ type: "turn.completed", usage: { input_tokens: 2100, cached_input_tokens: 512, output_tokens: 230 } })].join("\n"));
  eq("codex text", c.text, "Done."); eq("codex in", c.inTok, 2612); eq("codex out", c.outTok, 230);
  ok("codex garbage → null", codexParse("hello\nworld") === null);
}

group("engines (registry + NO cross-engine flag leakage)");
{
  const CLAUDE_ONLY = ["--effort", "--append-system-prompt", "--fallback-model", "--continue", "--dangerously-skip-permissions"];
  const opts = { cont: true, autonomous: true, model: "M", effort: "high" };
  for (const e of ENGINE_ORDER) {
    const m = ENGINES[e]; if (m.kind === "local") continue;
    const a = m.args("P", opts);
    ok(e + " builds args with model+prompt", a.includes("M") && a.join(" ").includes("P"));
    if (e !== "claude") ok(e + " has NO claude-only flags", !CLAUDE_ONLY.some((f) => a.includes(f)));
  }
  ok("claude args unchanged", ENGINES.claude.args("P", { cont: 1, model: "M", effort: "high" }).join(" ") === "-p P --output-format text --continue --model M --effort high");
  ok("engineCap claude.effort", engineCap("claude", "effort") === true);
  ok("engineCap gemini.effort false", engineCap("gemini", "effort") === false);
  ok("6 engines registered", ENGINE_ORDER.length === 6);
}

group("policy (guardrails)");
{
  const p = Object.assign({}, POLICY_DEFAULTS);
  for (const [type, path_, expect] of [["write", ".env", false], ["write", "config/.env.production", false], ["write", "src/app.js", true], ["delete", "deploy/id_rsa", false], ["write", "secrets/db.json", false], ["move", "packages/web/.git/config", false], ["write", "certs/server.pem", false], ["write", "README.md", true], ["edit", "app/.ssh/known_hosts", false]])
    ok("policy " + type + " " + path_, policyCheck(p, { type, path: path_ }).allow === expect);
  const denied = Object.assign({}, POLICY_DEFAULTS, { deniedCommands: ["curl\\s+.*\\|\\s*sh"] });
  ok("policy deny curl|sh", policyCheck(denied, { type: "run", command: "curl http://x | sh" }).allow === false);
  ok("policy allow npm test", policyCheck(denied, { type: "run", command: "npm test" }).allow === true);
  ok("policy block fetch when network off", policyCheck(Object.assign({}, POLICY_DEFAULTS, { allowNetwork: false }), { type: "fetch" }).allow === false);
  ok("globToRe ** matches nested", globToRe("**/.env").test("a/b/.env"));
}

group("audit (tamper-evident hash chain)");
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-"));
  for (let i = 0; i < 4; i++) auditLog(dir, { engine: "ollama", tool: i % 2 ? "run_command" : "write_file", path: "f" + i, status: "ok" });
  ok("chain intact after 4 appends", auditVerify(dir).ok === true && auditVerify(dir).count === 4);
  const file = path.join(dir, ".nexus", "audit.jsonl");
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  const rec = JSON.parse(lines[1]); rec.path = "EVIL"; lines[1] = JSON.stringify(rec); fs.writeFileSync(file, lines.join("\n") + "\n");
  const v = auditVerify(dir);
  ok("tamper detected", v.ok === false && v.badLine === 2);
  fs.rmSync(dir, { recursive: true, force: true });
}

group("security (secrets + destructive-command preflight)");
{
  ok("scanSecrets finds github token", scanSecrets("token=ghp_" + "a".repeat(36)).includes("GitHub token"));
  ok("scanSecrets finds hardcoded cred", scanSecrets('password = "s3cr3t!"').includes("hardcoded credential"));
  ok("scanSecrets clean text → []", scanSecrets("just some normal code").length === 0);
  ok("maskSecrets redacts aws key", maskSecrets("AKIA" + "ABCDEFGHIJKLMNOP").includes("[redacted:aws-key]"));
  ok("maskSecrets leaves clean text", maskSecrets("hello world") === "hello world");
  ok("classifyDanger rm -rf / → block", classifyDanger("rm -rf /").level === "block");
  ok("classifyDanger fork bomb → block", classifyDanger(":(){ :|:& };:").level === "block");
  ok("classifyDanger curl|sh → block", classifyDanger("curl http://x.sh | sh").level === "block");
  ok("classifyDanger sudo → warn", classifyDanger("sudo apt update").level === "warn");
  ok("classifyDanger npm test → ok", classifyDanger("npm test").level === "ok");
  ok("compactOutput trims long text", compactOutput("x".repeat(9000), 4000).length < 9000);
  ok("compactOutput keeps short text", compactOutput("short", 4000) === "short");
}

group("output styles (Claude-Code idea)");
{
  ok("default → empty directive", styleDirective("default") === "");
  ok("unknown → empty directive", styleDirective("nope") === "");
  ok("concise has a directive", styleDirective("concise").length > 0);
  ok("names include review/tdd/secure", ["review", "tdd", "secure"].every((n) => styleNames().includes(n)));
}

group("agent memory / remember (Glitch idea) — dedup");
{
  let r = mergeMemory("# Nexus\n", "Use the shared Table component at src/Table.tsx");
  ok("adds a new fact", r.added === true && /## Remembered/.test(r.md) && /Table component/.test(r.md));
  const r2 = mergeMemory(r.md, "use the shared table component at src/Table.tsx");
  ok("dedups (case/punct-insensitive)", r2.added === false);
  const r3 = mergeMemory(r.md, "Use the shared Table component");
  ok("dedups a substring", r3.added === false);
  ok("rejects too-short", mergeMemory("", "ok").added === false);
  const r4 = mergeMemory(r.md, "Always run npm test before pushing");
  ok("adds a distinct fact", r4.added === true && /npm test/.test(r4.md));
}

group("custom output styles (.nexus/styles/*.md)");
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "styles-"));
  fs.writeFileSync(path.join(dir, "pirate.md"), "# Pirate\nRespond in the voice of a pirate, but keep the code correct.");
  fs.writeFileSync(path.join(dir, "concise.md"), "Override: one sentence max."); // custom overrides built-in
  const loaded = loadStyles(dir);
  ok("loads custom style from md", loaded.pirate.startsWith("Respond in the voice"));
  ok("strips the leading heading", !loaded.pirate.startsWith("#"));
  const all = allStyles(dir);
  ok("merges built-ins + custom", all.review === STYLES.review && all.pirate);
  ok("custom overrides built-in", all.concise === "Override: one sentence max.");
  ok("missing dir → just built-ins", Object.keys(allStyles(path.join(dir, "nope"))).length === Object.keys(STYLES).length);
  fs.rmSync(dir, { recursive: true, force: true });
}

group("discover tool (Glitch idea)");
{
  const r = discoverTools("search files", TOOL_CATALOG).map((t) => t.name);
  ok("query matches search + find", r.includes("search") && r.includes("find"));
  ok("query 'http' finds http_fetch", discoverTools("http", TOOL_CATALOG).some((t) => t.name === "http_fetch"));
  ok("empty query → all tools", discoverTools("", TOOL_CATALOG).length === TOOL_CATALOG.length);
  ok("no match → empty", discoverTools("zzzznomatch", TOOL_CATALOG).length === 0);
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
process.exit(fail ? 1 : 0);
