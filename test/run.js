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
const { createBgJobs, MAX_BUF } = require("../lib/bgjobs");
const { SETTINGS, describe } = require("../lib/settings");
const { pickCoderModel } = require("../lib/ollama");
const { validatePolicy, validateTeam } = require("../lib/validate");

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

group("background jobs (Claude-Code idea) — state machine");
{
  const bg = createBgJobs();
  const id = bg.start("npm run dev", { kill() { this.killed = true; } }, 1000);
  ok("starts running", bg.get(id).status === "running" && bg.running() === 1);
  bg.append(id, "listening on :3000\n"); bg.append(id, "compiled\n");
  ok("buffers output", bg.tail(id).includes("listening on :3000") && bg.tail(id).includes("compiled"));
  ok("list shape", bg.list()[0].id === id && bg.list()[0].status === "running" && bg.list()[0].bytes > 0);
  bg.finish(id, 0);
  ok("finish -> done, running=0", bg.get(id).status === "done" && bg.get(id).code === 0 && bg.running() === 0);
  ok("finish is idempotent", (bg.finish(id, 7), bg.get(id).code === 0)); // already done, code unchanged
  const bg2 = createBgJobs(); const child = { killed: false, kill() { this.killed = true; } };
  const id2 = bg2.start("sleep 999", child, 0); bg2.killAll();
  ok("killAll kills running + marks killed", child.killed === true && bg2.get(id2).status === "killed");
  const bg3 = createBgJobs(); const id3 = bg3.start("x", null, 0); bg3.append(id3, "y".repeat(MAX_BUF + 5000));
  ok("output buffer is bounded", bg3.get(id3).out.length <= MAX_BUF);
  const bg4 = createBgJobs(); const kc = { kill() { this.k = true; } }; const id4 = bg4.start("srv", kc, 0);
  ok("stop() kills a specific job", bg4.stop(id4) === true && kc.k === true && bg4.get(id4).status === "killed");
  ok("stop() unknown id → false", bg4.stop("nope") === false);
}

group("settings schema (data-driven /settings panel)");
{
  const v = { engine: "claude", model: "opus", effort: "high", fallback: "", style: "review", lean: true, cowork: { on: true, strong: "opus", weak: "haiku" }, costCap: 5, cost: 0.1234, mode: "plan", guard: "enforce", policyOrg: true, audit: true, redact: true, offline: false, notify: true, ctxPct: 42, pins: 2, bgRunning: 1 };
  const d = describe(v);
  ok("groups present", d.map((g) => g.group).join(",") === "Model,Output,Cost,Safety & policy,Privacy,Session");
  const flat = {}; d.forEach((g) => g.rows.forEach((r) => (flat[r.label] = r.value)));
  ok("engine value", flat["Engine"] === "claude");
  ok("style value", flat["Output style"] === "review");
  ok("lean on", flat["Lean output"] === "on");
  ok("cowork rendered", flat["Cowork (strong+weak)"] === "opus -> haiku");
  ok("budget rendered", flat["Budget cap"] === "$5.00");
  ok("policy org-enforced", flat["Security policy"] === "org-enforced");
  ok("every row has a cmd", d.every((g) => g.rows.every((r) => r.cmd && r.cmd.length)));
}

group("ollama coder-model selection");
{
  ok("prefers qwen2.5-coder", pickCoderModel(["llama3.2:3b", "qwen2.5-coder:7b", "mistral"]) === "qwen2.5-coder:7b");
  ok("priority order (deepseek over codellama)", pickCoderModel(["codellama:7b", "deepseek-coder:6.7b"]) === "deepseek-coder:6.7b");
  ok("falls back to code-ish", pickCoderModel(["mystery-code-model", "random"]) === "mystery-code-model");
  ok("falls back to first", pickCoderModel(["random1", "random2"]) === "random1");
  ok("empty → empty string", pickCoderModel([]) === "");
}

group("config validation (.nexus/policy.json + team.json)");
{
  ok("valid policy → no warnings", validatePolicy({ protectedPaths: ["*.env"], blockSecrets: true, maxFilesPerTurn: 5 }).length === 0);
  ok("protectedPaths wrong type", validatePolicy({ protectedPaths: "nope" })[0].includes("must be an array"));
  ok("blockSecrets wrong type", validatePolicy({ blockSecrets: "yes" })[0].includes("true or false"));
  ok("negative maxFilesPerTurn", validatePolicy({ maxFilesPerTurn: -1 }).some((s) => />= 0/.test(s)));
  ok("invalid denied-command regex", validatePolicy({ deniedCommands: ["("] }).some((s) => /invalid regex/.test(s)));
  ok("non-object policy", validatePolicy(42)[0].includes("must be a JSON object"));
  ok("valid team → no warnings", validateTeam({ roles: [{ role: "builder", engine: "claude" }], maxRounds: 2 }, ["claude", "ollama"]).length === 0);
  ok("team role missing engine", validateTeam({ roles: [{ role: "builder" }] }).some((s) => /missing 'engine'/.test(s)));
  ok("team unknown engine", validateTeam({ roles: [{ role: "x", engine: "gpt9" }] }, ["claude"]).some((s) => /unknown engine/.test(s)));
  ok("team bad maxRounds", validateTeam({ maxRounds: 0 }).some((s) => />= 1/.test(s)));
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
process.exit(fail ? 1 : 0);
