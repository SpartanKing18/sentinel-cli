# Architecture

Sentinel is a dependency-free Node CLI. The security console and tools live in
`sentinel.js`; **Nexus**, the terminal AI coding agent, is the largest subsystem.
Pure, testable logic is being progressively extracted into `lib/` so the domain
model is decoupled from the terminal UI.

```
sentinel.js            entry + CLI dispatch + the Nexus full-screen TUI (raw ANSI)
lib/
  engines.js           multi-AI registry: one entry per backend (claude, gemini,
                       codex, opencode, aider, ollama). args(prompt,opts) is the
                       ONLY place an engine's flags are built -> no cross-engine leak
  pricing.js           per-model $/token cost model + cowork delegation economics
  parsers.js           Gemini/Codex structured-output parsers (real token counts)
  policy.js            guardrails engine: policyCheck + tamper-evident audit chain
  security.js          scanSecrets / maskSecrets / classifyDanger / compactOutput
  styles.js            output styles (built-in + custom .nexus/styles/*.md)
  memory.js            durable-note merge with dedup (the agent `remember` tool)
  tools.js             local-agent tool catalog + `discover` keyword search
  bgjobs.js            background-command manager (run_background/check/stop)
  settings.js          data-driven schema behind the /settings panel
  ollama.js            local-model client (chat, tags, coder-model pick)
  validate.js          .nexus/policy.json + team.json config validation
  text.js              pure text helpers (oneline, extractJson)
  diff.js              frame reconciler + word-level intra-line diff
  scanutil.js          security-console core: parsePorts, idHash, parseCve, cidrCalc, inCidr
  loop.js              autonomous goal-loop controller (Nexus /loop)
  ioc.js               IOC defang / refang (safe-to-paste indicators)
  entropy.js           Shannon entropy — flag high-entropy secrets/keys
  epoch.js             unix timestamp <-> ISO/UTC converter
  urlparse.js          URL breakdown (scheme/host/port/path/query/fragment)
test/
  run.js               framework-free unit suite (npm test) — 195 assertions
.github/workflows/
  ci.yml               node --check + npm test + CLI smoke on Node 18/20/22
```

## Design invariants (enforced by tests)

- **Engine isolation.** A flag meant for one AI can never reach another: each
  engine's `args()` builder is the single source of its CLI flags. `test/run.js`
  asserts no Claude-only flag appears in any other engine's argv.
- **Least privilege.** The local agent's file/command tools are checked against
  `.nexus/policy.json` (protected paths, denied commands, per-turn write limit,
  secret-write blocking) *before* execution. An org floor at `~/.sentinel/policy.json`
  can only be made stricter locally, never weaker.
- **Provenance.** Every enforced tool action is appended to a hash-chained
  `.nexus/audit.jsonl`; `auditVerify` (via `/audit verify`) detects any edit,
  deletion, or reordering.

## Extraction pattern

Modules are carved out incrementally and safely: each `lib/*.js` `module.exports`
everything its former block defined, and `sentinel.js` replaces the block with a
single `require`, so every existing reference resolves unchanged. Thin wrappers
that need live process state (`loadPolicy` -> home dir, `engineAvail` -> `hasBin`)
stay in `sentinel.js`. Boot and `npm test` are verified after each extraction.

The terminal UI (render loop, engine runners, command handlers) remains in
`sentinel.js` for now — it is tightly coupled to session state and is refactored
only where it can be verified without a live TTY.

## Testing

```
npm test        # unit suite (lib/*)
node --check sentinel.js lib/*.js test/*.js
```

CI runs both plus a CLI smoke test across Node 18/20/22 on every push and PR.
