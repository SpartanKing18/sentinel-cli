# Architecture

Sentinel is a dependency-free Node CLI. The security console and tools live in
`sentinel.js`; **Nexus**, the terminal AI coding agent, is the largest subsystem.
Pure, testable logic is being progressively extracted into `lib/` so the domain
model is decoupled from the terminal UI.

```
sentinel.js            entry + CLI dispatch + the Nexus full-screen TUI (raw ANSI)
lib/                   pure, testable logic in four domain subpackages
  cli/                 CLI framework: dispatch tables, help, presentation
    reference.js         --help command catalog (single source of truth) + renderer
    registry.js          data-driven command registry (19 string-returning commands)
    settings.js          data-driven schema behind the /settings panel
    styles.js            output styles (built-in + custom .nexus/styles/*.md)
    text.js              pure text helpers (oneline, extractJson)
    diff.js              frame reconciler + word-level intra-line diff
    validate.js          .nexus/policy.json + team.json config validation
  toolkit/             security & OSINT primitives (pure, exact-output tested)
    scanutil.js          parsePorts, idHash, parseCve, cidrCalc, inCidr
    ioc.js               IOC defang / refang (safe-to-paste indicators)
    entropy.js           Shannon entropy — flag high-entropy secrets/keys
    epoch.js             unix timestamp <-> ISO/UTC converter
    urlparse.js          URL breakdown (scheme/host/port/path/query/fragment)
    base32.js            base32 (RFC 4648) encode/decode + raw bytes
    totp.js              TOTP/HOTP 2FA codes (RFC 4226/6238)
    jwt.js               JWT decode + expiry/alg-none analysis
    useragent.js         User-Agent parser (browser/OS/device/bot)
    ports.js             port <-> service map + bidirectional lookup
    passphrase.js        diceware memorable-passphrase generator (injectable rng)
    revshell.js          reverse-shell one-liner payloads
    httpstatus.js        HTTP status-code map + classification
    dorks.js             google-dork catalog + URL builder
    payloads.js          attack-payload library by vuln class
    cheats.js            command cheat-sheets by topic
    hashing.js           md5/sha digests + injectable-rng password gen
    encoders.js          b64/hex/url/base32 encode-decode op map
  nexus/               AI coding-agent infrastructure
    engines.js           multi-AI registry: one entry per backend; args() is the
                         ONLY place an engine's flags are built -> no cross-engine leak
    pricing.js           per-model $/token cost model + cowork delegation economics
    parsers.js           Gemini/Codex structured-output parsers (real token counts)
    ollama.js            local-model client (chat, tags, coder-model pick)
    loop.js              autonomous goal-loop controller (Nexus /loop)
    tools.js             local-agent tool catalog + `discover` keyword search
    bgjobs.js            background-command manager (run_background/check/stop)
    memory.js            durable-note merge with dedup (the agent `remember` tool)
    todos.js             tech-debt marker scanner (TODO/FIXME/HACK) — /todo, sentinel todo
    codestats.js         codebase overview: files/lines/languages — /stats, sentinel stats
    deps.js              dependency hygiene: unused + undeclared imports — /deps, sentinel deps
    envaudit.js          env-var audit: code refs vs .env.example — /env, sentinel env
    review.js            multi-lens code-review prompt builder — /ultrareview
    changelog.js         release-notes generator from git history — /changelog, sentinel changelog
  governance/          enterprise policy, audit, cost & compliance
    policy.js            guardrails engine: policyCheck + tamper-evident audit chain
    security.js          scanSecrets / maskSecrets / classifyDanger / compactOutput
    usage.js             per-project AI usage ledger + cost/chargeback report
    identity.js          operator/team resolution — SSO env -> config -> OS user
    compliance.js        signed audit+usage compliance bundle + verify (SOC2 export)
test/
  run.js               framework-free unit suite (npm test) — 394 assertions
.github/workflows/
  ci.yml               node --check + npm test + CLI smoke on Node 18/20/22
```

## Dispatch flow

`process.argv` is read at the bottom of `sentinel.js`: `-v/--version` prints the
version + detected engines; no args → `mainMenu()` (interactive menu); `--help` →
`usage()` (rendered from `lib/cli/reference`); otherwise → `cli(args)`.

`cli(args)` splits `[cmd, ...rest]` and routes in order:

1. **Registry first** — if `CMD_MAP[cmd]` exists (`lib/cli/registry`), run it: the
   ~19 pure/deterministic string-returning commands (uuid, hash, encode/decode,
   defang, entropy, cidr, base32, epoch, urlparse, useragent, ports, dorks,
   passphrase…), backed by `lib/toolkit/*`.
2. **Async / network toolkit** — scan, dns, whois, headers, cert, subs, cve, fuzz,
   git, totp, payloads, genpass, myip, ipinfo, serve, listen, tools, setup.
3. **Governance & code-intel** — policy, audit, report, compliance, doctor, plus
   changelog, env, deps, stats, todo → `lib/governance/*` and `lib/nexus/*`.
4. **Nexus** (`nexus` | `code` | `ai`) — sub-router: init, docs, setup, login,
   run/supervise/loop (autonomous multi-round), overnight, agents/parallel, or
   default → `nexusTui()`, the raw-ANSI full-screen agent.

```
             process.argv (sentinel.js)
                     |
        +------------+------------------+---------------+
     mainMenu     usage()            cli(args)  -- router
                (lib/cli/reference)      |
     +---------------+-----------------+------------------+
     v               v                 v                  v
  registry     async toolkit      governance         nexus dispatch
 (lib/cli)     (scan/dns/cert...) (policy/audit/      -> nexusTui()
     |                            report/compliance)        |
     v                                  |            ENGINES registry (lib/nexus)
 lib/toolkit/*                          v            args() -> spawn backend CLI
                                 lib/governance/*     (claude/gemini/codex/ollama)
```

**Nexus tool loop.** Inside `nexusTui`, each turn runs via `runEngineTask` (spawns
the chosen engine's CLI) or `ollamaExec` (in-process local loop). Every tool the
model requests is **`policyCheck`-gated before it executes**, secret writes are
blocked by `scanSecrets`, each enforced action is appended to the hash-chained
`auditLog`, outbound text is masked in privacy mode, and one priced `usage` record
is appended per turn.

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
