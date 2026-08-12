# Changelog

All notable changes to Sentinel / Nexus. Format loosely follows
[Keep a Changelog](https://keepachangelog.com).

## [Unreleased] — branch `feat/multi-ai-enterprise-arch`

### Added — multi-AI
- Engine registry driving **six backends**: Claude Code, Gemini CLI, Codex CLI,
  OpenCode, Aider, Ollama. Per-engine `args()` is the single place each backend's
  flags are built, so a flag can never leak across engines.
- Gemini/Codex run in JSON output modes; real token counts parsed from their output.
- `/engine` picker, `/model` catalog picker, per-model pricing, estimated cost for
  the paid CLIs, and a `/team` multi-model workspace (architect -> builder ->
  independent reviewer, looping until the reviewer returns PASS).

### Added — enterprise
- Guardrails policy (`.nexus/policy.json`): protected paths, denied commands,
  per-turn write limit, secret-write blocking; enforced on the local agent and
  injected into Claude's instructions.
- Two-tier policy: an org floor at `~/.sentinel/policy.json` a local policy can only
  make stricter, never weaker.
- Tamper-evident, hash-chained audit trail; `sentinel audit verify` / `/audit verify`
  detect any edit, deletion, or reordering (non-zero exit for CI gates).
- `sentinel policy` / `sentinel audit` usable outside the TUI for CI and compliance.

### Added — from Claude Code & Glitch
- Output styles (`/style`), including custom `.nexus/styles/*.md`.
- Agent `remember` tool (durable NEXUS.md notes with dedup) and `discover` tool
  (keyword search over the agent's own toolset).
- Background bash: `run_background` / `check_background` tools, a `/jobs` list, and
  a status-bar indicator; jobs are guard/policy-checked and killed on exit.
- A neatly categorized `/settings` panel (aliases `/options`, `/config`).

### Added — quality
- Sign-in via a pairing code from the website (`/login`), first-run Ollama setup.
- Faster startup (memoized PATH-based tool detection), skippable boot, fuzzy command
  palette, word-level intra-line diffs, a richer theme system.

### Changed — architecture
- Extracted pure subsystems into `lib/` modules (engines, pricing, parsers, policy,
  security, styles, memory, tools, bgjobs, settings, ollama).
- Added a framework-free unit suite: `npm test` — 102 assertions.
- CI workflow (`.github/workflows/ci.yml`) running check + tests + smoke on Node
  18/20/22 (add via a workflow-scoped token or the Actions UI).
