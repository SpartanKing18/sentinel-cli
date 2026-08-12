# Multi-AI engines, enterprise guardrails, modular architecture

Turns Nexus into a multi-backend AI coding agent with enterprise controls, and
starts decomposing the monolith into a tested `lib/` layer.

## Highlights

- **Six AI backends** through one registry (Claude, Gemini, Codex, OpenCode, Aider,
  Ollama). A flag for one engine can't leak into another — enforced by tests.
- **Enterprise guardrails**: policy file (protected paths / denied commands / write
  limits / secret blocking), an org floor local config can only tighten, and a
  **tamper-evident hash-chained audit trail** (`sentinel audit verify` for CI).
- **Multi-model `/team`** workspace: architect -> builder -> independent reviewer,
  looping until PASS.
- **From Claude Code & Glitch**: output styles (+ custom), `remember`, `discover`,
  background bash (`run_background`/`check_background`), a neat `/settings` panel.
- **Architecture**: 11 pure `lib/` modules + a framework-free suite (`npm test`,
  102 assertions) + CI across Node 18/20/22. See `ARCHITECTURE.md`.

## Testing

```
npm test                                   # 102 assertions, all green
node --check sentinel.js lib/*.js test/*.js
node sentinel.js --version                 # boots
```

## Notes

- The CI workflow file (`.github/workflows/ci.yml`) is included in the branch but was
  held back from the push because the PAT lacks the `workflow` scope. Add it via the
  Actions UI or push with a `workflow`-scoped token to turn CI on.
- The terminal UI, engine runners, and command dispatch remain in `sentinel.js` for
  now; they're refactored only where verifiable without a live TTY.
