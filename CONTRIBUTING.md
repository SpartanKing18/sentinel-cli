# Contributing

Thanks for helping improve Sentinel / Nexus.

## Setup

No dependencies to install — it runs on Node 18+.

```
git clone https://github.com/SpartanKing18/sentinel-cli
cd sentinel-cli
npm test
```

## Before you open a PR

1. `npm test` is green (add assertions in `test/run.js` for new pure logic).
2. `node --check sentinel.js lib/*.js test/*.js` passes.
3. The CLI still boots: `node sentinel.js --version`.

CI runs all three across Node 18/20/22.

## Where things go

- New AI backend -> one entry in `lib/engines.js` (define `args()` for its flags).
  Never build another engine's flags anywhere else.
- New cost/pricing rule -> `lib/pricing.js` (keep specific regexes before broad).
- Guardrail / audit logic -> `lib/policy.js`; secret/danger detection -> `lib/security.js`.
- Put pure, side-effect-free logic in `lib/` with a test; UI/session-coupled code
  stays in `sentinel.js`.

See `ARCHITECTURE.md` for the module map and design invariants.

## Conventions

- Dependency-free: standard library only, so the single-file build keeps working.
- No emojis in code or user-facing output.
- Match the terse, high-density style of the surrounding code.
