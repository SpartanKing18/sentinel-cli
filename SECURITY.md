# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.
Use GitHub's **Report a vulnerability** (Security tab -> Advisories) so the report
stays confidential until a fix is available. Include steps to reproduce and the
affected version. We aim to acknowledge reports promptly and coordinate disclosure.

## Scope

Sentinel is offensive-security tooling meant for systems you own or are
authorized to test. Reports about the tool itself are in scope: for example, the
Nexus agent bypassing its own guardrails, the audit chain failing to detect
tampering, secret redaction missing a credential class, or a command-injection
path in the CLI.

## Built-in safeguards

- **Guardrails** — the agent enforces `.nexus/policy.json` (protected paths, denied
  commands, per-turn write limits, secret-write blocking) before any file or command
  action, plus an org-level floor that a local config can only tighten.
- **Destructive-command preflight** — shell commands are classified and blocked or
  flagged (`classifyDanger`).
- **Secret handling** — files are scanned for credentials before writing, and text is
  redacted before it is sent to a cloud engine.
- **Tamper-evident audit** — enforced actions are appended to a hash-chained
  `.nexus/audit.jsonl`; run `sentinel audit verify` to check its integrity.

Verify your setup at any time with `sentinel doctor`.
