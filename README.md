<div align="center">

# Sentinel — Terminal Edition

**A dependency-free security console for your terminal.**

[![CI](https://github.com/SpartanKing18/sentinel-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/SpartanKing18/sentinel-cli/actions/workflows/ci.yml)

![License](https://img.shields.io/badge/license-MIT-00d4ff)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-2b3b5c)
![Node](https://img.shields.io/badge/node-%E2%89%A518-339933)
![Dependencies](https://img.shields.io/badge/dependencies-0-2ee6a6)

</div>

Sentinel's command-line edition packs a native port scanner, reverse-shell
generator, encoders, payload builders, and cheat sheets into a single file with
**zero dependencies** — it runs anywhere Node does, and ships as standalone
binaries that need no runtime at all. Perfect for a headless box over SSH.

---

## Install

**git clone — smallest, self-updating (needs Node 18+)**

```bash
git clone https://github.com/SpartanKing18/sentinel-cli
cd sentinel-cli
node sentinel.js            # or: node sentinel.js scan 10.0.0.1
```

Only ~300 KB on disk (one file), and `git pull` gets the latest. No `npm install` — it uses only Node built-ins.

**Standalone binary — no Node required (~52 MB)**

```bash
# Linux
chmod +x Sentinel-cli-linux
./Sentinel-cli-linux

# Windows (PowerShell or cmd)
.\Sentinel-cli-windows.exe
```

**From source — Node 18+**

```bash
node sentinel.js          # or: npm start
```

## Usage

Run with no arguments for the interactive menu, or use one-shot commands:

```
sentinel scan <host> [ports]        TCP scan (ports: top | 1-1024 | 80,443)
sentinel revshell <lang> <ip> <port>
sentinel encode <b64|hex|url> <text>
sentinel decode <b64|hex|url> <text>
sentinel hash <text>                md5 / sha1 / sha256 / sha512
sentinel hashid <hash>              identify a hash type
sentinel genpass [length]           generate a strong random password (default 20)
sentinel myip                       show your public IP address
sentinel status <code>              look up an HTTP status code
sentinel lab [target]               practice targets (dvwa, juice, webgoat, bwapp, mutillidae)
sentinel payloads [class]           payload library (sqli, xss, lfi, cmdi, ssti, ssrf)
sentinel cheats [topic]             nmap · shells · privesc · transfer · web · cracking · windows
sentinel tools                      tool catalog + install commands
sentinel --help | --version
```

### Example

```console
$ sentinel scan 10.10.14.7 top
  PORT   SERVICE     BANNER
  22     ssh         SSH-2.0-OpenSSH_9.6p1
  80     http
  443    https
  ● 3 open ports on 10.10.14.7
  nmap: nmap -sV -sC -p 22,80,443 10.10.14.7
```

## Features

| Command    | What it does                                                        |
| ---------- | ------------------------------------------------------------------- |
| `scan`     | Native async TCP scanner with service detection and banner grabbing |
| `revshell` | bash · python3 · nc · php · perl · powershell one-liners             |
| `encode`   | base64 · hex · URL, plus MD5/SHA hashing and a hash identifier       |
| `cheats`   | Copy-ready one-liners for every stage of an engagement              |
| `tools`    | Catalog of tools with install commands                              |

## Nexus — the AI coding agent

Nexus is a full-screen terminal coding agent built into Sentinel. It drives
whichever AI you have, with enterprise controls and a local, private option.

```
sentinel nexus                 open the agent (Claude if installed, else local)
sentinel nexus -e ollama       drive a 100% local, private, free agent
sentinel nexus "add tests to server.js and run them"   one-shot task
sentinel nexus run "<goal>"    autonomous multi-step run
sentinel policy                show the effective security policy
sentinel audit verify          verify the tamper-evident audit trail (CI-friendly)
```

- **Works with any AI** — one registry drives Claude Code, Gemini, Codex, OpenCode,
  Aider, and local Ollama models. A flag meant for one engine can never leak into
  another. Switch with `/engine`, pick a model with `/model`.
- **Multiple models together** — `/team` runs an architect, a builder, and an
  independent reviewer (each a model of your choice) and loops until the review passes.
- **Enterprise guardrails** — a `.nexus/policy.json` (protected paths, denied commands,
  per-turn write limits, secret-write blocking) enforced on the agent, with an org
  floor a local config can only tighten, plus a hash-chained audit trail.
- **In the UI** — `/settings` for every option, output styles (`/style`), background
  commands (`run_background`), a `remember` tool for durable project rules, cost
  meters, plan mode, checkpoints/undo, and more.

Architecture and design invariants: see [ARCHITECTURE.md](ARCHITECTURE.md).
Run the tests with `npm test`.

## Build

```bash
npx @yao-pkg/pkg .        # writes dist/Sentinel-cli-linux and Sentinel-cli-windows.exe
```

## Responsible use

Sentinel is for **authorized** security testing and learning only. Only scan or
target systems you own or have explicit written permission to test.

## License

[MIT](LICENSE) © 2026 Sentinel
