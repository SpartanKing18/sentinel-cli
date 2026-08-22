# Sentinel CLI

The terminal edition of Sentinel — a single command that drives a full security
toolkit and hosts **Nexus**, the AI coding agent. Recon, exploitation helpers,
practice labs, governance, and an autonomous AI layer, all from your shell.

## Architecture

```
   You (a command)
        |
        v
   sentinel.js  (dispatch + first-run setup)
        |
        +--> nexus ------> Nexus engine (lib/nexus) ---> Ollama (local) | Claude / API (cloud)
        |                    plan -> act -> observe, cost meter, /undo
        |
        +--> toolkit ----> external tools: nmap · sqlmap · nuclei · ffuf · httpx ...
        |
        +--> governance -> identity · usage ledger · compliance bundle
        |
        +--> lab --------> docker practice targets (spin up / tear down)
        v
   Results in your terminal
```

Most subcommands run through the toolkit or governance layers; `nexus` (aliases
`code`, `ai`) hands the turn to the AI engine, which edits files and runs commands
against your workspace with a live token/cost readout.

## Project Structure

```
sentinel-cli/
├── sentinel.js           # entry point + command dispatch
├── lib/
│   ├── cli/              # command implementations & shared CLI helpers
│   ├── nexus/            # the Nexus AI-coder engine  (also its own repo: SpartanKing18/nexus)
│   ├── governance/       # identity, usage ledger, compliance/policy
│   └── toolkit/          # external-tool drivers (recon / web / passwords / ...)
├── scripts/              # build & release helpers
├── test/                 # test suite (npm test)
├── docs/                 # command reference & guides
├── package.json
└── README.md
```

## Installation

```
# from source (Node 18+)
git clone https://github.com/SpartanKing18/sentinel-cli
cd sentinel-cli && npm install && node sentinel.js

# or grab a standalone binary from Releases and put it on PATH
```

## Usage

```
sentinel nexus --tui        # the AI coding agent
sentinel nexus --engine ollama   # local, private models
sentinel <tool> ...         # drive the security toolkit
```

## Running Tests

```
npm test
```

## Status

Active. The Nexus engine lives in `lib/nexus` and is mirrored to its own repo
([SpartanKing18/nexus](https://github.com/SpartanKing18/nexus)); the CLI is the
interactive host for it plus the toolkit and governance layers.

## Security

The CLI can run external tools and, via Nexus, edit files and run commands. Use it
only against systems you're authorized to test, and prefer the local `ollama` engine
for sensitive code. Credentials are never stored in source.

## License

See `LICENSE`.
