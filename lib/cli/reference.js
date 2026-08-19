"use strict";
// Single source of truth for the `sentinel --help` command reference. Previously
// this lived as a hand-spaced block inside usage() AND overlapped with each
// handler's inline usage string, so the two drifted. Now the catalog is structured
// data and the help text is GENERATED from it (renderCommands), which also makes it
// testable — a unit test can assert every dispatched command is documented here.
//
// Row shape: [left, right]. The literal token "__CHEATS__" in a right cell is
// replaced at render time with the live cheat-sheet topic list (dynamic content).

const COMMAND_GROUPS = [
  { title: "AI & Nexus", rows: [
    ["nexus [opts] [task]", "Nexus AI coder chat: -e claude|gemini|codex|opencode|aider|ollama, -y skip prompts, --print headless"],
    ["nexus run \"<goal>\" [opts]", "autonomous multi-level runner: -e engine, --overnight, --until, --resume"],
    ["nexus serve [port]", "headless Nexus service: POST /run {goal} (loopback-only, token-gated)"],
    ["update [--check]", "self-update to the latest version (git fast-forward; --check only reports)"],
    ["init", "scaffold Nexus in this project (.nexus/NEXUS.md + config)"],
    ["docs [topic]", "built-in Nexus documentation (docs all for everything)"],
    ["report [--json] [--since <date>]", "AI cost & usage report for chargeback (reads .nexus/usage.jsonl)"],
    ["savings [--json] [--since <date>]", "cost-savings analysis: run-rate, 30d projection, local/downshift levers"],
    ["todo [TAG] [--max N] [--json]", "scan the project for TODO/FIXME/HACK markers (CI gate)"],
    ["stats [--json]", "codebase overview: files, lines & languages, largest files"],
    ["deps [--json] [--strict]", "dependency hygiene: unused + undeclared imports (CI gate)"],
    ["env [--json] [--strict]", "env-var audit: code vs .env.example (undocumented/unused)"],
    ["changelog [range] [--json]", "release notes from git history, grouped by commit type"],
    ["compliance [verify <file>]", "signed audit+usage compliance bundle for SOC2/review"],
  ] },
  { title: "Setup & security", rows: [
    ["doctor", "health check: engines, Ollama, policy, audit chain"],
    ["policy [init|--json]", "show/scaffold the security policy (init writes a starter .nexus/policy.json)"],
    ["audit [verify|--json]", "show the audit trail; 'verify' checks the hash chain (exit 1 if tampered)"],
    ["login [google|github|<code>]", "sign in (paste your code from the website Settings)"],
    ["setup <tool>", "auto-configure a tool on first use"],
  ] },
  { title: "Recon", rows: [
    ["scan <host> [ports]", "TCP scan (ports: top | 1-1024 | 80,443)"],
    ["dns <domain>", "A / AAAA / MX / NS / TXT / CNAME + reverse"],
    ["whois <domain|ip>", "native WHOIS lookup"],
    ["headers <url>", "HTTP status + security-header check"],
    ["cert <host>", "TLS certificate inspector"],
    ["subs <domain>", "passive subdomain enum (crt.sh)"],
    ["cve <keyword | CVE-id>", "search the NVD vulnerability database"],
    ["fuzz <url> [wordlist]", "directory / content brute-forcer"],
    ["nmap <host> [args]", "system nmap wrapper (falls back to the native scanner)"],
    ["nuclei <target> [args]", "run projectdiscovery nuclei templates (if installed)"],
    ["subrecon <domain>", "chained recon: subs → resolve → live-HTTP probe"],
  ] },
  { title: "Offensive", rows: [
    ["revshell <lang> <ip> <port>", "reverse-shell one-liner"],
    ["serve [port] [dir]", "HTTP file server for payload delivery (default 8000)"],
    ["listen [port]", "TCP listener to catch a reverse shell (default 4444)"],
    ["payloads [class]", "payload library (sqli, xss, lfi, cmdi, ssti, ssrf)"],
    ["hashcat <hashfile> <mode> [wl]", "hashcat runner (run with no mode for the mode list)"],
    ["lab [doctor|up <t>|sandbox|down|<id>]", "security lab: isolated vulnerable targets + malware-detonation sandbox"],
  ] },
  { title: "Encoding & hashing", rows: [
    ["encode <b64|hex|url|base32> <text>", "encode text"],
    ["decode <b64|hex|url|base32> <text>", "decode text"],
    ["hash <text>", "md5 / sha1 / sha256 / sha512"],
    ["hashfile <file>", "md5 / sha1 / sha256 / sha512 of a file"],
    ["hashid <hash>", "identify a hash type"],
    ["genpass [length]", "generate a strong random password (default 20)"],
    ["defang <ioc>", "neutralize a URL/IP/email for safe pasting (hxxp, [.])"],
    ["refang <text>", "reverse defang"],
  ] },
  { title: "Network & analysis", rows: [
    ["entropy <string>", "Shannon entropy — flag high-entropy secrets/keys"],
    ["epoch [ts|date]", "unix timestamp <-> ISO/UTC (no arg = now)"],
    ["incidr <ip> <cidr>", "is an IP inside a CIDR range? (firewall/allowlist checks)"],
    ["port <number|service>", "port <-> service lookup (both directions)"],
    ["passphrase [count]", "memorable diceware passphrase (default 4 words)"],
    ["url <url>", "break a URL into scheme/host/port/path/query/fragment"],
    ["totp <base32-secret>", "generate a 2FA (TOTP) code from a secret"],
    ["useragent <ua-string>", "parse a User-Agent (browser / OS / device / bot)"],
    ["cidr <a.b.c.d/xx>", "subnet calculator (range, hosts, mask)"],
    ["jwt <token>", "decode a JWT header + payload"],
    ["dorks <domain>", "print Google dork search URLs for a domain"],
    ["uuid", "generate a random UUID v4"],
    ["myip", "show your public IP address"],
    ["ipinfo <ip>", "geolocate an IP (city, ISP, ASN)"],
    ["status <code>", "look up an HTTP status code"],
  ] },
  { title: "Git", rows: [
    ["git clone <url>", "clone a repo (SENTINEL_GH_TOKEN for private)"],
    ["git push [message]", "commit all changes + push"],
    ["git pull", "pull the latest changes"],
    ["git status", "working-tree status"],
    ["git log", "recent commits"],
    ["git diff [file]", "working-tree diff"],
    ["git branch", "list branches"],
    ["git checkout <branch>", "switch branch"],
    ["git repos", "list your repositories"],
    ["git new <name>", "create a private repo"],
    ["git issues <owner/repo>", "list open issues"],
    ["git prs <owner/repo>", "list open pull requests"],
    ["git issue <owner/repo> \"title\"", "create an issue"],
    ["git pr \"title\" [base]", "open a PR from the current branch"],
    ["git comment <owner/repo> <n> \"…\"", "comment on an issue/PR"],
    ["git gists", "list your gists"],
    ["git gist <file> [description]", "create a gist from a file"],
  ] },
  { title: "Reference", rows: [
    ["cheats [topic]", "__CHEATS__"],
    ["tools", "tool catalog + install commands"],
  ] },
];

// The leading verbs of every documented command — the set a drift test checks the
// dispatch against. "git clone" -> "git", "nexus run ..." -> "nexus", etc.
function documentedVerbs() {
  const set = new Set();
  for (const g of COMMAND_GROUPS) for (const [left] of g.rows) set.add(left.split(/\s+/)[0]);
  return set;
}

// renderCommands(groups, { color, cheats }) -> the text body of the COMMANDS section.
// color: fn to style a group title (identity if omitted). cheats: string that
// replaces the "__CHEATS__" token. Column math matches the original hand-spacing:
// left cell padded to at least 34 chars, always >= 2 spaces before the summary.
function renderCommands(groups, opts) {
  opts = opts || {};
  const color = typeof opts.color === "function" ? opts.color : (s) => s;
  const cheats = opts.cheats != null ? String(opts.cheats) : "";
  const out = [];
  groups.forEach((g, gi) => {
    if (gi > 0) out.push("");
    out.push("    " + color(g.title));
    for (const [left, rightRaw] of g.rows) {
      const right = rightRaw === "__CHEATS__" ? cheats : rightRaw;
      out.push("    " + left.padEnd(Math.max(34, left.length + 2)) + right);
    }
  });
  return out.join("\n");
}

module.exports = { COMMAND_GROUPS, documentedVerbs, renderCommands };
