"use strict";
// Data-driven command registry. Replaces the flat else-if branches in sentinel.js
// for every string-returning command with table entries. Each entry is
// { name, aliases?, run(ctx) } where ctx = { rest, c } and c is the CLI's
// color-helper set ({ red, green, yellow, cyan, gray, bold }). run() RETURNS the
// string the old inline branch passed to console.log (multi-line = arr.join("\n"),
// h1 rebuilt via mkH1) — migrated verbatim, so output is byte-identical (colors
// come from the same helpers, honoring NO_COLOR). Covers pure/deterministic tools
// plus the random string generators (uuid, passphrase); the remaining inline
// commands are async/network, time-based, or menu-shared and are not registry fits.
const crypto = require("crypto");
const { defang, refang } = require("./ioc");
const { assess: entropyAssess } = require("./entropy");
const { inCidr, idHash } = require("./scanutil");
const { portLookup, SERVICES } = require("./ports");
const { parseUrl } = require("./urlparse");
const { parseUA } = require("./useragent");
const { cidrCalc } = require("./scanutil");
const { convert: epochConvert } = require("./epoch");
const { analyzeJwt } = require("./jwt");
const { revshell } = require("./revshell");
const { statusInfo } = require("./httpstatus");
const { DORK_BASE, dorkUrls } = require("./dorks");
const { CHEATS } = require("./cheats");
const { ENC } = require("./encoders");
const { genPassphrase, passphraseBits } = require("./passphrase");

// encode/decode share one transform: op = "<type><e|d>". Plain output (no color),
// matching the original CLI branch.
function encDec(rest, dir) { const [type, ...v] = rest; const fn = ENC[(type || "") + dir]; return fn ? fn(v.join(" ")) : "unknown type (b64|hex|url|base32)"; }

// Rebuild the CLI's h1 header as a STRING (h1() itself prints; here we need the
// text so a multi-line run() can console.log the whole block at once). Matches
// sentinel.js h1(): "\n  " + bold(cyan("▌ " + t)) + "\n".
const mkH1 = (c) => (t) => "\n  " + c.bold(c.cyan("▌ " + t)) + "\n";

const CMDS = [
  { name: "defang", run: ({ rest, c }) => { const t = rest.join(" "); return t ? defang(t) : c.red("usage: sentinel defang <url|ip|email>  — neutralize an IOC for safe pasting"); } },
  { name: "refang", run: ({ rest, c }) => { const t = rest.join(" "); return t ? refang(t) : c.red("usage: sentinel refang <defanged text>  — reverse defang"); } },
  { name: "entropy", run: ({ rest, c }) => {
    const t = rest.join(" ");
    if (!t) return c.red("usage: sentinel entropy <string>  — Shannon entropy (flags likely secrets)");
    const a = entropyAssess(t);
    const col = a.level === "high" ? c.red : a.level === "medium" ? c.yellow : c.green;
    return "  " + col(a.bitsPerChar.toFixed(2) + " bits/char") + c.gray("  ·  " + a.totalBits.toFixed(0) + " bits over " + a.length + " chars  ·  ") + col(a.level) + (a.likelySecret ? c.red("  (likely a secret/key)") : "");
  } },
  { name: "incidr", aliases: ["inrange"], run: ({ rest, c }) => {
    const r = inCidr(rest[0], rest[1]);
    if (r === null) return c.red("usage: sentinel incidr <ip> <cidr>   e.g. sentinel incidr 10.0.0.5 10.0.0.0/24");
    return r ? c.green("  yes") + c.gray(" — " + rest[0] + " is inside " + rest[1]) : c.red("  no") + c.gray(" — " + rest[0] + " is NOT inside " + rest[1]);
  } },
  { name: "hashid", run: ({ rest }) => idHash(rest.join(" ")) },
  { name: "port", run: ({ rest, c }) => {
    const r = portLookup(rest[0]);
    if (!r) return c.red("usage: sentinel port <number|service>   e.g. sentinel port 3306  ·  sentinel port redis");
    if (r.kind === "port") return "  " + c.bold(c.cyan(String(r.port))) + "  " + (r.service ? r.service : c.gray("no well-known service"));
    if (!r.ports.length) return "  " + c.gray("no well-known port matches ") + r.name;
    return r.ports.map((p) => "  " + c.bold(c.cyan(String(p))).padEnd(20) + SERVICES[p]).join("\n");
  } },
  { name: "url", run: ({ rest, c }) => {
    const u = parseUrl(rest.join(" "));
    if (!u) return c.red("usage: sentinel url <url>   e.g. sentinel url https://host.com:8443/a?x=1#f");
    const lines = [mkH1(c)("URL")];
    const row = (k, v) => { if (v !== "" && v != null) lines.push("  " + k.padEnd(10) + c.cyan(v)); };
    row("scheme", u.scheme); row("host", u.host); row("port", u.port); row("path", u.path); row("fragment", u.fragment);
    if (u.username) row("user", u.username);
    if (u.password) row("pass", u.password);
    const keys = Object.keys(u.params);
    if (keys.length) { lines.push("  " + c.gray("query params:")); keys.forEach((k) => lines.push("    " + k.padEnd(14) + c.cyan(u.params[k]))); }
    lines.push("");
    return lines.join("\n");
  } },
  { name: "useragent", aliases: ["ua"], run: ({ rest, c }) => {
    const u = parseUA(rest.join(" "));
    if (!u) return c.red("usage: sentinel useragent <ua-string>   — parse browser/OS/device");
    const lines = [mkH1(c)("User-Agent")];
    const row = (k, v) => lines.push("  " + k.padEnd(9) + v);
    row("browser", c.cyan(u.browser + (u.version ? " " + u.version : "")));
    row("os", c.cyan(u.os));
    row("device", u.device);
    row("bot", u.bot ? c.yellow("yes") : "no");
    lines.push("");
    return lines.join("\n");
  } },
  { name: "cidr", run: ({ rest, c }) => {
    const cc = cidrCalc(rest[0]);
    if (!cc) return c.red("usage: sentinel cidr 192.168.1.0/24");
    return [mkH1(c)("CIDR " + rest[0]),
      "  Network    " + c.cyan(cc.network),
      "  Broadcast  " + c.cyan(cc.broadcast),
      "  Netmask    " + cc.netmask,
      "  Usable     " + cc.firstUsable + "  -  " + cc.lastUsable,
      "  Hosts      " + c.green(String(cc.hosts))].join("\n");
  } },
  { name: "epoch", aliases: ["time", "ts"], run: ({ rest, c }) => {
    const t = rest.join(" ").trim() || String(Math.floor(Date.now() / 1000));
    const cc = epochConvert(t);
    if (!cc) return c.red("usage: sentinel epoch <unix-ts | ISO date>   (no arg = now)");
    return [mkH1(c)("timestamp  (" + cc.from + ")"),
      "  epoch (s)   " + c.cyan(String(cc.epochSeconds)),
      "  epoch (ms)  " + String(cc.epochMs),
      "  ISO 8601    " + c.cyan(cc.iso),
      "  UTC         " + cc.utc + "\n"].join("\n");
  } },
  { name: "jwt", run: ({ rest, c }) => {
    const a = analyzeJwt(rest[0]);
    if (!a) return c.red("not a valid JWT (expected header.payload[.signature])");
    const lines = [mkH1(c)("JWT"),
      c.gray("// header"), JSON.stringify(a.header, null, 2),
      c.gray("\n// payload"), JSON.stringify(a.payload, null, 2)];
    const humanT = (t) => { const cc = epochConvert(String(t)); return cc ? cc.iso.replace(/\.000Z$/, "Z") : String(t); };
    const times = []; if (a.iat != null) times.push("iat " + humanT(a.iat)); if (a.nbf != null) times.push("nbf " + humanT(a.nbf)); if (a.exp != null) times.push("exp " + humanT(a.exp));
    if (times.length) lines.push(c.gray("\n// times: ") + times.join(c.gray("  ·  ")));
    const sc = (a.state === "expired" || a.state === "not-yet-valid") ? c.red : a.state === "valid" ? c.green : c.gray;
    lines.push("\n  status: " + sc(a.state.toUpperCase()) + c.gray("   (signature NOT verified — no key)"));
    for (const w of a.warnings) lines.push("  " + c.yellow("warning: " + w));
    if (a.signature) lines.push(c.gray("\nsignature: ") + a.signature);
    return lines.join("\n");
  } },
  { name: "revshell", run: ({ rest }) => { const [lang = "bash", ip = "10.0.0.1", port = "4444"] = rest; return revshell(lang, ip, port); } },
  { name: "status", run: ({ rest, c }) => {
    const info = statusInfo(rest[0]);
    if (!info) return c.red("unknown status code (try 200, 404, 500...)");
    return c.bold(c.cyan(info.code)) + " " + info.text + (info.class ? c.gray("  · " + info.class) : "");
  } },
  { name: "dorks", run: ({ rest, c }) => {
    const domain = rest[0];
    if (!domain) return c.red("usage: sentinel dorks example.com");
    const lines = [mkH1(c)("Google dorks for " + domain)];
    dorkUrls(domain).forEach((d) => { lines.push("  " + c.bold(d.label)); lines.push("  " + c.gray(DORK_BASE) + d.encoded + "\n"); });
    return lines.join("\n");
  } },
  { name: "cheats", run: ({ rest }) => { const t = rest[0]; return (t && CHEATS[t]) ? CHEATS[t].join("\n") : "topics: " + Object.keys(CHEATS).join(", "); } },
  { name: "encode", run: ({ rest }) => encDec(rest, "e") },
  { name: "decode", run: ({ rest }) => encDec(rest, "d") },
  { name: "uuid", run: () => crypto.randomUUID() },
  { name: "passphrase", run: ({ rest, c }) => { const n = /^\d+$/.test(rest[0] || "") ? +rest[0] : 4; return "  " + c.bold(c.cyan(genPassphrase(n))) + "  " + c.gray("(~" + passphraseBits(n) + " bits)"); } },
];

const CMD_MAP = {};
for (const cmd of CMDS) { CMD_MAP[cmd.name] = cmd; (cmd.aliases || []).forEach((a) => { CMD_MAP[a] = cmd; }); }

module.exports = { CMDS, CMD_MAP };
