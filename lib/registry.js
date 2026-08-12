"use strict";
// Data-driven command registry — batch 1. Replaces a handful of the flat else-if
// branches in sentinel.js with table entries. Each entry is { name, aliases?,
// run(ctx) } where ctx = { rest, c } and c is the CLI's color-helper set
// ({ red, green, yellow, cyan, gray, bold }). run() RETURNS the exact string the
// old inline branch passed to console.log — migrated verbatim, so output is
// byte-identical (colors come from the same helpers, honoring NO_COLOR). Only
// single-console.log, deterministic handlers are migrated here; the rest stay
// inline until they can be moved just as safely.
const { defang, refang } = require("./ioc");
const { assess: entropyAssess } = require("./entropy");
const { inCidr, idHash } = require("./scanutil");

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
];

const CMD_MAP = {};
for (const cmd of CMDS) { CMD_MAP[cmd.name] = cmd; (cmd.aliases || []).forEach((a) => { CMD_MAP[a] = cmd; }); }

module.exports = { CMDS, CMD_MAP };
