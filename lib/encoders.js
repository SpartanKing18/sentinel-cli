"use strict";
// Encode/decode operations keyed by op ("<type><e|d>"), e.g. b64e / b64d / hexe /
// hexd / urle / urld / base32e / base32d. Pure string transforms — shared by the
// CLI `encode`/`decode` commands and the interactive menu, and unit-tested here.
// Extracted from sentinel.js.
const { base32encode, base32decode } = require("./base32");

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

module.exports = { ENC };
