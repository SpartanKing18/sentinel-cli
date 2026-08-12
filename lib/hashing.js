"use strict";
// Hashing + password generation core. Pure computation, no coloring — sentinel.js
// wraps digests() with color for display. Extracted so both the CLI and the
// interactive menu share one implementation and it can be unit-tested.
const crypto = require("crypto");

const ALGOS = ["md5", "sha1", "sha256", "sha512"];

// digests(s) -> [["md5", hex], ["sha1", hex], ["sha256", hex], ["sha512", hex]]
function digests(s) {
  return ALGOS.map((a) => [a, crypto.createHash(a).update(String(s == null ? "" : s)).digest("hex")]);
}

const GENPASS_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

// genPass(len, rngBytes?) -> a random password of length clamped to [8, 128]
// (default 20). rngBytes(n) -> Buffer|Uint8Array of n bytes; defaults to
// crypto.randomBytes but is injectable so tests are deterministic.
function genPass(len, rngBytes) {
  len = Math.max(8, Math.min(128, parseInt(len, 10) || 20));
  const bytes = (typeof rngBytes === "function" ? rngBytes : crypto.randomBytes)(len);
  let out = "";
  for (let i = 0; i < len; i++) out += GENPASS_CHARS[bytes[i] % GENPASS_CHARS.length];
  return out;
}

module.exports = { ALGOS, GENPASS_CHARS, digests, genPass };
