"use strict";
// Base32 (RFC 4648) encode/decode. Handy for TOTP/2FA secrets and DNS-exfil
// analysis. Pure; encode->decode round-trips. Verified against RFC test vectors.
const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32encode(input) {
  const bytes = Buffer.from(String(input == null ? "" : input), "utf8");
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += ALPHA[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += ALPHA[(value << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += "=";
  return out;
}
// Decode base32 to raw bytes (Buffer), or null on an invalid character.
function base32ToBytes(input) {
  const s = String(input == null ? "" : input).toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0, value = 0; const out = [];
  for (const ch of s) {
    const idx = ALPHA.indexOf(ch);
    if (idx === -1) return null; // invalid base32 character
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function base32decode(input) { const b = base32ToBytes(input); return b === null ? null : b.toString("utf8"); }
module.exports = { base32encode, base32decode, base32ToBytes };
