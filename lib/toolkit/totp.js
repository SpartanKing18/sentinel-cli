"use strict";
// TOTP / HOTP (RFC 4226 / 6238) — generate 2FA codes from a base32 secret. Pure
// crypto (HMAC-SHA1 by default); deterministic given the counter/time, so it's
// verified against the RFC 6238 test vectors.
const crypto = require("crypto");
const { base32ToBytes } = require("./base32");

function hotp(keyBytes, counter, digits, algo) {
  digits = digits || 6;
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac(algo || "sha1", keyBytes).update(buf).digest();
  const offset = h[h.length - 1] & 0xf;
  const bin = ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
  return (bin % Math.pow(10, digits)).toString().padStart(digits, "0");
}
// totp(base32Secret, { time, step, digits, algo }) -> code string, or null if the
// secret isn't valid base32. `time` defaults to now (seconds); pass it for testing.
function totp(base32Secret, opts) {
  opts = opts || {};
  const key = base32ToBytes(String(base32Secret || "").trim());
  if (!key || key.length === 0) return null;
  const step = opts.step || 30;
  const time = opts.time != null ? opts.time : Math.floor(Date.now() / 1000);
  return hotp(key, Math.floor(time / step), opts.digits || 6, opts.algo);
}
// Seconds remaining in the current step (for a countdown display).
function secondsRemaining(step, time) { step = step || 30; time = time != null ? time : Math.floor(Date.now() / 1000); return step - (time % step); }
module.exports = { hotp, totp, secondsRemaining };
