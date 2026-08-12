"use strict";
// Shannon entropy — measure the randomness of a string (bits per character). High
// entropy over a reasonable length flags likely secrets/keys/tokens; low entropy
// flags predictable values. Pure and tested.
function shannon(s) {
  s = String(s || "");
  if (!s.length) return 0;
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0; const n = s.length;
  for (const k in freq) { const p = freq[k] / n; e -= p * Math.log2(p); }
  return e; // bits per character (0 .. log2(alphabet size))
}
// Assess a string: entropy per char, total bits, and a coarse level. "high" over a
// decent length is the tell for a random secret; "low" is a predictable value.
function assess(s) {
  s = String(s || "");
  const bpc = shannon(s), totalBits = bpc * s.length;
  let level = "low";
  if (bpc >= 3.5 && s.length >= 16) level = "high"; // real 32-char hex/base64 tokens land ~3.6-4.3
  else if (bpc >= 3) level = "medium";
  return { length: s.length, bitsPerChar: bpc, totalBits, level, likelySecret: level === "high" };
}
module.exports = { shannon, assess };
