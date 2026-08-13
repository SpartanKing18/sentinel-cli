"use strict";
// JWT decode + analysis — decode header/payload, evaluate validity window
// (exp/nbf), and flag the alg:none vulnerability. Pure; no signature verification
// (we don't have the key), so it never claims a token is authentic.
function b64urlJson(x) {
  try { return JSON.parse(Buffer.from(String(x).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")); }
  catch (_) { return null; }
}
function decodeJwt(token) {
  const parts = String(token || "").trim().split(".");
  if (parts.length < 2) return null;
  const header = b64urlJson(parts[0]), payload = b64urlJson(parts[1]);
  if (!header || !payload || typeof payload !== "object") return null;
  return { header, payload, signature: parts[2] || "" };
}
// analyzeJwt(token, now?) -> { header, payload, signature, alg, state, expired?, notYetValid?, exp?, iat?, nbf?, warnings[] } or null
function analyzeJwt(token, now) {
  const d = decodeJwt(token);
  if (!d) return null;
  now = now != null ? now : Math.floor(Date.now() / 1000);
  const p = d.payload, out = { header: d.header, payload: p, signature: d.signature, alg: d.header.alg || "?", warnings: [] };
  if (typeof p.exp === "number") { out.exp = p.exp; out.expired = now >= p.exp; }
  if (typeof p.iat === "number") out.iat = p.iat;
  if (typeof p.nbf === "number") { out.nbf = p.nbf; if (now < p.nbf) out.notYetValid = true; }
  out.state = out.expired ? "expired" : out.notYetValid ? "not-yet-valid" : (typeof p.exp === "number" ? "valid" : "no-exp");
  if (String(out.alg).toLowerCase() === "none") out.warnings.push("alg=none — signature not verified; a classic JWT bypass vector");
  return out;
}
module.exports = { decodeJwt, analyzeJwt };
