"use strict";
// Small pure text helpers used throughout the CLI/agent. Dependency-free, tested.

// Collapse whitespace to single spaces and truncate to n chars with an ellipsis.
function oneline(s, n) { s = String(s || "").replace(/\s+/g, " ").trim(); return s.length > (n || 44) ? s.slice(0, (n || 44) - 1) + "…" : s; }

// Pull the first JSON array or object out of noisy model text; fallback on failure.
function extractJson(text, fallback) {
  const s = String(text || ""); const arr = s.match(/\[[\s\S]*\]/), obj = s.match(/\{[\s\S]*\}/);
  for (const m of [arr, obj]) if (m) { try { return JSON.parse(m[0]); } catch (_) {} }
  return fallback;
}
module.exports = { oneline, extractJson };
