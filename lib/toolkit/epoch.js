"use strict";
// Timestamp converter — unix epoch <-> ISO/UTC, both directions, auto-detecting the
// input. Deterministic (UTC, no wall-clock), so it's fully testable.

// Detect the input: all-digits -> epoch (10-digit-ish = seconds, 12+ = milliseconds);
// otherwise parse as a date string. Returns { kind, ms } or null.
function detect(input) {
  const s = String(input || "").trim();
  if (/^\d+$/.test(s)) { const n = Number(s); return { kind: "epoch", ms: s.length >= 12 ? n : n * 1000 }; }
  const t = Date.parse(s);
  if (!Number.isNaN(t)) return { kind: "date", ms: t };
  return null;
}
// Convert any accepted input to a normalized set of representations, or null.
function convert(input) {
  const d = detect(input);
  if (!d) return null;
  const dt = new Date(d.ms);
  return { from: d.kind, epochSeconds: Math.floor(d.ms / 1000), epochMs: d.ms, iso: dt.toISOString(), utc: dt.toUTCString() };
}
module.exports = { detect, convert };
