"use strict";
// Data-driven settings schema — the single source of truth for the /settings panel.
// Each item knows how to read its current value from a plain state snapshot and which
// command changes it, so the UI stays a neat, categorized render of this structure.
const SETTINGS = [
  { group: "Model", items: [
    { label: "Engine", cmd: "/engine <name>", get: (v) => v.engine },
    { label: "Model", cmd: "/model <name>", get: (v) => v.model || "engine default" },
    { label: "Thinking effort", cmd: "/effort low|medium|high", get: (v) => v.effort || "default" },
    { label: "Fallback model", cmd: "/fallback <model>", get: (v) => v.fallback || "off" },
  ] },
  { group: "Output", items: [
    { label: "Output style", cmd: "/style <name>", get: (v) => v.style || "default" },
    { label: "Lean output", cmd: "/lean", get: (v) => (v.lean ? "on" : "off") },
  ] },
  { group: "Cost", items: [
    { label: "Cowork (strong+weak)", cmd: "/cowork <strong> <weak>", get: (v) => (v.cowork && v.cowork.on ? v.cowork.strong + " -> " + v.cowork.weak : "off") },
    { label: "Budget cap", cmd: "/budget <usd>", get: (v) => (v.costCap ? "$" + Number(v.costCap).toFixed(2) : "none") },
    { label: "Spent this session", cmd: "/cost", get: (v) => "$" + Number(v.cost || 0).toFixed(4) },
  ] },
  { group: "Safety & policy", items: [
    { label: "Permission mode", cmd: "shift+tab", get: (v) => v.mode || "auto-accept" },
    { label: "Command guard", cmd: "/guard enforce|warn|off", get: (v) => v.guard || "enforce" },
    { label: "Security policy", cmd: "/policy", get: (v) => (v.policyOrg ? "org-enforced" : "local/default") },
    { label: "Audit trail", cmd: "/audit verify", get: (v) => (v.audit ? "on (hash-chained)" : "off") },
  ] },
  { group: "Privacy", items: [
    { label: "Redact secrets to cloud", cmd: "/redact", get: (v) => (v.redact ? "on" : "off") },
    { label: "Offline lock", cmd: "/offline", get: (v) => (v.offline ? "on" : "off") },
  ] },
  { group: "Session", items: [
    { label: "Desktop notify", cmd: "/notify", get: (v) => (v.notify ? "on" : "off") },
    { label: "Context used", cmd: "/context", get: (v) => (v.ctxPct == null ? "-" : v.ctxPct + "%") },
    { label: "Pinned files", cmd: "/pin <file>", get: (v) => String(v.pins || 0) },
    { label: "Background jobs", cmd: "/jobs", get: (v) => String(v.bgRunning || 0) + " running" },
  ] },
];
// -> [{ group, rows: [{ label, value, cmd }] }]
function describe(v) {
  v = v || {};
  return SETTINGS.map((g) => ({ group: g.group, rows: g.items.map((it) => ({ label: it.label, value: String(it.get(v)), cmd: it.cmd })) }));
}
module.exports = { SETTINGS, describe };
