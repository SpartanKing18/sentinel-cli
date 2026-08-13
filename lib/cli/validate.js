"use strict";
// Config validation — catch a malformed .nexus/policy.json or team.json early and
// tell the operator exactly what's wrong, instead of silently ignoring fields.
// Returns an array of human-readable warning strings ([] = valid). Pure/testable.
function validatePolicy(obj) {
  if (obj == null || typeof obj !== "object" || Array.isArray(obj)) return ["policy must be a JSON object"];
  const w = [];
  for (const f of ["protectedPaths", "deniedCommands", "requireApprovalPaths"]) if (obj[f] !== undefined && !Array.isArray(obj[f])) w.push(f + " must be an array of strings");
  for (const f of ["blockSecrets", "allowNetwork", "audit"]) if (obj[f] !== undefined && typeof obj[f] !== "boolean") w.push(f + " must be true or false");
  if (obj.maxFilesPerTurn !== undefined && (typeof obj.maxFilesPerTurn !== "number" || obj.maxFilesPerTurn < 0)) w.push("maxFilesPerTurn must be a number >= 0");
  for (const rs of (Array.isArray(obj.deniedCommands) ? obj.deniedCommands : [])) { try { new RegExp(rs); } catch (_) { w.push("deniedCommands: invalid regex " + JSON.stringify(rs)); } }
  return w;
}
function validateTeam(obj, knownEngines) {
  if (obj == null || typeof obj !== "object" || Array.isArray(obj)) return ["team config must be a JSON object"];
  const w = [];
  if (obj.roles !== undefined) {
    if (!Array.isArray(obj.roles)) w.push("roles must be an array");
    else obj.roles.forEach((r, i) => {
      if (r == null || typeof r !== "object") { w.push("roles[" + i + "] must be an object"); return; }
      if (!r.role) w.push("roles[" + i + "] is missing 'role'");
      if (!r.engine) w.push("roles[" + i + "] is missing 'engine'");
      else if (knownEngines && knownEngines.length && !knownEngines.includes(r.engine)) w.push("roles[" + i + "]: unknown engine '" + r.engine + "'");
    });
  }
  if (obj.maxRounds !== undefined && (typeof obj.maxRounds !== "number" || obj.maxRounds < 1)) w.push("maxRounds must be a number >= 1");
  return w;
}
module.exports = { validatePolicy, validateTeam };
