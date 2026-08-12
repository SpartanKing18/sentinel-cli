"use strict";
// Output styles (a Claude Code idea): a named directive injected into the engine's
// system prompt to shape HOW it works, independent of the task. Pure/testable.
const STYLES = {
  default: "",
  concise: "Be concise: minimal output, no preamble or recap, prefer code over prose.",
  explanatory: "Explain your reasoning and key decisions as you go, and call out trade-offs.",
  review: "Act as a critical senior reviewer: surface bugs, edge cases, and security/performance issues; be specific and cite lines.",
  tdd: "Practice test-driven development: write or update tests FIRST, then implement until they pass; do not skip the tests.",
  secure: "Prioritize security: validate all inputs, avoid injection, never hardcode secrets, and flag any risky operation before doing it.",
  teacher: "Explain like a mentor: define unfamiliar terms briefly and note why an approach is chosen, without being verbose.",
};
function styleNames() { return Object.keys(STYLES); }
function styleDirective(name) { return STYLES[name] || ""; }
module.exports = { STYLES, styleNames, styleDirective };
