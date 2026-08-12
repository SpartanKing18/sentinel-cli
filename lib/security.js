"use strict";
// Security utilities — pure, dependency-free, unit-tested (test/run.js).
//  - scanSecrets:    detect credentials in text (block/flag before writing)
//  - maskSecrets:    redact them before text is sent to a cloud engine
//  - classifyDanger: Sentinel preflight — rate a shell command's destructive intent
//  - compactOutput:  head+tail trim of long tool output to save tokens

function scanSecrets(text) {
  const s = String(text || ""), pats = [
    [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key id"],
    [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, "private key"],
    [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/, "GitHub token"],
    [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, "Slack token"],
    [/\bsk-[A-Za-z0-9]{20,}\b/, "OpenAI-style API key"],
    [/\bAIza[0-9A-Za-z_-]{35}\b/, "Google API key"],
    [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/, "JWT"],
    [/(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"\s]{6,}['"]/i, "hardcoded credential"],
  ];
  const hits = []; for (const [re, name] of pats) if (re.test(s)) hits.push(name);
  return [...new Set(hits)];
}
// Mask secrets before text is sent to a cloud engine (privacy layer).
function maskSecrets(text) {
  return String(text)
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, "[redacted:private-key]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[redacted:aws-key]")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "[redacted:github-token]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[redacted:slack-token]")
    .replace(/\bsk-[A-Za-z0-9]{20,}\b/g, "[redacted:api-key]")
    .replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, "[redacted:google-key]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g, "[redacted:jwt]");
}
// Sentinel preflight — classify a shell command's destructive intent.
function classifyDanger(cmd) {
  const c = String(cmd || "");
  const block = [
    [/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
    [/\brm\s+(-\S*\s+)*(\/(\s|$)|\/\*|~(\/|\s|$)|\$HOME\b|\/(etc|usr|var|boot|bin|lib|sys|dev|opt|root)\b)/i, "rm on a system/home path"],
    [/\bmkfs(\.\w+)?\b|\bdd\b[^\n]*\bof=\/dev\/|\b(wipefs|shred)\b|>\s*\/dev\/(sd|nvme|hd|mmcblk)/i, "writes/formats a raw disk"],
    [/\bgit\s+reset\s+--hard\b/i, "git reset --hard discards uncommitted work"],
    [/\bgit\s+push\b[^\n]*(--force(-with-lease)?\b|\s-f\b)/i, "git force-push"],
    [/\bgit\s+clean\s+-\S*f\S*d|\bgit\s+clean\s+-\S*d\S*f/i, "git clean -fd deletes untracked files"],
    [/\bchmod\s+-R\s+0*777\s+\//i, "chmod -R 777 on a root path"],
    [/\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python\d?)\b/i, "pipe-to-shell of a downloaded script"],
    [/\b(shutdown|reboot|halt|poweroff)\b|\binit\s+0\b/i, "powers off / reboots the machine"],
    [/\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b/i, "destructive SQL (DROP/TRUNCATE)"],
  ];
  for (const [re, why] of block) if (re.test(c)) return { level: "block", why };
  const warn = [
    [/(^|\s)sudo\s/i, "runs as root (sudo)"],
    [/\bgit\s+checkout\s+(--\s|\.\s*$|\.\s)/i, "git checkout discards local changes"],
    [/\brm\s+-\S*r\S*f|\brm\s+-\S*f\S*r|\brm\s+-\S*r\b/i, "recursive (force) delete"],
    [/\b(killall|pkill)\b/i, "kills processes by name"],
    [/\bnpm\s+publish\b|\bgit\s+push\b/i, "publishes / pushes"],
  ];
  for (const [re, why] of warn) if (re.test(c)) return { level: "warn", why };
  return { level: "ok" };
}
function compactOutput(text, max) { text = String(text || ""); max = max || 4000; if (text.length <= max) return text; const head = text.slice(0, Math.floor(max * 0.6)); const tail = text.slice(-Math.floor(max * 0.3)); return head + "\n… [" + (text.length - head.length - tail.length) + " chars trimmed to save tokens] …\n" + tail; }

module.exports = { scanSecrets, maskSecrets, classifyDanger, compactOutput };
