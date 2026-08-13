"use strict";
// User-Agent parser — identify browser, OS, device class, and whether it's a bot.
// Heuristic (UA strings are famously messy) but covers the common cases; pure/tested.
// Order matters: more specific patterns first (Edge/Opera before Chrome; Chrome
// before Safari, since Chrome's UA also contains "Safari").
const BROWSERS = [
  [/Edg(?:e|iOS|A)?\/([\d.]+)/, "Edge"],
  [/OPR\/([\d.]+)|Opera\/([\d.]+)/, "Opera"],
  [/Firefox\/([\d.]+)/, "Firefox"],
  [/Chrome\/([\d.]+)/, "Chrome"],
  [/Version\/([\d.]+).*Safari/, "Safari"],
  [/MSIE ([\d.]+)|Trident.*rv:([\d.]+)/, "Internet Explorer"],
  [/curl\/([\d.]+)/, "curl"],
  [/Wget\/([\d.]+)/, "Wget"],
  [/python-requests\/([\d.]+)/, "python-requests"],
];
const OSES = [
  [/Windows NT 10\.0/, "Windows 10/11"],
  [/Windows NT 6\.3/, "Windows 8.1"],
  [/Windows NT 6\.1/, "Windows 7"],
  [/Windows/, "Windows"],
  [/Android ([\d.]+)/, "Android"],
  [/(?:iPhone|iPad).*OS ([\d_]+)/, "iOS"],
  [/Mac OS X ([\d_]+)/, "macOS"],
  [/CrOS/, "ChromeOS"],
  [/Linux/, "Linux"],
];
function parseUA(ua) {
  ua = String(ua == null ? "" : ua);
  if (!ua.trim()) return null;
  let browser = "unknown", version = "";
  for (const [re, name] of BROWSERS) { const m = ua.match(re); if (m) { browser = name; version = m[1] || m[2] || ""; break; } }
  let os = "unknown";
  for (const [re, name] of OSES) { const m = ua.match(re); if (m) { os = name + (m[1] ? " " + m[1].replace(/_/g, ".") : ""); break; } }
  const bot = /bot\b|crawler|spider|slurp|bingpreview|facebookexternalhit|curl|wget|python-requests|go-http|axios|headless|monitoring/i.test(ua);
  const mobile = /Mobile|Android|iPhone|iPad|iPod/i.test(ua);
  return { browser, version, os, device: mobile ? "mobile" : "desktop", bot };
}
module.exports = { parseUA };
