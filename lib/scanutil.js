"use strict";
// Security-console core logic — pure and testable. Kept out of the CLI monolith so
// the parts where a bug actually matters (which ports get scanned, hash identity,
// CVE parsing) are covered by the test suite.

// The default "top ports" scanned when no explicit spec is given.
const TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 4444, 5432, 5601, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017];

// Parse a port spec: "top" (or empty) -> TOP_PORTS; "1-1024" -> a range; "80,443" -> a list.
function parsePorts(spec) {
  if (!spec || spec === "top") return TOP_PORTS;
  const m = spec.match(/^(\d+)-(\d+)$/);
  if (m) { const a = []; for (let i = +m[1]; i <= +m[2]; i++) a.push(i); return a; }
  return spec.split(",").map(Number).filter((n) => n > 0 && n < 65536);
}

// Identify a hash's likely type from its shape.
function idHash(h) {
  h = h.trim();
  if (/^\$2[aby]\$/.test(h)) return "bcrypt";
  if (/^\$6\$/.test(h)) return "sha512crypt"; if (/^\$1\$/.test(h)) return "md5crypt";
  if (/^[a-f0-9]{32}$/i.test(h)) return "MD5 or NTLM (-m 0 / -m 1000)";
  if (/^[a-f0-9]{40}$/i.test(h)) return "SHA-1 (-m 100)";
  if (/^[a-f0-9]{64}$/i.test(h)) return "SHA-256 (-m 1400)";
  if (/^[a-f0-9]{128}$/i.test(h)) return "SHA-512 (-m 1700)";
  return "unknown";
}

// Reduce an NVD CVE API object down to the fields we display.
function parseCve(v) {
  const c = v.cve, desc = (c.descriptions.find((d) => d.lang === "en") || c.descriptions[0] || {}).value || "";
  const m = c.metrics || {}, p = m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2;
  const score = p && p[0] ? p[0].cvssData.baseScore : "", sev = p && p[0] ? (p[0].cvssData.baseSeverity || p[0].baseSeverity || "") : "";
  return { id: c.id, desc, score, sev, published: (c.published || "").slice(0, 10) };
}
// Subnet calculator: "a.b.c.d/xx" -> { network, broadcast, netmask, first/lastUsable, hosts } or null.
function cidrCalc(input) {
  const m = String(input || "").trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const ip = m[1].split(".").map(Number), bits = +m[2];
  if (ip.some((o) => o > 255) || bits > 32) return null;
  const ipn = (((ip[0] << 24) >>> 0) + (ip[1] << 16) + (ip[2] << 8) + ip[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net_ = (ipn & mask) >>> 0, bc = (net_ | (~mask >>> 0)) >>> 0;
  const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const hosts = bits >= 31 ? (bits === 32 ? 1 : 2) : (bc - net_ - 1);
  return { bits, network: toIp(net_), broadcast: toIp(bc), netmask: toIp(mask), firstUsable: toIp(bits >= 31 ? net_ : net_ + 1), lastUsable: toIp(bits >= 31 ? bc : bc - 1), hosts };
}
module.exports = { TOP_PORTS, parsePorts, idHash, parseCve, cidrCalc };
