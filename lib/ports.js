"use strict";
// Common port <-> service map + bidirectional lookup. Shared by the scanner (which
// labels open ports) and `sentinel port`. Pure/tested.
const SERVICES = { 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp", 4444: "metasploit", 5432: "postgres", 5601: "kibana", 5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9200: "elastic", 11211: "memcached", 27017: "mongodb" };
function portName(n) { return SERVICES[n] || null; }
function findByName(name) { name = String(name || "").toLowerCase(); if (!name) return []; return Object.keys(SERVICES).filter((p) => SERVICES[p].toLowerCase().includes(name)).map(Number).sort((a, b) => a - b); }
// portLookup("3306") -> { kind:"port", port, service } ; portLookup("mysql") -> { kind:"name", name, ports:[...] } ; null if empty
function portLookup(query) {
  const q = String(query == null ? "" : query).trim();
  if (!q) return null;
  if (/^\d+$/.test(q)) { const n = +q; return { kind: "port", port: n, service: SERVICES[n] || null }; }
  return { kind: "name", name: q, ports: findByName(q) };
}
module.exports = { SERVICES, portName, findByName, portLookup };
