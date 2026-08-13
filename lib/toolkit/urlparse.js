"use strict";
// URL breakdown — split a URL into its parts (scheme, host, port, path, query
// params, fragment, credentials). Pure (uses the WHATWG URL parser). A scheme-less
// input like "example.com:8080/x" is treated as http so host/port parse correctly.
function parseUrl(input) {
  let s = String(input || "").trim();
  if (!s) return null;
  if (!/:\/\//.test(s) && !/^(mailto|tel|data|javascript|urn):/i.test(s)) s = "http://" + s;
  let u; try { u = new URL(s); } catch (_) { return null; }
  const params = {}; for (const [k, v] of u.searchParams) params[k] = v;
  return {
    scheme: u.protocol.replace(/:$/, ""),
    host: u.hostname,
    port: u.port || "",
    path: u.pathname,
    query: u.search.replace(/^\?/, ""),
    params,
    fragment: u.hash.replace(/^#/, ""),
    username: u.username || "",
    password: u.password || "",
  };
}
module.exports = { parseUrl };
