"use strict";
// Google-dork catalog + URL builder for passive recon. Pure data + string logic
// (the site: query construction and URL-encoding) — no coloring — so it is
// unit-tested. sentinel.js keeps the presentation. For authorized recon only.

const DORK_BASE = "https://www.google.com/search?q=";
const DORKS = [
  ["exposed files", 'intitle:"index of"'],
  ["config/env", "ext:env | ext:ini | ext:conf"],
  ["SQL dumps", "ext:sql"],
  ["login pages", "inurl:login | inurl:admin"],
  ["docs", "ext:pdf | ext:xls | ext:docx"],
  ["errors", 'intext:"sql syntax near"'],
  ["backups", "ext:bak | ext:old | ext:backup"],
];

// dorkUrls(domain) -> [{ label, query, encoded, url }]. `encoded` is the
// URL-encoded "site:<domain> <query>" component; `url` is the full search URL.
// Presentation colors DORK_BASE and appends `encoded`, matching the original.
function dorkUrls(domain) {
  domain = String(domain == null ? "" : domain);
  return DORKS.map(([label, query]) => {
    const encoded = encodeURIComponent("site:" + domain + " " + query);
    return { label, query, encoded, url: DORK_BASE + encoded };
  });
}

module.exports = { DORK_BASE, DORKS, dorkUrls };
