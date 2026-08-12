"use strict";
// IOC defang / refang — make indicators (URLs, domains, IPs, emails) safe to paste
// into reports and tickets by neutralizing the clickable/executable bits, and reverse
// it. Pure and reversible (defang -> refang round-trips). A staple analyst tool.
function defang(s) {
  return String(s)
    .replace(/http(s?):\/\//gi, "hxxp$1[://]") // scheme first, before dots are bracketed
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}
function refang(s) {
  return String(s)
    .replace(/\[\.\]/g, ".")
    .replace(/\[@\]/g, "@")
    .replace(/hxxp(s?)\[:\/\/\]/gi, "http$1://") // bracketed scheme
    .replace(/hxxp(s?):\/\//gi, "http$1://");    // also tolerate plain hxxp://
}
module.exports = { defang, refang };
