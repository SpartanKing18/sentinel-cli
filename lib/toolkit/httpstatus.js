"use strict";
// HTTP status-code reference + classification. Pure lookup/logic (no coloring) so
// it can be unit-tested; sentinel.js keeps the thin presentation wrapper that
// colors the result. Extracted from sentinel.js.
const HTTP_STATUS_MAP = { "200": "OK", "201": "Created", "202": "Accepted", "204": "No Content", "206": "Partial Content", "301": "Moved Permanently", "302": "Found", "303": "See Other", "304": "Not Modified", "307": "Temporary Redirect", "308": "Permanent Redirect", "400": "Bad Request", "401": "Unauthorized", "402": "Payment Required", "403": "Forbidden", "404": "Not Found", "405": "Method Not Allowed", "406": "Not Acceptable", "407": "Proxy Authentication Required", "408": "Request Timeout", "409": "Conflict", "410": "Gone", "413": "Payload Too Large", "414": "URI Too Long", "418": "I'm a teapot", "422": "Unprocessable Entity", "425": "Too Early", "429": "Too Many Requests", "431": "Request Header Fields Too Large", "451": "Unavailable For Legal Reasons", "500": "Internal Server Error", "501": "Not Implemented", "502": "Bad Gateway", "503": "Service Unavailable", "504": "Gateway Timeout", "505": "HTTP Version Not Supported" };
// statusClass(n) -> the "Nxx ..." family label, or "" if out of range.
function statusClass(n) { return n < 200 ? "1xx informational" : n < 300 ? "2xx success" : n < 400 ? "3xx redirect" : n < 500 ? "4xx client error" : n < 600 ? "5xx server error" : ""; }
// statusInfo(code) -> { code, text, class } for a known code, else null. Trims
// surrounding whitespace to match the historical CLI behavior.
function statusInfo(code) { code = String(code == null ? "" : code).trim(); const text = HTTP_STATUS_MAP[code]; if (!text) return null; return { code, text, class: statusClass(+code) }; }
module.exports = { HTTP_STATUS_MAP, statusClass, statusInfo };
