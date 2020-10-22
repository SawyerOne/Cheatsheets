# Automatic Linux Priv Esc
## tools:
* [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester.git)
* [linux-exploit-suggester2](https://github.com/mzet-/linux-exploit-suggester)
* [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
* [LaZagne](https://github.com/AlessandroZ/LaZagne)
* [Beeroot](https://github.com/AlessandroZ/BeRoot)
* [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
* [mimipenguin](https://github.com/huntergregal/mimipenguin)



<h3>Simple Manual Priv esc<h3>
<h4>User enumeration<h4>

<h4>Info about User<h4>
  
```
id || (whoami && groups) 2>/dev/null
id
```

<h4>List all users<h4>
  
```
cat /etc/passwd | cut -d: -f1
```

<h4>List superusers<h4>
  
```
awk -F: '($3 == "0") {print}' /etc/passwd
grep -v -E “^#” /etc/passwd | awk -F: ‘$3 == 0 { print $1}’
awk -F: ‘($3 == “0”) {print}’ /etc/passwd   
```

<h4>Currently logged users<h4>

```
w
```

<h4>OS info: <h4>

```(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null
```

Environmental info:
```
env
(env || set) 2>/dev/null
```

Kernal Exploit
```
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
You can find a good vulnerable kernel list and some already compiled exploits here: https://github.com/lucyoa/kernel-exploits and exploitdb sploits.
Other sites where you can find some compiled exploits: https://github.com/bwbwbwbw/linux-exploit-binaries, https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack


To extract all the vulnerable kernel versions from that web you can do:
```
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
Tools that could help searching for kernel exploits are:
linux-exploit-suggester.sh
linux-exploit-suggester2.pl
linuxprivchecker.py (execute IN victim,only checks exploits for kernel 2.x)
```
Always search the kernel version in Google, maybe your kernel version is wrote in some kernel exploit and then you will be sure that this exploit is valid.

Sudo version
Based on the vulnerable sudo versions that appear in:
```
searchsploit sudo
```
You can check if the sudo version is vulnerable using this grep.
```
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
More system enumeration
```
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

<h4>Drives<h4>
Check what is mounted and unmounted, where and why. If anything is unmounted you could try to mount it and check for private info

```ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
<h4>GTFOBins<h4>
GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.
https://gtfobins.github.io/


The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

Installed SoftwareUseful software
Enumerate useful binaries
Vulnerable Software Installed
Check for the version of the installed packages and services. Maybe there is some old Nagios version (for example) that could be exploited for escalating privileges… It is recommended to check manually the version of the more suspicious installed software.
```
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use openVAS to check for outdated and vulnerable software installed inside the machine.


<h4>Processes<h4>
  
```ps aux,
ps -ef,
top -n 1,
```
  
<h4>Process monitoring<h4>
You can use tools like [pspy](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.
  
<h4>Scheduled/Cron jobs<h4>
Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
  
```
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
