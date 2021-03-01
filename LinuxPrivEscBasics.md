<h1>Linux Fundementals for Privilege escalation</h1>

<h3>This is my personal cheetsheet + checklist for basic Linux fundamentals that I personally made & use</h3>


Linux Functions;

- [ ] Command Stored;
```
cat /home/bob/.bashrc | grep 
```

- [ ] MOTD Store point;
```
cat /etc/update-motd.d/* | grep flag -i
```

- [ ] To check system process;
```
ps -aux 
ps -ef
top -n 1
```

- [ ] checking host files;
```
cat /etc/hosts
```

- [ ] Checking passwords;
```
cat /etc/passwd;
```

- [ ] check crontabs are created;
```
cd /etc/; 
crontab -e
```

- [ ] checking Release version;
```
cat /etc/*-release
```

- [ ] checking system mount;
```
cd /media/f/l/a/g/1/6/is/ #.....
```

- [ ] Checking kernel version;
```
uname -a
cat /proc/version
```

- [ ] Check local hosts;
```
cat /etc/hosts; 
curl localhost
```

- [ ] checking Personal $PATH;
```
cat /home/*/.profile | grep -i flag
```

- [ ] check environment variables:;
```
env | grep -i flag
```

- [ ] looking at groups created;
```
cat /etc/group | grep -i flag
```

- [ ] Checking SQL Database;
```
mysql -u root --password; #then input root's password
show databases;
```


- [ ] to check bash history;
```
cat .bash_history
history
```

- [ ] Checking installed software;
```
which nmap 
which aws 
which nc  
which ncat  
which netcat  
which wget  
which curl 
which ping  
which gcc  
which python 
which python2 
which python3 
which perl 
which php
which ruby 
which xterm 
which sudo 
which docker 
```


- [ ] Checking who you are;
```
#Info about me
*id || (whoami && groups) 2>/dev/null
id

cat /etc/passwd 

```

- [ ] Checking User history + Enviroment variables;
```
cat ~/.bash_profile
cat ~/.bash_logout
cat ~/.bashrc
cat /etc/bashrc
cat /etc/profile
```

- [ ] Checking SSH keys;
```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```



REMINDER TO CHECK IMPORTANT DIRECTORIES!~, here's a short list of them :)) 
```
/etc/passwd - Stores user information - Often used to see all the users on a system
/etc/group
/etc/shadow - Has all the passwords of these users
/tmp - Every file inside it gets deleted upon shutdown - used for temporary files
/etc/sudoers - Used to control the sudo permissions of every user on the system -
/home - The directory where all your downloads, documents etc are. - The equivalent on Windows is C:\Users\<user>
/root - The root user's home directory - The equivilent on Windows is C:\Users\Administrator
/usr - Where all your software is installed
/bin and /sbin - Used for system critical files - DO NOT DELETE
/etc/shells - The location in which the shells for valid logins are stored

$PATH - Stores all the binaries you're able to run - same as $PATH on Windows ($PATH is an environment variable that contains all the binaries you're able to execute)

```



How to's
Check the manual/help page;
```
man <command>
--help
-h
```

using diff to compare scripts;
```
cd /var/log; ls -la | grep flag;
cat /var/log/flagtourteen.txt
```

checking specific lines
```
sed -n "2345,2345p" /home/alice/flag19
```

Base64 encoded;
```
find / -type f -name flag20 2>/dev/null;
cat /home/alice/flag20;
base64 -d /home/alice/flag20
```

Represented as a hex:
xxd -p -r takes the piped output from our cat converts from Hex to readable format.
```
find / -type f -name flag22 2>/dev/null;
cat/home/alice/flag22 | xxd -p -r
```

locating and reversing files;
```
find / -type f -name flag23 2>/dev/null;
rev /home/alice/flag23
```

analyzing files in compiled in C program to human readable strings, this can be done using strings;
```
Find / -type f -name flag24 2>/dev/null
strings /home.garry/flag24 | grep flag
```

Trying to find the file and knowing the string begins with 4bceb and is 32 characters long;
Instead of just running the grep command in the / directory, I ran it for a shorter period of time in each folder.
Eventually finding a result in /var in a shorter period of time that waiting for it to go through all files in the system.
```
egrep -Re "^4bceb.{27}" 2>/dev/null;
```

Looking for flags;
```
find flag6 / 2> /dev/null | grep flag6;
```

Using $ to announce enviroment variables;
```
echo $USER
Bob
```





