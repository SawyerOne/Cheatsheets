# Linux fundementals in CTF!
## These commands are important once you enter a machine and your trying to set yourself at home and feel more comfortable   

###Linux Functions;

* Command Stored;
cat /home/bob/.bashrc | grep flag11


*  MOTD Store point;
cat /etc/update-motd.d/* | grep flag -i


*  To check system process;
33t

*  checking host files;

cat /etc/hosts

*  Checking passwords;
cat /etc/passwd;

*  check crontabs are created;
cd /etc/;
crontab -e


*  checking Release version;
cat /etc/*-release


*  checking system mount;
cd /media/f/l/a/g/1/6/is/ #.....


*  Checking kernel version;
uname -a


*   Check local hosts;
cat /etc/hosts;
curl localhost


*   checking Personal $PATH;
cat /home/*/.profile | grep -i flag


*   check environment variables:;
env | grep -i flag

  
*   looking at groups created;
cat /etc/group | grep -i flag


*   Checking SQL Database;
mysql -u root --password; #then input root's password
show databases;


* to check bash history;
cat .bash_history


* to check for SUID's
find / -user root -perm /4000 2>/dev/null


REMINDER TO CHECK IMPORTANT DIRECTORIES!~, here's a short list of them :))
/etc/passwd - Stores user information - Often used to see all the users on a system
/etc/shadow - Has all the passwords of these users
/tmp - Every file inside it gets deleted upon shutdown - used for temporary files
/etc/sudoers - Used to control the sudo permissions of every user on the system -
/home - The directory where all your downloads, documents etc are. - The equivalent on Windows is C:\Users\<user>
/root - The root user's home directory - The equivilent on Windows is C:\Users\Administrator
/usr - Where all your software is installed
/bin and /sbin - Used for system critical files - DO NOT DELETE
/etc/shells - The location in which the shells for valid logins are stored
$PATH - Stores all the binaries you're able to run - same as $PATH on Windows ($PATH is an environment variable that contains all the binaries you're able to execute)
