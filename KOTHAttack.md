#KOTH Defense
This cheat sheet fore defending in KOTH

Aggressive Defense:
```
w # to see whos in with you
tty # To find out what PTS you are 
ps aux | grep pts # Then, look at the pts number from the result.
kill -9 $PID

ps aux --forest                     # to see in a tree POV
ps aux --forest | grep pts          # to see only where enemies came from
```

To break a shell:
```
cat /dev/urandom > /dev/pts/$
```

Cronjob upload:
```
* *     * * *   root    echo N0rthWinds > /root/king.txt
```

Finding  possible flags:
```
find / -type f -exec grep -l "thm{" {} \; 2>/dev/null
find / -type f -exec grep -l "THM{" {} \; 2>/dev/null
```

SUID and SGID patch
```
chmod u-s file_name #SUID
chmod g-s file_name #SGID
```

Vulnerable program patch:
```
chmod 000 /path/to/program && chown -u root && mv file /usr/sbin
```

Vulnerable LFI patch:
```
str_replace("../","",$_GET['VARIABLE'])
```





Vulnerable Insecure File upload:
```
move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], "/YOUR_DIRECTORY/" . $_FILES["fileToUpload"]["name"])
```

CHATTR:
```
chattr +i /root/king.txt
chattr -i /root/king.txt
which chattr # Get chattr's path, default: /usr/bin/chattr
rm usr/bin/chattr # Or another path if different
```

Counter to Chattr:
```
write a bash script that automatically echos your name into the txt
```

Persistence techniques 
SSH:
```
echo "my_id_rsa.pub" > /target machine/root/.ssh/authorized_keys
```

Sudoers:
```
<YOUR_USERNAME>        ALL=(ALL)        NOPASSWD: ALL
```






