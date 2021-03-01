<h1>Spawning TTY shell</h1>


Below are some useful tips to spawn a TTY shell on the occasion you need more interaction with the target machine once in, These are the helpful (or atleast hope so) breaking out of "jail shells"
Techniques that you may find useful, take care have fun and hack on




<h4> Python </h4>

```bash

python -c 'import pty; pty.spawn("/bin/sh")'

python3 -c 'import pty; pty.spawn("/bin/sh")'

python3 -c "__import__('pty').spawn('/bin/bash')"

python3 -c "__import__('subprocess').call(['/bin/bash'])"

```




<h3>Perl</h3>

```bash
perl -e 'exec "/bin/sh";'

perl: exec "/bin/sh";
```




<h3>Ruby</h3>

```bash

ruby: exec "/bin/sh"

```



I have seen a lot of people ask about this yet there are not too many good online resources that explain it simply. When obtaining a reverse shell with a Netcat listener,

it is by default non-interactive and you cannot pass keyboard shortcuts or special characters such as tab. It is quite simple to work around.
For starters, in your shellrun python -c 'import pty;pty.spawn("/bin/bash");' to obtain a partially interactive bash shell. 

After that, do CTRL+Z to background Netcat. Enter stty raw -echo in your terminal, 
which will tell your terminal to pass keyboard shortcuts etc. through. Once that is done, run the command fg to bring Netcat back to the foreground. Note you will not be able to see what you are typing in terminal after you change your stty setting. You should now have tab autocomplete as well as be able to use interactive commands such as su and nano.


Optional before initiating code below!:

```bash

export SHELL=/bin/bash (If bash is not present in machine)

export TERM=xterm-color (Adding coloring to shell)

export TERM=xterm (exporting xterm)

```

After getting a shell within the target machine:

```bash

python -c 'import pty; pty.spawn("/bin/bash")'

CTRL-z (exit out of session)

stty raw -echo

fg (after here the rest is also optional, i recommend for beginners like myself to stop here)

reset

export SHELL=bash

export TERM=xterm-256color

stty rows <num> columns <cols>


```



citations:

https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell_
