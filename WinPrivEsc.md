Windows Privilage Escalation




Best tool to look for Windows local privilege escalation vectors: WinPEAS


Vulnerable Kernel?


 - [ ] Search for kernel exploits using scripts (post/windows/gather/enum_patches, post/multi/recon/local_exploit_suggester, sherlock, watson )

- [ ] Use Google to search for kernel exploits

- [ ] Use searchsploit to search for kernel exploits

- [ ] Any vulnerable Driver?


Logging/AV enumeration


- [ ] Check for credentials in environment variables

- [ ] Check LAPS

- [ ] Check Audit and WEF settings

- [ ] Check if any AV


User Privileges


- [ ] Check current user privileges

- [ ] Check if you have any of these tokens enabled: SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege ?

- [ ] What is inside the Clipboard?


Network


- [ ] Check current network information

- [ ] Check hidden local services restricted to the outside


Vulnerable Software or Processes?


- [ ] Is any unknown software running?

- [ ] Is any software with more privileges that it should have running?

- [ ] Search for exploits for running processes (specially if running of versions)

- [ ] Can you read any interesting process memory (where passwords could be saved)?

- [ ] Have write permissions over the binaries been executed by the processes?

- [ ] Have write permissions over the folder of a binary been executed to perform a DLL Hijacking?

- [ ] What is running on startup or is scheduled? Can you modify the binary?

- [ ] Can you dump the memory of any process to extract passwords?


Services


- [ ] Can you modify any service?

- [ ] Can you modify the binary that is executed by any service?

- [ ] Can you modify the registry of any service?

- [ ] Can you take advantage of any unquoted service binary path?


DLL Hijacking


- [ ] Can you write in any folder inside PATH?

- [ ] Is there any known service binary that tries to load any non-existant DLL?

- [ ] Can you write in any binaries folder?


Credentials


- [ ] Windows Vault credentials that you could use?

- [ ] Interesting DPAPI credentials?

- [ ] Wifi netoworks?

- [ ] SSH keys in registry?

- [ ] Credentials inside "known files"? Inside the Recycle Bin? At home?

- [ ] Registry with credentials?

- [ ] Inside Browser data (dbs, history, bookmarks....)?

- [ ] AppCmd.exe exists? Credentials?

- [ ] SCClient.exe? DLL Side Loading?

- [ ] Cloud credentials?


AlwaysInstallElevated


- [ ] Is this enabled?


Is vulnerable WSUS?


- [ ] Is it vulnerable?


Write Permissions


- [ ] Are you able to write files that could grant you more privileges?


Any open handler of a privileged process or thread?


- [ ] Maybe the compromised process is vulnerable.


UAC Bypass


- [ ] There are several ways to bypass the UAC

If you want to know about my latest modifications/additions or you have any suggestion for HackTricks or PEASS, join the PEASS & HackTricks telegram group here.
