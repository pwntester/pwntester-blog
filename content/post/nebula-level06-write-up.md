+++
author = "pwntester"
categories = ["nebula06"]
date = 2013-11-21T14:47:00Z
description = ""
draft = false
slug = "nebula-level06-write-up"
tags = ["nebula06"]
title = "Nebula level06 write-up"

+++

In [Level06](http://exploit-exercises.com/nebula/level06) all we are said is that flag06 user comes from a legacy unix system. There is nothing special in his home folder. Lets take a look at the **/etc/passwd** file:

```lang-bash  data-line=38 
level06@nebula:/home/flag06$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
nebula:x:1000:1000:nebula,,,:/home/nebula:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
level00:x:1001:1001::/home/level00:/bin/sh
flag00:x:999:999::/home/flag00:/bin/sh
level01:x:1002:1002::/home/level01:/bin/sh
flag01:x:998:998::/home/flag01:/bin/sh
level02:x:1003:1003::/home/level02:/bin/sh
flag02:x:997:997::/home/flag02:/bin/sh
level03:x:1004:1004::/home/level03:/bin/sh
flag03:x:996:996::/home/flag03:/bin/sh
level04:x:1005:1005::/home/level04:/bin/sh
flag04:x:995:995::/home/flag04:/bin/sh
level05:x:1006:1006::/home/level05:/bin/sh
flag05:x:994:994::/home/flag05:/bin/sh
level06:x:1007:1007::/home/level06:/bin/sh
flag06:ueqwOCnSGdsuM:993:993::/home/flag06:/bin/sh
level07:x:1008:1008::/home/level07:/bin/sh
flag07:x:992:992::/home/flag07:/bin/sh
level08:x:1009:1009::/home/level08:/bin/sh
flag08:x:991:991::/home/flag08:/bin/sh
level09:x:1010:1010::/home/level09:/bin/sh
flag09:x:990:990::/home/flag09:/bin/sh
level10:x:1011:1011::/home/level10:/bin/sh
flag10:x:989:989::/home/flag10:/bin/sh
level11:x:1012:1012::/home/level11:/bin/sh
flag11:x:988:988::/home/flag11:/bin/sh
level12:x:1013:1013::/home/level12:/bin/sh
flag12:x:987:987::/home/flag12:/bin/sh
level13:x:1014:1014::/home/level13:/bin/sh
flag13:x:986:986::/home/flag13:/bin/sh
level14:x:1015:1015::/home/level14:/bin/sh
flag14:x:985:985::/home/flag14:/bin/sh
level15:x:1016:1016::/home/level15:/bin/sh
flag15:x:984:984::/home/flag15:/bin/sh
level16:x:1017:1017::/home/level16:/bin/sh
flag16:x:983:983::/home/flag16:/bin/sh
level17:x:1018:1018::/home/level17:/bin/sh
flag17:x:982:982::/home/flag17:/bin/sh
level18:x:1019:1019::/home/level18:/bin/sh
flag18:x:981:981::/home/flag18:/bin/sh
level19:x:1020:1020::/home/level19:/bin/sh
flag19:x:980:980::/home/flag19:/bin/sh
```

Nice, we can try to crack it with **John the Ripper** (this remainds me my collage days ...). You can use the same VM to install and play with **JTR**, to install it, login as nebula and run:

```lang-bash line-numbers 
nebula@nebula:~$ sudo apt-get install john
[sudo] password for nebula:
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following extra packages will be installed:
  john-data
The following NEW packages will be installed:
  john john-data
0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.
Need to get 1001 kB of archives.
After this operation, 2056 kB of additional disk space will be used.
Do you want to continue [Y/n]?
Get:1 http://us.archive.ubuntu.com/ubuntu/ oneiric/main john-data all 1.7.8-1 [639 kB]
Get:2 http://us.archive.ubuntu.com/ubuntu/ oneiric/main john i386 1.7.8-1 [362 kB]
Fetched 1001 kB in 27s (36.5 kB/s)
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = "en_US:",
	LC_ALL = (unset),
	LC_CTYPE = "es_ES.UTF-8",
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
locale: Cannot set LC_CTYPE to default locale: No such file or directory
locale: Cannot set LC_ALL to default locale: No such file or directory
Selecting previously deselected package john-data.
(Reading database ... 32487 files and directories currently installed.)
Unpacking john-data (from .../john-data_1.7.8-1_all.deb) ...
Selecting previously deselected package john.
Unpacking john (from .../archives/john_1.7.8-1_i386.deb) ...
Processing triggers for man-db ...
locale: Cannot set LC_CTYPE to default locale: No such file or directory
locale: Cannot set LC_ALL to default locale: No such file or directory
Setting up john-data (1.7.8-1) ...
Setting up john (1.7.8-1) ...
```

Now we are ready to crack that password:

```lang-bash line-numbers data-line=4 
nebula@nebula:~$ john /etc/passwd
Created directory: /home/nebula/.john
Loaded 1 password hash (Traditional DES [128/128 BS SSE2])
hello            (flag06)
guesses: 1  time: 0:00:00:00 100% (2)  c/s: 75300  trying: 12345 - biteme
Use the "--show" option to display all of the cracked passwords reliably
```

That was fast!, password is **hello**. All we need to do now is login as flag06 and execute **getflag**

```lang-bash line-numbers 
flag06@nebula:~$ getflag
You have successfully executed getflag on a target account
```

