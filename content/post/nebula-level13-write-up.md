+++
author = "pwntester"
categories = ["nebula13"]
date = 2013-11-25T14:16:00Z
description = ""
draft = false
slug = "nebula-level13-write-up"
tags = ["nebula13"]
title = "Nebula level13 write-up"

+++

In [Level13](http://exploit-exercises.com/nebula/level13) we are given the following code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#define FAKEUID 1000
int main(int argc, char **argv, char **envp)
{
  int c;
  char token[256];
  if(getuid() != FAKEUID) {
    printf("Security failure detected. UID %d started us, we expect %d\n", getuid(), FAKEUID);
    printf("The system administrators will be notified of this violation\n");
    exit(EXIT_FAILURE);
  }
  // snip, sorry :)
  printf("your token is %s\n", token);

}
```

Well the code is missing the token but it is clear that is reading the user **UID** anc comparing it with **1000**, so the only way to get our token is to fake that our UID is 1000.

You can run **strings** on the binary and get the encrypted token **8mjomjh8wml;bwnh8jwbbnnwi;>;88?o;9ob** but this is not about crypto, so lets use a different approach.

I used **Hopper** to dissasmble the ELF binary and look for the UID comparision:

{% img /images/flag13hopper.png %}

The code is calling **getuid()** and comparing the result stored in **EAX** with **0x3e8** that is 1000 in decimal. All we need to do is change the value using a debugger:

```lang-bash line-numbers 
level13@nebula:/home/flag13$ gdb flag13  -q
Reading symbols from /home/flag13/flag13...(no debugging symbols found)...done.
(gdb) break main
Breakpoint 1 at 0x80484c9
(gdb) run
Starting program: /home/flag13/flag13

Breakpoint 1, 0x080484c9 in main ()
(gdb) x/20i main
(gdb) x/20i main
   0x80484c4 <main>:	push   %ebp
   0x80484c5 <main+1>:	mov    %esp,%ebp
   0x80484c7 <main+3>:	push   %edi
   0x80484c8 <main+4>:	push   %ebx
=> 0x80484c9 <main+5>:	and    $0xfffffff0,%esp
   0x80484cc <main+8>:	sub    $0x130,%esp
   0x80484d2 <main+14>:	mov    0xc(%ebp),%eax
   0x80484d5 <main+17>:	mov    %eax,0x1c(%esp)
   0x80484d9 <main+21>:	mov    0x10(%ebp),%eax
   0x80484dc <main+24>:	mov    %eax,0x18(%esp)
   0x80484e0 <main+28>:	mov    %gs:0x14,%eax
   0x80484e6 <main+34>:	mov    %eax,0x12c(%esp)
   0x80484ed <main+41>:	xor    %eax,%eax
   0x80484ef <main+43>:	call   0x80483c0 <getuid@plt>
   0x80484f4 <main+48>:	cmp    $0x3e8,%eax
   0x80484f9 <main+53>:	je     0x8048531 <main+109>
   0x80484fb <main+55>:	call   0x80483c0 <getuid@plt>
   0x8048500 <main+60>:	mov    $0x80486d0,%edx
   0x8048505 <main+65>:	movl   $0x3e8,0x8(%esp)
   0x804850d <main+73>:	mov    %eax,0x4(%esp)
(gdb) break *main + 48
Breakpoint 2 at 0x80484f4
(gdb) cont
Continuing.

Breakpoint 2, 0x080484f4 in main ()
(gdb) p $eax
$1 = 1014
(gdb) set $eax = 1000
(gdb) p $eax
$2 = 1000
(gdb) cont
Continuing.
your token is b705702b-76a8-42b0-8844-3adabbe5ac58
[Inferior 1 (process 1572) exited with code 063]
```

And there we go, the token is **b705702b-76a8-42b0-8844-3adabbe5ac58**. We can now log in as flag13 user:

```lang-bash line-numbers 
alvaro@nebula ~> ssh flag13@nebula

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


flag13@nebula's password:
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

flag13@nebula:~$ id
uid=986(flag13) gid=986(flag13) groups=986(flag13)
flag13@nebula:~$ getflag
You have successfully executed getflag on a target account
```

Voila!!

A different approach is using crypto, the token is encrypted using XOR and as we can see in the disassembly, the key is **0x5a** (dec 90)

{% img /images/flag13main.png %}

The following script will decrypt it for us:

```lang-python line-numbers 
def xor_string_int(s, i):
	array = []
	for c in s:
		array.append(chr(ord(c) ^ i))
	xored = "".join(array)
	print xored

xor_string_int("8mjomjh8wml;bwnh8jwbbnnwi;>;88?o;9ob", 90)
```

```lang-bash line-numbers 
alvaro@winterfell ~/Desktop> python xor.py
b705702b-76a8-42b0-8844-3adabbe5ac58
```

-.-
