+++
author = "pwntester"
categories = ["CTF", "HackYou2014", "Crypto"]
date = 2014-01-17T18:14:00Z
description = ""
draft = false
slug = "hackyou2014-crypto400-write-up"
tags = ["CTF", "HackYou2014", "Crypto"]
title = "#hackyou2014 Crypto400 write-up"

+++

In this [level](http://hackyou.ctf.su/tasks/crypto400) we are said that:

> We have intercepted communication in a private network. It is used a strange protocol based on RSA cryptosystem.
> 
> Can you still prove that it is not secure enough and get the flag?

We are given a pcap file with a bunch of transmissions generated with this script:

```lang-python line-numbers 
#!/usr/bin/python
import sys
import struct
import zlib
import socket

class Client:
    def __init__(self, ip):
        #init
        self.ip = ip
        self.port = 0x1337
        #connect
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.ip, self.port))
        #recieve e
        self.e = self.Recv()
        #recieve n
        self.n = self.Recv()
        self.e, self.n = int(self.e), int(self.n)

    def Recv(self):
        #unpack data
        length = struct.unpack('!H', self.conn.recv(2))
        data = zlib.decompress(self.conn.recv(length[0]))
        return data

    def Pack(self, data):
        #compress data
        data = zlib.compress('%s' % data)
        length = struct.pack('!H', len(data))
        return '%s%s' % (length, data)

    def Send(self, msg):
        #send message
        msg = int(msg.encode('hex'),16)
        assert(msg < self.n)
        msg = pow(msg, self.e, self.n)
        self.conn.send(self.Pack(msg))
        print '[+] Message send'

    def __del__(self):
        #close connection
        self.conn.close()

if len(sys.argv) != 2:
    print 'Usage: %s <ip>' % sys.argv[0]
    sys.exit(0)

flag = open('message.txt').readline()
test = Client(sys.argv[1])
test.Send(flag)
```

Analyzing the protocol it looks like it goes something like:

* Message to be send is read from external file
* Connection is established against given IP on port 4919 (0x1337)
* Server sends "e" packet [data lengt + zlib(data)]
* Server sends "n" packet [data lengt + zlib(data)]
* Both "e" and "n" are casted to integers
* Client encodes message as integer
* Client verifies message < n
* Client encrpyts message using: enc = pow(message, e, n)
* Client sends encrypted message packet [data lengt + zlib(data)]

If we explore the pcap with wireshark we can see a bunch of transmissions from Client to Server. We will need to process it in order to extract the message, the following python+scapy script will read all the interesting elements being transmited for each communication: e, n and flag:

```lang-python line-numbers 
#!/usr/bin/python
from scapy.all import *
from struct import *
import zlib

pkts = PcapReader("packets.pcap")
for p in pkts:
    pkt = p.payload
    if pkt.getlayer(Raw):
        raw = pkt.getlayer(Raw).load
        print "{0}:{1} -> {2}:{3}".format(pkt.src,pkt.sport,pkt.dst,pkt.dport)
        if str(pkt.sport) == "4919":
            elength = struct.unpack("!H",raw[0:2])[0]
            ezip = raw[2:2 + elength]
            e = int(zlib.decompress(ezip))
            nlength = struct.unpack("!H",raw[elength + 2 :elength + 4])[0]
            nzip =  raw[elength + 4:elength + 4 + nlength]
            n = int(zlib.decompress(nzip))
            print "e = {0}".format(e)
            print "n = {0}".format(n)
        if str(pkt.dport) == "4919":
            flaglength = struct.unpack("!H",raw[0:2])[0]
            flagzip = raw[2:2 + flaglength]
            encflag = int(zlib.decompress(flagzip))
            print "encflag = {0}".format(encflag)
```

As an example of one communication:

```lang-bash line-numbers 
alvaro@winterfell ~/D/h/crypto400> python decrypter.py
WARNING: No route found for IPv6 destination :: (no default route?)
192.168.1.10:4919 -> 192.168.1.5:41260
e = 17
n = 27658060678038715780470429570597987144542213875178081185638364125349217264266787337266356239252353691015124430930507236433817624156361120645134956689683794554169169254645287613480048966030722812191823753459580311585866523664171185580520752591976764843551787247552790540802105791272457516072210641470817920157370947681970410336005860197552073763981521526496955541778866864446616347452950889748333309771690509856724643918258831575902389005661750464296924818808365029037591660424882588976607197196824985084365272217072807601787578262208488572448451271800547820717066767396857464594301327160705353075064322975430897551911
192.168.1.5:41260 -> 192.168.1.10:4919
encflag = 11433488612991990768536086698965180146550356348457563234735402111134701115830423042016221831657484325065472609147436229496479358788735270448637824809543880271526735635196884978639585020518147152207002685868984199742884443523231593245377292570809368330956970290791633106067116466080014631110596564728982066569618319541351401820732547227122970369299780366876340403436785218211729531092484723580223801525992510782266856454394478372421830988205823368541860973674259795969870252832216828042174346473447490557323038031625277043161510854825069681462499200978561823301487118145650943076528233694749306585201212677836363102350
```

Analyzing the traffic, there are 19 communications with different modulos but always same exponent (e=17) which simplifies the problem

```lang-bash line-numbers 
encrypted = (flag^17) % modulo
```

We should only care to find F so that:

```lang-bash line-numbers 
encflag1 = F % n1
encflag2 = F % n2
...
...
encflag18 = F % n18
encflag19 = F % n19
```

In order to solve the equation we can use the [Chinese Remainder Theorem (CRT)](http://en.wikipedia.org/wiki/Chinese_remainder_theorem). For which I found a [Python implementation](https://mail.python.org/pipermail/edu-sig/2001-August/001665.html) that I needed to adjust a little bit:

```lang-python line-numbers 
from operator import mod

def eea(a,b):
    """Extended Euclidean Algorithm for GCD"""
    v1 = [a,1,0]
    v2 = [b,0,1]
    while v2[0]<>0:
       p = v1[0]//v2[0] # floor division
       v2, v1 = map(lambda x, y: x-y,v1,[p*vi for vi in v2]), v2
    return v1

def inverse(m,k):
     """
     Return b such that b*m mod k = 1, or 0 if no solution
     """
     v = eea(m,k)
     return (v[0]==1)*(v[1] % k)

def crt(ml,al):
     """
     Chinese Remainder Theorem:
     ms = list of pairwise relatively prime integers
     as = remainders when x is divided by ms
     (ai is 'each in as', mi 'each in ms')

     The solution for x modulo M (M = product of ms) will be:
     x = a1*M1*y1 + a2*M2*y2 + ... + ar*Mr*yr (mod M),
     where Mi = M/mi and yi = (Mi)^-1 (mod mi) for 1 <= i <= r.
     """

     M  = reduce(lambda x, y: x*y,ml)        # multiply ml together
     Ms = [M/mi for mi in ml]   # list of all M/mi
     ys = [inverse(Mi, mi) for Mi,mi in zip(Ms,ml)] # uses inverse,eea
     return reduce(lambda x, y: x+y,[ai*Mi*yi for ai,Mi,yi in zip(al,Ms,ys)]) % M

F = crt(modulos,remainders)
```

Once we find F, we can calculate its 17th root in order to find the integer version of the flag:

```lang-python line-numbers 
def root(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

intflag = root(F,17)
```

And from there its easy to get the flag:

```lang-python line-numbers 
flag = hex(intflag)[2:-1].decode('hex')
```

Running our script returns:

```lang-bash line-numbers 
alvaro@winterfell ~/D/h/crypto400> python decrypter.py
WARNING: No route found for IPv6 destination :: (no default route?)
Secret message! CTF{336b2196a2932c399c0340bc41cd362d}
```

Cool!!!!

This is the full script:

```lang-python line-numbers 
#!/usr/bin/python
from scapy.all import *
from struct import *
import zlib
from operator import mod

def eea(a,b):
    """Extended Euclidean Algorithm for GCD"""
    v1 = [a,1,0]
    v2 = [b,0,1]
    while v2[0]<>0:
       p = v1[0]//v2[0] # floor division
       v2, v1 = map(lambda x, y: x-y,v1,[p*vi for vi in v2]), v2
    return v1

def inverse(m,k):
     """
     Return b such that b*m mod k = 1, or 0 if no solution
     """
     v = eea(m,k)
     return (v[0]==1)*(v[1] % k)

def crt(ml,al):
     """
     Chinese Remainder Theorem:
     ms = list of pairwise relatively prime integers
     as = remainders when x is divided by ms
     (ai is 'each in as', mi 'each in ms')

     The solution for x modulo M (M = product of ms) will be:
     x = a1*M1*y1 + a2*M2*y2 + ... + ar*Mr*yr (mod M),
     where Mi = M/mi and yi = (Mi)^-1 (mod mi) for 1 <= i <= r.
     """

     M  = reduce(lambda x, y: x*y,ml)        # multiply ml together
     Ms = [M/mi for mi in ml]   # list of all M/mi
     ys = [inverse(Mi, mi) for Mi,mi in zip(Ms,ml)] # uses inverse,eea
     return reduce(lambda x, y: x+y,[ai*Mi*yi for ai,Mi,yi in zip(al,Ms,ys)]) % M

def root(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

pkts = PcapReader("packets.pcap")
modulos = []
remainders = []
exponents = []
for p in pkts:
    pkt = p.payload
    if pkt.getlayer(Raw):
        raw = pkt.getlayer(Raw).load
        if str(pkt.sport) == "4919":
            elength = struct.unpack("!H",raw[0:2])[0]
            ezip = raw[2:2 + elength]
            e = int(zlib.decompress(ezip))
            nlength = struct.unpack("!H",raw[elength + 2 :elength + 4])[0]
            nzip =  raw[elength + 4:elength + 4 + nlength]
            n = int(zlib.decompress(nzip))
            modulos.append(n)
            exponents.append(e)
        if str(pkt.dport) == "4919":
            flaglength = struct.unpack("!H",raw[0:2])[0]
            flagzip = raw[2:2 + flaglength]
            encflag = int(zlib.decompress(flagzip))
            remainders.append(encflag)

F = crt(modulos,remainders)
intflag = root(F,17)
flag = hex(intflag)[2:-1].decode('hex')
print flag
```

Thanks for reading!

References:

* [Chinese Remainder Theorem](http://www.youtube.com/watch?v=3PkxN_r9up8)
* [Hastad's broadcast attack](http://www.usna.edu/Users/math/wdj/_files/documents/book/node45.html)
