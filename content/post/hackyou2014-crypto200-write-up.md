+++
author = "pwntester"
categories = ["CTF", "HackYou2014", "Crypto"]
date = 2014-01-16T20:43:00Z
description = ""
draft = false
slug = "hackyou2014-crypto200-write-up"
tags = ["CTF", "HackYou2014", "Crypto"]
title = "#hackyou2014 Crypto200 write-up"

+++

In this [level](http://hackyou.ctf.su/tasks/crypto200) we are said that our challange is login with administrator role in a service listening on hackyou2014tasks.ctf.su 7777
We are given the following source code:

```lang-python line-numbers 
#!/usr/bin/python
from math import sin
from urlparse import parse_qs
from base64 import b64encode
from base64 import b64decode
from re import match

SALT = ''
USERS = set()
KEY = ''.decode('hex')

def xor(a, b):
    return ''.join(map(lambda x : chr(ord(x[0]) ^ ord(x[1])), zip(a, b * 100)))

def hashme(s):
    #my secure hash function
    def F(X,Y,Z):
        return ((~X & Z) | (~X & Z)) & 0xFFFFFFFF
    def G(X,Y,Z):
        return ((X & Z) | (~Z & Y)) & 0xFFFFFFFF
    def H(X,Y,Z):
        return (X ^ Y ^ Y) & 0xFFFFFFFF
    def I(X,Y,Z):
        return (Y ^ (~Z | X)) & 0xFFFFFFFF
    def ROL(X,Y):
        return (X << Y | X >> (32 - Y)) & 0xFFFFFFFF

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476
    X = [int(0xFFFFFFFF * sin(i)) & 0xFFFFFFFF for i in xrange(256)]

    for i,ch in enumerate(s):
        k, l = ord(ch), i & 0x1f
        A = (B + ROL(A + F(B,C,D) + X[k], l)) & 0xFFFFFFFF
        B = (C + ROL(B + G(C,D,A) + X[k], l)) & 0xFFFFFFFF
        C = (D + ROL(C + H(D,A,B) + X[k], l)) & 0xFFFFFFFF
        D = (A + ROL(D + I(A,B,C) + X[k], l)) & 0xFFFFFFFF

    return ''.join(map(lambda x : hex(x)[2:].strip('L').rjust(8, '0'), [B, A, D, C]))

def gen_cert(login):
    global SALT, KEY
    s = 'login=%s&role=anonymous' % login
    s += hashme(SALT + s)
    print("decrypted cert: %s" % s)
    s = b64encode(xor(s, KEY))
    print("encrypted cert: %s" % s)
    return s

def register():
    global USERS
    login = raw_input('Your login: ').strip()
    if not match('^[\w]+$', login):
        print '[-] Wrong login'
        return
    if login in USERS:
        print '[-] Username already exists'
    else:
        USERS.add(login)
        print '[+] OK\nYour auth certificate:\n%s' % gen_cert(login)

def auth():
    global SALT, KEY
    cert = raw_input('Provide your certificate:\n').strip()
    try:
        cert = xor(b64decode(cert), KEY)
        print cert
        auth_str, hashsum = cert[0:-32], cert[-32:]
        print auth_str
        print hashsum
        if hashme(SALT + auth_str) == hashsum:
            data = parse_qs(auth_str, strict_parsing = True)
            print '[+] Welcome, %s!' % data['login'][0]
            if 'administrator' in data['role']:
                flag = open('flag.txt').readline()
                print flag
        else:
            print '[-] Auth failed'
    except:
        print '[-] Error'


def start():
    while True:
        print '======================'
        print '[0] Register'
        print '[1] Login'
        print '======================'
        num = raw_input().strip()
        if num == '0':
            register()
        elif num == '1':
            auth()

start()
```

The service generates certificate when you register that you need to present in order to login in.
The certificate is a XOR encrypted version of the following string:

```lang-bash line-numbers 
login=<login>&role=anonymous<salted hash of login+role string>
```

The problem is that we dont know the encryption key nor the hash salt. So let's take it one step at a time:

## Getting the key to the kingdom
Getting the key was the easy part as the cert is encrypted in an ECB way, we only need to send a login name long enough so that the whole key is xored with our know long login name, so we register the user:

```lang-bash line-numbers 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

And get the cert:

```lang-bash line-numbers 
RK5yZMJaRRl8LVBk5mx9xmVfPhXWqPlNObWPakmd6mpMs0qh6p9KVhBr0hqGJCE9tKRpgFRM7SZFGXwtUGTmbH3GZV8+Fdao+U05tY9qSZ3qakyzSqHqn0pWEGvSGoYkIT20pGmAVEztJkUZfC1QZOZsfcZlXz4V1qj5TTm1j2pJnepqTLNKoeqfSlYQa9IahiQhPbSkaYBUTO0mRRl8LVBk5mx9xmVfPhXWqPlNObWPakmd6mpMs0qh6p9KVhBr0hqGJCE9tKRpgFRM7SZFGXwtUGTmbH3GZV8+Fdao+U05tY9qSZ3qakyzSqHqn0pWEGvSGoYkIT20pA6zemHJWmU2UgJoSMhYT7cXe0kyoN7cakrNq0lu7MgSaJYz0p/rb3NpE6FqpgZQ
```

Now if we xor the two together (adding "login=" before the login name) we get the key and since our login name was long enough we can extract the key that is repeated several times:

```lang-bash line-numbers 
28c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e5
```

Now we can decrypt our cert and extrack the login string and hashsum:

```lang-bash line-numbers 
[+] Credentials: login=pwntester&role=anonymous
[+] Hashsum: 3e4d482fd5ce578af79312466b50b8f6
```

## Putting some salt
Our goal is to submit an "administrator" version of the string so we need to know the **salt** in order to produce the right hash that is going to be checked in the server ... or not?
Well, actually, the hashing function is not reversible and no collisions are found easy, but there is still hope in the way of [Length extension attacks](http://en.wikipedia.org/wiki/Length_extension_attack). Actually is even simpler since we dont have to care about the padding!
Ok, so here is the idea.

* The Hashing state machine starts in a initial state (that we know, check A,B,C,D in the hashme function)
* The hashing machine iterates over all the characters (abcd) and ends in a different state that is returned as the hashsum
* If we extend the original characters (abcd1234) and pass it to the hash function, we can do two things:
    * Start from scratch, reset the hash FSM, and calculate process it till there are no more characters and we return the last state in the form of a hashsum
    * Since we already hashed some characters and know the machine state, we can modify the hash FSM so its initial state is the one returned when we hashed (abcd) and then just continue from that state with the new characters (1234) until there are no more characters and we return the state in the form of a hashsum

Well, the server is going to do the first approach, but we can do the second without knowing the Salt!! So we know that "login=pwntester&role=anonymous" hash is 3e4d482fd5ce578af79312466b50b8f6.

Lets say we want to calculate the hash of "login=pwntester&role=anonymousNEWSTUFFHERE", we can reset the Hash machine so its initial state is 3e4d482fd5ce578af79312466b50b8f6 and then just hash the "NEWSTUFFHERE", the result will be the same hash as hashing the whole string.

Now, if we focus on the auth() method:

```lang-python line-numbers 
def auth():
    global SALT, KEY
    cert = raw_input('Provide your certificate:\n').strip()
    try:
        cert = xor(b64decode(cert), KEY)
        print cert
        auth_str, hashsum = cert[0:-32], cert[-32:]
        print auth_str
        print hashsum
        if hashme(SALT + auth_str) == hashsum:
            data = parse_qs(auth_str, strict_parsing = True)
            print '[+] Welcome, %s!' % data['login'][0]
            if 'administrator' in data['role']:
                flag = open('flag.txt').readline()
                print flag
        else:
            print '[-] Auth failed'
    except:
        print '[-] Error'
```

We can see that the auth string is parsed as a query string (parse_qs) so if we pass different parameters with the same name, they will be treated as an array.
Then the "if 'administrator' in data['role']" will pass if one of them is **administrator**

So now we know what we need to hash:

```lang-bash line-numbers 
login=pwntester&role=anonymous&role=administrator
```

This is the function I wrote to hash from a given state:

```lang-python line-numbers 
def hashmeFromState(s,hash,init):
    #my secure hash function
    def F(X,Y,Z):
        return ((~X & Z) | (~X & Z)) & 0xFFFFFFFF
    def G(X,Y,Z):
        return ((X & Z) | (~Z & Y)) & 0xFFFFFFFF
    def H(X,Y,Z):
        return (X ^ Y ^ Y) & 0xFFFFFFFF
    def I(X,Y,Z):
        return (Y ^ (~Z | X)) & 0xFFFFFFFF
    def ROL(X,Y):
        return (X << Y | X >> (32 - Y)) & 0xFFFFFFFF


    B = int(hash[0:8], 16)
    A = int(hash[8:16], 16)
    D = int(hash[16:24], 16)
    C = int(hash[24:32], 16)

    X = [int(0xFFFFFFFF * sin(i)) & 0xFFFFFFFF for i in xrange(256)]

    i = init
    for j,ch in enumerate(s):
        # We add the length of the previous state (we dont know secret length so we have to brute force it) to restaurate the state
        k, l = ord(ch), i & 0x1f
        if j==0:
            print("hashmeext pos:{0} char:{1} l:{2}".format(j,ch,l))
        A = (B + ROL(A + F(B,C,D) + X[k], l)) & 0xFFFFFFFF
        B = (C + ROL(B + G(C,D,A) + X[k], l)) & 0xFFFFFFFF
        C = (D + ROL(C + H(D,A,B) + X[k], l)) & 0xFFFFFFFF
        D = (A + ROL(D + I(A,B,C) + X[k], l)) & 0xFFFFFFFF
        i += 1

    return ''.join(map(lambda x : hex(x)[2:].strip('L').rjust(8, '0'), [B, A, D, C]))
```

Note that we dont know the length of the Salt, so we need to brute force it to initialize the hash FST in the right state. After running the script against the live service, we get that the right length is 18:

```lang-bash line-numbers 
alvaro@winterfell ~/D/h/crypto200> python crack.py
[+] Concatenated key (250 bytes): 28c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e528c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e528c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e528c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e528c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e5
[+] Key: 28c1150dac6704583d6c1125a72d3c87241e7f5497e9b80c78f4ce2b08dcab2b0df20be0abde0b17512a935bc765607cf5e5
[+] Credentials: login=pwntester&role=anonymous
[+] Hashsum: 3e4d482fd5ce578af79312466b50b8f6
[+] User Credentials: login=pwntester&role=anonymous3e4d482fd5ce578af79312466b50b8f6
[+] User Cert: RK5yZMJadC9TGHRW00hOoVZxEzGqiNZjFo2jRH2vmE45lj/YmbhvIjJPpmz/BAZLzNYZ8yE7mgUxaF9UdxM=
[-] Auth failed
hashmeext pos:0 char:& l:1
[+] Admin Credentials (secret length=1: login=pwntester&role=anonymous&role=administrator72d2e3d8de7b390f146cc6b5e8552ea8)
[+] Admin Cert (secret length=1: RK5yZMJadC9TGHRW00hOoVZxEzGqiNZjFo2jRH2vjVlinm7dyrpmfj9D4C+1BBQTh9IapSdonwM8PFhbcxaeHVq2ECgcN6GLjWlAwfsZbb2T)
[+] Admin Cert decoded (secret length=1: login=pwntester&role=anonymous&role=administrator72d2e3d8de7b390f146cc6b5e8552ea8)

...
...
...

[-] Auth failed
hashmeext pos:0 char:& l:18
[+] Admin Credentials (secret length=18: login=pwntester&role=anonymous&role=administrator6ca059630c51cb32e3d791aeca560eae)
[+] Admin Cert (secret length=18: RK5yZMJadC9TGHRW00hOoVZxEzGqiNZjFo2jRH2vjVlinm7dyrpmfj9D4C+1BBQTh9NLoCU4lVE3aF5ZIEbFHg7iF3pIbaaI3W8Zwfgbbb3O)
[+] Admin Cert decoded (secret length=18: login=pwntester&role=anonymous&role=administrator6ca059630c51cb32e3d791aeca560eae)

[+] Welcome
Eureka!!
```

Now we can use the cert to login and get the flag:

```lang-bash line-numbers 
RK5yZMJadC9TGHRW00hOoVZxEzGqiNZjFo2jRH2vjVlinm7dyrpmfj9D4C+1BBQTh9NLoCU4lVE3aF5ZIEbFHg7iF3pIbaaI3W8Zwfgbbb3O
```

```lang-bash line-numbers 
alvaro@winterfell ~/D/h/crypto200> nc hackyou2014tasks.ctf.su 7777                                                                                                                                                                                                            1
======================
[0] Register
[1] Login
======================
1
Provide your certificate:
RK5yZMJadC9TGHRW00hOoVZxEzGqiNZjFo2jRH2vjVlinm7dyrpmfj9D4C+1BBQTh9NLoCU4lVE3aF5ZIEbFHg7iF3pIbaaI3W8Zwfgbbb3O
[+] Welcome, pwntester!
CTF{40712b12d4be002e20f51424309a068c}
```



