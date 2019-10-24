+++
author = "pwntester"
categories = ["nebula14"]
date = 2013-11-25T16:14:00Z
description = ""
draft = false
slug = "nebula-level14-write-up"
tags = ["nebula14"]
title = "Nebula level14 write-up"

+++

In [Level14](http://exploit-exercises.com/nebula/level14) we are given an encrypted token: **857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW.** and the cipher.

We can try to reverse the cipher but lets play with it and see if we can find out the encryption routine:

```lang-bash line-numbers 
level14@nebula:/home/flag14$ ./flag14 -e
aaaaaaaaaaaaaaaaa
abcdefghijklmnopq
```

```lang-bash line-numbers 
level14@nebula:/home/flag14$ ./flag14 -e
abcdefg
acegikm
```

Ok, so it looks pretty simple, we shift a given characters a number of positions in the ASCII table where the key is the position of the character to encrypt. So we will shift the first character 0 positions, the second character 1 position, the third chracter 2 positions ...

We can code a simple decrypter in python:

```lang-python line-numbers 
import sys

def decrypt(ciphertext):
        count = 0
        result = []
        for c in ciphertext:
                result.append(chr((ord(c) - count)))
                count +=1
        print("Decrypting: " + ciphertext + " -> " + "".join(result))
        return("".join(result))

decrypt(sys.argv[1])
```

If we run the decrypter:

```lang-bash line-numbers 
level14@nebula:~$ python crack.py 857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW.
Decrypting: 857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW. -> 8457c118-887c-4e40-a5a6-33a25353165
```

Let's try it:

```lang-bash line-numbers 
alvaro@nebula ~/Development> ssh flag14@nebula

      _   __     __          __
     / | / /__  / /_  __  __/ /___ _
    /  |/ / _ \/ __ \/ / / / / __ `/
   / /|  /  __/ /_/ / /_/ / / /_/ /
  /_/ |_/\___/_.___/\__,_/_/\__,_/

    exploit-exercises.com/nebula


For level descriptions, please see the above URL.

To log in, use the username of "levelXX" and password "levelXX", where
XX is the level number.

Currently there are 20 levels (00 - 19).


flag14@nebula's password:
Welcome to Ubuntu 11.10 (GNU/Linux 3.0.0-12-generic i686)

 * Documentation:  https://help.ubuntu.com/
Your Ubuntu release is not supported anymore.
For upgrade information, please visit:
http://www.ubuntu.com/releaseendoflife

New release '12.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

flag14@nebula:~$ id
uid=985(flag14) gid=985(flag14) groups=985(flag14)
flag14@nebula:~$ getflag
You have successfully executed getflag on a target account
```

Voila!!
