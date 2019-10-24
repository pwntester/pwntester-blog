+++
author = "pwntester"
categories = ["nebula08"]
date = 2013-11-22T11:05:00Z
description = ""
draft = false
slug = "nebula-level08-write-up"
tags = ["nebula08"]
title = "Nebula level08 write-up"

+++

In [Level08](http://exploit-exercises.com/nebula/level08) we are given a network capture file: **capture.pcap**. If we open it with **Wireshark** we will only find one TCP Stream. We will use **Follow TCP Stream** to visualize it:

{% img /images/tcpstream.png 500 %}

We can see that the user was trying to login into the **wwwbugs** server and the login failed. We can assume that it was the **flag08** user trying to log in and sending his flag08 password by mistake... Yep, I know it is assuming too much, but anyway, that all we got.

In the password we can see some non printable ASCII characters, if we switch to the **Hex view**, we can see they are **7B** characters that correspond with the **delete** key:

{% img /images/tcpstreamhex.png 500 %}

So we can fix the password to: **backd00Rmate**

Let's try it:

```lang-bash line-numbers 
alvaro@winterfell ~/Desktop> ssh flag08@nebula

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


flag08@nebula's password:
Welcome to Ubuntu 11.10 (GNU/Linux 3.0.0-12-generic i686)

 * Documentation:  https://help.ubuntu.com/
Your Ubuntu release is not supported anymore.
For upgrade information, please visit:
http://www.ubuntu.com/releaseendoflife

New release '12.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

flag08@nebula:~$ id
uid=991(flag08) gid=991(flag08) groups=991(flag08)
```

Voila!
