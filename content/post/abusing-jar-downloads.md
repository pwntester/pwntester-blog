+++
author = "pwntester"
categories = ["XXE", "Java"]
date = 2013-11-28T20:45:00Z
description = ""
draft = false
slug = "abusing-jar-downloads"
tags = ["XXE", "Java"]
title = "Abusing jar:// downloads"

+++

Recently I saw Timothy Morgan ([@ecbftw](https://twitter.com/ecbftw)) presentation on OWASP AppSec USA'13 ([Video](http://www.youtube.com/watch?v=eHSNT8vWLfc&feature=youtu.be)) where he explained a clever trick to exploit a **XXE** or **SSRF** vulnerability fooling the server to fetch a file for us using the **jar://** protocol. The trick is to serve the file but keep the connection opened, so our file is effectively uploaded to the victim server and stored on a temporary location until we close the connection. The server needs to keep the temporary file till the connection is closed and he can try to unzip it to access the inner resource pointed in the **jar://** URL. As long as we keep the connection opened, we will be able to exploit the same XXE issue to locate the temporary file and use it to commit other attacks as the one explained in the video.

I decided to give the trick a try and implemented a simple Java blocking server that will serve our malicious payload and keep the connection open so we have time to use it for our attacking purposes. The blocking server can be found in my [github repo](https://github.com/pwntester/BlockingServer).

The trick works like a charm and in my case (OSX) the temporary file was stored on **/var/folders/q0/tx9tt7p511qbxt26vl0wtxqr0000gn/T** with the name pattern: **jar_cachexxxxxxxxxxxxxxxx.tmp**.

Have fun!
