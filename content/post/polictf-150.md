+++
author = "pwntester"
categories = ["polictf2015"]
date = 2015-07-12T09:55:56Z
description = ""
draft = false
slug = "polictf-150"
tags = ["polictf2015"]
title = "PoliCTF 2015. Web150 - John The Referee"

+++

We are presented with an online shop to buy Referee t-shirts:
![](/images/2015/07/ref1.png)

They have ids from 1-8 and then 10 (skipping 9).

There is also a search form that seems to escape some characters:
![](/images/2015/07/Screen-Shot-2015-07-11-at-16-52-35.png)

The search submission is somehow weird. Our search is submitted to server that returns a hash that we submit back to get the actual results. So either way the hash is an encrypted version of our search query that is decrypted and executed in the server or its a hash that represents the query and its mapped to our query in the server sesssion. Since there are no session cookies, it seems the former. So the process is the following, we submit our search query, it goes to the server where it gets escaped and encrypted. We get the encrypted value that we submit again for the server to decrypt and run the query. Since the query was escaped before encryption, there is no reason to not trust the decrypted query, right? someone said integrity? Ok, so all we have to do is submit our SQLi payload and replace the single quote with any arbitrary character. Then bit flip that character and send to server and see if any flipped queries result in a valid query with a single quote:
![](/images/2015/07/ref3.png)
![](/images/2015/07/ref2-1.png)

Now we can take the encrypted query and replay it bitflipping the first character (`a`) until it or the next one (eg: cbc) becomes a single quote. We get the flag:
![](/images/2015/07/ref5.png)


