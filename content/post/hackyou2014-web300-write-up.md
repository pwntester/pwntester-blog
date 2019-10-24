+++
author = "pwntester"
categories = ["CTF", "Web", "PHP", "HackYou2014"]
date = 2014-01-15T18:33:00Z
description = ""
draft = false
slug = "hackyou2014-web300-write-up"
tags = ["CTF", "Web", "PHP", "HackYou2014"]
title = "#hackyou2014 Web300 write-up"

+++


In this [level]() we were presented with an online shop:

![](/images/octopress/web300-1.png)

The task name was "AngryBird" and this was very relevant to solve the challange! It actually comes down to two parts:

* Finding a hidden admin area
* Exploiting a blind SQLi to get credentials

## Finding the hidden admin area
We were given the following description:

> Some web-developers still host their sites on Windows platform, and think that it is secure enough

So we have to unravel our Windows PHP trickery and one of the coolest thigs Ive seen lately is this [Windows+PHP bug realted with **findfirstfile**](http://onsec.ru/onsec.whitepaper-02.eng.pdf). If you havent read the paper so far, go and read it, is awesome!.

Anyway, using this trick on the main page and a little bit of burp intruder, we can find interesting hidden stuff. For examplo:

```lang-bash line-numbers 
http://hackyou2014tasks.ctf.su:30080/index.php?page=p<<
```

the "p&lt;&lt;" bit will become "p*" and Windows's findfirstfile API used by include_once will return us the first file starting with "p" and it will show us **phpinfo()**

![](/images/octopress/phpinfo.png)

Using same trick we can see that "0&lt;&lt;" returns an expty page instead of a "Page does not exists", so it can be the beggining of a directory name. After bruteforcing it we find a secret admin login in

```lang-bash line-numbers 
http://hackyou2014tasks.ctf.su:30080/0a5d2eb35b90e338ed481893af7a6d78/index.php
```

Now we need the credentials.

## Exploiting the Angry Bird
Its easy to find that the order parameter is vulnerable to SQL injection:

```lang-bash line-numbers 
http://hackyou2014tasks.ctf.su:30080/index.php?page=shop&order=cost
```

We cannot actually uses single quotes or many other characters because of the WAF, but we can easily prove it with the following URLs:

```lang-bash line-numbers 
http://hackyou2014tasks.ctf.su:30080/index.php?page=shop&order=cost ASC
```

![](/images/octopress/web300-2.png)

```lang-bash line-numbers 
http://hackyou2014tasks.ctf.su:30080/index.php?page=shop&order=cost DESC
```

![](/images/octopress/web300-3.png)

We can use a similar approach to the one explained [here](http://www.tuxz.net/blog/archives/2010/11/21/sql_injection__exploiting_the_order_by_clause/) but if we try similar queries we get errors.
So the DB backend doesnt look like MySQL nor MSSQLServer ... but what the hell can be. Well, actually the task name was quite inspiring: Firebird.

After setting up a local instance and learning the basics of firebird syntax and how the WAF works (substring is not allowed), we come with some valid queries like:

```lang-bash line-numbers 
(case when (select ascii_val(reverse(left(list(rdb$relation_name),{1}))) from rdb$relations) = 82 then name end)
```

Using a basic python script we brute force it and find the following user tables: USERS and ITEMS

Using similar script we can extract all the users and passwords and so we get: admin/9shS3FAk
If we try those credentials in the admin page, we get the flag:

> CTF{7aac9050378b1c41e4ba5ce48a2f6642}
