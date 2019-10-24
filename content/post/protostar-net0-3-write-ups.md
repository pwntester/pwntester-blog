+++
author = "pwntester"
categories = ["protostar", "net0", "net1", "net2", "net3"]
date = 2013-12-21T13:28:00Z
description = ""
draft = false
slug = "protostar-net0-3-write-ups"
tags = ["protostar", "net0", "net1", "net2", "net3"]
title = "Protostar net0-3 write-ups"

+++

## Net 0
In this [level](http://exploit-exercises.com/protostar/net0) we are presented with an integer and we have to reply the server with a little endian version of the integer. We use python and the struct module to do the conversion for us:

```lang-python line-numbers 
from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 2999))
challange = s.recv(1024)
start = challange.find("'") + 1
end = challange.find("'", start)
num = int(challange[start:end])
print "Challange: " + str(num)
li = pack("<I", num)
s.send(li)
print(s.recv(1024))
s.close()
```

And the result:

```lang-bash line-numbers 
user@protostar:~$ python net0.py
Challange: 637794649
Thank you sir/madam
```

## Net 1
In this [level](http://exploit-exercises.com/protostar/net1) we are presented with an integer in little endian representation and we have to send back se ASCII representation. The following script can do that:

```lang-python line-numbers 
from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 2998))

wanted = s.recv(1024)
challange = str(unpack("<I", wanted)[0])
print("Received: " + str(challange))
s.send(challange)

print(s.recv(1024))
s.close()
```

And the result:

```lang-bash line-numbers 
user@protostar:~$ python net1.py
Received: 2033048370
you correctly sent the data
```

## Net 2
In this [level](http://exploit-exercises.com/protostar/net2) we are presented with 4 integers in little endian representation and we have to sum them and send back the little endian representation. The following script can do that:

```lang-python line-numbers 
from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 2997))

sum = 0
for i in range(4):
        n = s.recv(1024)
        num = int(unpack("<I", n)[0])
        print("Received: " + str(num))
        sum += num
print("Sum: " + str(sum))
sum = pack("<I", sum)
s.send(str(sum))

print(s.recv(1024))
s.close()
```

The output:

```lang-bash line-numbers 
user@protostar:~$ python net2.py
Received: 1586317571
Received: 1593370836
Received: 1661924573
Received: 1044911132
Sum: 5886524112
net2.py:14: DeprecationWarning: struct integer overflow masking is deprecated
  sum = pack("<I", sum)
you added them correctly
```

It seems that the integer overflow masking is deprecated so we better do it our selves:

```lang-python line-numbers 
from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 2997))

sum = 0
for i in range(4):
        n = s.recv(1024)
        num = int(unpack("<I", n)[0])
        print("Received: " + str(num))
        sum += num
print("Sum: " + str(sum))
sum &= 0xffffffff
sum = pack("<I", sum)
s.send(str(sum))

print(s.recv(1024))
s.close()
```

and no warning this time:

```lang-bash line-numbers 
user@protostar:~$ python net2.py
Received: 1138605574
Received: 1651147310
Received: 1386380907
Received: 1000341308
Sum: 5176475099
you added them correctly
```

## Net 3
In this [level](http://exploit-exercises.com/protostar/net3) we are given the following code:

```lang-clike line-numbers 
#include "../common/common.c"

#define NAME "net3"
#define UID 996
#define GID 996
#define PORT 2996

/*
 * Extract a null terminated string from the buffer
 */

int get_string(char **result, unsigned char *buffer, u_int16_t len)
{
  unsigned char byte;

  byte = *buffer;

  if(byte > len) errx(1, "badly formed packet");
  *result = malloc(byte);
  strcpy(*result, buffer + 1);

  return byte + 1;
}

/*
 * Check to see if we can log into the host
 */

int login(unsigned char *buffer, u_int16_t len)
{
  char *resource, *username, *password;
  int deduct;
  int success;

  if(len < 3) errx(1, "invalid login packet length");

  resource = username = password = NULL;

  deduct = get_string(&resource, buffer, len);
  deduct += get_string(&username, buffer+deduct, len-deduct);
  deduct += get_string(&password, buffer+deduct, len-deduct);

  success = 0;
  success |= strcmp(resource, "net3");
  success |= strcmp(username, "awesomesauce");
  success |= strcmp(password, "password");

  free(resource);
  free(username);
  free(password);

  return ! success;
}

void send_string(int fd, unsigned char byte, char *string)
{
  struct iovec v[3];
  u_int16_t len;
  int expected;

  len = ntohs(1 + strlen(string));

  v[0].iov_base = &len;
  v[0].iov_len = sizeof(len);

  v[1].iov_base = &byte;
  v[1].iov_len = 1;

  v[2].iov_base = string;
  v[2].iov_len = strlen(string);

  expected = sizeof(len) + 1 + strlen(string);

  if(writev(fd, v, 3) != expected) errx(1, "failed to write correct amount of bytes");

}

void run(int fd)
{
  u_int16_t len;
  unsigned char *buffer;
  int loggedin;

  while(1) {
    nread(fd, &len, sizeof(len));
    len = ntohs(len);
    buffer = malloc(len);

    if(! buffer) errx(1, "malloc failure for %d bytes", len);

    nread(fd, buffer, len);

    switch(buffer[0]) {
      case 23:
        loggedin = login(buffer + 1, len - 1);
        send_string(fd, 33, loggedin ? "successful" : "failed");
        break;

      default:
        send_string(fd, 58, "what you talkin about willis?");
        break;
    }
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run(fd);
}
```

The program is reading a value from the network (len) and convert it from network byte order (bin endian) to host byte order (little endian) and then uses malloc to reserve that length in the heap

Then it reads again from the network the number of bytes specified in the length value and into the heap chunk we just reserved.

Then it reads the first byte and if it is 23 (0x17) then it calls the login function with the rest of the string read from the network

The login function scans the string for three values: net3, awesomesauce and password
Each of these strings need to be preceded of a byte indicating its size (including the null byte) and followed by a NULL byte.

Solution:

```lang-python line-numbers 
from socket import *
from struct import *

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", 2996))

# Send the login string
login = "\x17" + "\x05net3\x00" + "\x0dawesomesauce\x00" + "\x0apassword\x00"
llength = len(login)

print "Sending login string: " + login
print "length: " + str(llength)

# Send the login length as unsigned short (H) and network byte order (!)
s.send(pack("!H", llength))
s.send(login)

print(s.recv(1024))
s.close()
```

```lang-bash line-numbers 
user@protostar:~$ python net3.py
awesomesaucen string: net3
password
length: 31

!successful
```
