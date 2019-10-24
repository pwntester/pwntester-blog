+++
author = "pwntester"
categories = ["CTF", "HackYou2014", "Crypto"]
date = 2014-01-16T20:26:00Z
description = ""
draft = false
slug = "hackyou2014-crypto100-write-up"
tags = ["CTF", "HackYou2014", "Crypto"]
title = "#hackyou2014 Crypto100 write-up"

+++

In this [level](http://hackyou.ctf.su/tasks/crypto100) we are asked to break a code and decrypt [msg002.enc](http://hackyou.ctf.su/files/crypto100.zip). We are given the encryptor code without the key:

```lang-clike line-numbers 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("USAGE: %s INPUT OUTPUT\n", argv[0]);
        return 0;
    }
    FILE* input  = fopen(argv[1], "rb");
    FILE* output = fopen(argv[2], "wb");
    if (!input || !output) {
        printf("Error\n");
        return 0;
    }
    char k[] = "CENSORED";
    char c, p, t = 0;
    int i = 0;
    while ((p = fgetc(input)) != EOF) {
        c = (p + (k[i % strlen(k)] ^ t) + i*i) & 0xff;
        t = p;
        i++;
        fputc(c, output);
    }
    return 0;
}
```

And we are also given a plaintext (msg001) and its corresponding cryptotext (msg001.enc) so we can easily extract the key with something like:

```lang-clike line-numbers 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("USAGE: %s CRYPTO \n", argv[0]);
        return 0;
    }
    FILE* input  = fopen(argv[1], "rb");
    if (!input) {
        printf("Error\n");
        return 0;
    }

    char c, p, t = 0;
    int i = 0;

    // We use the following loop to get the key knowing the cryptotext(input) and plaintaext(w[])
    char w[] = "Hi! This is only test message";
    unsigned int j = 0;
    while ((p = fgetc(input)) != 0) {
        // printf("read %d", p);
        for (j=31;j<125;j++) {
            c = (p - (j ^ t) - i*i) & 0xff;
            if (c == w[i]) {
                printf("%c\n",j);
                t = c;
                i++;
                break;
            }
        }
    }
    return 0;
}
```

The resulting key is: **VeryLongKeyYouWillNeverGuess**
Now we can use a decryptor to extract msg002:

```lang-clike line-numbers 
 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>

 int main(int argc, char **argv) {
    if (argc != 3) {
         printf("USAGE: %s INPUT OUTPUT\n", argv[0]);
         return 0;
     }
     FILE* input  = fopen(argv[1], "rb");
     FILE* output = fopen(argv[2], "wb");
     if (!input || !output) {
         printf("Error\n");
         return 0;
     }


     char c, p, t = 0;
     int i = 0;

    char k[] = "VeryLongKeyYouWillNeverGuess";
    i = 0;
    c, p, t = 0;
    int g = 0;
    while ((p = fgetc(input)) != 1) {
        c = (p - (k[i % strlen(k)] ^ t) - i*i) & 0xff;
         printf("Decrypting %x i=%d t=%d k=%d -> %d\n",p,i,t,(k[i % strlen(k)] ^ t),c);
        t = c;
        i++;
         //printf("%c",c);
         fputc(c, output);
         g++;
         if (g>450) {break;}
    }

    return 0;
 }

```

And the results are:

> The known-plaintext attack (KPA) is an attack model for cryptanalysis where the attacker has samples of both the plaintext (called a crib), and its encrypted version (ciphertext). These can be used to reveal further secret information such as secret keys and code books. The term "crib" originated at Bletchley Park, the British World War II decryption operation.
> The flag is CTF{6d5eba48508efb13dc87220879306619}

