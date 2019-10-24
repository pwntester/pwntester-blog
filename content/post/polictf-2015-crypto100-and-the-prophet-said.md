+++
author = "pwntester"
categories = ["polictf2015"]
date = 2015-07-12T09:55:16Z
description = ""
draft = false
slug = "polictf-2015-crypto100-and-the-prophet-said"
tags = ["polictf2015"]
title = "PoliCTF 2015. Crypto100 - And the prophet said"

+++

We are given a text that looks like base64, so we decode it and find a gzip file that contains a text file with 296 phrases from the bible. These phrases are repited so we assigned a random character to each line and got something like:

```lang-raw
abccde fagh iajccbklb gh mbno bjho ghkpf gfq gpr fnogkl fd sngfb j cdkl rbhhjlb hd hfjfghfgih sgcc abct odu sgfa fab cbffbn vnbwubkigbhx yuf gpr kdf nbjcco lddz jf fajfx d0 fajfph bkdulae jajae gpr gk cdmb sgfa hgrtcb cdsbnijhb vcjlh sgfaduf htjibh jkz hfnjklb horydchx vcjl1cyafyllumvhokfyywsyd2
```

Using a substitution decipher and a little bit of manual correction we get:

```lang-raw
hello, this challenge is very easy isn't it? i'm trying to write a long message so statistics will help you with the letter frequencies. but i'm not really good at that. ok that's enough, ahah, i'm in love with simple lowercase flags without spaces and strange symbols. flag{lbhtbgguvfsyntbbqwbo}
```

So flag is:

```lang-raw
flag{lbhtbgguvfsyntbbqwbo}
```

Which turns out to be anot valid flag. But the challange description said we need an extra step here, so we try to decode it using decoders such as ROT13 and voila:

```lang-raw
flag{yougotthisflagoodjob}
```

