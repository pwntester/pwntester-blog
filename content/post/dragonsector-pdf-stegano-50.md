+++
author = "pwntester"
categories = ["stegano", "pdf"]
date = 2014-04-27T16:47:00Z
description = ""
draft = false
slug = "dragonsector-pdf-stegano-50"
tags = ["stegano", "pdf"]
title = "DragonSector PDF Stegano 50"

+++

This was the task that most player solved (89). We were given a PDF with a Lorem ipsum text. Using PeePDF from [@EternalTodo](https://twitter.com/EternalTodo) we can easily analyze the PDF.

The `info` command shows two suspicious sectors:

![](/images/octopress/dsctf-21.png)

But the `metadata` one shows more interesting stuff:

![](/images/octopress/dsctf-22.png)

It seems there may be a morse code hidden in the PDF. Looking around different PFD objects we see something interesting in object 8:

![](/images/octopress/dsctf-23.png)

If we treat A's and B's as dots and dashes we get the following texts:

```lang-bash line-numbers 
BABA BBB B A BBA ABA AB B AAB ABAA AB B AA BBB BA AAA BBAABB AABA ABAA AB BBA BBBAAA ABBBB BA AAAB ABBBB AAAAA ABBBB BAAA ABAA AAABB BB AAABB AA AAA AAAAA AAAAB BBA AAABB

.-.- ... . - ..- -.- -. . --. -.-- -. . -- ... .- --- ..--.. --.- -.-- -. ..- ...--- -.... .- ---. -.... ----- -.... .--- -.-- ---.. .. ---.. -- --- ----- ----. ..- ---..
?SETUKNEGYNEMSAO?QYNU?6A?606JY8I8MO09U8
-.-. --- - . --. .-. .- - ..- .-.. .- - .. --- -. ... --..-- ..-. .-.. .- --. ---... .---- -. ...- .---- ..... .---- -... .-.. ...-- -- ...-- .. ... ..... ....- --. ...--
COTEGRATULATIONS,FLAG:1NV151BL3M3IS54G3
```

There is something wrong with my decoding since CONGRATULATIONS is decoded as COTEGRATULATIONS, but the flag looks ok except for the extra 'I' and 'S' that turned out to be another '5'. So the flag was:

`1NV151BL3M3554G3`

