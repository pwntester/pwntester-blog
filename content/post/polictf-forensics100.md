+++
author = "pwntester"
categories = ["polictf2015"]
date = 2015-07-12T09:54:02Z
description = ""
draft = false
slug = "polictf-forensics100"
tags = ["polictf2015"]
title = "PoliCTF 2015. Forensics100 - John In The Middle"

+++

We are given a pcap with the traffic generated to an old version of `http://polictf.it`. We can use NetworkMiner or similar tools to extract all files and compare them with the originals. `logo.png` differs from original and using StegoSolve we can find the secret flag:
![](/images/2015/07/Screen-Shot-2015-07-11-at-17-08-48.png)
