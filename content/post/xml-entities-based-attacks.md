+++
author = "pwntester"
categories = ["post"]
date = 2013-08-02T10:25:00Z
description = ""
draft = false
slug = "xml-entities-based-attacks"
tags = ["post"]
title = "XML Entities based attacks"

+++

> "Wait, I'm not clear on what's happening here. Is this even possible? Just by giving an application a single piece of XML, you can cause it to steal other files for you?"

Those were a customer’s words when an XML External Entity injection vulnerability was reported on one of his applications and although these kinds of attacks are known since the early 2000s I'm still under the impression that they are not known and tested enough by application developers and security auditors. Actually during this research we found complete frameworks like SpringMVC being vulnerable to XXE injection. Find more on the podcast and whitepaper I wrote on this interesting topic in the [HPSR blog](http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/HP-Security-Research-Threat-Intelligence-Briefing-Episode-6/ba-p/6156265#.UfuJTVPPeKg).
