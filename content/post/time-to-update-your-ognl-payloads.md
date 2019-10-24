+++
author = "pwntester"
categories = ["Java", "OGNL"]
date = 2014-01-20T15:39:00Z
description = ""
draft = false
slug = "time-to-update-your-ognl-payloads"
tags = ["Java", "OGNL"]
title = "Time to update your OGNL payloads"

+++

OGNL is an expression language for getting and setting properties of Java objects, plus other extras such as list projection, selection, lambda expressions and method invocation. So if attackers can provide the OGNL engine with arbitrary OGNL expressions, they will be able to execute arbitrary code on the application server and/or access and modify any value stored in the Struts 2 value stack.

Struts 2 provided an addition layer of protection by disabling static method invocation so that methods like **java.lang.Runtime.exec** could not be executed. This protection was bypassed in the first place by [Meder Kydyraliev](https://twitter.com/meder) who came up with the following OGNL expression where he was able to modify the required objects in order to disable the protection before actually calling the static methods:

```lang-java line-numbers data-line=1 
#_memberAccess['allowStaticMethodAccess'] = true
#rt = @java.lang.Runtime@getRuntime()
#rt.exec('calc')
```

Its important to note that even if static methods were not allowed, an attacker will normally be able to modify objects stored in the Value Stack like “Session” and cause severe damage to the running application and back end.

Due to the severity of the vulnerabilities and the number of them being reported at that time, Struts 2 decided to make the **#_memberAccess** “**allowStaticMethodAccess**” member immutable in version 2.3.14.2, effectively disabling Meder’s payload.

This control is still easily bypassable using basic Java reflection to set the “**allowStaticMethodAccess**” as an accessible field:

```lang-java line-numbers data-line=1-3 
#f = #_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')
#f.setAccessible(true)
#f.set(#_memberAccess, true)
#rt = @java.lang.Runtime@getRuntime()
#rt.exec('calc')
```

Note that even if the application is using the latest Struts 2 version, a developer can still pass user controlled data to Struts 2 methods evaluating their arguments as OGNL Expressions as the [**Apache Roller** vulnerability](http://security.coverity.com/advisory/2013/Oct/remote-code-execution-in-apache-roller-via-ognl-injection.html) found by [Jon Passki](https://twitter.com/jonpasski)

