+++
author = "pwntester"
categories = ["post"]
date = 2014-04-24T11:52:00Z
description = ""
draft = false
slug = "struts2-0day-in-the-wild"
tags = ["post"]
title = "Struts2 0day in the wild"

+++


### Remote code execution 0 day in up-to-date Struts 2 applications:
Some months ago Struts2 announced a security vulnerability  [S2-020](http://struts.apache.org/release/2.3.x/docs/s2-020.html) that allowed ClassLoader manipulation and that could be used to get Remote Code Execution on certain application servers like Tomcat 8. The [fix](https://github.com/apache/struts/commit/aaf5a3010e3c11ae14e3d3c966a53ebab67146be) for this vulnerability was to forbid the `(.*\.|^)class\..*` regex from action parameters. However a [bypass](http://blog.vulnhunt.com/index.php/2014/04/24/apache_struts2_0day/) was made public that basically consists in changing the dot notation for the square bracket notation. So instead of using `class.classloader` to access the classloader, the bypass used `class['classLoader']`. I just verified the bypass on my local PoC with latest Struts version (2.3.16.1) and I was able to pop up an evil calc. Also it is possible to bypass the original regex by using `Class.classloader` (with capital 'C').

#### Remediation:
While Struts2 releases a fix, please update your `excludeParams` regex to account for the opening square bracket and capital 'C':

`(.*\.|^)(class|Class)(\.|\[).*`

**Update:**
After talking with Struts2 security team, they confirmed they are working on the patch and the regex to be released will be:
`(.*\.|^|.*|\[('|"))(c|C)lass(\.|('|")]|\[).*`

The easiest way is to modify your struts config file and add:

```lang-bash line-numbers 
<struts>
...
...
    <package name="default" namespace="/" extends="struts-default">
        <interceptors>
            <interceptor-stack name="secureParamInterceptor">
                <interceptor-ref name="defaultStack">
                    <param name="params.excludeParams">(.*\.|^|.*|\[('|"))(c|C)lass(\.|('|")]|\[).*,^dojo\..*,^struts\..*,^session\..*,^request\..*,^application\..*,^servlet(Request|Response)\..*,^parameters\..*,^action:.*,^method:.*</param>
                </interceptor-ref>
            </interceptor-stack>
        </interceptors>

        <default-interceptor-ref name="secureParamInterceptor" />
        ...
        ...
    </package>
...
...
</struts>
```

Stay secure!

