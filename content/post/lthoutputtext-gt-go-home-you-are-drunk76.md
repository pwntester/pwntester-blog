+++
author = "pwntester"
categories = ["JSF", "outputText"]
date = 2014-02-14T17:43:00Z
description = ""
draft = false
slug = "lthoutputtext-gt-go-home-you-are-drunk76"
tags = ["JSF", "outputText"]
title = "&lt;h:outputText/&gt; go home you are drunk!"

+++

This is just a copy of the post I wrote in the [HP corporate blog](http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/JSF-outputText-tag-the-good-the-bad-and-the-ugly/ba-p/6368011), but just wanted to post it as well to spread the word:

While working on a JSF (Java Server Faces) test case recently I had one of those WAT?!?! moments - where something you take for granted starts behaving in a completely different way from how you expect. In this case it was even worse, since the behavior I was observing was breaking my application security and undermining the trust I place on libraries and frameworks as a developer.

##The good

The http://java.sun.com/jsf/html/outputText tag renders basic text on your JSF page. You can customize the appearance of the text using CSS styles, in which case the generated text is wrapped in an HTML &lt;span&gt; element. What developers know and trust is that by default the &lt;h:outputText&gt; tag encodes the rendered text if it contains sensitive HTML and XML characters, making it safe for an HTML context.

The following example is XSS safe:

```lang-bash line-numbers 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:h="http://java.sun.com/jsf/html">
<h:head />
<body>
<h:outputText value="#{param.xss}" />
</body>
</html>
```

##The bad

What is less known - and undocumented - is that within &lt;script&gt; and &lt;style&gt; blocks, &lt;h:outputText&gt; and other similar tags like &lt;h:outputLabel&gt; disable their HTML encoding, making the following example XSS vulnerable:

```lang-bash line-numbers 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:h="http://java.sun.com/jsf/html">
<h:head />
<body>
<script>
  var a = <h:outputText value="#{param.xss}" />;
</script>
</body>
</html>
```

This can be dangerous if developers are not aware of this behavior and trust &lt;h:outputText&gt; encoding beyond its own capabilities.

##The ugly

The HP Software Security Research Group found that &lt;h:outputText&gt; tags immediately following &lt;script&gt; or &lt;style&gt; blocks are not encoded either making the following example XSS vulnerable:

```lang-bash line-numbers 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:h="http://java.sun.com/jsf/html">
<h:head />
<body>
<script>
    var a = “test”;
</script>
<h:outputText value="#{param.xss}" />
</body>
</html>
```

This bug not only applies to the &lt;h:outputText&gt; tag but also to raw EL expressions. For example:

```lang-bash line-numbers 
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:h="http://java.sun.com/jsf/html">
<h:head />
<body>
<script>
    var a = “test”;
</script>
#{param.xss}
</body>
</html>
```

Necessary and Sufficient Conditions For the Vulnerability to be Present:

* Must have an EL expression immediately after a &lt;/script&gt; element, without any intervening components or markup, and the EL expression must contain the XSS attacking code.  The presence of any intervening markup between the &lt;/script&gt; and the EL expression causes this bug to not manifest.
* Must be using a version of Mojarra that is subject to the vulnerability.  Any versions older than 2.2.6-SNAPSHOT and 2.1.28-SNAPSHOT are subject to the vulnerability.

##Disclosure

These issues, the lack of documentation around outputText behavior within &lt;script&gt; or &lt;style&gt; blocks and the lack of output encoding when tags follow a &lt;/script&gt; or &lt;/style&gt; end tag, have been reported to the Oracle JSF team. The fixes are due to be released in the next JSF version:

[https://java.net/jira/browse/JAVASERVERFACES-3150](https://java.net/jira/browse/JAVASERVERFACES-3150)
[https://java.net/jira/browse/JAVASERVERFACES_SPEC_PUBLIC-1258](https://java.net/jira/browse/JAVASERVERFACES-3150)

We decided to disclose these issues before the release of the patched version as we understand that this disclosure does not give any advantage to attackers already testing for XSS issues. However, by providing the vulnerable patterns as soon as possible we can help developers to better protect their applications.

CVE Id assigned is CVE-2013-5855.

##Workaround

JSF won’t escape raw EL expressions or the &lt;h:outputText&gt; tag family within &lt;script&gt; or &lt;style&gt; blocks, so manual encoding is required if untrusted data is used in these contexts. We recommend using Javascript context encoders like the one in OWASP ESAPI

Also, make sure you are either using a patched JSF version, or that every &lt;/script&gt; element has at least one intervening markup element present between it and the next EL expression, either embedded in the page, or on the right hand side of an attribute in a JSF UI Component Tag.


##Conclusion

As developers we trust the libraries and frameworks we use to build our applications, and since we depend on them so strongly we don’t really have a choice. This puts the risk and responsibility on us to monitor the component projects we use and make sure we update to the latest versions when serious quality or security issues are found.
