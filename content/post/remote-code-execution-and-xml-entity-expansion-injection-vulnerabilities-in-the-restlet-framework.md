+++
author = "pwntester"
categories = ["post"]
date = 2014-03-26T18:05:00Z
description = ""
draft = false
slug = "remote-code-execution-and-xml-entity-expansion-injection-vulnerabilities-in-the-restlet-framework"
tags = ["post"]
title = "Remote code execution and XML Entity Expansion injection vulnerabilities in the Restlet framework"

+++


This blog was published in the [**HP Security research blog**](http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/Remote-code-execution-and-XML-Entity-Expansion-injection/ba-p/6403370) but publishing it here for greater dissemination:

## Advisory overview

Restlet is a lightweight Java framework for building RESTful APIs. It comes in different flavors (Java SE, Java EE, Android, Google Web Toolkit and Google App Engine) and is composed of a core API and different extensions that provide additional functionality.

While adding support for the Restlet API to HP Fortify SCA, the Software Security Research group discovered that the XStream extension prior to 2.2 RC3 is susceptible to Remote Code Execution (RCE) via unsafe deserialization of XML messages. Also, versions prior to 2.1.7 and 2.2 RC1 contain APIs susceptible to XML Entity Expansion (XEE) injection, including the default extension to handle XML messages (JAXB).

## Remote code execution via unsafe XStream deserialization

RESTful APIs normally deal with JSON or XML Messages. If the latter is used, a broad set of XML data binding options are available for the developer to choose from; JAXB, JiBX and XStream amongst others. XStream is unique because it allows more than simple Java POJOs to be serialized. In particular, it allows the serialization of [Java Dynamic Proxies](http://docs.oracle.com/javase/7/docs/api/java/lang/reflect/Proxy.html). If the application is configured to use the XStream extension to handle XML messages, an attacker can easily abuse it by sending specially crafted XML messages that use Dynamic Proxy serialization to execute arbitrary code on the server side. HP SSR previously identified a similar vulnerability in the core XStream library and the frameworks using it (such as SpringMVC, for example).

### Details

A dynamic proxy  can intercept calls to any method declared in the interface it implements.

Dynamic proxy deserialization allows an attacker to send a serialized object that invokes dynamic proxy methods during its initialization, the simplest case being a [java.util.SortedSet](http://docs.oracle.com/javase/7/docs/api/java/util/SortedSet.html) that includes a regular object like a String and an object that proxifies the [java.lang.Comparable](http://docs.oracle.com/javase/7/docs/api/java/lang/Comparable.html) interface. During the deserialization of the SortedSet, the “compare” method of each object in the set is invoked in order to sort the set and the proxified object will replace the original call to “compare” with the attacker’s custom payload.

When the Restlet controller receives a malicious XML payload, it attempts to de-serialize it using XStream, effectively executing the malicious payload. Since the application would not normally be expecting a SortedSet, it throws an exception as soon as the SortedSet is cast to the expected type but the payload has already executed.

### Mitigation

If your application relies on the use of XStream, make sure it uses at least Restlet [2.2 RC3 where a whitelist feature](https://github.com/restlet/restlet-framework-java/wiki/XStream-security-enhancements) has been added to prevent the deserialization of unexpected objects.

## XML Entity Expansion (XEE) injection

The core API uses JAXB to unmarshall XML messages on both client and server code by default. Restlet failed to disable local entity resolution, enabling attackers to run XEE (XML Entity Expansion) attacks -- attackers could perform Denial of Service (DOS) attacks on Restlet-based web services.

This is not the first time we’ve found this type of problem in RESTful frameworks. Last August we found that all SpringMVC/JAXB-based web services were vulnerable to XXE (XML External Entity) attacks as described in [CVE-2013-4152](http://www.gopivotal.com/security/cve-2013-4152) (details published by the SpringMVC team).

If you are not familiar with these types of vulnerabilities, you can learn how [XXE and XEE attacks work in our XML Entity based attacks post](http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/HP-Security-Research-Threat-Intelligence-Briefing-Episode-6/ba-p/6156265#.Uvz_OV7-S-g).

In this case, Restlet APIs were correctly configured to disable external entity resolution by default and were not vulnerable to XXE attacks. However, Doctype blocks (DTD) processing and local entity resolution were allowed and, more importantly, could not be disabled by any configuration property, making all the Restlet-based web services consuming XML messages vulnerable to this attack.

### Details

The following snippet describes a simplified Restlet Server Resource consuming XML messages sent by clients to create Contacts:

```lang-bash line-numbers 
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.restlet.ext.xml.XmlRepresentation;

public class XMLResource extends ServerResource {
    @Post("xml")
    public Contact createContact(Contact c) {
        System.out.println("Contact received: " + c.getName());
        return c;
    }
}
```

Since Restlet versions prior to version 2.1.7 and 2.2 RC1 do not disable local entity resolution, an attacker could send a contact like this:

```lang-bash line-numbers 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<contact>
    <name>&lol9;</name>
    <lastName>test</lastName>
</contact>
```

When processed internally by the Restlet XML processor (that uses JAXB by default) for instantiating a Contact object, the name of the contact unfolds into more than 1 billion “lol” strings - using almost 3GB of memory and crashing the Java Virtual Machine (JVM) on the server. This attack is also known as the [Billion laughs attack](http://en.wikipedia.org/wiki/Billion_laughs).

The Restlet components affected by this vulnerability are:

* "xml" extension,
* "atom", "javamail", "lucene", "odata", "openid", "rdf", "wadl", "xdb" that directly depends on the "xml" extension.
* "jackson", "jaxb", "jibx", "xstream", "rome" that provides automatic converters.

### Mitigation

Update to Restlet versions 2.1.7, 2.2 RC1 and above that disable local entity resolution by default.

More technical details can be found in the [Restlet technical note](https://github.com/restlet/restlet-framework-java/wiki/XEE-security-enhancements).

## CVEs

* Remote Code Execution via XStream deserialization - [CVE-2014-2228](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2228).
* XML Entity Expand (XEE) Injection - [CVE-2014-1868](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1868).
