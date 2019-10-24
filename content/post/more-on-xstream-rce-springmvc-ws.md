+++
author = "pwntester"
categories = ["SpringMVC", "Java", "RCE", "XStream"]
date = 2013-12-24T10:25:00Z
description = ""
draft = false
slug = "more-on-xstream-rce-springmvc-ws"
tags = ["SpringMVC", "Java", "RCE", "XStream"]
title = "More on XStream RCE: SpringMVC WS"

+++


Continuing my previous post where I mentioned that the [XStream RCE issue](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization/) issue also affected SpringMVC RESTful WebServices using the XStream SpringOXM wrapper, I  wanted to share a POC server. The code is quite simple and can be found in the [XStreamServer GitHub Repo](https://github.com/pwntester/XStreamServer). It contains a WebService defined by the **ContactController**:

```lang-java line-numbers 
@Controller
@RequestMapping("/contacts")
public class ContactController {

    @Autowired
    private ContactRepository contactRepository;

    @RequestMapping( value = "/{id}", method = RequestMethod.GET )
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public final Contact get( @PathVariable( "id" ) final Long contactId ){
        System.out.println("get");
        return contactRepository.findOne(contactId);
    }

    @RequestMapping( method = RequestMethod.POST )
    @ResponseStatus( HttpStatus.CREATED )
    @ResponseBody
    public final String create( @RequestBody final Contact contact ){
        System.out.println("Contact name: " + contact.getFirstName());
        contactRepository.save((ContactImpl) contact);
        return "OK";
    }
}
```

The **create** method binds an incoming XML message with a **Contact** instance. This application is configured to use **XStream** as its binding library as shown here:

```lang-markup line-numbers 
<!-- Marshaller configuration -->
<bean id="marshallingHttpMessageConverter" class="org.springframework.http.converter.xml.MarshallingHttpMessageConverter">
    <property name="marshaller" ref="xstreamMarshaller"/>
    <property name="unmarshaller" ref="xstreamMarshaller"/>
</bean>

<bean id="xstreamMarshaller" class="org.springframework.oxm.xstream.XStreamMarshaller">
    <property name="aliases">
        <props>
            <prop key="contact">org.pwntester.springserver.ContactImpl</prop>
        </props>
    </property>
</bean>
```

So SpringMVC will handle the XML document to the SpringOXM wrapper for unmarshalling. SpringOXM uses the **XStreamMarshaller** so it will simply call **XStream** in order to unmarshall the **Contact** object. At this point and with the details provided in the [XStream RCE post](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization/) its game over.

Use maven and jetty to start the server:
```lang-bash line-numbers 
mvn -Djetty.port=8080 -DDebug clean jetty:run
```

Expected use:
```lang-bash line-numbers 
curl --header "content-type: application/xml" --data @contact.xml "http://localhost:8080/contacts"
```

Exploit knowing the interface:
```lang-bash line-numbers 
curl --header "content-type: application/xml" --data @exploit.xml "http://localhost:8080/contacts"
```

Generic Exploit:
```lang-bash line-numbers 
curl --header "content-type: application/xml" --data @exploit2.xml "http://localhost:8080/contacts"
```

## What to do about it
When I reported the issue to the Spring Security Team they updated their documentation and they added a CatchAllConverter for the users to use if they wish:

Documentation changes:

* [https://github.com/SpringSource/spring-framework/commit/4da7e304b86c9528d05b51b02459ee071b65e68a#spring-oxm/src/main/java/org/springframework/oxm/xstream/XStreamMarshaller.java](https://github.com/SpringSource/spring-framework/commit/4da7e304b86c9528d05b51b02459ee071b65e68a#spring-oxm/src/main/java/org/springframework/oxm/xstream/XStreamMarshaller.java)
* [https://github.com/SpringSource/spring-framework/commit/5311e84c64cb453e3779a4f235c5030b7c569edd#spring-oxm/src/main/java/org/springframework/oxm/xstream](https://github.com/SpringSource/spring-framework/commit/5311e84c64cb453e3779a4f235c5030b7c569edd#spring-oxm/src/main/java/org/springframework/oxm/xstream)
* [https://github.com/SpringSource/spring-framework/commit/d9bfac393bc8f2df93a29cf685e7d81c222a59e7#spring-oxm/src/main/java/org/springframework/oxm/xstream](https://github.com/SpringSource/spring-framework/commit/d9bfac393bc8f2df93a29cf685e7d81c222a59e7#spring-oxm/src/main/java/org/springframework/oxm/xstream)

Jira ticket to create a new **CatchAllConverter**:

* [https://jira.springsource.org/browse/SPR-10821?page=com.googlecode.jira-suite-utilities:transitions-summary-tabpanel](https://jira.springsource.org/browse/SPR-10821?page=com.googlecode.jira-suite-utilities:transitions-summary-tabpanel)

> The main purpose of the catch-all converter class is to register itself as a catchall last converter with normal (or higher) priority, after converters that support specific domain classes. That way default XStream converters with lower priorities and **possible security vulnerabilities** do not get invoked.

They added the catch-all converter which is great but they did not register it by default so unless your XStreamMarshaller config looks the following, you will be in trouble:

```lang-markup line-numbers 
<!-- Marshaller configuration -->
<bean id="marshallingHttpMessageConverter" class="org.springframework.http.converter.xml.MarshallingHttpMessageConverter">
    <property name="marshaller" ref="xstreamMarshaller"/>
    <property name="unmarshaller" ref="xstreamMarshaller"/>
</bean>

<bean id="xstreamMarshaller" class="org.springframework.oxm.xstream.XStreamMarshaller">
    <property name="aliases">
        <props>
            <prop key="contact">org.pwntester.springserver.ContactImpl</prop>
        </props>
    </property>
    <property name="converters">
        <list>
            <bean class="org.springframework.oxm.xstream.CatchAllConverter"/>
            <bean class="org.pwntester.springserver.ContactConverter"/>
        </list>
    </property>
</bean>
```

Please note that Spring documentation is wrong and the "CatchAllConverter" needs to be registered in the first place so it gets lower priority as showed in the [XStreamMarshaller.setConverters](http://grepcode.com/file/repo1.maven.org/maven2/org.springframework.ws/spring-ws/1.5.10/org/springframework/oxm/xstream/XStreamMarshaller.java#XStreamMarshaller.setConverters%28org.springframework.oxm.xstream.ConverterMatcher[]%29) code and not in the last place as suggested by the documentation:

```lang-java line-numbers 
    public void  [More ...] setConverters(ConverterMatcher[] converters) {
        for (int i = 0; i < converters.length; i++) {
            if (converters[i] instanceof Converter) {
                getXStream().registerConverter((Converter) converters[i], i);
            }
            else if (converters[i] instanceof SingleValueConverter) {
                getXStream().registerConverter((SingleValueConverter) converters[i], i);
            }
            else {
                throw new IllegalArgumentException("Invalid ConverterMatcher [" + converters[i] + "]");
            }
        }
    }
```

So summing up, if you are using XStream marshaller in your SpringMVC web service and havent set any Catch-All Converter, you are screwed. But it has an easy (undocumented) solution:

* Write a custom converter for each of the classes you are expecting
* Register a **CatchAllConverter** followed by your custom converters in the **XStreamMarshaller** configuration.

Thanks for reading!
