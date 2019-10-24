+++
author = "pwntester"
categories = ["post"]
date = 2012-10-30T09:18:00Z
description = ""
draft = false
slug = "fourgoats-vulnerabilities-hardcoded-backdoor"
tags = ["post"]
title = "FourGoats Vulnerabilities: Hardcoded Backdoor"

+++

If we keep on reading the Login activity, we will soon spot an asynchronous task used to validate the user credentials in the server and we will see that there is a harcoded user/password pair that will set up the admin property and so it will enable us to access the AdminHome Activity:

```
if (userName.equals("customerservice") &&
password.equals("Acc0uNTM@n@g3mEnT")) userInfo.put("isAdmin", "true");
```

If we enter these credentials (and the user is registered in the backend), we will be able to access the AdminHome Activity:

{% img /images/c9fd9-admin-scaled1000.png %}
