---
layout: post
title: BUUCTF-Web
date: 2021-07-22
tags: ["web"]
---

[toc]

## EasySQL

> 考点：sql语句的猜测以及sql_mode参数的设置

[![img](20210817020714.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/07/wp_editor_md_c8cb2dbd591fcaed268155fdd3d97df3.jpg)
如图所示，输入1查询，结果发现输出1.
尝试几次，发现存在堆叠注入：
[![img](20210817020714.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/07/wp_editor_md_192c0e6f360417ed5055fc9bc1c07f58.jpg)
根据回显，大致猜测sql语句为：
`select $_POST['query']''flag from flag`
注意：**在mysql中，默认''的意思是或，而在oracle中默认''的意思是连接符号。在mysql中可以用sql语句`set sql_mode=PIPES_AS_CONCAT`来使得''符号的意义变为连接符。**
因此：
[![img](20210817020714.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/07/wp_editor_md_ceac6f8b1fb955d091fb205317a4fb3f.jpg)
`query=1;set sql_mode=PIPES_AS_CONCAT;select 1`

## [强网杯 2019]随便注

### 方法1

> 考点：
> 1.堆叠注入
> 2.sql语句desc命令（describe）查看表结构
> 3.数据库表名的更改(rename)
> 4.数据库列名的更改

开局判断注入类型，单引号字符型注入。order by判断一共有两行。使用union select联合查询，发现提示如图所示的关键字均被过滤：
[![img](20210817020714.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_83df02852a97a48e8ae2dfd9055d10ff.jpg)
select都被过滤了，尝试使用堆叠注入。

    ?inject=1';show databases;

如图，得到数据库：
[![img](20210817020714.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_f317569b3eb1501829bef5b0afeff5b6.jpg)
继续，可以得到表：

    ?inject=1';show tables;%23

[![img](20210817020714.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_55215f35b7327ec59a0601a79c41e347.jpg)
分别查看两个表的结构，如图：

    ?inject=1';desc <code>1919810931114514</code>;%23
    ?inject=1';desc words;%23

[![img](20210817020942.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_310e7e5b6178d475b4a969289073724a.jpg)

[![img](20210817020948.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_b60311754f522764ebac96573f46f15c.jpg)
**注意，此处的表名1919*需要加反引号，推测是关键字冲突或者数据类型的原因。**
根据两张表的结构，猜测很有可能直接在输入框中进行的查询就是在words表中的，而真正的flag就在1919表中。
因此我们可以直接修改两张表的名字，使得直接查询就是查询的1919表中的flag。
此处需要注意的是，输入框默认查询的是words中的id列，但1919表中没有该列，因此只需要修改任意列为id或者增添一列为id即可。

    ?inject=1';rename table words to ttt; rename table <code>1919810931114514</code> to words; alter table words change flag id varchar(10) not null;%23

### 方法2

> 考点：sql语句预编译

由题目知道题目是过滤了select等关键字的，因此可以用预编译+concat绕过。
此处提供几个payload:

    ?inject=1';PREPARE test from concat('se','lect',' * from <code>1919810931114514</code>');EXECUTE test; %23
    ?inject=1';SET @sql=concat(char(115,101,108,101,99,116),'* from <code>1919810931114514</code>');PREPARE test from @sql;EXECUTE test;%23
    ?inject=1';PREPARE test from concat(char(115,101,108,101,99,116),'* from <code>1919810931114514</code>');EXECUTE test;%23

## [极客大挑战 2019]Http

> 考点：http
> 注意X-Forwarded-For字段，用来标识连接到web服务器请求的ip地址。

## [RoarCTF 2019]Easy Calc

> 考点：
> waf的绕过
> php特殊字符的绕

首先查看源代码，发现网页开启了waf：
[![img](20210817020958.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_1b3d351c3941779e69d6dcbb8d521261.jpg)
发现网页是对get方法传入的参数进行URL编码，然后传递给calc.php进行处理。
查看calc.php发现有代码：
[![img](20210817021001.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_2285cf7cc08f41e4914448f77cfdc88e.jpg)
代码审计，发现过了了很多，然后直接有代码执行。
想扫描目录文件，但是发现有过滤，因此用chr函数绕过：

    ?num=1;var_dump(scandir(chr(47)))

结果发现执行不了：
[![img](20210817021005.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_4c198138f519cedc9caf30856e5be72a.jpg)
应该是waf给杀了
但我们并不知道waf的逻辑，只能猜测是过滤的get方法传入的num的值。
此处有**php的字符串解析漏洞**
我们传入：

    ? num=1

waf会理解为一个空格加一个num，即名为 num的变量，但php会先去除空格，因此php可以正确理解get方法传入的参数

    ? num=1;var_dump(scandir(chr(47)))

[![img](20210818151023.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_be4544fbba401a23910fd09f1fb7728c.jpg)
然后使用chr函数即可得到flag:

    ? num=1;var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))

[![img](20210817021035.jpeg)](http://code.ltfall.top/wp-content/uploads/2021/08/wp_editor_md_515d08bad33c512f00b80c7baef3840c.jpg)

## [护网杯 2018]easy_tornado

> 考点：
> 
> easy_tornado模板注入

打开环境，提示了三个文件：

![image-20210818150904282](20210818150939.png)

无内鬼，看看flag:

![image-20210818151227030](20210818151833.png)

看看，好像上当了：

![image-20210818152201134](20210818152203.png)

看看前面的welcome:

![image-20210818152625608](20210818152628.png)

听别的师傅说看到render就想到模板注入，我，我···

然后康康hint:

![image-20210818153127626](20210818153129.png)

回头看其他访问的文件都是这个样式的：

![image-20210818154648421](20210818154649.png)

说明需要找到这个cookie_secret就可以了。

修改url的filename或者filehash的任意一项，发现：

![image-20210818154855680](20210818155642.png)

url里面有Error这里就显示error是吧，牛的

try一哈子：

![image-20210818154952596](20210818155639.png)

看到这里以为是一般的模板注入，试了下不行，很多符号被过滤成这个样子：

![image-20210818155054682](20210818155636.png)

写个py来fuzz一哈：

    import requests

    for i in range(0,128):
        url = "http://f36f225e-bdbc-423c-ade8-666c5d25da50.node4.buuoj.cn:81/error?msg={{"+chr(i)+"}}"
        response = requests.get(url)
        if 'ORZ' in response.text:
            print(chr(i),end="")

过滤得还挺多：

![image-20210818155333846](20210818155632.png)

所以只能想别的法子了。。

参考了师傅的[这篇文章]([一篇文章带你理解漏洞之 SSTI 漏洞 ' K0rz3n's Blog](https://www.k0rz3n.com/2018/11/12/一篇文章带你理解漏洞之SSTI漏洞/#3-Tornado))

读一哈子tornado框架的文档，英文的，读完不现实，看一下模板渲染的语法，前面不是提示了render嘛

![image-20210818155628572](20210818155630.png)

挑关键的出来读了一下，就是说，表达式用{{}}包起来，至于%都已经被过滤了

然后就说下面的是一些模板代码，可以用比较简短的方式调用，看到这两个有点哈人：

![image-20210818155956740](20210818155957.png)

分别进去试一哈子，handler是个对象，打印出来啥也没有

request打印出来就是抓包直接可以看到的文件头，没啥用

但是handler对象肯定可以调用其中的方法的。

handler是RequestHandler这个对象，无内鬼，搜一下：

![image-20210818160509020](20210818160510.png)

第一个看一哈子

里面可以找到这个

![image-20210818160726245](20210818160727.png)

参考上面写的师傅的wp，其实tornado框架代码里面secret_cookie就是它的键值，所以直接打印，出cookie_secret了

![image-20210818160914715](20210818160915.png)

python算一下：

    import hashlib
    cookie_secret = '29c393d2-96d2-4885-961d-422b8d299efd'
    md5 = hashlib.md5()
    md5.update('/fllllllllllllag'.encode())
    result = cookie_secret + md5.hexdigest()
    md5 = hashlib.md5()
    md5.update(result.encode())
    result = md5.hexdigest()
    print(result)

![image-20210818163618341](20210818163620.png)

## [HCTF 2018]admin

> 考点：
> 
> Unicode编码欺骗
> 
> [作者的wp]([[HCTF] admin出题人求挨打 - ckj123](https://www.ckj123.com/?p=147))
> 
> nodeprep.prepare()函数漏洞

打开题目，源码提示you are not admin，推测要以admin用户登录

![](20210820173753.png)

先随便注册个用户登录，在修改密码的源码处找到github地址，有框架源码

![image-20210820174214852](20210820174409.png)

呜呜

代码审计，注册，登录，修改密码的时候都调用了strlower()方法，而这个方法是自己实现的：

![image-20210820174331084](20210820174353.png)

该方法是通过调用nodeprep.prepare方法实现的，这个方法有unicode编码漏洞，即ᴬ经过该函数会变成A。

注意，这是strlower函数的几次调用：

注册：

![image-20210820180313365](20210820180315.png)

登录：

![image-20210820181602485](20210820181604.png)

修改密码：

![image-20210820181639002](20210820181640.png)

因此以ᴬdmin用户注册，注册后数据库内为Admin

然后登录的时候由于是先执行了这个函数再比对，因此以ᴬdmin用户登录

实际上登录为Admin用户：

![image-20210820174925541](20210820174933.png)

修改密码，修改后，用admin登录，密码即为修改的密码：

![image-20210820182148528](20210820182149.png)

## [BJDCTF2020]Easy MD5

> 考点：常见md5绕过

首先打开环境是一个输入框：

![image-20210903160542851](20210903160545.png)

抓包发现有Hint：

![image-20210903160610907](20210903160617.png)

注意到里面md5函数有参数true，查阅是十六位md5的意思

这里看了其他师傅的wp发现：

> mysql会将十六位hex转化为字符串。因此可以考虑构造出一个万能密码

这里密码是：ffifdyop：

经过十六位md5再转字符串后，是形如`'or'6]!r,b`的形式，而以数字开头的字符串在mysql里面会被当成整型数，因此布尔值无论如何都是true。

然后第二关是简单md5绕过：

![image-20210903161009254](20210903161011.png)

可以数组绕过也可以0e绕过，直接数组绕过：

`?a[]=1&b[]=2`

第三关：

![image-20210903161101423](20210903161102.png)

数组直接绕：

`param1[]=1&param2[]=2`

## [ZJCTF 2019]NiZhuanSiWei

> 考点：php伪协议，反序列化
> 
> php://filter/read=convert.base64-encode/resource= 可以以base64读取
> 
> data://text/plain;base64,base64字符串 
> 
> 我对两个伪协议的理解：data伪协议会先把这段协议处理的东西处理了，再交给php
> 
> 而上面的php伪协议是先交给php处理了，再用伪协议处理。

打开环境

![image-20210903194919768](20210903194922.png)

首先要读取一个文件名为变量$text的文件，然后判断是否等于这个字符串

使用data伪协议：

`?text=data://text/plain,welcome to the zjctf`

再看嵌套的if，可以看到这里的file是不能包含flag的。看else语句，有提示include一个useless.php

这里直接Include会被php解析，使用php伪协议转base64：

`file=php://filter/read=convert.base64-encode/resource=useless.php`

![image-20210903201058441](20210903201059.png)

读代码

![image-20210903201125154](20210903201126.png)

读到源码之后直接include一下useless.php。看上面的useless.php源码，里面是有tostring方法的。

因此只需要把password正常反序列化，然后输出即可：

    ?text=data://plain/text,welcome to the zjctf&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}

![image-20210903211524750](20210903211525.png)

## [极客大挑战 2019]HardSQL

> 考点：报错注入
> 
> 空格过滤

这里略微写下，就不直接复现了

注意几个点：

1.在mysql里面过滤了空格可以用括号代替，比如`select(schema_name)from(information_schema.schemata)`

2.根据上面的可以用报错注入，`updatexml(1,语句,1)`

3.left可以看前面，当然right()就可以看后面，我这里用的是reverse()

    ?username=1&password=2'or(updatexml(1,(concat('~',reverse((select(group_concat(concat(password,'-',id)))from(H4rDsq1))),'~')),1))%23

## [网鼎杯 2020 青龙组]AreUSerialz

> 考点：php反序列化
> 
> php弱类型比较

阅读源码

    <?php

    include("flag.php");

    highlight_file(__FILE__);

    class FileHandler {

        protected $op;
        protected $filename;
        protected $content;

        function __construct() {
            $op = "1";
            $filename = "/tmp/tmpfile";
            $content = "Hello World!";
            $this->process();
        }

        public function process() {
            if($this->op == "1") {
                $this->write();
            } else if($this->op == "2") {
                $res = $this->read();
                $this->output($res);
            } else {
                $this->output("Bad Hacker!");
            }
        }

        private function write() {
            if(isset($this->filename) && isset($this->content)) {
                if(strlen((string)$this->content) > 100) {
                    $this->output("Too long!");
                    die();
                }
                $res = file_put_contents($this->filename, $this->content);
                if($res) $this->output("Successful!");
                else $this->output("Failed!");
            } else {
                $this->output("Failed!");
            }
        }

        private function read() {
            $res = "";
            if(isset($this->filename)) {
                $res = file_get_contents($this->filename);
            }
            return $res;
        }

        private function output($s) {
            echo "[Result]: <br>";
            echo $s;
        }

        function __destruct() {
            if($this->op === "2")
                $this->op = "1";
            $this->content = "";
            $this->process();
        }

    }

    function is_valid($s) {
        for($i = 0; $i < strlen($s); $i++)
            if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
                return false;
        return true;
    }

    if(isset($_GET{'str'})) {

        $str = (string)$_GET['str'];
        if(is_valid($str)) {
            $obj = unserialize($str);
        }

    }

在php里面，几个魔术方法：

> __wake()：只有反序列化的时候调用
> 
> __sleep()：只有序列化的时候调用
> 
> __construct()：只有创建对象的时候调用
> 
> __destruct()：只有销毁对象的时候调用

代码里的类只有__construct和\__destruct两个方法，那么唯一可能被这段代码调用的就只有destruct方法

代码审计，逻辑是假如op的值为1，那么执行write；op的值为2，那么执行read，且若op的值为2，那么修改为1。

先简单尝试用file_put_contents写文件，发现全都access denied。

这个时候发现：

![image-20210905171635271](20210905171636.png)

![image-20210905171653505](20210905171654.png)

这里可能存在弱类型漏洞，fuzz一下：

![image-20210905171735901](20210905171736.png)

![image-20210905171805617](20210905171807.png)

发现.可以绕过。

然后直接反序列化，读取filename为flag.php的就可了：

`?str=O:11:"FileHandler":3:{s:2:"op";s:2:"2.";s:8:"filename";s:8:"flag.php";s:7:"content";s:5:"test2";}`

![image-20210905171907690](20210905171908.png)

## [GXYCTF2019]BabySQli

> 考点：猜测比较语句
> 
> 联合查询的时候会临时在数据库中创建一条查询的信息

打开环境，简单查询一下：

![image-20210908155733335](20210908155734.png)

提示错误密码，替换掉admin，发现提示wrong user，因此猜测应该是先判断的user，再判断的password。

查看源码，里面有提示语句：

![image-20210908155945659](20210908155948.png)

咋说呢，这个属实不知道，查了下是base32编码。

解码后明显是base64，再解码，得出一个查询语句：

![image-20210908160117252](20210908160118.png)

可以看到查询语句的源码，直接开始注

![image-20210908160200057](20210908160201.png)

有过滤，随便测试了一下发现=以及括号这些都被过滤了

使用union select：

![image-20210908160629708](20210908160631.png)

可以看到有三列，猜测即是id,username,password

我们可以先把username是哪一列猜出来，先试第一个：

![image-20210908160750926](20210908160751.png)

不对，试第二个，对了：

![image-20210908160819224](20210908160820.png)

猜测第三列就是密码。

回想一下，是先比较用户名，再比对密码，因此猜想密码大概率是md5这种来比较的，属于是大开脑洞了

**然后此处有一个联合查询的知识点：在union select联合查询的时候，会在数据库中临时生成一个数据：**

如图：

![image-20210908162141116](20210908162142.png)

然后使用union select联合查询：

![image-20210908162220293](20210908162221.png)

这样就为我们上面的提供了思路，我们假如在数据库union select一个admin，然后自己构造一个密码，就可以绕过了。

猜想密码比对是md5，因此可以直接构造payload了。

首先得到md5码：

![image-20210908162630554](20210908162631.png)

直接注入：

![image-20210908162603333](20210908162605.png)

    name=1'union select 1,'admin','5d41402abc4b2a76b9719d911017c592'%23&pw=hello

## [GYCTF2020]Blacklist

> 考点：Handler的使用

开环境，发现这道题和前面强网杯的随便注有点像。

发现可以堆叠注入：

![image-20211027142431870](20211027142445.png)

看一下黑名单：

![image-20211027142614196](20211027142615.png)

发现强网杯可以用的sql语句预编译以及更改数据库表名都没有办法使用了。

因此想起mysql的黑科技：handler的使用。

这里使用handler读表：

    ?inject=1';HANDLER FlagHere OPEN;HANDLER FlagHere READ FIRST;HANDLER FlagHere CLOSE#

即可得到flag。

![image-20211027142837411](20211027142839.png)

## [网鼎杯 2018]Fakebook

> 考点：源码泄露+sql注入+ssrf+反序列化
> 
> ssrf: 可以使得我们可以直接访问内网中本来无法访问的内容

开环境探索下

注册一个用户，点进去看看，发现可能有sql注入：

![image-20211122225309328](20211122225310.png)

开注，发现过滤了union select

使用union/****/select可以绕过。

爆出字段：

![image-20211122230102859](20211122230104.png)

上面看到一个反序列化，嗯？

到这里思路暂时就断了。

冷静下来，发现两种思路可以继续：

查看源代码，发现这里有一个data流，打开发现是我们填写的博客的网站：

![image-20211122230302994](20211122230303.png)

说明我们可能可以根据这里来直接读取网站上的文件;

第二种就是师傅们简单粗暴的看robots.txt,发现直接有网站备份：

![image-20211122230614702](20211122230615.png)

嗯，看红框里面curl，可能有ssrf

然后联系到上面是对我们union select里面其中一个参数进行了反序列化，猜测是curl读取了一个反序列化之后的网站。

所以我们反序列化如下：（curl可以读取文件流file:///)

![image-20211122231227583](20211122231229.png)

把这个带到union select里面几个参数去试，发现是第四个，如图：（unserialize的warning消失了）

![image-20211122231303258](20211122231304.png)

查看源代码：

![image-20211122231326550](20211122231327.png)

点进去查看源代码即可得到flag：

![image-20211122231347750](20211122231348.png)