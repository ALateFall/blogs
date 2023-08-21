---
layout: post
title: [Zer0pts2020]easy strcmp
date: 2020-11-25
tags: ["逆向"]
---

[toc]

# 前置知识

## hook

用菜鸡的话讲就是出题人不讲武德，把原本的库函数给你改到其他函数上面去，来骗。

## binascii库

烦死了这个，可以看[这里](http://ltfa1l.top/%e5%90%84%e7%a7%8d%e5%ba%93%e7%9a%84%e4%bd%bf%e7%94%a8/)

# 解题思路

## 流程分析

先看main函数，比较输入的是不是后面那个，看起来真简单，嘻嘻。
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_fdb2586d669e8b61b5e75d77911ccfa3.jpg)](wp_editor_md_fdb2586d669e8b61b5e75d77911ccfa3.jpg)
直接上调试，需要注意的是这种带参数的调试要在ida的debugger里面添加parameters，如图：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_8c6a625ee292d667c32c29c71396723d.jpg)](wp_editor_md_8c6a625ee292d667c32c29c71396723d.jpg)
经过调试，发现这个strcmp函数并没有执行，而是转而执行了其他函数。
跟进main函数的strcmp，发现并没有别的调用；
转而想想，既然strcmp被更改了，那肯定是在main函数之前就被更改了，跟进start函数：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_84b4e2f027655f57514c1c9b3c842a94.jpg)](wp_editor_md_84b4e2f027655f57514c1c9b3c842a94.jpg)
如上图所示，发现虽然start里面没有，但是start在执行main函数之前还执行了init函数。继续跟进：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_8b2699fcfbb9c109ef5ddfb5f998a3ec.jpg)](wp_editor_md_8b2699fcfbb9c109ef5ddfb5f998a3ec.jpg)
这里就可以看到，init函数执行了两个偏移之间的每个函数。跟进查看：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_ecf489bc4e6024938001de59d8afacb9.jpg)](wp_editor_md_ecf489bc4e6024938001de59d8afacb9.jpg)
一共执行了三个函数，其他两个没啥用，重点看sub_795():
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_76b63585c8a37765c00822e862d75764.jpg)](wp_editor_md_76b63585c8a37765c00822e862d75764.jpg)
发现strcmp和sub_6EA()都被更换到了新的偏移。
查看main函数里面的strcmp，查看调用情况：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_0e50b6222c3c34c2b57dab5b923c915d.jpg)](wp_editor_md_0e50b6222c3c34c2b57dab5b923c915d.jpg)
这下就明白了，它执行的这个偏移被更改为sub_6EA()了。
查看这个函数：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_e577bd1cc915e62de64dc52936f6d7b2.jpg)](wp_editor_md_e577bd1cc915e62de64dc52936f6d7b2.jpg)
最下面的qword实际上是真正的strcmp，因此整个程序实际上是在进行strcmp之前还进行了一些运算，整个过程就分析完毕了。

## 算法分析

算法很简单，就是把输入的字符串减去那个qword常量，逆向过来就是加上就行。
注意大小端即可。

# 解题过程

贴脚本：

    import binascii

    qword = [0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B]
    _result = "********CENSORED********"
    flag = b''
    for i in range(3):
        a = _result[i * 8:i * 8 + 8]
        a = binascii.b2a_hex(a.encode('utf-8')[::-1])
        flag += binascii.a2b_hex(hex(int(a, 16) + qword[i])[2:])[::-1]
    print(flag.decode('utf-8'))

注意hex()的结果是字符串。
这个我真打算自己写的，但是这个字节流是真得把我搞成啥b了，就一步一步对照网上的wp改自己的脚本，结果后面直接改得差不多了...只能说大佬带带呜呜呜
flag:zer0pts{l3ts_m4k3_4_DETOUR_t0d4y}