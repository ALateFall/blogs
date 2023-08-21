---
layout: post
title: [BJDCTF2020]easy
date: 2020-10-26
tags: ["逆向"]
---

[toc]

## 解题流程

### 分析程序结构

这是主函数：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_ccd9072e6b870b005ccc8f0156b29f7f.jpg)](wp_editor_md_ccd9072e6b870b005ccc8f0156b29f7f.jpg)
&#42;都没有，我佛了
再看看字符串：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_f1a4618d2fdd64158f3dcbdff01d98a7.jpg)](wp_editor_md_f1a4618d2fdd64158f3dcbdff01d98a7.jpg)
还是&#42;都没有...
然后这个时候看函数，发现也不是太多，这里查了一下，有两种说法，一种是肉眼观察发现函数名叫que的：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_c53786bc8fe31dea56ae49c2125c7f38.jpg)](wp_editor_md_c53786bc8fe31dea56ae49c2125c7f38.jpg)
网上说就是question...?
好吧，或者也可以一个一个函数点开看，因为除了这些内置函数，只有几个，而且这一个函数是有putchar()的，难免产生怀疑：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_5773f80e8d92705b2409c6b2aa0d6fe4.jpg)](wp_editor_md_5773f80e8d92705b2409c6b2aa0d6fe4.jpg)
然后就用od在这里打断点看看：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_733b23485d3b952ab3089af197a858b8.jpg)](wp_editor_md_733b23485d3b952ab3089af197a858b8.jpg)
地址是401520，OD打断点：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_8246bd44404ace9b0d4cfb9adb7ec99e.jpg)](wp_editor_md_8246bd44404ace9b0d4cfb9adb7ec99e.jpg)
结果发现根本运行不到这个函数，程序就会结束。
那么就只能...强行跳转到这里来了。

### 更改跳转指令

根据ida里面的汇编地址，定位到Od的main函数的汇编地址：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_bd4363eeea8fbc4aaca7b7704091a89b.jpg)](wp_editor_md_bd4363eeea8fbc4aaca7b7704091a89b.jpg)
可以看到下面它有跳转函数，直接让他跳转到刚刚定位的函数过去看看情况：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_bae1f99b4af15e88b308eb50dbf3ad69.jpg)](wp_editor_md_bae1f99b4af15e88b308eb50dbf3ad69.jpg)
这样一来它肯定会跳转过去了。运行程序：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_9f7864ee7959feba2e25473118074e01.jpg)](wp_editor_md_9f7864ee7959feba2e25473118074e01.jpg)
可以看到已经停在这里了。
在ida里面定位到当前函数结束的地址，下断点，查看函数运行完毕之后的状态：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_04a71e00ad52fbea938b01106f27b7a6.jpg)](wp_editor_md_04a71e00ad52fbea938b01106f27b7a6.jpg)
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_3e0d801a526b2cc02a2132bfbc1b6869.jpg)](wp_editor_md_3e0d801a526b2cc02a2132bfbc1b6869.jpg)
运行程序：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_f86e40dca2e3b39c39944e5e11231293.jpg)](wp_editor_md_f86e40dca2e3b39c39944e5e11231293.jpg)
打印出的结果即为flag:
flag{HACKIT4FUN}