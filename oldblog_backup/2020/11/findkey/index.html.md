---
layout: post
title: findKey
date: 2020-11-27
tags: ["逆向"]
---

[toc]
这道题其实不难，主要记录一下

# 前置知识

## 花指令

不过这道题只涉及一点点花花

## 函数调用

看汇编找不到函数从哪里开始怎么办？

# 解题思路

定位到关键位置：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_c29b9b337e83760fa1f3df3e5e776239.jpg)](wp_editor_md_c29b9b337e83760fa1f3df3e5e776239.jpg)
反汇编，提示要在函数内部进行反汇编，就要想一下怎么声明为函数。
往上一直翻，找函数入口。
翻了很久，看起来这里有点像：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_47d08efe1e673c5dcd20dfd37426bc7d.jpg)](wp_editor_md_47d08efe1e673c5dcd20dfd37426bc7d.jpg)
因为上面不仅是另一个函数的结尾，而且这里有push ebp，然后把esp移到了ebp，看起来就像是在调用函数。
按p声明为函数试试：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_6f0402ac1de5f3689869a1e25804b79f.jpg)](wp_editor_md_6f0402ac1de5f3689869a1e25804b79f.jpg)
提示目标位置分析不了，那就过去康康。
就是这里了：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_1fbcdf85b4b45b8da30ea6b0181171de.jpg)](wp_editor_md_1fbcdf85b4b45b8da30ea6b0181171de.jpg)
发现连续push了同一段字符串两次，那就nop掉一个：
都试了一下，发现nop掉第二个的时候，在刚刚的函数开头按p，就可以声明为函数了。
反编译如图：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_782daa86d59c60bd6c9a6c7f6ca4157e.jpg)](wp_editor_md_782daa86d59c60bd6c9a6c7f6ca4157e.jpg)
后面的都是常规内容了，此处就不写详细解法了，就写下怎么看出来md5加密的。
中间有对pbData进行加密：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_10193c2f65c069b6b54fa356feb4ead2.jpg)](wp_editor_md_10193c2f65c069b6b54fa356feb4ead2.jpg)
跟进，发现是一种hash算法。
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_85fd161c61c44ffd33dd4aabe05acc6a.jpg)](wp_editor_md_85fd161c61c44ffd33dd4aabe05acc6a.jpg)
故大概是md5.

# 解题过程

上脚本：

    strs = "0kk`d1a`55k222k2a776jbfgd`06cjjb"
    lt = []
    for i in strs:
        lt.append(i)
    key = "SS"
    length = len(strs)
    out = ""
    for i in range(length):
        lt[i] = chr(ord(lt[i]) ^ ord(key[i % 2]))
        out += lt[i]
    md5 = "123321"
    lt2 = [87, 94, 82, 84, 73, 95, 1, 109, 105, 70,
           2, 110, 95, 2, 108, 87, 91, 84, 76]
    flag = ""
    for i in range(len(lt2)):
        flag += chr(lt2[i] ^ ord(md5[i % 6]))
    print(flag)

flag{n0_Zu0_n0_die}