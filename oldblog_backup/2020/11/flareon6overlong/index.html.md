---
layout: post
title: [FlareOn6]Overlong
date: 2020-11-15
tags: ["逆向"]
---

[toc]

## 解题思路

查壳没壳，32位。
用ida打开，发现程序逻辑比较简单：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_b312da075af664b33a56fd74fcaa80db.jpg)](wp_editor_md_b312da075af664b33a56fd74fcaa80db.jpg)
只有几个函数，而且功能也比较明显
进入sub_401160康康：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_edff91955a4a65efc6ed45a52af00815.jpg)](wp_editor_md_edff91955a4a65efc6ed45a52af00815.jpg)
箭头指的地方就是唯一一个加密函数。
打开这个程序康康：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_20df93a984479a1889c48428c13dc7c5.jpg)](wp_editor_md_20df93a984479a1889c48428c13dc7c5.jpg)
细心的大家可能已经发现了这句话的后面有一个冒号，所以可能猜测本来后面就会输出flag的。
不过我是没有发现的。
然后看循环体，发现只循环了28次，但是用于加密的字符远远不止28.
联想上面的冒号，所以可能是后面就会输出一些我们想看到的东西。

## 解题

我们打开ollydbg修改for循环里面的那个循环次数。
先定位到这个地方：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_c0d66e7154bf32e70a0d2c4d338083d0.jpg)](wp_editor_md_c0d66e7154bf32e70a0d2c4d338083d0.jpg)
此处要注意，假如我们直接修改这个值，会造成偏移错位（因为其他的代码可能会用到偏移）
此处错误示范：直接修改这个值
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_93918eb9d98661408cf133efda9c3ced.jpg)](wp_editor_md_93918eb9d98661408cf133efda9c3ced.jpg)
可以看到都自动添加了两个nop。运行程序：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_7f6c73c413a858211eb20fbdbf74f66e.jpg)](wp_editor_md_7f6c73c413a858211eb20fbdbf74f66e.jpg)
发现确实什么也没了。
那我们就需要想一种只改变这个循环的值，而不会改变其他地方的代码的方法。
看到程序这个地方是push到栈里面去的，那我们等他压到栈里面去不就好了。
正确示范：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_239e46d89b78ae7d52cbc32a82b3c15f.jpg)](wp_editor_md_239e46d89b78ae7d52cbc32a82b3c15f.jpg)
运行代码：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_73a53cc5a9ad8b9ef7cd7f44ce3a86b0.jpg)](wp_editor_md_73a53cc5a9ad8b9ef7cd7f44ce3a86b0.jpg)
得到flag。