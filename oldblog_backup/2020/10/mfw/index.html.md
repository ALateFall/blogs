---
layout: post
title: mfw
date: 2020-10-08
tags: ["web"]
---

[toc]

## 前置知识

### 源码泄露

常见的有svn泄露、git泄露等等，比如此处的git泄露就是网站目录后面的/.git中泄露了一些数据。

### php命令执行

*   assert()方法，会执行里面的的代码
*   system()函数，里面可以接系统命令执行

## 解题

### 源码泄露找路径

开题，事后发现这个还蛮关键的：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_cd434f660e3ba3813bac4ce90cf765e9.jpg)](wp_editor_md_cd434f660e3ba3813bac4ce90cf765e9.jpg)
用了git->所以猜git泄露？
反正俺没有猜出来，扫一下：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_ef8d3991892dfb0065313c9014ebe270.jpg)](wp_editor_md_ef8d3991892dfb0065313c9014ebe270.jpg)
这里就比较明显了，然后在输出文件中查看目录结构：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_4911f60160ee0bd3b8f989f0fcc47132.jpg)](wp_editor_md_4911f60160ee0bd3b8f989f0fcc47132.jpg)
templates里面是几个文件：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_7ef077032f81efdadb58056610604708.jpg)](wp_editor_md_7ef077032f81efdadb58056610604708.jpg)
发现有flag.php，打开结果发现啥也不是
查看index.php，发现有源码：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_1d0a931fdf0494b70964ce896b8fdebc.jpg)](wp_editor_md_1d0a931fdf0494b70964ce896b8fdebc.jpg)

### 代码审计&&命令执行

查看代码，意思就是把get请求传进来的page作为变量，拼接到file变量里面，再执行下面的几个assert()方法，这里也是涨知识了，assert()方法里面的代码也是可以拼接的······
然后就是构造page变量：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_7e8b63b469a13c60f32c635d4e9f2bf6.jpg)](wp_editor_md_7e8b63b469a13c60f32c635d4e9f2bf6.jpg)
完成之后发现执行命令成功：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_f9d8422988d1c0c9076306770f32b858.jpg)](wp_editor_md_f9d8422988d1c0c9076306770f32b858.jpg)
查看flag:
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_937c1c34134203ca72c0645fdf5ec610.jpg)](wp_editor_md_937c1c34134203ca72c0645fdf5ec610.jpg)
得到结果：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_5a4f4d46814303bf7894158850cf23d8.jpg)](wp_editor_md_5a4f4d46814303bf7894158850cf23d8.jpg)