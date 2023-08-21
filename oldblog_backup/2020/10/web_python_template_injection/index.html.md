---
layout: post
title: Web_python_template_injection
date: 2020-10-07
tags: ["web"]
---

[toc]

## 前置知识

*   在有的python的web项目中，项目的某些页面存在url的回显。
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_054b53980b9ed9bd106ef06a8092d29a.jpg)](wp_editor_md_054b53980b9ed9bd106ef06a8092d29a.jpg)
猜测可能存在xss或者模板注入，例：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_c84f95faa910bb3f7b5bf0eff6fe33b9.jpg)](wp_editor_md_c84f95faa910bb3f7b5bf0eff6fe33b9.jpg)
*   python的内置函数知识（此处是python2）
可以查看[此篇文章](https://xuanxuanblingbling.github.io/ctf/web/2019/01/02/python/ "此篇文章")
即了解&#95;&#95;class__,&#95;&#95;mro__,&#95;&#95;subclasses__,&#95;&#95;init__,&#95;&#95;globals__等几个函数的用法
**实测python3和python2的这几个函数用起来还是有差别的，比如`"".\_\_class__.\_\_mro__[-1].\_\_subclasses__()[0].\_\_init__`是没有&#95;&#95;globals__这个属性的。**
至于python3怎么办，俺也不知道（呜呜

## 解题

上面我们知道了存在模板注入，下一步就是找出flag。
猜测flag大概是在服务器上的一个文件，那怎么读取服务器上的文件呢？想到python内置的函数有os.popen(),file.read()等。此处演示用系统命令即os.poepn()函数。

### 写脚本

因为要构造出一个os.popen()方法出来，所以就可以用python的内置函数。
（参考了wp）

    cnt = 0
    for item in ''.__class__.__mro__[-1].__subclasses__():
        try:
            if 'os' in item.__init__.__globals__:
                print cnt, item
            cnt += 1
        except:
            cnt += 1
            continue

可以得到结果：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_9de3183f116b88a2829a3ca7588f6f16.jpg)](wp_editor_md_9de3183f116b88a2829a3ca7588f6f16.jpg)

### 执行命令

构造出os模块之后就可以执行命令了，如图：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_0520fb95b52b46ff0e2f272a226de244.jpg)](wp_editor_md_0520fb95b52b46ff0e2f272a226de244.jpg)
查看fl4g:
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_76c2b10a6ec921aafbc57ab5128a65d0.jpg)](wp_editor_md_76c2b10a6ec921aafbc57ab5128a65d0.jpg)