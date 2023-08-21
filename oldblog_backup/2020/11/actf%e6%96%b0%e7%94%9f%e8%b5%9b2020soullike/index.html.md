---
layout: post
title: [ACTF新生赛2020]SoulLike
date: 2020-11-29
tags: ["逆向"]
---

[toc]

# 前置知识

*   subprocess库
可以看[这里](http://ltfa1l.top/%e5%90%84%e7%a7%8d%e5%ba%93%e7%9a%84%e4%bd%bf%e7%94%a8/)，也可以用其他有相似功能的库替代。

# 解题思路

丢到ida，题目流程很简单：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_50a359b39afb287ce04cdabb4fb786cd.jpg)](wp_editor_md_50a359b39afb287ce04cdabb4fb786cd.jpg)
除了箭头指的那个地方的加密。大概就是判断前几位是不是actf{，然后把后半部分拿去加密。
跟进这个函数，发现太大了无法反编译：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_2c2c8fb1b6a9744ca16920e93e8d2e96.jpg)](wp_editor_md_2c2c8fb1b6a9744ca16920e93e8d2e96.jpg)
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_98c4243cb33579704cbe957c8f7f6c73.jpg)](wp_editor_md_98c4243cb33579704cbe957c8f7f6c73.jpg)
都是上图所示的内容。
运行文件，发现：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_9d696782d49e2c5c924e571cf7c43597.jpg)](wp_editor_md_9d696782d49e2c5c924e571cf7c43597.jpg)
提示了第几位错误。。。
爆破两个字差不多已经写出来了。
用程序输入输出流开始爆破就完事。

# 解题过程

上脚本：

    import subprocess
    flag = 'actf{'
    for i in range(12):
        for j in range(32,128):
            p = subprocess.Popen(['./re'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            temp = flag+chr(j)+'}'
            p.stdin.write(temp.encode('utf-8'))
            p.stdin.close()
            out = p.stdout.read()
            if str(i) in out:
                pass
            else:
                flag += chr(j)
                print(flag+'}')
                break
    print(flag+'}')

actf{b0Nf'Re_LiT!}