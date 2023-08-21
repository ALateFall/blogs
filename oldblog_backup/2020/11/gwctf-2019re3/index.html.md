---
layout: post
title: [GWCTF 2019]re3
date: 2020-11-24
tags: ["逆向"]
---

[toc]

# 前置知识

## AES加密

可以看[这个](https://www.cxyxiaowu.com/3239.html)

## AES加密的逆向特征

可以看[这个](https://blog.csdn.net/zhangmiaoping23/article/details/8949290 "这个")

# 解题

## 解题思路

首先开题，发现是这样子的：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_a4e85233ddb607b526cdcc6c343b2c29.jpg)](wp_editor_md_a4e85233ddb607b526cdcc6c343b2c29.jpg)
注意到输入的是长度为32位的字符串。
查看sub_402219这个函数，ida提示是不可以看的，用汇编模式看发现是有很多数据还没有被处理。
第一时间想到的是可能有花指令，但是不是，看图中的这一个部分：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_9d279a4fe59e44857a72a19f491c3026.jpg)](wp_editor_md_9d279a4fe59e44857a72a19f491c3026.jpg)
在for循环里面对这个函数的数据进行了异或操作，所以猜想可能是异或完之后的函数就可以正常查看了。
所以直接上手调试，断点打到上图中那个地方，此时就已经完成了异或操作。
此时点击sub_402219函数，提示还是不能进入，用汇编模式进入：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_30912b0c52df1f625d714ee9373323f4.jpg)](wp_editor_md_30912b0c52df1f625d714ee9373323f4.jpg)
这个时候其实异或操作已经完了，但是没有转化为正确的函数，需要我们手动操作。
（年轻人不讲武德，来逆 向，来改 代 码）
首先把选中部分按D转化为数据：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_48a87adb48dcdbc13c2787617d38427f.jpg)](wp_editor_md_48a87adb48dcdbc13c2787617d38427f.jpg)
就转化成了下图，选中所有数据：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_9c066171132c9aa42fcc923f4bf1d363.jpg)](wp_editor_md_9c066171132c9aa42fcc923f4bf1d363.jpg)
先全部转化为代码，按C转化为代码：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_7c2ccc3f1b403ac068eadcf712679c7d.jpg)](wp_editor_md_7c2ccc3f1b403ac068eadcf712679c7d.jpg)
此时他们还不是函数，在函数开头loc_402219处按p，就可以转化为函数，反编译：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_622319957478374280fbf051d057d712.jpg)](wp_editor_md_622319957478374280fbf051d057d712.jpg)
这个函数是处理输入的字符串s的，需要用到字符串unk_603170，返回去看第一张图，函数sub_40207B是专门用来处理这个字符串的，点进去看：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_33c3678f4598fbbf78800da3fd2e1b18.jpg)](wp_editor_md_33c3678f4598fbbf78800da3fd2e1b18.jpg)
有一堆加密，但是不慌，这个和输入没关系，说明经过这个函数应该是个定值。
那么调试直接可以看到这个字符串的值：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_de4a9feac9906e7da6bb526c10dd13bc.jpg)](wp_editor_md_de4a9feac9906e7da6bb526c10dd13bc.jpg)
现在开始具体分析函数sub_402219到底干了什么。
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_0a250cde43c3b1c2ada98d50f0d4ead6.jpg)](wp_editor_md_0a250cde43c3b1c2ada98d50f0d4ead6.jpg)
第三个箭头是用来和字符串比对的，就不说了，那么明显前两个箭头的地方就是加密的。
用插件findcrypt，发现前两个是AES加密。（此处吐槽一下不知道为啥在调试的时候我开findcrypt就会直接卡死要关了调试才能开。）
是AES加密，那么第一个对于字符串常量操作的函数猜测就是生成轮密钥。
后面两个函数是一模一样的，而且输入字符串是32位，分别操作了16位和16位，那么猜测是那啥，是ECB电话本的加密方式的AES。
那么这个AES就是，密钥就是那个unk字符串常量，加密后的就是那个bytes数组。

## 解题过程

脚本如下：

    from Crypto.Cipher import AES
    from Crypto.Util.number import *
    key = long_to_bytes(0xCB8D493521B47A4CC1AE7E62229266CE)
    strs = long_to_bytes(0xBC0AADC0147C5ECCE0B140BC9C51D52B46B2B9434DE5324BAD7FB4B39CDB4B5B)
    aes = AES.new(key,AES.MODE_ECB)
    flag = aes.decrypt(strs)
    print(str(flag))

以前没有用过这个库，怎么用这个库都给我搞成啥b了。
经过一番测试发现是用的bytes类型的参数，所以先之前先把密文和密钥都转化为bytes类型的数据。目前没有找到其他的方式转化，所以代码里面的转化方式比较奇特，是抄的别人的wp嘻嘻。
这个库的使用方式就是这样：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_24f4270562e2473a27ccaadaf2bc0464.jpg)](wp_editor_md_24f4270562e2473a27ccaadaf2bc0464.jpg)
然后就出结果了。
flag{924a9ab2163d390410d0a1f670}