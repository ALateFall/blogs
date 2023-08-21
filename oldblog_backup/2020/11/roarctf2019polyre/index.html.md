---
layout: post
title: [RoarCTF2019]polyre
date: 2020-11-29
tags: ["逆向"]
---

[toc]
好烦啊这道题呜呜呜

# 前置知识

## Ollvm反混淆

可以看[这里](https://www.freebuf.com/articles/terminal/130142.html)
使用[deflat.py](https://github.com/cq674350529/deflat)反混淆，使用方法：
`python deflat.py -f path/to/binary --addr hexaddress`
path/to/binary填文件，hexaddress填函数入口地址。

# 解题思路

开题，不太对劲：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_e2ef8689a554e7c39a7fc9aa3e0b1c48.jpg)](wp_editor_md_e2ef8689a554e7c39a7fc9aa3e0b1c48.jpg)
查了一下发现是ollvm平坦化了，使用python下的deflat.py脚本去平坦化。
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_163e8d0ee47edcac355db0c5235a0d00.jpg)](wp_editor_md_163e8d0ee47edcac355db0c5235a0d00.jpg)
这个是函数入口地址，反混淆如下：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_4ffd3ef61add28c2ad6521ea7cc154b8.jpg)](wp_editor_md_4ffd3ef61add28c2ad6521ea7cc154b8.jpg)
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_77779da092dbcba3e1f5e7950eb57114.jpg)](wp_editor_md_77779da092dbcba3e1f5e7950eb57114.jpg)
等待脚本运行，完了之后就可以丢到ida了。
后面的就不上截图了，分析之后发现是把六个八字节的数用来加密，加密方式是64次判断是否大于0，假如大于0就乘以2，小于零就乘2再异或。此处看了别人的wp，判断方式很巧妙，因为偶数异或那个key值肯定是奇数，就可以判断是否被异或了。

# 解题过程

贴脚本：

    import libnum
    lt = [0x96, 0x62, 0x53, 0x43, 0x6D, 0xF2, 0x8F, 0xBC, 0x16, 0xEE,
          0x30, 0x05, 0x78, 0x00, 0x01, 0x52, 0xEC, 0x08, 0x5F, 0x93,
          0xEA, 0xB5, 0xC0, 0x4D, 0x50, 0xF4, 0x53, 0xD8, 0xAF, 0x90,
          0x2B, 0x34, 0x81, 0x36, 0x2C, 0xAA, 0xBC, 0x0E, 0x25, 0x8B,
          0xE4, 0x8A, 0xC6, 0xA2, 0x81, 0x9F, 0x75, 0x55, ]
    nums = []
    for i in range(6):
        num = 0
        for j in range(8):
            num = 256 * num + lt[8 * (i + 1) - j - 1]
        nums.append(num)
    result = 0
    for i in nums:
        print('0x%x '%i,end="")
    # 醒来时惊恐的心悬停腹中寻氧
    print("")
    for i in nums:
        for j in range(64):
            if i & 1==1:
                i = i ^ 0xB0004B7679FA26B3
                i //= 2
                i '= 0x8000000000000000
            else:
                i //= 2
        print(libnum.n2s(i)[::-1].decode('utf-8'),end="")

flag{6ff29390-6c20-4c56-ba70-a95758e3d1f8}