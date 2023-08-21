---
layout: post
title: [ACTF新生赛2020]Oruga
date: 2020-11-17
tags: ["逆向"]
---

[toc]

## 解题思路

每次遇到迷宫问题好像都对怎么分析上下左右不是很懂...希望通过这道题来略微学一下。

### 函数分析

首先不卖关子了，main函数里面就是确定flag的前几个字母的，关键函数是这个：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_075a24731e33e34119d2f26673582db4.jpg)](wp_editor_md_075a24731e33e34119d2f26673582db4.jpg)
红框里面就是上下左右对应的字符，不过还没有确定具体代表哪个方向。
这个嵌套if其实就是读到W，v4就是-16，读到E，v4就是1这样子，开始有点没读懂。
然后看下面确定移动的部分：
首先看这个byte数组，发现有256个字符。假如我们知道它是迷宫，那明显是16x16了。
下面是关键的一段while：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_d873dd7bbe9e6517ded62923cd93df06.jpg)](wp_editor_md_d873dd7bbe9e6517ded62923cd93df06.jpg)
可以看到，这个while循环里面一直在进行v2+=v4，那说明只能走到一个byte数组不是0的地方才会停下来，分析一下byte数组之后发现是遇到障碍物就会停下来。那不是走到障碍物上面去了吗？看第一张图的while循环里面，发现有v2-=v4，意思就是退一步，走到路上面来。

### 那么如何确定上下左右？

这是一个256大小的数组，然后v4=1的时候，判断的是!(v4&0xF)，因为碰到障碍物停止这次移动，那么这个直接return0的应该就是碰到边界退出失败了。然后!(v4&0xF),明显v4的2进制的后四位必须应该为0，那不就是迷宫的最左边一行嘛。那应该就是向左。
v4%16 要= 15,就是迷宫的最右边一行，那就是向右。
v4-240<=15,那就是迷宫的最后一行，那就是向下。
v2+15<=30,那就是迷宫的第一行，那就是向上。
至此上下左右就分析完了。

## 解题过程

输出迷宫：

    #include "base64.h"
    #include <algorithm>
    #include <cstdlib>
    #include <cstring>
    #include <iostream>
    #include <string>
    #include <vector>

    using namespace std;

    int main()
    {
        int maze[] = {0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x23, 0x23, 0x23, 0x23, 0x00, 0x00, 0x00, 0x23,
                      0x23, 0x00, 0x00, 0x00, 0x4F, 0x4F, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x4F, 0x4F, 0x00, 0x50, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x4C, 0x00, 0x4F, 0x4F, 0x00, 0x4F, 0x4F, 0x00, 0x50,
                      0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x4F,
                      0x4F, 0x00, 0x4F, 0x4F, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x4C, 0x4C, 0x00, 0x4F, 0x4F, 0x00, 0x00, 0x00,
                      0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x4F, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00,
                      0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x4D, 0x4D, 0x4D, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x4D, 0x4D,
                      0x00, 0x00, 0x00, 0x00, 0x45, 0x45, 0x00, 0x00, 0x00, 0x30,
                      0x00, 0x4D, 0x00, 0x4D, 0x00, 0x4D, 0x00, 0x00, 0x00, 0x00,
                      0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x45, 0x54, 0x54,
                      0x54, 0x49, 0x00, 0x4D, 0x00, 0x4D, 0x00, 0x4D, 0x00, 0x00,
                      0x00, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x49, 0x00, 0x4D,
                      0x00, 0x4D, 0x00, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00,
                      0x00, 0x54, 0x00, 0x49, 0x00, 0x4D, 0x00, 0x4D, 0x00, 0x4D,
                      0x21, 0x00, 0x00, 0x00, 0x45, 0x45};
        int length = sizeof(maze) / sizeof(maze[0]);
        for (int i = 0; i < length; i++)
        {
            if(!i){
                printf("B");
            }
            if (maze[i] == 0)
            {
                printf(".");
            }
            else if(maze[i]==0x21){
                printf("E");
            }
            else
            {
                printf("0");
            }
            if ((i + 1) % 16 == 0)
            {
                printf("\n");
            }
        }
        return 0;
    }

输出迷宫：
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_044650dcd4e90c7a697bcc7c7f3fbadb.jpg)](wp_editor_md_044650dcd4e90c7a697bcc7c7f3fbadb.jpg)
走迷宫如下：（真的难走）
[![](http://ltfa1l.top/wp-content/uploads/2020/11/wp_editor_md_a7d85ed0b4bd790afd684a6555241b69.jpg)](wp_editor_md_a7d85ed0b4bd790afd684a6555241b69.jpg)
结合上面分析的：
上W
下M
左J
右E
flag{MEWEMEWJMEWJM}