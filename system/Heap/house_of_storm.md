---
layout: post
title: house of storm：unsortedbin和largebin attack组合技
category: system/Heap
date: 2023-1-23 21:04:32

---

Heap基础知识
<!-- more -->

[toc]

# house of storm

## 总结

你可以做到：

- 任意地址的`chunk`分配

你需要完成：

- 控制一个`unsortedbin`和`largebin`中的`chunk`，且`unsortedbin`中的要比`largebin`中的大

具体操作：

- 假设要分配到`fake chunk`
- 写`unsortedbin`的`chunk`的`bk`为`fake chunk`的地址
- 写`largebin`中的`chunk`的`bk`为`fake chunk + 0x18 - 0x10`
- 写`largebin`中的`chunk`的`bk_nextsize`为`fake chunk + 0x3 - 0x20`
- 申请一个大小为`0x50`的`chunk`

## 原理

一句话描述一下这个漏洞：通过`largebin attack`在`fake chunk`的`header`上错位写下一个`0x55`或`0x56`的`size`，并在`fake chunk`的`bk`处写一个堆地址。控制`unsortedbin`的`chunk`的`bk`指向要申请的`fake chunk`。申请一个大小为`0x50`的`chunk`，先触发`largebin attack`，从而根据`unsortedbin`的`bk`申请到`fake chunk`，完成任意地址写。

这实际上分为两个部分，首先，我们要知道，`unsortedbin attack`并非只能在指定位置写一个`libc`地址，还可以类似于`fastbin attack`完成一个`chunk`的分配，只是条件比较苛刻。一句话就是需要`unsortedbin`的`bk`指向的`chunk`的`bk`可写，其`size`合法。

那么我们便可以利用`largebin attack`来完成这些条件：

- `largebinattack`可以写两个值
- 第一个值错位写要申请的地方的`size`，使得堆地址最开始的`0x55`或者`0x56`为`size`
- 第二个值写要申请的地方的`bk`，使得`bk`为一个可写的值
- 然后申请大小为`0x50`的`chunk`即可申请到`unsortedbin`的`bk`