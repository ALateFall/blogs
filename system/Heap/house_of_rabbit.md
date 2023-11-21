---
layout: post
title: house of rabbit：fastbin的其他攻击方式
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# house of rabbit

`house of rabbit`是一种`fastbin`的攻击方法，可以在没有`leak`的情况下通过获得一个`overlap chunk`或者是一个`fake chunk`。这是利用了`malloc_consolidate`没有进行很好的安全校验来进行攻击的。

我们知道`fastbin attack`需要保证取出的`chunksize`和`fastbin`的`size`一样，在很多情况下需要寻找`0x7f`或者是打`unsortedbin attack`来找`0x7f`。而`house of rabbit`同样针对`fastbin`，它只需要能够触发`malloc_consolidate`（`malloc`一个很大的值就可以触发），然后下列两者条件中的一个即可：

- 可以控制`fastbin`中`chunk`的`fd`指针
- 可以控制`fastbin`中`chunk`的`size`

上面我们提到两个条件是二选一即可，是因为两个条件可以发起不同的攻击。下面让我们详细理解。

## 可以控制fd指针

当可以控制`fd`指针的时候，师傅们很容易想到`fastbin attack`，然而`fastbin attack`在部分情况下存在局限性。

只要可以控制`fastbin chunk`的`fd`指针，之后只需要将`fd`指针指向一个任意地方的`fake chunk`，然后触发`malloc_consolidate`，就可以申请到该位置的`fake chunk`。但也需要附加条件，那就是需要该`fake chunk`的下一个和下下个`fake chunk`也构造好（实际上只需要构造`chunk size`）。画个图来理解：

![image-20231114100530815](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211716419.png)

## 可以控制chunksize

当可以控制`chunksize`时，可以获得一个`chunk overlap`。具体过程如下：

首先申请两个相同大小的`chunk`，例如`0x40`的两个`chunk`。释放后，我们将第一个`chunksize`更改为`0x80`，此时若触发`malloc_consolidate`，那么会分别将两个`chunk`添加到大小为`0x40`和`0x80`的`smallbin`中。那么当`size`被修改为`0x80`的`chunk`被添加到大小为`0x80`的`smallbin`中后，`chunk overlap`实际上就已经发生了。因为只需要申请大小为`0x80`的`chunk`就可以获得这个`chunk`了。