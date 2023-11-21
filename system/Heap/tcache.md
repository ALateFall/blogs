---
layout: post
title: tcache浅谈
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# tcache attack

先略记录一下，以后可能会回来补充细节。

## 什么事tcache

这是`glibc 2.26`以后引入的一种为了加快内存分配速度的机制，但同时也产生了很多安全漏洞。由于`ubuntu18.04`已经开始使用`glibc 2.27`，因此`ubuntu 18.04`版本存在`tcache`机制的使用。由于`tcache`机制也逐渐进行了诸多更新，修复了部分漏洞，本文暂时站在`tcache`最初始的版本进行讲解。

若存在`tcache`机制，那么当一个非`large chunk`被`free`后，它不再会被直接添加到`unsorted bin`或者`fast bin`，而是被添加到对应的`tcache bin`中。`tcache bin`是一个单向链表结构，只有`fd`指针，结构可以说是非常简单。

同一个大小的`tcache`中只能存在`7`个`chunk`（默认情况下）。因此，若你想将一个`chunk`申请到`unsorted bin`中，不妨申请`8`个属于`unsorted bin`的`chunk`，由此也可以使用`unsorted bin leak`来泄露`libc`基地址。

值得注意的是，`tcache`指向的直接是用户地址，而不是之前`bin`指向的是`header`的地址。

对于`tcache`，`glibc`会在第一次申请堆块的时候创建一个`tcache_perthread_struct`的数据结构，同样存放在堆上。它的定义如下所示：

```C
/* 每个线程都有一个这个数据结构，所以他才叫"perthread"。保持一个较小的整体大小是比较重要的。  */
// TCACHE_MAX_BINS的大小默认为64
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
// 在glibc2.26-glibc2.29中，counts的大小为1个字节，因此tcache_perthread_struct的大小为1*64 + 8*64 = 0x250(with header)
// 在glibc2.30及以上版本中，counts的大小为2个字节，因此tcache_perthread_struct的大小为2*64 + 8*64 = 0x290(with header)
```

## tcache poisoning

若存在`tcache`机制时，若申请一个属于`tcache`中的`chunk`，使用到的函数是`tcache_get()`函数，该函数在初始版本没有任何的安全机制，因此只需要简单地将某个`tcache`中的`chunk`的`fd`指针修改为想要分配到的地方，即可在目标地址申请一个`chunk`。

## tcache double free

若没有`tcache`的时候，`double free`不能简单地连续对一个`chunk`进行`free`两次这个机制略显复杂的话，那么`tcache double free`就显得单纯许多了。在初始版本下`tcache`的释放操作是使用的`tcache_get()`函数，该函数同样没有任何安全机制，因此可以简单地直接对一个`chunk`进行两次`free`，因此可以申请回该`chunk`，对其修改后再次申请，完成任意地址写/任意地址`chunk`分配的目的。

要注意的是，`glibc`在后来的版本中，在`tcache`的数据结构中添加了`key`，会一定程度上防止`double free`的发生。这个后面再补。

## tcache house of spirit

与`fastbin`的`house of spirit`是相当类似的，不同的是，`tcache`的`house of spirit`更加简单，可以直接在任意地方伪造一个`chunk`然后进行`free`。`fast bin`的`house of spirit`还需要控制要`free`的下一个`chunk`的`size`域。

## tcache stashing unlink attack

这个可以完成任意地址的`chunk`申请。

首先要知道两个小知识点：

- `calloc`获取`chunk`不会从`tcache`中获取
- 在`tcache`有空闲位置的情况下，若从`small bin`中获取到了一个`chunk`，那么会将`small bin`中的所有`chunk`挂到`tcache`中

通过上面两个知识点即可完成`tcache stashing unlink attack`。讲一下流程：

- 通过一定方式，让`tcache`和`small bin`中同时存在某个大小的`chunk`，且`small bin`中不止一个
- 修改`small bin`中的末尾的`chunk`的`bk`指针，使其指向要申请的`fake chunk`。
- 使用`calloc`申请一个`chunk`，此时被修改过的`chunk`将会被挂入`tcache`。而由于该`chunk`的`bk`指针被修改，那么操作系统会误认为该`fake chunk`也在`small bin`中，此时也会被挂入`tcache`中。
- 由于`tcache`是`LIFO`，只要直接申请就可以获得该`fake chunk`。

## tcache_perthread_struct hijacking

上面我们提到了`tcache_perthread_struct`数据结构的形式为：

```c
/* 每个线程都有一个这个数据结构，所以他才叫"perthread"。  */
// TCACHE_MAX_BINS的大小默认为64
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
// 在glibc2.26-glibc2.29中，counts的大小为1个字节，因此tcache_perthread_struct的大小为1*64 + 8*64 = 0x250(with header)
// 在glibc2.30及以上版本中，counts的大小为2个字节，因此tcache_perthread_struct的大小为2*64 + 8*64 = 0x290(with header)
```

在程序初始化堆的时候，会创建一个对应大小的`tcache_perthread_struct`。其中：

- `counts`数组存放了每一个大小的`chunk`目前存放了多少个。
- `entries`是一个链表，它里面存放的值是在下一次申请这个大小的`tcache chunk`的时候，应该分配哪个位置的`chunk`。

要注意，`counts`和`entries`的对应关系是按顺序来的，例如前`0x40`个字节中，第`0`个字节指示大小为`0x20`的`tcache chunk`的已分配数量，第`1`个字节指示大小为`0x30`的`tcache chunk`的已分配数量。又例如，`0x40`字节处的`8`字节表示下一个要分配的`0x20`大小的`tcache chunk`要分配的地址。

若我们能够控制`tcache_pertrhead_struct`，则这两个值都可以被篡改。效果分别为：

- 若我们控制了`counts`，对指定地方大小的`count`设置为7，则再次分配该大小的`chunk`时，就不会分配到`tcache`中。例如可以分配一个`unsorted chunk`来泄露`libc`。
- 若我们控制了`entries`，相当于实现了任意大小的`chunk`的`tcache poisoning`，即可以在任意地址分配`chunk`，威力巨大。