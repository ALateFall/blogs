---
layout: post
title: tcache浅谈
category: Heap
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

## tcache perthread struct

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

## tcache poisoning及其变迁

### glibc2.27低版本

若存在`tcache`机制时，若申请一个属于`tcache`中的`chunk`，使用到的函数是`tcache_get()`函数，该函数在初始版本没有任何的安全机制，因此只需要简单地将某个`tcache`中的`chunk`的`fd`指针修改为想要分配到的地方，即可在目标地址申请一个`chunk`。

### glibc2.27高版本-glibc2.29

在`glibc2.27`的高版本开始，`tcache chunk`的`bk`将不再为空，而是`tcache_perthread_struct`的用户地址。然而这和`tcache poisoning`没有任何关系，我们仍然可以没有任何限制地使用`tcache poisoning attack`。

### glibc2.31

在`glibc2.31`，`glibc`添加了对`tcache`的`count`的检查，即在对应`index`的`count`小于等于`0`时，无法从该`tcache`中申请`chunk`。这意味着我们在`tcache`中只有一个`chunk`时修改其`fd`指针来完成攻击，而是至少需要两个`chunk`位于同一个`tcache bin`中。

总结：

- 至少两个`chunk`位于同一个`tcache bin`（或者别的方式，总之有`count`检查）

### glibc2.32-glibc2.38

自从`glibc2.32`开始，`glibc`引入了相当多对于`tcache`的检查。我们这里只说`poisoning`，不说`double free`，这一部分在后面。

首先，`tcache bin`会检查待申请的地址是否对齐，即末位是否为`0`。若不为`0`，则会报错。

其次，`tcache`的`fd`指针将会被加密。假设要申请的地址为`target`，`chunk`的用户地址为`address`，则：

```c
chunk->fd = target ^ (address >> 12);
```

值得注意的是，在`glibc2.27`高版本到`glibc2.33`，我们**可以通过泄露`bk`的方式来获得堆地址。**

总结：

- 至少两个`chunk`位于同一个`tcache bin`（或者别的方式，总之有`count`检查）
- 待申请地址必须对齐
- `chunk -> fd = target ^ (address >> 12)`

## tcache double free

若没有`tcache`的时候，`double free`不能简单地连续对一个`chunk`进行`free`两次这个机制略显复杂的话，那么`tcache double free`就显得单纯许多了。在初始版本下`tcache`的释放操作是使用的`tcache_get()`函数，该函数同样没有任何安全机制，因此可以简单地直接对一个`chunk`进行两次`free`，因此可以申请回该`chunk`，对其修改后再次申请，完成任意地址写/任意地址`chunk`分配的目的。

### 高版本

从`glibc2.27`高版本开始简单的`tcache double free`已经成为了历史。

`patch`方式为`tcache chunk`的`bk`指针处将会有一个`key`，对于每一个释放的`chunk`，若其`bk`指针等于其`key`，说明该`chunk`属于`tcache`，便会循环`tcache`来遍历检查其是否已经位于`tcache`。因此若你能修改其`bk`指针为任意值（只要不等于`key`），也可以进行`double free`。（或者你可以尝试`house of botcake`）

- 在`glibc2.27`高版本-`glibc2.33`，`tcache`的`key`为`tcache_perthread_struct`的用户地址。

- 在`glibc2.33-glibc2.38`，`tcache`的`key`为随机数。

## tcache house of spirit

与`fastbin`的`house of spirit`是相当类似的，不同的是，`tcache`的`house of spirit`更加简单，可以直接在任意地方伪造一个`chunk`然后进行`free`。`fast bin`的`house of spirit`还需要控制要`free`的下一个`chunk`的`size`域。

## tcache_stash_unlink_attack

`tcache stash unlink`可以达成两个目的：

- 任意地址申请一个`fake chunk`
- 往任意地址写一个`main_arena`地址

看起来就像`fastbin attack`和`unsortedbin attack`的结合，威力很强，但是同时利用条件也非常苛刻：

- 需要保证同一种大小的`chunk`在`tcache`中有`5`个，而在`smallbin`中有`2`个。（一般利用）
- 至少进行一次`calloc`
- 需要`UAF`来对`smallbin`中的`chunk`进行修改

其原理是：

首先需要知道`calloc`。`calloc`和`malloc`有两个不同点，其一是会自动清零申请到的`chunk`，其二是`calloc`不会申请`tcache`中的`chunk`。而`smallbin`有一个特点，那就是当`smallbin`中的`chunk`被申请后，其通过`bk`相连的所有`chunk`都会被挂入`tcache`。

由此，我们可以修改后插入的`chunk`（它的`bk`指针指向`main_arena`）的`bk`指针，使其指向我们控制的`fake_chunk`。只要进行一次`calloc`，`glibc`会使得其从`smallbin`中申请一个`chunk`，然后将剩下的`smallbin`中的`chunk`都挂入`tcache`（包括我们修改后的`smallbin chunk`）。当我们修改后的`chunk`被挂入`tcache`后，由于其是通过`bk`指针来寻找下一个`chunk`的，因此会将`fake_chunk`也挂入`tcache`。

然后，其会试图再将`fake_chunk`的`bk`也挂入`tcache`，其中会使得：`bck->fd=bin`，会使得`fake_chunk`的`bk`指针指向的`chunk`的`fd`写一个`main_arena`地址。因此，若我们想要在`target_addr`写一个`main_arena`的值，我们需要控制`fake_chunk`的`bck`的值为`target_addr-0x10`。

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
