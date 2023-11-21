---
layout: post
title: unsortedbin leak及unsortedbin attack利用分析
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# unsortedbin attack

广义上的`unsorted bin attack`其实分为`unsorted bin leak`和`unsorted bin attack`，前者可以根据`unsorted bin`的特性来泄露出`libc`的地址，后者的作用是对一个指定地址写入一个非常大的值（其实是写入`main_arena`的地址的一个偏移）。

## unsortedbin特性

首先是`unsorted bin`的来源，这里抄一下`wiki`

```
1.当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2.释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。
3.当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。
```

然后是使用情况，抄一下`wiki`

```
1.Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取。
2.在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。
```

用一下`gzy`的图

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712814.jpeg)

## unsortedbin leak

从上图也可以看到，与`unsorted bin`直接相连的一个`bin`是最后插入到`unsorted bin`里面来的。它的`bk`指针指向`unsorted bin`。换句话说，它的`bk`指针指向`main_arena`的一个固定偏移，而`main_arena`和`libc_base`也有一个固定偏移，那么只要泄露出来了它的`bk`指针，也就不愁计算出`libc`的地址了。这里用先插入到`unsorted bin`的`fd`指针也是同理的。

## unsortedbin attack

作用是向指定地址写入一个非常大的值，即`main_arena`的一个固定偏移。

`unsotred bin attack`的攻击过程发生在这种情况：

调用`malloc`时，反向遍历`unsorted bin`，若`unsorted bin`里面恰好有与请求的`chunk size`相等的`chunk`大小，那么将对应的`chunk`取出来，该`chunk`也就被叫做`victim`。若不是恰好相等，那么这个`chunk`就会被放到对应的`small bin`或者`large bin`中去。

来看这一小段`glibc2.23`的源代码：（第一行和第二行之间省略了一部分不影响的）

```c
bck = victim->bk;                        
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

正常情况下，这一小段代码会将`victim`取出，而`unsorted bin`继续保持双向链表。注意，`victim`始终是`unsorted bin`里面的最后一个`chunk`，因为是反向遍历的`unsorted bin`，且遍历到的`chunk`要么会返回给用户，要么就会被移动到`small bin`或者`large bin`里面去。

而攻击情况下，我们将控制`victim`的`bk`指针为希望进行地址修改的地方减去`8byte`的地方（32位为`4byte`）。

我们通过画图的方式来解释一下正常情况和攻击的情况。

首先是正常情况：

![image-20230623150536713](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712785.png)如图所示，我们假设最后一个`chunk`刚好是`malloc`需要的大小，因此被标记为`victim`。

此时运行到第一行代码 `bck = victim->bk;`很简单，我们将`victim`的`bk`指针指向的`chunk`标记为`bck`。如图所示：

![image-20230623150554561](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712370.png)

然后是第二行代码`unsorted_chunks (av)->bk = bck;` 很简单，本来`unsorted bin`的`bk`指针是指向`victim`的，而`victim`将要被`malloc`，因此先将`unsorted bin`的`bk`指针指向`bck`。

第三行代码`bck->fd = unsorted_chunks (av);`也很简单，和上面同理，我们要将`bck`的`fd`指针指向`unsorted bin`，以此将`victim`脱链。这两步如图所示：

![image-20230623151132502](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712850.png)

此时实际上`victim`的两个指针还指向它们，但`unsorted bin`和`bck`指针都不再指向它，因此相当于`victim`已经被取出了。

**现在我们考虑对其进行攻击的情况。**

若我们能够控制`victim`的`bk`指针，并将其指向一个`fake_chunk`（该`fake_chunk`的`fd`指针是我们希望修改的值。也就是`&fake_chunk + 0x10`，那么在代码的第一行`bck = victim->bk;   `，将会出现如图所示的情况：

![image-20230623151718915](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712822.png)

那么第二行代码`unsorted_chunks (av)->bk = bck;`，将会将`unsorted bin`的`bk`指针也指向该`fake_chunk`。

第三行代码`bck->fd = unsorted_chunks (av);`则是攻击的真正实施：它将`bck`处的`fd`指针修改为了`unsorted bin`的地址。也就是实现了这一步：`*(&fake_chunk + 0x10) = unsorted_bin`。

此时如图所示：

![image-20230623152236540](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712794.png)

至此，已经实现了攻击。