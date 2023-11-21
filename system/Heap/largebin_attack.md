---
layout: post
title: largebin attack小记
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# largebin attack

## largebin结构示意图

笔者曾经阅读过一些文章后得出下面的示意图，实际上是错误的。

![image-20230703232238755](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211713814.png)

正确的结构图如图所示：

- 每一个`largebin`中存放的`chunk`大小是不相同的，一共有`63`个`largebin`。在这`63`个`largebin`中，前`32`个`largebin`的最大`chunk`和最小的`chunk`之差为`64bytes(0x40)`。例如第一个`largebin`的大小为`512bytes-568bytes`，而第二个`largebin`的大小就为`576bytes-632bytes`。
- 每一个`largebin`中的`chunk`按照大小顺序从大到小排序。
- 若大小相同，则会按照释放顺序排序：最先释放的`chunk`拥有`fd_nextsize`和`bk_nextsize`指针，之后的`chunk`的这两个指针的值都为`0`。若将这个`chunk`称为小堆头，那么后面释放的`chunk`都会被插入到小堆头的后面。因此，对于同一个大小的`large chunk`，最先释放的在最上面，除此之外越先释放在越后面。

- `fd_nextsize`和`bk_nextsize`是指向当前`bin`的下一个大小的`chunk`。`fd_nextsize`指向比自己小的，而`bk_nextsize`指向比自己大的。

![image-20230731190106590](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211713703.png)

## largebin attack（glibc 2.23）

首先让我们明确攻击需要的条件、出现的位置，和其正常情况下本来的目的。

首先是**攻击需要的条件：**

- 能够对一个`large bin`中的`chunk1`进行任意写
- 从`unsorted bin`中有一个正常`chunk2`释放到`large bin`

攻击能完成的结果：

- 将一个攻击者指定的地址的值修改为一个非常大的值，即一个`heap`的地址。

正常情况下，若用户使用`malloc`申请了一个`large chunk`，那么`ptmalloc2`会进行如下操作：

- 若直接与`unsorted bin`相连的是`last remainder`，那么切割该`last remainder`
- 否则，倒序遍历`unsorted bin`，遍历到的`chunk`称为`victim`。若用户请求的大小与`victim`的大小恰好相同，那么会将其返回给用户。若不是恰好相同，则会将`victim`插入到其属于的`large bin`或者`small bin`中。
- 在插入对应的`large bin`时，由于`large bin`是从大到小排序的，那么需要通过`bk_nextsize`指针一直定位到其属于的地方。**`Largebin attack`即发生在这里。**
- 遍历完`unsorted bin`后，若没有找到恰好相等的`chunk`，那么会去对应的`large bin`查看。 

**攻击的情况如下：**

假如本来有两个`chunk`，分别叫做`chunk1`和`chunk2`，且`chunk1`在`large bin`中，而`chunk2`在`unsorted bin`中，如图所示：

![image-20230802155357129](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211713757.png)

我们对`chunk1`进行构造，主要是针对其`size`、`bk`、`bk_nextsize`。如图所示：

我们最终的目的就是要修改其中的`value1`和`value2`。我们构造了两个`fake chunk`，其中一个是`chunk1`的`bk`指针指向的，它的`fd`指针就是我们要修改的`value1`，而另一个是`chunk1`的`bk_nextsize`指针指向的，它的`fd_nextsize`指针就是我们要修改的`value2`。因此，`chunk1`的`bk`和`bk_nextsize`指针是要分别指向要修改的地址处减去`0x10`和`0x20`个字节。此外，我们还将其`size`减小到了`0x3f0`。

![image-20230802165220878](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211713922.png)

接下来，若用户再次申请一个不属于`fast bin`的`chunk`，且`chunk2`与其不相同，那么会导致`chunk2`被挂进`large bin`。根据`chunk2`是不是比其属于的`bin`中最小的`chunk`还要小，会有两种插入逻辑，我们这里讲一下更复杂的情况，即`chunk2`不是最小的`chunk`。那么，此时我们便需要将其插入到正确的位置。这里放代码如下：

```c
while ((unsigned long)size < fwd->size) 
{
    fwd = fwd->fd_nextsize; 
    assert((fwd->size & NON_MAIN_ARENA) == 0);
}
if ((unsigned long)size == (unsigned long)fwd->size)
    fwd = fwd->fd; 
else               
{
    victim->fd_nextsize = fwd;                 
    victim->bk_nextsize = fwd->bk_nextsize;    
    fwd->bk_nextsize = victim;                 
    victim->bk_nextsize->fd_nextsize = victim; 
}
bck = fwd->bk;
```

由于我们将`chunk1`的`size`减小了，那么其中的`if`语句将不再执行，而是进入接下来的`else`。

其中，`fwd`也就是`chunk1`，`victim`是`chunk2`。

第一句`victim->fd_nextsize=fwd`，就是`chunk2`的`fd_nextsize`指向`fwd`，没有影响，甚至不用管

第二句，`victim->bk_nextsize=fwd->bk_nextsize`，这就有意思了，由于`fwd->bk_nextsize`是执行我们的`fake_chunk`，那么`victim->bk_nextsize`也会指向`fake_chunk`。此时如图所示：

![image-20230802170041495](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211713969.png)

第三句，`fwd->bk_nextsize=victim`，现在把`chunk1`的`bk_nextsize`指向`victim`，不用管。

第四句，`victim->bk_nextsize->fd_nextsize=victim`，此时`victim->bk_nextsize`是我们的`fake_chunk`，那么`victim->bk_nextsize->fd_nextsize`也就是`value1`！那么，我们就完成了`value2`的修改了，将其修改为了`victim`的地址。如图所示：

![image-20230802170334141](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211713890.png)

接下来在将`chunk2`置入`largebin`的过程中还会设置其`fd`指针和`bk`指针，代码如下：

```c
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

同样的，这会将`value1`修改为`victim`，此处不再赘述。