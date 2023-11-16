---
layout: post
title: 经典文章阅读：Understanding glibc malloc
category: system
date: 2023-8-21 20:55:29
---
对经典文章Understanding glibc malloc的阅读笔记&夹带自己理解的翻译
<!-- more -->
[toc]


[原文链接](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/comment-page-1/)

内存的管理方式有许多种，例如：

```
- dlmalloc – General purpose allocator
- ptmalloc2 – glibc
- jemalloc – FreeBSD and Firefox
- tcmalloc – Google
- libumem – Solaris
…
```

本文将只对`glibc malloc`进行讲解，其他的内存管理方式将留到以后进行讲解。让我们开始吧！（本文讲解的内存管理方式基于[此处](https://sourceware.org/legacy-ml/libc-alpha/2014-09/msg00088.html)）

# 发展历史

实际上，`ptmalloc2`是由`dlmalloc`的源代码`fork`而来的，并在`dlmalloc`的基础上添加了线程的支持，最终2006年发布。这之后，`ptmalloc2`这一内存管理方式被集成到了`glibc`中，这之后`glibc`开始自己对`malloc`内存管理方式进行修改。因此，目前`ptmalloc2`内存管理方式和`glibc`的`malloc`实现已经有着不小的差距了。

# 系统调用

[如此所示](https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc/)，`malloc`内部有两种系统调用，即`brk`和`mmap`。

# 线程

在`linux`的早期版本，`dlmalloc`才是其默认的内存管理方式，但由于`ptmalloc2`添加的线程支持，这之后`ptmalloc2`才成为了`linux`的默认内存管理方式。线程能够改善内存分配的性能，也就是说，线程的支持能够改善应用程序的性能。在`dlmalloc`中，当两个线程同时调用`malloc`的时候，只有一个线程能够进入临界区修改数据，但这个时候操作系统中的空闲内存又是所有线程共享的。因此，内存分配问题在多线程的应用程序中占用了大量时间，造成程序的应用性能下降。在`ptmalloc2`中，当两个线程同时调用`malloc`的时候，内存将可以被立即分配，因为每个线程都维护了一个独立的`heap`，这些`heap`的空闲内存也是独立的。这个用于为每个线程维护独立的`heap`和空闲内存的东西就叫做线程`arena`。在`ptmalloc2`中，这个“空闲内存”也就是`bin`。

*Example*：

```c
/* Per thread arena example. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

void* threadFunc(void* arg) {
        printf("Before malloc in thread 1\n");
        getchar();
        char* addr = (char*) malloc(1000);
        printf("After malloc and before free in thread 1\n");
        getchar();
        free(addr);
        printf("After free in thread 1\n");
        getchar();
}

int main() {
        pthread_t t1;
        void* s;
        int ret;
        char* addr;

        printf("Welcome to per thread arena example::%d\n",getpid());
        printf("Before malloc in main thread\n");
        getchar();
        addr = (char*) malloc(1000);
        printf("After malloc and before free in main thread\n");
        getchar();
        free(addr);
        printf("After free in main thread\n");
        getchar();
        ret = pthread_create(&t1, NULL, threadFunc, NULL);
        if(ret)
        {
                printf("Thread creation error\n");
                return -1;
        }
        ret = pthread_join(t1, &s);
        if(ret)
        {
                printf("Thread join error\n");
                return -1;
        }
        return 0;
}
```

*输出结果分析*：

*在调用`malloc`之前：*

我们的程序会输出程序进程对应的`pid`。我们可以访问`linux`下的`/proc/[pid]/maps`来查看其内存空间的分配。在下面的输出中，我们可以看到，目前是没有任何`heap`被创建的，而由于`thread1`还没有被创建，因此输出中可以看到也没有线程的栈空间出现。

```bash
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
b7e05000-b7e07000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

*主线程调用`malloc`之后*：

此时，我们从下面的输出中可以看到，`heap`段已经被创建了，且其范围为`0x0804b000-0x0806c000`，即大小为`132kb`。这说明这里的堆内存是由`brk`系统调用来创建的（不懂的可以看上面系统调用那里提到的那篇文章）。注意，用户只申请了`1000bytes`的内存空间，但操作系统仍然创建了`132kb`的堆内存。这一段连续的内存区域就叫做`arena`。以后的内存申请都会使用该区域，直到该区域的内存被分配完为止。有的师傅可能会想，那假如这个`arena`的内存分配完了的时候怎么办呢？此时，`arena`可以再通过中断的方式来增加内存。类似地，若`top chunk`处的空闲内存过大，`arena`也可以通过这种方式来缩小。

（`top chunk`是`arena`中顶部的一个`chunk`，我们接下来还会进行详细的讲解）

```bash
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

*主线程调用`free`之后：*

在下面的输出中，我们可以看到，即使用户刚刚申请的内存已经被释放了，刚刚通过`brk`系统调用获得的`132kb`的内存并没有被立即释放。此时，刚刚释放的`1000bytes`的内存空间被释放给了`glibc`中叫做`bin`的地方（可以理解为`Windows`系统中的回收站）。我们前面提到，每个线程都拥有自己的`arena`，因此我们刚刚释放的`1000bytes`实际上是放入了`main arena`的`bin`中。接下来，若用户需要申请内存，那么`glibc`将不会从`arena`中给用户一块新的内存，而是从`bin`中取出一块内存来给用户使用。只有`bins`中不含有空闲的内存块时，`glibc`才会从`arena`中给用户分配内存。

```bash
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

*thread1调用malloc之前：*

观察代码，我们创建了一个子线程，并且让它执行代码中的`threadFunc`函数。在子线程刚刚创建，还没有调用`malloc`的时候，我们查看它的内存空间如下。可以看到，`thread1`的`heap`空间目前还没有创建，但它的栈空间已经创建好了。

```bash
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

*therad1调用malloc之后：*

从下面的输出中我们可以看到，`thread1`的`heap`空间已经创建好了，且其位于内存的映射区域，即`0xb7500000-0xb7521000`处，大小也为`132kb`。这说明这一段内存是通过`mmap`系统调用来生成的（记得前文说过`main arena`是通过`brk`系统调用来生成的吗）。这里同样的，尽管用户只申请了`1000bytes`，但是操作系统仍然分配了`1MB(0xb7500000-b75600000)`的内存空间。在这`1MB`的内存空间中，只有`132KB`的内存空间有读写权限，这个部分就是`thread arena`。

```bash
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0 
b7521000-b7600000 ---p 00000000 00:00 0 
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

*thread1调用free后*：

在`thread1`调用`free`后，我们可以看到这段`free`掉的`1000bytes`内存空间同样没有还给操作系统。事实上，这段内存空间被释放给了`thread arenas bin`。

```bash
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
After free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0 
b7521000-b7600000 ---p 00000000 00:00 0 
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$
```

# Areana

## Arena的数量

在上面的例子中，主线程包含了一个主`arena`，而`thread1`包含了一个`thread arena`。那么是否一个线程一定和一个`arena`一一对应呢？答案是否定的。举个例子，一个程序可以有非常多的线程，甚至多于操作系统拥有的`cpu`的核心数量，那么这种情况下给每个线程都分配一个`arena`非常浪费。因此，一个应用程序的子线程`arena`的数量限制与系统中的`cpu`核心数相关，如下所示：

```tex
对于32位系统：
arena数目 = 2 * cpu核心数
对于64位系统：
arena数目 = 8 * cpu核心数
```

注意，主线程一定有自己的`main arena`，因此总的`arena`数量要在此基础上`+1`

## Arena调度策略

上面我们讲述了`arena`的数量限制。那么，一个很自然的问题就出现了：对于没有分配到`arena`的线程，如何进行内存管理呢？这就要引出`arena`的调度策略了。

假设我们现在有一个`32位`应用程序，它一共含有`3`个子线程，且只有`1`个`cpu`核心。那么，此时线程的数量是`3+1=4`个线程，而`arena`的最大个数是`1(cpu核心数) * 2 (32位系统) = 2`个。在这种情况下，`glibc`为了让每个线程都能在工作的时候分配到`arena`，会采用调度策略。假设线程间的`malloc`顺序如下：

- 主线程第一次调用`malloc`时，直接使用`main arena`，没有竞争。
- `thread1`和`thread2`第一次调用`malloc`的时候，都会为他们分配一个`thread arena`，没有任何的竞争。此时线程和`arena`之间也是一对一的关系。
- 接下来，`thread3`也调用了`malloc`。由于`arena`数量已经达到最大值，无法再给`thread3`分配一个`arena`，因此此时`glibc`将会让`thread3`尝试重用这几个`arena`（`main arena, arena1, arena2`）：
- 重用过程：
- - 循环遍历来寻找可用的`arena`，直到找到一个可用的`arena`为止。
  - 若找到了一个可用的`arena`，则尝试将它锁定，并将这个`arena`返回给线程使用、
  - 若没有找到可用的`arena`，那么`thread3`将会被阻塞，直到有一个可用的`arena`为止。
- 在`thread3`第二次调用`malloc`1的时候，`thread3`将会尝试使用最后一次使用的`arena`。假设上一次`thread3`使用了`main arena`，那么`thread3`将会尝试使用`main arena`。若`main arena`此时可用，那么`thread3`将会直接尝试使用`main arena`。若`main arena`此时不可用，那么`thread3`将会被阻塞，直到`main arena`可用为止。如此一来，`main arena`就在主线程和`thread3`之间实现了共享。

## heap

在`glibc`的源代码中，主要有以下三种数据结构：

```tex
heap_info
这是heap的header。一个arena可以含有多个heap，而每个heap都有一个header。为什么需要这么多个heap？事实上，在刚开始的时候每个thread arena只有一个heap，但在这个heap的空间用完的时候，会使用mmap来申请更多的heap（与之前的heap并不是连续的空间）。
```

```tex
malloc_state
这是arena的header。一个arena可以有多个heap，但是这些heap都由这一个arena管理，因此他们归属于同一个arena header。arena header中有多种信息，包括bins、top chunk、last remainder chunk...
```

```tex
malloc_chunk
这是chunk的header。一个heap会基于用户请求分成很多个chunk。每一个chunk都有自己的header，即malloc_chunk。
```

注意：

- `main arena`没有多个`heap`段，也因此没有`heap_info`结构。当`main arena`的内存空间不够时，`sbrk`的堆结构将会被扩展（且是扩展了一段连续区域），直到遇到内存映射段为止。
- 与`thread arena`不同，`main arena`的`arena header`并不是`sbrk`堆段的一部分，它实际上是一个全局变量，并且被保存在`libc`中。数据段也是同样的。

`main arena`和`thread arena`的示意图如下：

只有一个`heap`的情况：

![image-20230710100156754](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307101001851.png)

`thread arena`中含有多个`heap`的情况：

![image-20230710100313034](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307101003078.png)

## chunk

`chunk`是进行内存管理的基本单元，`heap`中的`chunk`可能有如下形式：

- `Allocated chunk`（正在被使用）
- `Free chunk`（空闲）
- `Top chunk`
- `Last Remainder chunk`

其中，前面两种表示`chunk`的状态，而后面两种表示两种特殊的`chunk`。

`Allocated chunk`的结构如图所示：（每一行是一个数据，在32位下为`4byte`，64位下为`8byte`）

![image-20230710100603017](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307101006056.png)

`prev_size`：实际上是最上面的数据。它不取决于当前`chunk`的状态，而是取决于与之相连的上一个`chunk`的状态。若上一个`chunk`的状态是`free`的，那么这个数据将会存放上一个`chunk`的大小，即`prev_size`；若上一个`chunk`的状态是`allocated`，那么这个数据空间将会作为上一个`chunk`额外可以存放的一点数据。

`size`：这是图中的第二行数据。可以看到，它包含`chunk size`和`N/M/P`三个数据位。这里是把本行的最后三个`bit`用作数据位（因为`size`最后三个`bit`本来肯定为0，因此这三个`bit`可以用来表示信息）。

其中：

- `N`表示`NON_MAIN_ARENA`。表示当前的`chunk`是属于`main arena`的还是属于`thread arena`的。若属于`thread arena`，那么`N=1`。

- `M`表示`IS_MMAPED`。若当前`chunk`是由`mmap`创建的，那么`M=1`。

- `P`表示`PREV_INUSE`。若前一个`chunk`的状态是`free`，那么该标志位为`0`，若为`allocated`，那么该标志位为`1`。

`Free Chunk`的结构如图所示：

![image-20230710182624916](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230710182624916.png)

`prev_size`：当`chunk`的状态为`free`的时候，上一个`chunk`若也为`free`状态，那么两个`chunk`会被合并，因此不存在这种情况。因此，上一个`chunk`的状态此时一定为`allocated`，`prev_size`一定存放的是上一个`chunk`的数据。

`size`：和`allocated`状态的`size`位是一样的。

`fd`：前向指针，指向同一个`bin`中的下一个`chunk`。注意，不是指向物理内存相连的下一个`chunk`。

`bk`：后向指针，指向同一个`bin`中的上一个`chunk`。同上，不一定指向物理内存相连的下一个`chunk`。

## bins

`bins`是维护被`free`掉的`chunk`的数据结构。基于`chunk`大小的不同，`bins`可以被分为如下形式：

- `Fast bin`
- `Unsorted bin`
- `Small bin`
- `Large bin`

`bin`在操作系统中由以下数据结构进行管理：

**`fastbinsY`**: 管理`fastbin`

**`bins`**: 管理`unsortedbin`、`small bin`和`large bin`。`bins`是个数组，长度为`126`，并且对应关系如下：

- `Bin 1` - `Unsorted bin`
- `Bin 2 - Bin 63` - `Small bin`
- `Bin 64 - Bin 126` - `Large bin`

## Fast bin

- 一共有`10`个`fastbin`。每一个`fastbin`都是单链表，因为`fastbin`的`chunk`的存取操作都不会发生在链表的中间。由于`fastbin`是为了时间局部性原则，因此是后进先出（`LIFO`），存取操作都发生在链表头。
- 在一个单链表内，`chunk`的大小都是相同的。不同的单链表之间的大小差是根据系统的位数决定的，在`32位`下，差为`8`，在`64位`下的差则为`16`。例如在`32`位下，`fastbin0`的大小为`16bytes`，那么`fastbin1`的大小为`24bytes`。

- 在`malloc`初始化期间，最大的`fastbin size`被设置为`64bytes`，因此默认情况下`16bytes-4bytes`的`chunk`被分类为`fastbin chunk`
- **`fastbin`不会合并。**其他的`bins`中，两个相邻的空闲块可能会发生合并，但是`fastbin`是不会的，尽管这可能会产生内存碎片。这是因为这样做可以使得`free`的速度更快，`fastbin`就是为了操作系统能够更快地利用这些刚释放的`chunk`而设计的。
- `fastbin`的范围是由一个叫做`global_max_fast`的变量决定的，而这个变量在第一次`malloc`请求的时候还是空的。因此，当第一次使用`malloc`申请内存的时候，即使申请的内存大小属于`fastbin`，也会交给`small bin`来处理。

![image-20230716232409024](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230716232409024.png)

## Unsorted bin

当大小属于`small bin`或者`large bin`的`chunk`被释放的时候，`chunk`也不会直接添加到对应的`bin`里面去，而是先被添加到`unsorted bin`，类似于`fast bin`，这样有利于时间局部性，因此略微加快了内存分配的速度，因为没有寻找合适的`bin`这个过程的时间。

- 一共有`1`个`unsorted bin`。`unsorted bin`包含一个循环双向链表。如图所示。
- `chunk`的大小：没有限制，任何一个大小的`chunk`都可以被添加到`unsorted bin`。

![image-20230716232356352](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230716232356352.png)

## Small bin

低于`512bytes(0x200)`的`chunk`被称为`small chunk`。`small bin`的分配速度比`large bin`略快，但是比`fastbin`更慢。

- 一共有`62`个`small bin`。每一个`small bin`都是一个双向循环链表，因此在`small bin`中的`chunk`都是通过`unlink`的方式进行解链的。添加到`small bin`的`chunk`将会被添加到链表头，但是删除操作会发生在链表尾（`FIFO`）。
- 不同`small bin`之间的差值和`fastbin`是一样的。在同一个`small bin`中，`chunk`的大小是一样的，因此他们在循环链表中的顺序是置入`small bin`的顺序，不会发生别的排序。
- **合并**：在`small bin`中，若有两个相邻的`chunk`都是`free`的，那么他们会发生合并，成为一个空闲的`chunk`。合并操作减少了外部碎片，但是同时也减慢了`free`的速度。
- `malloc`时：初始状态下`small bin`都为空，因此用户即使访问了一个属于`small bin`的`chunk`也是由`unsorted bin`来处理。在第一次调用`malloc`时，`small bin`和`large bin`都将被初始化，并且它们的`bin`都会指向自身，表示它们是空的。若`small bin`不为空，那么会取出对应`small bin`中的最后一个`chunk`给用户。
- `free`时：会检查相邻的上一个或者下一个`chunk`是否是`free`的，如果是，那么则会发生合并，并且将合并后的`chunk`添加到`unsorted bin`中。

## Large bin

大于或等于`512bytes(0x200)`的`chunk`被称为`large chunk`，管理空闲的`large chunk`的数据结构叫做`Large bin`。

- 一共有`63`个`largebin`。每一个`large bin`都是双链表，因为在链表头、链表尾以及任意位置都可能添加或者删除数据。

- 和`small bin`不同，在`large bin`中的`chunk`并不是同一个大小，因此在`largebin`中的`chunk`是按照降序排列的：最大的`chunk`在链表头，而最小的`chunk`在链表尾部。

- 在这`63`个`largebin`中，前`32`个`largebin`的最大`chunk`和最小的`chunk`之差为`64bytes`。例如第一个`largebin`的大小为`512bytes-568bytes`，而第二个`largebin`的大小就为`576bytes-632bytes`。

  接下来的`16`个`largebin`相差`512bytes`。

  接下来的`8`个`largebin`相差`4096bytes`。

  接下来的`4`个`largebin`相差`32768bytes`。

  接下来的`2`个`largebin`相差`262144bytes`。

  最后的`1`个`largebin`包含其他所有的大小。

- **合并**：两个相邻的`free`的`chunk`会被合并为一个`chunk`。

- `malloc`时：未初始化时，与`small bin`过程相同。

  初始化完成后，若用户请求的`chunk`大小要小于`large bin`中最大的`chunk`，那么`largebin`会进行遍历来找到大小相等或者接近的`chunk`。找到之后，这个`chunk`会被进行切割成两个部分：第一个部分返回给用户，第二部分作为`Remainder chunk`添加到`unsorted bin`。

  若用户请求的`chunk`大小要大于`large bin`中最大的`chunk`，那么`largebin`则需要寻找一个更大的`largebin`。但此时若直接遍历查看往后的`largebin`是否有满足条件的`largebin`太慢了，因此有一个叫做`binmaps`的东西用来记录哪些`largebin`为空，并以此找到下一个不为空的`largebin`来重复以上的遍历方法。一旦找到了，同上。若没有找到，那么会使用`top chunk`来分配合适的内存。

- `free`操作：和`small bin`相同。

## Top Chunk

`Top Chunk`是在一个`arena`的顶端部分的`chunk`，它不属于任意的`bin`。`Top chunk`的作用是在所有`bin`中都没有空闲的`chunk`时来处理用户的`malloc`请求。

若`top chunk`大小要大于用户请求大小，那么`top chunk`会被分为以下两个部分：

- 用户请求，返回给用户
- `Remainder chunk`，`Remainder chunk`会成为新的`top chunk`。

若`top chunk`大小要小于用户请求大小，那么`top chunk`会通过`sbrk(main arena)`或者`mmap(thread arena)`的系统调用方式来进行扩展，取决于是`main arena`还是`thread arena`。

## Last Remainder Chunk

`Last Remainder Chunk`是一个在`Unsorted bin`中的特殊`chunk`。它会有两个地方产生作用：

- 用户请求的`size`输入`small bin`，但`small bin`中对应的`bin`为空，而略大于这个`chunk`对应的值的`small bin`非空，那么就从这个`small bin`上面取出一个`chunk`，分为两部分，一部分给用户，而另一部分形成`Last Remainder Chunk`返回到`Unsortedbin`中。这也就是产生。

- 若处理用户的请求时，`fastbin`和`smallbin`均分配失败，那么会尝试从`unsorted bin`中分配。如果满足以下条件：

  - 申请的`size`在`small bin`范围内
  - `unsortedbin`仅有一个`free chunk`
  - 且为`last remainder chunk`
  - 正好满足用户请求的`size`

  那么，就将`last remainder chunk`分成两部分，一部分返回用户而另一部分作为新的`last remainder chunk`插入到`unsorted bin`中。

`last remainder chunk`主要是利用了内存分配的局部性来提高连续`malloc`的效率（试想有一连串的`small request`）。



至此，`Understanding glibc malloc`这篇文章的个人翻译也就结束了，希望能通过这篇文章为起点，学习到`glibc`的更多知识^ ^。
