---
layout: post
title: glibc中的bins链表详解
category: system/Heap
date: 2023-12-25 15:48:32
---

`glibc`中的`bins`链表详解
<!-- more -->

[toc]

不知道是否有师傅和我一样，有时候会迷失在`glibc`的链表中，傻傻分不清楚`fd`和`bk`指向的是什么，也会忘记`chunk`的释放和分配顺序。因此就有了这篇文章，以一系列小实验来记录下各个链表的`fd`、`bk`指针的作用，以及各个链表的分配顺序。

# fastbin

通过以下代码在`glibc2.23`进行测试：

```c
// 先进行一个fastbin的测试
// Notice, a -> b means that a's fd pointer points to b

#include <stdio.h>
#include <stdlib.h>


int main(){
    size_t* p1 = malloc(0x20);
    size_t* p2 = malloc(0x20);
    printf("The addr of p1 is %p.\n", (size_t*)((size_t)p1 - 0x10));
    printf("The addr of p2 is %p.\n", (size_t*)((size_t)p2 - 0x10));
    printf("\n");

    free(p1);
    free(p2);
    printf("We free p1 first and free p2 later.\n");
    printf("And p1->fd = %p, while p1->bk = %p.\n", (size_t*)p1[0], (size_t*)p1[1]);
    printf("While p2->fd = %p, p2->bk = %p.\n", (size_t*)p2[0], (size_t*)p2[1]);
    printf("So we can see that the link of fastbin is p2 (free later) -> p1 (free first).\n");
    printf("It's %p -> %p.\n", (size_t*)((size_t)p2 - 0x10), (size_t*)((size_t)p1 - 0x10));
    printf("\n");
    
    size_t* p3 = malloc(0x20);
    printf("Now we malloc a chunk again, and it's address is %p.\n", (size_t*)((size_t)p3 - 0x10));
    printf("Which proves that fastbin is Last In, Frist Out.(LIFO)\n");
    printf("And the fd pointer of fastbin points to the chunk that is free before.\n");
    return 0;
}
```

其输出为：

```
$ ./test 
The addr of p1 is 0x555555559000.
The addr of p2 is 0x555555559030.

We free p1 first and free p2 later.
And p1->fd = (nil), while p1->bk = (nil).
While p2->fd = 0x555555559000, p2->bk = (nil).
So we can see that the link of fastbin is p2 (free later) -> p1 (free first).
It's 0x555555559030 -> 0x555555559000.

Now we malloc a chunk again, and it's address is 0x555555559030.
Which proves that fastbin is Last In, Frist Out.(LIFO)
And the fd pointer of fastbin points to the chunk that is free before.
```

这证明：

- `fastbin`是`LIFO`(`Last in, Fist out`)，即最后释放的`chunk`会最先被申请回去。这种分配方式满足操作系统上的时间局部性。
- `fastbin`中只存在`fd`指针，不存在`bk`指针，**后释放**的`chunk`的`fd`指针**指向先释放**的`chunk`。
- 从链表头添加，从链表头取出。

即：

![image-20231225163717312](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202312251637367.png)

# unsortedbin

通过以下代码在`glibc2.23`进行测试：

```c
// 这里是unsortedbin的测试
// Notice, a -> b means that a's fd pointer points to b

#include <stdio.h>
#include <stdlib.h>


int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    size_t* p1 = malloc(0xf0);
    malloc(0x20);
    size_t* p2 = malloc(0xf0);
    malloc(0x20); 
    printf("The addr of p1 is %p.\n", (size_t*)((size_t)p1 - 0x10));
    printf("The addr of p2 is %p.\n", (size_t*)((size_t)p2 - 0x10));
    printf("\n");

    free(p1);
    printf("Now we free p1, and it's fd and bk are %p and %p.\n", (size_t*)p1[0], (size_t*)p1[1]);
    printf("\n");

    free(p2);
    printf("Now we free p2.\n");
    printf("And p1->fd = %p, while p1->bk = %p.\n", (size_t*)p1[0], (size_t*)p1[1]);
    printf("While p2->fd = %p, p2->bk = %p.\n", (size_t*)p2[0], (size_t*)p2[1]);
    printf("\n");

    printf("FD: p2 (free later) -> p1 (free first) -> main_arena + x\n");
    printf("BK: p1 (free first) -> p2 (free later) -> main_arena + x\n");
    printf("FD: %p -> %p -> %p.\n", (size_t*)((size_t)p2 - 0x10), (size_t*)((size_t)p1 - 0x10), (size_t*)(*p1));
    printf("BK: %p -> %p -> %p.\n", (size_t*)((size_t)p1 - 0x10), (size_t*)((size_t)p2 - 0x10), (size_t*)(p2[1]));
    printf("\n");

    size_t* p3 = malloc(0xf0);
    printf("Now we malloc a chunk again, and it's address is %p.\n", (size_t*)((size_t)p3 - 0x10));
    printf("Which proves the order of Unsortedbin is FIFO(First In, First Out).\n");
    printf("The fd pointer points to the chunk freed before it.\n");
    printf("The bk pointer points to the chunk freed after it.\n");
    return 0;
}
```

其输出为：

```
$ ./test
The addr of p1 is 0x555555559000.
The addr of p2 is 0x555555559130.

Now we free p1, and it's fd and bk are 0x7ffff7dd1b78 and 0x7ffff7dd1b78.

Now we free p2.
And p1->fd = 0x7ffff7dd1b78, while p1->bk = 0x555555559130.
While p2->fd = 0x555555559000, p2->bk = 0x7ffff7dd1b78.

FD: p2 (free later) -> p1 (free first) -> main_arena + x
BK: p1 (free first) -> p2 (free later) -> main_arena + x
FD: 0x555555559130 -> 0x555555559000 -> 0x7ffff7dd1b78.
BK: 0x555555559000 -> 0x555555559130 -> 0x7ffff7dd1b78.

Now we malloc a chunk again, and it's address is 0x555555559000.
Which proves the order of Unsortedbin is FIFO(First In, First Out).
The fd pointer points to the chunk freed before it.
The bk pointer points to the chunk freed after it.
```

这说明：

- `unsortedbin`是遵循`FIFO`(`First in, First out`)的，即先释放的会先被申请出去。
- `unsortedbin`的`fd`指针指向比他先释放的`chunk`，而`bk`指针指向比它后释放的`chunk`。
- `fd`和`bk`指针都会指向`main_arena`，因此最先释放的`chunk`的`fd`指针将会指向`main_arena`，而最后释放的`chunk`的`bk`指针会指向`main_arena`。
- 从链表头插入，从链表尾取出

即：

![image-20231225170537440](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202312251705501.png)

# smallbin

通过以下代码在`glibc2.23`进行测试：

```c
// 这里是smallbin的测试
// Notice, a -> b means that a's fd pointer points to b

#include <stdio.h>
#include <stdlib.h>


int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    size_t* p1 = malloc(0xf0);
    malloc(0x20);
    size_t* p2 = malloc(0xf0);
    malloc(0x20); 
    printf("The addr of p1 is %p.\n", (size_t*)((size_t)p1 - 0x10));
    printf("The addr of p2 is %p.\n", (size_t*)((size_t)p2 - 0x10));
    printf("\n");

    free(p1);
    malloc(0x100);
    printf("Now we free p1 and malloc a chunk of size 0x100, which drives p1 to smallbin.\n");

    free(p2);
    malloc(0x100);
    printf("And then we free p2 and malloc a chunk of size 0x100, drives p2 to the smallbin.\n");

    printf("Now p1->fd = %p, while p1->bk = %p.\n", (size_t*)p1[0], (size_t*)p1[1]);
    printf("While p2->fd = %p, p2->bk = %p.\n", (size_t*)p2[0], (size_t*)p2[1]);
    printf("\n");

    printf("FD: p2 (free later) -> p1 (free first) -> main_arena + x\n");
    printf("BK: p1 (free first) -> p2 (free later) -> main_arena + x\n");
    printf("FD: %p -> %p -> %p.\n", (size_t*)((size_t)p2 - 0x10), (size_t*)((size_t)p1 - 0x10), (size_t*)(*p1));
    printf("BK: %p -> %p -> %p.\n", (size_t*)((size_t)p1 - 0x10), (size_t*)((size_t)p2 - 0x10), (size_t*)(p2[1]));
    printf("\n");

    size_t* p3 = malloc(0xf0);
    printf("Now we malloc a chunk again, and it's address is %p.\n", (size_t*)((size_t)p3 - 0x10));
    printf("Which proves the order of Smallbin is FIFO(First In, First Out).\n");
    printf("The fd pointer points to the chunk freed before it.\n");
    printf("The bk pointer points to the chunk freed after it.\n");
    return 0;
}
```

其输出为：

```
$ ./smallbin 
The addr of p1 is 0x555555559000.
The addr of p2 is 0x555555559130.

Now we free p1 and malloc a chunk of size 0x100, which drives p1 to smallbin.
And then we free p2 and malloc a chunk of size 0x100, drives p2 to the smallbin.
Now p1->fd = 0x7ffff7dd1c68, while p1->bk = 0x555555559130.
While p2->fd = 0x555555559000, p2->bk = 0x7ffff7dd1c68.

FD: p2 (free later) -> p1 (free first) -> main_arena + x
BK: p1 (free first) -> p2 (free later) -> main_arena + x
FD: 0x555555559130 -> 0x555555559000 -> 0x7ffff7dd1c68.
BK: 0x555555559000 -> 0x555555559130 -> 0x7ffff7dd1c68.

Now we malloc a chunk again, and it's address is 0x555555559000.
Which proves the order of Smallbin is FIFO(First In, First Out).
The fd pointer points to the chunk freed before it.
The bk pointer points to the chunk freed after it.
```

这说明：

- 其和`unsortedbin`的管理机制基本一样，同样为`FIFO`，只是`unsortedbin`只有一条链，而`smallbin`根据大小不同，有很多链。
- `smallbin`的`fd`指针指向比他先释放的`chunk`，而`bk`指针指向比它后释放的`chunk`。
- `fd`和`bk`指针都会指向`main_arena`，因此最先释放的`chunk`的`fd`指针将会指向`main_arena`，而最后释放的`chunk`的`bk`指针会指向`main_arena`。
- 从链表头插入，从链表尾取出

即：

![image-20231225173018218](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202312251730278.png)

# largebin

`largebin`的链表结构比较复杂，若仍然使用代码的形式给读者展示，比较晦涩。这部分内容可以查看[Rolan师傅的文章](https://bbs.kanxue.com/thread-262424.htm)进行参考。这里放一张以前画的`largebin`的结构图。

其中：

- 每一个`largebin`中存放的`chunk`大小是不相同的，一共有`63`个`largebin`。在这`63`个`largebin`中，前`32`个`largebin`的最大`chunk`和最小的`chunk`之差为`64bytes(0x40)`。例如第一个`largebin`的大小为`512bytes-568bytes`（`32`位），而第二个`largebin`的大小就为`576bytes-632bytes`。
- 每一个`largebin`中的`chunk`按照大小顺序从大到小排序。
- 若大小相同，则会按照释放顺序排序：最先释放的`chunk`拥有`fd_nextsize`和`bk_nextsize`指针，之后的`chunk`的这两个指针的值都为`0`。若将这个`chunk`称为小堆头，那么后面释放的`chunk`都会被插入到小堆头的后面。因此，对于同一个大小的`large chunk`，最先释放的在最上面，除此之外越先释放在越后面。

- `fd_nextsize`和`bk_nextsize`是指向当前`bin`的下一个大小的`chunk`。`fd_nextsize`指向比自己小的，而`bk_nextsize`指向比自己大的。

![image-20230731190106590](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202312251728311.png)

# tcache

通过以下代码在`glibc2.27`下完成测试：

```c
// 这里是tcache的测试
// Notice, a -> b means that a's fd pointer points to b

#include <stdio.h>
#include <stdlib.h>


int main(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    size_t* p1 = malloc(0x20);
    size_t* p2 = malloc(0x20);
    printf("The addr of p1 is %p.\n", (size_t*)((size_t)p1 - 0x10));
    printf("The addr of p2 is %p.\n", (size_t*)((size_t)p2 - 0x10));
    printf("\n");

    free(p1);
    free(p2);
    printf("We free p1 first and free p2 later.\n");
    printf("And p1->fd = %p, while p1->bk = %p.\n", (size_t*)p1[0], (size_t*)p1[1]);
    printf("While p2->fd = %p, p2->bk = %p.\n", (size_t*)(p2[0] - 0x10), (size_t*)p2[1]);
    printf("So we can see that the link of tcache is p2 (free later) -> p1 (free first).\n");
    printf("It's %p -> %p.\n", (size_t*)((size_t)p2 - 0x10), (size_t*)((size_t)p1 - 0x10));
    printf("\n");
    
    size_t* p3 = malloc(0x20);
    printf("Now we malloc a chunk again, and it's address is %p.\n", (size_t*)((size_t)p3 - 0x10));
    printf("Which proves that tcache is Last In, Frist Out.(LIFO)\n");
    printf("And the fd pointer of tcache points to the chunk that is free before.\n");
    return 0;
}
```

其结果如下：

（根据`glibc`版本的不同，其`bk`指针有差异，指示的是其安全规则）

```
$ ./tcache 
The addr of p1 is 0x555555559250.
The addr of p2 is 0x555555559280.

We free p1 first and free p2 later.
And p1->fd = (nil), while p1->bk = (nil).
While p2->fd = 0x555555559250, p2->bk = (nil).
So we can see that the link of tcache is p2 (free later) -> p1 (free first).
It's 0x555555559280 -> 0x555555559250.

Now we malloc a chunk again, and it's address is 0x555555559280.
Which proves that tcache is Last In, Frist Out.(LIFO)
And the fd pointer of tcache points to the chunk that is free before.
```

从上面可以看到：

- `tcache`的管理机制和`fastbin`的管理机制很像，区别在于`tcache`还包括`smallbin`大小，且其`bk`指针用于安全校验。
- `tcache`是`LIFO`(`Last in, Fist out`)，即最后释放的`chunk`会最先被申请回去。这种分配方式满足操作系统上的时间局部性。
- `tcache`同样也是**后释放**的`chunk`的`fd`指针**指向先释放**的`chunk`。
- 从链表头添加，从链表头取出。

即：（是的，我只需要更改`fastbin`为`tcache`即可。）

![image-20231225185850655](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202312251858721.png)

# 参考文献

[unsortbin attack分析与总结-二进制漏洞-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-262423.htm)

[Largebin attack总结-二进制漏洞-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-262424.htm)