---
layout: post
title: IO_FILE初探
category: system
date: 2023-11-09 20:39:36
---
以house of orange为首的IO_FILE利用
<!-- more -->
[toc]

# IO_FILE

## IO_FILE leak

将`_IO_2_1_stdout_`结构体中的`_flags`变量覆盖为`0xfbad1800`，然后将结构体中的`_IO_write_base`和`_IO_write_ptr`分别指向要输出的开始处的地址和结束处的地址即可完成输出。

## House of orange

`IO_FILE`相关的知识一直不太了解，因此就以`house of orange`的利用来认真学习一下。

一句话描述该漏洞：将`top chunk`置入`unsortedbin`并打`unsortedbin attack`对`_IO_list_all`写入`main_arena+88`，将该`chunk`置入`smallbin`，使其`_IO_list_all`的`_chain`刚好指向该`chunk`，便可劫持`vtable`来触发`FSOP`。

先看一下总体流程：

- 通过漏洞修改`top chunk`的`size`，使得系统以`brk`的方式来扩展空间，此时`top chunk`会被置入到`unsorted bin`中去
- 利用`unsortedbin attack`，将`_IO_list_all`指针的值改写为`unsortedbin`的头`chunk`地址，即`main_arena+88`
- 通过再次修改该`unsorted chunk`的`size`为`0x61`，使其被置入`smallbin[4]`中，如此以来`main_arena+88+0x68`（也就是`_IO_list_all`的`_chain`）将指向这个`chunk`
- 再次`malloc`的时候由于`unsortedbin`中指针被修改，因此会触发调用链`malloc() -> malloc_printerr() -> __libc_message() -> abort() -> fflush() -> _IO_flush_all_lockp() -> _IO_new_file_overflow()`。而最终调用的函数实际上是调用了`_IO_FILE_plus.vtable`中的`_IO_OVERFLOW`函数，函数原型为`_IO_OVERFLOW(fp, EOF)`。通过上面的`chunk`覆盖函数指针，将`_IO_FILE`结构体0字节偏移处的`fp`写为`/bin/xh`，即可获得`shell`。

以上就是`House of orange`的简要流程，整个流程在我第一次见的时候是相当震撼的，因此只能慢慢嚼碎再咽下去。

### 0x00: 将top chunk置入unsortedbin

需要利用的漏洞：控制`top chunk`的`size`

当程序调用`malloc`时，系统会以此检查`fastbin`、`small bins`、`unsorted bin`、`large bins`是否满足分配要求。若都不满足，那么`_init_malloc`函数会试图使用`top chunk`。若`top_chunk`也不满足分配要求，那么`ptmalloc`将会执行`sysmalloc`来申请更多的空间。此时有两种分配方式，一种是`brk`，而另一种是`mmap`。我们需要让`sysmalloc`以`brk`的方式扩展内存，因为`brk`方式扩展内存后，会将原有的`top chunk`置入到`unsorted bin`中。到这里，我们已经明白如何让`top chunk`被置入到`unsortedbin`：一是`top chunk`不满足分配要求，二是让系统以`brk`方式扩展内存。要满足这些条件，我们要使得：

- 伪造的`top chunk`的`size`对齐到内存页（自己计算，要使得其`top chunk addr+size`对齐`0x1000`）
- `size`大于`MINSIZE(0X10)`
- `top chunk size`小于之后申请的`chunk size + MINSIZE`（使其使用`brk`扩展）
- `top chunk size`的`prev_inuse`位为1
- 申请的内存小于`mmap`阈值，即`0x20000`

满足上述条件后我们即可以在`malloc`一个`chunk`的时候将`top chunk`置入到`unsorted bin`中，这段代码如下：

```c
char* p1 = malloc(0x400-0x10); // 先申请一个大小为0x400的chunk，它的下一个chunk即为top chunk

size_t* top = (size_t *) ( (char *) p1 + 0x400 - 0x10); // 获得top chunk，也就是p1的用户地址加上0x400-0x10
top[1] = 0xc01; // 修改top chunk的size为0xc01，使其能够对齐0x1000，且小于接下来申请的一个不大于0x20000的请求

char* p2 = malloc(0x1000); // 申请一个大于top chunk size的内存空间，将会使用brk申请空间，同时使得top chunk被置入unsortedbin
```

运行这段代码后，效果如下，其中第一个`chunk`是申请的大小为`0x400`的`chunk`，第二个是已经位于`unsorted bin`中的以前的`top chunk`，另外两个`chunk`是在这个过程中产生的`chunk`，暂时不清楚原因。

![image-20231109151427847](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20231109151427847.png)

`bins`中如下：

![image-20231109151602936](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20231109151602936.png)

### 0X01: 使用Unsortedbin attack改写_IO_list_all指针

需要利用的漏洞：`unsortedbin attack`，需要你能够控制刚刚的`top chunk`的`bk`指针

由于最开始的`top chunk`已经位于`unsortedbin`中，我们可由其`fd`和`bk`泄露出`libc`，也就可以获得`libc`具有固定偏移的`io_list_all`的地址。我们将`top chunk`的`bk`写为`_IO_list_all-0x10`，在下一次`malloc`时便将会触发`unsortedbin attack`，往`_IO_list_all`中写入`main_arena+88`。我们知道`_IO_list_all`本来是指向`_IO_2_1_stderr_`的，即指向一个`_IO_FILE_plus`结构，那么`main_arena+88`地址开始处也会被当做一个`_IO_FILE_plus`结构体。然而，此处空间我们并不是可控的，该怎么办呢？先不管，我们先看这一段的代码：

```c
// 由于top chunk位于unsortedbin，我们知道此时chunk的fd和bk都会指向libc固定偏移main_arena+88
io_list_all = top[2] + 0x9a8; // 由此也可以获得libc固定偏移的io_list_all的地址

top[3] = io_list_all - 0x10; // 将top chunk的bk写为io_list_all-0x10，触发unsortedbin attack
```

### 0x02: 将top chunk置入smallbin使得_chain指向该chunk

 需要利用的漏洞：仍然是控制`top chunk`即可

根据上面的问题，很显然，我们需要能够控制`_IO_FILE_plus`结构体的空间才可以继续。目前我们已经使得`_IO_list_all`指向了`main_arena+88`，那么`main_arena+88`处的地址空间将会被当做一个`IO_FILE_plus`结构体，而该结构体里面含有一个`_chain`域即`_IO_FILE_plus.file._chain`，它指向下一个`IO_FILE_plus`结构。若我们能够控制该`_chain`指向一个我们可以控制的`chunk`，这样一来当前的`IO_FILE_plus`指向的下一个`IO_FILE_plus`就完全受我们控制了。此时问题就回到，如何控制该`_chain`？`_chain`在`_IO_FILE_plus`结构体中的偏移为`0x68`，即`main_arena+88+0x68`，即`main_arena+192`。实际上，`main_arena`附近的内存空间相对复杂，笔者通过`mallopt(M_MXFAST,0)`的方式禁用`fastbin`，得到如下结果：

![image-20231109183045439](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20231109183045439.png)

从图上可以看到，`main_arena+192`指向的区域是大小为`0x60`的`smallbin`中的最后一个`chunk`，也就是`smallbin(0x60)->bk`。那么，接下来我们就将`top chunk`挂入大小为`0x60`的`smallbin`，挂入后`_IO_FILE_plus`的`_chain`就将指向这个`top chunk`，也就是`top chunk`会成为下一个`_IO_FILE_plus`。此外，最终我们执行的代码是`_IO_OVERFLOW(fp, EOF)`，而其中的`fp`实际上也就是`top chunk`的地址，因此若我们在`top chunk`的地址处写下`/bin/sh\x00`，那么相当于执行了`_IO_OVERFLOW('/bin/sh\x00')`，覆盖函数指针后就是`system('/bin/sh\x00')`。

这部分的代码如下：

```c
memcpy( ( char *) top, "/bin/sh\x00", 8); // 最终执行的_IO_OVERFLOW(fp, EOF)中的fp实际上是_IO_FILE_plus结构体的地址，对应top chunk的地址
// 因此直接往top chunk地址处写/bin/sh\x00

top[1] = 0x61; // 更改top chunk的size为0x61，在触发unsortedbin attack后，还会将其挂入大小为0x60的smallbin
// 这是因为main_arena + 192是指向大小为0x60的smallbin的最后一个chunk的，如此以来第一个_IO_FILE_plus的_chain指向top chunk
```

### 0x03: 满足利用条件，触发FSOP调用链获得shell

需要利用的漏洞：控制`top chunk`即可

有的读者可能注意到我们将`top chunk`置入`unsortedbin`后，一直没有调用`malloc`来触发`unsortedbin attack`，也没有将`top chunk`置入`small bin`中。实际上在最后调用`malloc`时，这个申请内存的操作会先后触发`unsortedbin attack`，然后将其置入`small bin`；并且由于`unsortedbin attack`时已经破坏了其链表结构，因此会触发`malloc() -> malloc_printerr() -> __libc_message() -> abort() -> fflush() -> _IO_flush_all_lockp() -> _IO_new_file_overflow()`函数的调用链。因此，在`malloc`之前，我们需要检查剩下的安全机制，来保证我们的攻击可以成功。在`_IO_flush_all_lockp()`函数中，要满足要求`fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base`。因此，可以设置如下条件：

- `fp->_mode=0`，其中`_mode`对于起始位置的偏移是`0xc0`
- `fp->_IO_write_base = (char*)2;`
- `fp->_IO_wirte_ptr = (char*)3;`

满足以上条件后，我们便可以覆盖掉`_IO_new_file_overflow`函数的函数指针了。`vtable`中的函数如下：

```c
void * funcs[] = {
   1 NULL, // "extra word"
   2 NULL, // DUMMY
   3 exit, // finish
   4 NULL, // overflow
   5 NULL, // underflow
   6 NULL, // uflow
   7 NULL, // pbackfail
   8 NULL, // xsputn  #printf
   9 NULL, // xsgetn
   10 NULL, // seekoff
   11 NULL, // seekpos
   12 NULL, // setbuf
   13 NULL, // sync
   14 NULL, // doallocate
   15 NULL, // read
   16 NULL, // write
   17 NULL, // seek
   18 pwn,  // close
   19 NULL, // stat
   20 NULL, // showmanyc
   21 NULL, // imbue
};
```

这里我们需要覆盖`overflow`函数，也就是`vtable[3]`。而另外`vtable`相对于`_IO_FILE_plus`起始地址处的偏移是`0xd8`。`top chunk`的`IO_FILE_plus`结构体中的`vtable`是可以任意构造值的，我们将其设置到`top chunk`处的任意地方即可，只需要注意`fake_vtable->overflow`处不要被占用。这部分代码如下：

```c
// 将top chunk解释为一个FILE结构体
FILE *fp = (FILE *) top;
// 满足函数调用链中的_IO_flush_all_lockp()函数的要求
fp->_mode = 0; // top+0xc0
fp->_IO_write_base = (char *) 2; // top+0x20
fp->_IO_write_ptr = (char *) 3; // top+0x28

size_t *jump_table = &top[20]; // 我们将top chunk的vtable指向自身的某个地方，随意
jump_table[3] = (size_t) &winner; // top chunk的vtable的第[3]个函数也就是overflow，将其函数指针设置为winner
*(size_t *) ((size_t) fp + sizeof(FILE)) = (size_t) jump_table; // top chunk的vtable指向刚刚设置的fake vtable

malloc(10); // 最终进行一次malloc，来完成unsortedbin attack开始的所有流程
```

其中`winner`函数就是咱们的后门函数。

```c
int winner(char *ptr)
{ 
    system(ptr); // 按照上面的步骤会传入一个/bin/sh
    syscall(SYS_exit, 0);
    return 0;
}
```

参考链接：

[ha1vik师傅](https://blog.csdn.net/seaaseesa/article/details/104314949)

[House_of_orange学习小结](https://www.cnblogs.com/L0g4n-blog/p/14217309.html)

[借助gdb调试glibc代码学习House of Orange - 简书 (jianshu.com)](https://www.jianshu.com/p/57a5c9a492aa?utm_campaign=maleskine&utm_content=note&utm_medium=seo_notes&utm_source=recommendation)