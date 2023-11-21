---
layout: post
title: CTF-PWN做题的思路小记
category: system/tricks
date: 2023-9-20 12:00:00
---
栈溢出基础知识点
<!-- more -->

[toc]


以下内容都是做题的时候遇到的一些知识点，但是由于时间原因，不可能详细记录每道题的详细解法，因此将这些题目的`trick`进行一个简要的总结。

# exec 1>&0

`stdin` 是`0`

`stdout` 是`1`

`stderr` 是`2`

程序使用`close(1)`关闭了输出流，那么可以使用`exec 1>&0`将其重定向到`stdin`，因为这三个都是指向终端的，可以复用。

# 存在格式化字符串漏洞，但是只能利用一次

程序在结束的时候会遍历`fini_array`里面的函数进行执行，将其劫持为`main`函数将会重新执行一次`main`函数。

# 存在栈溢出，但是只能覆盖返回地址，无法构建ROP链

栈迁移

# off-by-one利用

- 上一个`chunk`末尾为`0x8`这种类型，那么通过`off-by-one`可以任意修改下一个`chunk`的大小，将其改大，并将其释放，再申请，即可造成`chunk`的重叠，即被改大的这个`chunk`和它之后的`chunk`重叠，那么可以通过修改这个`chunk`来修改被重叠的`chunk`。同时也可以将重叠的`unsorted chunk`释放，打印被改大的`chunk`，即可泄露`libc`。

# fastbin attack的0x7f

很多时候`fastbin attack`为了绕开`memory corruption (fast)`，需要使用`malloc_hook`或者`free_hook`附近的`0x7f`来构造一个`fake chunk`。实际上，`size`为`0x7f`的`chunk`去掉`N M P`位，也就是`0x78`，由于最后`0x8`是在下一个`chunk`的`prev_size`字段，那么实际上`0x7f`的`chunk`是对应`size`为`0x70`的普通`chunk`，也就是通过`malloc(0x60)`得到的。

# one_gadget环境变量修改

`one_gadget`并不是直接就生效的，而是在一定条件下才生效，如下图所示，`constraints`部分就是必须满足的条件。

![image-20231010203017288](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202310102030415.png)

从上面可以看到，若要使用第一个`gadgets`，那么要满足`rax=0`；若要使用第二个`gadgets`，那么要满足`[rsp+0x30]=0`。然而，多数情况下我们是无法这么轻易地操纵这些寄存器的值的，但是我们可以借助`realloc_hook`来轻松完成这个操作。

首先，在`libc`中，`__realloc_hook`和`__malloc_hook`是相邻的，这意味着在使用`fastbin attack`的`0x7f`的`fake_chunk`来打`__malloc_hook`的时候，可以很顺便地打`__realloc_hook`（`__realloc_hook`在`__malloc_hook`前面一个）。`__realloc_hook`和`__malloc_hook`类似，程序在调用`realloc`的时候，同样会检查`__realloc_hook`，若`__realloc_hook`里面有值，会跳转到`__realloc_hook`里面的地址执行。但不同的是，`realloc`函数在跳转到`__realloc_hook`之前，还有一系列的`push`操作，如图所示：

![2](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202310102036583.png)

上图是`libc`里面的`realloc`函数，可以看到`0x846d4`处会跳转到`realloc_hook`，而在这之前有一系列的`pop`操作。

那么现在考虑：我们将`__malloc_hook`写为`realloc`函数的值，并将`__realloc_hook`写为`one_gadget`。

那么函数调用链如下：

```c
malloc => __malloc_hook => realloc => 一系列的push操作 => __realloc_hook => one_gadget
```

我们将断点打到`one_gadget`开始的地方（选取的`gagdet`的满足条件是`[rsp + 0x30]=0`），即：

![image-20231010204021779](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202310102040851.png)

此时`rsp`的值为`0x7ffeeeb9a588`，那么查看`$rsp + 0x30`有：

![image-20231010204216088](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202310102042125.png)

发现`[$rsp + 0x30]`不为0，但`[$rsp + 0x38]`是为0的。

由于在调用`__realloc_hook`之前，进行了大量的`push`操作，而`push`操作会减小`rsp`的值。因此，若我们少一个`push`操作，就会使得`rsp`的值加8，也就使得`[$rsp + 0x38]=0`了。

翻到上面再看看`realloc`函数，若我们的`__malloc_hook`不跳转到`realloc`函数的开头，而是偏移两个字节的地方，就少了一个`push`操作了，这样一来整个流程就可以打通，也就满足了`one_gadget`的条件了！

最后，记录一下`realloc`函数依次增加多少个偏移的字节可以减少一个`push`操作：

```tex
2,4,6,12,13,20
```

# exit_hook

实际上这并不是一个真正意义上的`hook`，因为它实际上是劫持了一个指针而已。

程序在正常执行完毕或者调用`exit`函数的时候，会经过一个程序调用链：

```c
exit -> __run_exit_handlers -> _dl_fini
```

而`_dl_fini`部分的源码如下：

```c
#ifdef SHARED
   int do_audit = 0;
  again:
 #endif
   for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
     {
       /* Protect against concurrent loads and unloads.  */
       __rtld_lock_lock_recursive (GL(dl_load_lock));
 
       unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
       /* No need to do anything for empty namespaces or those used for
      auditing DSOs.  */
       if (nloaded == 0
 #ifdef SHARED
       || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
 #endif
       )
     __rtld_lock_unlock_recursive (GL(dl_load_lock));
```

可以看到其调用了`__rtld_lock_lock_recursive`函数和`__rtld_lock_unlock_recursive`函数。

实际上，调用这两个函数位于`_rtld_global`结构体，如图所示：

![image-20231022140653713](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20231022140653713.png)

![image-20231022140719260](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20231022140719260.png)

在结构体中可以看到，实际上`_dl_rtld_lock_recursive`存放了`trld_lock_default_lock_recursive`函数指针，`unlock`也是如此。若我们劫持该指针为`one_gadget`，那么调用`exit`函数时无论如何也会调用到`one_gadget`了。

使用如下方式查看该`_dl_rtld_lock_recursive`的地址：

`p &_rtld_global._dl_rtld_lock_recursive`

![image-20231022141016950](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20231022141016950.png)

即，我们只需要覆盖该地址处的值为`one_gadget`即可。该地址和`libc`的偏移是固定的，可以直接算出，也有的师傅是通过以下三行代码来完整算出的：

```c
ld_base = libc_base + 0x1f4000
_rtld_global = ld_base + ld.sym['_rtld_global'] // _rtld_global实际上是属于ld而不是Libc的
_dl_rtld_lock_recursive = _rtld_global + 0xf08
_dl_rtld_unlock_recursive = _rtld_global + 0xf10
```

# off by null制作三明治结构

`off-by-null`，本部分是在做西南赛区国赛2019年的`pwn2`总结的，该题目环境是`ubuntu18, glibc2.27`。

先大致说明一下流程，再详细讲。首先申请三个`chunk012`，`chunk0`为`large chunk`，`chunk1`为`small chunk`，`chunk2`为`large chunk`。释放`chunk0`置入`unsortedbin`，释放`chunk1`再申请回来（申请末尾为8的，同时写`chunk2`的`prev_size`为`chunk0`+`chunk1`），此时触发`off by null`让`chunk2`认为前一个`chunk`为`free`状态。释放`chunk2`，这会导致`chunk2`前向合并，将三个`chunk`合并为一个`chunk`。申请一个大小为`chunk0`大小的`chunk`，会切割这个大`chunk`为以前的`chunk0`和`chunk1+chunk2`，由于`chunk1`其实并没有被释放而是被合并进来的，因此此时我们可以打印`chunk1`，即可泄露`libc`地址，并且再次申请`chunk1`大小的`chunk`，会将`chunk1`切割下来，此时有两个指针都指向`chunk1`，接下来可以打`double free`之类的。

画一个图：

![image-20231107164708077](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311071647194.png)

如上图，构造如上的形式即`chunk0`在`unsortedbin`，`chunk1`来`off-by-null`掉`chunk2`的`size`末尾使得`chunk2`认为`prev`是`free`的，同时将`chunk2`的`prev_size`写成`chunk0+chunk1`。

此时释放`chunk2`，会将三个`chunk`合并成一个并置入`unsortedbin`。切割下来`chunk0`，打印`chunk1`即可泄露`libc`地址（`chunk1`虽然合并在里面，但是它并没有被释放）。再次切割`chunk1`下来，就有两个指向`chunk1`的指针了。

# glibc2.23下通过劫持vtable来getshell

程序调用`exit`时，会遍历`_IO_list_all`，并调用`_IO_2_1_stdout_`下的`vtable`中的`setbuf`函数。而在`glibc2.23`下是没有`vtable`的检测的，因此可以把假的`stdout`的虚表构造到`stderr_vtable-0x58`上，由此`stdout`的虚表的偏移`0x58(setbuf的偏移)`就是`stderr`的虚表位置。

# 通过largebin泄露堆地址

总是忘了在`largebin`中只有一个`chunk`的时候它的`fd_nextsize`和`bk_nextsize`会指向自身。特此记录，可以通过`largebin`的`bk_nextsize`和`fd_nextsize`来泄露堆地址。
