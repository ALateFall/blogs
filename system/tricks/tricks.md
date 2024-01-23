---
layout: post
title: CTF-PWN做题的思路小记
category: system/tricks
date: 2023-12-28 12:00:00
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

程序在结束的时候会遍历`fini_array`里面的函数进行执行，将其劫持为`main`函数将会重新执行一次`main`函数。要无限执行，请看下一条。

# fini_array劫持无限执行main函数

若只覆盖`array[1]`为`main_addr`，那么只会执行一次`main`函数便会执行下一个`array`中的函数。

要无限执行某个函数，需要使用这个方式：

```tex
array[0]覆盖为__libc_csu_fini
array[1]覆盖为另一地址addrA

其中，start函数中的__libc_start_main函数的第一个参数为main函数地址
第四个参数为__libc_csu_init函数，在main函数开始前执行
第五个参数为__libc_csu_fini函数，在main函数结束时执行
```

这是因为默认情况下，`fini`数组中函数中存放的函数为：

```c
array[0]:__do_global_dtors_aux
array[1]:fini
```

而在`__libc_csu_fini`函数中会调用这两个函数，其执行顺序为`array[1] -> array[0]`。

修改后，其执行顺序将会变为：

```c
main -> __libc_csu_fini -> addrA -> __libc_csu_fini -> addrA -> __libc_csu_fini ....
```

从而达到无限执行的目的。

终止条件即只要当`array[0]`不为`__libc_csu_fini`即可。

## 通过fini_array栈迁移来实现ROP

通过上面的无限循环方法执行某个函数时，若该函数可以进行一个任意地址写，那么我们便可以利用上述方式在`array[2]`处布置`rop`链。

布置完成后，布置`fini_array`为如下形式：

```c
fini_array + 0x00: leave_ret (gadget)
fini_array + 0x08: ret (gadget)
fini_array + 0x10: ROP chain
```

由于本身执行的函数是存放于`array[1]`的，因此执行完后会执行`array[0]`处的`leave_ret`的`gadget`，导致`rip`为`ret`，然后执行我们布置的`rop`链。

[参考文献](https://www.freebuf.com/articles/neopoints/226003.html)

# 存在栈溢出，但是只能覆盖返回地址，无法构建ROP链

栈迁移

# off-by-one利用

上一个`chunk`末尾为`0x8`这种类型，那么通过`off-by-one`可以任意修改下一个`chunk`的大小，将其改大，并将其释放，再申请，即可造成`chunk`的重叠，即被改大的这个`chunk`和它之后的`chunk`重叠，那么可以通过修改这个`chunk`来修改被重叠的`chunk`。同时也可以将重叠的`unsorted chunk`释放，打印被改大的`chunk`，即可泄露`libc`。

# fastbin attack的0x7f

很多时候`fastbin attack`为了绕开`memory corruption (fast)`，需要使用`malloc_hook`或者`free_hook`附近的`0x7f`来构造一个`fake chunk`。实际上，`size`为`0x7f`的`chunk`去掉`N M P`位，也就是`0x78`，由于最后`0x8`是在下一个`chunk`的`prev_size`字段，那么实际上`0x7f`的`chunk`是对应`size`为`0x70`的普通`chunk`，也就是通过`malloc(0x60)`得到的。

# one_gadget环境变量修改（realloc_hook调整栈帧）

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

# exit_hook(stdlib/exit.c)

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

即，我们只需要覆盖该地址处的值为`one_gadget`即可。需要注意，该`exit_hook`是`ld`的固定偏移，而不是关于`libc`的固定偏移。若能得知`libc`和`ld`的偏移，可以使用以下方式算出：

```c
ld_base = libc_base + 0x1f4000
_rtld_global = ld_base + ld.sym['_rtld_global'] // _rtld_global实际上是属于ld而不是Libc的
_dl_rtld_lock_recursive = _rtld_global + 0xf08
_dl_rtld_unlock_recursive = _rtld_global + 0xf10
```

此外，若无法打`one_gadget`，也可以打`system`，其参数为`_rtld_global.dl_load_lock.mutex`。推荐通过调试得出。

# exit_hook 2

在`exit.c`的源码中有这样一段：

```c
__run_exit_handlers (int status, struct exit_function_list **listp,
             bool run_list_atexit, bool run_dtors)
{
...
if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ()); // 可以打__libc_atexit
...
```

其中，只要`exit`正常被调用，`run_list_atexit`就为真，如下所示：

```c
void exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true); // 传的run_list_atexit为True
}
```

这个`exit_hook`最大的优点是其在`libc`而不是`ld`中，缺点是无法传参，只能看运气打`one_gadget`。

而`__libc_atexit`是`libc.so.6`中的一个段，要找它的偏移只需要在`ida`中查看该段(`segments`)的地址即可。

或者在`gdb`中使用如下方式查看：

```bash
p &__elf_set___libc_atexit_element__IO_cleanup__
```

**最大的问题是，这种`hook`在很多版本是不可写的，包括`glibc2.23`和`glibc2.27`等。在`glibc 2.31-0ubuntu9.2`中是可写的，而在`glibc 2.31-0ubuntu9.7`中又不可写。因此，这种`hook`并不能保证通用，在适当的时候可以偷家。**

# exit_hook 3

这是打`SCUCTF2023`新生赛学到的一个`exit_hook`。我们知道`fini_array`会在程序结束的时候被调用。而`fini_array`是在`elf`中的，因此在开启`PIE`时，一定会将`fini_array`来加上程序基地址来获取到`fini_array`的实际地址，从而执行里面的函数。因此，**在`libc`（其实是`ld`**）中必然存放有`code_base`，事实上也确实如此。在程序执行`fini_array`时，首先从`_rtld_global._dl_ns[0]._ns_loaded->l_addr`中来获取到`code_base`，也就是程序基地址，接下来再通过该基地址来加上`elf`中的`fini_array`的值，通过该指针来执行里面的函数。

因此，若对`_rtld_global._dl_ns[0]._ns_loaded->l_addr`进行覆盖，便可以起到`hook`的作用。只需要满足以下式子即可：

```c
_rtld_global._dl_ns[0]._ns_loaded->l_addr(修改后) + fini_array of elf == one_gadget (任意要执行的函数)
```

这里通常情况下可能不太好打`one_gadget`，也可以打`system`，调试一下观察`rdi`，也是一个可以打的值。

**获取该`hook`的地址：**

```c
p/x &_rtld_global._dl_ns[0]._ns_loaded->l_addr
p/x &(*_rtld_global._dl_ns[0]._ns_loaded).l_addr
```

最终，执行该`hook`的代码位于`elf/_dl_fini.c`中，代码如下：

```c
while (i-- > 0)
     ((fini_t) array[i]) ();
 }
```

其中汇编代码如下：

```assembly
 ► 0x7f99aefbaf5b <_dl_fini+507>    lea    r14, [rsi + rax*8]
   0x7f99aefbaf5f <_dl_fini+511>    test   edx, edx
   0x7f99aefbaf61 <_dl_fini+513>    je     _dl_fini+536                <_dl_fini+536>
 
   0x7f99aefbaf63 <_dl_fini+515>    nop    dword ptr [rax + rax]
   0x7f99aefbaf68 <_dl_fini+520>    call   qword ptr [r14]
```

可以看到`rax`是数组的`i`，在`i=0`时最后执行的即是`rsi`存放的值指向的值。

在调用这个函数时，该`rdi`也是可控的，在笔者本次调试为`_rtld_global+2312`

# 通过ld来获取程序基地址

```c
_rtld_global._dl_ns[0]._ns_loaded->l_addr // 因为_rtld是ld里面的
    // 低版本可能libc和ld有固定偏移，也可以尝试用一下
```

# off by null制作三明治结构

先一句话：大小大，通过小覆盖第二个大的`prev_inuse`，同时改第二个大的`prev size`，按照顺序释放两个大，此时三个合并，申请第一个大回来，此时可以通过小来获得`libc`，再次申请还可以获得重叠指针，进而使用`UAF`进行`fastbin attack`或者`unsortedin attack`等

`off-by-null`，本部分是在做西南赛区国赛2019年的`pwn2`总结的，该题目环境是`ubuntu18, glibc2.27`。

先大致说明一下流程，再详细讲。首先申请三个`chunk012`，`chunk0`为`large chunk`，`chunk1`为`small chunk`，`chunk2`为`large chunk`。释放`chunk0`置入`unsortedbin`，释放`chunk1`再申请回来（申请末尾为8的，同时写`chunk2`的`prev_size`为`chunk0`+`chunk1`），此时触发`off by null`让`chunk2`认为前一个`chunk`为`free`状态。释放`chunk2`，这会导致`chunk2`前向合并，将三个`chunk`合并为一个`chunk`。申请一个大小为`chunk0`大小的`chunk`，会切割这个大`chunk`为以前的`chunk0`和`chunk1+chunk2`，由于`chunk1`其实并没有被释放而是被合并进来的，因此此时我们可以打印`chunk1`，即可泄露`libc`地址，并且再次申请`chunk1`大小的`chunk`，会将`chunk1`切割下来，此时有两个指针都指向`chunk1`，接下来可以打`double free`之类的。

画一个图：

![image-20231107164708077](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311071647194.png)

如上图，构造如上的形式即`chunk0`在`unsortedbin`，`chunk1`来`off-by-null`掉`chunk2`的`size`末尾使得`chunk2`认为`prev`是`free`的，同时将`chunk2`的`prev_size`写成`chunk0+chunk1`。

此时释放`chunk2`，会将三个`chunk`合并成一个并置入`unsortedbin`。切割下来`chunk0`，打印`chunk1`即可泄露`libc`地址（`chunk1`虽然合并在里面，但是它并没有被释放）。再次切割`chunk1`下来，就有两个指向`chunk1`的指针了。

## 修复与破局

遗憾的是，从`glibc2.29`开始，合并时会检查合并的`size`和`prev_size`是否相同，传统的三明治也就没有办法使用了。

`off-by-null`可以通过在泄露了堆地址的情况下构造`unlink`。**注意：**

**本来`small bin`和`fastbin `正常情况下不会使用`unlink`。**

**但实际上，只是因为若是fastbin或者smallbin或者tcachebin，不会设置下一个chunk的prev_size和prev_inuse位罢了。**

**若我们设置了这两个位，同样可以对fastbin、smallbin、tcache进行unlink，从而构造重叠指针等。**

我们同样利用`off-by-null`和`unlink`来用三明治类似的思想进行重叠指针的构造。

构造如下图所示：

![image-20240113164151315](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202401131641391.png)

可能比较难以理解，我们详细、分步地解释：

注意，若我没有写对某个堆块`free`，那么它**没有**被`free`。此外，我们需要**提前泄露堆地址**，保证每个堆块地址可知。

我们有三个`chunk`，分别是`chunk1`、`chunk2`、`chunk3`，其中`chunk3`是个`large chunk`，大小为`0x500`，另外两个为大小为`0x30`的`chunk`。

- 我们通过`chunk2`写`chunk3`的`prev_size`等于`0x50`，并`off-by-null`将`chunk3`的`prev_in_use`置为`0`。
- 正常情况的`unlink`我们需要知道一个指向合并后堆块的指针，那么我们在`chunk2`中写一个合并后堆块的地址，也就是在`addr2`处写一个`addr1`。
- 在`chunk1`中构造`fake chunk`，`fake chunk`的`size`为`fake chunk + chunk2`的大小，这里为`0x51`
- `fake chunk`的`fd`为`addr2-0x18`，而`bk`为`addr2-0x10`，因为`addr2`存放的是它自己的地址，是个指向它自己的指针，绕过`unlink`安全检查。
- `free`掉`chunk3`，此时通过`chunk3`的`prev_size`来找到`fake chunk`，将`fake chunk`进行`unlink`，从而导致`chunk1-3`合并为一个。
- 还需要注意的就是，`glibc2.29`下，从`tcache`中获得`chunk`还会检查对应`tcache bin`的`count`是否大于`0`，大于`0`才可以申请。因此需要事先释放一个对应大小的`chunk`。
- 此时三个`chunk`会合并到`fake chunk`的位置而不是`chunk1`的位置。申请回一个大于`fake chunk + chunk1`大小的`chunk`，即可编辑`chunk2`，获得了`chunk2`的重叠指针。

# off-by-null制作三明治结构-revenge(calloc)

上面我们通过三明治结构可以构造重叠指针。若可以实现多次`off-by-null`，我们可以在构造重叠指针后，重新将三明治结构再制作一遍，然后三个`chunk`合并添加到`unsortedbin`时，可以直接再次`delete`小的，此时小的会添加到`fastbin`，然后申请第一个大的，就会使得小的`fd`和`bk`被写`main_arena+88`。这个在使用`calloc`申请的时候比较有用。

即：两次三明治结构会让保留有重叠指针的情况下让三个`chunk`再次合并为一个`unsortedbin chunk`。

# glibc2.23下通过劫持vtable来getshell

程序调用`exit`时，会遍历`_IO_list_all`，并调用`_IO_2_1_stdout_`下的`vtable`中的`setbuf`函数。而在`glibc2.23`下是没有`vtable`的检测的，因此可以把假的`stdout`的虚表构造到`stderr_vtable-0x58`上，由此`stdout`的虚表的偏移`0x58(setbuf的偏移)`就是`stderr`的虚表位置。

# 通过largebin泄露堆地址

总是忘了在`largebin`中只有一个`chunk`的时候它的`fd_nextsize`和`bk_nextsize`会指向自身。特此记录，可以通过`largebin`的`bk_nextsize`和`fd_nextsize`来泄露堆地址。

# 反调试

部分题目可能会使用子进程、`ptrace`的方式来防止调试，一旦调试就会出错。这种情况直接`patch`掉该部分即可，例如`call`反调试的函数可以直接跳转到下一条指令转而不执行`call`。

# canary绕过大全

## 泄露canary

打印栈上地址，覆盖`canary`末尾的`\x00`来直接打印

## 爆破canary

实际上`canary`在某些场景确实可以爆破，比如在多进程时，每个子进程的`canary`都是相同的。因此可以采用`one-by-one`的方式来对`canary`进行爆破

## 劫持__stack_chk_failed函数

`canary`校验失败时会跳转到`__stack_chk_failed`函数，因此可以劫持其`got`表来利用这一点

## 覆盖TLS中的canary

`canary`实际上存放在`TLS, Thread Local Storage`结构体里，校验`canary`时会通过`fs`结构体中的值和当前的`canary`进行比对，若不同则报错。因此可以通过覆盖掉`TLS`结构体中的值来绕过这个校验。这种绕过方式会根据子进程还是主进程而有略微的不同。

### 子进程

子进程中该结构体和栈都使用`mmap`映射到了同一个段中，且其地址比子进程的栈高。因此，可以直接通过栈溢出来覆盖掉`tls`结构体。即在子进程中若栈存在长度极大的溢出，可以覆盖`TLS`来覆盖`canary`。

### 主进程

主进程中`tls`结构体仍然位于映射段，但我们知道映射段实际上是基于`libc`地址的一个偏移。因此，要修改`tls`结构体基本上不能通过简单的栈溢出，而是可以考虑有`libc`地址的情况下打一个任意地址写，或者是`malloc`一个很大的内存，使其通过`mmap`分配到映射段前面，然后通过堆块溢出来修改`tls`结构体的值。

归根到底，子进程的`tls`结构体同样也在映射段上，只是因为子进程的栈也是映射出来的，因此可以直接栈溢出来修改。

### 覆盖方式

在`gdb`中，可以通过如下方式查看该结构体：

```
p/x *(tcbhead_t*)(pthread_self())
```

如下所示：

```
{
  tcb = 0x7ffff7d99700,
  dtv = 0x6032b0,
  self = 0x7ffff7d99700,
  multiple_threads = 0x1,
  gscope_flag = 0x0,
  sysinfo = 0x0,
  stack_guard = 0x1ba15d91dd80a100,
  pointer_guard = 0x6322b58812f391de,
  vgetcpu_cache = {0x0, 0x0},
  feature_1 = 0x0,
  __glibc_unused1 = 0x0,
  __private_tm = {0x0, 0x0, 0x0, 0x0},
  __private_ss = 0x0,
  ssp_base = 0x0,
  __glibc_unused2 = {{{
        i = {0x0, 0x0, 0x0, 0x0}
      }, {
      .........
       }},
  __padding = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
}
```

其中的`stack_guard`就是`canary`的值。可以在`gdb`中定位到这个`stack_guard`的地址，覆盖掉这个值。如：

```
pwndbg> p/x &(*(tcbhead_t*)(pthread_self())).stack_guard
$10 = 0x7ffff7d99728
```

如果上面的方法没有找到`canary`的存放地址（这是很有可能发生的），可以直接在`gdb`中寻找`tls`结构体中`canary`的地址。

在`gdb`中可以通过`canary`命令查看`canary`的值（有时候也无法得出结果，就在栈上观察一下）。随后，通过`gdb`搜索内存空间内还有何处有该值。

`32`位和`64`位下分别为：

```bash
search -4 0x73a2f100 # 假设后面那个值为canary的值
search -8 0x58e1f3982b6400 # 后面那个值为canary的值
```



# 栈溢出难以回到主函数重新执行一遍

部分栈溢出尤其是`ret2libc`等题目时，通常会先泄露`libc`，再重新回到`main`函数或者存在栈溢出的函数重新执行一遍以执行`ROP`。但有的情况下中间会经历太过复杂的操作，因此可以直接使用如下方式：

- 在`ROP`链中泄露`libc`，同时调用程序中的`read`函数读`gadgets`到`bss`段
- 布置`leave_ret`，使得栈迁移到`bss`段执行剩下的`gadgets`，避免重新执行整个流程

# shellcode题目

## 输入shellcode长度有限

- 可以考虑构造一个`read`和`ret`到`rsp`，再输入`shellcode`到`rsp`执行。栈不可执行的话也可输入`rop`链
- 要注意：`read`的`rdx`也就是长度不能太长
- `push`不能输入`64`位立即数
- 可以用`push`再`pop`的方式来将`rdx`里存放`rsp`的值而不是`mov rdx, rsp`，这是因为前者字节数更短
- 一个例子如下：

```assembly
# 可以完成一个read系统调用的rdx和rsi部分
push rsp
pop rsi
mov edx, esi
syscall
ret
```

# 将global_max_fast打了unsortedbin后链表损坏如何打fastbin attack

`unsortedbin attack`打了之后链表会损坏，若是要继续申请其它`chunk`将会出错。

而一种攻击方式是打`global_max_fast`，使用`unsortedbin attack`打`global_max_fast`之后，来打`fastbin attack`。

然而，`unsortedbin attack`之后链表损坏，已经难以申请新的`chunk`了。

解决办法是，在`unsortedbin attack`时，通过切割，将要进行`unsortedbin attack`的`unsortedbin chunk`的大小设置为接下来要进行`fastbin attack`的大小。如此一来，通过`malloc`来申请`unsorted chunk`并触发`unsortedbin attack`之后，只需要将这个`chunk`进行`free`就可以将其置入对应的`fastbin`了。

# 通过libc偏移进行堆地址泄露

`libc.sym['__curbrk']`是堆地址的一个固定偏移

# 通过FSOP触发setcontext+53

在`orw`中可以通过`FSOP`触发`setcontext+53`，此时`rdi`是当前正在刷新的`_IO_FILE_plus`，因此假如将当前的`_IO_FILE_plus`劫持为堆上的`chunk`后，即可控制`rdi`来控制程序执行流。

# tcache无法leak时直接修改tcache_perthread_struct

在`tcache`中含有多个`chunk`时，`tcache`存储的指针和`tcache_perthread_struct`存在固定偏移，可以直接`partial overwrite`。

# tcache中释放tcache_perthread_struct获得unsorted bin chunk

如题

# 没有leak时通过stdout泄露地址

如果没有`leak`，那么可以考虑通过打`unsortedbin`中残留的`libc`指针，通过`partial overwrite`的方式来操纵`stdout`泄露地址。

# ROP中的magic gadget

## inc

用到的`gadget`是：

```assembly
inc dword ptr [ebp - 0x17fa8b40] ; ret 0
```

由于那道题中的`ebp`可以随便控制，且`got`表可以写，因此我们构造一下，使得一直让`atol`的`got`表值+1，直到等于`system`。事实上这道题不是直接用这个`gadget`来一直`+1`的，而是使用其来给倒数第二字节一直`+1`，最低位直接用`read`来读，以此来减少`+1`的次数。

## ebx的magic gadget

```assembly
$ ROPgadget --binary ./cscctf_2019_qual_signal | grep ebx
0x0000000000400618 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
```

如上所示，可以往`[rbp - 0x3d]`加上`ebx`的值。若我们可以控制这两个值，可以往任意地址加上一些值。

通常情况下可以配合`ret2csu`，因为`csu`可以控制这些寄存器嘛。

例如，可以通过`csu`和这个`magic gadget`配合来将`alarm`的`got`表的值加五，`alarm+5`实际上就是`syscall`。

# malloc_consolidate实现fastbin double free->unlink

大小属于`fastbin`的`chunk`被`free`时，会检查和`fastbin`头相连的`chunk`是否是同一个`chunk`。然而，`malloc_consolidate`可以将`fastbin`链表中的`chunk`脱下来添加到`unsortedbin`，并设置其内存相邻的下一个`chunk`的`prev_inuse`为`0`。`malloc_consolidate`可以由申请一个很大的`chunk`触发。由此，若只能释放同一个`fastbin`的`chunk`，可以先`free`它将其添加到`fastbin`，然后使用`malloc_consolidate`将其置入`unsortedbin`。此时便可以再次`free`该`chunk`添加到`fastbin`，此时一个位于`fastbin`，另一个位于`unsortedbin`。申请回`fastbin`的`chunk`，在里面伪造一个`fake chunk`，由于其下一个`chunk`的`prev_inuse`被设置，因此可以进行`unsafe unlink`。不适用于继续`fastbin attack`，因为另一个`chunk`不位于`fastbin`。例题为`sleepyHolder_hitcon_2016`.

# mmap分配的chunk的阈值更改

我们知道`malloc`一个很大的`chunk`时会通过`mmap`来映射到`libc`附近，而不是`top chunk`中分配。

然而，当`free`很大的`chunk`时，其通过`mmap`分配的`chunk`的阈值会改变，改变为`free`的`chunk`的大小的页对齐的值。

例如，第一次`malloc(0x61a80)`，会将其以`mmap`的方式分配到`libc`附近。我们`free`这个`chunk`，此时`mmap`的阈值将会变为`0x62000`。我们再次`malloc(0x61a80)`，将会使得其切割`top chunk`来分配，而不是`mmap`分配到`libc`附近。

# 栈上的字符串数组未初始化泄露libc

某些栈上的字符串若未初始化，可能其中本来存放有一些`libc`地址，可以直接泄露，或者使用`strlen()`、`strdup()`等函数利用。

# strcat、strncat等函数漏洞

这些函数会在末尾补一个`\x00`，有的时候会有奇效（比如覆盖掉下一个变量）

# add和edit是分开的情况

若没有清零堆块，那么这种情况下`add`得到的`chunk`中可以含有各种残留的堆块指针和残留的`libc`地址，可以泄露或使用。

# 若存在alarm，则可以利用偏移得到syscall

如下所示，`alarm+5`即可获得`syscall`，正常情况则没有

![image-20240115104436982](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20240115104436982.png)

# printf中获取到特别长的字符串时会调用malloc和free

如题，因此可以通过这种方式来获得`shell`：

```python
payload = fmtstr_payload(7, {libc.sym['__malloc_hook']:one_gadget[0] + libc.address})
payload += b'%100000c'
```

具体多长呢？说不清楚，但是假如`printf`没有输出那个很长的空白字符串，那就说明执行到`malloc_hook`里面去了，对吧？

所以可以观察是否有这个输出来判断是否是执行了`malloc_hook`。
