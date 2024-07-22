---
layout: post
title: IO_FILE之stdin和stdout的任意读写(glibc2.23-Latest)
category: Heap
date: 2023-11-20 20:39:36
updated: 2023-11-20 15:03:00
---
IO_FILE知识
<!-- more -->
[toc]
# IO_FILE之任意读写(glibc2.23-Latest)

无论是任意写还是任意读，希望你能够明白其任意读写的道理：我们控制其读写指针指向可控部分，并控制`_fileno`为标准输入或者标准输出，从而从标准输入输入数据到可控部分或者从可控部分读取数据输出到标准输出。

劫持`stdin `可以完成：

- 从标准输入读取数据，写入到任意位置。

劫持`stdout`可以完成：

- 将要输出的文件的内容写入到任意位置。
- 将任意变量内容输出到标准输出。

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

// 正常情况下会从文件流输入到一个变量中
// 劫持stdin，将fileno从文件流劫持到0即标准输入，劫持缓冲区指针使其指向要写入的地方
// 因此变为从标准输入中输入数据到任意位置

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
- 调用从文件输入的一些函数例如`fread`、`fgets`

## 使用stdout标准输出进行任意读写

`stdin`是将输入数据拷贝到缓冲区，而`stdout`会先将数据拷贝到缓冲区，然后将缓冲区数据输出到标准输出或文件。因此，若我们能够劫持`stdout`，那么既可以进行任意写，也可以进行任意读。

### 任意写

我们上面提到了`stdout`的输出包括两个部分，任意写的操作就是根据`stdout`会先将数据拷贝到缓冲区这一步来进行劫持的。

因此，只要我们能够控制缓冲区的开始位置和结束位置，且输出的数据可控，那么我们就可以进行任意数据写。

一段劫持`stdout`进行任意写的`C`代码如下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int main(){
    char content[0x20] = "flag{th1s_1s_my_secret_flag!}";
    char secret[0x20];
    
    FILE* fp = fopen("./content", "wr");

    // 原意是向content文件中写入长度为0x20的secret变量
    // 我们通过劫持，能够实现其向任意位置写secret变量
    

    // 我们需要劫持fp->_IO_write_ptr和fp->_IO_write_end，其偏移分别为0x28和0x30
    *(size_t*)((char*)fp + 0x28) = (size_t)secret;
    *(size_t*)((char*)fp + 0x30) = (size_t)((size_t)secret + 0x20);

    // fwrite(content, 0x20, 1, fp);
    fputs(content, fp);

    printf("The flag is %s. How could you change it?\n", secret);
    return 0;
}
```

总结一下`stdout`的任意写，只需要构造：

- `fp -> _IO_write_ptr`和`fp -> _IO_write_end`，指向要写的位置。写的内容为要写入文件的变量的内容。偏移为`0x28`和`0x30`。
- 调用写入文件的一些函数例如`fwrite`、`fputs`。

### 任意读

上面提到`stdout`包括将数据拷贝到缓冲区和将缓冲区数据写入文件两个部分，而任意读是劫持将缓冲区数据写入文件这一部分。我们将缓冲区指针指向我们要输出的内容，再将`_fileno`劫持为标准输出，如此一来`stdout`的”将缓冲区数据写入文件“这一步就变为”将指定区域数据输出到标准输出“了。具体利用过程如下分析所示。只想看劫持条件的师傅也可以直接反倒最后面。

我们跟进一下`fwrite`的源码，看看`C`语言调用`fwrite`后，`glibc`做了哪些操作。

首先`fwrite`函数的实现实际上是`_IO_fwrite`函数，如下：

```c
// 位于/libio/fwrite.c
_IO_size_t
_IO_fwrite(const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
    _IO_size_t request = size * count; // 计算请求的字节数
    _IO_size_t written = 0;
    CHECK_FILE(fp, 0);
    if (request == 0) // 请求字节为0，那么无事发生，直接返回
        return 0;
    _IO_acquire_lock(fp); // 文件操作，需要加锁
    if (_IO_vtable_offset(fp) != 0 || _IO_fwide(fp, -1) == -1) // 存在vtable。说明已经初始化了
        written = _IO_sputn(fp, (const char *)buf, request); // 调用written进行输出
    _IO_release_lock(fp);
    /* We have written all of the input in case the return value indicates
       this or EOF is returned.  The latter is a special case where we
       simply did not manage to flush the buffer.  But the data is in the
       buffer and therefore written as far as fwrite is concerned.  */
    if (written == request || written == EOF) // 输出的字节数等于请求的字节数，返回请求的变量单位的数量
        return count;
    else
        return written / size;  // 否则返回实际输出的变量单位的数量
}
```

可以知道`fwrite`调用了`_IO_fwrite()`函数，并且计算了请求的字节数后加锁并调用`_IO_sputn()`函数来进一步地进行输出。继续跟进：

```c
// 位于/libio/fileops.c
_IO_size_t
_IO_new_file_xsputn(_IO_FILE *f, const void *data, _IO_size_t n)
{
    const char *s = (const char *)data;
    _IO_size_t to_do = n; // 还需要写的字节数
    int must_flush = 0;
    _IO_size_t count = 0;

    if (n <= 0) // 若请求字节数小于0，直接返回
        return 0;
    /* This is an optimized implementation.
       If the amount to be written straddles a block boundary
       (or the filebuf is unbuffered), use sys_write directly. */

    /* First figure out how much space is available in the buffer. */
    // 假如是行缓冲，且正在写入数据。第二个标志位很难满足，不会进入这个分支
    // 而且文件流、标准输入流默认都是全缓冲
    if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
        count = f->_IO_buf_end - f->_IO_write_ptr;
        if (count >= n)
        {
            const char *p;
            for (p = s + n; p > s;)
            {
                if (*--p == '\n')
                {
                    count = p - s + 1;
                    must_flush = 1;
                    break;
                }
            }
        }
    }
    else if (f->_IO_write_end > f->_IO_write_ptr) // 当_IO_write_end大于_IO_write_ptr时说明当前还有数据没写到缓冲区，要避免
        count = f->_IO_write_end - f->_IO_write_ptr; // 没写到缓冲区的数据

    /* Then fill the buffer. */
    if (count > 0) // 会写到缓冲区
    {
        if (count > to_do)
            count = to_do;
#ifdef _LIBC
        f->_IO_write_ptr = __mempcpy(f->_IO_write_ptr, s, count); 
#else
        memcpy(f->_IO_write_ptr, s, count);
        f->_IO_write_ptr += count;
#endif
        s += count;
        to_do -= count;
    }
    if (to_do + must_flush > 0) // to_do是还需要写的字节数，肯定大于0
    {
        _IO_size_t block_size, do_write;
        /* Next flush the (full) buffer. */
        if (_IO_OVERFLOW(f, EOF) == EOF) // 调用_IO_OVEFLOW来设置和刷新缓冲区
            /* If nothing else has to be written we must not signal the
               caller that everything has been written.  */
            return to_do == 0 ? EOF : n - to_do;

        // 通过分页机制来减少系统调用的次数。计算要写入的字节数整除0x1000的值
        block_size = f->_IO_buf_end - f->_IO_buf_base;
        do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

        // 将0x1000的整数倍的字节进行写入
        if (do_write)
        {
            count = new_do_write(f, s, do_write);
            to_do -= count;
            if (count < do_write)
                return n - to_do;
        }


        // 剩下的字节交给_IO_default_xsputn()处理
        if (to_do)
            to_do -= _IO_default_xsputn(f, s + do_write, to_do);
    }
    return n - to_do;
}
```

根据上面的代码，我们得知`_IO_new_file_xsputn()`函数的作用为：调用`_IO_OVERFLOW`来刷新文件的缓冲区，并且调用`_IO_default_xsputn()`来完成对文件的写入。而在接下来要分析的`_IO_OVERFLOW()`有一点非常重要：**若文件中缓冲区已满，则会刷新缓冲区**。这意味着只要我们控制其缓冲区指针，造成其已经是满的假象，并且将其指向我们想要读取的内容，那么就会将想要读取的内容输出。由此我们不再跟进`_IO_default_xsputn()`这个用于写入文件的函数，而是看看`_IO_OVERFLOW`是如何刷新缓冲区的。此外，目前这里我们需要满足一个条件，即：

- `f->_IO_write_end` <= `f->_IO_write_ptr`

接下来跟进`_IO_OVERFLOW()`如下：

```c
// 位于/libio/fileops.c
int _IO_new_file_overflow(_IO_FILE *f, int ch)
{
    // 假如包含_IO_NO_WRITES，值为8，那么报错并返回
    if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
        f->_flags |= _IO_ERR_SEEN;
        __set_errno(EBADF);
        return EOF;
    }
    // 假如正在输出数据，或者缓冲区未建立。正常情况下是未建立缓冲区的，因此会进入分支，分支会采取大量措施建立缓冲区不可控
    // 因此最好提前设置_IO_write_base的值，并设置f->_flags包含_IO_CURRENTLY_PUTTING，其值为8
    if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
        /* Allocate a buffer if needed. */
        if (f->_IO_write_base == NULL)
        {
            _IO_doallocbuf(f);
            _IO_setg(f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
        }
        /* Otherwise must be currently reading.
     If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
     logically slide the buffer forwards one block (by setting the
     read pointers to all point at the beginning of the block).  This
     makes room for subsequent output.
     Otherwise, set the read pointers to _IO_read_end (leaving that
     alone, so it can continue to correspond to the external position). */
        if (__glibc_unlikely(_IO_in_backup(f)))
        {
            size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
            _IO_free_backup_area(f);
            f->_IO_read_base -= MIN(nbackup,
                                    f->_IO_read_base - f->_IO_buf_base);
            f->_IO_read_ptr = f->_IO_read_base;
        }

        if (f->_IO_read_ptr == f->_IO_buf_end)
            f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
        f->_IO_write_ptr = f->_IO_read_ptr;
        f->_IO_write_base = f->_IO_write_ptr;
        f->_IO_write_end = f->_IO_buf_end;
        f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

        f->_flags |= _IO_CURRENTLY_PUTTING;
        if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
            f->_IO_write_end = f->_IO_write_ptr;
    }
    // ch在上一个函数传入的就是EOF，因此必会进入这个if语句，调用_IO_do_write函数
    if (ch == EOF)
        return _IO_do_write(f, f->_IO_write_base,
                            f->_IO_write_ptr - f->_IO_write_base);
    // 我们这暂时不用看后面了，因为上面已经return
    if (f->_IO_write_ptr == f->_IO_buf_end) /* Buffer is really full */
        if (_IO_do_flush(f) == EOF)
            return EOF;
    *f->_IO_write_ptr++ = ch;
    if ((f->_flags & _IO_UNBUFFERED) || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
        if (_IO_do_write(f, f->_IO_write_base,
                         f->_IO_write_ptr - f->_IO_write_base) == EOF)
            return EOF;
    return (unsigned char)ch;
}
```

实际上`_IO_OVERFLOW`在`glibc`的实现也就是`_IO_new_file_overflow()`函数，该函数首先会进行一些标志位的校验，我们需要绕过。此外，该函数还会检查自身缓冲区是否建立，若未建立会进行一系列复杂操作，因此我们此处需要设置`f->_IO_write_base`不为0，使其不会再次建立缓冲区。满足上述条件后，其会调用`_IO_do_write()`函数。到此为止需要满足的条件如下：

- `f -> _IO_write_end` <= `f -> _IO_write_ptr`
- `f -> _flags & _IO_NO_WRITES`为`0`，即不包含`_IO_NO_WRITES`，为8
- `f -> _IO_write_base`不为`0`
- `f -> _flags & _IO_CURRENTLY_PUTTING`不为`0`，即包含`_IO_CURRENTLY_PUTTING`，为`0x800`

继续跟进`_IO_do_write()`函数如下：

```c
// 位于libio/fileops.c
int _IO_new_do_write(_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
    return (to_do == 0 || (_IO_size_t)new_do_write(fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver(_IO_new_do_write, _IO_do_write)

    static _IO_size_t
    new_do_write(_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
    _IO_size_t count;
    // 有两个判断，第一个看起来不影响，但else if里面比较复杂不可控，需要绕过
    if (fp->_flags & _IO_IS_APPENDING)
        /* On a system without a proper O_APPEND implementation,
           you would need to sys_seek(0, SEEK_END) here, but is
           not needed nor desirable for Unix- or Posix-like systems.
           Instead, just indicate that offset (before and after) is
           unpredictable. */
        fp->_offset = _IO_pos_BAD;
    else if (fp->_IO_read_end != fp->_IO_write_base) // 绕过
    {
        _IO_off64_t new_pos = _IO_SYSSEEK(fp, fp->_IO_write_base - fp->_IO_read_end, 1);
        if (new_pos == _IO_pos_BAD)
            return 0;
        fp->_offset = new_pos;
    }
    // 满足条件后通过系统调用执行_IO_SYSWRITE
    // data从上面传过来的，是f->_IO_write_base, to_do是f->_IO_write_ptr - f->_IO_write_base
    // 意思就是输出f -> _IO_write_base和_IO_write_ptr之间的内容
    count = _IO_SYSWRITE(fp, data, to_do); 
    // 后面已经和我们无关
    if (fp->_cur_column && count)
        fp->_cur_column = _IO_adjust_column(fp->_cur_column - 1, data, count) + 1;
    _IO_setg(fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
    fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
    fp->_IO_write_end = (fp->_mode <= 0 && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                             ? fp->_IO_buf_base
                             : fp->_IO_buf_end);
    return count;
}
```

在`_IO_do_write()`函数中，有一个`if`语句和一个`else if`两处判断，然后就会调用`_IO_SYSWRITE`系统调用来输出内容。其调用的形式为：`_IO_SYSWRITE(fp, data, to_do);`。`fp`我们需要劫持为`1`，即`stdout`标准输出，而传入该函数的`data`实际上是`fp -> _IO_write_base`，传入的`to_do`即长度实际上是`fp -> _IO_write_ptr - fp -> _IO_write_base`，因此只要执行到这个地方，就能够输出我们想要的内容了。回到刚刚讲的两处判断，第一处`if`语句若满足，实际上也不会影响我们的系统调用；而`else if`中的内容比较复杂，不太可控，因此我们选择绕过这一段代码，因此设置`fp->_IO_read_end == fp->_IO_write_base`即可。

到了这里，我们就完成了劫持`stdout`进行任意读的操作。劫持`stdout`进行任意写的`C`语言示意代码如下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int main(){
    // 原意是将content变量写入文件
    // 我们劫持写入的过程，转而将secret变量输出到标准输出
    char content[] = "Whatever it writes";
    char secret[] = "flag{You_got_how_to_use_stdout_lol}\n";
    
    FILE *fp = fopen("./flag", "w");   

    // step1: f -> _flags == 0xfbad0800
    *(size_t*)(fp) = 0xfbad0800;

    // step2: f -> _fileno == 1 ，偏移0x70
    *(size_t*)((char*)fp + 0x70) = 1;

    // step3: f -> write_base和 f -> write_ptr之间为输出的内容，偏移0x20和0x28
    *(size_t*)((char*)fp + 0x20) = (size_t)secret;
    *(size_t*)((char*)fp + 0x28) = (size_t)secret+ (size_t)strlen(secret);
    printf("The length is %ld.\n", (size_t)strlen(secret));

    // step4: f -> _IO_write_end == f -> IO_write_ptr ，其中_IO_write_end偏移为0x30
    *(size_t*)((char*)fp + 0x30) = (size_t)secret + (size_t)strlen(secret);

    // step5: f -> _IO_read_end == f -> _IO_write_base，其中_IO_read_end偏移为0x10
    *(size_t*)((char*)fp + 0x10) = (size_t)secret;

    // step6: 调用stdout函数
    fwrite(content, 1, 0x20, fp);
    return 0;
}
```

总结一下利用的条件如下：

- `f -> _flags`为`0xfbad0800`，偏移为`0x0`
- `f -> _fileno`为`1`，偏移为`0x70`
- `f -> _IO_write_base`和 `f -> _IO_write_ptr`之间为输出的内容，其中`f -> _IO_write_base`的偏移为`0x20`，`f -> _IO_write_ptr`为`0x28`
- `f -> _IO_read_end == f -> _IO_write_base`，其中`f -> _IO_read_end`偏移为`0x10`
- `f -> _IO_write_end == f -> _IO_write_ptr`，其中`f -> _IO_write_end`偏移为`0x30`
- 调用输出到文件的一些函数例如`fwrite`、`fputs`，或是`_fileno`本来就为`1`时任意调用`stdout`

后记：

发现如下方式也可以，更加简单，原理待补充：

- `f -> _flags`为`0xfbad1887`，偏移为`0x0`

- 通过`stdout`输出数据

- `f -> _IO_write_base`和 `f -> _IO_write_ptr`之间为输出的内容，其中`f -> _IO_write_base`的偏移为`0x20`，`f -> _IO_write_ptr`为`0x28`

**参考链接：**

[raycp师傅的IO_FILE任意读写](https://xz.aliyun.com/t/5853)

[hollk师傅的好好说话系列的IO_FILE](https://blog.csdn.net/qq_41202237/article/details/113845320)