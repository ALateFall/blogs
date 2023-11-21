---
layout: post
title: IO_FILE之stdin和stdout的任意读写(glibc2.23-Latest)
category: system/IO_FILE
date: 2023-11-09 20:39:36
updated: 2023-11-20 15:03:00
---
IO_FILE知识
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