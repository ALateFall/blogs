---
layout: post
title: IO_FILE基础知识小结
category: system/IO_FILE
date: 2023-11-09 20:39:36
updated: 2023-11-20 15:03:00
---
IO_FILE知识
<!-- more -->

[toc]

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

## _IO_wide_data结构体

```c
// 同样是随便找了个，用来查看偏移而已
{
  _IO_read_ptr = 0, // 偏移0x0
  _IO_read_end = 0x0, // 偏移0x8
  _IO_read_base = 0x0, // 偏移0x10
  _IO_write_base = 0x0, // 偏移0x18
  _IO_write_ptr = 0x0, // 偏移0x20
  _IO_write_end = 0x0, // 偏移0x28
  _IO_buf_base = 0x0, // 偏移0x30
  _IO_buf_end = 0x0, // 偏移0x38
  _IO_save_base = 0x0, // 偏移0x40
  _IO_backup_base = 0x0, // 偏移0x48
  _IO_save_end = 0x0, // 偏移0x50
  _IO_state = {...}, // 偏移0x58
  _IO_last_state = {...}, // 偏移0x60
  _codecvt = {...}, // 偏移0x68
  _shortbuf = "", // 偏移0xd8
  _wide_vtable = 0x0 // 偏移0xe0
}

```



# IO_FILE利用链总结

## printf利用链 -- glibc2.23

这条利用链如下：

```c
printf -> vfprintf -> buffered_vfprintf -> _IO_sputn（覆盖该函数指针）
```

这条利用链的需要满足的条件有三点，第一个是进入`buffered_vfprintf`函数，如下所示：

```c
if (UNBUFFERED_P (s))
	return buffered_vfprintf (s, format, ap);
// #define UNBUFFERED_P(S) ((S)->_IO_file_flags & _IO_UNBUFFERED)
// #define _IO_UNBUFFERED 2
```

因此，`_flags`需要含有2。

第二个条件是`buffered_vfprintf`函数中存在`_IO_flockfile`宏限制：

```c
# define _IO_flockfile(_fp) \
  if (((_fp)->_flags & _IO_USER_LOCK) == 0) _IO_flockfile (_fp)
// #define _IO_USER_LOCK 0x8000
```

若`_flags`不含有`0x8000`，那么会调用`_IO_flockfile`函数对文件加锁。因此`_flags`需要含有`0x8000`。

第三个条件调用函数指针时：

```c
if ((to_flush = hp->_IO_write_ptr - hp->_IO_write_base) > 0)
{
  	if ((int) _IO_sputn (s, hp->_IO_write_base, to_flush) != to_flush)
		result = -1;
}
```

因此需要`_IO_write_ptr > _IO_write_base`即可。

总结条件如下：

- `_flags`需要包含`0x8000`和`0x2`，即起码需要为`0xfbad8002`的形式。（偏移为`0x0`）
- `_IO_write_ptr > _IO_write_base`，偏移分别为`0x28`和`0x20`。

## C语言中默认的缓冲模式

- 对于`stdin`和`stdout`，默认是行缓冲的，这意味着部分行不会显示，直到打印了换行符、调用了`fflush()`，或程序退出。（**本人测试实际上是全缓冲**）
- 对于`stderr`，默认是无缓冲的，这意味着遇到错误会立即输出。
- 对于文件流，例如使用`fopen`打开的文件，通常是全缓冲的。这意味着只有缓冲区满的时候或者显式调用`fflush()`函数时才会写入底层文件。
