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

## C语言中默认的缓冲模式

- 对于`stdin`和`stdout`，默认是行缓冲的，这意味着部分行不会显示，直到打印了换行符、调用了`fflush()`，或程序退出。（**本人测试实际上是全缓冲**）
- 对于`stderr`，默认是无缓冲的，这意味着遇到错误会立即输出。
- 对于文件流，例如使用`fopen`打开的文件，通常是全缓冲的。这意味着只有缓冲区满的时候或者显式调用`fflush()`函数时才会写入底层文件。
