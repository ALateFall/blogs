---
layout: post
title: glibc做题思路
category: Heap
date: 2023-9-27 18:38
---

`glibc`题目的一些做题思路
<!-- more -->

# libc泄露

- `glibc2.27`以下可以直接释放一个不属于`fastbin`的`chunk`，其会被添加到`unsortedbin`中，其`fd`和`bk`便为`libc`的偏移

- `glibc2.27`的每个`tcache`最多为7个，因此可以使得同一个`tcache`中存放超过7个`chunk`，从而添加到`unsortedbin`
- `glibc2.27`中可以释放一个`large chunk`，其不会添加到`tcache`而是直接添加到`unsortedbin`

- `glibc2.27`中可以通过修改`tcache_perthread_struct`，来控制`tcache`某个大小的数量。超过的会被放到`unsortedbin`
- 可以通过`malloc`一个很大的`chunk`从而使用`mmap`来分配，其地址为`libc`的固定偏移

# 堆地址泄露

- `fastbin`、`tcache`等在不止一个`chunk`时的`fd`指针
- `libc`中的`_curbrk`变量，例如`libc.sym['_curbrk']`

# 栈地址泄露

- 栈上地址的固定偏移
- `libc`中的`_environ`变量指示了一个栈地址，即`libc.sym['_environ']`