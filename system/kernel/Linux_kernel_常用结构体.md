---
layout: post
title: 0xFF. Linux kernel：结构体总结
category: kernel pwn
date: 2024-7-29 14:00:00
---

难道不应该打`__free_hook`吗

<!-- more -->

[toc]

# 重要结构体

## 0x00. tty_struct (kmalloc-1k | GFP_KERNEL_ACCOUNT)

### 属性

#### 总结

- 通过`open("/dev/ptmx", 2)`来打开

- 大小：`kmalloc-1k`

- 分配`flag`：`GFP_KERNEL_ACCOUNT`
- 泄露内核基地址
- 泄露堆地址
- 劫持程序控制流

#### 打开方式

打开`/dev/ptmx`，但需要注意是否挂载了`pts`，若没有挂载则无法打开

#### 魔数

`tty_struct`在结构体起始位置`int magic`含有魔数`0x5401`，可以方便我们搜索该结构体。

#### 利用效果

- 利用函数指针劫持程序控制流

- 参数可控，其第一个参数为`tty_struct`的地址

- 泄露内核基地址

- 泄露内核堆地址

#### 结构体

位于`include/linux/tty.h`，如下所示：

```c
struct tty_struct {
    int    magic;
    struct kref kref;
    struct device *dev;    /* class device or NULL (e.g. ptys, serdev) */
    struct tty_driver *driver;
    const struct tty_operations *ops;
    int index;

    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;

    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    char name[64];
    unsigned long flags;
    int count;
    struct winsize winsize;        /* winsize_mutex */

    struct {
        spinlock_t lock;
        bool stopped;
        bool tco_stopped;
        unsigned long unused[0];
    } __aligned(sizeof(unsigned long)) flow;

    struct {
        spinlock_t lock;
        struct pid *pgrp;
        struct pid *session;
        unsigned char pktstatus;
        bool packet;
        unsigned long unused[0];
    } __aligned(sizeof(unsigned long)) ctrl;

    int hw_stopped;
    unsigned int receive_room;    /* Bytes free for queue */
    int flow_change;

    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;        /* protects tty_files list */
    struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;

/* Each of a tty's open files has private_data pointing to tty_file_private */
struct tty_file_private {
    struct tty_struct *tty;
    struct file *file;
    struct list_head list;
};

/* tty magic number */
#define TTY_MAGIC        0x5401
```

其中含有一个函数表结构体，即`tty_operations`，如下所示：

```c
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    unsigned int (*write_room)(struct tty_struct *tty);
    unsigned int (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    int  (*get_serial)(struct tty_struct *tty, struct serial_struct *p);
    int  (*set_serial)(struct tty_struct *tty, struct serial_struct *p);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

### 利用

#### 数据泄露 - 内核基地址

`tty_operations`会被初始化为全局变量`ptm_unix98_ops`或者`pyt_unix98_ops`，而即使开启`kaslr`，低三位不变。

因此可以通过该数值来获取内核基地址。在`/proc/kallsyms`中也可以查看：

```bash
/ # cat /proc/kallsyms | grep 'ptm_unix98_ops'
ffffffff98083ca0 r ptm_unix98_ops
/ # cat /proc/kallsyms | grep 'pty_unix98_ops'
ffffffff98083b80 r pty_unix98_ops
```

#### 数据泄露 - 堆地址

`tty_struct`中的`dev`与`driver`是通过`kmalloc`分配的，因此可以通过这两个成员泄露内核地址。

#### 劫持程序控制流

劫持`tty_operations`函数表即可，例如劫持其中的`write`函数指针，即可通过`write`系统调用时，设置`tty_struct`的`fd`即可调用劫持后的`write`函数。

参数可控，第一个参数`rdi`即为`tty_struct`的地址。

## 0x01. seq_file (kmalloc-32 | GFP_KERNEL_ACCOUNT)

### 属性

#### 总结

- 通过`open("/proc/self/stat", O_RDONLY)`来打开

- 大小：`kmalloc-32`
- 分配`flag`：`GFP_KERNEL_ACCOUNT`
- 泄露内核基地址
- 不带参数劫持程序控制流

#### 打开方式

以**只读方式**打开文件`/proc/self/stat`，申请得到的是`seq_operations`结构体，**注意不是**`seq_file`

#### 魔数

无

#### 利用效果

- 劫持程序控制流，无法控制参数
- 泄露内核基地址

#### 结构体

`seq_file`会单独从`seq_file_cache`分配，一般难以控制。其结构体为：

```c
struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    loff_t index;
    loff_t read_pos;
    struct mutex lock;
    const struct seq_operations *op;
    int poll_event;
    const struct file *file;
    void *private;
};
```

而其中`seq_operations`函数表结构体可以打开`/proc/self/stat`来获取，其结构体为：

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
```

注意其中参数并不可控。

### 利用

#### 数据泄露 - 泄露内核基地址

`seq_operations`函数表中的第一个函数指针`start`即为函数`single_start`函数的地址，可以用于泄露内核基地址：

```bash
/ # cat /proc/kallsyms | grep 'single_start'
ffffffffb6c4b160 T single_start
```

其实其余的同理，即`single_stop`，`single_next`，`single_show`

#### 劫持程序控制流

覆盖`seq_operations`函数表中的函数指针`start`。

对该结构体调用`read`，即可以触发`seq_operations->start`控制程序执行流。

注意参数不可控，一般可能需要配合`pt_regs`等结构体。

## 0x02. user_key_payload (kmalloc-any, GFP_KERNEL)

### 属性

#### 总结

- 通过`add_key`系统调用打开（会有临时`obj`）

- 大小：任意，且是由用户指定的
- 分配`flag`：`GFP_KERNEL`、`__GFP_HARDWALL`、`__GFP_NOWARN`
- 可以泄露内核基地址
- 可以泄露内核堆地址
- 通过越界读，无需驱动提供`read`即可泄露内核基地址

#### 打开方式

通过`add_key()`系统调用为用户申请密钥时，会遵循如下流程来打开结构体：

- 从内核中分配`obj1`和`obj2`，分别用于保存`description`和`payload`。其中`desciption`的大小为其内容长度，而`payload`大小由我们设置的`plen`指定。
- 再次分配`obj3`和`obj4`。`obj3`和`obj1`一模一样，并将`obj1`内容复制到`obj3`；`obj4`和`obj2`一模一样，并将`obj4`内容复制到`obj2`。
- 释放`obj1`和`obj2`，返回分配密钥的`id`

可以看到，无论是对于`desctiption`还是`payload`，它们**都会有一个临时的`obj`**。此外，在我们利用时，我们最好将`description`的值设置为和`payload`大小以及别的结构体毫不相关，直接不考虑`desciption`来简化利用过程。

如此一来，只考虑`payload`的情况下，流程为：

- 申请大小为`plen`的保存`payload`的`obj1`，其`flag`为`GFP_KERNEL`
- 再次申请一个大小和类型都一样的`obj2`，将`obj1`复制到`obj2`，并释放`obj1`

如此我们可以理清楚`add_key`系统调用的流程。

#### 魔数

无

#### 利用效果

- 泄露内核基地址
- 泄露内核堆地址
- 通过越界读来读取地址

#### 结构体

主要作为越界读这个利用方式的`user_key_payload`的结构体如下所示：

```c
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */
	unsigned short	datalen;	/* length of this data */
	char		data[] __aligned(__alignof__(u64)); /* actual data */
};
```

其中，`struct rcu_head`结构体如下所示：

```c
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
```

不难得知`user_key_payload`的头部（即`struct rcu_head`和`datalen`）一共为`0x18`字节。剩下的`data[]`数组是保存`payload`本身。

### 利用

#### 数据泄露 - 泄露内核基地址

当通过`key_revoke`来销毁密钥时，`rcu->func`（可以查看上面的结构体）将会被赋值为`user_free_payload_rcu`函数的地址，该函数地址和内核偏移固定，可以通过`/proc/kallsyms`查看其地址，如下所示：

```c
/# cat /proc/kallsyms | grep 'user_free_payload_rcu'
```

#### 数据泄露 - 泄露堆地址

和刚刚提到的方法异曲同工，即通过`rcu->next`来泄露堆地址

#### 数据泄露 - 越界读（无需驱动提供read）

上面我们写了泄露内核基地址的方法。但该方法即使存在`UAF`，也需要驱动本身提供一个`read`功能，而若驱动本身提供了`read`功能，那我们实际上也不是很需要用`user_key_payload`来打了....

实际上`user_key_payload`最主要的作用就是其存在读取自身`payload`的功能，且其是根据结构体里的长度`datalen`来读取的。若我们能够控制`datalen`为一个大于其`payload`长度的数字，即可实现越界读，若能够读到其它被释放的`user_key_payload`结构体，即可获取到程序基地址。

总结流程：

- 修改`user_key_payload`的`datalen`
- 调用`keyctl_read`系统调用，来根据`datalen`越界读数据
- 读到其他被释放的`user_key_payload`，即可读到其中`rcu->func`，泄露内核基地址

## 0x03. pipe_buffer(kmalloc-1k | GFP_KERNEL_ACCOUNT)

### 属性

#### 总结

- 通过`void pipe(int fd[])`函数来打开
- 同时打开`pipe_inode_info`和`pipe_buffer`两个结构体
- `pipe_inode_info`的大小为`kmalloc-192`，分配`flag`为`GFP_KERNEL_ACCOUNT`
- `pipe_buffer`的大小为`kmalloc-1k`（注意为`1024`），分配`flag`为`GFP_KERNEL_ACCOUNT`

#### 打开方式

通过`pipe`函数来打开一个管道即可创建`pipe_inode_info`和`pipe_buffer`两个结构体。

如下所示：

```c
int pipe_fd[2];
pipe(pipe_fd);
```

#### 魔数

无

#### 利用效果

- 劫持程序控制流
- 其`rdi`和`rsi`均可控，`rdi`为`struct pipe_inode_info`，`rsi`为`struct pipe_buffer`
- 泄露内核基地址

#### 结构体

打开管道时会创建两个结构体，其中之一为`pipe_inode_info`

( `kmalloc-192 | GFP_KERNEL_ACCOUNT` )

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

与另一个结构体`pipe_buffer`：

( `kmalloc-1k | GFP_KERNEL_ACCOUNT` )

```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

其中函数指针表`pipe_buf_operations`为：

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

### 利用

#### 数据泄露 - 泄露内核基地址

`pipe_buffer->pipe_buf_operations`指向全局函数表，可以通过该函数表的地址来泄露出内核基地址

#### 数据泄露 - 泄露pipe_buffer地址

`pipe_inode_info`中有一个指向`struct pipe_buffer`的指针，可以通过该指针来获取申请到的`pipe_buffer`的地址。即`(pipe_inode_info[16])`。（注：只是通过`user_key_payload`泄露时才是`buf[16]`，具体还待笔者补充）

#### 劫持程序控制流

劫持`pipe_buffer`的函数指针表，覆盖里面的`release`函数指针。

在调用`close`关闭管道时，会调用`pipe_buffer -> pipe_buffer_operations -> release() `

其`rdi`和`rsi`均可控，`rdi`为`struct pipe_inode_info`，`rsi`为`struct pipe_buffer`。



# 实用结构体/函数

## 0x00. work_for_cpu_fn函数

实际上`work_for_cpu_fn`并不是结构体，只是在**开启了多核支持的`CPU`上**都有的一个函数。因此这里我们记录得简短一些。

```c
struct work_for_cpu {
    struct work_struct work;
    long (*fn)(void *);
    void *arg;
    long ret;
};
 
static void work_for_cpu_fn(struct work_struct *work)
{
    struct work_for_cpu *wfc = container_of(work, struct work_for_cpu, work);
 
    wfc->ret = wfc->fn(wfc->arg);
}
```

可以简单理解为如下形式：

```c
static void work_for_cpu_fn(size_t * args)
{
    args[6] = ((size_t (*) (size_t)) (args[4](args[5]));
}
```

可以看到，其将参数得第四个值作为函数，而参数的第五个值作为函数的参数执行。这让我们有简单的方式来直接执行一个带参数的函数。（要是`system("/bin/sh")`或许已经拿下了）。

例如，若我们将`tty_operations`中的函数指针劫持为`work_for_cpu_fn`，此时函数的参数为`tty_struct`。

由此，对`tty_struct`执行`ioctl`即可执行：

```c
((void*)tty_struct[4])(tty_struct[5]);
```

注意这里需要执行`ioctl`。

## 0x01. pt_regs结构体

主要利用位于低版本：当用户代码进入内核态时，用户态寄存器的值会放在内核态的底部。因此，可以通过布置适当的寄存器值，从而使得内核态中可以根据`pt_regs`结构体的值来进行`rop`等操作。

定义如下所示：

```c
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
    unsigned long orig_rax;
/* Return frame for iretq */
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
/* top of stack page */
};
```

若需要在`CTF Linux kernel`中使用，可以使用如下板子：

```c
__asm__(
    "mov r15,   0xbeefdead;"
    "mov r14,   0x11111111;"
    "mov r13,   0x22222222;"
    "mov r12,   0x33333333;"
    "mov rbp,   0x44444444;"
    "mov rbx,   0x55555555;"
    "mov r11,   0x66666666;"
    "mov r10,   0x77777777;"
    "mov r9,    0x88888888;"
    "mov r8,    0x99999999;"
    "xor rax,   rax;"
    "mov rcx,   0xaaaaaaaa;"
    "mov rdx,   8;"
    "mov rsi,   rsp;"
    "mov rdi,   seq_fd;"        // 这里假定通过 seq_operations->stat 来触发
    "syscall"
);
```

## 0x02. setxattr系统调用

### 介绍

我们可以通过如下方式进行`setxattr`的系统调用:

```c
#include <sys/xattr.h>

setxattr("/exploit", "username", value, size);
```

其中:

- 第一个参数只需要指定一个存在的文件
- 第二个参数随便

该系统调用中, 主要有如下内容:

```c
static long setxattr(struct dentry *d, const char __user *name, const void __user *value,
     size_t size, int flags)
{
    //...
        kvalue = kvmalloc(size, GFP_KERNEL);
        if (!kvalue)
            return -ENOMEM;
        if (copy_from_user(kvalue, value, size)) {

    //,..

    kvfree(kvalue);

    return error;
}
```

**可以看到其实现了一个任意大小的`obj`申请,并且其内容也完全由我们控制!**

但不幸的是,该`obj`分配过后,随机就会被释放掉,导致其没有干任何事~

### 利用 - 结合userfaultfd来堆占位

`setxattr`函数中有一个`copy_from_user`,不难想到可以利用`userfaultfd`来将其**卡在这里**

而如果只是卡在这里,那该函数将失去控制其内容的能力. 

由此,我们可以利用堆占位技术来使得其既可以使得内容可控, 又随即让`copy_from_user`不再继续往下执行.

我们申请一块连续的两页内存:

```tex
| memory1: size=pagesize | memory2: size=pagesize |
```

随后,我们**为第二部分的内存,注册`userfaultfd`**, 使得访问到这里时直接卡住. 

![image-20240910154201533](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202409101542656.png)

如图所示,我们将我们要写入的内容写到第一页的末尾,使其结束时,刚好是第二页的`userfaultfd`的内容.

如此,我们即可让`copy_from_user`正常执行,随后访问到缺页的内容,导致线程卡住,不会执行`free`.

代码示意如下:

```c
pwn_addr = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
register_userfaultfd_for_thread_stucking(&monitor_setx, (void*)((size_t)pwn_addr + 0x1000), 0x1000);

*(size_t*)((size_t)pwn_addr + 0x1000 - 8) = add_rsp_0x1f8 + kernel_offset;
setxattr("/init", "ltfall", (char*)((size_t)pwn_addr + 0x1000 - 8), 0x20, 0);
```

可以看到,我们上面便申请了一个`kmalloc-32`的`obj`,并写入了`add_rsp_0x1f8`的`gadget`~



# 0x

## 属性

### 总结

### 打开方式

### 魔数

### 利用效果

### 结构体

## 利用

### 数据泄露 - 泄露内核基地址

### 劫持程序控制流

