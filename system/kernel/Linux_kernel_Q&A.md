---
layout: post
title: excluded
category: kernel pwn
date: 2024-7-20 14:00:00
exclude: true
---
Linux kernel基础：Kernel 
<!-- more -->

[TOC]



# Q & A

这里用于记录一些`Linux Kernel Pwn`中遇到的各种问题。

## 0x00. 成功执行提权函数，但没有获得root权限的shell

问题表现于如上所示，或者是一些其它的奇怪症状。

可以在`gcc`编译时通过加上编译参数`-Os`，或者例如`-O0`等优化选项都可以试试，推测是由于优化选项带来的问题。

后记：检查一下`system`的`rsp`呢？其实就是栈对齐，用户态`rop`经典问题了。

## 0x01. 断点打不上

首先检查`gdb`是否有`add-symbol-file xxx.ko address`这样设置了，这里不讨论如何打断点，而是考虑在看似一切正常的情况下，打不上断点的情况。

笔者遇到过一次，启动脚本中有一行参数`-enable-kvm`。

将其删掉就好了。

## 0x02. Linux kernel 调试板子

写下笔者自用的`gdb`调试板子和`exp`运行板子。

`gdb`调试板子：

```bash
	"gdb_extended": {
		"prefix": "gdb",
		"body": [
			"#!/bin/bash",
			"",
			"# 定义变量",
			"KERNEL_MODULE=\"${1:}\"",
			"OFFSET=\"${2:}\"",
			"PORT=\"${3:1234}\"",
			"EXPLOIT=\"${4:core/exploit}\"",
			"",
			"# 使用gdb调试",
			"gdb -q \\",
			"    -ex \"add-symbol-file $$KERNEL_MODULE $$OFFSET\" \\",
			"    -ex \"file ./$$KERNEL_MODULE\" \\",
			"    -ex \"file $$EXPLOIT\" \\",
			"    -ex \"target remote:$$PORT\""
		],
		"description": "an extended template for gdb in linux kernel pwn"
	},
```

`exp.sh`调试板子：（编译`exploit`并启动环境）

```bash
	"exp": {
		"prefix": "exp",
		"body": [
			"FILE_NAME=\"${1:core.cpio}\"",
			"BOOT_SCRIPT=\"${2:boot.sh}\"",
			"",
			"gcc -o core/exploit ./exp.c -static -masm=intel -g",
			"cd core",
			"find . | cpio -o --format=newc > ../$$FILE_NAME",
			"cd ..",
			"./$$BOOT_SCRIPT"
		],
		"description": "a template for compiling and creating a cpio archive, then running a boot script"
	}
```

## 0x03. 无法打开/dev/ptmx，无法打开tty_struct结构体

有时候我们无法打开`/dev/ptmx`来获取到`tty_struct`结构体，表现为返回的`fd`为`-1`。

若发现`ls /dev/ptmx`发现该文件存在，而`cat /dev/ptmx`又发现该文件不存在，则说明`rcS`脚本里面，大概率没有挂载`pts`：

```bash
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
```

而`ptmx`在没有挂载该`pts`的时候是无法打开的。这和终端、伪终端有一定关系。

因此，无法打开是出题者刻意为之，此时需要寻找其它的结构体进行利用。

## 0x04. gadgets寻找相关问题

`Linux kernel`中的`gadgets`寻找相较于用户态会麻烦许多，而`ropper`和`ROPgadget`半斤八两。经过笔者测试，还是`ROPgadget`会好用许多（对比之下笔者在用户态更喜欢用`ropper`~）

例如，有的时候会面临，明明有这个`gadget`却寻找不到的问题。此时可以在`ROPgadget`中添加`--depth`参数：

```bash
ROPgadget --binary ./vmlinux --depth=20 > gadgets.txt
```

随后我们可以利用`grep`加上正则表达式快速匹配一些`gadgets`~

要在`grep`中使用正则表达式，可以加上`-E`参数，来支持扩展的正则表达式。

这里总结一些查找`gadget`的常用正则表达式：

```
.    匹配任意单个字符
.*   匹配任意数量的任意字符
^    匹配开头
$    匹配结尾
```

利用上面这些，我们便可以找到一些很难找到的`gadgets`。例如，匹配`add rsp, 0x18`这样的`gadgets`：

```bash
$ cat gadgets.txt| grep -E '.*: pop ... ; pop ... ; pop ... ; ret$'
0xffffffff81053164 : pop r12 ; pop rbp ; pop rbx ; ret
0xffffffff8267b9ab : pop r13 ; pop r14 ; pop rbp ; ret
0xffffffff8267b9ac : pop rbp ; pop r14 ; pop rbp ; ret
0xffffffff8267d549 : pop rbp ; pop rdx ; pop rcx ; ret
0xffffffff8267e408 : pop rbx ; pop rsi ; pop rbp ; ret
0xffffffff8267d6a9 : pop rsi ; pop rdi ; pop rbp ; ret
0xffffffff81053165 : pop rsp ; pop rbp ; pop rbx ; ret
```

如上，我们利用`.*: `匹配了前面地址部分，随后多次使用`pop ...`表示`pop`一个寄存器，最后`ret`后面使用`$`表示匹配结尾。

## 0x05. 内核崩溃时卡死 qemu不退出或重启

注意`qemu`启动脚本中，`-append`的如下选项：

```c
panic=1 oops=panic
```

开启之后即可让内核崩溃时触发`panic`。

而`panic`之后，若设置了`-no-reboot`则不会重启内核。

## 0x06. 通过内核堆上泄露程序基地址

内核堆地址`+0x9d000`处存放了函数`secondary_startup_64`函数的地址，可以通过该函数地址泄露程序基地址

## 0x07. 寻找modprobe_path地址

我们无法通过`cat /proc/kallsyms`来找到`modprobe_path`的地址。幸运的是，在`__request_module`中，存在一个对`modprobe_path`的引用。由此，我们可以从`/proc/kallsyms`中找到`__request_module`函数的地址，并使用`gdb`连接到`kernel`，查看该函数附近的汇编代码，即可找到`modprobe_path`的地址~

具体如下：

首先我们找到`__request_module`函数的地址：

![QQ_1722493258038](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011511350.png)

随后，我们让`gdb`连接到该`kernel`，设置`target remote:1234`即可，通过`x/40i`来查看刚刚获得的函数地址附近的代码：

![QQ_1722493343591](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011511409.png)

如上所示，箭头所指的地方就是`modprobe_path`的地址的引用。

通过如上方式，我们就可以获得`modprobe_path`的地址。

## 0x08. 回到用户态起shell的板子

没有开启`kpti`时如下所示：

```c
swapgs
iretq
user_shell_addr // the func that will be execute
user_cs
user_eflags // 64bit:user_rflags
user_sp
user_ss
```

开启时如下所示：

```c
↓   swapgs_restore_regs_and_return_to_usermode + 27
    0 // padding
    0 // padding
    user_shell_addr
    user_cs
    user_rflags
    user_sp
    user_ss
```

**值得注意的是：**

**我们知道`swapgs_restore_regs_and_return_to_usermode`函数需要加上一个偏移，具体来说该偏移不是固定的，需要跳过前面的栈操作，从`mov rdi, rsp`开始即可**

# 笔者自用kernel.h模板（到处抄的）

```c
#ifndef LTFALLKERNEL_H
#define LTFALLKERNEL_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <semaphore.h>


/**
 * 0x00. 基本函数
 */

size_t user_cs, user_ss, user_rflags, user_sp;
size_t kernel_base = 0xffffffff81000000, kernel_offset = -1;

/**
 * @ show basic information
 */
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

    exit(0);
}

void err_exit(char *buf)
{
    error(buf);
    exit(0);
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    info("Process binded to core %d.", core);
}

/**
 * 0x01. userfaultfd相关
 * 本部分全部抄自于arttnba3师傅
 */

/**
 * The MUSL also doesn't contain `userfaultfd.h` :(
 * Luckily we just need a bit of micros in exploitation,
 * so just define them directly is okay :)
 */

#define UFFD_API ((uint64_t)0xAA)
#define _UFFDIO_REGISTER (0x00)
#define _UFFDIO_COPY (0x03)
#define _UFFDIO_API (0x3F)

/* userfaultfd ioctl ids */
#define UFFDIO 0xAA
#define UFFDIO_API _IOWR(UFFDIO, _UFFDIO_API, \
                         struct uffdio_api)
#define UFFDIO_REGISTER _IOWR(UFFDIO, _UFFDIO_REGISTER, \
                              struct uffdio_register)
#define UFFDIO_COPY _IOWR(UFFDIO, _UFFDIO_COPY, \
                          struct uffdio_copy)

/* read() structure */
struct uffd_msg
{
    uint8_t event;

    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;

    union
    {
        struct
        {
            uint64_t flags;
            uint64_t address;
            union
            {
                uint32_t ptid;
            } feat;
        } pagefault;

        struct
        {
            uint32_t ufd;
        } fork;

        struct
        {
            uint64_t from;
            uint64_t to;
            uint64_t len;
        } remap;

        struct
        {
            uint64_t start;
            uint64_t end;
        } remove;

        struct
        {
            /* unused reserved fields */
            uint64_t reserved1;
            uint64_t reserved2;
            uint64_t reserved3;
        } reserved;
    } arg;
} __attribute__((packed));

#define UFFD_EVENT_PAGEFAULT 0x12

struct uffdio_api
{
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct uffdio_range
{
    uint64_t start;
    uint64_t len;
};

struct uffdio_register
{
    struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING ((uint64_t)1 << 0)
#define UFFDIO_REGISTER_MODE_WP ((uint64_t)1 << 1)
    uint64_t mode;
    uint64_t ioctls;
};

struct uffdio_copy
{
    uint64_t dst;
    uint64_t src;
    uint64_t len;
#define UFFDIO_COPY_MODE_DONTWAKE ((uint64_t)1 << 0)
    uint64_t mode;
    int64_t copy;
};

// #include <linux/userfaultfd.h>

char temp_page_for_stuck[0x1000];

void register_userfaultfd(pthread_t *monitor_thread, void *addr,
                          unsigned long len, void *(*handler)(void *))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
    {
        err_exit("userfaultfd");
    }

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    {
        err_exit("ioctl-UFFDIO_API");
    }

    uffdio_register.range.start = (unsigned long)addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    {
        err_exit("ioctl-UFFDIO_REGISTER");
    }

    s = pthread_create(monitor_thread, NULL, handler, (void *)uffd);
    if (s != 0)
    {
        err_exit("pthread_create");
    }
}

void *uffd_handler_for_stucking_thread(void *args)
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

        /* just stuck there is okay... */
        sleep(100000000);

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

        uffdio_copy.src = (unsigned long long)temp_page_for_stuck;
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

void register_userfaultfd_for_thread_stucking(pthread_t *monitor_thread,
                                              void *buf, unsigned long len)
{
    register_userfaultfd(monitor_thread, buf, len,
                         uffd_handler_for_stucking_thread);
}

/**
 * 0x02. keyctl相关
 * 本部分仍然就是摘录于arttnba3师傅的博客
 */

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


#endif // LTFALLKERNEL_H

```

