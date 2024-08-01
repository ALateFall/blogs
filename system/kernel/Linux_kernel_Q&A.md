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

