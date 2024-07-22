---
layout: post
title: excluded
category: system/kernel
date: 2024-7-20 14:00:00
exclude: true
---

Linux kernel基础：Kernel 

[TOC]



# Q & A

这里用于记录一些`Linux Kernel Pwn`中遇到的各种问题。

## 0x00. 成功执行提权函数，但没有获得root权限的shell

问题表现于如上所示，或者是一些其它的奇怪症状。

可以在`gcc`编译时通过加上编译参数`-Os`，或者例如`-O0`等优化选项都可以试试，推测是由于优化选项带来的问题。

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



