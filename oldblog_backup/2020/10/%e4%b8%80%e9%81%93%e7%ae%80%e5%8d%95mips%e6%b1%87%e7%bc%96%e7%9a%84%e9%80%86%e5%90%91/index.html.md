---
layout: post
title: 一道简单mips汇编的逆向
date: 2020-10-13
tags: ["逆向"]
---

[toc]
爷今儿遇见一道mips汇编，没管别的用ida打开，是这样的：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_568b30ae091cbb5e502a3ff09fbdb373.jpg)](wp_editor_md_568b30ae091cbb5e502a3ff09fbdb373.jpg)
f5反编译，结果提示不能反编译mips的这种文件······
搜了一下也有这种插件，反正俺没有装。

## 前置知识

*   mips汇编
有个dailao的[博客](https://www.cnblogs.com/thoupin/p/4018455.html "博客")写得好
*   mips汇编指令集
另一个dailao的[博客](https://blog.csdn.net/ben_chong/article/details/51794093#comments_12600614 "博客")写得好
*   没了

## 解题

### 分析程序结构

看图把
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_bfe84736d5342d88d0d0221be4a4733c.jpg)](wp_editor_md_bfe84736d5342d88d0d0221be4a4733c.jpg)

### 分析Mips代码

放一下前面的变量值：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_a2f077b19284351eab1e00deeae1261a.jpg)](wp_editor_md_a2f077b19284351eab1e00deeae1261a.jpg)
把关键函数部分的代码分析得：
（试了半天没有高亮，难受）

    loc_4013C8:
    lui     $v0, 0x4A        # 把0x4A放到v0寄存器高十六位
    addiu   $v1, $v0, (meow - 0x4A0000)  # "cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ"
    # v1 = vo + (meow - 0x4A0000),即v1存放meow的偏移量
    lw      $v0, 0x28+var_10($fp)  # 据说是取出循环的i值
    addu    $v0, $v1, $v0    # 这样v0就存放第一个字符的偏移量
    lb      $v1, 0($v0)      # v1等于第一个字符
    lw      $v0, 0x28+arg_4($fp)  # 后面不想写了 嘻嘻
    addiu   $v0, 4           # Add Immediate Unsigned
    lw      $a0, 0($v0)      # Load Word
    lw      $v0, 0x28+var_10($fp)  # Load Word
    addu    $v0, $a0, $v0    # Add Unsigned
    lb      $v0, 0($v0)      # Load Byte
    xori    $v0, 0x37        # Exclusive OR Immediate
    sll     $v0, 24          # Shift Left Logical
    sra     $v0, 24          # Shift Right Arithmetic
    beq     $v1, $v0, loc_401428  # Branch on Equal
    move    $at, $at

读完发现就是，字符串meow的每一位异或0x37，就可以得到答案了
即TUCTF{but_really_whoisjohngalt}