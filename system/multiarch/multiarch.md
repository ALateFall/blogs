[toc]

# 架构速通

参考如下文章：

[mips_arm汇编学习 | Note (gitbook.io)](https://b0ldfrev.gitbook.io/note/iot/mipsarm-hui-bian-xue-xi)

[HWS赛题 入门 MIPS Pwn | Clang裁缝店 (xuanxuanblingbling.github.io)](https://xuanxuanblingbling.github.io/ctf/pwn/2020/09/24/mips/)

# qemu安装

```bash
sudo apt install qemu qemu-system qemu-user-static binfmt-support
```

# mips

## 使用工具

- `gdb-multiarch`
- `qemu-mipsel-static`

## shell中如何调试

假设我们需要调试`./mips`，那么开启两个`shell`，第一个`shell`执行如下命令：

```bash
# 若程序是动态链接
qemu-mipsel-static -L /usr/mips-linux-gnu -g 1234 ./mips
# -L /usr/mips/linux/gnu 表示动态链接库
# 例如，我的动态链接需要文件/lib/ld-linux-armhf.so.3，而题目给了这个lib文件夹，
# 那么我们就将lib文件夹放在当前文件夹，随后通过 -L ./ 来启动程序
# -g 1234 表示支持gdb调试连接，端口为1234

# 若程序是静态链接
qemu-mipsel-static -g 1234 ./mips
```

运行后程序不会有任何输出，而会直接暂停，并暴露在端口`1234`上等待调试连接。

此时，在第二个`shell`中，输入以下命令：

```bash
gdb-multiarch ./mips
```

通过以上命令启动`gdb`后，输入以下命令设置`mips`架构：

```bash
set architecture mips
```

输入以下命令连接到程序：

```bash
target remote:1234
```

此时`gdb`就已经连接到`mips`程序，接下来只需要和正常程序一样下断点调试即可。

此外需要注意，`mips`程序没有`call`指令，因此我的尝试中`ni`是无效的，我的做法是直接下断点到函数之后。

## pwntools中如何调试

和正常情况的区别是要在脚本中设置如下架构相关的设置：

```python
context.arch='mips'
context.os='linux'
```

启动程序需要通过如下方式：

```python
sh = process(['qemu-mipsel-static', '-L', '/usr/mips-linux-gnu', filename])
```

若需要进行调试，那么使用如下方式：

```python
sh = process(['qemu-mipsel-static', '-L', '/usr/mips-linux-gnu', '-g', '1234', filename])
```

## 如何寻找gadget

可以使用`mipsrop`，这是一个`ida`插件，我目前还没有使用过。

除此之外还可以使用`ropper`，和`x86`的`gadget`寻找方式一样。

寄存器名称和作用如下所示：

![image-20240409102655311](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20240409102655311.png)

## shellcode

可以使用`shellcraft`，例如：

```python
shellcraft.mips.linux.sh()
```

若报错提示安装库，根据给的`url`安装即可。

`mips`安装方法如下：

```bash
sudo apt install binutils-mips-linux-gnu binutils-mips-linux-gnu-dbg
```

记录一个较短的`shellcode`如下：

```python
shellcode = '''
lui $t6,0x6e69
ori $t6,$t6,0x622f
sw $t6,28($sp)

lui $t7,0x6873
ori $t7,$t7,0x2f2f
sw $t7,32($sp)
sw $zero,36($sp) 

la $a0,28($sp)

addiu $a1,$zero,0
addiu $a2,$zero,0
addiu $v0,$zero,4011

syscall 0x40404
'''
shellcode = asm(shellcode)
```

# arm

调试方面都和`mips`大差不差。

`winmt`师傅的[文章](https://bbs.kanxue.com/thread-272332.htm)，推荐阅读

使用`rizzo`[插件](https://github.com/Reverier-Xu/Rizzo-IDA/blob/main/rizzo.py)修复静态编译的程序表

`pwntools`仍然需要安装以下库：

```bash
sudo apt install binutils-arm-linux-gnueabi binutils-arm-linux-gnueabi-dbg libc6-armhf-cross
```

若程序为动态链接，通过如下方式来运行程序：

```bash
qemu-arm-static -L /usr/arm-linux-gnueabihf/ ./program
```

寄存器如下所示，其中系统调用需要使用`svc #0`指令。

此外，`r0-r3`等寄存器为参数，`r7`寄存器存放系统调用号类似于`x86`的`rax`。

![image-20240409105241751](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20240409105241751.png)

## ROP

`arm`的`ROP`方式和`x86`非常类似，可以用`ropper`搜索如下：

```bash
(arm/ELF/ARM)> search pop {%, pc}
[INFO] Searching for gadgets: pop {%, pc}

[INFO] File: ./arm
0x0001056c: pop {fp, pc};
0x00060fb8: pop {pc}; push {r4, lr}; bl #0x50ba4; ldr r0, [r0, #0x48]; pop {r4, pc};
0x0005f73c: pop {r0, pc};
0x00026634: pop {r0, r4, pc};
0x0005f824: pop {r1, pc};
0x0005f810: pop {r2, r3}; bx lr; push {r1, lr}; mov r0, #8; bl #0x2888c; pop {r1, pc};
0x00010160: pop {r3, pc};
0x00014264: pop {r3, r4, r5, r6, r7, r8, sb, sl, fp, pc};
0x00024ac4: pop {r3, r4, r5, r6, r7, r8, sb, sl, fp, pc}; mov r1, lr; mov r0, r8; blx r3;
0x00024278: pop {r4, lr}; b #0xf784; add sp, sp, #8; pop {r4, pc};
0x00024278: pop {r4, lr}; b #0xf784; add sp, sp, #8; pop {r4, pc}; mov r1, lr; bx r3;
0x0005b500: pop {r4, lr}; mov r0, r0; ldr r3, [pc, #0x38]; cmp r3, #0; bne #0x4b4fc; pop {r4, pc};
0x000104e0: pop {r4, pc};
0x00052e54: pop {r4, pc}; andeq fp, r8, r4, lsr #10; ldr r0, [r0]; bx lr;
0x000582d0: pop {r4, pc}; ldr r3, [pc, #0x14]; add r2, r3, #4; str r2, [r3]; bx lr;
0x000527ac: pop {r4, pc}; ldrb r3, [r1]; rsb r0, r3, #0; bx lr;
0x000527a4: pop {r4, pc}; mov r0, #1; pop {r4, pc}; ldrb r3, [r1]; rsb r0, r3, #0; bx lr;
0x00024284: pop {r4, pc}; mov r1, lr; bx r3;
0x0001d698: pop {r4, r5, pc};
0x00061fcc: pop {r4, r5, r6, lr}; b #0x141c4; andeq fp, r8, ip, lsl sb; push {r3, lr}; pop {r3, pc};
0x00011240: pop {r4, r5, r6, pc};
0x0004dcf4: pop {r4, r5, r6, pc}; ldr r3, [pc, #0x30]; ldr r3, [r3]; blx r3;
0x000535fc: pop {r4, r5, r6, pc}; ldr r3, [sp]; mov r0, r2; mov r4, r3; str r3, [r6, r5]; blx r1;
0x0001d880: pop {r4, r5, r6, pc}; mov r0, #0; bx lr;
0x0004dd0c: pop {r4, r5, r6, pc}; mvn r2, #0; mov r0, r2; bx lr;
0x00010970: pop {r4, r5, r6, r7, pc};
0x000198bc: pop {r4, r5, r6, r7, r8, fp, pc};
0x00023f84: pop {r4, r5, r6, r7, r8, lr}; b #0x13b8c; mov r5, #0; mov r0, r5; pop {r4, r5, r6, r7, r8, pc};
0x000110dc: pop {r4, r5, r6, r7, r8, pc};
0x00020d0c: pop {r4, r5, r6, r7, r8, pc}; blx r3;
0x00020cb0: pop {r4, r5, r6, r7, r8, pc}; ldr r3, [r6, #0x4a0]; rsb r0, r5, #0; blx r3;
0x00023cd0: pop {r4, r5, r6, r7, r8, pc}; mov r1, lr; bx r3;
0x00023f94: pop {r4, r5, r6, r7, r8, pc}; mov r3, r4; pop {r4, r5, r6, r7, r8, lr}; bx r3;
0x00026f2c: pop {r4, r5, r6, r7, r8, sb, fp, pc};
0x000196a8: pop {r4, r5, r6, r7, r8, sb, pc};
0x00010c1c: pop {r4, r5, r6, r7, r8, sb, sl, fp, pc};
0x000597cc: pop {r4, r5, r6, r7, r8, sb, sl, fp, pc}; ldr r3, [pc, #0xc]; ldr r3, [r3]; blx r3;
0x0002bf70: pop {r4, r5, r6, r7, r8, sb, sl, fp, pc}; mov r0, #8; bx lr;
0x000245cc: pop {r4, r5, r6, r7, r8, sb, sl, fp, pc}; mov r2, lr; mov r3, r4; add sp, sp, #4; pop {r4, r5, r6, r7, r8, sb, sl, fp, lr}; bx r3;
0x00010d9c: pop {r4, r5, r6, r7, r8, sb, sl, pc};
0x0001e6c4: pop {r4, r5, r6, r7, r8, sb, sl, pc}; mvn r0, #0; mvn r1, #0; bx lr;
0x0005d1ac: pop {r4, r5, r6, r7, r8, sl, pc};
0x0001c590: pop {r4, r5, r7, pc};
0x0001b884: pop {r4, r6, r7, pc};
0x000280a4: pop {r4, r7, pc};
0x00027d78: pop {r7, pc};
```

其中例如`pop {r7, pc}`和`pop rax; ret`并无区别，相信你一定能理解。





