---
layout: post
title: 栈溢出最基本的ret2xxx
category: system/StackOverflow
date: 2023-9-20 12:00:00
---
栈溢出基础知识点
<!-- more -->
# ret2system

若反汇编出得来的文件中既含有`system()`函数，也含有`/bin/sh`这个参数，那可以直接将返回的地址处的栈构造成这种方式：（此处我们压入栈里面的是`_system()`函数的地址，因此需要函数的返回地址）

|           &(/bin/sh)         |

|   ret add of _system  |

|            &(_system)      |

此外，需要注意的是，若我们返回到的地址是`call _system`这种使用`call`来调用某个函数的形式，是不需要在栈里面压入返回地址的，因为`call`这种调用方式会自动执行这个操作，执行完毕后会自动继续执行。如图：

|           &(/bin/sh)       |

|     &(call _system)     |

# ret2shellcode

个人感觉是必须有可读部分，且NX保护不能开。（开了还执行个der的shellcode

![image-20221025202358102](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211722878.png)

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))
sh.interactive()
```

# ret2syscall

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