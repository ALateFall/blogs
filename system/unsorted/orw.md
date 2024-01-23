---
layout: post
title: 除你execve：ORW(Open-Read-Write)小记
category: system/unsorted
date: 2023-9-21 12:00:00
---
ORW
<!-- more -->

[toc]


若程序使用了沙箱机制，例如`seccomp`，可能会禁用`execve`的系统调用，此时我们便只能使用`ORW(open read write)`的系统调用来读取`flag`文件。

# 查看沙箱：seccomp-tools

```bash
seccomp-tools dump ./file
```

# ropper工具的使用

类似于`ROPgadgets`，`ropper`也可查找`gadgets`，但`ROPgadgtes`有时候无法查找到某些`gadgets`，而且`ropper`的速度相对来说会快一些。

可以直接在搜索`gadgets`：

```bash
ropper --file ./libc.so.6 --search pop rax
```

或者是进入`ropper`，然后使用`ropper`内置的终端加载要查找的文件，连续查找`gadgets`，就不需要多次读取文件内的`gadgets`了：

```bash
ropper # 进入内置的ropper终端
file ./libc.so.6 # 加载要搜索gadgets的文件
search rdi
search rsi
```

# open函数

若我们要发起一个`open`函数的系统调用，自然首先需要明白它的各个参数。详细信息如下：

```C
int open(const char *filename, int flags, mode_t mode);
```

其中，第一个参数`filename`，也就是`rdi`对应的内容，我们填写为字符串类型的要打开的文件名即可。

第二个参数为`flags`，即读写模式，若读文件则设置为`0`，若写文件则设置为`1`，读写文件设置为`2`。

第三个参数在`ORW`中我们一般可以不填。

此外，`open`函数的系统调用号`rax`为`2`。

# open系统调用被禁用

尝试使用`openat()`函数，它的系统调用号是`257`，可以`syscall`调用也可以直接`libc`调用

```c
int openat(int dirfd, const char *pathname, int flags, ...);
```

只需要写`openat(0, '/flag\x00')`的形式即可

# write函数/read函数

这两个函数比较常用，此处不再赘述。

# setcontext函数

## 低版本（glibc 2.27及以下）

在低版本的`glibc`中，`setcontext`中有一段`gadgets`如下：

```assembly
<setcontext+53>:  mov    rsp,QWORD PTR [rdi+0xa0] *
<setcontext+60>:  mov    rbx,QWORD PTR [rdi+0x80]
<setcontext+67>:  mov    rbp,QWORD PTR [rdi+0x78]
<setcontext+71>:  mov    r12,QWORD PTR [rdi+0x48]
<setcontext+75>:  mov    r13,QWORD PTR [rdi+0x50]
<setcontext+79>:  mov    r14,QWORD PTR [rdi+0x58]
<setcontext+83>:  mov    r15,QWORD PTR [rdi+0x60]
<setcontext+87>:  mov    rcx,QWORD PTR [rdi+0xa8] *
<setcontext+94>:  push   rcx
<setcontext+95>:  mov    rsi,QWORD PTR [rdi+0x70]
<setcontext+99>:  mov    rdx,QWORD PTR [rdi+0x88]
<setcontext+106>: mov    rcx,QWORD PTR [rdi+0x98]
<setcontext+113>: mov    r8,QWORD PTR [rdi+0x28]
<setcontext+117>: mov    r9,QWORD PTR [rdi+0x30]
<setcontext+121>: mov    rdi,QWORD PTR [rdi+0x68]
<setcontext+125>: xor    eax,eax
<setcontext+127>: ret
```

可以看到，该版本的`setcontext`函数在`<setcontext+53>`处时可以通过`rdi`控制几乎所有的寄存器。但是`rdi`又如何控制呢？

我们可以想到，`rdi`是函数的第一个参数，因此若我们控制`__free_hook`为`<setcontext+53>`，就可以在`free`的时候将程序劫持到`<setcontext+53>`。那么应该如何布置地址空间，才能让我们彻底控制程序执行流程呢？

观察这一段`gadgets`，发现在`<setcontext+53>`处控制了`rsp`为`[rdi+0xa0]`，随后在`<setcontext+87>`处`push`了`[rdi+0xa8]`。相当于说是把栈迁移到了`[rdi+0xa0]`处，然后再往栈里面`push`了一个值`[rdi+0xa8]`。若我们控制`[rdi+0xa8]`为`ret`，那么即可使得程序执行`[rdi+0xa0]`了，也就是控制了程序执行的流程。那么，如何才能劫持`[rdi+0xa0]`的值呢？

现在来看：

```c
// 首先假设已经劫持__free_hook为setcontext+53
// 我们执行：
free(chunk_a);
// 假设chunk_a的地址为0x5630f8b000
// 那么由于本来会执行：
mov rsp, [rdi + 0xa0];
// 实际上即：
mov rsp, [0x5630f8b000 + 0xa0];
// 即：
mov rsp, [0x5630f8b0a0];
// 即意味着我们只需要控制chunk_a偏移0xa0的地方的chunk，就是控制了上面提到的`[rdi+0xa0]`。以这里为例子继续看：
// 假设chunk_b的地址为0x5630f8b0a0，我们已经对其进行了控制
// chunk_b存放的内容为：p64(addr_of_orw_gadgets) p64(retn)
// 程序继续执行到<setcontext+87>，即：
mov rcx, [rdi+0xa8];
// 即
mov rcx, [0x5630f8b0a8];
// 我们知道0x5630f8b0a8处的内容为retn，那么会pop rip,程序开始执行orw_gadgets。
```

## glibc 2.29

该版本开始，`setcontext`中使用的就不是`rdi`来对寄存器进行设置了，而是使用的`rdx`。因此从这个版本开始，需要使用额外的`gadget`来通过`rdi`控制`rdx`，后面的步骤不变。这个版本的`setcontext`为：

```assembly
.text:0000000000055E35                 mov     rsp, [rdx+0A0h]
.text:0000000000055E3C                 mov     rbx, [rdx+80h]
.text:0000000000055E43                 mov     rbp, [rdx+78h]
.text:0000000000055E47                 mov     r12, [rdx+48h]
.text:0000000000055E4B                 mov     r13, [rdx+50h]
.text:0000000000055E4F                 mov     r14, [rdx+58h]
.text:0000000000055E53                 mov     r15, [rdx+60h]
.text:0000000000055E57                 mov     rcx, [rdx+0A8h]
.text:0000000000055E5E                 push    rcx
.text:0000000000055E5F                 mov     rsi, [rdx+70h]
.text:0000000000055E63                 mov     rdi, [rdx+68h]
.text:0000000000055E67                 mov     rcx, [rdx+98h]
.text:0000000000055E6E                 mov     r8, [rdx+28h]
.text:0000000000055E72                 mov     r9, [rdx+30h]
.text:0000000000055E76                 mov     rdx, [rdx+88h]
.text:0000000000055E7D                 xor     eax, eax
.text:0000000000055E7F                 retn
```

`glibc2.29`下一般使用这个`gadget`：

```assembly
mov rdx, qword ptr [rdi + 8]; mov rax, qword ptr [rdi]; mov rdi, rdx; jmp rax;
```

## glibc 2.30

同样，但这个版本使用的`gadget`一般为：

```assembly
mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
```

此外也可能是`setcontext+61`，`setcontext+61`为：

```assembly
.text:000000000005803D                 mov     rsp, [rdx+0A0h] *
.text:0000000000058044                 mov     rbx, [rdx+80h]
.text:000000000005804B                 mov     rbp, [rdx+78h]
.text:000000000005804F                 mov     r12, [rdx+48h]
.text:0000000000058053                 mov     r13, [rdx+50h]
.text:0000000000058057                 mov     r14, [rdx+58h]
.text:000000000005805B                 mov     r15, [rdx+60h]
.text:0000000000058126                 mov     rcx, [rdx+0A8h] * 
.text:000000000005812D                 push    rcx             *
.text:000000000005812E                 mov     rsi, [rdx+70h]
.text:0000000000058132                 mov     rdi, [rdx+68h]
.text:0000000000058136                 mov     rcx, [rdx+98h]
.text:000000000005813D                 mov     r8, [rdx+28h]
.text:0000000000058141                 mov     r9, [rdx+30h]
.text:0000000000058145                 mov     rdx, [rdx+88h]
.text:000000000005814C                 xor     eax, eax
.text:000000000005814E                 retn
```

## glibc2.31

这个版本的`gadget`和上面一样，但是变为了`setcontext+61`

# 通过_environ获取栈地址

在`orw`时，除了可以通过`setcontext`以外，还可以通过`_environ`来获得栈地址。`libc`中的`_environ`中存放了一个栈地址，该栈地址中存放的是环境变量的地址，因此知道`libc`地址的情况可以通过`_environ`来获取栈的地址，从而控制程序执行流。如下所示：

```python
libc.address = 0x7fxxxxxx
_environ = libc.sym['_environ']
# _environ中存放了栈地址
```

