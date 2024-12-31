---
layout: post
title: 0x07. Linux kernel基础：保护机制驱动
category: kernel pwn
date: 2024-10-17 15:00:00

---

啊？
<!-- more -->

[toc]

# Linux kernel之保护机制驱动

## 0x00. 前言

在`kernel pwn`的题目中，我有时希望知道题目内核有哪些保护，未开启哪些保护，而通过题目功能来测试的话，有时候比较复杂，且事先知道开启了哪些保护的话，能便于我们构建好解决题目的思路。

因此，若内核下有`checksec`这样直接查看开启了哪些保护的程序就好了！如此我们可以便捷地知道开启了哪些保护。

本项目由此想法而生：我们事先写好一个驱动，然后注册到题目给定的内核里面，通过交互来尝试不就可以知道开启了哪些保护么。

想必互联网上已经由很多这样的项目，笔者写的只是一个玩具`demo`，望海涵。

## 0x01. 驱动构建

编写如下代码：

```c
/*
 * checksec.c
 * developed by ltfall
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/gfp.h>

#define DEVICE_NAME "ltdevice"
#define DEVICE_PATH "/dev/ltdevice"
#define CLASS_NAME "ltmodule"

static int major_num;
static struct class *module_class = NULL;
static struct device *module_device = NULL;
struct inode *__inode = NULL;
static void *buffer[0x20];

static long ltfall_ioctl(struct file *__file, unsigned int cmd, unsigned long param);
static int ltfall_open(struct inode *, struct file *);
static int ltfall_release(struct inode *, struct file *);
static ssize_t ltfall_read(struct file *__file, char __user *user_buf, size_t size, loff_t *loff);
static ssize_t ltfall_write(struct file *__file, const char __user *user_buf, size_t size, loff_t *loff);

static struct file_operations lt_module_fo =
    {
        .owner = THIS_MODULE,
        .unlocked_ioctl = ltfall_ioctl,
        .open = ltfall_open,
        .read = ltfall_read,
        .write = ltfall_write,
        .release = ltfall_release,
};

static int __init kernel_module_init(void)
{
    printk(KERN_ALERT "[ltfall] Module Loaded, Start to Register device...\n");

    // 第一步：注册字符型设备
    // register_chrdev(unsigned int major, const char* name, const struct file_operations* fops);
    major_num = register_chrdev(0, DEVICE_NAME, &lt_module_fo);

    if (major_num < 0)
    {
        printk(KERN_ALERT "[ltfall] Failed to register a major number.\n");
        return major_num;
    }
    printk(KERN_ALERT "[ltfall] Register complete, major number : %d.\n", major_num);

    // 第二步：创建设备类
    // struct class *class_create(struct module *owner, const char *name);
    module_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(module_class))
    {
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_ALERT "[ltfall] Failed to register class device!\n");
        return PTR_ERR(module_class);
    }
    printk(KERN_ALERT "[ltfall] Class device register complete.\n");

    // 第三步：创建设备节点并在/dev目录下生成设备节点文件
    // device_create(struct class *cls, struct device* parent, dev_t devt, void* drvdata, const char *fmt);
    // cls: 设备的设备类
    // parent: 父设备节点，为顶级设备时填写为NULL
    // devt: 设备的设备号
    // drvdata: 驱动相关信息
    // fmt: 设备名称
    module_device = device_create(module_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
    if (IS_ERR(module_device))
    {
        class_destroy(module_class);
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_ALERT "[ltfall] Failed to create the device!\n");
        return PTR_ERR(module_device);
    }
    printk(KERN_ALERT "[ltfall] Module register complete.\n");

    return 0;
}

static void __exit kernel_module_exit(void)
{
    printk(KERN_ALERT "[ltfall] Start to clean up the module.\n");
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_ALERT "[ltfall] Module clean up complete.\n");
}

static int ltfall_open(struct inode *node, struct file *__file)
{
    printk(KERN_ALERT "[ltfall] Open device successfully!\n");
    return 0;
}

static int ltfall_release(struct inode *node, struct file *__file)
{
    printk(KERN_ALERT "[ltfall] Release device successfully!\n");

    return 0;
}

typedef struct
{
    int index;
    int flag;
    int size;
    size_t addr;
    char *content;
} alloc;

static long ltfall_ioctl(struct file *__file, unsigned int cmd, unsigned long param)
{
    alloc *chunk = (alloc *)param;
    size_t value = 0;

    printk(KERN_ALERT "[ltfall] Your choice number is %d.\n", cmd);

    if (cmd == 0x10000)
    {
        // 申请chunk
        buffer[chunk->index] = kmalloc(chunk->size, chunk->flag);
        printk(KERN_ALERT "[ltfall] The address of alloc obj is 0x%px.\n", buffer[chunk->index]);
        value = copy_to_user((char*)&chunk->addr, &buffer[chunk->index], 8);
    }
    else if (cmd == 0x10001)
    {
        // 释放chunk
        kfree(buffer[chunk->index]);
        printk(KERN_ALERT "[ltfall] Kfree %d down.\n", chunk->index);
    }
    else if (cmd == 0x10002)
    {
        // 任意地址读
        size_t address = *(size_t *)chunk->addr;
        printk(KERN_ALERT "[ltfall] The value of your requiered address 0x%lx is 0x%lx, as %s.\n", chunk->addr, address, (char*)chunk->addr);
        value = copy_to_user((char*)&(chunk->addr), (char *)&address, 8);
    }
    else if (cmd == 0x10003)
    {
        // read
        value = copy_from_user(buffer[chunk->index], chunk->content, chunk->size);
        printk(KERN_ALERT "[ltfall] Read Successfully.\n");
    }
    else if (cmd == 0x10004)
    {
        // write
        value = copy_to_user(chunk->content, buffer[chunk->index], chunk->size);
        printk(KERN_ALERT "[ltfall] Write Successfully.\n");
    }

    return 0;
}

static ssize_t ltfall_read(struct file *__file, char __user *user_buf, size_t size, loff_t *loff)
{
    return 0;
}

static ssize_t ltfall_write(struct file *__file, const char __user *user_buf, size_t size, loff_t *loff)
{

    return 0;
}

module_init(kernel_module_init);
module_exit(kernel_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ltfall");
```

使用如下`makefile`来编译：

```makefile
obj-m += checksec.o

EXTRA_CFLAGS += -g -O0

CURRENT_PATH := $(shell pwd)
LINUX_KERNEL := 5.11.0
LINUX_KERNEL_PATH := /kernel/kernel_source/linux-5.11

all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
```

随后通过命令`make`，即可获得一个含有多功能的驱动`checksec.ko`~。

## 0x02. 交互代码编写

由于内核态下难以进行打开结构体等操作，我们主要的测试代码还是放到用户态来运行。

这里给出代码：

（现在只有框架）

```c
#include "ltfallkernel.h"

#define ADD 0x10000
#define DELETE 0x10001
#define SHOW 0x10002
#define READ 0x10003
#define WRITE 0x10004

#define GFP_KERNEL 0xcc0
#define GFP_KERNEL_ACCOUNT 0x400000
#define GFP_ATOMIC 0xa20

/**
 * 本exp用于与测试驱动交互，便于测试各项保护
 */

int fd;

typedef struct
{
    int index;
    int flag;
    int size;
    size_t addr;
    char *content;
} alloc;

size_t add(int index, int size, int flag)
{
    alloc chunk = {
        .index = index,
        .size = size,
        .flag = flag};
    ioctl(fd, ADD, &chunk);
    return chunk.addr;
}

void delete(int index)
{
    alloc chunk = {
        .index = index};
    ioctl(fd, DELETE, &chunk);
}

size_t show(size_t addr)
{
    alloc chunk = {
        .addr = addr};
    ioctl(fd, SHOW, &chunk);
    return chunk.addr;
}

void read_chunk(int index, int size, char *content)
{
    alloc chunk = {
        .index = index,
        .size = size,
        .content = content};
    ioctl(fd, READ, &chunk);
}

void write_chunk(int index, int size, char *content)
{
    alloc chunk = {
        .index = index,
        .size = size,
        .content = content};
    ioctl(fd, WRITE, &chunk);
}

void init()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main()
{

    info("Start to checksec...");
    init();
    save_status();
    bind_core(0);

    fd = open("/dev/ltdevice", 2);
    if (fd < 0)
    {
        err_exit("Failed to open test device, check if you insmod!");
    }

    success("Testing if GFP_KERNEL_ACCOUNT and GFP_KERNEL merge...");

    int merge_flag = 0;
    for (int i = 0; i < 3; i++)
    {
        size_t addr1 = add(0, 0x100, GFP_KERNEL);
        delete (0);
        size_t addr2 = add(0, 0x100, GFP_KERNEL_ACCOUNT);
        if (addr1 == addr2)
        {
            merge_flag = 1;
        }
    }
    if(merge_flag){
        success("GFP_KERNEL_ACCOUNT and GFP_KERNEL merge!");
    }else{
        success("GFP_KERNEL_ACCOUNT and GFP_KERNEL not merge!");
    }

    return 0;
}
```

## 0xFF. 在不用版本的内核中编译驱动

很遗憾的是，编译出来的驱动是针对我指定的`linux`内核版本的，这意味着若我将驱动放到不同版本的`linux`内核中，只能借助不同版本的`linux`内核源码。

我们可以通过如下步骤来完成源码的准备：

下载源码：

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.4.72.tar.xz
```

解压：

```bash
tar -xvf ./linux-4.4.72.tar.xz
```

切换到目录，并生成默认配置`.config`：

```bash
make defconfig
```

准备好编译所需的头文件：

```bash
make prepare
make modules_prepare
```

如此一来，我们就可以在`makefile`中指定该源码文件夹来进行编译。



