---
layout: post
title: 0x03. Linux kernel基础：条件竞争
category: system/kernel
date: 2024-7-20 15:00:00
---
Linux kernel基础：条件竞争

[toc]

# Linux kernel之条件竞争

在用户态下，若看到某个程序使用了多线程，那么我们往往会考虑该程序的利用方式是否是条件竞争。而在内核态下，用户可以非常便捷地编写多线程，因此内核驱动的锁若使用不当，或者根本没有加锁，那么就可以使用条件竞争来进行漏洞利用。

## 0x00. 基础知识

### 锁

学过《操作系统》的师傅可能并不会对锁感到陌生。锁能够防止多个进程同时使用某些资源，或者进入临界区。而若锁使用不当时，就会造成各种意料之外的结果，或是在`Linux kernel pwn`中受到条件竞争的攻击。

这里先列出各种锁和其使用范围：

| 锁类型                   | 允许的并发数（读操作） | 允许的并发数（写操作） |
| ------------------------ | ---------------------- | ---------------------- |
| 自旋锁 (Spinlock)        | 1                      | 1                      |
| 读写锁 (Read-Write Lock) | 多个（读锁）           | 1（写锁）              |
| 互斥锁 (Mutex)           | 1                      | 1                      |
| 信号量 (Semaphore)       | 可配置                 | 可配置                 |
| RCU (Read-Copy Update)   | 多个（读操作）         | 1（更新操作）          |
| 顺序锁 (Seqlock)         | 多个（可能需要重试）   | 1                      |

可以看到，只有互斥锁`mutex`以及自旋锁`spinlock`能够严格要求只能有一个进程进入临界区。而其它种类的锁若使用不当，则容易出现漏洞。例如，对于读写锁`read-write lock`，其中若使用写锁，则能够严格控制只有一个进程进入临界区，而若使用读锁，则能够有**多个进程进入临界区**，此时就容易出现漏洞。

### 多进程

通过`C`语言在用户态下编写多进程的代码是相对比较容易的，这里笔者向师傅复习一下`C`语言多进程的实现方式：

```c
#include <pthread.h>

// 我们主要通过pthread_create函数来创建多进程
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
```

其中：

- 第一个参数为指向线程标识符的指针，相当于`pid`。
- 第二个参数为指向线程属性对象的指针，例如线程的堆栈大小等，我们一般填`NULL`即可。
- 第三个参数为线程执行的函数。填函数名即可。
- 第四个参数为线程执行的参数。

因此，我们通过如下方式来创建多进程函数即可：

```c
#include <stdio.h>
#include <pthread.h>

// 注意这个函数是void*
void* hello(void* args) // 参数为void* args
{
    printf("Hello world from thread 2!\n");
}

int main()
{
    pthread_t new_thread;
    pthread_create(&new_thread, NULL, hello, NULL);
    printf("Hello world from main thread!\n");
    return 0;
}
```

### 信号量

信号量也是操作系统中经常提到的概念。而信号量我们能够用来做什么呢？用法其实多种多样。例如，我们可以使用信号量来控制多个线程的先后执行顺序——以便于我们进行条件竞争。

先来看信号量的使用方法。

定义信号量：

```c
#include <semaphore.h>

sem_t signal1, signal2;
```

初始化信号量：

```c
sem_init(&signal1, 0, 0);
sem_init(&signal2, 0, 0);
```

获取一个信号量，若没有则等待：

```c
sem_wait(&signal1);
```

释放一个信号量，使得信号量`+1`：

```c
sem_post(&signal1);
```

因此，我们通过一个多线程的例子，来理清信号量的使用方法：

```c
#include <semaphore.h>
#include <pthread.h>
#include <stdio.h>

// 定义两个信号量
sem_t signal_hello, signal_bye;
// 定义两个线程标识符
pthread_t thread_hello, thread_bye;

// 线程1：hello，输出hello, world
void* hello(void* args)
{
    // 获取到signal_hello才继续执行
    sem_wait(&signal_hello);
    printf("Hello, world!\n");
}

// 线程2：bye，输出bye bye
void* bye(void* args)
{
    // 获取到信号量signal_bye才继续执行
    sem_wait(&signal_bye);
    printf("bye bye!\n");
}

int main()
{
    // 使用信号量前，需要先进行初始化
    sem_init(&signal_hello, 0, 0);
    sem_init(&signal_bye, 0, 0);
    
    // 创建两个线程
    // 由于两个线程内部都有sem_wait，因此都不会立即输出
    pthread_create(&thread_hello, NULL, hello, NULL);
    pthread_create(&thread_bye, NULL, bye, NULL);
    
    // signal_hello信号量+1，因此立即输出helloworld
    sem_post(&signal_hello);
    
    sleep(1);
    
    // signal_bye信号量+1，因此立即输出bye bye
    sem_pose(&signal_bye);
    
    return 0;
}
```

## 0x01. double fetch

```tex
coming soon
```

## 0x02. userfaultfd系统调用

```tex
coming soon
```















