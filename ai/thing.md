---
layout: post
title: 一些深度学习可能会用到的trick
category: ai
date: 2023-8-19
---
如题
<!-- more -->
[toc]

## 在服务器上后台运行

```cmd
nohup python train.py > test.log 2>&1 &
```

**nohup表示不挂断，退出终端不会关闭程序。最后一个&表示在后台运行**

**2>&1** 解释：

将标准错误 2 重定向到标准输出 &1 ，标准输出 &1 再被重定向输入到 runoob.log 文件中。

- 0 – stdin (standard input，标准输入)
- 1 – stdout (standard output，标准输出)
- 2 – stderr (standard error，标准错误输出)

可以通过查看进程并`kill`的方式来停止程序运行。

## 查看进程以及杀死进程

查看进程：

```
ps -aux | grep "python" 
```

参数说明：

- **a** : 显示所有程序
- **u** : 以用户为主的格式来显示
- **x** : 显示所有程序，不区分终端机

杀死进程：

```bash
kill -9  进程号PID
```

