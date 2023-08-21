---
layout: post
title: pytorch(talk is cheap版
date: NaN-NaN-NaN
tags: ["未分类"]
---

oc]

## 命令执行的函数

*   system()
*   passthru()
*   exec()
*   shell_exec()
*   popen()
*   proc_open()
*   pcntl_exec()
*   反引号，和shell_exec()等价

### 有回显的函数

*   system()
*   passthru()

### 没有回显的函数

*   exec()
*   shell_exec()
*   popen()
结果为文件指针，可以用fgets()等方法输出
*   proc_open()
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_6f955d108686d26f41c9ff6b32fa1b75.jpg)](wp_editor_md_6f955d108686d26f41c9ff6b32fa1b75.jpg)
*   pcntl_exec()
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_af115ba1a1c825cf0fe13b9b8b963ab3.jpg)](wp_editor_md_af115ba1a1c825cf0fe13b9b8b963ab3.jpg)

\