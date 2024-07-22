---
layout: post
title: 栈溢出trick
category: StackOverflow
date: 2023-9-20 12:00:00
---
栈溢出基础知识点
<!-- more -->
# 栈转移

有的情况下，栈溢出的空间很小，可能仅仅覆盖到`ebp`和`return address`，甚至没有办法构造参数，因此可以把栈迁移到其他地方。栈迁移其实主要是把`esp`放到想要放到的位置，因为像`pop`指令这种都是在栈顶也就是`esp`指向的地方操作的。栈一般可以迁移到例如`bss`段，或者是`read`进来存放到栈上的`payload`等（当然要知道存放的地址）。

汇编指令：

```assembly
leave
# 相当于两条指令：
# mov esp ebp
# pop ebp
# leave指令的作用一般是撤销栈帧，即把esp置入现在ebp的位置，再将esp的位置取出一个值当做ebp地址
ret
# 相当于pop eip，将当前esp寄存器指向的内容赋值给eip，这样接下来就会执行更新后的eip。
# 若使得栈中return address为leave ret，有以下几个过程：
# mov esp ebp 将esp收回到ebp的位置，此时二者都指向原来ebp的位置
# pop ebp     将此时二者指向的地址弹出，ebp此时指向这个地址，esp+4，指向return address即leave ret
# pop eip     esp指向的return address即leave ret弹出，接下来将再次执行leave ret，esp+4（但不管）
# mov esp ebp 将esp收回到ebp的位置，此时二者指向原来ebp的位置存放的地址
# pop ebp     将此时二者指向的地址弹出，ebp地址再次变为指向的这个值，栈迁移时可以不管ebp去哪了，esp+4.
# pop eip     已经栈迁移到这里了，执行此时esp指向的地址
```



![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311211725580.png)

一般来说`payload`如下：

```python
buffer padding|fake ebp|leave ret addr|
```

构造的虚假栈帧如下如下：

```python
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2
```

