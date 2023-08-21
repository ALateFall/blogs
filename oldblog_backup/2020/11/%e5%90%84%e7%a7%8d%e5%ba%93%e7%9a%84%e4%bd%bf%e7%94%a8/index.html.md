---
layout: post
title: 各种库的使用
date: 2020-11-25
tags: ["零碎"]
---

[toc]

# binascii库

俺用来处理字符串转十六进制和十六进制转字符串等等，需要注意的是这个地方的**参数均是使用的bytes类型**。
更新：别用这个方法了，用binascii.hexlify()吧，求你了

## 字符串转十六进制：

用的是binascii.b2a_hex():

    a = 'hello'
    b = binascii.b2a_hex(a.encode('utf-8'))
    print(b)
    # 输出： b'68656c6c6f'
    # 用这种方法转换，假如没有到两位会自动补零，非常贴心

## 十六进制转字符串：

用的是binascii.a2b_hex():

    a = b'68656c6c6f20776f726c64' # 注意不能用0x
    print(binascii.a2b_hex(a))
    # 输出： b'hello world'

**更新内容：**

## 字符串转十六进制

`binascii.hexlify()`

## 十六进制转字符串

`binascii.unhexlify()`

# z3库

z3这个库的功能非常强大，不过俺仅仅用来解方程。所以这个地方只介绍基本的解方程相关的内容。

## 引入库：

`from z3 import *`

## 定义变量

z3可以定义三种变量，分别是Int整型，Real有理数，和BitVec位向量。
可以同时定义一种类型的多个变量，但是要在后面加s变成复数形式，比如Ints。

    from z3 import *
    a, b, c = Ints('a b c')
    a, b, c = Reals('a b c')
    a = BitVec('a')

## 添加约束

假如用来解方程，那就是添加方程组。
单行解方程：
`solve(x+1==2)`
注意solve方法是自带输出的，因此不需要调用print方法。
解方程组：

    s = Solver()
    s.add(a+b+c==1)
    s.add(a*3+b*2+c==3)
    # 后面还可以加

## 得到结果

**必须先要判断是否有解**，假如是方程组形式，可以调用Solver()对象的check()方法，如下所示：

    s = Solver()
    s.add(a+b==1)
    s.add(a+b==2)
    check = s.check()
    if str(check)=="unsat":
        print("No answer")
    else:
        print("Solve")

输出结果：

    check = s.check()
    m = s.model()
    print(m)
    # 形式是一个列表，但实际上不是
    # 例如 [a=1,b=2]

获取每个值：

    check = s.check()
    m = s.model()
    for d in m.decls():
        print("%s:%s"%(d.name(),m[d]))

## 示例

    from z3 import *
    a, b, c = Reals('a b c')
    s = Solver()
    s.add(a+b==1)
    s.add(a == 1)
    check = s.check()
    m = s.model()
    print(m)
    for d in m.decls():
        print("%s:%s"%(d.name(),m[d]))
    # 输出结果：
    # [b = 0, a = 1]
    # b:0
    # a:1

# subprocess库

可以代替os.system执行命令，和控制程序的输入输出流。
直接上示例吧：

    import subprocess

    subprocess.call(['ping','192.168.81.143'])

默认是数组形式，后面可以跟参数。
也可以是shell形式，设置参数shell=True,此时就不用数组了。

    import subprocess

    subprocess.call('ping 192.168.81.143',shell=True)

主要还是可以用来读取输入和输出，示例：

    import subprocess

    p = subprocess.Popen(['D:\\temp\\test.exe'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p.stdin.write(b'test')
    p.stdin.close()
    out = p.stdout.read()
    print(out)

注意写入之后要关闭输入，而且输出和输出都是Bytes类型的。

# libnum库

不会真有人用了这个库还要去用binascii库来转换字符串和十六进制吧。
需要注意的是仍然是转换的bytes类型的数据。
引入：
`import libnum`
字符串转数字：（没找到怎么直接转十六进制...）
`libnum.s2n()`
任意进制数字转字符串：
`libnum.n2s()`
记忆也比较简单，n就代表number，s就代表字符串。
因此同理，还可以用来转化二进制的数据和字符串的数据，比如`libnum.s2b()`等等、