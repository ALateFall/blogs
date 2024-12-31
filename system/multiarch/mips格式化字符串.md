[toc]

# 安装必要的包

```bash
sudo apt-get install gcc-mips-linux-gnu gcc-mips64-linux-gnuabi64 qemu qemu-system-mips qemu-user debootstrap gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-mips64-linux-gnuabi64 gcc-mips64el-linux-gnuabi64
```

随后，即可通过如下命令编译文件为`64`位的`mips`：

```bash
mips64-linux-gnuabi64-gcc test.c -o test_mips
```

并使用如下命令运行：

```bash
qemu-mips64 -L /usr/mips64-linux-gnuabi64/ ./test_mips
```



或者如下命令编译为`32`位：

```bash
mips-linux-gnu-gcc -o program test.c
```

并使用如下命令运行：

```bash
qemu-mips -L /usr/mips-linux-gnu ./program
```

**若为小段，则为`qemu-mipsel`。**

值得注意的是，`mips`的返回地址一般为`fp`的上方。



在线编译、反编译：

[Online Assembler and Disassembler](https://shell-storm.org/online/Online-Assembler-and-Disassembler/)

# 格式化字符串 - 64位

在`mips`中，格式化字符串漏洞并没有很大的区别。

由于`$a0 - $a7`一共八个寄存器表示函数的参数，而`$a0`存储的是输入本身，因此`%8$p`表示栈上的第一个值。

# 格式化字符串 - 32位

同样的，但`32`位下，一共只有`$a0 - $a3`四个寄存器。

但与上面不同的是，栈上的第`5`个位置为`%4$p`。记住即可。