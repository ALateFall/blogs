---
layout: post
title: docker入门指南&从零配置一台ubuntu容器
category: 未分类
date: 2023-8-18
---
本文记录了docker的一些基本操作以及如何一步一步配置一台ubuntu的容器，进行基础设置。
<!-- more -->
[toc]

# docker基本操作

## 镜像操作

查看本地机器上有的镜像

```bash
docker images
```

搜索网络上的镜像

```bash
docker search xxx
# e.g.
docker search php
```

下载镜像到本地

```bash
docker pull xxx  # 注意这里xxx一定要全名
docker pull mysql:5.7  # 指定版本
```

删除镜像

```bash
docker rmi -f xxx  # id名 若有多个，以空格隔开 id名不需要写完
```

## 容器操作

查看运行的容器

```bash
docker ps  # 当前运行的
docker ps -a # 当前运行的和历史运行过的
```

删除容器

```bash
docker rm 容器id  # 需要先停止运行容器
```

启动容器

```bash
docker run # 启动
# 参数
--name 设定容器名称
-it 以交互模式启动
-p 添加端口映射，格式为 主机:容器端口
-d 后台运行容器，并返回容器id
-v 设定主机和docker的共享目录，格式为 主机:容器目录
# 常用
# 运行一个交互式的容器，将容器80端口映射到主机的8888端口，并运行/bin/bash以获得终端
docker run -it -p 0.0.0.0:8888:80 镜像名 /bin/bash 
```

停止容器

```bash
docker stop 容器id  # 停止运行中的容器
ctrl p + ctrl q # 退出并在后台运行
```

启动历史容器

```bash
docker start 容器ID
```

重启容器

```bash
docker restart 容器id
```

进入正在运行的容器

```bash
docker exec -it 容器id /bin/bash # 若在这里exit 容器不会停止
docker attach 容器id # 若在这里exit 容器会停止
```

## 容器打包镜像

```bash
docker commit -m="描述信息" -a="作者" 容器id 目标镜像名称:tag # 打包为镜像
docker save myimage:1.0 > myimage.tar
```

## docker 从零开始配置torch容器

### 创建容器

使用如下命令创建一个容器：

```bash
docker run -it -p 0.0.0.0:"your_port":"ssh_port" --gpus all --name "your_name" -e NVIDIA_DRIVER_CAPABILITIES=compute,utility -e NVIDIA_VISIBLE_DEVICES=all "your_image_name" /bin/bash
```

由于主机可以创建多个容器，每个容器的SSH端口不可能都是22，因此需要将容器的SSH端口映射到主机的其它端口上。

其中，`your_port`以及`ssh_port`以及`your_name`和`your_image_name`分别需要设置为你想将映射到的主机端口（注意不要和别人的一样）、主机当前的SSH端口（默认是22）、你的容器名称、你要拉取的镜像名称。

例如，我用如下命令创建了我的`pytorch`容器：

```bash
docker run -it -p 0.0.0.0:9595:22 -v /home/puao:/data --gpus all --name torch_pa -e NVIDIA_DRIVER_CAPABILITIES=compute,utility -e NVIDIA_VISIBLE_DEVICES=all pytorch/pytorch:1.10.0-cuda11.3-cudnn8-devel /bin/bash
```

其中：

- `-e NVIDIA_DRIVER_CAPABILITIES=compute,utility` 和 `-e NVIDIA_VISIBLE_DEVICES=all` 是设置环境变量，分别表示驱动程序功能和可见设备，如此一来可以使得容器能够直接使用`cuda`以及`gpu`。你也可以使用`nvidia-docker run`命令来创建容器，这将会自动添加这些环境变量。
- `-p 0.0.0.0:9595:22`表示将容器内部的端口`22`映射到主机的端口`9595`。你可以多次使用`-p`参数来添加映射别的端口。
- `-v /home/puao:/data`表示将容器内部的目录`/data`挂载到主机的目录`/home/puao`。如此以来容器内部的`/data`目录将实现与`/home/puao`目录进行数据共享。

### 配置密码

当使用上述命令创建好容器后，由于该镜像是一个纯净的`pytorch-cuda-cudnn`的`ubuntu`镜像，因此我们需要先对该`ubuntu`进行一些配置。

我们使用`passwd root`命令来为`root`用户设置密码，如此以来使用`ssh`或者其他方式登录容器时，需要先输入该密码。

### 配置apt

在配置`apt`之前，需要先有一个编辑器（部分镜像没有自带编辑器）。

```bash
apt update # 不然可能没有软件源
apt install vim
apt install gedit
# 二者选一个自己喜欢的安装即可
# 接下来的编辑部分，若此处选择了安装gedit，那么请将命令由vim更换为gedit
```

由于`apt`默认是国外源，下载速度比较慢，此处我们更换为清华镜像源：

```bash
vim /etc/apt/sources.list 
```

打开该文件后，我们将其修改为清华镜像源：

请注意，根据`ubuntu`版本的不同，清华镜像源有略微的不同，具体可以查询[ubuntu | 镜像站使用帮助 | 清华大学开源软件镜像站 | Tsinghua Open Source Mirror](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/)。下面展示的是`ubuntu 20.04.1`版本的。

```bash
# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-updates main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-backports main restricted universe multiverse
# deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-backports main restricted universe multiverse

# deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-security main restricted universe multiverse
# # deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-security main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse
# deb-src http://security.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse

# 预发布软件源，不建议启用
# deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-proposed main restricted universe multiverse
# # deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-proposed main restricted universe multiverse
```

完成后，我们使用以下命令，更新`apt`源：

```bash
apt update
```

此处若出现如下错误：

```bash
W: GPG error: https://developer.download.nvidia.cn/compute/cuda/repos/ubuntu1804/x86_64  InRelease: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY A4B469963BF863CC
E: The repository 'https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64  InRelease' is not signed.
N: Updating from such a repository can't be done securely, and is therefore disabled by default.
```

则使用如下命令来导入软件包签名：

```bash
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys A4B469963BF863CC
# 注意最后面的key需要更换为报错中的key
# 完成之后重新apt update即可
```

此处若仍然出现错误，且提示`The repository ... does not have a release file`

那么大概率是由于源是`https`而没有安装`https`相关的包。

解决方法1：

```bash
# 安装相关的包
apt install apt-transport-https ca-certificates
```

解决方法2：

```bash
在源镜像网站取消https选项。
```

完成之后，安装常用软件包：

```bash
apt install -y wget build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev liblzma-dev net-tools ufw
```

### 配置SSH

首先安装`OpenSSH`服务器：

```bash
apt install openssh-server
# 笔者此处遇到提示输入所在区域和时区，选择Asia以及Shanghai
```

完成后，查看`SSH`服务是否已经开启：

```bash
service ssh status
```

若未开启，则使用命令开启：

```bash
service ssh start
```

接下来，修改防火墙策略将`ssh`添加到白名单：

```bash
ufw allow ssh
```

修改`SSH`配置文件，设置可以使用`root`用户登录，以及登录需要验证。

```bash
vim /etc/ssh/sshd_config
```

打开文件后，找到注释的内容，并修改为如下：

若你不知道/找不到对应的内容，也可以直接将下面内容添加到该文件。

```bash
PermitRootLogin yes
PasswordAuthentication yes
```

设置完成后，重启`ssh`即可连接到该容器：

```bash
service ssh restart
```

现在，你就可以在任意一台你自己的电脑上使用如下命令来通过`SSH`连接你的`docker`了：

```bash
ssh root@你的服务器IP -p 你讲容器映射到主机的端口
```

### 配置SSH环境变量

为什么要配置`SSH`的环境变量？先举一个例子：虽然我拉取的镜像是`pytorch`的，且我在容器内部直接调用`python`时，`import torch`是可以正常工作的，但我在`ssh`中调用`python`时，`torch`不但提示未安装，甚至`python`版本都不一样。

这只能说明一件事情：`ssh`的终端和我们自己在容器中使用的终端的环境变量不同。

为了在`ssh`中能够使用正常的命令，我们需要修改环境变量。

首先在容器中使用命令`env`，查看正常情况下的环境变量。找到其中一项：

```bash
PATH=/opt/conda/bin:/usr/local/nvidia/bin:/usr/local/cuda/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

复制该内容，打开下面的文件：

```bash
vim ~/.bashrc
```

在`# If not running interactively, don't do anything`这段话前面，粘贴刚刚复制的内容。

再输入命令：

```bash
source ~/.bashrc
```

现在我们就可以在`SSH`中使用正确的命令了。

至此，一台支持`gpu`和`cuda`的容器就已经配置完毕了。

### 额外配置

这些配置可以根据自己的需求来选择。

- 配置免密`ssh`登录

实际上是使用公钥登录。假设主机A是`Windows`，要免密码连接主机B，即`Linux`主机，此时主机A在终端输入：

```bash
ssh-keygen # 可以生成ssh公私钥
```

输入后会提示生成文件的路径，选择，通过该路径（一般是`C:/Users/用户名/.ssh`下）找到刚刚生成的`id_rsa.pub`文件，复制里面的内容，并粘贴到目标主机的`~/.ssh/authorized_keys`文件内即可完成。

- 更换`pip`镜像源

切换到用户目录：

```bash
cd ~
mkdir .pip
```

创建文件`pip.conf`，粘贴如下内容即可更换为豆瓣源:

```bash
[global]
index-url = http://pypi.douban.com/simple/
```

