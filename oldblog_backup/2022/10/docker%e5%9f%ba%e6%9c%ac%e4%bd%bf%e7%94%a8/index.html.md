---
layout: post
title: docker基本使用
date: 2022-10-14
tags: ["未分类"]
---

[toc]

# docker基本操作

## 镜像操作

查看本地机器上有的镜像

    docker images

搜索网络上的镜像

    docker search xxx
    # e.g.
    docker search php

下载镜像到本地

    docker pull xxx  # 注意这里xxx一定要全名
    docker pull mysql:5.7  # 指定版本

删除镜像

    docker rmi -f xxx  # id名 若有多个，以空格隔开 id名不需要写完

## 容器操作

查看运行的容器

    docker ps  # 当前运行的
    docker ps -a # 当前运行的和历史运行过的

删除容器

    docker rm 容器id  # 需要先停止运行容器

启动容器

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

停止容器

    docker stop 容器id  # 停止运行中的容器
    ctrl p + ctrl q # 退出并在后台运行

启动历史容器

    docker start 容器ID

重启容器

    docker restart 容器id

进入正在运行的容器

    docker exec -it 容器id /bin/bash # 若在这里exit 容器不会停止
    docker attach 容器id # 若在这里exit 容器会停止

## 容器打包镜像

    docker commit -m="描述信息" -a="作者" 容器id 目标镜像名称:tag # 打包为镜像
    docker save myimage:1.0 > myimage.tar

## apache启动

    /etc/init.d/apache2 start