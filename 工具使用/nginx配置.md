---
layout: post
title: nginx入门指北
category: 工具使用
date: 2023-8-18
---
作者使用nginx+hexo搭建blog，由此总结nginx基础知识
<!-- more -->
[toc]

# Nginx配置

## 前言 - 什么是反向代理？

`Nginx`是一款高性能`Web`服务器，可以实现反向代理。什么叫做`反向代理`？实际上，我们正常的代理服务器是为客户机进行代理，来访问外部资源。而反向代理的服务器是将客户端的请求来转发到适当的后端服务器，因此可以实现负载均衡等功能。

本文将讲解`Ubuntu20.04.1`下`Nginx`的最基本配置，主要是在笔者搭建`blog`的时候用到的相关知识。

## Nginx快速配置

安装`Nginx`

```bash
sudo apt install nginx
```

查看`Nginx`状态

```bash
sudo systemctl status nginx
```

使用编写`nginx`配置：

```bash
vim /etc/nginx/sites-available/"your_sites"
```

例如，笔者的网站域名叫做`ltfa1l.top`，因此上述命令为：

```bash
vim /etc/nginx/sites-available/ltfa1l.top
```

`Nginx`可以对本地服务器进行反向代理，也可以对本地静态文件进行托管。例如，我们知道`Hexo`可以以`hexo server`来启动本地服务器，也可以通过`hexo generate`来生成静态文件。这两种方式的`Nginx`配置分别如下所示：

```nginx
# 代理服务器
server {
    listen 80; # 监听端口
    server_name ltfa1l.top www.ltfa1l.top; # 配置域名

    location / { # ‘/’表示匹配所有请求 
        proxy_pass http://localhost:4000; # 反向代理localhost的4000端口
        proxy_set_header Host $host; # 设置HTTP头，即Host设置为原始host
        proxy_set_header X-Real-IP $remote_addr; # 设置HTTP头X-Real-IP为原始请求IP地址
    }
}
```

和：

```nginx
# 托管静态文件
server {
    listen 80;
    server_name ltfa1l.top ltfa1l.top;

    location / {
        root /websites/public;
        index index.html; # 默认访问文件
        try_files $uri $uri/ =404; # 若访问不存在的文件
    }
}
```

创建符号链接，使得`Nginx`能够使用刚刚编写的配置文件：

```bash
sudo ln -s /etc/nginx/sites-available/"your_sites" /etc/nginx/sites/enabled/
```

例如笔者的命令是：

```bash
sudo ln -s /etc/nginx/sites-available/ltfa1l.top /etc/nginx/sites/enabled/
```

完成对应的编写内容后，重新加载一下`Nginx`：

```bash
sudo systemctl reload nginx
```

有时候需要重启`Nginx`:

```bash
sudo systemctl restart nginx
```

到这里，我们就完成了`Nginx`的所有基本配置了。

## 使用Let's encrypt配置免费SSL

我们可以利用`Let's encrypt`来配置免费的`https`。

安装`Certbot`：

```bash
sudo apt install certbot python3-certbot-nginx
```

使用`Certbot`获取并为`Nginx`安装证书：

```bash
sudo certbot --nginx -d ltfa1l.top www.ltfa1l.top # 更换成自己的域名
```

调整`Nginx`配置：

```nginx
server {
    if ($host = ltfa1l.top) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


    listen 80;
    server_name ltfa1l.top www.ltfa1l.top;

    location / {
        return 301 https://$host$request_uri; # 将http重定向到https
    }


}

server {
    listen 443 ssl;
    server_name ltfa1l.top www.ltfa1l.top;
    ssl_certificate /etc/letsencrypt/live/ltfa1l.top/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/ltfa1l.top/privkey.pem; # managed by Certbot


    location / {
        root /websites/public;
        index index.html;
        try_files $uri $uri/ =404;
    }

}
```

