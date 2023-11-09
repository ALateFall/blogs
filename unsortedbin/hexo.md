---
layout: post
title: hexo基础知识
category: 未分类
date: 2023-8-18
---
使用hexo + markdown编写blog
<!-- more -->
[toc]

# hexo(ubutnu)

首先需要安装`nodejs + npm`：

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - &&\
sudo apt-get install -y nodejs
```

此处选择安装的是`nodejs18`，使用`apt`安装可能会因为版本过低导致`hexo`启动失败。

安装`hexo`：

```bash
npm install -g hexo-cli
hexo init "your_website_dir"
# 例如笔者已经在hexo目录下，则使用命令hexo init .
```

现在，只需要在该目录下的`source/_posts`文件夹下放置好你的`markdown`文件即可。

若对内容进行了修改，使用以下命令：

```bash
hexo clean && hexo generate
# 清除以前生成的内容，并且生成新的内容
```
