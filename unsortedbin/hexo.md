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
hexo init "your"
```

