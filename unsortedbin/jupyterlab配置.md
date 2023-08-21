---
layout: post
title: jupyterlab配置
category: 未分类
date: 2023-8-18
---
记录作者在配置jupyterlab的一些坑
<!-- more -->
[toc]

# Jupyter Lab配置

安装`jupyterlab`

```python
pip install jupyterlab
```

接下来，我们准备设置`jupyter`的密码，以允许远程使用。

我们先获得`jupyter`密码的哈希值，待会儿会用到。

在终端中输入`python`，获得哈希值：

```python
> from notebook.auth import passwd
> passwd()
'argon2:$argon2id$v=19$m=10240,t=10,p=8$tuOUUSE/KyCKtjW6HmLLvg$WJWRe2O/TDJheuzPcWebZcXkSe8aoW8hsZQrKAyeGxQ'
> exit()
```

记得保存上面的字符串。

接下来进行`jupyter`的设置编写。打开终端，输入以下命令：

```bash
jupyter lab --generate-config 	// 创建配置文件
cd ~/.jupyter
vim jupyter_lab_config.py 		// 编辑配置文件
```

以下需要手动编辑的设置：（在`vim`命令模式下可输入`/`来进行查找，按回车确认，按`n`正向查找）

```python
c.ServerApp.allow_origin = '*'	// 允许的主机
c.ServerApp.allow_remote_access = True // 允许远程访问
c.ServerApp.ip = '0.0.0.0' // 允许的IP地址
c.ServerApp.notebook_dir = '/workspace/jupyter' // 项目文件夹，需要手动创建好
c.ServerApp.password = 'xxxxxx' // 刚刚自己设置的密码对应的哈希值
c.ServerApp.open_browser = False // 禁止浏览器打开
c.ServerApp.port = 8888 // 端口 随自己选择即
```

设置简体中文：

```bash
pip install jupyterlab-language-pack-zh-CN
```

安装插件管理器：

```bash
pip install nodejs # 先安装nodejs才可以安装插件管理器。若已安装则忽视
pip install jupyter_contrib_nbextensions
```

启动`jupyter`：

```bash
jupyter lab # 非root用户
jupyter lab --allow-root # root用户
```

