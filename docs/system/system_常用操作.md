[toc]

# 常用操作

## Linux查找文件

```bash
find /etc -name "php.ini"
```

## VIM操作

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

## vmware共享文件夹

我现在设置到了主机桌面的`vmware_share`

在`ubuntu`下是在`/mnt/hgfs/vmware_share`

## ubuntu解压缩

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

## ubuntu使用vscode远程开发

命令行下ssh命令：

```bash
ssh ltfall@192.168.81.159
```

在vscode中，若想打开ubuntu的终端，使用：

```
ctrl+shift+`(波浪号)
```

