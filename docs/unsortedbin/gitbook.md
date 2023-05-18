[toc]

# Gitbook

## 说明

本项目是由`typora`+`picGo`+`AliyunOSS`+`Gitbook`+`github pages`构建起来的。

## 安装

安装`gitbook`

```bash
npm install gitbook -g
```

安装完成后使用时会出现某个函数错误问题，原因是`gitbook`依赖的包未更更新，`STFW`即可

## 使用

`cd`到欲创建`gitbook`的目录

```bash
gitbook init
```

完成后，编写`readme.md`文件以及`summary.md`文件。其中，本项目现在的`summary.md`如下：

```markdown
# Summary

- [Introduction](README.md)
- [System](system/README.md)
  - [Stack](system/stack.md)
  - [Format String](system/format_string.md)
  - [Heap](system/heap.md)
  - [ELF](system/ELF.md)
  - [unsorted_bin](system/system_常用操作.md)

- [AI](ai/README.md)
  - [pandas](ai/pandas.md)
  - [pytorch](ai/pytorch.md)
  - [unsorted_bin](ai/thing.md)

- [unsorted_notes](unsortedbin/README.md)
  - [Frequent operations](unsortedbin/常用操作.md)
  - [docker](unsortedbin/docker使用.md)
  - [vim](unsortedbin/vim.md)
  - [gitbook](unsortedbin/gitbook.md)
```

之后，进行每一次修改需要重新`build`。可以添加两个参数来分别指定`md`存放的目录以及`gitbook`生成的目录。

```bash
gitbook build # 默认
gitbook build . /docs # 将gitbook输出到docs目录而不是默认的/_books目录
```

若欲本地部署，则：

```bash
gitbook serve
```

由于本项目使用`github pages`，因此：

```bash
git add .
git commit -m ""
git push origin main
```