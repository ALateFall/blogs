[toc]

# tmux - 终端复用器

## tmux简述

我们在使用终端的时候，若终端退出，那么终端的历史记录以及当前运行的程序等也就丢失了。`tmux`可以将终端以另一种逻辑管理，`tmux`可以将新建的终端进行命名、后台运行等，并可以灵活地切换`tmux`终端。想让你退出`ssh`的时候保留终端吗？那就使用`tmux`吧。

`tmux`还可以将一个终端划分为多个窗口，在同一个画面上显示多个终端。想在调试的时候免去切换来切换去的烦恼吗？那就使用`tmux`吧。

本文将简要介绍上述两个功能，称为终端管理和窗口切割。

### 安装

```bash
apt install tmux
```

### tmux前缀键

在`tmux`中，快捷键需要先按下`ctrl+b`再松开，然后再输入另一个键才可以生效。这里所说的`ctrl+b`也就是前缀键。

`tmux`的快捷键只能在`tmux`终端中使用，因此至少需要创建一个`tmux`终端才能使用。例如在`bash`中就是无法使用的。

## 终端管理

### 新建会话

创建一个名为`session_name`的窗口。

```bash
tmux new -s <session_name>
```

实际上，直接在终端中输入`tmux`也可以创建一个`tmux`终端，它的名字默认是从`0`开始按顺序增长。

在新建的终端中，输入`exit`将会退出`tmux`终端。

可以对`tmux`终端进行重命名：

```tmux
tmux rename-session -t <old_name> <new_name>
```

也有快捷键方式：

```
ctrl+b $
```

### 挂起tmux终端

需要先创建`tmux`终端后在`tmux`终端中进行。

```tmux
tmux detach
```

输入该命令后，将会后台运行此`tmux`终端。

快捷键方式为：

```
ctrl+b d
```

### 列出tmux终端

可以通过以下命令来查看目前所有的`tmux`终端：

```tmux
tmux ls
tmux list-session
```

快捷键方式为：

```
ctrl+b s
```

### 重新进入挂起的tmux终端

重新进入后台运行的`tmux`终端的方式如下：

```bash
tmux attach -t <session_name>
```

`-t`表示`target`。

### tmux终端间切换

可以使用以下命令进行`tmux`终端间的切换：

```bash
tmux switch -t <session_name>
```

## 窗口切割

### 划分窗口

直接输入命令，默认划分上下两个窗口

```
tmux split-window
```

也可以划分左右两个窗口

```
tmux split-window
```

快捷键方式：

```
ctrl+b " # 划分上下两个窗口 注意这里是双引号
ctrl+b % # 划分左右两个窗口
```

### 移动光标

很简单 `up down left right`

```
tmux select-pane -U # 向上移动光标
tmux select-pane -D # 向下移动光标
tmux select-pane -L # 向左移动光标
tmux select-pane -R # 向右移动光标
```

快捷键方式：

```
ctrl+b <arrow_keys>
# 例如，向右：
ctrl+b →
```

## 鼠标模式

在`tmux`终端中可能会遇到一些问题，包括无法使用鼠标滚轮来翻动窗口内容等。可以使用以下方式打开鼠标模式：

```
ctrl+b :
setw -g mouse on
```

## 后记

`tmux`还有很多功能，但是个人不怎么用就不记录了，包括交换窗格位置、窗口管理（同一个窗口中的两个终端可以分别全屏）等。还有一些很优秀的终端管理器，例如`byodu`、`screen`等，可以自行了解。

