[toc]

# 安装

基于`Ubuntu22.04`。首先下载二进制包，通过如下方式：

```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
```

随后将其解压到`/usr/local`:

```bash
sudo tar -C /usr/local -xzf ./go1.22.4.linux-amd64.tar.gz
```

将以下命令添加到`~/.bashrc`文件末尾，从而将`go`添加到环境变量目录：

若你使用了`zsh`，可以将其添加到`~/.zshrc`或者`~/.zshenv`末尾。

```bash
export PATH=$PATH:/usr/local/go/bin
```

# 0x00. 初探golang

编写如下代码，命名为`hello.go`：

```go
package main

import "fmt"

func main(){
	fmt.Println("hello, world!")
}
```

可以通过如下命令来直接运行：

```bash
go run hello.go
```

也可以通过如下命令来编译出可执行文件：

```bash
go build hello.go
```

注意，函数的大括号`{`不能放在单独的一行，而是只能跟在函数名那一行。

