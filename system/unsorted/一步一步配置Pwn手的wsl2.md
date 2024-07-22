---
layout: post
title: 一步一步配置wsl2 for pwn
category: tricks
date: 2024-05-01 12:00:00
---
还在用传统vmware？
<!-- more -->

[toc]

# 安装wsl2

使用管理员权限在`powershell`中输入如下命令来启动适用于`Linux`的`Windows`子系统：

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
```

查看`windows`版本，需要大于`1903`

使用管理员权限在`powershell`中输入以下命令：

```powershell
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

访问[这里](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi)来下载和安装`wsl2`内核组件。若无法安装则重启。

访问[这里](https://learn.microsoft.com/en-us/windows/wsl/install-manual#downloading-distributions)来下载一个`wsl2`的发行版，本文档基于`Ubuntu 22.04 LTS`。

下载后会得到一个名为`Ubuntuxx04-xxxxx.AppxBundle`文件，将其后缀名`AppxBundle`更改为`zip`，并将其解压。

解压后会得到一系列包括`appx`的文件，找到其中的`Ubuntu_xx04.x.x.x_x64.appx`文件（别的文件不需要了），将其后缀名更改为`zip`并解压。

解压后会得到一系列文件，都是需要的，运行`ubuntu.exe`，即可安装得到`wsl2`子系统了。

有问题可以查阅[这里](https://docs.eesast.com/docs/tools/wsl)

# 配置wsl2

下载并安装[升级包](https://github.com/microsoft/WSL/releases/download/2.1.1/wsl.2.1.1.0.x64.msi)。

在`powershell`中输入以下命令来设置自动回收内存：

```powershell
wsl --manage Ubuntu --set-sparse true
```

在`Windows`的用户目录（`%UserProfile% `）下创建`.wslconfig`文件，并填写以下内容：

```tex
[experimental]
autoMemoryReclaim=gradual # 可以在 gradual 、dropcache 、disabled 之间选择
networkingMode=mirrored
dnsTunneling=true
firewall=true
autoProxy=true
sparseVhd=true
```

如此以来`wsl`可以继承`Windows`的网络设置，包括代理设置，更加方便。保存后在`powershell`中输入`wsl --shutdown`来关闭`wsl`并重启，使用命令`curl -I https://www.google.com`查看是否代理成功。注意不能使用`ICMP`协议的`ping`命令。

使用`sudo passwd`命令设置`root`用户的密码。

输入以下命令来更新`apt`源：

```bash
sudo apt update
```

# 将你的pwn文件夹移植到你的wsl

我以前是在`vmware`中使用`Ubuntu`，在这一步我们将`vmware`中的常用目录迁移到`wsl`即可。

使用`zip`命令打包文件夹：

```bash
zip -r ./pwn.zip /path_to_your_dir 
```

# 配置pwn环境

## 基础工具配置

在这之前要保证已经成功开启代理。

我使用的是`roderick`师傅的脚本，并进行了一些自定义配置，如下。

将其命名为`install.sh`，使用**普通用户权限安装**而不是`root`用户，**不要加**`sudo`！

```bash
#!/bin/bash
# 环境变量
export DEBIAN_FRONTEND=noninteractive
export TZ=Asia/Shanghai
export HUB_DOMAIN=github.com
# 基础包
sudo apt update && sudo apt install -y --fix-missing python3 python3-pip python3-dev lib32z1 \
xinetd curl gcc expect gdb gdbserver g++ git libssl-dev libffi-dev build-essential tmux zstd \
vim netcat tldr liblzma-dev iputils-ping cpio gdb-multiarch file net-tools socat ruby ruby-dev locales \
autoconf automake libtool make zsh openssh-server openssh-client ipython3 \
gdb-multiarch bison

# qemu相关, 需要的话取消注释
# sudo apt install qemu qemu-system qemu-user-static binfmt-support

# ruby包
sudo gem install one_gadget seccomp-tools

# cargo
cargo install pwninit

# python包
python3 -m pip install --upgrade pip && \
pip3 install ropper capstone unicorn keystone-engine z3-solver qiling lief libnum pycryptodome angr trash-cli && \
cd $HOME 
export HUB_DOMAIN=github.com
git clone https://${HUB_DOMAIN}/pwndbg/pwndbg && \
cd ./pwndbg && \
./setup.sh && \
cd $HOME && \
git clone https://${HUB_DOMAIN}/hugsy/gef.git && \
git clone https://${HUB_DOMAIN}/RoderickChan/Pwngdb.git && \
git clone https://${HUB_DOMAIN}/Gallopsled/pwntools && \
pip3 install --upgrade --editable ./pwntools && \
git clone https://${HUB_DOMAIN}/RoderickChan/pwncli.git && \
pip3 install --upgrade --editable ./pwncli && \
git clone https://${HUB_DOMAIN}/marin-m/vmlinux-to-elf.git && \
git clone https://${HUB_DOMAIN}/JonathanSalwan/ROPgadget.git && \
python3 ./ROPgadget/setup.py install

# 安装patchelf和r2
git clone https://${HUB_DOMAIN}/NixOS/patchelf.git && \
cd ./patchelf && \
./bootstrap.sh && \
./configure && \
make && \
sudo make install && \
cd $HOME && \
export version=$(curl -s https://api.github.com/repos/radareorg/radare2/releases/latest | grep -P '"tag_name": "(.*)"' -o| awk '{print $2}' | awk -F"\"" '{print $2}') && \
wget https://${HUB_DOMAIN}/radareorg/radare2/releases/download/${version}/radare2_${version}_amd64.deb && \
sudo dpkg -i radare2_${version}_amd64.deb && rm radare2_${version}_amd64.deb


# 配置文件
cat > ~/.tmux.conf << "EOF"
set -g prefix C-a #
unbind C-b # C-b即Ctrl+b键，unbind意味着解除绑定
bind C-a send-prefix # 绑定Ctrl+a为新的指令前缀

# 设置保存的buffer大小
set -g history-limit 5000
# 关闭自动重命名
setw -g automatic-rename off
setw -g allow-rename off
# 增加鼠标支持
set -g mouse on
# 使用vi风格
setw -g mode-keys vi

# 从tmux v1.6版起，支持设置第二个指令前缀
set-option -g prefix2 ` # 设置一个不常用的`键作为指令前缀，按键更快一些
#set-option -g mouse on # 开启鼠标支持
# 修改分屏快捷键
unbind '"'
bind - splitw -v -c '#{pane_current_path}' # 垂直方向新增面板，默认进入当前目录
unbind %
bind \\ splitw -h -c '#{pane_current_path}' # 水平方向新增面板，默认进入当前目录

# 设置面板大小调整快捷键
bind j resize-pane -D 10
bind k resize-pane -U 10
bind h resize-pane -L 10
bind l resize-pane -R 10
bind 1 next-window
EOF

# 安装musl
sudo apt install musl-dev musl-tools
cd $HOME
wget https://musl.libc.org/releases/musl-1.2.3.tar.gz
tar -xvzf musl-1.2.3.tar.gz
cd musl-1.2.3
CC="gcc" CXX="g++" CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og -Wno-error -z now" CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og -Wno-error -z now" ./configure --enable-debug --disable-werror
make -j8
sudo make install

# 安装zsh
export HUB_DOMAIN=github.com
sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" && \
git clone https://${HUB_DOMAIN}/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions && \
git clone https://${HUB_DOMAIN}/zsh-users/zsh-syntax-highlighting $ZSH_CUSTOM/plugins/zsh-syntax-highlighting && \
git clone https://${HUB_DOMAIN}/zsh-users/zsh-completions ${ZSH_CUSTOM:-${ZSH:-~/.oh-my-zsh}/custom}/plugins/zsh-completions


cat > ~/.zshrc << "EOF"
# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:/usr/local/bin:$PATH

# Path to your oh-my-zsh installation.
if [ ! "$TMUX" = "" ]; then export TERM=xterm-256color; fi # auto-suggestion in tmux
export ZSH="$HOME/.oh-my-zsh"
export PATH=$PATH:$HOME/.local/bin:$HOME/.cargo/bin
alias rm='echo "This is not the command you are looking for. Use trash-put instead.";false'
alias trp=trash-put
alias tre=trash-empty
alias trl=trash-list
alias trr=trash-restore
alias trm=trash-rm
alias openaslr="sudo -u root sh -c 'echo 2 >/proc/sys/kernel/randomize_va_space'"
alias closeaslr="sudo -u root sh -c 'echo 0 >/proc/sys/kernel/randomize_va_space'"

# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/ohmyzsh/ohmyzsh/wiki/Themes
ZSH_THEME="ys"

# Set list of themes to pick from when loading at random
# Setting this variable when ZSH_THEME=random will cause zsh to load
# a theme from this variable instead of looking in $ZSH/themes/
# If set to an empty array, this variable will have no effect.
# ZSH_THEME_RANDOM_CANDIDATES=( "robbyrussell" "agnoster" )

# Uncomment the following line to use case-sensitive completion.
# CASE_SENSITIVE="true"

# Uncomment the following line to use hyphen-insensitive completion.
# Case-sensitive completion must be off. _ and - will be interchangeable.
# HYPHEN_INSENSITIVE="true"

# Uncomment one of the following lines to change the auto-update behavior
# zstyle ':omz:update' mode disabled  # disable automatic updates
# zstyle ':omz:update' mode auto      # update automatically without asking
# zstyle ':omz:update' mode reminder  # just remind me to update when it's time

# Uncomment the following line to change how often to auto-update (in days).
# zstyle ':omz:update' frequency 13

# Uncomment the following line if pasting URLs and other text is messed up.
# DISABLE_MAGIC_FUNCTIONS="true"

# Uncomment the following line to disable colors in ls.
# DISABLE_LS_COLORS="true"

# Uncomment the following line to disable auto-setting terminal title.
# DISABLE_AUTO_TITLE="true"

# Uncomment the following line to enable command auto-correction.
# ENABLE_CORRECTION="true"

# Uncomment the following line to display red dots whilst waiting for completion.
# You can also set it to another string to have that shown instead of the default red dots.
# e.g. COMPLETION_WAITING_DOTS="%F{yellow}waiting...%f"
# Caution: this setting can cause issues with multiline prompts in zsh < 5.7.1 (see #5765)
# COMPLETION_WAITING_DOTS="true"

# Uncomment the following line if you want to disable marking untracked files
# under VCS as dirty. This makes repository status check for large repositories
# much, much faster.
# DISABLE_UNTRACKED_FILES_DIRTY="true"

# Uncomment the following line if you want to change the command execution time
# stamp shown in the history command output.
# You can set one of the optional three formats:
# "mm/dd/yyyy"|"dd.mm.yyyy"|"yyyy-mm-dd"
# or set a custom format using the strftime function format specifications,
# see 'man strftime' for details.
# HIST_STAMPS="mm/dd/yyyy"

# Would you like to use another custom folder than $ZSH/custom?
# ZSH_CUSTOM=/path/to/new-custom-folder

# Which plugins would you like to load?
# Standard plugins can be found in $ZSH/plugins/
# Custom plugins may be added to $ZSH_CUSTOM/plugins/
# Example format: plugins=(rails git textmate ruby lighthouse)
# Add wisely, as too many plugins slow down shell startup.
plugins=(git zsh-syntax-highlighting z sudo extract docker rand-quote tmux colored-man-pages zsh-autosuggestions colorize)

source $ZSH/oh-my-zsh.sh

# User configuration

# export MANPATH="/usr/local/man:$MANPATH"

# You may need to manually set your language environment
# export LANG=en_US.UTF-8

# Preferred editor for local and remote sessions
# if [[ -n $SSH_CONNECTION ]]; then
#   export EDITOR='vim'
# else
#   export EDITOR='mvim'
# fi

# Compilation flags
# export ARCHFLAGS="-arch x86_64"

# Set personal aliases, overriding those provided by oh-my-zsh libs,
# plugins, and themes. Aliases can be placed here, though oh-my-zsh
# users are encouraged to define aliases within the ZSH_CUSTOM folder.
# For a full list of active aliases, run `alias`.
#
# Example aliases
# alias zshconfig="mate ~/.zshrc"
# alias ohmyzsh="mate ~/.oh-my-zsh"
EOF
```

创建`init.sh`文件，同样使用普通用户权限执行该文件：

```bash
#!/bin/zsh
omz reload
pwncli misc setgdb -g
cd $HOME
# 安装decomp2dbg
git clone https://github.com/mahaloz/decomp2dbg.git
cd decomp2dbg 
# 记得拷贝文件
# cp -r ./decompilers/d2d_ida/* /path/to/ida/plugins/
pip3 install . && \
cp d2d.py ~/.d2d.py && echo "source ~/.d2d.py" >> ~/.gdbinit
# 更新各个仓库、工具的脚本：
```

创建`update.sh`文件，同上：

```bash
#!/bin/bash
install_path=$HOME

repos=(gef Pwngdb pwndbg pwntools pwncli peda decomp2dbg deploy_pwn_template )
for repo in ${repos[@]}
do
cd ${install_path}/${repo} && git pull && echo "update ${repo} end!"
done

cd $install_path/pwndbg && ./setup.sh
```

## zsh配置

在`Windows`上下载字体并安装：

[链接1](https://github.com/romkatv/powerlevel10k-media/raw/master/MesloLGS%20NF%20Regular.ttf)

[链接2](https://github.com/romkatv/powerlevel10k-media/raw/master/MesloLGS%20NF%20Bold.ttf)

[链接3](https://github.com/romkatv/powerlevel10k-media/raw/master/MesloLGS%20NF%20Italic.ttf)

[链接4](https://github.com/romkatv/powerlevel10k-media/raw/master/MesloLGS%20NF%20Bold%20Italic.ttf)

在`~`目录下输入该命令下载`zsh`主题：

```bash
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
```

编辑`~/.zshrc`文件：

```bash
# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:/usr/local/bin:$PATH

# Path to your oh-my-zsh installation.
if [ ! "$TMUX" = "" ]; then export TERM=xterm-256color; fi # auto-suggestion in tmux
export ZSH="$HOME/.oh-my-zsh"
export PATH=$PATH:$HOME/.local/bin
alias rm='echo "This is not the command you are looking for. Use trash-put instead.";false'
alias trp=trash-put
alias tre=trash-empty
alias trl=trash-list
alias trr=trash-restore
alias trm=trash-rm
alias openaslr="sudo -u root sh -c 'echo 2 >/proc/sys/kernel/randomize_va_space'"
alias closeaslr="sudo -u root sh -c 'echo 0 >/proc/sys/kernel/randomize_va_space'"
fpath=(/home/ltfall/patchelf/completions/zsh $fpath)
# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/ohmyzsh/ohmyzsh/wiki/Themes
ZSH_THEME="ys"

# Set list of themes to pick from when loading at random
# Setting this variable when ZSH_THEME=random will cause zsh to load
# a theme from this variable instead of looking in $ZSH/themes/
# If set to an empty array, this variable will have no effect.
# ZSH_THEME_RANDOM_CANDIDATES=( "robbyrussell" "agnoster" )

# Uncomment the following line to use case-sensitive completion.
# CASE_SENSITIVE="true"

# Uncomment the following line to use hyphen-insensitive completion.
# Case-sensitive completion must be off. _ and - will be interchangeable.
# HYPHEN_INSENSITIVE="true"

# Uncomment one of the following lines to change the auto-update behavior
# zstyle ':omz:update' mode disabled  # disable automatic updates
# zstyle ':omz:update' mode auto      # update automatically without asking
# zstyle ':omz:update' mode reminder  # just remind me to update when it's time

# Uncomment the following line to change how often to auto-update (in days).
# zstyle ':omz:update' frequency 13

# Uncomment the following line if pasting URLs and other text is messed up.
# DISABLE_MAGIC_FUNCTIONS="true"

# Uncomment the following line to disable colors in ls.
# DISABLE_LS_COLORS="true"

# Uncomment the following line to disable auto-setting terminal title.
# DISABLE_AUTO_TITLE="true"

# Uncomment the following line to enable command auto-correction.
# ENABLE_CORRECTION="true"

# Uncomment the following line to display red dots whilst waiting for completion.
# You can also set it to another string to have that shown instead of the default red dots.
# e.g. COMPLETION_WAITING_DOTS="%F{yellow}waiting...%f"
# Caution: this setting can cause issues with multiline prompts in zsh < 5.7.1 (see #5765)
# COMPLETION_WAITING_DOTS="true"

# Uncomment the following line if you want to disable marking untracked files
# under VCS as dirty. This makes repository status check for large repositories
# much, much faster.
# DISABLE_UNTRACKED_FILES_DIRTY="true"

# Uncomment the following line if you want to change the command execution time
# stamp shown in the history command output.
# You can set one of the optional three formats:
# "mm/dd/yyyy"|"dd.mm.yyyy"|"yyyy-mm-dd"
# or set a custom format using the strftime function format specifications,
# see 'man strftime' for details.
# HIST_STAMPS="mm/dd/yyyy"

# Would you like to use another custom folder than $ZSH/custom?
# ZSH_CUSTOM=/path/to/new-custom-folder

# Which plugins would you like to load?
# Standard plugins can be found in $ZSH/plugins/
# Custom plugins may be added to $ZSH_CUSTOM/plugins/
# Example format: plugins=(rails git textmate ruby lighthouse)
# Add wisely, as too many plugins slow down shell startup.
plugins=(git zsh-syntax-highlighting z sudo extract docker rand-quote tmux colored-man-pages zsh-autosuggestions colorize)

source $ZSH/oh-my-zsh.sh

# User configuration

# export MANPATH="/usr/local/man:$MANPATH"

# You may need to manually set your language environment
# export LANG=en_US.UTF-8

# Preferred editor for local and remote sessions
# if [[ -n $SSH_CONNECTION ]]; then
#   export EDITOR='vim'
# else
#   export EDITOR='mvim'
# fi

# Compilation flags
# export ARCHFLAGS="-arch x86_64"

# Set personal aliases, overriding those provided by oh-my-zsh libs,
# plugins, and themes. Aliases can be placed here, though oh-my-zsh
# users are encouraged to define aliases within the ZSH_CUSTOM folder.
# For a full list of active aliases, run `alias`.
#
# Example aliases
# alias zshconfig="mate ~/.zshrc"
# alias ohmyzsh="mate ~/.oh-my-zsh"
```

编写`plugins.sh`并执行，来配置`zsh`插件：

```bash
#!/bin/bash
cd ~
git clone https://github.com/zsh-users/zsh-syntax-highlighting && \
git clone https://github.com/zsh-users/zsh-autosuggestions && \
cp -r ~/zsh-syntax-highlighting/ ~/.oh-my-zsh/custom/plugins && \
cp -r ~/zsh-autosuggestions/ ~/.oh-my-zsh/custom/plugins
```

编辑`~/patchelf/completions/zsh/_patchelf`文件修复`patchelf`的`bug`：

```bash
#compdef patchelf

local options=(
  '--page-size[Uses the given page size]:SIZE'
  '--set-interpreter[Change the dynamic loader of executable]:INTERPRETER:_files'
  '(- : *)--print-interpreter[Prints the ELF interpreter of the executable]'
  '(- : *)--print-os-abi[Prints the OS ABI of the executable]'
  '--set-os-abi[Changes the OS ABI of the executable]:ABI:(none sysv hpux netbsd gnu linux solaris aix irix freebsd tru64 modesto openbsd arm_aeabi arm standalone)'
  '(- : *)--print-soname[Prints DT_SONAME entry of .dynamic section]'
  '--set-soname[Sets DT_SONAME entry of a library to SONAME]:SONAME'
  '--set-rpath[Change the DT_RUNPATH of the executable or library to RUNPATH]:RUNPATH:_dirs'
  '--remove-rpath[Removes the DT_RPATH or DT_RUNPATH entry of the executable or library]'
  '--shrink-rpath[Remove from the DT_RUNPATH or DT_RPATH all directories that do not contain a library referenced by DT_NEEDED fields of the executable or library]'
  '--allowed-rpath-prefixes[Combined with the "--shrink-rpath" option, this can be used for further rpath tuning]:PREFIXES'
  '(- : *)--print-rpath[Prints the DT_RUNPATH or DT_RPATH for an executable or library]'
  '--force-rpath[Forces the use of the obsolete DT_RPATH in the file instead of DT_RUNPATH]'
  '--add-needed[Adds a declared dependency on a dynamic library]:LIBRARY'
  '*--replace-needed[Replaces a declared dependency on a dynamic library with another one]:a declared dependency:LIB_ORIG:another declared dependency:LIB_NEW'
  '--remove-needed[Removes a declared dependency on LIBRARY]:LIBRARY'
  '(- : *)--print-needed[Prints all DT_NEEDED entries of the executable]'
  '--no-default-lib[Marks the object so that the search for dependencies of this object will ignore any default library search paths]'
  '--no-sort[Do not sort program headers or section headers]'
  '--add-debug-tag[Adds DT_DEBUG tag to the .dynamic section if not yet present in an ELF object]'
  '(- : *)--print-execstack[Prints the state of the executable flag of the GNU_STACK program header, if present]'
  '--clear-execstack[Clears the executable flag of the GNU_STACK program header, or adds a new header]'
  '--set-execstack[Sets the executable flag of the GNU_STACK program header, or adds a new header]'
  '--rename-dynamic-symbols[Renames dynamic symbols]:NAME_MAP_FILE'
  '--output[Set the output file name]:FILE:_files'
  '--debug[Prints details of the changes made to the input file]'
  '--version[Shows the version of patchelf]'
  "(- : *)"{-h,--help}'[Show list of command-line options]'
)

_arguments -s -S $options '*: :_files'
```

将编辑后的路径添加到`zsh`的查找路径`fpath`中，即编辑`~/.zshrc`添加如下内容（我的脚本中已经添加）：

```bash
fpath=(/home/ltfall/patchelf/completions/zsh $fpath)
```

## pwngdb配置

编辑`~/.gdbinit`文件来添加`pwngdb`的命令：

```bash
#source ~/pwndbg/pwndbg.py
source ~/pwndbg/gdbinit.py
source ~/Pwngdb/pwngdb.py
source ~/Pwngdb/angelheap/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end

# telescop don't skip repeating value
set telescope-skip-repeating-val off

# ignore the alarm signal
handle SIGALRM nostop

# debug parent and child process
set detach-on-fork off
```

## 通过题目给定的libc自动获取ld以及符号链接

### 通过pwninit

在[这里](https://github.com/io12/pwninit/releases)下载`pwninit`可执行文件，并将其放置到位于环境变量的文件夹下。

但是不好用，经常出问题，因此切换到下面的方法

### 通过dl_dbgsym和pwncli init结合

来源于[这里](https://github.com/veritas501/dl_dbgsym)，但我修正了其中的几个`bug`。

```python
#!/usr/bin/env python3
import requests
import re
from os import system,popen,chdir, environ
import sys
from pwn import pause

log_info = lambda s: print(f'[\033[1;36m*\033[0m] {s}')
log_success = lambda s: print(f'[\033[1;32m√\033[0m] {s}')
log_fail = lambda s: print(f'[\033[1;31m×\033[0m] {s}')
underline = lambda s: f'\033[4m{s}\033[0m'

def set_libc_env(filename):

	def get_data_tar_name(deb_filename):
		output = popen(f'ar t "{deb_filename}"').read()
		if 'data.tar.xz' in output:
			return 'data.tar.xz'
		elif 'data.tar.zst' in output:
			return 'data.tar.zst'
		else:
			log_fail(f'Unsupported archive format in {deb_filename}')
			clean()
			exit(1)

	def get_arch(filename):
		data = popen(f'readelf -h "{filename}"').read()
		if 'X86-64' in data:
			return 'amd64'
		elif '80386' in data:
			return 'i386'
		elif 'ARM' in data:
			return 'armhf'
		elif 'AArch64' in data:
			return 'arm64'
		elif 'PowerPC64' in data:
			return 'ppc64el'
		elif 'IBM S/390' in data:
			return 's390x'
		else:
			log_fail(f'unsupported arch')
			clean()
			exit(1)

	def get_ver(filename):
		data = popen(f'strings "{filename}" | grep "GNU C Library"').read()
		try:
			ver = re.search(r'GLIBC (.*?)\)', data).group(1)
		except:
			log_fail(f'can\'t find ubuntu glibc version')
			clean()
			exit(1)
		return ver

	def get_buildid(filename):
		data = popen(f'readelf --notes "{filename}" | grep "Build ID"').read()
		try:
			buildid = re.search(r'Build ID: (\w+)',data).group(1)
		except:
			log_fail(f'can\'t find glibc buildid')
			clean()
			exit(1)
		return buildid

	def find_dist(ver):
		url = f'https://launchpad.net/ubuntu/+source/glibc/{ver}'
		r = requests.get(url)
		try:
			dist = re.search(r'<a href="/ubuntu/(\w+)">', r.text).group(1)
		except:
			log_fail(f'can\'t find ubuntu dist')
			clean()
			exit(1)
		return dist

	def find_libc_dbg_url(dist,arch,ver):
		url = f'https://launchpad.net/ubuntu/{dist}/{arch}/libc6-dbg/{ver}'
		r = requests.get(url)
		try:
			dl_url = re.search(r'<a class="sprite" href="(.*?)">', r.text).group(1)
		except:
			log_fail(f'can\'t find libc-dbg download url')
			clean()
			exit(1)
		return dl_url

	def find_libc_dbgsym_url_i386_amd64(dist,arch,ver):
		url = f'https://launchpad.net/ubuntu/{dist}/amd64/libc6-i386-dbgsym/{ver}'
		r = requests.get(url)
		try:
			dl_url = re.search(r'<a class="sprite" href="(.*?)">', r.text).group(1)
		except:
			log_fail(f'can\'t find libc-dbg download url')
			clean()
			exit(1)
		return dl_url

	def find_libc_bin_url(dist,arch,ver):
		url = f'https://launchpad.net/ubuntu/{dist}/{arch}/libc6/{ver}'
		r = requests.get(url)
		try:
			dl_url = re.search(r'<a class="sprite" href="(.*?)">', r.text).group(1)
		except:
			log_fail(f'can\'t find libc download url')
			clean()
			exit(1)
		return dl_url

	def find_libc_bin_url_i386_amd64(dist,arch,ver):
		url = f'https://launchpad.net/ubuntu/{dist}/amd64/libc6-i386/{ver}'
		r = requests.get(url)
		try:
			dl_url = re.search(r'<a class="sprite" href="(.*?)">', r.text).group(1)
		except:
			log_fail(f'can\'t find libc download url')
			clean()
			exit(1)
		return dl_url

	def move_dbgysm(filename,buildid):
		target_dir = f'/usr/lib/debug/.build-id/{buildid[:2]}'
		target_name = f'/usr/lib/debug/.build-id/{buildid[:2]}/{buildid[2:]}.debug'
		log_info(f'moving dbgsym to {underline(target_name)}')
		system(f'sudo mkdir -p {target_dir}')
		system(f'sudo cp {filename} {target_name}')
		recheck_buildid = get_buildid(target_name)
		if recheck_buildid != buildid:
			log_fail(f'move dbgsym fail')
			clean()
			exit(1)
		log_success(f'move dbgsym done!!')

	def clean():
		log_info(f'cleaning...')
		system(f'cd ..;rm -rf "{version}_tmp"')

	arch = get_arch(filename)
	log_info(f'find libc arch: {underline(arch)}')
	version = get_ver(filename)
	log_info(f'find libc version: {underline(version)}')
	buildid = get_buildid(filename)
	log_info(f'find libc buildid: {underline(buildid)}')
	dist = find_dist(version)
	log_info(f'find ubuntu dist: {underline(dist)}')
	system(f'rm -rf "{version}_tmp"')
	system(f'mkdir -p "{version}_tmp"')
	chdir(f'{version}_tmp')
	# set dbgsym
	amd64_ver_i386 = False
	libc_dbg_url = find_libc_dbg_url(dist,arch,version)
	log_info(f'find libc-dbg url: {underline(libc_dbg_url)}')
	system(f'wget {libc_dbg_url} -O libc6-dbg.deb')

	# 文件名可能为data.tar.zst
	data_tar_name = get_data_tar_name('libc6-dbg.deb')
	system(f'ar -x libc6-dbg.deb {data_tar_name}')
	system(f'mkdir -p libc6-dbg')

	if data_tar_name == 'data.tar.xz':
		# system(f'ar -x libc6-dbg.deb data.tar.xz')
		# system(f'tar -xf data.tar.xz -C ./libc6-dbg')
		system(f'tar -xf {data_tar_name} -C ./libc6-dbg')
	elif data_tar_name == 'data.tar.zst':
		system(f'zstd -d data.tar.zst -o data_dbg.tar')
		system(f'tar -xf data_dbg.tar -C ./libc6-dbg')

	dbgsym_filename = popen(f'find libc6-dbg -name "libc-*.so" -or -name "{buildid[2:]}.debug" -type f | grep -v prof').read().strip()
	dbg_buildid = get_buildid(dbgsym_filename)
	if dbg_buildid != buildid:
		log_fail(f'dbgsym buildid not match: {underline(dbg_buildid)}')
		if arch != 'i386':
			clean()
			exit(1)
		else:
			log_info(f'try to fetch amd64 build version of libc6-i386-dbgsym')
		libc_dbgsym_url = find_libc_dbgsym_url_i386_amd64(dist,arch,version)
		log_info(f'find libc6-i386-dbgsym url: {underline(libc_dbgsym_url)}')
		system(f'wget {libc_dbgsym_url} -O libc6-i386-dbgsym.ddeb')

		# 文件名可能为data.tar.zst
		data_tar_name = get_data_tar_name('libc6-i386-dbgsym.ddeb')
		system(f'ar -x libc6-i386-dbgsym.ddeb {data_tar_name}')

		system(f'mkdir -p libc6-i386-dbgsym')
		if data_tar_name == 'data.tar.xz':
			# system(f'ar -x libc6-i386-dbgsym.ddeb data.tar.xz')
			# system(f'tar -xf data.tar.xz -C ./libc6-i386-dbgsym')
			system(f'tar -xf {data_tar_name} -C ./libc6-i386-dbgsym')
		elif data_tar_name == 'data.tar.zst':
			system(f'zstd -d data.tar.zst -o data.tar')
			system(f'tar -xf data.tar -C ./libc6-i386-dbgsym')
		
		dbgsym_filename = popen(f'find libc6-i386-dbgsym -name "{buildid[2:]}.debug" -type f').read().strip()
		dbg_buildid = get_buildid(dbgsym_filename)
		if dbg_buildid != buildid:
			log_fail(f'dbgsym buildid not match: {underline(dbg_buildid)}')
			clean()
			exit(1)
		amd64_ver_i386=True
	log_success(f'find dbgsym!!')
	move_dbgysm(dbgsym_filename,dbg_buildid)
	# download ld.so
	if amd64_ver_i386:
		libc_bin_url = find_libc_bin_url_i386_amd64(dist,arch,version)
	else:
		libc_bin_url = find_libc_bin_url(dist,arch,version)
	log_info(f'find libc-bin url: {underline(libc_bin_url)}')
	system(f'wget {libc_bin_url} -O libc6.deb')

	# 文件名可能为data.tar.zst
	data_tar_name = get_data_tar_name('libc6.deb')
	system(f'ar -x libc6.deb {data_tar_name}')

	system(f'mkdir -p libc6')
	if data_tar_name == 'data.tar.xz':
		# system(f'ar -x libc6.deb data.tar.xz')
		# system(f'tar -xf data.tar.xz -C ./libc6')
		system(f'tar -xf {data_tar_name} -C ./libc6')
	elif data_tar_name == 'data.tar.zst':
		system(f'zstd -d data.tar.zst -o data.tar')
		system(f'tar -xf data.tar -C ./libc6')

	ld_filename = popen(f'find libc6 -name "ld-*.so*" -type f').read().strip()
	log_success(f'find ld.so!!')
	system(f'cp "{ld_filename}" ../')
	clean()

if __name__ == "__main__":
	if len(sys.argv) == 1:
		print('Download libc dbgsym and ld.so')
		print(f'Usage: python3 {sys.argv[0]} <target_libc.so>')
	else:
		environ['http_proxy'] = 'http://127.0.0.1:7890'
		environ['https_proxy'] = 'http://127.0.0.1:7890'
		set_libc_env(sys.argv[1])


```

将其命名为`dbgsym`，并置入环境变量的目录例如`/usr/bin`内（需要`root`权限），即可使用如下方式来下载某个`libc`文件对于的`debug symbol`和`ld`：

```bash
dbgsym ./libc.so.6
```

完成后，通过`pwncli`的`init`功能自动`patch`两个文件：

```bash
pwncli init
```

## decomp2dbg配置

我们采用手动安装，首先在[这里](https://github.com/mahaloz/decomp2dbg)下载`decomp2dbg`的所有源码，或者是`git clone`。

在`wsl`中`cd`到下载好的目录，使用如下命令：

```bash
cp -r ./decompilers/d2d_ida/* /path/to/ida/plugins/  # 注意后面替换为你自己的目录
```

然后再使用如下命令：

```bash
pip3 install . && \
cp d2d.py ~/.d2d.py && echo "source ~/.d2d.py" >> ~/.gdbinit
```

然后在`Windows`的管理员身份的`Powershell`中，输入以下命令来放行`3662`端口：

```bash
New-NetFirewallRule -DisplayName "ida_Decomp2dbg" -Direction Inbound -Protocol TCP -LocalPort 3662 -Action Allow -Profile Private
```

在`ida`中，打开某个文件后，在`edit-plugins-Decomp2dbg`中，`IP`地址输入为`0.0.0.0`，输入端口为`3662`，点击监听。

然后在`gdb`调试时输入以下命令即可（程序启动起来才可以）：

```bash
decompiler connect ida --host localhost --port 3662
```

## 将wsl固定到任务栏

鼠标右键创建一个快捷方式，目标填写如下：

```bash
C:\Windows\System32\wsl.exe -d Ubuntu
```

起始位置填写如下：

```bash
\\wsl.localhost\Ubuntu\home\ltfall
```

然后将其拖拽到任务栏即可。

## 在vscode的wsl中编辑配置

编辑`pylance`的`settings.json`，使得可以正确寻找到`pwntools`等包：

```json
{
    "editor.fontSize": 18,
    "python.analysis.extraPaths": [
        "/usr/local/lib/python3.10/dist-packages",
        "/usr/lib/python3/dist-packages",
        "/home/ltfall/pwntools",
        "/usr/lib/python3.10/dist-packages"
    ],
    "python.autoComplete.extraPaths": [
        "/usr/local/lib/python3.10/dist-packages",
        "/home/ltfall/pwntools",
        "/usr/lib/python3/dist-packages",
        "/usr/lib/python3.10/dist-packages"
    ],
}
```

## 安装docker

`docker`的重要性不必多说，此外`Ubuntu22.04`上编译的程序的`__libc_start_main`都会依赖于`GLIBC2.34`，使得其无法编译低版本可用的程序，也给我们在低版本上测试一些`glibc`特性带来了困难。这也可以使用`docker`来安装低版本工具链来解决。

输入以下命令来安装`docker的GPG KEY`：

```bash
 sudo apt install ca-certificates
 sudo install -m 0755 -d /etc/apt/keyrings
 sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
 sudo chmod a+r /etc/apt/keyrings/docker.asc
 
 echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
```

然后输入如下命令安装`docker`：

```bash
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

启动`docker`服务：

```bash'
sudo service docker start
```

进行一个`hellowolrd`来查看是否安装成功：

```bash
sudo docker run hello-world
```

此时已经可以以`sudo`权限来运行`docker`。下面是使得普通用户拥有`docker`的权限：

```bash
sudo usermod -aG docker $USER
newgrp docker
```

通过以下命令查看是否已经修改成功：

```bash
docker run hello-world
```

## 编写基于ubuntu20.04的docker编译脚本

首先创建镜像。使用如下命令：

```bash
cd ~ && mkdir dockerfiles && cd dockerfiles
```

编写名为`Dockerfile`的文件：

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*
```

构建镜像：

```bash
docker build -t ubuntu-gcc:20.04 .
```

等待完成后，在环境变量的目录下例如`/usr/bin`下（需要`root`权限）编写`gcc_libc`脚本，如下：

```bash
#!/bin/bash

# 检查最少输入参数
if [ "$#" -lt 2 ]; then
    echo "Usage: gcc_libc <full_glibc_directory_path> <source_file_name_without_extension> [additional gcc options]"
    exit 1
fi

GLIBC_DIRECTORY=$1
SOURCE_FILE_NAME=$2
shift 2 # 移除前两个已处理的参数，剩下的都是额外的gcc参数

SOURCE_FILE="${SOURCE_FILE_NAME}.c"
OUTPUT_BINARY="${SOURCE_FILE_NAME}"

# 获取当前工作目录
CURRENT_DIR=$(pwd)

# 使用docker运行编译命令，"${@}"用于传递所有额外的gcc参数
docker run --rm -v "${GLIBC_DIRECTORY}":"${GLIBC_DIRECTORY}" -v "${CURRENT_DIR}":"${CURRENT_DIR}" -w "${CURRENT_DIR}" ubuntu-gcc:20.04 gcc -Wl,--rpath="${GLIBC_DIRECTORY}" -Wl,--dynamic-linker="${GLIBC_DIRECTORY}/ld-linux-x86-64.so.2" "${SOURCE_FILE}" -o "${OUTPUT_BINARY}" "${@}"
```

赋予执行权限：

```bash
sudo chmod +x /usr/bin/gcc_libc
```

如此一来，便可在`wsl`中指定低版本`glibc`文件并运行。示例：

```bash
gcc_libc /glibc/2.31-0ubuntu9_amd64 pwn (-g -no-pie) # 括号为可选项
```

## 配置快速开启\关闭\查看aslr状态脚本

由于`suid`不能直接作用于`bash`脚本（为了安全考虑），我们这里采用`expect`脚本的方式。如下所示：

注意，其中的`your_passwod`需要替换为你自己的`sudo`密码。

关闭`aslr`：

```bash
#!/usr/bin/expect
spawn su root
expect "Password: "
send "your_password\r"
send "echo 0 > /proc/sys/kernel/randomize_va_space\r"
send "exit\r"
expect eof
send_user "\n"
```

你可以以`sudo`权限将这个脚本放在`/usr/bin`中，给予执行权限即可。

同理，开启`aslr`的脚本如下：

```bash
#!/usr/bin/expect
spawn su root
expect "Password: "
send "your_password\r"
send "echo 2 > /proc/sys/kernel/randomize_va_space\r"
send "exit\r"
expect eof
send_user "\n"
```

查看`aslr`状态：

```bash
#!/usr/bin/expect
spawn su root
expect "Password: "
send "your_password\r"
send "cat /proc/sys/kernel/randomize_va_space\r"
send "exit\r"
expect eof
send_user "\n"
```

# 连接到wsl

## 通过vscode直接连接到wsl

在`vscode`中安装`wsl`插件，即可在左下角连接到`wsl`，非常方便。

## ssh安装（或许不是很用得到）

输入以下命令来安装`ssh`：

```bash
sudo apt install openssh-server
```

完成后，查看`SSH`服务是否已经开启：

```bash
service ssh status
```

若未开启，则使用命令开启：

```bash
sudo service ssh start
```

接下来，修改防火墙策略将`ssh`添加到白名单：

```bash
sudo ufw allow ssh
```

修改`SSH`配置文件，设置可以使用`root`用户登录，以及登录需要验证。

```bash
sudo vim /etc/ssh/sshd_config
```

打开文件后，找到注释的内容，并修改为如下：

若你不知道/找不到对应的内容，也可以直接将下面内容添加到该文件。

```bash
PermitRootLogin yes
PasswordAuthentication yes
```

设置完成后，重启`ssh`即可连接到该容器：

```bash
sudo service ssh restart
```

在`powershell`中使用管理员权限输入以下命令来放行`22`端口：

```powershell
New-NetFirewallHyperVRule -DisplayName "allow WSL ssh" -Direction Inbound -LocalPorts 22 -Action Allow
```

