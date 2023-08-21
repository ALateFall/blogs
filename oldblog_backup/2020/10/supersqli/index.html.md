---
layout: post
title: supersqli
date: 2020-10-06
tags: ["web"]
---

打开环境，看上去像sql注入：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_4c1659f1b464e00da664fae316d03496.jpg)](wp_editor_md_4c1659f1b464e00da664fae316d03496.jpg)
尝试爆出数据库名：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_28fd4af13971fc2ce0bfb4108438e28c.jpg)](wp_editor_md_28fd4af13971fc2ce0bfb4108438e28c.jpg)
发现题目对常见的语句都进行了过滤，其中包括select，那常见的查询就没用了。
尝试了一下（然后看了答案）之后发现可以进行堆叠注入，即输入多条语句，如图：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_0131b9e8e82e6c678d38918a0166724d.jpg)](wp_editor_md_0131b9e8e82e6c678d38918a0166724d.jpg)
继续，爆出所有的表：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_e98ab319df34de6f30881d1f89e668a0.jpg)](wp_editor_md_e98ab319df34de6f30881d1f89e668a0.jpg)
看了一圈之后发现这两个表就是supersqli这个数据库里面的，说明当前是在supersqli这个数据库里面。
检查word表：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_9e640f366c7aa7b8046dc4c38f21e36d.jpg)](wp_editor_md_9e640f366c7aa7b8046dc4c38f21e36d.jpg)
检查另一个表：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_79cdc5f10e0294040347e37edafbf4e9.jpg)](wp_editor_md_79cdc5f10e0294040347e37edafbf4e9.jpg)
发现flag在1919这个表里面，但是查询的应该是words这张表。
由于不能使用select，因此可以将1919这张表改为words，就可以直接通过接口查询flag了。
更改数据库：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_6acb6a137593409de914a810954a254d.jpg)](wp_editor_md_6acb6a137593409de914a810954a254d.jpg)
更改了之后本以为可以直接爆出flag，但是发现不可以，输了个1提示如下：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_926c80691d9459e30bd57c35f20752c7.jpg)](wp_editor_md_926c80691d9459e30bd57c35f20752c7.jpg)
才发现上当了，原来这个查询是通过id查询的。
那只能重来，而且在改数据库名的时候要给flag在的那张表增加一个id字段或者将其他字段修改成id。
重新开环境，在刚刚那个地方代码更改如下：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_02d21f5e291603051fc58cefe11b2f6d.jpg)](wp_editor_md_02d21f5e291603051fc58cefe11b2f6d.jpg)
查询即可得到结果：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_cbf5f976c5e4a0e05b9e46cd14b2beaa.jpg)](wp_editor_md_cbf5f976c5e4a0e05b9e46cd14b2beaa.jpg)

    http://220.249.52.133:31265/?inject=1' ;alter table `words` rename to `byebye`;alter table `1919810931114514` rename to `words`;alter table `words` add `id` varchar(10);#
    