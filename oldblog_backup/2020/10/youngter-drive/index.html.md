---
layout: post
title: Youngter-drive
date: 2020-10-24
tags: ["逆向"]
---

[toc]

## 前置知识

*   一点点多线程知识
*   处理堆栈平衡
*   无了

## 解题流程

### 查壳脱壳

[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_b5aee77607d6cc5639fe8b9a9f1cc343.jpg)](wp_editor_md_b5aee77607d6cc5639fe8b9a9f1cc343.jpg)
反正俺暂时也只会脱这个。。。
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_0bb6dde1a2c31eb276246ba272e58d84.jpg)](wp_editor_md_0bb6dde1a2c31eb276246ba272e58d84.jpg)

### 分析程序结构

这是main函数 看起来就是多线程的 看起来就不是很好做的样子
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_320fefcdb2d75380678dadcfaa22400c.jpg)](wp_editor_md_320fefcdb2d75380678dadcfaa22400c.jpg)
shift+f12看字符串 发现主要输入flag是在上面的sub_411BD0()：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_69033981f180a448a2d85cd1fee3c628.jpg)](wp_editor_md_69033981f180a448a2d85cd1fee3c628.jpg)
然后肯定就还有比对输出，发现是在下面的：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_5deccbd4244119210074155151633e3f.jpg)](wp_editor_md_5deccbd4244119210074155151633e3f.jpg)
和一个数组比较了之后就可以得出结果。
那中间那一堆涉及线程的东西应该就是关于加密的，那我们点看看：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_74d951b6a3bd9425c171798062d24404.jpg)](wp_editor_md_74d951b6a3bd9425c171798062d24404.jpg)
第一个函数就是赋值，不说了
第二个和第三个是创建了线程，会交替执行，重点就看这两个线程执行了什么
先看startaddress这个：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_0c476405aef3178e1c390cad5b22f93b.jpg)](wp_editor_md_0c476405aef3178e1c390cad5b22f93b.jpg)
用来减的那个数是一个常量，而且等于29，很难不怀疑是用来计数的
那图中的那个函数是把这个常量和输入用来传的参数，很难不怀疑这个函数是用来加密的
那点进去看看：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_66c18b618ea0ba3f2b683f1c03fcc109.jpg)](wp_editor_md_66c18b618ea0ba3f2b683f1c03fcc109.jpg)
？
啥意思？
查了一下发现是堆栈不平衡，就是调用这个函数之后本来应该栈是不变的，但是现在变了，所以会出问题导致不能反汇编
用汇编改一下就行了：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_514f8861bccf82de07ef73a0a02a6b71.jpg)](wp_editor_md_514f8861bccf82de07ef73a0a02a6b71.jpg)
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_72c78564655bc83408ba9511939c43fb.jpg)](wp_editor_md_72c78564655bc83408ba9511939c43fb.jpg)
明显是pop出的问题，那就改成0.
改了之后就可以反汇编了：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_0d875116018bd11b3dec3aacea2ce04b.jpg)](wp_editor_md_0d875116018bd11b3dec3aacea2ce04b.jpg)
发现是一个加密函数。
以同样的方法去看另一个线程，发现逻辑是这样的：
第一个线程会加密，但是第二个线程只会减少count值而不会加密，相当于是加密一位跳一位这样子。

### 编写解密脚本

剩下的也没啥好说的了，解法也比较简单，附上解密脚本：

    #include <algorithm>
    #include <cstdlib>
    #include <cstring>
    #include <iostream>
    #include <string>
    #include <vector>

    using namespace std;
    int my_find(char str[],char t){
        for (int i = 0; i < 53;i++){
            if(str[i]==t){
                return i;
            }
        }
        return -1;
    }

    int main(int argc, char const *argv[])
    {
        char to_com[] = "TOiZiZtOrYaToUwPnToBsOaOapsyS";
        char jiami[] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
        char flag[29];
        for (int i = 29; i >= 0;i--){
            if(i%2==0){
                flag[i] = to_com[i];
            }else{
                char t = my_find(jiami, to_com[i]);
                char t2 = t;
                if(t2+38>='A'&&t2+38<='Z'){
                    t = t2 + 38;
                }
                if(t2+96>='a'&&t2+96<='z'){
                    t = t2 + 96;
                }
                flag[i] = t;
            }
        }
        for (int i = 0; i < 29;i++){
            printf("%c",flag[i]);
        }
    }

完事之后得出结果：
[![](http://ltfa1l.top/wp-content/uploads/2020/10/wp_editor_md_173137e775b82e631677e0f103d630b2.jpg)](wp_editor_md_173137e775b82e631677e0f103d630b2.jpg)
交上去是不对的，查了一下发现是说什么转变后还有一位是没有拿来比较的，这里还有一位'E'要加上...
Goodbye!