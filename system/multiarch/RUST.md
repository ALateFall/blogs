---
layout: post
title: Rust语法基础学习
category: multiarch
date: 2024-04-01 12:00:00
---
螃蟹好吃捏
<!-- more -->
[toc]

# Rust

## 0x00. 开始之前

### 安装

我是`WSL2`，先开全局代理，然后：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

完成后重启终端，输入以下命令检查是否安装完毕：

```bash
cargo -V
rustc -V
```

### VSCode插件

我使用了：

- `rust`
- `rust-analyzer`

## 0x01. 构建一个项目

切换到要创建工作目录的地方，输入以下命令创建一个项目：

```bash
cargo new <your_project_name>
```

例如，我们使用如下命令创建一个叫做`hello`的项目：

```bash
cargo new hello
```

使用如下命令构建、运行项目：

```bash
cd ./hello
cargo build 
cargo run 
```

## 0x02. 基础语法

### 变量声明

各种数据类型如下：

```rust
let a: i8 = 1;
let b: u32 = 5;
let c: bool = true;
let d: f64 = 1.1;
let e: char = 'z';
let f: &str = "yes";
```

`rust`会自动推断变量类型，但`rust`是强类型语言。

```rust
let a = 1; // 正确
```

### 输出

`println!`换行输出，而`printl!`是不换行输出。

如下所示：

```rust
let f: &str= "sunny";
println!("The weather is {} today.", str)
```

### 变量性质

在`rust`中，变量被定义后就不可改变：

```rust
let a = 1;
a = 2; // 错误，不可改变其值
```

若需要改变，可以用`mut`声明，意味着这是一个可以改变的变量：

```rust
let mut a = 1;
a = 2; // 正确
```

但我们上面提到了，`rust`是强类型语言，因此也不能将其赋值给别的变量类型。

### 重影

我们提到了`rust`没有使用`mut`定义的变量的值不可改变，但可以重影：

```rust
let a = 1;
let a = a + 2;
println!("a is {}", a);
```

这段代码的值为`3`。可以得知，`rust`在声明变量后可以再次用`let`声明并重新绑定其值。

### 数组

数组需要为同类型数据。注意，数组的长度一旦确定，是不能够再改变的。若需要改变，可以参照后文章节`vector`。

如下：

```rust
let c:[i32; 5] = [1, 2, 3, 4, 5];
// 表示c为一个数据类型为i32的长度为5的数组
```

### 函数

和其他语言类似：

```rust
fn add(a:i32, b:i32) -> i32{
    return a + b
}
```

若没有加上返回值类型，则一定不能有返回值。

### 函数表达式

也就是如下形式，需要注意的就是大括号内部最后是没有分号的：

```rust
let x = {
    let x = 2;
    x + 5
};
```

### 条件语句

如下：

```rust
let a = 1;
let b = 2;
if a > b {
    println!("a is larger.");
}else if a == b{
    println!("equal!");
}else{
    println!("a is smaller.");
}
```

注意几点：

- `rust`中用于判断的部分**不一定**需要加小括号
- `rust`中**一定需要**大括号

也有三元表达式：

```rust
let a = 1;
let b = if a == 1 {5} else {0};
```

### 循环

有如下两种写法，分别是`while`循环和`for-iter`迭代器：

```rust
// while循环写法
let mut i = 0;
while i <= 10 {
    i += 1;
    println!("The value of i is {} now.", i);
}
```

和：

```rust
// for写法
let a: [i32; 6] = [10, 20, 30, 40, 50, 60];
for i in a.iter(){
    println!("The value of i is {} now.", i);
}
```

另外，`RUST`里面的无限循环可以用`loop`而不是`while True`来实现，`loop`可以外带一个返回值：

```rust
let mut i: i32 = 0;
let mut x: i32 = 0;
let result: i32 = loop{
    x = 2 * i;
    if i == 10{
        break x;
    }
    i += 1;
};
println!("The value of result is {}.", result);
```

（当然不带也是可以的）

### 迭代器

有三种迭代器：借用迭代器、可变借用迭代器、所有权迭代器。如下：

```rust
// 借用迭代器，不可修改迭代器的值
let vec = vec![1, 2, 3, 4, 5];
let iter = vec.iter();

// 可变借用迭代器，可以修改原数组的值
let mut vec = vec![1, 2, 3, 4, 5];
let iter_mut = vec.iter_mut();

// 所有权迭代器，会获取所有权，使用结束后vec不再可使用
let vec = vec![1, 2, 3, 4, 5];
let into_iter = vec.into_iter();
```

### 切片

使用`..`即可对字符串切片，同样是左闭右开。

```rust
fn main() {
    let s1 = String::from("hello, world!");
    let slice = &s1[0..3];
    println!("The slice of string is {}.", slice);
}
```

### 结构体

先看一个完整的结构体写法，以及其输出：

```rust
// 若要对结构体进行格式化输出，才需要导入这个包
#[derive(Debug)]

// 定义结构体
struct Book{
    title: String,
    content: String,
    price: i32,
}


fn main() {
    // 实例化一个结构体
    let b1 = Book{
        title: "Harry Potter".to_string(),
        content: String::from("VoldMort and Harry"),
        price: 60
    };
	
    // 通过格式化输出结构体，需要导入包
    println!("rect is {:#?}", b1);   
    
}
```

输出结构体需要`#[derive(Debug)]`，此时可以通过如下两种方式来输出结构体：

- `{:?}` 结构体输出在一行内，适合属性较少
- `{:#?}` 结构体输出为多行，适合属性多一点

### 枚举

看下面这个例子，我们展示了如何编写一个枚举，并使用`match`来判断枚举类型：

```rust
enum Fruit{
    Apple,
    Orange,
    Banana
}

fn describe_fruit(fruit:Fruit){
    match fruit{
        Fruit::Apple => { println!("This is an apple."); },
        Fruit::Orange => { println!("This is an orange."); },
        Fruit::Banana => { println!("This is a banana."); },
    }
}

fn main() {
    let my_fruit = Fruit::Orange;
    describe_fruit(my_fruit);
}
```

### 文件与IO

我们可以用`std::fs::read_to_string`函数来读取文件内容为字符串，但该函数的返回值并不是字符串类型，需要加上`.unwrap()`来转换其类型为字符串类型。

可以用如下方式来**读取文件**内容为字符串：

```rust
fn main() {
    let contents:String = std::fs::read_to_string("src/flag").unwrap();
    println!("File contents: {}.", contents);
}
```

也可以通过`std::fs::read`函数来以`u8`的数组类型读取：

```rust
fn main() {
    let contents: Vec<u8> = std::fs::read("src/flag").unwrap();
    println!("File contents: {:?}.", contents);
}
```

**写入文件**，使用`std::fs::write`函数即可，第一个参数为文件路径，第二个参数为文件内容：

```rust
fn main() {
    std::fs::write("src/flag2", "flag{You_write_flag!}").unwrap();
}
```

**从命令行读入**，我们使用`std::io::read_line()`函数即可。

在如下的例子中，我们通过`String::new()`来创建了一个可变的空字符串，并从标准输入读入数据，随后输出到标准输出。

```rust
fn main() {
    let mut str_buf = String::new();

    std::io::stdin().read_line(&mut str_buf).expect("Failed to read line.");
    println!("Your input is {}", str_buf);
}
```

### 向量

和数组很像，但是是可变的，这与`c++`等很多语言类似。

```rust
fn main() {
    let mut vector: Vec<i32> = Vec::new();
    let mut vector = vec![1, 2, 3, 4];

    println!("initial vec: {:?}", vector);
    
    vector.push(5);
    vector.push(6);
    
    println!("final vec: {:?}", vector)
}
```

在上面这段代码中，我们使用`Vec::new()`来创建了一个空向量，并使用宏`vec![1, 2, 3, 4]`来初始化了`vector`。

也可以使用`append`来将一个向量拼接到另一个向量：

```rust
fn main() {
    let mut vector: Vec<i32> = Vec::new();
    let mut vector = vec![1, 2, 3, 4];

    let mut vector2 = vec![5, 6, 7, 8];
    vector.append(&mut vector2);
    println!("The vec is {:?}", vector);
}
```

### 字符串

字符串是`String`类型。

创建一个空的字符串：

```rust
let a: String = String::new();
```

需要注意的是，常量字符串并不是`String`类型，而是字符串切片类型`&str`。

因此，可以使用如下方式来从常量字符串创建一个字符串：

```rust
let b: String = String::from("hello");
```

可以使用`to_string()`方法来将基础变量类型转换为字符串类型：

```rust
let c: String = 1.to_string();
let d: String = 1.1.to_string();
let e: String = "haha".to_string();
```

可以通过`push`方法来追加字符，或者`push_str`方法来追加字符串：

```rust
let mut e: String = "haha".to_string();
e.push('u');
e.push_str("what");
```

字符串可以通过`+`号进行拼接，但是要注意所有权：

```rust
let mut a = String::from("hello");
let mut b = String::from("world");

a = a + ", " + &b;
println!("{}", a); 
```

注意，我们并不想改变`b`的所有权，因此使用了`a`，但`b`是借用`&b`。

使用`.len()`方法获取字符串长度：

```rust
fn main() {
    let mut a = String::from("hello");
    let mut b = String::from("world");

    a = a + ", " + &b;
    println!("The string is {}, and the length of it is {}.", a, a.len()); 
}
```

## 0x03. 内存管理语法

### 所有权

`Rust`里面最有意思的部分（当然是个人认为）

一个值的所有权只能为一个变量所拥有。因此，考虑如下情况：

```rust
fn main() {
    let s1 = String::from("Hello"); // 返回值是一个指向heap中的chunk的指针
    let s2 = s1; // 把s1指针的值赋值给s2
    println!("{}, world!", s1); // 已经赋值给s2，所有权转移，s1已经不存在了！所以报错
}
```

### 克隆

和上面的所有权对应。

由于`Rust`的所有权机制，因此难以直接将指针的值赋值给另外一个变量，而有时候我们需要这个机制。

此时可以采用克隆，克隆会直接复制整份数据，而不是传递指针。

```rust
fn main() {
    let s1 = String::from("Hello");
    let s2 = s1.clone();
    println!("{}, world!", s1);
}
```

### 函数的所有权

对于`pwner`其实不难理解。看一个例子如下：

```rust
fn main() {
    let s = String::from("hello");
    // s 被声明有效

    takes_ownership(s);
    // s 的值被当作参数传入函数
    // 所以可以当作 s 已经被移动，从这里开始已经无效

    let x = 5;
    // x 被声明有效

    makes_copy(x);
    // x 的值被当作参数传入函数
    // 但 x 是基本类型，依然有效
    // 在这里依然可以使用 x 却不能使用 s

} // 函数结束, x 无效, 然后是 s. 但 s 已被移动, 所以不用被释放


fn takes_ownership(some_string: String) { 
    // 一个 String 参数 some_string 传入，有效
    println!("{}", some_string);
} // 函数结束, 参数 some_string 在这里释放

fn makes_copy(some_integer: i32) { 
    // 一个 i32 参数 some_integer 传入，有效
    println!("{}", some_integer);
} // 函数结束, 参数 some_integer 是基本类型, 无需释放
```

总结，对于一个指针：

- 在函数`A`中传递给函数`B`，在函数`A`中不再可以使用；
- 在函数`B`结尾时其指向的`chunk`自动释放。

而对于一个基本变量类型例如`i32`：

- 在函数`A`中传递给函数`B`，在函数`A`中仍然可以使用。

这很好理解，因为`Rust`的安全管理机制，传递指针给函数相当于改变了所有权，因此无法再使用该堆块（指针）。

而对于基本变量类型，函数传参时基本相当于直接将值赋值给了寄存器，自然谈不上释放和所有权转移。

### 引用

和`C++`的引用较为类似。我们刚刚提到了所有权的概念，而引用只会”租借“，获得使用权，而不会改变所有权。

因此下面这段代码正确：

```rust
fn main() {
    let s1 = String::from("hello");
    let s2 = &s1; // 把s1借给s2，没有改变使用权
    println!("{}, world!", s1); // 仍然可以访问s1
}
```

因此，同样也可以将引用传递给函数：

```rust
fn main() {
    let s1 = String::from("hello");
    stdout(&s1); // 传递的也是租借的变量
    println!("{}, world2!", s1);
}

fn stdout(a: &String){ // a的变量类型是字符串的引用
    println!("{}, world!", a);
}
```

可能难以理解，尤其是我们刚刚还学了所有权这个概念后。

实际上，引用是指向原有指针的一个指针，而不是指向原指针指向的数据的指针，偷了个图：

![img](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405271113389.jpeg)

因此，我们不难想到，一个引用在原变量的所有权已经丢失的时候，引用也失效了：

```rust
fn main() {
    let s1 = String::from("hello");
    let s2: &String = &s1; // s2是s1的一个引用
    stdout(s1); // s1的所有权丢失了
    println!("{}, world2!", s2); // 报错，因为s2已经寄了
}

fn stdout(a: String){
    println!("{}, world!", a);
}
```

此外，租借的变量也无法修改其变量内容，除非变量所有者通过`&mut`允许你修改其值：

```rust
fn main() {
    let mut s1 = String::from("hello");
    let s2:&mut String = &mut s1; //  s2是s1的一个可变引用
    s2.push_str(" world!");
    println!("{}", s2);
}
```

## 0x04. Rust Pwn

### 插件安装

首先需要在`Windows`上[安装](https://static.rust-lang.org/rustup/dist/i686-pc-windows-gnu/rustup-init.exe)`Rust`，选择默认即可。

随后[安装](https://github.com/timetravelthree/FTLRustDemangler)依赖。下载该文件夹内容后，通过`cargo`进行编译：

```bash
cargo build --release
```

编译完成后，可以在`target/release`找到`rs-dml.exe`可执行文件，将其复制一份放到环境变量中。

随后[安装](https://github.com/timetravelthree/IDARustDemangler/releases/download/v0.1.0/IDARustDemangler-v0.1.0.zip)插件`IDARustDemangler`，下载后将`py`文件放置到`IDA`的`plugins`文件夹下即可，`IDA PRO8.3`是支持的。

随后启动`IDA`后，只需要点击左上角`edit-plugins-IDA Rust Demangler`即可。

虽然但是，即使有了这个插件，可读性也没有变得很高（甚至说是持平），因此还是愉快地读汇编吧。

### 函数调用

这一点与`C`语言和`C++`就持平，而不是像`golang`一样甚至改变了函数参数寄存器。

在`Rust`中，函数的几个参数仍然是`rdi rsi rdx rcx r8 r9`。

### 函数名

实际上，`IDA`反编译后的函数名看着虽然十分冗长，但是遵循`name mangling`命名规则。

我们看一个例子，我有一个`rust`项目，名为`hello`，那么在`IDA`第一层的`main`函数中，可以看到其调用了如下函数：

![image-20240529143115907](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405291431009.png)

可以看到其中调用的函数名称为`_ZN11hello__mainE1639c47d804b494029`。剖析这个函数名，实际上组成如下：

- 固定开头`_ZN`
- 长度`11`，例如这里表示`hello__main`的长度
- 项目名称`hello`
- 函数名`main`
- 哈希值`E1639c47d804b494029`

是不是会觉得简单多了？有了这个小知识后，观察如下函数名称（随便截的图）：

![image-20240529143423592](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405291434664.png)

通过`hello`这个字符串定位，我们便可以方便地找到哪些是该`Rust`项目中编写的函数，而哪些是库函数。

### 常见函数参数

很遗憾，`ida`并不能正确识别`Rust`的函数参数，这让我们在阅读反编译的`Rust`代码时带来了麻烦。

如图所示：

![image-20240529153718117](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405291537167.png)

这里有一个`read_line`函数，乍一看似乎是对变量`v7`进行输入，那这样就掉入陷阱了。

实际上，`read_line`函数有三个参数，第一个参数为`self`，即`core::result:Result<usize,std::io::error::Error>`，第二个参数是`io::stdin()`，第三个参数`rdx`，才是要输入的字符串的地址。

根据以上信息，我们按`y`，将函数改为三个参数，如下：

![image-20240529155733893](https://ltfallpics.oss-cn-hangzhou.aliyuncs.com/images/202405291557943.png)

可以看到，改为三个参数后，我们看到输入的字符串刚好是通过`String::new()`来创建的字符串。

基于此，现总结在`IDA`反汇编中的常见函数的参数，供在做`Rust`时能够快速识别函数，理清逻辑。

#### read_line()

由于在`rust`中`read_line()`的写法通常为如下形式：

```rust
io::stdin()
    .read_line(&mut choice)
    .expect("failed to read input.");
```

因此在汇编中其会先`call`一个`std::io::stdio::stdin`形式的函数，随后才会调用`read_line`。

三个参数如下：

- 第一个参数`self`，即`core::result:Result<usize, std::io::error::Error>`
- 第二个参数`io::stdin()`对象示例，同时也是返回值
- 第三个参数为要输入的字符串的地址

